import 'dart:async';

import 'package:sqflite/sqflite.dart';

import '../services/database_service.dart';

class VoWifiMessageStore {
  VoWifiMessageStore({Future<Database> Function()? openDatabase})
    : _openDatabase = openDatabase ?? (() => DatabaseService().database);

  final Future<Database> Function() _openDatabase;
  static final _changes = StreamController<void>.broadcast();

  /// Shared across stores so an inbox can refresh without a live SIM service.
  static Stream<void> get changes => _changes.stream;

  Future<Database>? _ready;

  Future<Database> _database() async {
    try {
      return await (_ready ??= _initialize());
    } catch (_) {
      _ready = null;
      rethrow;
    }
  }

  Future<Database> _initialize() async {
    final database = await _openDatabase();
    await database.transaction((transaction) async {
      await transaction.execute('''
      CREATE TABLE IF NOT EXISTS vowifi_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        line_key TEXT NOT NULL,
        peer TEXT NOT NULL,
        content TEXT NOT NULL,
        direction TEXT NOT NULL,
        state TEXT NOT NULL,
        message_id TEXT,
        at TEXT NOT NULL
      )
    ''');
      final columns = await transaction.rawQuery(
        'PRAGMA table_info(vowifi_messages)',
      );
      if (!columns.any((column) => column['name'] == 'message_id')) {
        await transaction.execute(
          'ALTER TABLE vowifi_messages ADD COLUMN message_id TEXT',
        );
      }
      await transaction.execute('''
      CREATE UNIQUE INDEX IF NOT EXISTS vowifi_message_identity
      ON vowifi_messages(line_key, message_id)
    ''');
    });
    await database.transaction((migration) async {
      final fields = await migration.rawQuery(
        'PRAGMA table_info(vowifi_messages)',
      );
      for (final name in ['is_read', 'deleted']) {
        if (!fields.any((field) => field['name'] == name)) {
          await migration.execute(
            'ALTER TABLE vowifi_messages ADD COLUMN $name INTEGER NOT NULL DEFAULT 0',
          );
        }
      }
      await migration.execute('''
      CREATE TABLE IF NOT EXISTS vowifi_sms_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        line_key TEXT NOT NULL,
        sim_id TEXT NOT NULL,
        peer TEXT NOT NULL,
        reference INTEGER NOT NULL,
        total INTEGER NOT NULL,
        min_scts INTEGER NOT NULL,
        max_scts INTEGER NOT NULL,
        message_row_id INTEGER
      )
    ''');
      await migration.execute('''
      CREATE INDEX IF NOT EXISTS vowifi_sms_group_identity
      ON vowifi_sms_groups(line_key, sim_id, peer, reference, total, min_scts)
    ''');
      await migration.execute('''
      CREATE TABLE IF NOT EXISTS vowifi_sms_parts (
        group_id INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        content TEXT NOT NULL,
        scts INTEGER NOT NULL,
        PRIMARY KEY(group_id, sequence)
      )
    ''');
      await migration.execute('''
      CREATE TABLE IF NOT EXISTS vowifi_sms_part_receipts (
        line_key TEXT NOT NULL,
        sim_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        group_id INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        PRIMARY KEY(line_key, sim_id, message_id)
      )
    ''');
    });
    return database;
  }

  Future<void> markRead(Set<int> ids) => _changeRecords(ids, {'is_read': 1});
  Future<void> deleteRecords(Set<int> ids) async {
    // Deletion is scoped to the records actually confirmed by the user. Unlike
    // marking a conversation read, it must not include older hidden messages.
    final snapshot = Set<int>.unmodifiable(ids);
    if (snapshot.isEmpty) return;
    final db = await _database();
    await db.transaction((tx) async {
      for (final id in snapshot) {
        await tx.update(
          'vowifi_messages',
          {'deleted': 1},
          where: 'id = ?',
          whereArgs: [id],
        );
      }
    });
    _changes.add(null);
  }

  Future<void> _changeRecords(Set<int> ids, Map<String, Object?> values) async {
    if (ids.isEmpty) return;
    final db = await _database();
    await db.transaction((tx) async {
      final groups = <(String, String), int>{};
      for (final id in ids) {
        final rows = await tx.query(
          'vowifi_messages',
          columns: ['line_key', 'peer'],
          where: 'id = ?',
          whereArgs: [id],
        );
        if (rows.isEmpty) continue;
        final key = (
          rows.first['line_key'] as String,
          rows.first['peer'] as String,
        );
        if (id > (groups[key] ?? 0)) groups[key] = id;
      }
      for (final entry in groups.entries) {
        await tx.update(
          'vowifi_messages',
          values,
          where: 'line_key = ? AND peer = ? AND id <= ?',
          whereArgs: [entry.key.$1, entry.key.$2, entry.value],
        );
      }
    });
    _changes.add(null);
  }

  Future<List<Map<String, Object?>>> list([String? lineKey]) async {
    final database = await _database();
    return database.query(
      'vowifi_messages',
      where: lineKey == null ? 'deleted = 0' : 'deleted = 0 AND line_key = ?',
      whereArgs: lineKey == null ? null : [lineKey],
      orderBy: 'id DESC',
      limit: 200,
    );
  }

  Future<int> add({
    required String lineKey,
    required String peer,
    required String content,
    required String direction,
    required String state,
    String? at,
    String? messageId,
  }) async {
    return (await _add(
      lineKey: lineKey,
      peer: peer,
      content: content,
      direction: direction,
      state: state,
      at: at,
      messageId: messageId,
    )).id;
  }

  /// The result describes the committed transaction, not last_insert_rowid:
  /// SQLite can return an earlier row ID for INSERT OR IGNORE on a duplicate.
  Future<VoWifiMessageInsert> addIncoming({
    required String lineKey,
    required String peer,
    required String content,
    required String messageId,
    String? at,
  }) => _add(
    lineKey: lineKey,
    peer: peer,
    content: content,
    direction: 'incoming',
    state: 'received',
    messageId: messageId,
    at: at,
  );

  /// Persist each concatenated SMS segment before acknowledging it to IMS.
  /// An incomplete message returns null; only the transaction assembling its
  /// last missing sequence publishes an inbox change. Completed groups and
  /// receipts remain tombstones even when the displayed message is deleted.
  Future<VoWifiMessageInsert?> addIncomingSegment({
    required String lineKey,
    required String peer,
    required String content,
    required String messageId,
    required String simId,
    required int concatReference,
    required int concatTotal,
    required int concatSequence,
    String? at,
  }) async {
    final timestamp = at == null ? null : DateTime.tryParse(at);
    if (lineKey.isEmpty ||
        peer.isEmpty ||
        messageId.isEmpty ||
        !RegExp(r'^[a-fA-F0-9]{64}$').hasMatch(simId) ||
        concatReference < 0 ||
        concatReference > 65535 ||
        concatTotal < 2 ||
        concatTotal > 255 ||
        concatSequence < 1 ||
        concatSequence > concatTotal ||
        timestamp == null ||
        !timestamp.isUtc) {
      throw ArgumentError('Invalid multipart SMS identity, sequence or SCTS');
    }
    final sim = simId.toLowerCase();
    final scts = timestamp.millisecondsSinceEpoch;
    const window = Duration(minutes: 5);
    final identity = [lineKey, sim, peer, concatReference, concatTotal];
    const identityWhere =
        'line_key = ? AND sim_id = ? AND peer = ? AND reference = ? AND total = ?';
    final database = await _database();
    final result = await database.transaction<VoWifiMessageInsert?>((tx) async {
      Future<VoWifiMessageInsert?> existingResult(
        Map<String, Object?> group,
      ) async {
        final id = group['message_row_id'];
        return id is int ? VoWifiMessageInsert(id: id, inserted: false) : null;
      }

      Future<void> saveReceipt(int groupId) async {
        await tx.insert('vowifi_sms_part_receipts', {
          'line_key': lineKey,
          'sim_id': sim,
          'message_id': messageId,
          'group_id': groupId,
          'sequence': concatSequence,
        });
      }

      // A repeated network delivery must never revive a deleted inbox row,
      // nor may its identity be reused to overwrite a different segment.
      final receipts = await tx.query(
        'vowifi_sms_part_receipts',
        where: 'line_key = ? AND sim_id = ? AND message_id = ?',
        whereArgs: [lineKey, sim, messageId],
        limit: 1,
      );
      if (receipts.isNotEmpty) {
        final receipt = receipts.single;
        final groups = await tx.query(
          'vowifi_sms_groups',
          where: 'id = ?',
          whereArgs: [receipt['group_id']],
        );
        final parts = await tx.query(
          'vowifi_sms_parts',
          where: 'group_id = ? AND sequence = ?',
          whereArgs: [receipt['group_id'], receipt['sequence']],
        );
        if (groups.length != 1 || parts.length != 1) {
          throw StateError('Stored multipart SMS receipt has no segment');
        }
        final group = groups.single;
        final part = parts.single;
        if (group['peer'] != peer ||
            group['reference'] != concatReference ||
            group['total'] != concatTotal ||
            receipt['sequence'] != concatSequence ||
            part['content'] != content ||
            part['scts'] != scts) {
          throw StateError('Conflicting multipart SMS delivery identity');
        }
        return existingResult(group);
      }

      // Completed references are not permanently reserved: carriers reuse
      // their small reference space. Exact old segments remain duplicates;
      // overlapping SCTS with different content is ambiguous and fails closed.
      final completed = await tx.query(
        'vowifi_sms_groups',
        where:
            '$identityWhere AND message_row_id IS NOT NULL '
            'AND min_scts <= ? AND max_scts >= ?',
        whereArgs: [...identity, scts, scts],
      );
      if (completed.isNotEmpty) {
        if (completed.length != 1) {
          throw StateError('Ambiguous completed multipart SMS reference');
        }
        final group = completed.single;
        final parts = await tx.query(
          'vowifi_sms_parts',
          where: 'group_id = ? AND sequence = ?',
          whereArgs: [group['id'], concatSequence],
        );
        if (parts.length != 1 ||
            parts.single['content'] != content ||
            parts.single['scts'] != scts) {
          throw StateError('Conflicting completed multipart SMS reference');
        }
        await saveReceipt(group['id'] as int);
        return existingResult(group);
      }

      final candidates = await tx.query(
        'vowifi_sms_groups',
        where:
            '$identityWhere AND message_row_id IS NULL '
            'AND min_scts >= ? AND max_scts <= ?',
        whereArgs: [
          ...identity,
          scts - window.inMilliseconds,
          scts + window.inMilliseconds,
        ],
      );
      if (candidates.length > 1) {
        throw StateError(
          'Ambiguous multipart SMS reference within SCTS window',
        );
      }
      late final int groupId;
      if (candidates.isEmpty) {
        groupId = await tx.insert('vowifi_sms_groups', {
          'line_key': lineKey,
          'sim_id': sim,
          'peer': peer,
          'reference': concatReference,
          'total': concatTotal,
          'min_scts': scts,
          'max_scts': scts,
        });
      } else {
        final group = candidates.single;
        groupId = group['id'] as int;
        final minimum = (group['min_scts'] as int) < scts
            ? group['min_scts'] as int
            : scts;
        final maximum = (group['max_scts'] as int) > scts
            ? group['max_scts'] as int
            : scts;
        if (maximum - minimum > window.inMilliseconds) {
          throw StateError('Multipart SMS segments exceed the SCTS window');
        }
        final parts = await tx.query(
          'vowifi_sms_parts',
          where: 'group_id = ? AND sequence = ?',
          whereArgs: [groupId, concatSequence],
        );
        if (parts.isNotEmpty) {
          if (parts.single['content'] != content ||
              parts.single['scts'] != scts) {
            throw StateError('Conflicting multipart SMS sequence');
          }
          await saveReceipt(groupId);
          return null;
        }
        await tx.update(
          'vowifi_sms_groups',
          {'min_scts': minimum, 'max_scts': maximum},
          where: 'id = ?',
          whereArgs: [groupId],
        );
      }
      await tx.insert('vowifi_sms_parts', {
        'group_id': groupId,
        'sequence': concatSequence,
        'content': content,
        'scts': scts,
      });
      await saveReceipt(groupId);
      final parts = await tx.query(
        'vowifi_sms_parts',
        where: 'group_id = ?',
        whereArgs: [groupId],
        orderBy: 'sequence ASC',
      );
      if (parts.length < concatTotal) return null;
      if (parts.length != concatTotal ||
          parts.indexed.any((part) => part.$2['sequence'] != part.$1 + 1)) {
        throw StateError('Multipart SMS has an invalid stored sequence set');
      }
      final earliest = parts
          .map((part) => part['scts'] as int)
          .reduce((a, b) => a < b ? a : b);
      final rowId = await tx.insert('vowifi_messages', {
        'line_key': lineKey,
        'peer': peer,
        'content': parts.map((part) => part['content'] as String).join(),
        'direction': 'incoming',
        'state': 'received',
        'message_id': 'multipart:$sim:$groupId',
        'at': DateTime.fromMillisecondsSinceEpoch(
          earliest,
          isUtc: true,
        ).toIso8601String(),
      });
      await tx.update(
        'vowifi_sms_groups',
        {'message_row_id': rowId},
        where: 'id = ?',
        whereArgs: [groupId],
      );
      return VoWifiMessageInsert(id: rowId, inserted: true);
    });
    if (result?.inserted ?? false) _changes.add(null);
    return result;
  }

  Future<VoWifiMessageInsert> _add({
    required String lineKey,
    required String peer,
    required String content,
    required String direction,
    required String state,
    String? at,
    String? messageId,
  }) async {
    if (lineKey.isEmpty || (messageId != null && messageId.isEmpty)) {
      throw ArgumentError('SMS line and message identities must not be empty');
    }
    final database = await _database();
    final result = await database.transaction((transaction) async {
      final id = await transaction.insert('vowifi_messages', {
        'line_key': lineKey,
        'peer': peer,
        'content': content,
        'direction': direction,
        'state': state,
        'message_id': messageId,
        'at': at ?? DateTime.now().toUtc().toIso8601String(),
      }, conflictAlgorithm: ConflictAlgorithm.ignore);
      final changes = await transaction.rawQuery('SELECT changes() AS changed');
      if (changes.single['changed'] == 1) {
        return VoWifiMessageInsert(id: id, inserted: true);
      }
      final existing = await transaction.query(
        'vowifi_messages',
        columns: ['id'],
        where: 'line_key = ? AND message_id = ?',
        whereArgs: [lineKey, messageId],
        limit: 1,
      );
      if (existing.isEmpty) throw StateError('SMS was not persisted');
      return VoWifiMessageInsert(
        id: existing.single['id'] as int,
        inserted: false,
      );
    });
    if (result.inserted) _changes.add(null);
    return result;
  }

  Future<void> setState(int id, String state) async {
    final database = await _database();
    final updated = await database.update(
      'vowifi_messages',
      {'state': state},
      where: 'id = ?',
      whereArgs: [id],
    );
    if (updated > 0) _changes.add(null);
  }
}

class VoWifiMessageInsert {
  const VoWifiMessageInsert({required this.id, required this.inserted});

  final int id;
  final bool inserted;
}
