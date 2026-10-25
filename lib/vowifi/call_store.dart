import 'dart:async';

import 'package:sqflite/sqflite.dart';

import '../services/database_service.dart';

/// Persistent call history, independent of a connected reader and CallKit UI.
/// Only a real IMS Call-ID creates a row; early media is not an answered call.
class VoWifiCallStore {
  VoWifiCallStore({
    Future<Database> Function()? openDatabase,
    DateTime Function()? clock,
    String? sessionToken,
  }) : _openDatabase = openDatabase ?? (() => DatabaseService().database),
       _clock = clock ?? DateTime.now,
       _sessionToken = sessionToken ?? _processToken;

  final Future<Database> Function() _openDatabase;
  final DateTime Function() _clock;
  final String _sessionToken;
  static final String _processToken = DateTime.now().microsecondsSinceEpoch
      .toString();
  static final _changes = StreamController<void>.broadcast();
  static Stream<void> get changes => _changes.stream;
  Future<Database>? _ready;

  static const _terminal = {
    'idle',
    'unavailable',
    'ended',
    'failed',
    'rejected',
    'busy',
    'cancelled',
    'canceled',
    'interrupted',
  };
  static const _connected = {'active', 'established', 'connected'};

  Future<Database> _database() async {
    try {
      return await (_ready ??= _initialize());
    } catch (_) {
      _ready = null;
      rethrow;
    }
  }

  Future<Database> _initialize() async {
    final db = await _openDatabase();
    await db.transaction((tx) async {
      await tx.execute('''
        CREATE TABLE IF NOT EXISTS vowifi_calls (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          line_key TEXT NOT NULL,
          call_id TEXT NOT NULL,
          peer TEXT NOT NULL,
          direction TEXT NOT NULL,
          state TEXT NOT NULL,
          outcome TEXT NOT NULL,
          first_seen_at TEXT NOT NULL,
          connected_at TEXT,
          ended_at TEXT,
          last_seen_at TEXT NOT NULL,
          duration_seconds INTEGER NOT NULL DEFAULT 0,
          last_error TEXT NOT NULL DEFAULT '',
          session_token TEXT NOT NULL,
          UNIQUE(line_key, call_id)
        )
      ''');
      await tx.execute('''
        CREATE INDEX IF NOT EXISTS vowifi_calls_recent
        ON vowifi_calls(line_key, id DESC)
      ''');
      // An abruptly terminated app cannot know when the remote party ended.
      // Finish at the last observed snapshot, never at the next app launch.
      final abandoned = await tx.query(
        'vowifi_calls',
        where: 'ended_at IS NULL AND session_token != ?',
        whereArgs: [_sessionToken],
      );
      for (final row in abandoned) {
        await _interrupt(tx, row);
      }
    });
    await db.transaction((migration) async {
      final fields = await migration.rawQuery(
        'PRAGMA table_info(vowifi_calls)',
      );
      for (final name in ['is_read', 'deleted']) {
        if (!fields.any((field) => field['name'] == name)) {
          await migration.execute(
            'ALTER TABLE vowifi_calls ADD COLUMN $name INTEGER NOT NULL DEFAULT 0',
          );
        }
      }
    });
    return db;
  }

  Future<void> markRead(Set<int> ids) => _changeRecords(ids, {'is_read': 1});
  Future<void> deleteRecords(Set<int> ids) =>
      _changeRecords(ids, {'deleted': 1});
  Future<void> _changeRecords(Set<int> ids, Map<String, Object?> values) async {
    if (ids.isEmpty) return;
    final db = await _database();
    await db.transaction((tx) async {
      for (final id in ids) {
        await tx.update(
          'vowifi_calls',
          values,
          where: 'id = ?',
          whereArgs: [id],
        );
      }
    });
    _changes.add(null);
  }

  Future<List<Map<String, Object?>>> list([String? lineKey]) async {
    final db = await _database();
    return db.query(
      'vowifi_calls',
      where: lineKey == null ? 'deleted = 0' : 'deleted = 0 AND line_key = ?',
      whereArgs: lineKey == null ? null : [lineKey],
      orderBy: 'id DESC',
      limit: 200,
    );
  }

  Future<void> record({
    required String lineKey,
    required Map<String, dynamic> call,
  }) async {
    final callID = (call['call_id'] as String? ?? '').trim();
    if (lineKey.trim().isEmpty || callID.isEmpty) return;
    final state = call['state'] as String? ?? 'idle';
    final now = _clock().toUtc();
    final db = await _database();
    final changed = await db.transaction((tx) async {
      final rows = await tx.query(
        'vowifi_calls',
        where: 'line_key = ? AND call_id = ?',
        whereArgs: [lineKey, callID],
        limit: 1,
      );
      final existing = rows.isEmpty ? null : rows.single;
      // Finalization is monotonic: queued ring/active snapshots cannot revive
      // a finished dialog or rewrite its outcome and duration.
      if (existing?['ended_at'] != null) return false;
      final terminal = _terminal.contains(state);
      if (existing?['connected_at'] != null &&
          !terminal &&
          !_connected.contains(state)) {
        return false;
      }
      final direction =
          existing?['direction'] as String? ??
          (call['direction'] == 'incoming' ? 'incoming' : 'outgoing');
      DateTime? connected = _date(existing?['connected_at']);
      if (connected == null && (_connected.contains(state) || terminal)) {
        // mobilecore started_at is assigned on successful INVITE/ACK, not
        // dialing. A terminal snapshot may be our first observed snapshot.
        connected = _date(call['started_at']);
        if (connected != null && connected.isAfter(now)) connected = now;
        if (connected == null && _connected.contains(state)) connected = now;
      }
      final firstSeen = _date(existing?['first_seen_at']) ?? connected ?? now;
      final error =
          call['last_error'] as String? ??
          existing?['last_error'] as String? ??
          '';
      final outcome = !terminal
          ? (connected == null ? 'pending' : 'connected')
          : state == 'failed' || state == 'unavailable' || error.isNotEmpty
          ? 'failed'
          : state == 'interrupted'
          ? 'interrupted'
          : connected != null
          ? 'completed'
          : state == 'rejected' || state == 'busy'
          ? 'declined'
          : direction == 'incoming'
          ? 'missed'
          : 'unanswered';
      final values = <String, Object?>{
        'line_key': lineKey,
        'call_id': callID,
        'peer': call['peer'] as String? ?? existing?['peer'] as String? ?? '',
        'direction': direction,
        'state': state,
        'outcome': outcome,
        'first_seen_at': firstSeen.toIso8601String(),
        'connected_at': connected?.toIso8601String(),
        'ended_at': terminal ? now.toIso8601String() : null,
        'last_seen_at': now.toIso8601String(),
        'duration_seconds': _seconds(connected, now),
        'last_error': error,
        'session_token': _sessionToken,
      };
      if (existing == null) {
        if (!terminal) {
          // One IMS dialog per line is supported. If its final event was lost,
          // an actual new Call-ID closes the old observation conservatively.
          final previous = await tx.query(
            'vowifi_calls',
            where: 'line_key = ? AND ended_at IS NULL',
            whereArgs: [lineKey],
          );
          for (final row in previous) {
            await _interrupt(tx, row);
          }
        }
        await tx.insert('vowifi_calls', values);
      } else {
        await tx.update(
          'vowifi_calls',
          values,
          where: 'id = ?',
          whereArgs: [existing['id']],
        );
      }
      return true;
    });
    if (changed) _changes.add(null);
  }

  /// Use after native stop/disconnect, before discarding the SIM identity.
  /// No inferred successful completion when the final SIP event was lost.
  Future<void> finishActive({required String lineKey}) async {
    if (lineKey.trim().isEmpty) return;
    final db = await _database();
    final count = await db.transaction((tx) async {
      final rows = await tx.query(
        'vowifi_calls',
        where: 'line_key = ? AND ended_at IS NULL',
        whereArgs: [lineKey],
      );
      for (final row in rows) {
        await _interrupt(tx, row);
      }
      return rows.length;
    });
    if (count > 0) _changes.add(null);
  }

  static Future<void> _interrupt(
    Transaction tx,
    Map<String, Object?> row,
  ) async {
    final ended = _date(row['last_seen_at'])!;
    await tx.update(
      'vowifi_calls',
      {
        'state': 'interrupted',
        'outcome': 'interrupted',
        'ended_at': ended.toIso8601String(),
        'duration_seconds': _seconds(_date(row['connected_at']), ended),
      },
      where: 'id = ?',
      whereArgs: [row['id']],
    );
  }

  static DateTime? _date(Object? value) =>
      value is String ? DateTime.tryParse(value)?.toUtc() : null;

  static int _seconds(DateTime? connected, DateTime end) => connected == null
      ? 0
      : end.difference(connected).inSeconds.clamp(0, 1 << 31);
}
