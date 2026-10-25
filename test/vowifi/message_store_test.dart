import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  sqfliteFfiInit();
  late Database database;
  late VoWifiMessageStore store;

  setUp(() async {
    database = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    store = VoWifiMessageStore(openDatabase: () async => database);
  });

  tearDown(() async => database.close());

  test('read and delete persist and stay isolated by SIM', () async {
    final a = await store.add(
      lineKey: 'a',
      peer: '1033',
      content: 'one',
      direction: 'incoming',
      state: 'received',
    );
    final b = await store.add(
      lineKey: 'b',
      peer: '1033',
      content: 'two',
      direction: 'incoming',
      state: 'received',
    );
    await store.markRead({a});
    final reopened = VoWifiMessageStore(openDatabase: () async => database);
    expect((await reopened.list('a')).single['is_read'], 1);
    expect((await reopened.list('b')).single['is_read'], 0);
    await reopened.deleteRecords({a});
    expect(await reopened.list('a'), isEmpty);
    expect((await reopened.list('b')).single['id'], b);
  });

  Future<VoWifiMessageInsert> incoming(
    VoWifiMessageStore target, {
    String line = 'line-a',
    String identity = 'carrier-message',
    String content = 'Private message',
  }) => target.addIncoming(
    lineKey: line,
    peer: '+10000000000',
    content: content,
    messageId: identity,
  );

  test(
    'delete only confirmed IDs, preserving hidden same-peer messages and new arrivals',
    () async {
      final incomingId = await store.add(
        lineKey: 'a',
        peer: '1033',
        content: 'hidden incoming',
        direction: 'incoming',
        state: 'received',
      );
      final outgoingId = await store.add(
        lineKey: 'a',
        peer: '1033',
        content: 'selected outgoing',
        direction: 'outgoing',
        state: 'submitted',
      );
      final selected = <int>{outgoingId};
      final newArrival = await store.add(
        lineKey: 'a',
        peer: '1033',
        content: 'new arrival',
        direction: 'incoming',
        state: 'received',
      );
      final deletion = store.deleteRecords(selected);
      selected
        ..clear()
        ..add(incomingId)
        ..add(newArrival);
      await deletion;
      final reopened = VoWifiMessageStore(openDatabase: () async => database);
      expect((await reopened.list()).map((row) => row['id']).toSet(), {
        incomingId,
        newArrival,
      });
      await reopened.markRead({newArrival});
      expect(
        (await reopened.list()).every((row) => row['is_read'] == 1),
        isTrue,
      );
    },
  );

  test(
    'deleting the displayed 200 records preserves older records beyond the list limit',
    () async {
      await store.list();
      await database.transaction((tx) async {
        for (var index = 1; index <= 202; index++) {
          await tx.insert('vowifi_messages', {
            'id': index,
            'line_key': 'a',
            'peer': '1033',
            'content': 'message $index',
            'direction': 'incoming',
            'state': 'received',
            'at': '2026-10-23T00:00:00Z',
          });
        }
      });
      final displayed = await store.list();
      expect(displayed, hasLength(200));
      await store.deleteRecords(
        displayed.map((row) => row['id'] as int).toSet(),
      );
      expect((await store.list()).map((row) => row['id']).toSet(), {1, 2});
    },
  );

  test(
    'duplicates preserve the first row and expose a committed insert flag',
    () async {
      final first = await incoming(store);
      await store.add(
        lineKey: 'line-a',
        peer: '+20000000000',
        content: 'Other row',
        direction: 'outgoing',
        state: 'submitted',
      );
      final duplicate = await incoming(store, content: 'Do not overwrite');
      expect(first.inserted, true);
      expect(duplicate.inserted, false);
      expect(duplicate.id, first.id);
      final rows = await store.list('line-a');
      expect(rows, hasLength(2));
      expect(
        rows.singleWhere((row) => row['id'] == first.id)['content'],
        'Private message',
      );
    },
  );

  test(
    'message identities are scoped to the line and all-line inbox needs no reader',
    () async {
      await incoming(store);
      final secondLine = await incoming(store, line: 'line-b');
      expect(secondLine.inserted, true);
      expect(await store.list(), hasLength(2));
      expect(await store.list('line-a'), hasLength(1));
      expect(await store.list('missing-line'), isEmpty);
    },
  );

  test(
    'simultaneous store instances insert and publish a message only once',
    () async {
      final other = VoWifiMessageStore(openDatabase: () async => database);
      var changes = 0;
      final subscription = VoWifiMessageStore.changes.listen((_) => changes++);
      final results = await Future.wait([incoming(store), incoming(other)]);
      await Future<void>.delayed(Duration.zero);
      expect(results.where((result) => result.inserted), hasLength(1));
      expect(results.first.id, results.last.id);
      expect(changes, 1);
      expect(await other.list(), hasLength(1));
      await subscription.cancel();
    },
  );

  test(
    'failed writes publish no change and successful state updates refresh the inbox',
    () async {
      await store.list();
      await database.execute('''
      CREATE TRIGGER reject_test_message BEFORE INSERT ON vowifi_messages
      WHEN NEW.content = 'reject'
      BEGIN SELECT RAISE(ABORT, 'test storage failure'); END
    ''');
      final observed = <int>[];
      final subscription = VoWifiMessageStore.changes.listen(
        (_) => observed.add(1),
      );
      await expectLater(
        incoming(store, content: 'reject'),
        throwsA(isA<DatabaseException>()),
      );
      await Future<void>.delayed(Duration.zero);
      expect(observed, isEmpty);
      expect(await store.list(), isEmpty);
      final result = await incoming(store);
      await store.setState(result.id, 'received');
      await Future<void>.delayed(Duration.zero);
      expect(observed, hasLength(2));
      await subscription.cancel();
    },
  );

  test(
    'migrates earlier SMS tables without changing their existing messages',
    () async {
      await database.execute('''
      CREATE TABLE vowifi_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, line_key TEXT NOT NULL,
        peer TEXT NOT NULL, content TEXT NOT NULL, direction TEXT NOT NULL,
        state TEXT NOT NULL, at TEXT NOT NULL
      )
    ''');
      await database.insert('vowifi_messages', {
        'line_key': 'line-a',
        'peer': '+10000000000',
        'content': 'Older message',
        'direction': 'incoming',
        'state': 'received',
        'at': '2026-09-26T00:00:00Z',
      });
      await incoming(store);
      expect((await store.list()).map((row) => row['content']), [
        'Private message',
        'Older message',
      ]);
      expect((await incoming(store)).inserted, false);
    },
  );

  test(
    'deduplication survives database close and a new store instance',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'vowifi-message-store-',
      );
      final path = '${directory.path}/messages.sqlite';
      var durable = await databaseFactoryFfi.openDatabase(path);
      try {
        final firstStore = VoWifiMessageStore(
          openDatabase: () async => durable,
        );
        final first = await incoming(firstStore);
        await durable.close();
        durable = await databaseFactoryFfi.openDatabase(path);
        final reopened = VoWifiMessageStore(openDatabase: () async => durable);
        final duplicate = await incoming(reopened);
        expect(duplicate.inserted, false);
        expect(duplicate.id, first.id);
        expect(await reopened.list(), hasLength(1));
      } finally {
        await durable.close();
        await directory.delete(recursive: true);
      }
    },
  );
}
