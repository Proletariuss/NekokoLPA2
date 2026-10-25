import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

const _simA =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const _simB =
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

Future<VoWifiMessageInsert?> _part(
  VoWifiMessageStore store,
  int sequence, {
  String line = 'reader-line',
  String sim = _simA,
  String peer = '1033',
  int reference = 7,
  int total = 2,
  String? id,
  String? text,
  String? at = '2026-10-10T04:00:00Z',
}) => store.addIncomingSegment(
  lineKey: line,
  simId: sim,
  peer: peer,
  content: text ?? 'part$sequence',
  messageId: id ?? '$line-$sim-$peer-$reference-$total-$sequence-$at',
  concatReference: reference,
  concatTotal: total,
  concatSequence: sequence,
  at: at,
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  sqfliteFfiInit();
  late Database db;
  late VoWifiMessageStore store;
  setUp(() async {
    db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    store = VoWifiMessageStore(openDatabase: () async => db);
  });
  tearDown(() async => db.close());

  test(
    'out-of-order segments assemble once, never publish partial text',
    () async {
      var changes = 0;
      final subscription = VoWifiMessageStore.changes.listen((_) => changes++);
      try {
        expect(await _part(store, 2), isNull);
        expect(await store.list(), isEmpty);
        final result = await _part(store, 1);
        expect(result?.inserted, isTrue);
        expect((await store.list()).single['content'], 'part1part2');
        final duplicate = await _part(store, 2);
        expect(duplicate?.id, result?.id);
        expect(duplicate?.inserted, isFalse);
        await Future<void>.delayed(Duration.zero);
        expect(changes, 1);
      } finally {
        await subscription.cancel();
      }
    },
  );

  test(
    'incomplete parts and receipts survive a real database restart',
    () async {
      final directory = await Directory.systemTemp.createTemp('multipart-sms-');
      final path = '${directory.path}/messages.sqlite';
      var durable = await databaseFactoryFfi.openDatabase(path);
      try {
        var reopened = VoWifiMessageStore(openDatabase: () async => durable);
        expect(await _part(reopened, 2), isNull);
        await durable.close();
        durable = await databaseFactoryFfi.openDatabase(path);
        reopened = VoWifiMessageStore(openDatabase: () async => durable);
        expect(await _part(reopened, 2), isNull);
        expect(await reopened.list(), isEmpty);
        expect((await _part(reopened, 1))?.inserted, isTrue);
        expect((await reopened.list()).single['content'], 'part1part2');
      } finally {
        await durable.close();
        await directory.delete(recursive: true);
      }
    },
  );

  test(
    'equal text in different sequences is not dropped by deduplication',
    () async {
      await _part(store, 1, text: 'same');
      final result = await _part(store, 2, text: 'same');
      expect(result?.inserted, isTrue);
      expect((await store.list()).single['content'], 'samesame');
    },
  );

  test(
    'SIM, reader line, sender, reference and total isolate groups',
    () async {
      await _part(store, 1, text: 'a1');
      await _part(store, 1, sim: _simB, text: 'b1');
      await _part(store, 1, line: 'other-reader', text: 'c1');
      await _part(store, 1, peer: '888', text: 'd1');
      await _part(store, 1, reference: 8, text: 'e1');
      await _part(store, 1, total: 3, text: 'f1');
      await _part(store, 2, text: 'a2');
      await _part(store, 2, sim: _simB, text: 'b2');
      await _part(store, 2, line: 'other-reader', text: 'c2');
      await _part(store, 2, peer: '888', text: 'd2');
      await _part(store, 2, reference: 8, text: 'e2');
      await _part(store, 2, total: 3, text: 'f2');
      expect(await store.list(), hasLength(5));
      await _part(store, 3, total: 3, text: 'f3');
      expect((await store.list()).map((row) => row['content']).toSet(), {
        'a1a2',
        'b1b2',
        'c1c2',
        'd1d2',
        'e1e2',
        'f1f2f3',
      });
    },
  );

  test('completed references may be reused with fresh SCTS', () async {
    await _part(store, 1);
    final first = await _part(store, 2);
    await _part(store, 2, text: 'new2', at: '2026-10-10T04:00:10Z');
    final second = await _part(
      store,
      1,
      text: 'new1',
      at: '2026-10-10T04:00:10Z',
    );
    expect(second?.inserted, isTrue);
    expect(second?.id, isNot(first?.id));
    expect((await store.list()).map((row) => row['content']), [
      'new1new2',
      'part1part2',
    ]);
  });

  test('deleted completed messages never reappear after redelivery', () async {
    await _part(store, 1);
    final message = await _part(store, 2);
    await store.deleteRecords({message!.id});
    expect((await _part(store, 1))?.inserted, isFalse);
    expect(
      (await _part(store, 2, id: 'new-carrier-transaction'))?.inserted,
      isFalse,
    );
    expect(await store.list(), isEmpty);
  });

  test(
    'incomplete reference reuse outside five minute SCTS window is separate',
    () async {
      await _part(store, 1);
      expect(await _part(store, 2, at: '2026-10-10T04:06:00Z'), isNull);
      expect(await store.list(), isEmpty);
      expect((await _part(store, 2))?.inserted, isTrue);
      expect(
        (await _part(store, 1, at: '2026-10-10T04:06:00Z'))?.inserted,
        isTrue,
      );
      expect(await store.list(), hasLength(2));
    },
  );

  test('ambiguous SCTS and conflicting sequence fail closed', () async {
    await _part(store, 1);
    await expectLater(
      _part(store, 1, id: 'changed', text: 'wrong'),
      throwsStateError,
    );
    await expectLater(
      _part(store, 1, id: 'time-changed', at: '2026-10-10T04:00:01Z'),
      throwsStateError,
    );
    await _part(store, 1, at: '2026-10-10T04:06:00Z');
    await expectLater(
      _part(store, 2, at: '2026-10-10T04:03:00Z'),
      throwsStateError,
    );
    expect(await store.list(), isEmpty);
    expect(await db.query('vowifi_sms_parts'), hasLength(2));
  });

  test('reused network identity cannot silently replace a segment', () async {
    await _part(store, 1, id: 'carrier-id');
    await expectLater(_part(store, 2, id: 'carrier-id'), throwsStateError);
    expect(await store.list(), isEmpty);
    expect(await db.query('vowifi_sms_parts'), hasLength(1));
  });

  test(
    'assembly transaction rolls back final receipt on persistence failure',
    () async {
      await _part(store, 1);
      await db.execute('''
      CREATE TRIGGER reject_assembly BEFORE INSERT ON vowifi_messages
      BEGIN SELECT RAISE(ABORT, 'test storage failure'); END
    ''');
      await expectLater(_part(store, 2), throwsA(isA<DatabaseException>()));
      expect(await db.query('vowifi_sms_parts'), hasLength(1));
      expect(await db.query('vowifi_sms_part_receipts'), hasLength(1));
      await db.execute('DROP TRIGGER reject_assembly');
      expect((await _part(store, 2))?.inserted, isTrue);
    },
  );

  test('simultaneous final deliveries produce exactly one inbox row', () async {
    await _part(store, 1);
    final other = VoWifiMessageStore(openDatabase: () async => db);
    final results = await Future.wait([_part(store, 2), _part(other, 2)]);
    expect(results.where((result) => result?.inserted ?? false), hasLength(1));
    expect(results.first?.id, results.last?.id);
    expect(await store.list(), hasLength(1));
  });

  test('malformed multipart metadata is rejected before storage', () async {
    for (final operation in <Future<VoWifiMessageInsert?> Function()>[
      () => _part(store, 0),
      () => _part(store, 3),
      () => _part(store, 1, total: 1),
      () => _part(store, 1, total: 256),
      () => _part(store, 1, reference: -1),
      () => _part(store, 1, reference: 65536),
      () => _part(store, 1, sim: ''),
      () => _part(store, 1, at: null),
      () => _part(store, 1, at: 'not-a-time'),
      () => _part(store, 1, at: '2026-10-10T04:00:00'),
    ]) {
      await expectLater(operation(), throwsArgumentError);
    }
    expect(await store.list(), isEmpty);
  });
}
