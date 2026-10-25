import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:nlpa2/vowifi/call_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  sqfliteFfiInit();
  late Database database;
  late VoWifiCallStore store;
  late DateTime now;

  setUp(() async {
    database = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    now = DateTime.utc(2026, 9, 26, 10);
    store = VoWifiCallStore(
      openDatabase: () async => database,
      clock: () => now,
      sessionToken: 'test-session',
    );
  });

  tearDown(() async => database.close());

  Future<void> record(
    String state, {
    String id = 'call-1',
    String line = 'sim-1',
    String direction = 'incoming',
    String? connectedAt,
    String? error,
    bool early = false,
  }) => store.record(
    lineKey: line,
    call: {
      'call_id': id,
      'state': state,
      'direction': direction,
      'peer': '+441234567890',
      'early_media': early,
      'media_ready': early,
      'started_at': ?connectedAt,
      'last_error': ?error,
    },
  );

  test('no history is synthesized before IMS supplies a Call-ID', () async {
    await record('active', id: '');
    await record('active', line: '');
    expect(await store.list(), isEmpty);
  });

  test(
    'early media and ringing are not counted as connected duration',
    () async {
      await record('outgoing', direction: 'outgoing');
      now = now.add(const Duration(seconds: 10));
      await record('early', direction: 'outgoing', early: true);
      now = now.add(const Duration(seconds: 30));
      await record('ended', direction: 'outgoing');
      final row = (await store.list()).single;
      expect(row['outcome'], 'unanswered');
      expect(row['connected_at'], isNull);
      expect(row['duration_seconds'], 0);
    },
  );

  test(
    'duration starts at Go active started_at and finalization is monotonic',
    () async {
      await record('incoming');
      now = now.add(const Duration(seconds: 20));
      final answered = now.toIso8601String();
      await record('active', connectedAt: answered);
      now = now.add(const Duration(seconds: 35));
      await record('ended', connectedAt: answered);
      now = now.add(const Duration(minutes: 10));
      await record('incoming');
      await record('failed', error: 'late callback');
      final row = (await store.list()).single;
      expect(row['direction'], 'incoming');
      expect(row['outcome'], 'completed');
      expect(row['duration_seconds'], 35);
      expect(row['last_error'], '');
      expect(
        row['first_seen_at'],
        DateTime.utc(2026, 9, 26, 10).toIso8601String(),
      );
    },
  );

  test('missed and failed calls remain distinct', () async {
    await record('incoming');
    await record('ended');
    await record('outgoing', id: 'call-2', direction: 'outgoing');
    await record(
      'failed',
      id: 'call-2',
      direction: 'outgoing',
      error: 'SIP 487',
    );
    final rows = await store.list();
    expect(rows.map((row) => row['outcome']), ['failed', 'missed']);
    expect(rows.first['last_error'], 'SIP 487');
  });

  test('terminal-only snapshot retains real connected timestamp', () async {
    final answered = now.subtract(const Duration(seconds: 17));
    await record('ended', connectedAt: answered.toIso8601String());
    final row = (await store.list()).single;
    expect(row['outcome'], 'completed');
    expect(row['duration_seconds'], 17);
  });

  test('same Call-ID is independent for each SIM', () async {
    await record('incoming', line: 'sim-1');
    await record('outgoing', line: 'sim-2', direction: 'outgoing');
    await record('ended', line: 'sim-1');
    expect((await store.list('sim-1')).single['outcome'], 'missed');
    expect((await store.list('sim-2')).single['outcome'], 'pending');
  });

  test(
    'disconnect marks unfinished calls interrupted, not successful',
    () async {
      await record('active', connectedAt: now.toIso8601String());
      now = now.add(const Duration(seconds: 12));
      await record('active');
      await store.finishActive(lineKey: 'sim-1');
      final row = (await store.list()).single;
      expect(row['outcome'], 'interrupted');
      expect(row['duration_seconds'], 12);
    },
  );

  test(
    'new app session recovers unfinished call at last observation time',
    () async {
      final answered = now.toIso8601String();
      await record('active', connectedAt: answered);
      now = now.add(const Duration(seconds: 5));
      await record('active');
      final lastSeen = now.toIso8601String();
      now = now.add(const Duration(days: 2));
      final reopened = VoWifiCallStore(
        openDatabase: () async => database,
        clock: () => now,
        sessionToken: 'restarted-session',
      );
      final row = (await reopened.list()).single;
      expect(row['outcome'], 'interrupted');
      expect(row['ended_at'], lastSeen);
      expect(row['duration_seconds'], 5);
    },
  );

  test('opening history within same app does not end a live call', () async {
    await record('active');
    final anotherViewStore = VoWifiCallStore(
      openDatabase: () async => database,
      sessionToken: 'test-session',
    );
    expect((await anotherViewStore.list()).single['outcome'], 'connected');
    expect((await anotherViewStore.list()).single['ended_at'], isNull);
  });

  test('new real call closes missing final snapshot conservatively', () async {
    await record('incoming');
    await record('incoming', id: 'call-2');
    final rows = await store.list();
    expect(rows.first['outcome'], 'pending');
    expect(rows.last['outcome'], 'interrupted');
  });
}
