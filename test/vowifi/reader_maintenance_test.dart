import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:logging/logging.dart';
import 'package:nlpa2/adapter/euicc_adapter.dart';
import 'package:nlpa2/vowifi/reader_lease.dart';

class _MaintenanceAdapter extends BaseAdapter
    implements CoordinatedReaderMaintenance {
  _MaintenanceAdapter() : super(Logger('MaintenanceTest'));
  ReaderMaintenanceRunner? runner;
  final commands = <int>[];
  int connects = 0;
  @override
  void setMaintenanceRunner(ReaderMaintenanceRunner? runner) =>
      this.runner = runner;
  @override
  Stream<EuiccPortState> get stateStream => const Stream.empty();
  @override
  bool get requiresRefresh => false;
  @override
  String? get lastAtr => null;
  @override
  Future<List<Reader>> listReaders({bool force = false}) async => [];
  @override
  Future<void> connect(Reader reader) async {
    connects++;
    updateConnectedReader(reader);
  }

  @override
  Future<void> disconnect() async => updateConnectedReader(null);
  @override
  Future<Channel> openChannel({List<String>? aids}) =>
      throw UnimplementedError();
  @override
  Future<Uint8List> sendRawApdu(Uint8List command) => runExclusive(() async {
    commands.add(command[0]);
    return Uint8List.fromList([0x90, 0]);
  });
  Future<void> ping() async {
    await runner!(() async {
      await sendRawApdu(Uint8List.fromList([0x99]));
    });
  }
}

void main() {
  test('keepalive joins lease but never interleaves an AKA batch', () async {
    final composite = _MaintenanceAdapter();
    final source = _MaintenanceAdapter();
    final reader = Reader(id: 'nine', name: 'Nine', source: source);
    composite.updateConnectedReader(reader);
    source.updateConnectedReader(reader);
    final lease = await VoWifiReaderLease.acquire(composite, reader);
    final selected = Completer<void>();
    final finishAuth = Completer<void>();
    try {
      final batch = lease.runBatch(() async {
        await lease.transmit(Uint8List.fromList([0xa4]));
        selected.complete();
        await finishAuth.future;
        await lease.transmit(Uint8List.fromList([0x88]));
      });
      await selected.future;
      final heartbeat = source.ping();
      await Future<void>.delayed(Duration.zero);
      expect(source.commands, [0xa4]);
      finishAuth.complete();
      await Future.wait([batch, heartbeat]);
      expect(source.commands, [0xa4, 0x88, 0x99]);
      // Maintenance progresses without surrendering the reader to management.
      await expectLater(
        source.runExclusiveNow(() async {}),
        throwsA(isA<ReaderBusyException>()),
      );
      await source.ping();
      expect(source.commands.last, 0x99);
    } finally {
      await lease.close();
    }
    expect(source.runner, isNull);
  });

  test(
    'busy acquisition has no deferred reconnect or native reservation',
    () async {
      final composite = _MaintenanceAdapter();
      final source = _MaintenanceAdapter();
      final reader = Reader(id: 'nine', name: 'Nine', source: source);
      composite.updateConnectedReader(reader);
      final release = Completer<void>();
      final entered = Completer<void>();
      final owner = composite.runExclusive(() async {
        entered.complete();
        await release.future;
      });
      await entered.future;
      await expectLater(
        VoWifiReaderLease.acquire(composite, reader),
        throwsA(isA<ReaderBusyException>()),
      );
      release.complete();
      await owner;
      await Future<void>.delayed(Duration.zero);
      expect(source.runner, isNull);
      expect(source.connects, 0);
    },
  );

  test(
    'closed lease rejects old heartbeat callback and frees both locks',
    () async {
      final composite = _MaintenanceAdapter();
      final source = _MaintenanceAdapter();
      final reader = Reader(id: 'nine', name: 'Nine', source: source);
      composite.updateConnectedReader(reader);
      source.updateConnectedReader(reader);
      final lease = await VoWifiReaderLease.acquire(composite, reader);
      final oldRunner = source.runner!;
      await lease.close();
      var ran = false;
      await expectLater(
        oldRunner(() async {
          ran = true;
        }),
        throwsStateError,
      );
      expect(ran, isFalse);
      await composite.runExclusiveNow(() async {});
      await source.runExclusiveNow(() async {});
      final next = await VoWifiReaderLease.acquire(composite, reader);
      try {
        // A late duplicate stop from the old service must not remove the new
        // session's transport keepalive runner.
        await lease.close();
        expect(source.runner, isNotNull);
        await source.ping();
      } finally {
        await next.close();
      }
    },
  );
}
