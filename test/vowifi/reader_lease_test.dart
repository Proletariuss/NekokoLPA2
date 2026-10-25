import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:logging/logging.dart';
import 'package:nlpa2/adapter/euicc_adapter.dart';
import 'package:nlpa2/vowifi/reader_lease.dart';

class _Adapter extends BaseAdapter {
  _Adapter() : super(Logger('LeaseTest'));
  int transmitted = 0;
  @override
  Stream<EuiccPortState> get stateStream => const Stream.empty();
  @override
  bool get requiresRefresh => false;
  @override
  String? get lastAtr => null;
  @override
  Future<List<Reader>> listReaders({bool force = false}) async => [];
  @override
  Future<void> connect(Reader reader) async => updateConnectedReader(reader);
  @override
  Future<void> disconnect() async => updateConnectedReader(null);
  @override
  Future<Channel> openChannel({List<String>? aids}) =>
      throw UnimplementedError();
  @override
  Future<Uint8List> sendRawApdu(Uint8List apdu) async {
    transmitted++;
    return Uint8List.fromList([0x90, 0]);
  }
}

class _CompositeAdapter extends _Adapter {
  @override
  Future<void> connect(Reader reader) async {
    await reader.source.connect(reader);
    updateConnectedReader(reader);
  }

  @override
  Future<void> disconnect() async {
    final reader = connectedReader;
    if (reader != null) await reader.source.disconnect();
    updateConnectedReader(null);
  }
}

void main() {
  test(
    'UI source refresh cannot redirect AKA to an unconnected adapter',
    () async {
      final adapter = _Adapter();
      final original = _Adapter();
      final replacement = _Adapter();
      final reader = Reader(id: 'red', name: 'ESTKme Red', source: original);
      adapter.updateConnectedReader(reader);
      original.updateConnectedReader(reader);
      final lease = await VoWifiReaderLease.acquire(adapter, reader);
      try {
        reader.source = replacement;
        expect(identical(lease.source, original), isTrue);
        expect(await lease.transmit(Uint8List.fromList([0, 0x88, 0, 0, 0])), [
          0x90,
          0,
        ]);
        expect(original.transmitted, 1);
        expect(replacement.transmitted, 0);
      } finally {
        await lease.close();
      }
    },
  );
  test(
    'native callbacks use a reserved reader while other operations wait',
    () async {
      final adapter = _Adapter();
      final source = _Adapter();
      final reader = Reader(id: 'test', name: 'Test reader', source: source);
      adapter.updateConnectedReader(reader);
      source.updateConnectedReader(reader);
      final lease = await VoWifiReaderLease.acquire(adapter, reader);
      var compositeEntered = false;
      var sourceEntered = false;
      final compositeWork = adapter.runExclusive(() async {
        compositeEntered = true;
      });
      final sourceWork = source.runExclusive(() async {
        sourceEntered = true;
      });
      await Future<void>.delayed(Duration.zero);
      expect(compositeEntered, false);
      expect(sourceEntered, false);
      expect(await lease.transmit(Uint8List.fromList([0, 0xb0, 0, 0, 9])), [
        0x90,
        0,
      ]);
      await lease.close();
      await Future.wait([compositeWork, sourceWork]);
      expect(compositeEntered, true);
      expect(sourceEntered, true);
      expect(() => lease.transmit(Uint8List(5)), throwsStateError);
    },
  );

  test(
    'refuses to reconnect or silently substitute the selected reader',
    () async {
      final adapter = _Adapter();
      final source = _Adapter();
      final reader = Reader(id: 'old', name: 'Old reader', source: source);
      adapter.updateConnectedReader(
        Reader(id: 'new', name: 'New reader', source: source),
      );
      await expectLater(
        VoWifiReaderLease.acquire(adapter, reader),
        throwsStateError,
      );
      var entered = false;
      await adapter.runExclusive(() async {
        entered = true;
      });
      expect(entered, true);
    },
  );

  test(
    'repairs a stale composite selection after the BLE transport drops',
    () async {
      final adapter = _CompositeAdapter();
      final source = _Adapter();
      final reader = Reader(
        id: 'ble-reader',
        name: 'BLE reader',
        source: source,
      );
      // Simulate the UI retaining the selection after the BLE adapter has
      // reported a link loss and cleared its own transport state.
      adapter.updateConnectedReader(reader);
      expect(source.connectedReader, isNull);

      final lease = await VoWifiReaderLease.acquire(adapter, reader);
      expect(source.connectedReader?.id, reader.id);
      await lease.close();
    },
  );
}
