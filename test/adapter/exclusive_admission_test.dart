import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:logging/logging.dart';
import 'package:nlpa2/adapter/composite_adapter.dart';
import 'package:nlpa2/adapter/euicc_adapter.dart';

class _ReaderAdapter extends BaseAdapter {
  _ReaderAdapter() : super(Logger('ExclusiveAdmissionTest'));
  int connections = 0;
  int disconnections = 0;
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
    connections++;
    updateConnectedReader(reader);
  }

  @override
  Future<void> disconnect() async {
    disconnections++;
    updateConnectedReader(null);
  }

  @override
  Future<Channel> openChannel({List<String>? aids}) =>
      throw UnimplementedError();
  @override
  Future<Uint8List> sendRawApdu(Uint8List apdu) async => Uint8List(0);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('expired owner zone cannot enter a later exclusive operation', () async {
    final adapter = _ReaderAdapter();
    late Zone expired;
    await adapter.runExclusive(() async {
      expired = Zone.current;
      expect(adapter.isExclusivelyBusy, isFalse);
      await adapter.runExclusiveNow(() async {});
    });
    final entered = Completer<void>();
    final release = Completer<void>();
    final owner = adapter.runExclusive(() async {
      entered.complete();
      await release.future;
    });
    await entered.future;
    var detachedEntered = false;
    final detached = expired.run(
      () => adapter.runExclusive(() async {
        detachedEntered = true;
      }),
    );
    await Future<void>.delayed(Duration.zero);
    expect(detachedEntered, isFalse);
    await expectLater(
      expired.run(
        () => adapter.runExclusiveNow(() async {
          fail('Stale ownership cannot bypass fail-fast admission');
        }),
      ),
      throwsA(isA<ReaderBusyException>()),
    );
    release.complete();
    await Future.wait([owner, detached]);
    expect(detachedEntered, isTrue);
  });

  test('busy admission never executes a rejected operation later', () async {
    final adapter = _ReaderAdapter();
    final release = Completer<void>();
    final entered = Completer<void>();
    final owner = adapter.runExclusive(() async {
      entered.complete();
      await release.future;
    });
    await entered.future;
    expect(adapter.isExclusivelyBusy, isTrue);
    var ran = false;
    await expectLater(
      adapter.runExclusiveNow(() async {
        ran = true;
      }),
      throwsA(isA<ReaderBusyException>()),
    );
    release.complete();
    await owner;
    await Future<void>.delayed(Duration.zero);
    expect(ran, isFalse);
    expect(adapter.isExclusivelyBusy, isFalse);
    await adapter.runExclusiveNow(() async {
      ran = true;
    });
    expect(ran, isTrue);
  });

  test('throwing owner releases admission without stale permission', () async {
    final adapter = _ReaderAdapter();
    await expectLater(
      adapter.runExclusiveNow(() async {
        throw StateError('expected');
      }),
      throwsStateError,
    );
    expect(adapter.isExclusivelyBusy, isFalse);
    await adapter.runExclusiveNow(() async {});
  });

  test(
    'composite repairs stale same-id connection and explicit reconnect',
    () async {
      final composite = CompositeAdapter();
      final source = _ReaderAdapter();
      final reader = Reader(id: 'fake-red', name: 'Fake RED', source: source);
      try {
        await composite.connect(reader);
        await composite.connect(reader);
        expect(source.connections, 1);
        source.updateConnectedReader(null);
        await composite.connect(reader);
        expect(source.connections, 2);
        expect(source.connectedReader, same(reader));
        source.updateConnectedReader(null);
        await composite.reconnect();
        expect(source.connections, 3);
        expect(source.connectedReader, same(reader));
      } finally {
        await composite.disconnect();
      }
    },
  );

  test(
    'composite connection waits for reserved source before transport work',
    () async {
      final composite = CompositeAdapter();
      final source = _ReaderAdapter();
      final reader = Reader(id: 'reserved-red', name: 'RED', source: source);
      final entered = Completer<void>();
      final release = Completer<void>();
      final owner = source.runExclusive(() async {
        entered.complete();
        await release.future;
      });
      await entered.future;
      final connect = composite.connect(reader);
      await Future<void>.delayed(Duration.zero);
      expect(source.connections, 0);
      expect(source.disconnections, 0);
      release.complete();
      await Future.wait([owner, connect]);
      expect(source.connections, 1);
      await composite.disconnect();
    },
  );

  test(
    'composite disconnect waits for reserved source without touching transport',
    () async {
      final composite = CompositeAdapter();
      final source = _ReaderAdapter();
      final reader = Reader(id: 'reserved-usb', name: 'USB', source: source);
      await composite.connect(reader);
      final entered = Completer<void>();
      final release = Completer<void>();
      final owner = source.runExclusive(() async {
        entered.complete();
        await release.future;
      });
      await entered.future;
      final disconnect = composite.disconnect();
      await Future<void>.delayed(Duration.zero);
      expect(source.disconnections, 0);
      release.complete();
      await Future.wait([owner, disconnect]);
      expect(source.disconnections, 1);
    },
  );
}
