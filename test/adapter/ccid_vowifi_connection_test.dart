import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/adapter/ccid/ccid_adapter.dart';
import 'package:nlpa2/adapter/composite_adapter.dart';
import 'package:nlpa2/adapter/euicc_adapter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('ccid');
  final command = Uint8List.fromList([0, 0x88, 0, 0, 0]);
  final disconnected = PlatformException(code: 'DISCONNECTED');
  late CcidAdapter adapter;
  late Reader reader;
  late List<String> methods;
  late Future<String?> Function() respond;

  setUp(() {
    adapter = CcidAdapter();
    reader = Reader(id: 'ccid:test', name: 'Test USB', source: adapter);
    methods = [];
    respond = () async => '9000';
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          methods.add(call.method);
          switch (call.method) {
            case 'connect':
              return '3B00';
            case 'disconnect':
              return null;
            case 'transceive':
              return respond();
            default:
              throw StateError('Unexpected native call ${call.method}');
          }
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test(
    'native USB loss invalidates lease transport without APDU replay',
    () async {
      await adapter.connect(reader);
      adapter.currentEid = 'cached';
      respond = () async => throw disconnected;
      await expectLater(
        adapter.sendRawApdu(command),
        throwsA(isA<PlatformException>()),
      );
      expect(adapter.connectedReader, isNull);
      expect(adapter.currentEid, isNull);
      expect(adapter.lastAtr, isNull);
      await expectLater(
        adapter.sendRawApdu(command),
        throwsA(isA<PlatformException>()),
      );
      expect(methods, ['connect', 'transceive']);
    },
  );

  test('old APDU loss cannot invalidate a new USB connection', () async {
    await adapter.connect(reader);
    final entered = Completer<void>();
    final release = Completer<void>();
    respond = () async {
      entered.complete();
      await release.future;
      throw disconnected;
    };
    final pending = expectLater(
      adapter.sendRawApdu(command),
      throwsA(isA<PlatformException>()),
    );
    await entered.future;
    await adapter.disconnect();
    await adapter.connect(reader);
    adapter.currentEid = 'new';
    release.complete();
    await pending;
    expect(adapter.connectedReader, same(reader));
    expect(adapter.currentEid, 'new');
    expect(adapter.lastAtr, '3B00');
  });

  test('composite repairs USB transport before another lease', () async {
    final composite = CompositeAdapter();
    addTearDown(composite.disconnect);
    await composite.connect(reader);
    respond = () async => throw disconnected;
    await expectLater(
      composite.sendRawApdu(command),
      throwsA(isA<PlatformException>()),
    );
    respond = () async => '9000';
    await composite.connect(reader);
    expect(methods.where((method) => method == 'connect'), hasLength(2));
    expect(adapter.connectedReader, same(reader));
    expect(await composite.sendRawApdu(command), [0x90, 0]);
  });
}
