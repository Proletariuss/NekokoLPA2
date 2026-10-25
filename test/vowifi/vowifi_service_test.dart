import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:nlpa2/adapter/ble/red_ble_adapter.dart';
import 'package:nlpa2/adapter/euicc_adapter.dart';
import 'package:nlpa2/vowifi/message_store.dart';
import 'package:nlpa2/vowifi/call_store.dart';
import 'package:nlpa2/vowifi/notifications.dart';
import 'package:nlpa2/vowifi/vowifi_service.dart';

class _MessageStore extends VoWifiMessageStore {
  final records = <Map<String, Object?>>[];
  Completer<void>? commitGate;
  bool failCommit = false;
  final segments = <Map<String, Object?>>[];

  @override
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
    await commitGate?.future;
    if (failCommit) throw StateError('Storage unavailable');
    segments.add({
      'sim_id': simId,
      'concat_reference': concatReference,
      'concat_total': concatTotal,
      'concat_sequence': concatSequence,
    });
    return null;
  }

  @override
  Future<List<Map<String, Object?>>> list([String? lineKey]) async => records
      .where((row) => lineKey == null || row['line_key'] == lineKey)
      .toList();

  @override
  Future<VoWifiMessageInsert> addIncoming({
    required String lineKey,
    required String peer,
    required String content,
    required String messageId,
    String? at,
  }) async {
    await commitGate?.future;
    if (failCommit) throw StateError('Storage unavailable');
    final existing = records.indexWhere(
      (row) => row['line_key'] == lineKey && row['message_id'] == messageId,
    );
    if (existing >= 0) {
      return VoWifiMessageInsert(id: existing, inserted: false);
    }
    records.add({
      'line_key': lineKey,
      'peer': peer,
      'content': content,
      'direction': 'incoming',
      'state': 'received',
      'at': at,
      'message_id': messageId,
    });
    return VoWifiMessageInsert(id: records.length - 1, inserted: true);
  }

  @override
  Future<int> add({
    required String lineKey,
    required String peer,
    required String content,
    required String direction,
    required String state,
    String? at,
    String? messageId,
  }) async {
    await commitGate?.future;
    if (failCommit) throw StateError('Storage unavailable');
    if (messageId != null &&
        records.any(
          (row) => row['line_key'] == lineKey && row['message_id'] == messageId,
        )) {
      return 0;
    }
    records.add({
      'line_key': lineKey,
      'peer': peer,
      'content': content,
      'direction': direction,
      'state': state,
      'at': at,
      'message_id': messageId,
    });
    return records.length - 1;
  }

  @override
  Future<void> setState(int id, String state) async {
    records[id]['state'] = state;
  }
}

class _Notifications implements VoWifiNotifications {
  int permissionRequests = 0;
  bool permissionGranted = true;
  bool fail = false;
  Completer<void>? presentationGate;
  final shown = <({int messageId, String lineKey})>[];

  @override
  Future<bool> requestPermission() async {
    permissionRequests++;
    if (fail) throw StateError('Notification plugin unavailable');
    return permissionGranted;
  }

  @override
  Future<void> showIncoming({
    required int messageId,
    required String lineKey,
  }) async {
    shown.add((messageId: messageId, lineKey: lineKey));
    await presentationGate?.future;
    if (fail) throw StateError('Notification plugin unavailable');
  }
}

class _CallStore extends VoWifiCallStore {
  final recorded = <({String lineKey, Map<String, dynamic> call})>[];
  final finished = <String>[];
  Completer<void>? recordGate;
  bool fail = false;

  @override
  Future<void> record({
    required String lineKey,
    required Map<String, dynamic> call,
  }) async {
    await recordGate?.future;
    if (fail) throw StateError('Call database unavailable');
    recorded.add((lineKey: lineKey, call: call));
  }

  @override
  Future<void> finishActive({required String lineKey}) async {
    if (fail) throw StateError('Call database unavailable');
    finished.add(lineKey);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('test/vowifi');
  const codec = StandardMethodCodec();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  late VoWifiService service;
  late RedBleAdapter adapter;
  late int generation;
  late bool failStop;
  late _MessageStore messages;
  late _Notifications notifications;
  late _CallStore calls;
  Completer<void>? cardGate;
  Completer<void>? cardEntered;
  Future<dynamic> Function()? statusReply;
  Future<dynamic> Function()? startReply;
  Completer<void>? stopGate;
  late int stopCalls;
  final dispatchedCommands = <Map<String, dynamic>>[];

  Future<dynamic> receive(String method, Map<String, Object?> event) async {
    final complete = Completer<ByteData?>();
    await messenger.handlePlatformMessage(
      channel.name,
      codec.encodeMethodCall(MethodCall(method, jsonEncode(event))),
      complete.complete,
    );
    return codec.decodeEnvelope((await complete.future)!);
  }

  Future<void> emit(Map<String, Object?> event) async {
    await receive('event', event);
  }

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    generation = 0;
    failStop = false;
    cardGate = null;
    cardEntered = null;
    statusReply = null;
    startReply = null;
    stopGate = null;
    stopCalls = 0;
    dispatchedCommands.clear();
    adapter = RedBleAdapter();
    final reader = Reader(id: 'test', name: 'Test reader', source: adapter);
    adapter.updateConnectedReader(reader);
    messages = _MessageStore();
    notifications = _Notifications();
    calls = _CallStore();
    messenger.setMockMethodCallHandler(channel, (call) async {
      final values = call.arguments == null
          ? <String, dynamic>{}
          : jsonDecode(call.arguments as String) as Map<String, dynamic>;
      if (call.method == 'command') dispatchedCommands.add(values);
      if (call.method == 'command' && values['action'] == 'readCard') {
        generation = values['generation'] as int;
        cardEntered?.complete();
        await cardGate?.future;
        return jsonEncode({
          'imsi': '001010000000000',
          'iccid': 'test-card',
          'mcc': '001',
          'mnc': '01',
        });
      }
      if (call.method == 'stop') {
        stopCalls++;
        if (failStop) {
          throw PlatformException(
            code: 'STOP_FAILED',
            message: 'Native stop failed',
          );
        }
        await stopGate?.future;
      }
      if (call.method == 'status' && statusReply != null) {
        return await statusReply!();
      }
      if (call.method == 'start' && startReply != null) {
        return await startReply!();
      }
      if (call.method == 'stop' && cardGate != null && !cardGate!.isCompleted) {
        cardGate!.completeError(PlatformException(code: 'CANCELLED'));
      }
      return '{}';
    });
    service = VoWifiService(
      adapter: adapter,
      reader: reader,
      channel: channel,
      messages: messages,
      notifications: notifications,
      calls: calls,
    );
  });

  tearDown(() async {
    failStop = false;
    await service.stop();
    service.dispose();
    messenger.setMockMethodCallHandler(channel, null);
  });

  test(
    'checking blocks new work but preserves call controls and stop',
    () async {
      await service.start({});
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'messaging_ready': true,
        'call_ready': true,
        'checking_connection': true,
        'call': {'state': 'active', 'peer': '888'},
      });
      expect(service.checkingConnection, isTrue);
      expect(service.callReady, isFalse);
      expect(service.messagingReady, isFalse);
      expect(service.busy, isFalse);
      expect(service.inCall, isTrue);
      await expectLater(
        service.command('dial', {'peer': '888'}),
        throwsStateError,
      );
      await expectLater(
        service.command('sms', {'recipient': '888', 'text': 'Hi'}),
        throwsStateError,
      );
      await expectLater(service.sendSms('888', 'Hi'), throwsStateError);
      expect(messages.records, isEmpty);
      for (final action in ['answer', 'reject', 'hangup', 'dtmf']) {
        await service.command(action);
      }
      expect(dispatchedCommands.map((c) => c['action']), [
        'readCard',
        'answer',
        'reject',
        'hangup',
        'dtmf',
      ]);
      expect(
        dispatchedCommands.every((c) => c['generation'] == generation),
        isTrue,
      );
      await service.stop();
      expect(service.active, isFalse);
      expect(stopCalls, 1);
    },
  );

  test('verified native status restores outgoing readiness', () async {
    await service.start({});
    for (final flag in [
      'checking_connection',
      'status_uncertain',
      'retrying',
    ]) {
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'messaging_ready': true,
        'call_ready': true,
        flag: true,
      });
      expect(service.callReady, isFalse, reason: flag);
      expect(service.messagingReady, isFalse, reason: flag);
    }
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'ready',
      'registered': true,
      'messaging_ready': true,
      'call_ready': true,
      'checking_connection': false,
    });
    expect(service.callReady, isTrue);
    expect(service.messagingReady, isTrue);
    await service.command('dial', {'peer': '888'});
    await service.sendSms('888', 'Verified');
    expect(dispatchedCommands.map((c) => c['action']), [
      'readCard',
      'dial',
      'sms',
    ]);
    expect(messages.records.single['state'], 'submitted');
  });

  test(
    'connection check begun during SMS persistence prevents dispatch',
    () async {
      await service.start({});
      service.status = {'registered': true, 'messaging_ready': true};
      messages.commitGate = Completer<void>();
      final sending = service.sendSms('888', 'Pending');
      service.status = {...service.status, 'checking_connection': true};
      messages.commitGate!.complete();
      await expectLater(sending, throwsStateError);
      expect(messages.records.single['state'], 'failed');
      expect(dispatchedCommands.map((c) => c['action']), ['readCard']);
    },
  );

  test('status query recovery clears only its own error', () async {
    await service.start({});
    statusReply = () async => throw StateError('status unavailable');
    await service.refreshStatus();
    expect(service.error, contains('status unavailable'));
    expect(service.registered, isFalse);
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'ready',
      'registered': true,
    });
    expect(service.error, isNull);
    await emit({
      'type': 'native_error',
      'generation': generation,
      'source': 'audio',
      'error': 'Audio device unavailable',
    });
    await service.refreshStatus();
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'ready',
      'registered': true,
    });
    expect(service.error, 'Audio device unavailable');
  });

  test('old status query cannot overwrite a restarted session', () async {
    await service.start({});
    final reply = Completer<dynamic>();
    final entered = Completer<void>();
    statusReply = () {
      entered.complete();
      return reply.future;
    };
    final refresh = service.refreshStatus();
    await entered.future;
    await service.stop();
    await service.start({});
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'ready',
      'registered': true,
    });
    reply.completeError(StateError('stale failure'));
    await refresh;
    expect(service.registered, isTrue);
    expect(service.error, isNull);
  });

  test('new status event wins over an older pending query', () async {
    await service.start({});
    final reply = Completer<dynamic>();
    final entered = Completer<void>();
    statusReply = () {
      entered.complete();
      return reply.future;
    };
    final refresh = service.refreshStatus();
    await entered.future;
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'ready',
      'registered': true,
    });
    reply.completeError(StateError('stale failure'));
    await refresh;
    expect(service.registered, isTrue);
    expect(service.error, isNull);
  });

  test('successful retry clears the previous startup error', () async {
    await service.start({});
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'failed',
      'registered': false,
      'retrying': true,
      'error': 'IKE send failed',
    });
    expect(service.error, 'IKE send failed');
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'ready',
      'registered': true,
    });
    expect(service.error, isNull);
    expect(service.registered, isTrue);
  });

  test(
    'retry clears the old IMS error when the next IKE attempt starts',
    () async {
      await service.start({});
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'failed',
        'attempt': 1,
        'registered': false,
        'retrying': true,
        'error':
            'IMS incoming SIP listener ended: endpoint is in invalid state',
      });
      expect(service.error, contains('SIP listener'));
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ike',
        'attempt': 2,
        'registered': false,
      });
      expect(service.phase, 'ike');
      expect(service.error, isNull);
      await emit({
        'type': 'status',
        'generation': generation - 1,
        'phase': 'failed',
        'error': 'stale session error',
      });
      expect(service.phase, 'ike');
      expect(service.error, isNull);
    },
  );

  test('new attempt preserves an independent native audio error', () async {
    await service.start({});
    await emit({
      'type': 'native_error',
      'generation': generation,
      'source': 'audio',
      'error': 'Audio device unavailable',
    });
    await emit({
      'type': 'status',
      'generation': generation,
      'phase': 'ike',
      'attempt': 2,
      'registered': false,
    });
    expect(service.error, 'Audio device unavailable');
  });

  test('late start response does not overwrite a newer native event', () async {
    startReply = () async {
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ike',
        'attempt': 2,
        'registered': false,
      });
      return jsonEncode({
        'type': 'status',
        'generation': generation,
        'phase': 'failed',
        'attempt': 1,
        'error': 'old IMS failure',
      });
    };
    await service.start({});
    expect(service.phase, 'ike');
    expect(service.status['attempt'], 2);
    expect(service.error, isNull);
  });

  test('multipart carrier ACK waits for durable fragment commit', () async {
    await service.start({});
    messages.commitGate = Completer<void>();
    final storing = receive('storeSMS', {
      'generation': generation,
      'message_id': 'segment-one',
      'sender': '1033',
      'content': 'part',
      'sim_id': List.filled(64, 'a').join(),
      'concat_reference': 0,
      'concat_total': 2,
      'concat_sequence': 1,
      'at': '2026-10-10T03:00:00Z',
    });
    var acknowledged = false;
    unawaited(
      storing.then((_) {
        acknowledged = true;
      }),
    );
    await Future<void>.delayed(Duration.zero);
    expect(acknowledged, isFalse);
    messages.commitGate!.complete();
    expect(await storing, isTrue);
    expect(messages.segments.single['concat_reference'], 0);
    expect(messages.records, isEmpty);
    expect(notifications.shown, isEmpty);
  });

  test(
    'partial multipart metadata must not be acknowledged as complete SMS',
    () async {
      await service.start({});
      await expectLater(
        receive('storeSMS', {
          'generation': generation,
          'message_id': 'bad-segment',
          'sender': '1033',
          'content': 'part',
          'concat_total': 2,
        }),
        throwsA(isA<PlatformException>()),
      );
      expect(messages.records, isEmpty);
      expect(messages.segments, isEmpty);
    },
  );

  test(
    'registration status does not hide an independent audio error',
    () async {
      await service.start({});
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'failed',
        'error': 'IKE send failed',
      });
      await emit({
        'type': 'native_error',
        'generation': generation,
        'source': 'audio',
        'error': 'Audio device unavailable',
      });
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
      });
      expect(service.error, 'Audio device unavailable');
    },
  );

  test(
    'own number is visible only for current registered SIM and clears on stop',
    () async {
      await service.start({});
      final ready = <String, Object?>{
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'msisdn': '+441212345678',
        'mcc': '234',
        'mnc': '33',
      };
      expect(service.ownNumberDisplay, isNull);
      await emit(ready);
      expect(service.ownNumberDisplay, '🇬🇧 +441212345678');
      expect(service.ownPhoneNumber, '+441212345678');
      await emit({
        ...ready,
        'generation': generation - 1,
        'msisdn': '+85251234567',
      });
      expect(service.ownPhoneNumber, '+441212345678');
      await service.stop();
      await emit(ready);
      expect(service.ownPhoneNumber, isNull);
      expect(service.ownNumberDisplay, isNull);
    },
  );

  test(
    'registration loss or missing number never reuses previous displayed identity',
    () async {
      await service.start({});
      final ready = <String, Object?>{
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'msisdn': '01212345678',
        'mcc': '234',
      };
      await emit(ready);
      expect(service.ownPhoneNumber, '+441212345678');
      await emit({...ready, 'registered': false});
      expect(service.ownPhoneNumber, isNull);
      await emit({...ready, 'msisdn': ''});
      expect(service.ownPhoneNumber, isNull);
      await emit({...ready, 'msisdn': '00000000000'});
      expect(service.ownNumberDisplay, isNull);
      await emit({...ready, 'msisdn': '+85251234567'});
      expect(service.ownNumberDisplay, '🇭🇰 +85251234567');
    },
  );

  test(
    'ambiguous shared MCC cannot invent country code for a national number',
    () async {
      await service.start({});
      final ready = <String, Object?>{
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'msisdn': '696123456',
        'mcc': '340',
        'mnc': '01',
      };
      await emit(ready);
      expect(service.ownPhoneNumber, isNull);
      await emit({...ready, 'msisdn': '+596696123456'});
      expect(service.ownPhoneNumber, '+596696123456');
    },
  );

  test(
    'starting never invents registration and ignores stale events',
    () async {
      await service.start({});
      expect(service.active, true);
      expect(service.readerReady, true);
      expect(service.simReady, true);
      expect(service.registered, false);
      await emit({
        'type': 'status',
        'generation': generation - 1,
        'phase': 'ready',
        'registered': true,
        'messaging_ready': true,
      });
      expect(service.registered, false);
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'messaging_ready': true,
      });
      expect(service.registered, true);
      expect(service.messagingReady, true);
      expect(service.callReady, false);
    },
  );

  test(
    'registered session stays reserved until native Stop completes',
    () async {
      await service.start({});
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'messaging_ready': true,
        'call_ready': true,
      });
      stopGate = Completer<void>();
      final stopping = service.stop();
      final repeatedStop = service.stop();
      var managementEntered = false;
      final management = adapter.runExclusive(() async {
        managementEntered = true;
      });
      await Future<void>.delayed(Duration.zero);
      expect(service.stopping, isTrue);
      expect(service.active, isTrue);
      expect(service.phase, 'ready');
      expect(managementEntered, isFalse);
      expect(stopCalls, 1);

      stopGate!.complete();
      await Future.wait([stopping, repeatedStop, management]);
      expect(service.stopping, isFalse);
      expect(service.busy, isFalse);
      expect(service.active, isFalse);
      expect(service.registered, isFalse);
      expect(service.phase, 'stopped');
      expect(managementEntered, isTrue);
    },
  );

  test('reentrant Stop listener shares the pending native shutdown', () async {
    await service.start({});
    Future<void>? repeatedStop;
    var requested = false;
    void listener() {
      if (service.busy && !requested) {
        requested = true;
        repeatedStop = service.stop();
      }
    }

    service.addListener(listener);
    try {
      await service.stop();
      await repeatedStop;
      expect(requested, isTrue);
      expect(stopCalls, 1);
      expect(service.active, isFalse);
      expect(service.stopping, isFalse);
    } finally {
      service.removeListener(listener);
    }
  });

  test(
    'retains reader lock if native stop fails and releases after retry',
    () async {
      await service.start({});
      var managementEntered = false;
      final management = adapter.runExclusive(() async {
        managementEntered = true;
      });
      failStop = true;
      await expectLater(service.stop(), throwsA(isA<PlatformException>()));
      expect(service.active, true);
      expect(service.stopping, false);
      expect(managementEntered, false);
      failStop = false;
      await service.stop();
      await management;
      expect(service.active, false);
      expect(managementEntered, true);
      expect(service.registered, false);
      expect(service.error, isNull);
    },
  );

  test(
    'successful Stop retry preserves a newer independent native error',
    () async {
      await service.start({});
      failStop = true;
      await expectLater(service.stop(), throwsA(isA<PlatformException>()));
      await emit({
        'type': 'native_error',
        'generation': generation,
        'error': 'Audio route unavailable',
      });
      failStop = false;
      await service.stop();
      expect(service.error, 'Audio route unavailable');
      expect(service.active, isFalse);
    },
  );

  test(
    'cancels native card probing before waiting for startup completion',
    () async {
      cardGate = Completer<void>();
      cardEntered = Completer<void>();
      final starting = service.start({});
      await cardEntered!.future;
      await Future.wait([
        service.stop(),
        starting,
      ]).timeout(const Duration(seconds: 2));
      expect(service.active, false);
      expect(service.error, isNull);
    },
  );

  test(
    'stores received SMS and labels outgoing submission without delivery claim',
    () async {
      await service.start({});
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'messaging_ready': true,
      });
      await receive('storeSMS', {
        'type': 'sms',
        'generation': generation,
        'message_id': 'incoming-test-id',
        'sender': '+10000000000',
        'content': 'Test incoming message',
        'at': '2026-09-26T01:00:00Z',
      });
      await service.sendSms('+10000000000', 'Test outgoing message');
      expect(messages.records.map((row) => row['state']), [
        'received',
        'submitted',
      ]);
      expect(
        messages.records.every((row) => row['line_key'] == 'test-card'),
        true,
      );
    },
  );

  test(
    'SMS acknowledgement waits for commit and duplicate retries are idempotent',
    () async {
      await service.start({});
      final event = <String, Object?>{
        'type': 'sms',
        'generation': generation,
        'message_id': 'stable-id',
        'sender': '+10000000000',
        'content': 'Test',
      };
      messages.commitGate = Completer<void>();
      var acknowledged = false;
      final saving = receive('storeSMS', event).then((result) {
        acknowledged = true;
        expect(result, true);
      });
      await Future<void>.delayed(Duration.zero);
      expect(acknowledged, false);
      expect(notifications.shown, isEmpty);
      messages.commitGate!.complete();
      await saving;
      await receive('storeSMS', event);
      expect(messages.records.length, 1);
      expect(notifications.shown, hasLength(1));
      expect(notifications.shown.single.lineKey, 'test-card');
      messages.failCommit = true;
      await expectLater(
        receive('storeSMS', {...event, 'message_id': 'new-id'}),
        throwsA(
          isA<PlatformException>().having(
            (error) => error.code,
            'code',
            'SMS_STORAGE_FAILED',
          ),
        ),
      );
      expect(notifications.shown, hasLength(1));
    },
  );

  test(
    'notification presentation never holds carrier acknowledgement',
    () async {
      await service.start({});
      notifications.presentationGate = Completer<void>();
      final event = <String, Object?>{
        'type': 'sms',
        'generation': generation,
        'message_id': 'notify-once',
        'sender': '+10000000000',
        'content': 'Private verification code 123456',
      };
      expect(await receive('storeSMS', event), true);
      expect(notifications.presentationGate!.isCompleted, false);
      expect(await receive('storeSMS', event), true);
      expect(notifications.shown, hasLength(1));
      expect(notifications.permissionRequests, 0);
      notifications.presentationGate!.complete();
    },
  );

  test(
    'notification failure does not discard or redeliver saved SMS',
    () async {
      await service.start({});
      notifications.fail = true;
      final event = <String, Object?>{
        'type': 'sms',
        'generation': generation,
        'message_id': 'notification-unavailable',
        'sender': '+10000000000',
        'content': 'Saved despite a disabled notification plugin',
      };
      expect(await receive('storeSMS', event), true);
      await Future<void>.delayed(Duration.zero);
      expect(messages.records, hasLength(1));
      expect(await receive('storeSMS', event), true);
      expect(notifications.shown, hasLength(1));
      expect(service.error, isNull);
    },
  );

  test('notification authorization is explicit and optional', () async {
    notifications.permissionGranted = false;
    expect(await service.requestSmsNotifications(), false);
    expect(notifications.permissionRequests, 1);
    await service.start({});
    expect(service.lineKey, 'test-card');
    expect(service.simReady, true);
    expect(notifications.permissionRequests, 1);
    notifications.fail = true;
    expect(await service.requestSmsNotifications(), false);
    expect(service.error, isNull);
  });

  test('stale or disconnected SMS callbacks never store or notify', () async {
    await service.start({});
    final event = <String, Object?>{
      'type': 'sms',
      'generation': generation - 1,
      'message_id': 'stale-message',
      'sender': '+10000000000',
      'content': 'Old session',
    };
    await expectLater(
      receive('storeSMS', event),
      throwsA(isA<PlatformException>()),
    );
    await service.stop();
    await expectLater(
      receive('storeSMS', {...event, 'generation': generation}),
      throwsA(isA<PlatformException>()),
    );
    expect(messages.records, isEmpty);
    expect(notifications.shown, isEmpty);
  });

  test(
    'call snapshots keep their line and drain before finalizing at stop',
    () async {
      await service.start({});
      calls.recordGate = Completer<void>();
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'call': {
          'state': 'incoming',
          'call_id': 'call-a',
          'peer': '+10000000000',
        },
      });
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'call': {
          'state': 'active',
          'call_id': 'call-a',
          'started_at': '2026-09-26T01:02:03Z',
        },
      });
      var stopped = false;
      final stopping = service.stop().then((_) => stopped = true);
      await Future<void>.delayed(Duration.zero);
      expect(stopped, false);
      expect(calls.finished, isEmpty);
      calls.recordGate!.complete();
      await stopping;
      expect(calls.recorded.map((row) => row.call['state']), [
        'incoming',
        'active',
      ]);
      expect(calls.recorded.every((row) => row.lineKey == 'test-card'), true);
      expect(calls.finished, ['test-card']);
    },
  );

  test(
    'call-history failure is separate from IMS state and never holds reader lease',
    () async {
      await service.start({});
      calls.fail = true;
      await emit({
        'type': 'status',
        'generation': generation,
        'phase': 'ready',
        'registered': true,
        'call': {'state': 'outgoing', 'call_id': 'call-b'},
      });
      await Future<void>.delayed(Duration.zero);
      expect(service.registered, true);
      expect(service.callHistoryError, isNotNull);
      expect(service.error, isNull);
      await service.stop();
      expect(service.active, false);
      expect(service.error, isNull);
    },
  );
}
