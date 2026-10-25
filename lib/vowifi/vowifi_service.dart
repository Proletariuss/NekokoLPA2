import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../adapter/ble/red_ble_adapter.dart';
import '../adapter/ble/red_ble2_adapter.dart';
import '../adapter/ccid/ccid_adapter.dart';
import '../adapter/euicc_adapter.dart';
import '../utils/mcc_mapper.dart';
import 'apdu_exchange.dart';
import 'call_store.dart';
import 'connection_diagnostics.dart';
import 'message_store.dart';
import 'notifications.dart';
import 'reader_lease.dart';
import 'settings_store.dart';
import 'subscriber_number.dart';

class VoWifiService extends ChangeNotifier {
  VoWifiService({
    required this.adapter,
    required this.reader,
    String? profileIccid,
    MethodChannel? channel,
    VoWifiMessageStore? messages,
    VoWifiNotifications? notifications,
    VoWifiCallStore? calls,
  }) : _channel = channel ?? const MethodChannel('proletarius/vowifi'),
       _messages = messages ?? VoWifiMessageStore(),
       _notifications = notifications ?? const LocalVoWifiNotifications(),
       _calls = calls ?? VoWifiCallStore(),
       _lineKey = profileIccid ?? reader.id {
    _channel.setMethodCallHandler(_handleNativeCall);
  }

  final Adapter adapter;
  final Reader reader;
  final MethodChannel _channel;
  final VoWifiMessageStore _messages;
  final VoWifiNotifications _notifications;
  final VoWifiCallStore _calls;
  final VoWifiSettingsStore _settings = VoWifiSettingsStore();
  final VoWifiConnectionDiagnostics _diagnostics =
      VoWifiConnectionDiagnostics();
  String _lineKey;
  VoWifiReaderLease? _lease;
  StreamSubscription<EuiccPortState>? _readerSubscription;
  Future<void> _apduTail = Future<void>.value();
  Future<void> _callHistoryTail = Future<void>.value();
  Completer<void>? _startingDone;
  Future<void>? _stopping;
  bool _cancelStart = false;
  bool _nativeMayBeRunning = false;
  bool _acceptingApdus = false;
  bool _disposed = false;
  int _generation = 0;
  String? _numberCacheKey;
  SubscriberNumber? _numberCache;

  Map<String, dynamic> status = {'phase': 'idle'};
  List<Map<String, Object?>> messages = [];
  bool readerReady = false;
  bool simReady = false;
  bool busy = false;
  String? error;
  String? _statusError;
  String? _statusQueryError;
  String? _stopError;
  int _statusRevision = 0;
  String? callHistoryError;

  static bool supports(Reader? reader) =>
      reader != null &&
      (reader.source is CcidAdapter ||
          reader.source is RedBleAdapter ||
          reader.source is RedBle2Adapter);

  bool get active => _lease != null || _startingDone != null;
  bool get stopping => _stopping != null;
  String get lineKey => _lineKey;
  bool get registered => status['registered'] == true;
  String? get ownPhoneNumber => _ownNumber?.number;
  String? get ownNumberDisplay => _ownNumber?.display;

  SubscriberNumber? get _ownNumber {
    if (!registered) {
      _numberCacheKey = null;
      _numberCache = null;
      return null;
    }
    final raw = status['msisdn'];
    if (raw is! String || raw.isEmpty) {
      _numberCacheKey = null;
      _numberCache = null;
      return null;
    }
    final mcc = status['mcc'] is String ? status['mcc'] as String : null;
    // These MCCs span territories with different calling codes; the existing
    // flag mapper has a representative default, not enough evidence to expand
    // a national EF-MSISDN. An explicit international number still works.
    final region = const {'340', '362'}.contains(mcc)
        ? null
        : MccMapper.mccToCountryCode(
            mcc,
            mnc: status['mnc'] is String ? status['mnc'] as String : null,
          );
    final key = '$raw|$region';
    if (key != _numberCacheKey) {
      _numberCacheKey = key;
      _numberCache = SubscriberNumber.parse(raw, homeRegion: region);
    }
    return _numberCache;
  }

  bool get checkingConnection => status['checking_connection'] == true;
  bool get _connectionVerified =>
      !checkingConnection &&
      status['status_uncertain'] != true &&
      status['retrying'] != true;
  bool get messagingReady =>
      registered && _connectionVerified && status['messaging_ready'] == true;
  bool get callReady =>
      registered && _connectionVerified && status['call_ready'] == true;
  String get phase => status['phase'] as String? ?? 'idle';
  Map<String, dynamic> get call => status['call'] is Map
      ? Map<String, dynamic>.from(status['call'] as Map)
      : {};
  bool get inCall => const {
    'incoming',
    'ringing',
    'dialing',
    'calling',
    'early',
    'active',
    'established',
    'connected',
    'outgoing',
    'connecting',
    'cancelling',
  }.contains(call['state']);

  void _changed() {
    if (!_disposed) notifyListeners();
  }

  Future<void> loadMessages() async {
    messages = await _messages.list(_lineKey);
    _changed();
  }

  Future<Map<String, String>> loadSettings() => _settings.load(_lineKey);

  /// Invoke from Connect so iOS can ask permission before the first message.
  /// Denial or an unavailable notification plugin never blocks IMS or storage.
  Future<bool> requestSmsNotifications() async {
    try {
      // Notification initialization/permission is optional. Keep observing the
      // original request after timeout, but let Connect proceed without it.
      return await _notifications.requestPermission().timeout(
        const Duration(seconds: 5),
      );
    } catch (_) {
      return false;
    }
  }

  Future<void> start(Map<String, dynamic> configuration) async {
    if (active || busy) {
      throw StateError('A Wi-Fi calling session is already active');
    }
    if (!supports(reader)) {
      throw StateError('This reader does not support Wi-Fi calling');
    }
    _generation = DateTime.now().microsecondsSinceEpoch;
    _cancelStart = false;
    error = null;
    _statusError = null;
    _statusQueryError = null;
    _stopError = null;
    _statusRevision++;
    busy = true;
    readerReady = false;
    simReady = false;
    status = {'phase': 'sim', 'registered': false};
    final startingDone = Completer<void>();
    _startingDone = startingDone;
    _changed();
    try {
      var savedSettings = await _settings.save(_lineKey, configuration);
      if (_cancelStart) return;
      _lease = await VoWifiReaderLease.acquire(adapter, reader);
      _acceptingApdus = !_cancelStart;
      readerReady = true;
      _readerSubscription = _lease!.source.stateStream.listen((state) {
        if (state == EuiccPortState.closed && _lease != null) {
          error = 'The SIM reader disconnected';
          _changed();
          unawaited(stop().catchError((Object _) {}));
        }
      });
      if (_cancelStart) return;
      _changed();
      // readCard also creates a native engine/Host and must be cancellable.
      _nativeMayBeRunning = true;
      final identity = await _invoke('command', {
        'action': 'readCard',
        'generation': _generation,
      });
      if (_cancelStart) return;
      final card = identity['card'] is Map
          ? Map<String, dynamic>.from(identity['card'] as Map)
          : identity;
      if (card['imsi'] is! String || (card['imsi'] as String).isEmpty) {
        throw StateError('The active SIM did not provide an IMSI');
      }
      simReady = true;
      if (card['iccid'] is String && (card['iccid'] as String).isNotEmpty) {
        _lineKey = card['iccid'] as String;
      }
      // Once ICCID is known, its existing identity/settings take precedence
      // over a different reader's defaults. Explicit UI edits still apply.
      savedSettings = await _settings.save(
        _lineKey,
        configuration,
        defaults: savedSettings,
      );
      await loadMessages();
      if (_cancelStart) return;
      _nativeMayBeRunning = true;
      final startRevision = _statusRevision;
      final initialStatus = await _invoke('start', {
        ...card,
        ...configuration,
        ...savedSettings,
        'generation': _generation,
      }, throwOnError: false);
      // Events can arrive while native Start is returning its earlier snapshot.
      // Keep a newer event (or Stop) authoritative, as with refreshStatus.
      if (!_cancelStart &&
          startRevision == _statusRevision &&
          initialStatus.containsKey('phase')) {
        _acceptStatus(initialStatus);
      }
    } catch (failure) {
      if (!_cancelStart) {
        error = describeError(failure);
        status = {'phase': 'failed', 'registered': false};
        _diagnostics.record({
          ...status,
          'error': error,
          'generation': _generation,
        });
        _cancelStart = true;
        rethrow;
      }
    } finally {
      _startingDone = null;
      startingDone.complete();
      busy = _stopping != null;
      if (_cancelStart) {
        // stop is allowed to retry if the native engine could not be stopped.
        unawaited(stop().catchError((Object _) {}));
      }
      _changed();
    }
  }

  Future<void> stop({bool suspended = false}) {
    _cancelStart = true;
    _statusRevision++;
    // Let the physical APDU finish, but stop the remaining commands in its
    // batch and reject new authentication work while teardown is pending.
    _acceptingApdus = false;
    final previous = _stopping;
    if (previous != null) return previous;
    // Install the shared completion before notifying listeners: a listener
    // can request Stop again synchronously while the UI is being updated.
    final completion = Completer<void>();
    _stopping = completion.future;
    unawaited(
      _stop(suspended: suspended).then(
        (_) {
          _stopping = null;
          busy = false;
          _changed();
          completion.complete();
        },
        onError: (Object failure, StackTrace stack) {
          _stopping = null;
          busy = false;
          _changed();
          completion.completeError(failure, stack);
        },
      ),
    );
    return completion.future;
  }

  Future<void> _stop({required bool suspended}) async {
    busy = true;
    _changed();
    try {
      if (_nativeMayBeRunning) {
        // Keep the SIM reservation if native stop fails: the engine may still
        // authenticate. Releasing the reader in that case would be unsafe.
        await _invoke('stop', null);
        _nativeMayBeRunning = false;
      }
      // Native cancellation wakes a pending readCard/Start callback first;
      // waiting for startup before cancelling could hold both sides forever.
      await _startingDone?.future;
      await _apduTail;
      await _readerSubscription?.cancel();
      _readerSubscription = null;
      await _callHistoryTail;
      try {
        await _calls.finishActive(lineKey: _lineKey);
      } catch (_) {
        callHistoryError = 'Call history could not be saved on this device';
      }
      final lease = _lease;
      await lease?.close();
      _lease = null;
      readerReady = false;
      simReady = false;
      status = {
        'phase': suspended ? 'suspended' : 'stopped',
        'registered': false,
      };
      if (_stopError != null && error == _stopError) error = null;
      _stopError = null;
    } catch (failure) {
      _stopError = describeError(failure);
      error = _stopError;
      rethrow;
    }
  }

  Future<void> refreshStatus() async {
    if (!active || _nativeMayBeRunning == false) return;
    final generation = _generation;
    final lease = _lease;
    final revision = _statusRevision;
    bool isCurrent() =>
        !_disposed &&
        _nativeMayBeRunning &&
        _stopping == null &&
        generation == _generation &&
        identical(lease, _lease) &&
        revision == _statusRevision;
    try {
      final snapshot = await _invoke(
        'status',
        null,
        throwOnError: false,
      ).timeout(const Duration(seconds: 8));
      if (!isCurrent()) return;
      if (!snapshot.containsKey('phase')) {
        throw StateError('Could not confirm the current connection state');
      }
      _acceptStatus(snapshot);
    } catch (failure) {
      if (!isCurrent()) return;
      // Keep call controls available, but do not advertise stale readiness.
      status = {
        ...status,
        'registered': false,
        'messaging_ready': false,
        'call_ready': false,
        'status_uncertain': true,
      };
      final queryError = describeError(failure);
      if (error == null || error == _statusQueryError) error = queryError;
      _statusQueryError = queryError;
      _changed();
    }
  }

  Future<Map<String, dynamic>> command(
    String action, [
    Map<String, dynamic> arguments = const {},
  ]) async {
    if (!active || busy || _stopping != null) {
      throw StateError('Wi-Fi calling is not ready');
    }
    // Recheck at dispatch as readiness may change after a button was rendered
    // or while the outgoing SMS was being persisted. Existing call controls
    // must remain available throughout a connection check.
    if ((action == 'dial' || action == 'sms') && checkingConnection) {
      throw StateError('Checking connection…');
    }
    if (action == 'dial' && !callReady) {
      throw StateError('Wi-Fi calling is not ready');
    }
    if (action == 'sms' && !messagingReady) {
      throw StateError('IMS messaging is not registered');
    }
    return _invoke('command', {
      ...arguments,
      'action': action,
      'generation': _generation,
    });
  }

  Future<void> sendSms(String recipient, String content) async {
    if (checkingConnection) throw StateError('Checking connection…');
    if (!messagingReady) throw StateError('IMS messaging is not registered');
    final id = await _messages.add(
      lineKey: _lineKey,
      peer: recipient,
      content: content,
      direction: 'outgoing',
      state: 'submitting',
    );
    await loadMessages();
    try {
      await command('sms', {'recipient': recipient, 'text': content});
      // A successful submission is not a delivery receipt.
      await _messages.setState(id, 'submitted');
    } catch (_) {
      await _messages.setState(id, 'failed');
      rethrow;
    } finally {
      await loadMessages();
    }
  }

  Future<dynamic> _handleNativeCall(MethodCall call) async {
    if (call.method == 'storeSMS') {
      final event = _decode(call.arguments);
      if (_lease == null || event['generation'] != _generation) {
        throw PlatformException(
          code: 'SIM_SESSION_CHANGED',
          message: 'The SIM session changed before SMS persistence',
        );
      }
      final messageId = event['message_id'];
      if (messageId is! String ||
          messageId.isEmpty ||
          event['sender'] is! String ||
          event['content'] is! String) {
        throw PlatformException(
          code: 'INVALID_SMS',
          message: 'Invalid incoming SMS',
        );
      }
      final lineKey = _lineKey;
      final VoWifiMessageInsert? saved;
      try {
        final total = event['concat_total'];
        final sequence = event['concat_sequence'];
        final reference = event['concat_reference'];
        final hasConcat =
            total != null || sequence != null || reference != null;
        if (hasConcat &&
            (total is! int ||
                total < 1 ||
                total > 255 ||
                sequence is! int ||
                sequence < 1 ||
                sequence > total ||
                reference is! int ||
                reference < 0 ||
                reference > 65535 ||
                event['sim_id'] is! String)) {
          throw const FormatException('Invalid incoming SMS segments');
        }
        saved = hasConcat && (total as int) > 1
            ? await _messages.addIncomingSegment(
                lineKey: lineKey,
                peer: event['sender'] as String,
                content: event['content'] as String,
                at: event['at'] as String?,
                messageId: messageId,
                simId: event['sim_id'] as String,
                concatReference: reference as int,
                concatTotal: total,
                concatSequence: sequence as int,
              )
            : await _messages.addIncoming(
                lineKey: lineKey,
                peer: event['sender'] as String,
                content: event['content'] as String,
                at: event['at'] as String?,
                messageId: messageId,
              );
      } catch (_) {
        throw PlatformException(
          code: 'SMS_STORAGE_FAILED',
          message: 'Incoming SMS could not be saved on this device',
        );
      }
      if (saved?.inserted == true) {
        // Schedule after the commit and isolate presentation from carrier ACK.
        // The row ID and line are captured before a reader/session can change.
        unawaited(_notifyIncoming(saved!.id, lineKey));
      }
      // Carrier acknowledgement depends on the commit above, not presentation.
      unawaited(loadMessages().catchError((Object _) {}));
      return true;
    }
    if (call.method == 'exchangeAPDUs') {
      final request = _decode(call.arguments);
      final completer = Completer<String>();
      _apduTail = _apduTail.then((_) async {
        try {
          final lease = _lease;
          if (!_acceptingApdus ||
              lease == null ||
              request['generation'] != _generation) {
            throw StateError('SIM session changed');
          }
          final commands = request['commands'];
          if (commands is! List || commands.any((value) => value is! String)) {
            throw const FormatException('Invalid SIM command batch');
          }
          final exchange = VoWifiApduExchange(
            lease.transmit,
            isCurrent: () =>
                _acceptingApdus &&
                identical(_lease, lease) &&
                adapter.connectedReader?.id == reader.id,
          );
          final responses = await lease.runBatch(
            () => exchange.exchange(commands.cast<String>()),
          );
          completer.complete(jsonEncode({'responses': responses}));
        } catch (failure) {
          completer.completeError(
            PlatformException(
              code: 'SIM_APDU_FAILED',
              message: describeError(failure),
            ),
          );
        }
      });
      return completer.future;
    }
    if (call.method == 'event') {
      final event = _decode(call.arguments);
      if (event['generation'] != _generation || _lease == null) return null;
      if (event['type'] == 'sms') {
        // The StoreSMS callback already committed this event before RP-ACK.
        await loadMessages();
      } else if (event['type'] == 'status') {
        _acceptStatus(event);
      } else if (event['type'] == 'native_error') {
        _statusError = null;
        error =
            event['error'] as String? ?? 'The native engine reported an error';
        _diagnostics.record({...status, 'error': error});
        _changed();
      }
      return null;
    }
    throw MissingPluginException('Unknown Wi-Fi calling callback');
  }

  Future<void> _notifyIncoming(int messageId, String lineKey) async {
    try {
      await _notifications.showIncoming(messageId: messageId, lineKey: lineKey);
    } catch (_) {
      // The saved message remains available in the inbox. Notification failure
      // must not turn a successful SQLite commit into a carrier redelivery.
    }
  }

  void _acceptStatus(Map<String, dynamic> event) {
    if (_lease == null) return;
    if (event['generation'] != null && event['generation'] != _generation) {
      return;
    }
    _statusRevision++;
    if (_statusQueryError != null && error == _statusQueryError) error = null;
    _statusQueryError = null;
    status = event;
    _diagnostics.record(event);
    if (event['call'] is Map) {
      final lineKey = _lineKey;
      final snapshot = Map<String, dynamic>.from(event['call'] as Map);
      _callHistoryTail = _callHistoryTail.then((_) async {
        try {
          await _calls.record(lineKey: lineKey, call: snapshot);
          callHistoryError = null;
        } catch (_) {
          callHistoryError = 'Call history could not be saved on this device';
        }
        _changed();
      });
    }
    if (event['error'] is String && (event['error'] as String).isNotEmpty) {
      _statusError = event['error'] as String;
      error = _statusError;
    } else {
      // Native status is a complete snapshot. A retry clears its previous
      // connection error before IKE begins; do not display that IMS failure
      // during the next attempt. Independent audio/reader errors stay visible.
      if (error == _statusError) error = null;
      _statusError = null;
    }
    _changed();
    // The engine may retry a failed IKE/IMS connection under this lease.
    // Only a confirmed native stop/suspension triggers automatic release.
    if (const {'stopped', 'suspended'}.contains(phase) &&
        _nativeMayBeRunning &&
        _stopping == null) {
      unawaited(
        stop(suspended: phase == 'suspended').catchError((Object _) {}),
      );
    }
  }

  Future<Map<String, dynamic>> _invoke(
    String method,
    Map<String, dynamic>? data, {
    bool throwOnError = true,
  }) async {
    final result = await _channel.invokeMethod<dynamic>(
      method,
      data == null ? null : jsonEncode(data),
    );
    if (result == null || result == '') return {};
    final decoded = _decode(result);
    final failure = decoded['error'];
    if (throwOnError && failure is String && failure.isNotEmpty) {
      throw StateError(failure);
    }
    return decoded;
  }

  static Map<String, dynamic> _decode(dynamic value) {
    final decoded = value is String ? jsonDecode(value) : value;
    if (decoded is! Map) {
      throw const FormatException('Invalid Wi-Fi calling response');
    }
    return Map<String, dynamic>.from(decoded);
  }

  static String describeError(Object failure) {
    if (failure is MissingPluginException) {
      return 'The native Wi-Fi calling engine is unavailable in this build';
    }
    if (failure is PlatformException) return failure.message ?? failure.code;
    if (failure is StateError) return failure.message;
    if (failure is FormatException) return failure.message;
    return failure.toString();
  }

  @override
  void dispose() {
    assert(!active, 'Stop the native engine before disposing its SIM bridge');
    _disposed = true;
    _channel.setMethodCallHandler(null);
    super.dispose();
  }
}
