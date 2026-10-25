import 'dart:async';

import 'package:flutter/services.dart';

import '../adapter/ccid/ccid_adapter.dart';
import '../adapter/euicc_adapter.dart';
import '../utils/platform_adapter.dart';

/// Reserves the existing connection until the native engine has stopped.
/// The captured zone permits callbacks to use both adapter locks without
/// allowing unrelated eSIM management operations to enter the reservation.
class VoWifiReaderLease {
  VoWifiReaderLease._(
    this.reader,
    this.source,
    this._zone,
    this._release,
    this._finished,
  );

  final Reader reader;
  // Reader is UI metadata and its source can be refreshed. Never let that
  // redirect a reserved SIM session to a new, unconnected transport.
  final Adapter source;
  final Zone _zone;
  final Completer<void> _release;
  final Future<void> Function() _finished;
  bool _closed = false;
  Future<void> _ioTail = Future<void>.value();
  final Object _batchZoneKey = Object();
  Object? _activeBatch;

  static Future<VoWifiReaderLease> acquire(
    Adapter adapter,
    Reader reader,
  ) async {
    final source = reader.source;
    final selected = adapter.connectedReader;
    if (selected?.id != reader.id || !identical(selected?.source, source)) {
      throw StateError(
        'Connect this reader in Manage before starting Wi-Fi calling',
      );
    }

    final ready = Completer<VoWifiReaderLease>();
    final release = Completer<void>();
    late Future<void> operation;
    operation = adapter.runExclusiveNow(() async {
      if (adapter.connectedReader?.id != reader.id ||
          !identical(adapter.connectedReader?.source, source)) {
        throw StateError(
          'The SIM reader disconnected. Reconnect it and try Wi-Fi calling again.',
        );
      }
      await source.runExclusiveNow(() async {
        // Repair stale UI selection while both locks are owned. A busy reader
        // must fail before starting any disconnect/reconnect operation.
        if (source.connectedReader?.id != reader.id) {
          await adapter.disconnect();
          await adapter.connect(reader);
        }
        if (source.connectedReader?.id != reader.id) {
          throw StateError('The SIM reader did not reconnect. Please retry.');
        }
        final persistentUsb = PlatformX.isIOS && source is CcidAdapter;
        const ccid = MethodChannel('ccid');
        if (persistentUsb) {
          await ccid.invokeMethod<void>('beginSession', reader.name);
        }
        try {
          final lease = VoWifiReaderLease._(
            reader,
            source,
            Zone.current,
            release,
            () => operation,
          );
          if (source is CoordinatedReaderMaintenance) {
            (source as CoordinatedReaderMaintenance).setMaintenanceRunner(
              (action) => lease.runBatch(action),
            );
          }
          ready.complete(lease);
          await release.future;
        } finally {
          if (source is CoordinatedReaderMaintenance) {
            (source as CoordinatedReaderMaintenance).setMaintenanceRunner(null);
          }
          if (persistentUsb) {
            await ccid.invokeMethod<void>('endSession', reader.name);
          }
        }
      });
    });
    // Observe acquisition errors immediately, including before a lease exists.
    unawaited(
      operation.then<void>(
        (_) {},
        onError: (Object error, StackTrace stack) {
          if (!ready.isCompleted) ready.completeError(error, stack);
        },
      ),
    );
    return ready.future;
  }

  Future<Uint8List> transmit(Uint8List command) {
    if (_closed) throw StateError('SIM session has ended');
    return runBatch(() => source.sendRawApdu(command));
  }

  /// Serialize the complete SELECT / AUTHENTICATE / GET RESPONSE batch with
  /// transport keepalives, not just each individual APDU. Only this lease's
  /// native requests and maintenance runner may enter the reservation zone.
  Future<T> runBatch<T>(Future<T> Function() action) {
    if (_closed) return Future<T>.error(StateError('SIM session has ended'));
    if (_activeBatch != null &&
        identical(Zone.current[_batchZoneKey], _activeBatch)) {
      return action();
    }
    final operation = _ioTail.then<T>((_) async {
      if (_closed) throw StateError('SIM session has ended');
      final batch = Object();
      _activeBatch = batch;
      try {
        return await _zone.run(
          () => runZoned(action, zoneValues: {_batchZoneKey: batch}),
        );
      } finally {
        _activeBatch = null;
      }
    });
    // A failed AKA must not poison later requests or prevent lease shutdown.
    _ioTail = operation.then<void>(
      (_) {},
      onError: (Object _, StackTrace _) {},
    );
    return operation;
  }

  Future<void> close() async {
    if (_closed) {
      await _finished();
      return;
    }
    _closed = true;
    if (source is CoordinatedReaderMaintenance) {
      (source as CoordinatedReaderMaintenance).setMaintenanceRunner(null);
    }
    await _ioTail;
    if (!_release.isCompleted) _release.complete();
    await _finished();
  }
}
