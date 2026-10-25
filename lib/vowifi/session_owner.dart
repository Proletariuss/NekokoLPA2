import 'dart:async';
import 'package:flutter/widgets.dart';
import '../adapter/euicc_adapter.dart';
import 'vowifi_service.dart';

/// Owns the single native engine independently of any navigation route.
/// An active SIM bridge must never be replaced by opening another page.
class VoWifiSessionOwner extends ChangeNotifier with WidgetsBindingObserver {
  VoWifiSessionOwner._({this.createService}) {
    WidgetsBinding.instance.addObserver(this);
  }
  @visibleForTesting
  factory VoWifiSessionOwner.forTesting({
    required VoWifiService Function(Adapter, Reader, String?) createService,
  }) => VoWifiSessionOwner._(createService: createService);

  final VoWifiService Function(Adapter, Reader, String?)? createService;
  static final instance = VoWifiSessionOwner._();
  VoWifiService? _service;
  VoWifiService? get service => _service;
  VoWifiService? get activeService =>
      _service != null && (_service!.active || _service!.busy)
      ? _service
      : null;
  Timer? _poll;
  bool _foreground = true;
  bool _refreshing = false;

  VoWifiService obtain(Adapter adapter, Reader reader, String? iccid) {
    final current = _service;
    if (current != null && (current.active || current.busy)) return current;
    _poll?.cancel();
    current?.removeListener(notifyListeners);
    current?.dispose();
    final service =
        createService?.call(adapter, reader, iccid) ??
        VoWifiService(adapter: adapter, reader: reader, profileIccid: iccid);
    _service = service;
    service.addListener(notifyListeners);
    notifyListeners();
    _poll = Timer.periodic(const Duration(seconds: 2), (_) => _refresh());
    return service;
  }

  Future<void> _refresh() async {
    if (!_foreground || _refreshing) return;
    _refreshing = true;
    try {
      await _service?.refreshStatus();
    } finally {
      _refreshing = false;
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _foreground = state == AppLifecycleState.resumed;
    if (_foreground) unawaited(_refresh());
  }

  @override
  void dispose() {
    _poll?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    _service?.removeListener(notifyListeners);
    _service?.dispose();
    super.dispose();
  }
}
