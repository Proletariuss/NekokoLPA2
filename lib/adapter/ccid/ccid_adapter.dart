import 'dart:async';
import 'package:ccid/ccid.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:logging/logging.dart';
import '../euicc_adapter.dart';
import '../../utils/hex_utils.dart';
import 'nine_esim_usb_management.dart';

class CcidAdapter extends BaseAdapter {
  static final Logger _log = Logger('CcidAdapter');
  final Ccid _ccid = Ccid();
  CcidCard? _card;
  String? _lastAtr;

  CcidAdapter() : super(_log);

  // ignore: close_sinks
  final StreamController<EuiccPortState> _stateController =
      StreamController<EuiccPortState>.broadcast();

  @override
  Stream<EuiccPortState> get stateStream => _stateController.stream;

  @override
  bool get requiresRefresh => false;

  @override
  String? get lastAtr => _lastAtr;

  void _clearConnection() {
    _card = null;
    _lastAtr = null;
    currentEid = null;
    updateConnectedReader(null);
    _stateController.add(EuiccPortState.closed);
  }

  bool get _isNineEsimReader {
    final normalized = connectedReader?.name.toLowerCase().replaceAll(
      RegExp(r'[^a-z0-9]'),
      '',
    );
    return normalized != null &&
        (normalized.contains('9esim') ||
            normalized.contains('esim9') ||
            normalized.contains('nblesim'));
  }

  @override
  List<AdapterAction> get extraActions => _isNineEsimReader
      ? [
          AdapterAction(
            icon: Icons.settings_input_component_outlined,
            label: '9eSIM USB settings',
            onPressed: (context) => NineEsimUsbManagement.show(context, this),
            key: 'nine_esim_usb_settings',
          ),
        ]
      : const [];

  @override
  Future<List<Reader>> listReaders({bool force = false}) async {
    try {
      final readers = await _ccid.listReaders();
      return readers
          .map((r) => Reader(id: "ccid:$r", name: r, source: this))
          .toList();
    } catch (e) {
      _log.warning("Failed to list CCID readers: $e");
      return [];
    }
  }

  @override
  Future<void> connect(Reader reader) async {
    _log.info("Connecting to CCID reader ${reader.name}...");
    try {
      final card = await _ccid.connect(reader.name);
      _card = card;
      _lastAtr = card.atr;
      updateConnectedReader(reader);
      _stateController.add(EuiccPortState.open);
    } catch (e) {
      _log.severe("Failed to connect to CCID: $e");
      rethrow;
    }
  }

  @override
  Future<void> disconnect() async {
    final card = _card;
    _clearConnection();
    if (card != null) {
      try {
        await card.disconnect();
      } catch (e) {
        _log.warning("Error during CCID disconnect: $e");
      }
    }
  }

  @override
  Future<Channel> openChannel({List<String>? aids}) async {
    return await openLogicalChannel(aids: aids);
  }

  @override
  Future<Uint8List> sendRawApdu(Uint8List apdu) async {
    final card = _card;
    if (card == null) {
      throw PlatformException(code: 'DISCONNECTED', message: 'USB 读卡器未连接');
    }
    final hexCmd = HexUtils.bytesToHex(apdu);
    final String? responseHex;
    try {
      responseHex = await card.transceive(hexCmd);
    } on PlatformException catch (error) {
      if (error.code == 'DISCONNECTED' && identical(_card, card)) {
        _clearConnection();
      }
      rethrow;
    }
    if (responseHex == null) {
      throw Exception("Transceive failed (null response)");
    }
    return HexUtils.hexToBytes(responseHex);
  }
}
