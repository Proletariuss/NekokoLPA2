import 'package:flutter/services.dart';

/// The application owns the channel handler so SIM exchanges stay serialized
/// with its existing BLE/card transport. Payloads are UTF-8 JSON strings.
abstract final class ProletariusVowifi {
  static const MethodChannel channel = MethodChannel('proletarius/vowifi');
}
