import 'dart:typed_data';

/// ISO 7816 response handling for the native engine's exact APDU bytes.
/// Responses retain their status word; payloads are never logged.
class VoWifiApduExchange {
  VoWifiApduExchange(this.transmit, {this.isCurrent});

  final Future<Uint8List> Function(Uint8List) transmit;
  final bool Function()? isCurrent;

  Future<List<String>> exchange(List<String> commands) async {
    if (commands.isEmpty || commands.length > 64) {
      throw const FormatException('Invalid SIM command batch size');
    }
    final parsed = commands.map(_decode).toList(growable: false);
    final responses = <String>[];
    for (final command in parsed) {
      responses.add(_encode(await _exchange(command)));
    }
    return responses;
  }

  Future<Uint8List> _exchange(Uint8List original) async {
    var command = original;
    final data = BytesBuilder(copy: false);
    for (var hop = 0; hop < 32; hop++) {
      if (isCurrent?.call() == false) {
        throw StateError('SIM session changed');
      }
      final response = await transmit(command);
      if (response.length < 2) {
        throw const FormatException('Incomplete SIM response');
      }
      final sw1 = response[response.length - 2];
      final sw2 = response.last;
      if (sw1 == 0x6c) {
        command = _correctLength(command, sw2);
        continue;
      }
      data.add(response.sublist(0, response.length - 2));
      if (data.length > 65536) {
        throw const FormatException('SIM response exceeds size limit');
      }
      if (sw1 == 0x61 || sw1 == 0x9f) {
        command = Uint8List.fromList([
          original[0] & 0xef,
          0xc0,
          0x00,
          0x00,
          sw2,
        ]);
        continue;
      }
      if (!((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91)) {
        final status = (sw1 * 256 + sw2).toRadixString(16).padLeft(4, '0');
        throw StateError('SIM status ${status.toUpperCase()}');
      }
      data.add([sw1, sw2]);
      return data.takeBytes();
    }
    throw StateError('Too many SIM response continuations');
  }

  static Uint8List _correctLength(Uint8List command, int le) {
    final corrected = Uint8List.fromList(command);
    if (command.length == 5 ||
        (command.length > 5 &&
            command[4] != 0 &&
            command.length == command[4] + 6)) {
      corrected[corrected.length - 1] = le;
      return corrected;
    }
    if (command.length == 4 ||
        (command.length > 5 &&
            command[4] != 0 &&
            command.length == command[4] + 5)) {
      return Uint8List.fromList([...command, le]);
    }
    // Extended-length Le encodes 256 as 0100, unlike short Le=00.
    if (command.length >= 7 && command[4] == 0) {
      final lc = command[5] * 256 + command[6];
      if (command.length == 7 || command.length == lc + 9) {
        corrected[corrected.length - 2] = le == 0 ? 1 : 0;
        corrected[corrected.length - 1] = le;
        return corrected;
      }
    }
    throw const FormatException('Cannot correct SIM command length');
  }

  static Uint8List _decode(String hex) {
    if (hex.length < 8 ||
        hex.length > 131088 ||
        hex.length.isOdd ||
        !RegExp(r'^[0-9a-fA-F]+$').hasMatch(hex)) {
      throw const FormatException('Invalid SIM command encoding');
    }
    return Uint8List.fromList([
      for (var index = 0; index < hex.length; index += 2)
        int.parse(hex.substring(index, index + 2), radix: 16),
    ]);
  }

  static String _encode(Uint8List bytes) =>
      bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}
