import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// VoWiFi-specific settings; does not change the LPA's device identity.
class VoWifiSettingsStore {
  Future<Map<String, String>> load(
    String scope, {
    Map<String, String> defaults = const {},
  }) async {
    final preferences = await SharedPreferences.getInstance();
    final raw = preferences.getString(_key(scope));
    var values = Map<String, String>.from(defaults);
    if (raw != null) {
      final decoded = jsonDecode(raw);
      if (decoded is Map) {
        values = {
          for (final key in ['epdg', 'proxy', 'imei'])
            if (decoded[key] is String) key: decoded[key] as String,
        };
      }
    }
    if (!isValidImei(values['imei'] ?? '')) {
      values['imei'] = _generateImei();
      await _write(preferences, scope, values);
    }
    return values;
  }

  Future<Map<String, String>> save(
    String scope,
    Map<String, dynamic> changes, {
    Map<String, String> defaults = const {},
  }) async {
    final values = await load(scope, defaults: defaults);
    for (final key in ['epdg', 'proxy', 'imei']) {
      if (changes[key] is String) {
        final value = (changes[key] as String).trim();
        if (key == 'imei') {
          if (value.isEmpty) continue;
          if (!isValidImei(value)) {
            throw StateError(
              'IMEI must have 15 digits and a valid check digit',
            );
          }
        }
        values[key] = value;
      }
    }
    await _write(await SharedPreferences.getInstance(), scope, values);
    return values;
  }

  Future<void> _write(
    SharedPreferences preferences,
    String scope,
    Map<String, String> values,
  ) async {
    if (!await preferences.setString(_key(scope), jsonEncode(values))) {
      throw StateError('Could not save Wi-Fi calling settings');
    }
  }

  String _key(String scope) =>
      'vowifi.settings.${sha256.convert(utf8.encode(scope))}';

  static bool isValidImei(String value) =>
      RegExp(r'^\d{15}$').hasMatch(value) &&
      _checkDigit(value.substring(0, 14)) == int.parse(value[14]);

  static String _generateImei() {
    final random = Random.secure();
    final digits = '35${List.generate(12, (_) => random.nextInt(10)).join()}';
    return '$digits${_checkDigit(digits)}';
  }

  static int _checkDigit(String digits) {
    var sum = 0;
    for (var index = 0; index < digits.length; index++) {
      var digit = int.parse(digits[index]);
      if (index.isOdd) digit *= 2;
      sum += digit > 9 ? digit - 9 : digit;
    }
    return (10 - sum % 10) % 10;
  }
}
