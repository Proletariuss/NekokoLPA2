import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/settings/app_settings.dart';
import 'package:nlpa2/vowifi/privacy_redaction.dart';

void main() {
  test('VoWiFi privacy redacts display data without mutating its source', () {
    final settings = AppSettings();
    settings.setRedactEidMiddle(false);
    settings.setRedactIccidMiddle(false);
    settings.setRevealSensitiveProfileData(false);

    const number = '🇬🇧 +441212345678';
    const hardwareName = 'ESTKme Red:000000000001';
    const message = 'Private balance and account information';

    expect(VoWifiPrivacy.isEnabled, isTrue);
    expect(VoWifiPrivacy.phoneNumber(number), '🇬🇧 +••••••••••••');
    expect(VoWifiPrivacy.identifiers(hardwareName), 'ESTKme Red:••••••••••••');
    expect(
      VoWifiPrivacy.privateText(message, 'Message hidden'),
      'Message hidden',
    );
    expect(number, '🇬🇧 +441212345678');
    expect(message, 'Private balance and account information');

    settings.setRevealSensitiveProfileData(true);
    expect(VoWifiPrivacy.phoneNumber(number), number);
    expect(VoWifiPrivacy.identifiers(hardwareName), hardwareName);
    expect(VoWifiPrivacy.privateText(message, 'Message hidden'), message);
  });
}
