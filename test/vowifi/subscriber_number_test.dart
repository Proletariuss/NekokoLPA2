import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/subscriber_number.dart';

void main() {
  test('uses number country rather than SIM or device location', () {
    expect(
      SubscriberNumber.parse('+44 1212 345678', homeRegion: 'CN')?.display,
      '🇬🇧 +441212345678',
    );
    expect(
      SubscriberNumber.parse('+852 5123 4567')?.display,
      '🇭🇰 +85251234567',
    );
    expect(
      SubscriberNumber.parse('+372 5123 4567')?.display,
      '🇪🇪 +37251234567',
    );
    expect(
      SubscriberNumber.parse('+1 (416) 555-0123')?.display,
      '🇨🇦 +14165550123',
    );
    expect(
      SubscriberNumber.parse('+1 202 555 0123')?.display,
      '🇺🇸 +12025550123',
    );
  });

  test('national numbers require SIM home region', () {
    expect(
      SubscriberNumber.parse('01212345678', homeRegion: 'GB')?.number,
      '+441212345678',
    );
    expect(SubscriberNumber.parse('01212345678'), isNull);
    expect(SubscriberNumber.parse('01212345678', homeRegion: 'UN'), isNull);
    expect(SubscriberNumber.parse('5550123', homeRegion: 'US'), isNull);
  });

  test(
    'never turns placeholder, short code or private identity into a phone number',
    () {
      for (final raw in [
        '',
        '00000000000',
        '+00000000000',
        '888',
        '+999123456789',
        'sip:234330000000001@ims.example.net',
        '234330000000001',
        'nickname +441212345678',
        '+441212345678;ext=42',
      ]) {
        expect(
          SubscriberNumber.parse(raw, homeRegion: 'GB'),
          isNull,
          reason: raw,
        );
      }
    },
  );

  test(
    'global service number has neutral flag rather than invented nationality',
    () {
      expect(
        SubscriberNumber.parse('+80012345678')?.display,
        '🌐 +80012345678',
      );
    },
  );
}
