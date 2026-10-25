import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:nlpa2/vowifi/settings_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test(
    'generated IMEI has a valid checksum and persists across service instances',
    () async {
      final first = await VoWifiSettingsStore().load('test-card');
      final second = await VoWifiSettingsStore().load('test-card');
      expect(VoWifiSettingsStore.isValidImei(first['imei']!), true);
      expect(second['imei'], first['imei']);
      expect(
        (await VoWifiSettingsStore().load('other-card'))['imei'],
        isNot(first['imei']),
      );
    },
  );

  test(
    'persists scoped proxy/ePDG and valid identity override; clearing restores automatic routing',
    () async {
      final store = VoWifiSettingsStore();
      await store.save('test-card', {
        'proxy': 'socks5://192.0.2.1:1080',
        'epdg': 'epdg.example.test',
        'imei': '490154203237518',
      });
      final saved = await VoWifiSettingsStore().load('test-card');
      expect(saved['imei'], '490154203237518');
      expect(saved['proxy'], 'socks5://192.0.2.1:1080');
      expect(saved['epdg'], 'epdg.example.test');
      await store.save('test-card', {'proxy': '', 'epdg': '', 'imei': ''});
      final cleared = await store.load('test-card');
      expect(cleared['proxy'], '');
      expect(cleared['epdg'], '');
      expect(cleared['imei'], '490154203237518');
      await expectLater(
        store.save('test-card', {'imei': '490154203237519'}),
        throwsStateError,
      );
    },
  );

  test(
    'a known SIM identity takes precedence over a replacement reader default',
    () async {
      final store = VoWifiSettingsStore();
      final original = await store.save('sim', {
        'imei': '490154203237518',
        'proxy': 'socks5://192.0.2.1:1080',
      });
      final otherReader = await store.load('another-reader');
      final resolved = await store.save('sim', {}, defaults: otherReader);
      expect(resolved, original);
    },
  );
}
