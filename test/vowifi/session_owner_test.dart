import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/adapter/ble/red_ble_adapter.dart';
import 'package:nlpa2/adapter/euicc_adapter.dart';
import 'package:nlpa2/vowifi/session_owner.dart';
import 'package:nlpa2/vowifi/vowifi_page.dart';
import 'package:nlpa2/vowifi/vowifi_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _SessionService extends VoWifiService {
  _SessionService(Adapter adapter, Reader reader)
    : super(
        adapter: adapter,
        reader: reader,
        channel: const MethodChannel('test/session-owner'),
      );

  bool running = false;
  int starts = 0;
  int stops = 0;
  int refreshes = 0;
  final commands = <String>[];

  @override
  bool get active => running;
  @override
  Future<void> loadMessages() async {}
  @override
  Future<Map<String, String>> loadSettings() async => {};
  @override
  Future<void> start(Map<String, dynamic> configuration) async {
    starts++;
    running = true;
    status = {
      'phase': 'ready',
      'registered': true,
      'call_ready': true,
      'messaging_ready': true,
    };
    notifyListeners();
  }

  @override
  Future<void> stop({bool suspended = false}) async {
    stops++;
    running = false;
    notifyListeners();
  }

  @override
  Future<void> refreshStatus() async {
    refreshes++;
  }

  @override
  Future<Map<String, dynamic>> command(
    String action, [
    Map<String, dynamic> arguments = const {},
  ]) async {
    commands.add(action);
    return {};
  }
}

void main() {
  testWidgets(
    'application owner keeps one session across routes and pause/resume',
    (tester) async {
      SharedPreferences.setMockInitialValues({});
      final adapter = RedBleAdapter();
      final reader = Reader(
        id: 'owner-reader',
        name: 'Reader',
        source: adapter,
      );
      var creations = 0;
      final owner = VoWifiSessionOwner.forTesting(
        createService: (adapter, reader, iccid) {
          creations++;
          return _SessionService(adapter, reader);
        },
      );
      final service = owner.obtain(adapter, reader, 'line') as _SessionService;
      await service.start({});
      final navigator = GlobalKey<NavigatorState>();
      await tester.pumpWidget(
        MaterialApp(
          navigatorKey: navigator,
          home: const Scaffold(body: Text('Home')),
        ),
      );
      void open(int section, Reader routeReader) {
        navigator.currentState!.push(
          MaterialPageRoute<void>(
            builder: (_) => VoWifiPage(
              adapter: adapter,
              reader: routeReader,
              service: owner.obtain(adapter, routeReader, 'other-line'),
              initialSection: section,
              communicationOnly: section != 0,
            ),
          ),
        );
      }

      open(0, reader);
      await tester.pumpAndSettle();
      expect(
        tester.widget<VoWifiPage>(find.byType(VoWifiPage)).service,
        same(service),
      );
      navigator.currentState!.pop();
      await tester.pumpAndSettle();
      expect(service.stops, 0);
      expect(owner.activeService, same(service));
      final otherReader = Reader(
        id: 'other-reader',
        name: 'Other reader',
        source: adapter,
      );
      open(1, otherReader);
      await tester.pumpAndSettle();
      expect(
        tester.widget<VoWifiPage>(find.byType(VoWifiPage)).service,
        same(service),
      );
      expect(service.reader, same(reader));
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      await tester.pump();
      final pausedRefreshes = service.refreshes;
      await tester.pump(const Duration(seconds: 6));
      expect(service.refreshes, pausedRefreshes);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      expect(service.refreshes, greaterThan(pausedRefreshes));
      expect(service.starts, 1);
      expect(service.stops, 0);
      expect(creations, 1);
      expect(
        service.commands,
        isEmpty,
        reason:
            'Native lifecycle owns check_connection; Flutter only reads snapshots',
      );
      navigator.currentState!.pop();
      await tester.pumpAndSettle();
      expect(owner.activeService, same(service));
      expect(service.stops, 0);
      await tester.pumpWidget(const SizedBox.shrink());
      await service.stop();
      owner.dispose();
    },
  );
}
