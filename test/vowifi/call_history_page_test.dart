import 'dart:async';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/call_history_page.dart';
import 'package:nlpa2/vowifi/call_store.dart';
import 'package:nlpa2/settings/app_settings.dart';

class _Calls extends VoWifiCallStore {
  bool fail = false;
  bool omitCompleted = false;
  final deleted = <Set<int>>[];

  @override
  Future<void> deleteRecords(Set<int> ids) async => deleted.add(Set.of(ids));

  @override
  Future<List<Map<String, Object?>>> list([String? lineKey]) async {
    if (fail) throw StateError('Unavailable');
    return [
      {
        'id': 1,
        'peer': '+441234000001',
        'direction': 'incoming',
        'outcome': 'missed',
        'first_seen_at': '2026-09-26T10:00:00Z',
        'duration_seconds': 0,
        'line_key': 'sim-1111',
      },
      if (!omitCompleted)
        {
          'id': 2,
          'peer': '888',
          'direction': 'outgoing',
          'outcome': 'completed',
          'first_seen_at': '2026-09-26T09:00:00Z',
          'duration_seconds': 65,
          'line_key': 'sim-2222',
        },
    ];
  }
}

class _PendingCalls extends _Calls {
  final requests = <(String?, Completer<List<Map<String, Object?>>>)>[];

  @override
  Future<List<Map<String, Object?>>> list([String? lineKey]) {
    final completion = Completer<List<Map<String, Object?>>>();
    requests.add((lineKey, completion));
    return completion.future;
  }
}

void main() {
  for (final replaceStore in [false, true]) {
    for (final staleFailure in [false, true]) {
      testWidgets(
        '${replaceStore ? 'store' : 'line'} replacement ignores stale '
        '${staleFailure ? 'failure' : 'success'} and retains latest selection',
        (tester) async {
          AppSettings().setRevealSensitiveProfileData(true);
          final original = _PendingCalls();
          final replacement = replaceStore ? _PendingCalls() : original;
          await tester.pumpWidget(
            MaterialApp(
              home: VoWifiCallHistoryPage(calls: original, lineKey: 'a'),
            ),
          );
          final stale = original.requests.single.$2;
          await tester.pumpWidget(
            MaterialApp(
              home: VoWifiCallHistoryPage(
                calls: replacement,
                lineKey: replaceStore ? 'a' : 'b',
              ),
            ),
          );
          expect(replacement.requests.last.$1, replaceStore ? 'a' : 'b');
          replacement.requests.last.$2.complete([
            {
              'id': 2,
              'line_key': replaceStore ? 'a' : 'b',
              'peer': '888',
              'direction': 'incoming',
              'outcome': 'missed',
            },
          ]);
          await tester.pumpAndSettle();
          await tester.tap(find.text('Edit'));
          await tester.pumpAndSettle();
          await tester.tap(find.text('Select all'));
          await tester.pumpAndSettle();
          expect(find.text('1 records selected'), findsOneWidget);
          if (staleFailure) {
            stale.completeError(StateError('stale load failed'));
          } else {
            stale.complete([
              {
                'id': 1,
                'line_key': 'a',
                'peer': '999',
                'direction': 'incoming',
                'outcome': 'missed',
              },
            ]);
          }
          await tester.pumpAndSettle();
          expect(find.text('888'), findsOneWidget);
          expect(find.text('999'), findsNothing);
          expect(find.text('1 records selected'), findsOneWidget);
          expect(
            find.text('Could not load call history. Pull down to retry.'),
            findsNothing,
          );
          expect(tester.takeException(), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
        },
      );
    }
  }

  testWidgets(
    'edit row tap selects without dialing and filter clears hidden selection',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      final store = _Calls();
      var dialed = false;
      await tester.pumpWidget(
        MaterialApp(
          home: VoWifiCallHistoryPage(
            calls: store,
            onSelectNumber: (_, _) => dialed = true,
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();
      await tester.tapAt(tester.getCenter(find.text('888')));
      await tester.pumpAndSettle();
      expect(find.text('1 records selected'), findsOneWidget);
      expect(
        tester
            .widget<IconButton>(
              find
                  .byWidgetPredicate(
                    (widget) =>
                        widget is IconButton &&
                        widget.tooltip == 'Use number in dialer',
                  )
                  .last,
            )
            .onPressed,
        isNull,
      );
      expect(dialed, isFalse);
      await tester.tap(
        find.descendant(
          of: find.byType(CupertinoSlidingSegmentedControl<String>),
          matching: find.text('Missed'),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('888'), findsNothing);
      expect(find.text('0 records selected'), findsOneWidget);
      expect(
        tester
            .widget<TextButton>(
              find.widgetWithText(TextButton, 'Delete selected'),
            )
            .onPressed,
        isNull,
      );
      await tester.tap(find.text('Select all'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete selected'));
      await tester.pumpAndSettle();
      expect(
        find.text(
          'Delete the 1 selected records from this device? This cannot be undone.',
        ),
        findsOneWidget,
      );
      await tester.tap(find.widgetWithText(TextButton, 'Delete'));
      await tester.pumpAndSettle();
      expect(store.deleted, [
        {1},
      ]);
      expect(dialed, isFalse);
    },
  );

  testWidgets(
    'failed refresh preserves calls and selection; successful refresh prunes stale IDs',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      final store = _Calls();
      await tester.pumpWidget(
        MaterialApp(home: VoWifiCallHistoryPage(calls: store)),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();
      await tester.tapAt(tester.getCenter(find.text('888')));
      await tester.pumpAndSettle();
      store.fail = true;
      await tester.tap(find.byTooltip('Refresh call history'));
      await tester.pumpAndSettle();
      expect(find.text('888'), findsOneWidget);
      expect(find.text('1 records selected'), findsOneWidget);
      store
        ..fail = false
        ..omitCompleted = true;
      await tester.tap(find.byTooltip('Refresh call history'));
      await tester.pumpAndSettle();
      expect(find.text('888'), findsNothing);
      expect(find.text('0 records selected'), findsOneWidget);
    },
  );

  testWidgets('changing line scope clears selection and reloads', (
    tester,
  ) async {
    AppSettings().setRevealSensitiveProfileData(true);
    final store = _Calls();
    await tester.pumpWidget(
      MaterialApp(
        home: VoWifiCallHistoryPage(calls: store, lineKey: 'a'),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Edit'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Select all'));
    await tester.pumpAndSettle();
    expect(find.text('2 records selected'), findsOneWidget);
    await tester.pumpWidget(
      MaterialApp(
        home: VoWifiCallHistoryPage(calls: store, lineKey: 'b'),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('0 records selected'), findsOneWidget);
  });
  testWidgets('dial entry is centered below history, outside the app bar', (
    tester,
  ) async {
    var opened = false;
    await tester.pumpWidget(
      MaterialApp(
        home: VoWifiCallHistoryPage(
          calls: _Calls(),
          onDial: () => opened = true,
        ),
      ),
    );
    await tester.pumpAndSettle();
    final button = find.byKey(const ValueKey('bottom-dial-button'));
    expect(button, findsOneWidget);
    expect(
      find.descendant(of: find.byType(AppBar), matching: button),
      findsNothing,
    );
    expect(tester.getCenter(button).dx, closeTo(400, 1));
    expect(tester.getCenter(button).dy, greaterThan(500));
    await tester.tap(button);
    expect(opened, isTrue);
  });
  testWidgets('number selection preserves SIM identity without dialing', (
    tester,
  ) async {
    (String, String)? selected;
    await tester.pumpWidget(
      MaterialApp(
        home: VoWifiCallHistoryPage(
          calls: _Calls(),
          onSelectNumber: (line, peer) => selected = (line, peer),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(selected, isNull);
    await tester.tap(find.byTooltip('Use number in dialer').last);
    expect(selected, ('sim-2222', '888'));
  });
  testWidgets(
    'history is available without a reader and filters missed calls',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      await tester.pumpWidget(
        MaterialApp(home: VoWifiCallHistoryPage(calls: _Calls())),
      );
      await tester.pumpAndSettle();
      expect(find.text('Call history'), findsOneWidget);
      expect(find.text('888'), findsOneWidget);
      expect(find.textContaining('Duration 1:05'), findsOneWidget);
      expect(find.text('Incoming · Missed'), findsOneWidget);
      await tester.tap(find.byKey(const ValueKey('vowifi-privacy-toggle')));
      await tester.pumpAndSettle();
      expect(find.text('+••••••••••••'), findsOneWidget);
      expect(find.text('+441234000001'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('vowifi-privacy-toggle')));
      await tester.pumpAndSettle();
      await tester.tap(
        find.descendant(
          of: find.byType(CupertinoSlidingSegmentedControl<String>),
          matching: find.text('Missed'),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('888'), findsNothing);
      expect(find.text('+441234000001'), findsOneWidget);
    },
  );
}
