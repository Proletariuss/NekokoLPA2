import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/apple_active_call.dart';
import 'package:nlpa2/vowifi/apple_dialer.dart';
import 'package:nlpa2/vowifi/glass_surface.dart';

void main() {
  for (final scenario in [
    (
      name: 'small large text',
      size: const Size(320, 568),
      scale: 2.0,
      dark: false,
    ),
    (name: 'dark phone', size: const Size(390, 844), scale: 1.0, dark: true),
    (
      name: 'large text tablet',
      size: const Size(1024, 1366),
      scale: 2.0,
      dark: true,
    ),
  ]) {
    testWidgets('${scenario.name}: controls are reachable and labeled', (
      tester,
    ) async {
      tester.view.physicalSize = scenario.size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final semantics = tester.ensureSemantics();
      try {
        Widget app(Widget home) => MaterialApp(
          theme: scenario.dark ? ThemeData.dark() : ThemeData.light(),
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(
              context,
            ).copyWith(textScaler: TextScaler.linear(scenario.scale)),
            child: child!,
          ),
          home: home,
        );
        final actions = <String>[];
        await tester.pumpWidget(
          app(
            AppleActiveCall(
              peer: '+123456789012',
              status: 'In call',
              command: (action, _) async => actions.add(action),
            ),
          ),
        );
        final controls = ['Speaker', 'Mute', 'Keypad', 'End call'];
        for (final label in controls) {
          final target = find.byTooltip(label);
          expect(target.hitTestable(), findsOneWidget);
          expect(tester.getSize(target).shortestSide, greaterThanOrEqualTo(44));
          final node = tester.getSemantics(find.bySemanticsLabel(label));
          expect(node.flagsCollection.isButton, isTrue);
          expect(
            node.getSemanticsData().hasAction(SemanticsAction.tap),
            isTrue,
          );
        }
        final speaker = tester.getCenter(find.byTooltip('Speaker'));
        final mute = tester.getCenter(find.byTooltip('Mute'));
        final keypad = tester.getCenter(find.byTooltip('Keypad'));
        expect(speaker.dy, mute.dy);
        expect(mute.dy, keypad.dy);
        expect(keypad.dx - speaker.dx, lessThanOrEqualTo(280));
        expect(
          tester.getCenter(find.byTooltip('End call')).dx,
          closeTo(scenario.size.width / 2, 1),
        );
        await tester.tap(find.byTooltip('Keypad'));
        await tester.pumpAndSettle();
        await tester.ensureVisible(find.text('5'));
        await tester.tap(find.text('5'));
        await tester.pumpAndSettle();
        expect(actions, ['dtmf']);
        expect(find.byTooltip('End call').hitTestable(), findsOneWidget);
        expect(tester.takeException(), isNull);

        var calls = 0, deletes = 0;
        final digits = <String>[];
        await tester.pumpWidget(
          app(
            AppleDialer(
              number: '1033',
              line: 'SIM',
              onDigit: digits.add,
              onDelete: () => deletes++,
              onCall: () => calls++,
              onBack: () {},
            ),
          ),
        );
        await tester.pumpAndSettle();
        await tester.tap(find.text('1'));
        await tester.ensureVisible(find.byTooltip('Call'));
        final call = find.byTooltip('Call'),
            delete = find.byTooltip('Delete digit');
        expect(tester.getCenter(call).dy, tester.getCenter(delete).dy);
        expect(tester.getSize(call), tester.getSize(delete));
        expect(tester.getSize(call).shortestSide, greaterThanOrEqualTo(44));
        await tester.tap(call);
        await tester.tap(delete);
        expect(digits, ['1']);
        expect(calls, 1);
        expect(deletes, 1);
        expect(tester.takeException(), isNull);
        await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
      } finally {
        semantics.dispose();
      }
    });
  }

  for (final reduce in [false, true]) {
    testWidgets(
      'hangup bypasses animation and suppresses repeats, reduce=$reduce',
      (tester) async {
        final completion = Completer<void>();
        final actions = <String>[];
        await tester.pumpWidget(
          MaterialApp(
            builder: (context, child) => MediaQuery(
              data: MediaQuery.of(context).copyWith(disableAnimations: reduce),
              child: child!,
            ),
            home: AppleActiveCall(
              peer: '1033',
              status: 'In call',
              command: (action, _) {
                actions.add(action);
                return action == 'hangup' ? completion.future : Future.value();
              },
            ),
          ),
        );
        await tester.tap(find.byTooltip('Keypad'));
        await tester.pump();
        if (reduce) {
          expect(find.byType(AnimatedSize), findsNothing);
        } else {
          final animation = tester.widget<AnimatedSize>(
            find.byType(AnimatedSize),
          );
          expect(animation.duration, const Duration(milliseconds: 180));
        }
        await tester.pump(const Duration(milliseconds: 50));
        await tester.tap(find.byTooltip('End call'));
        await tester.tap(find.byTooltip('End call'));
        await tester.pump();
        expect(actions, ['hangup']);
        if (reduce) await tester.pumpAndSettle();
        expect(
          tester
              .widget<IconButton>(
                find.byWidgetPredicate(
                  (w) => w is IconButton && w.tooltip == 'End call',
                ),
              )
              .onPressed,
          isNull,
        );
        completion.complete();
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('shared motion respects accessible navigation', (tester) async {
    Duration? motion;
    await tester.pumpWidget(
      MaterialApp(
        home: MediaQuery(
          data: const MediaQueryData(accessibleNavigation: true),
          child: Builder(
            builder: (context) {
              motion = communicationMotion(context);
              return const SizedBox();
            },
          ),
        ),
      ),
    );
    expect(motion, Duration.zero);
  });
}
