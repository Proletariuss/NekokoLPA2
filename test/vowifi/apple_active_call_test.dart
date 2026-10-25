import 'package:flutter/material.dart';
import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/apple_active_call.dart';

void main() {
  testWidgets('call typography does not inherit Material button fonts', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: ThemeData(
          fontFamily: 'NonAppleTestFont',
          textButtonTheme: TextButtonThemeData(
            style: TextButton.styleFrom(
              textStyle: const TextStyle(
                fontFamily: 'NonAppleButtonFont',
                letterSpacing: 4,
              ),
            ),
          ),
        ),
        home: AppleActiveCall(
          peer: '1033',
          status: 'In call',
          command: (_, _) async {},
        ),
      ),
    );
    TextStyle renderedStyle(String value) => tester
        .widget<RichText>(
          find.descendant(
            of: find.text(value),
            matching: find.byType(RichText),
          ),
        )
        .text
        .style!;
    expect(renderedStyle('1033').fontFamily, 'CupertinoSystemDisplay');
    expect(renderedStyle('In call').fontFamily, 'CupertinoSystemDisplay');
    expect(renderedStyle('Speaker').fontFamily, 'CupertinoSystemText');
    await tester.tap(find.byTooltip('Keypad'));
    await tester.pumpAndSettle();
    expect(renderedStyle('5').fontFamily, 'CupertinoSystemDisplay');
    expect(renderedStyle('5').letterSpacing, 0);
    expect(tester.takeException(), isNull);
  });
  testWidgets('short screen large text keeps hangup visible with keypad open', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(320, 568);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(
            context,
          ).copyWith(textScaler: const TextScaler.linear(2)),
          child: child!,
        ),
        home: AppleActiveCall(
          peer: '1033',
          status: 'In call',
          command: (_, _) async {},
        ),
      ),
    );
    await tester.tap(find.byTooltip('Keypad'));
    await tester.pump();
    expect(find.byTooltip('End call').hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
  testWidgets('three controls share a row and hangup is centered below', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(
        home: AppleActiveCall(
          peer: '1033',
          status: 'In call',
          command: (_, _) async {},
        ),
      ),
    );
    final speaker = tester.getCenter(find.byTooltip('Speaker'));
    final mute = tester.getCenter(find.byTooltip('Mute'));
    final keypad = tester.getCenter(find.byTooltip('Keypad'));
    final end = tester.getCenter(find.byTooltip('End call'));
    expect(speaker.dy, mute.dy);
    expect(mute.dy, keypad.dy);
    expect(end.dx, closeTo(195, 1));
    expect(end.dy, greaterThan(mute.dy));
    expect(keypad.dx - mute.dx, closeTo(mute.dx - speaker.dx, 1));
  });
  testWidgets('hangup remains available while speaker command is pending', (
    tester,
  ) async {
    final speaker = Completer<void>();
    final actions = <String>[];
    await tester.pumpWidget(
      MaterialApp(
        home: AppleActiveCall(
          peer: '1033',
          status: 'In call',
          command: (action, values) async {
            actions.add(action);
            if (action == 'speaker') await speaker.future;
          },
        ),
      ),
    );
    await tester.tap(find.byTooltip('Speaker'));
    await tester.pump();
    await tester.tap(find.byTooltip('End call'));
    await tester.pump();
    expect(actions, ['speaker', 'hangup']);
    speaker.complete();
    await tester.pumpAndSettle();
  });
  testWidgets('call controls route commands and keypad can close', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final actions = <String>[];
    await tester.pumpWidget(
      MaterialApp(
        home: AppleActiveCall(
          peer: '1033',
          status: 'In call',
          command: (action, values) async => actions.add('$action:$values'),
        ),
      ),
    );
    await tester.tap(find.byTooltip('Speaker'));
    await tester.pump();
    expect(actions.last, 'speaker:{enabled: true}');
    await tester.tap(find.byTooltip('Keypad'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('5'));
    await tester.pump();
    expect(actions.last, 'dtmf:{digit: 5}');
    await tester.tap(find.byTooltip('Hide keypad'));
    await tester.pump();
    expect(find.text('5'), findsNothing);
    await tester.tap(find.byTooltip('End call'));
    await tester.pump();
    expect(actions.last, 'hangup:{}');
    expect(find.text('FaceTime'), findsNothing);
    expect(tester.takeException(), isNull);
  });
}
