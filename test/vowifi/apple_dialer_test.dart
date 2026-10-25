import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/apple_dialer.dart';

Future<void> pumpDialer(
  WidgetTester tester, {
  Size size = const Size(402, 874),
  EdgeInsets safeArea = const EdgeInsets.only(top: 62, bottom: 34),
  double textScale = 1,
  bool reducedMotion = false,
  bool dark = false,
  bool disabled = false,
  String number = '',
  String? status,
  String? error,
  ValueChanged<String>? onDigit,
  VoidCallback? onCall,
  VoidCallback? onDelete,
  VoidCallback? onBack,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      theme: ThemeData(brightness: dark ? Brightness.dark : Brightness.light),
      home: MediaQuery(
        data: MediaQueryData(
          size: size,
          padding: safeArea,
          viewPadding: safeArea,
          textScaler: TextScaler.linear(textScale),
          disableAnimations: reducedMotion,
        ),
        child: AppleDialer(
          number: number,
          line: 'SIM',
          status: status,
          error: error,
          onDigit: onDigit ?? (_) {},
          onDelete: disabled ? null : onDelete ?? () {},
          onCall: disabled ? null : onCall ?? () {},
          onBack: onBack ?? () {},
        ),
      ),
    ),
  );
  await tester.pump();
}

void main() {
  testWidgets('large text grows short-screen keys instead of shrinking them', (
    tester,
  ) async {
    await pumpDialer(tester, size: const Size(320, 568));
    final digit = find.byKey(const ValueKey('apple-dial-key-1'));
    final regular = tester.getSize(digit).width;
    await pumpDialer(tester, size: const Size(320, 568), textScale: 2.6);
    expect(tester.getSize(digit).width, greaterThan(regular));
    expect(tester.getSize(digit).width, greaterThanOrEqualTo(76));
    await tester.ensureVisible(find.byTooltip('Call'));
    expect(find.byTooltip('Call').hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
  for (final size in [
    const Size(402, 874),
    const Size(430, 932),
    const Size(768, 1024),
  ]) {
    testWidgets(
      'actual key group and two tabs center with safe insets at $size',
      (tester) async {
        await pumpDialer(tester, size: size);
        final viewport = tester.getRect(find.byType(SingleChildScrollView));
        final group = tester.getRect(
          find.byKey(const ValueKey('apple-dial-controls')),
        );
        final firstKey = tester.getRect(
          find.byKey(const ValueKey('apple-dial-key-1')),
        );
        final call = tester.getRect(
          find.byKey(const ValueKey('apple-dial-call')),
        );
        final delete = tester.getRect(
          find.byKey(const ValueKey('apple-dial-delete')),
        );
        expect(group.top, firstKey.top);
        expect(group.bottom, call.bottom);
        expect(group.center.dy, closeTo(viewport.center.dy, .1));
        expect(call.center.dx, closeTo(viewport.center.dx, .1));
        expect(call.center.dy, delete.center.dy);
        expect(call.height, delete.height);
        final bar = tester.getRect(
          find.byKey(const ValueKey('apple-dial-tabs')),
        );
        final recents = tester.getRect(
          find.byKey(const ValueKey('apple-dial-tab-recents')),
        );
        final keypad = tester.getRect(
          find.byKey(const ValueKey('apple-dial-tab-keypad')),
        );
        expect(bar.center.dx, closeTo(size.width / 2, .1));
        expect(bar.width, lessThanOrEqualTo(390));
        expect(size.height - 34 - bar.bottom, closeTo(8, .1));
        expect(viewport.bottom + 8, closeTo(bar.top, .1));
        expect(recents.width, keypad.width);
        expect(recents.height, keypad.height);
        expect(
          bar.center.dx - recents.center.dx,
          closeTo(keypad.center.dx - bar.center.dx, .1),
        );
        for (final entry in [
          (recents, 'Recents', CupertinoIcons.clock_fill),
          (keypad, 'Keypad', CupertinoIcons.circle_grid_3x3_fill),
        ]) {
          final label = tester.getRect(find.text(entry.$2));
          final icon = tester.getRect(find.byIcon(entry.$3));
          expect(label.center.dx, closeTo(entry.$1.center.dx, .1));
          expect(icon.center.dx, closeTo(entry.$1.center.dx, .1));
          expect(label.left, greaterThanOrEqualTo(entry.$1.left));
          expect(label.right, lessThanOrEqualTo(entry.$1.right));
          expect(label.bottom, lessThan(entry.$1.bottom));
        }
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('large labels stay in equal safe cells on narrow dark screen', (
    tester,
  ) async {
    await pumpDialer(
      tester,
      size: const Size(320, 568),
      textScale: 2.6,
      dark: true,
      number: '+123456789012345678901234567890',
      status: 'The line is ready to make calls',
      error: 'A longer error message to exercise the layout',
    );
    final bar = tester.getRect(find.byKey(const ValueKey('apple-dial-tabs')));
    final recents = tester.getRect(
      find.byKey(const ValueKey('apple-dial-tab-recents')),
    );
    final keypad = tester.getRect(
      find.byKey(const ValueKey('apple-dial-tab-keypad')),
    );
    expect(recents.height, keypad.height);
    for (final entry in [
      ('apple-dial-tab-recents', 'Recents'),
      ('apple-dial-tab-keypad', 'Keypad'),
    ]) {
      final cell = tester.getRect(find.byKey(ValueKey(entry.$1)));
      final text = tester.getRect(find.text(entry.$2));
      expect(text.center.dx, closeTo(cell.center.dx, .1));
      expect(text.left, greaterThanOrEqualTo(cell.left));
      expect(text.right, lessThanOrEqualTo(cell.right));
      expect(text.bottom, lessThan(bar.bottom));
      final paragraph = tester.renderObject<RenderParagraph>(
        find.descendant(
          of: find.text(entry.$2),
          matching: find.byType(RichText),
        ),
      );
      expect(paragraph.didExceedMaxLines, isFalse);
    }
    final number = tester.getRect(
      find.byKey(const ValueKey('apple-dial-number')),
    );
    expect(number.left, greaterThanOrEqualTo(24));
    expect(number.right, lessThanOrEqualTo(296));
    await tester.ensureVisible(find.byTooltip('Call'));
    expect(tester.takeException(), isNull);
  });

  testWidgets('rapid digits, long zero, delete and tabs each act once', (
    tester,
  ) async {
    final digits = <String>[];
    var calls = 0;
    var deletes = 0;
    var backs = 0;
    await pumpDialer(
      tester,
      onDigit: digits.add,
      onCall: () => calls++,
      onDelete: () => deletes++,
      onBack: () => backs++,
    );
    for (final digit in ['1', '2', '3', '0', '1']) {
      await tester.tap(find.byKey(ValueKey('apple-dial-key-$digit')));
    }
    await tester.longPress(find.byKey(const ValueKey('apple-dial-key-0')));
    await tester.tap(find.byTooltip('Delete digit'));
    await tester.tap(find.byTooltip('Call'));
    await tester.tap(find.byKey(const ValueKey('apple-dial-tab-keypad')));
    expect(backs, 0);
    await tester.tap(find.byKey(const ValueKey('apple-dial-tab-recents')));
    expect(digits, ['1', '2', '3', '0', '1', '+']);
    expect(calls, 1);
    expect(deletes, 1);
    expect(backs, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('disabled actions expose disabled semantics and do not invoke', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    var calls = 0;
    var deletes = 0;
    await pumpDialer(
      tester,
      disabled: true,
      onCall: () => calls++,
      onDelete: () => deletes++,
    );
    for (final label in ['Call', 'Delete digit']) {
      expect(
        tester.getSemantics(find.byTooltip(label)),
        matchesSemantics(
          label: label,
          isButton: true,
          hasEnabledState: true,
          isEnabled: false,
        ),
      );
      await tester.tap(find.byTooltip(label));
    }
    expect(calls, 0);
    expect(deletes, 0);
    semantics.dispose();
  });

  testWidgets('cancelled press never enters a digit', (tester) async {
    final digits = <String>[];
    await pumpDialer(tester, onDigit: digits.add);
    final key = find.byKey(const ValueKey('apple-dial-key-5'));
    final gesture = await tester.startGesture(tester.getCenter(key));
    await tester.pump(const Duration(milliseconds: 150));
    await gesture.cancel();
    await tester.pumpAndSettle();
    expect(digits, isEmpty);
    final animation = tester.widget<AnimatedScale>(
      find.descendant(of: key, matching: find.byType(AnimatedScale)),
    );
    expect(animation.scale, 1);
  });

  testWidgets('disabling a held action cancels it and clears press feedback', (
    tester,
  ) async {
    var calls = 0;
    await pumpDialer(tester, onCall: () => calls++);
    final call = find.byKey(const ValueKey('apple-dial-call'));
    final gesture = await tester.startGesture(tester.getCenter(call));
    await tester.pump(const Duration(milliseconds: 150));
    await pumpDialer(tester, disabled: true, onCall: () => calls++);
    await gesture.up();
    await pumpDialer(tester, onCall: () => calls++);
    final animation = tester.widget<AnimatedScale>(
      find.descendant(of: call, matching: find.byType(AnimatedScale)),
    );
    expect(animation.scale, 1);
    expect(calls, 0);
    await tester.tap(call);
    expect(calls, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'reduced motion press keeps geometry and commits only at release',
    (tester) async {
      final digits = <String>[];
      await pumpDialer(tester, reducedMotion: true, onDigit: digits.add);
      final key = find.byKey(const ValueKey('apple-dial-key-5'));
      final initial = tester.getRect(key);
      final gesture = await tester.startGesture(initial.center);
      await tester.pump(const Duration(milliseconds: 150));
      expect(digits, isEmpty);
      expect(tester.getRect(key), initial);
      final animation = tester.widget<AnimatedScale>(
        find.descendant(of: key, matching: find.byType(AnimatedScale)),
      );
      expect(animation.duration, Duration.zero);
      expect(animation.scale, 1);
      await gesture.up();
      await tester.pump();
      expect(digits, ['5']);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'dial text explicitly uses iOS typography independent of Material',
    (tester) async {
      await pumpDialer(tester);
      final digit = tester.widget<Text>(find.text('2')).style!;
      final letters = tester.widget<Text>(find.text('ABC')).style!;
      final title = tester.widget<Text>(find.text('SIM')).style!;
      expect(digit.fontFamily, 'CupertinoSystemDisplay');
      expect(digit.fontSize, 36);
      expect(digit.fontWeight, FontWeight.w400);
      expect(digit.letterSpacing, 0);
      expect(digit.inherit, isFalse);
      expect(letters.fontFamily, 'CupertinoSystemText');
      expect(letters.fontSize, 11);
      expect(letters.fontWeight, FontWeight.w500);
      expect(title.fontFamily, 'CupertinoSystemText');
      expect(title.fontWeight, FontWeight.w400);
    },
  );

  testWidgets('dial controls remain vertically centered on tall screens', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(402, 874);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(
        home: AppleDialer(
          number: '',
          line: 'SIM',
          onDigit: (_) {},
          onDelete: () {},
          onCall: () {},
          onBack: () {},
        ),
      ),
    );
    final viewport = tester.getRect(find.byType(SingleChildScrollView));
    final controls = tester.getRect(
      find.byKey(const ValueKey('apple-dial-controls')),
    );
    expect(controls.center.dy, closeTo(viewport.center.dy, 1));
    expect(controls.top, greaterThanOrEqualTo(viewport.top));
    expect(controls.bottom, lessThanOrEqualTo(viewport.bottom));
    expect(tester.takeException(), isNull);
  });
  testWidgets(
    'native dialer accepts digits and long zero, supports small screens',
    (tester) async {
      tester.view.physicalSize = const Size(320, 700);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final digits = <String>[];
      var called = false;
      await tester.pumpWidget(
        MaterialApp(
          home: MediaQuery(
            data: const MediaQueryData(textScaler: TextScaler.linear(1.8)),
            child: AppleDialer(
              number: '1033',
              line: 'SIM',
              onDigit: digits.add,
              onDelete: () {},
              onCall: () => called = true,
              onBack: () {},
            ),
          ),
        ),
      );
      await tester.tap(find.text('1'));
      await tester.longPress(find.text('0'));
      expect(digits, ['1', '+']);
      await tester.ensureVisible(find.byTooltip('Call'));
      await tester.tap(find.byTooltip('Call'));
      expect(called, isTrue);
      expect(tester.takeException(), isNull);
    },
  );
}
