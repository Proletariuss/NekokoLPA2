import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/glass_surface.dart';

const _channel = MethodChannel('proletarius/vowifi');

Widget _app({
  MediaQueryData media = const MediaQueryData(),
  Widget child = const Text('Test'),
}) => MaterialApp(
  home: MediaQuery(
    data: media,
    child: Scaffold(
      body: Center(
        child: SizedBox(
          width: 300,
          height: 100,
          child: CommunicationGlass(child: child),
        ),
      ),
    ),
  ),
);

void _appearance(
  WidgetTester tester,
  Future<Object?> Function(MethodCall) handler,
) {
  tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
    _channel,
    handler,
  );
  addTearDown(
    () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      _channel,
      null,
    ),
  );
}

void _resume(WidgetTester tester) {
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
  tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
}

void _expectOpaque(WidgetTester tester, bool opaque) {
  expect(
    tester.widget<BackdropFilter>(find.byType(BackdropFilter)).enabled,
    !opaque,
  );
  // Disabled filters must not submit a backdrop layer to the scene.
  expect(
    tester.layers.whereType<BackdropFilterLayer>(),
    hasLength(opaque ? 0 : 1),
  );
  final surface = tester.widget<DecoratedBox>(
    find
        .descendant(
          of: find.byType(BackdropFilter),
          matching: find.byType(DecoratedBox),
        )
        .first,
  );
  final color = (surface.decoration as BoxDecoration).color!;
  expect(color.a, closeTo(opaque ? 1 : .88, .001));
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  for (final reduce in [true, false]) {
    testWidgets('glass respects reduce transparency $reduce', (tester) async {
      const channel = MethodChannel('proletarius/vowifi');
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        channel,
        (_) async => reduce,
      );
      addTearDown(
        () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          channel,
          null,
        ),
      );
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(body: CommunicationGlass(child: Text('Test'))),
        ),
      );
      await tester.pumpAndSettle();
      _expectOpaque(tester, reduce);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('late appearance response cannot undo the resumed preference', (
    tester,
  ) async {
    const channel = MethodChannel('proletarius/vowifi');
    final requests = <Completer<bool>>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (
      _,
    ) {
      final request = Completer<bool>();
      requests.add(request);
      return request.future;
    });
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        channel,
        null,
      ),
    );
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(body: CommunicationGlass(child: Text('Test'))),
      ),
    );
    expect(requests, hasLength(1));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(requests, hasLength(2));
    requests.last.complete(true);
    await tester.pumpAndSettle();
    requests.first.complete(false);
    await tester.pumpAndSettle();
    _expectOpaque(tester, true);
    expect(tester.takeException(), isNull);
  });

  for (final preference in <String, MediaQueryData>{
    'accessible navigation': const MediaQueryData(accessibleNavigation: true),
    'high contrast': const MediaQueryData(highContrast: true),
  }.entries) {
    testWidgets('${preference.key} uses opaque surface', (tester) async {
      _appearance(tester, (_) async => false);
      await tester.pumpWidget(_app(media: preference.value));
      await tester.pumpAndSettle();
      _expectOpaque(tester, true);
    });
  }

  for (final failure in ['missing plugin', 'platform error', 'null response']) {
    testWidgets('$failure uses opaque fallback, also after resume', (
      tester,
    ) async {
      var fail = true;
      _appearance(tester, (_) async {
        if (!fail) return false;
        if (failure == 'missing plugin') throw MissingPluginException();
        if (failure == 'platform error') {
          throw PlatformException(code: 'unavailable');
        }
        return null;
      });
      await tester.pumpWidget(_app());
      await tester.pumpAndSettle();
      _expectOpaque(tester, true);
      fail = false;
      _resume(tester);
      await tester.pumpAndSettle();
      _expectOpaque(tester, false);
      fail = true;
      _resume(tester);
      await tester.pumpAndSettle();
      _expectOpaque(tester, true);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('appearance and accessibility changes preserve editable state', (
    tester,
  ) async {
    final initial = Completer<bool>();
    var reduce = false;
    var calls = 0;
    _appearance(
      tester,
      (_) => calls++ == 0 ? initial.future : Future.value(reduce),
    );
    const child = TextField(key: ValueKey('number'));
    await tester.pumpWidget(_app(child: child));
    await tester.enterText(find.byType(TextField), '12345');
    final editable = tester.state<EditableTextState>(find.byType(EditableText));
    final field = tester.state(find.byType(TextField));
    final rect = tester.getRect(find.byType(TextField));
    final selection = editable.textEditingValue.selection;

    void expectPreserved() {
      expect(tester.state(find.byType(TextField)), same(field));
      expect(tester.state(find.byType(EditableText)), same(editable));
      expect(editable.textEditingValue.text, '12345');
      expect(editable.textEditingValue.selection, selection);
      expect(editable.widget.focusNode.hasFocus, isTrue);
      expect(tester.getRect(find.byType(TextField)), rect);
    }

    initial.complete(false);
    await tester.pump();
    expectPreserved();
    for (final value in [true, false]) {
      reduce = value;
      _resume(tester);
      await tester.pump();
      expectPreserved();
      _expectOpaque(tester, value);
    }
    for (final media in [
      const MediaQueryData(accessibleNavigation: true),
      const MediaQueryData(highContrast: true),
      const MediaQueryData(),
    ]) {
      await tester.pumpWidget(_app(media: media, child: child));
      expectPreserved();
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('disposed glass ignores pending appearance and lifecycle', (
    tester,
  ) async {
    final request = Completer<bool>();
    var calls = 0;
    _appearance(tester, (_) {
      calls++;
      return request.future;
    });
    await tester.pumpWidget(_app());
    await tester.pumpWidget(const SizedBox.shrink());
    request.complete(false);
    await tester.pumpAndSettle();
    _resume(tester);
    await tester.pumpAndSettle();
    expect(calls, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('stale appearance error cannot override a newer preference', (
    tester,
  ) async {
    final initial = Completer<bool>();
    var calls = 0;
    _appearance(
      tester,
      (_) => calls++ == 0 ? initial.future : Future.value(false),
    );
    await tester.pumpWidget(_app());
    _resume(tester);
    await tester.pumpAndSettle();
    _expectOpaque(tester, false);
    initial.completeError(PlatformException(code: 'stale'));
    await tester.pumpAndSettle();
    _expectOpaque(tester, false);
    expect(tester.takeException(), isNull);
  });

  testWidgets('child paint updates do not dirty the bounded backdrop', (
    tester,
  ) async {
    _appearance(tester, (_) async => false);
    const childKey = ValueKey('painted child');
    await tester.pumpWidget(
      _app(
        child: const DecoratedBox(
          key: childKey,
          decoration: BoxDecoration(color: Colors.red),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final filter = tester.renderObject<RenderBackdropFilter>(
      find.byType(BackdropFilter),
    );
    final layer = filter.layer;
    final blur = tester
        .widget<BackdropFilter>(find.byType(BackdropFilter))
        .filter;
    final child = tester.renderObject<RenderDecoratedBox>(find.byKey(childKey));
    child.decoration = const BoxDecoration(color: Colors.blue);
    expect(filter.debugNeedsPaint, isFalse);
    await tester.pump();
    expect(filter.layer, same(layer));
    await tester.pumpWidget(
      _app(
        child: const DecoratedBox(
          key: childKey,
          decoration: BoxDecoration(color: Colors.green),
        ),
      ),
    );
    expect(
      tester.widget<BackdropFilter>(find.byType(BackdropFilter)).filter,
      same(blur),
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('glass keeps child hit region across appearance changes', (
    tester,
  ) async {
    var reduce = true;
    var taps = 0;
    _appearance(tester, (_) async => reduce);
    const target = ValueKey('target');
    await tester.pumpWidget(
      _app(
        child: GestureDetector(
          key: target,
          behavior: HitTestBehavior.opaque,
          onTap: () => taps++,
          child: const SizedBox.expand(),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final rect = tester.getRect(find.byKey(target));
    for (final value in [true, false, true]) {
      reduce = value;
      _resume(tester);
      await tester.pumpAndSettle();
      expect(tester.getRect(find.byKey(target)), rect);
      // A point near the straight edge, inside the existing rounded clip.
      await tester.tapAt(Offset(rect.left + 2, rect.center.dy));
    }
    expect(taps, 3);
    expect(tester.takeException(), isNull);
  });
}
