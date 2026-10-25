import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/record_actions.dart';

void main() {
  testWidgets(
    'toolbar captures visible IDs and delete callback before confirmation',
    (tester) async {
      final selection = RecordSelection()
        ..toggleMode()
        ..toggle({1, 2});
      var visible = <int>{1};
      final originalDeletes = <Set<int>>[];
      final replacementDeletes = <Set<int>>[];
      Future<void> Function(Set<int>) remove = (ids) async {
        originalDeletes.add(ids);
      };
      late StateSetter rebuild;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: StatefulBuilder(
              builder: (context, setState) {
                rebuild = setState;
                return recordToolbar(context, selection, visible, remove);
              },
            ),
          ),
        ),
      );
      expect(find.text('1 records selected'), findsOneWidget);
      await tester.tap(find.text('Delete selected'));
      await tester.pumpAndSettle();
      rebuild(() {
        visible = {2, 3};
        remove = (ids) async {
          replacementDeletes.add(ids);
        };
      });
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(TextButton, 'Delete'));
      await tester.pumpAndSettle();
      expect(originalDeletes, [
        {1},
      ]);
      expect(replacementDeletes, isEmpty);
      expect(selection.selected, {2});
      selection.dispose();
    },
  );

  testWidgets('left marks read, right requires deletion confirmation', (
    tester,
  ) async {
    final selection = RecordSelection();
    var reads = 0;
    var deletes = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => recordSwipe(
              context,
              identity: 'a',
              ids: {1},
              unread: true,
              selection: selection,
              read: (_) async {
                reads++;
              },
              remove: (_) async {
                deletes++;
              },
              child: const SizedBox(height: 80, child: Text('Record')),
            ),
          ),
        ),
      ),
    );
    await tester.drag(find.byType(Dismissible), const Offset(-600, 0));
    await tester.pumpAndSettle();
    expect(reads, 1);
    expect(deletes, 0);
    await tester.drag(find.byType(Dismissible), const Offset(600, 0));
    await tester.pumpAndSettle();
    expect(deletes, 0);
    await tester.tap(find.widgetWithText(TextButton, 'Delete'));
    await tester.pumpAndSettle();
    expect(deletes, 1);
  });

  testWidgets('confirmation locks actions and keeps an immutable ID snapshot', (
    tester,
  ) async {
    final selection = RecordSelection();
    final ids = <int>{1, 2};
    Set<int>? removed;
    var duplicateCalls = 0;
    late BuildContext pageContext;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) {
              pageContext = context;
              return const SizedBox();
            },
          ),
        ),
      ),
    );
    final pending = selection.perform(pageContext, ids, (value) async {
      removed = value;
    }, deleting: true);
    expect(selection.busy, isTrue);
    await tester.pumpAndSettle();
    expect(
      find.text(
        'Delete the 2 selected records from this device? This cannot be undone.',
      ),
      findsOneWidget,
    );
    ids
      ..clear()
      ..add(3);
    selection.toggle({4});
    expect(selection.selected, isEmpty);
    await selection.perform(pageContext, {9}, (_) async {
      duplicateCalls++;
    }, deleting: true);
    await tester.tap(find.widgetWithText(TextButton, 'Delete'));
    await tester.pumpAndSettle();
    await pending;
    expect(removed, {1, 2});
    expect(() => removed!.add(5), throwsUnsupportedError);
    expect(duplicateCalls, 0);
    expect(selection.busy, isFalse);
    selection.dispose();
  });

  testWidgets('scope changes cancel a pending confirmed deletion', (
    tester,
  ) async {
    final selection = RecordSelection();
    var removed = false;
    late BuildContext pageContext;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) {
              pageContext = context;
              return const SizedBox();
            },
          ),
        ),
      ),
    );
    final pending = selection.perform(pageContext, {1}, (_) async {
      removed = true;
    }, deleting: true);
    await tester.pumpAndSettle();
    selection.clear();
    await tester.tap(find.widgetWithText(TextButton, 'Delete'));
    await tester.pumpAndSettle();
    await pending;
    expect(removed, isFalse);
    expect(selection.busy, isFalse);
    selection.dispose();
  });

  testWidgets('cancel and failed delete preserve selection and release busy', (
    tester,
  ) async {
    final selection = RecordSelection()..toggle({1});
    late BuildContext pageContext;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) {
              pageContext = context;
              return const SizedBox();
            },
          ),
        ),
      ),
    );
    final pending = selection.perform(pageContext, {1}, (_) async {
      throw StateError('failed');
    }, deleting: true);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();
    await pending;
    expect(selection.selected, {1});
    expect(selection.busy, isFalse);
    await selection.perform(pageContext, {1}, (_) async {
      throw StateError('failed');
    });
    await tester.pump();
    expect(find.text('Could not update records. Try again.'), findsOneWidget);
    expect(selection.selected, {1});
    expect(selection.busy, isFalse);
    selection.dispose();
  });

  testWidgets('disposal during confirmation prevents the callback', (
    tester,
  ) async {
    final selection = RecordSelection();
    var removed = false;
    late BuildContext pageContext;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) {
              pageContext = context;
              return const SizedBox();
            },
          ),
        ),
      ),
    );
    final pending = selection.perform(pageContext, {1}, (_) async {
      removed = true;
    }, deleting: true);
    await tester.pumpAndSettle();
    selection.dispose();
    await tester.tap(find.widgetWithText(TextButton, 'Delete'));
    await tester.pumpAndSettle();
    await pending;
    expect(removed, isFalse);
    expect(tester.takeException(), isNull);
  });

  testWidgets('disposal during an action safely ignores its late failure', (
    tester,
  ) async {
    final selection = RecordSelection();
    final completion = Completer<void>();
    late BuildContext pageContext;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (context) {
              pageContext = context;
              return const SizedBox();
            },
          ),
        ),
      ),
    );
    final pending = selection.perform(pageContext, {
      1,
    }, (_) => completion.future);
    selection.dispose();
    await tester.pumpWidget(const SizedBox());
    completion.completeError(StateError('failed'));
    await pending;
    expect(tester.takeException(), isNull);
  });
}
