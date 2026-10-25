import 'dart:async';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/inbox_page.dart';
import 'package:nlpa2/vowifi/message_store.dart';
import 'package:nlpa2/settings/app_settings.dart';

class _Messages extends VoWifiMessageStore {
  String? queriedLine;
  bool fail = false;
  bool omitIncoming = false;
  bool extraPeer = false;
  final deleted = <Set<int>>[];

  @override
  Future<void> deleteRecords(Set<int> ids) async => deleted.add(Set.of(ids));
  @override
  Future<List<Map<String, Object?>>> list([String? lineKey]) async {
    queriedLine = lineKey;
    if (fail) throw StateError('Unavailable');
    return [
      if (!omitIncoming)
        {
          'id': 1,
          'line_key': 'line1234',
          'peer': '888',
          'content': 'Balance received',
          'direction': 'incoming',
          'state': 'received',
          'at': '2026-09-26T01:00:00Z',
        },
      {
        'id': 2,
        'line_key': 'line1234',
        'peer': '888',
        'content': 'BAL',
        'direction': 'outgoing',
        'state': 'submitted',
        'at': '2026-09-26T00:59:00Z',
      },
      if (extraPeer)
        {
          'id': 3,
          'line_key': 'line5678',
          'peer': '999',
          'content': 'Other message',
          'direction': 'incoming',
          'state': 'received',
          'at': '2026-09-26T00:58:00Z',
        },
    ];
  }
}

class _PendingMessages extends _Messages {
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
          final original = _PendingMessages();
          final replacement = replaceStore ? _PendingMessages() : original;
          await tester.pumpWidget(
            MaterialApp(
              home: VoWifiInboxPage(messages: original, lineKey: 'a'),
            ),
          );
          final stale = original.requests.single.$2;
          await tester.pumpWidget(
            MaterialApp(
              home: VoWifiInboxPage(
                messages: replacement,
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
              'content': 'Latest message',
              'direction': 'incoming',
              'state': 'received',
              'at': '2026-10-23T00:00:00Z',
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
                'content': 'Stale message',
                'direction': 'incoming',
                'state': 'received',
                'at': '2026-10-23T00:00:00Z',
              },
            ]);
          }
          await tester.pumpAndSettle();
          expect(find.text('Latest message'), findsOneWidget);
          expect(find.text('Stale message'), findsNothing);
          expect(find.text('1 records selected'), findsOneWidget);
          expect(
            find.text('Could not load messages. Pull down to retry.'),
            findsNothing,
          );
          expect(tester.takeException(), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
        },
      );
    }
  }

  testWidgets(
    'editing conversation selects records; search clears hidden selection',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      final store = _Messages()..extraPeer = true;
      await tester.pumpWidget(
        MaterialApp(home: VoWifiInboxPage(messages: store)),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();
      await tester.tapAt(tester.getCenter(find.text('Balance received')));
      await tester.pumpAndSettle();
      expect(find.text('2 records selected'), findsOneWidget);
      expect(find.byTooltip('Conversations'), findsNothing);
      await tester.enterText(find.byType(CupertinoSearchTextField), '999');
      await tester.pumpAndSettle();
      expect(find.text('Balance received'), findsNothing);
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
        {3},
      ]);
    },
  );

  testWidgets(
    'direction filter clears selection and deletes only displayed message IDs',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      final store = _Messages();
      await tester.pumpWidget(
        MaterialApp(home: VoWifiInboxPage(messages: store)),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Select all'));
      await tester.pumpAndSettle();
      expect(find.text('2 records selected'), findsOneWidget);
      await tester.tap(find.byTooltip('Filter messages'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Sent'));
      await tester.pumpAndSettle();
      expect(find.text('0 records selected'), findsOneWidget);
      await tester.tapAt(tester.getCenter(find.text('BAL')));
      await tester.pumpAndSettle();
      expect(find.text('1 records selected'), findsOneWidget);
      await tester.tap(find.text('Delete selected'));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(TextButton, 'Delete'));
      await tester.pumpAndSettle();
      expect(store.deleted, [
        {2},
      ]);
    },
  );

  testWidgets(
    'failed refresh retains selection and successful refresh prunes removed messages',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      final store = _Messages();
      await tester.pumpWidget(
        MaterialApp(home: VoWifiInboxPage(messages: store)),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Select all'));
      await tester.pumpAndSettle();
      store.fail = true;
      await tester.drag(find.byType(ListView).first, const Offset(0, 400));
      await tester.pumpAndSettle();
      expect(find.text('Balance received'), findsOneWidget);
      expect(find.text('2 records selected'), findsOneWidget);
      store
        ..fail = false
        ..omitIncoming = true;
      await tester.drag(find.byType(ListView).first, const Offset(0, 400));
      await tester.pumpAndSettle();
      expect(find.text('Balance received'), findsNothing);
      expect(find.text('1 records selected'), findsOneWidget);
    },
  );

  testWidgets('changing SIM scope clears selection', (tester) async {
    AppSettings().setRevealSensitiveProfileData(true);
    final store = _Messages();
    await tester.pumpWidget(
      MaterialApp(
        home: VoWifiInboxPage(messages: store, lineKey: 'a'),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Edit'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Select all'));
    await tester.pumpAndSettle();
    await tester.pumpWidget(
      MaterialApp(
        home: VoWifiInboxPage(messages: store, lineKey: 'b'),
      ),
    );
    await tester.pumpAndSettle();
    expect(store.queriedLine, 'b');
    expect(find.text('0 records selected'), findsOneWidget);
  });
  testWidgets(
    'inbox opens persisted incoming messages without live reader; sent keeps delivery distinction',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      final store = _Messages();
      await tester.pumpWidget(
        MaterialApp(
          home: VoWifiInboxPage(lineKey: 'line1234', messages: store),
        ),
      );
      await tester.pumpAndSettle();
      expect(store.queriedLine, 'line1234');
      expect(find.text('Balance received'), findsOneWidget);
      expect(find.text('BAL'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('vowifi-privacy-toggle')));
      await tester.pumpAndSettle();
      expect(find.text('Message hidden'), findsOneWidget);
      expect(find.text('Balance received'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('vowifi-privacy-toggle')));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Filter messages'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Sent'));
      await tester.pumpAndSettle();
      expect(find.text('BAL'), findsOneWidget);
      expect(find.text('Balance received'), findsNothing);
      await tester.tap(find.text('BAL'));
      await tester.pumpAndSettle();
      expect(find.text('Balance received'), findsOneWidget);
      expect(
        find.textContaining('Submitted, delivery unconfirmed'),
        findsOneWidget,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('conversation keeps privacy until explicitly revealed', (
    tester,
  ) async {
    AppSettings().setRevealSensitiveProfileData(false);
    await tester.pumpWidget(
      MaterialApp(home: VoWifiInboxPage(messages: _Messages())),
    );
    await tester.pumpAndSettle();
    expect(find.text('Balance received'), findsNothing);
    await tester.tap(find.text('Message hidden'));
    await tester.pumpAndSettle();
    expect(find.text('Balance received'), findsNothing);
    expect(find.text('BAL'), findsNothing);
    await tester.tap(find.byKey(const ValueKey('vowifi-privacy-toggle')));
    await tester.pumpAndSettle();
    expect(find.text('Balance received'), findsOneWidget);
    expect(find.text('BAL'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('vowifi-privacy-toggle')));
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Conversations'));
    await tester.pumpAndSettle();
    expect(find.text('Balance received'), findsNothing);
    expect(find.text('Message hidden'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'stored messages remain accessible across SIMs and refresh errors do not erase them',
    (tester) async {
      AppSettings().setRevealSensitiveProfileData(true);
      final store = _Messages();
      await tester.pumpWidget(
        MaterialApp(home: VoWifiInboxPage(messages: store)),
      );
      await tester.pumpAndSettle();
      expect(store.queriedLine, isNull);
      expect(find.text('SIM ····1234'), findsOneWidget);
      store.fail = true;
      await tester.drag(find.byType(ListView).first, const Offset(0, 400));
      await tester.pumpAndSettle();
      expect(find.text('Balance received'), findsOneWidget);
      expect(
        find.text('Could not load messages. Pull down to retry.'),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
