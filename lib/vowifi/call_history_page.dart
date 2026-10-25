import 'l10n.dart';
import 'dart:async';
import 'record_actions.dart';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';

import 'call_store.dart';
import 'privacy_redaction.dart';
import '../settings/app_settings.dart';

class VoWifiCallHistoryPage extends StatefulWidget {
  const VoWifiCallHistoryPage({
    super.key,
    this.lineKey,
    this.calls,
    this.onSelectNumber,
    this.onDial,
  });

  final String? lineKey;
  final VoWifiCallStore? calls;
  final void Function(String lineKey, String peer)? onSelectNumber;
  final VoidCallback? onDial;

  @override
  State<VoWifiCallHistoryPage> createState() => _VoWifiCallHistoryPageState();
}

class _VoWifiCallHistoryPageState extends State<VoWifiCallHistoryPage> {
  late VoWifiCallStore _store;
  StreamSubscription<void>? _updates;
  List<Map<String, Object?>> _calls = [];
  bool _loading = true;
  final _selection = RecordSelection();
  void _selectionChanged() {
    if (mounted) setState(() {});
  }

  bool _failed = false;
  int _loadGeneration = 0;
  String _filter = 'all';
  final AppSettings _appSettings = AppSettings();

  @override
  void initState() {
    super.initState();
    _selection.addListener(_selectionChanged);
    _appSettings.addListener(_onPrivacySettingsChanged);
    _store = widget.calls ?? VoWifiCallStore();
    _updates = VoWifiCallStore.changes.listen((_) => unawaited(_load()));
    unawaited(_load());
  }

  void _onPrivacySettingsChanged() {
    if (mounted) setState(() {});
  }

  @override
  void didUpdateWidget(covariant VoWifiCallHistoryPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.lineKey != widget.lineKey ||
        oldWidget.calls != widget.calls) {
      if (oldWidget.calls != widget.calls) {
        _store = widget.calls ?? VoWifiCallStore();
      }
      _selection.clear();
      _calls = [];
      _loading = true;
      _failed = false;
      unawaited(_load());
    }
  }

  Future<void> _load() async {
    final generation = ++_loadGeneration;
    try {
      final calls = await _store.list(widget.lineKey);
      if (!mounted || generation != _loadGeneration) return;
      _selection.retain(calls.map((row) => row['id']).whereType<int>().toSet());
      setState(() {
        _calls = calls;
        _loading = false;
        _failed = false;
      });
    } catch (_) {
      if (!mounted || generation != _loadGeneration) return;
      setState(() {
        _loading = false;
        _failed = true;
      });
    }
  }

  @override
  void dispose() {
    _selection.removeListener(_selectionChanged);
    _selection.dispose();
    _updates?.cancel();
    _appSettings.removeListener(_onPrivacySettingsChanged);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final rows = _calls
        .where((call) => _filter == 'all' || call['outcome'] == 'missed')
        .toList(growable: false);
    return Scaffold(
      appBar: AppBar(
        title: Text(voWifiL10n(context).voWifiCallHistory),
        actions: [
          const VoWifiPrivacyAction(),
          IconButton(
            onPressed: _loading ? null : _load,
            tooltip: voWifiL10n(context).voWifiRefreshCallHistory,
            icon: const Icon(CupertinoIcons.refresh),
          ),
        ],
      ),
      bottomNavigationBar: widget.onDial == null
          ? null
          : SafeArea(
              top: false,
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 12),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    IconButton(
                      key: const ValueKey('bottom-dial-button'),
                      onPressed: widget.onDial,
                      icon: const Icon(CupertinoIcons.circle_grid_3x3),
                      tooltip: voWifiL10n(context).voWifiKeypad,
                      iconSize: 30,
                      color: Theme.of(context).colorScheme.primary,
                      constraints: const BoxConstraints(
                        minWidth: 56,
                        minHeight: 56,
                      ),
                    ),
                  ],
                ),
              ),
            ),
      body: SafeArea(
        child: Column(
          children: [
            recordToolbar(
              context,
              _selection,
              rows.map((row) => row['id']).whereType<int>().toSet(),
              _store.deleteRecords,
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 8, 20, 12),
              child: SizedBox(
                width: double.infinity,
                child: CupertinoSlidingSegmentedControl<String>(
                  groupValue: _filter,
                  children: {
                    'all': Padding(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      child: Text(voWifiL10n(context).voWifiAllCalls),
                    ),
                    'missed': Text(voWifiL10n(context).voWifiMissed),
                  },
                  onValueChanged: (value) {
                    if (value != null && value != _filter) {
                      _selection.clear();
                      setState(() => _filter = value);
                    }
                  },
                ),
              ),
            ),
            if (_loading) const LinearProgressIndicator(),
            if (_failed)
              Padding(
                padding: const EdgeInsets.all(20),
                child: Text(
                  voWifiL10n(
                    context,
                  ).voWifiCouldNotLoadCallHistoryPullDownToRetry,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            Expanded(
              child: RefreshIndicator(
                onRefresh: _load,
                child: ListView.separated(
                  physics: const AlwaysScrollableScrollPhysics(),
                  padding: const EdgeInsets.fromLTRB(20, 4, 20, 24),
                  itemCount: rows.isEmpty ? 1 : rows.length,
                  separatorBuilder: (_, _) => const Divider(height: 1),
                  itemBuilder: (context, index) {
                    if (rows.isEmpty) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 56),
                        child: Column(
                          children: [
                            Icon(
                              CupertinoIcons.phone,
                              size: 36,
                              color: Theme.of(context).colorScheme.primary,
                            ),
                            const SizedBox(height: 12),
                            Text(voWifiL10n(context).voWifiNoCallHistoryYet),
                          ],
                        ),
                      );
                    }
                    final row = rows[index];
                    return recordSwipe(
                      context,
                      identity: 'call-${row['id']}',
                      ids: {if (row['id'] is int) row['id'] as int},
                      unread:
                          row['is_read'] == 0 && row['direction'] == 'incoming',
                      selection: _selection,
                      read: _store.markRead,
                      remove: _store.deleteRecords,
                      child: _callTile(row),
                    );
                  },
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _callTile(Map<String, Object?> call) {
    final theme = Theme.of(context);
    final incoming = call['direction'] == 'incoming';
    final outcome = call['outcome'] as String? ?? '';
    final attention = {'missed', 'failed', 'interrupted'}.contains(outcome);
    final result = switch (outcome) {
      'completed' => voWifiL10n(context).voWifiCompleted,
      'connected' => voWifiL10n(context).voWifiInCall,
      'missed' => voWifiL10n(context).voWifiMissed,
      'failed' => voWifiL10n(context).voWifiFailed,
      'declined' => voWifiL10n(context).voWifiDeclinedBusy,
      'unanswered' => voWifiL10n(context).voWifiNotAnswered,
      'interrupted' => voWifiL10n(context).voWifiInterruptedFinalStateUnknown,
      _ => voWifiL10n(context).voWifiConnecting,
    };
    final at = DateTime.tryParse(
      call['first_seen_at'] as String? ?? '',
    )?.toLocal();
    final time = at == null
        ? ''
        : '${at.year}-${at.month.toString().padLeft(2, '0')}-${at.day.toString().padLeft(2, '0')} '
              '${at.hour.toString().padLeft(2, '0')}:${at.minute.toString().padLeft(2, '0')}';
    final seconds = call['duration_seconds'] as int? ?? 0;
    final duration =
        '${seconds ~/ 60}:${(seconds % 60).toString().padLeft(2, '0')}';
    final direction = incoming
        ? voWifiL10n(context).voWifiIncoming
        : voWifiL10n(context).voWifiOutgoing;
    final line = call['line_key'] as String? ?? '';
    final suffix = line.length > 4 ? line.substring(line.length - 4) : line;
    final error = call['last_error'] as String? ?? '';
    final peer = call['peer'] as String? ?? '';
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            incoming
                ? CupertinoIcons.phone_arrow_down_left
                : CupertinoIcons.phone_arrow_up_right,
            size: 22,
            color: attention
                ? theme.colorScheme.error
                : theme.colorScheme.primary,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SelectableText(
                  peer.isEmpty
                      ? voWifiL10n(context).voWifiUnknownCaller
                      : VoWifiPrivacy.phoneNumber(peer),
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontSize: 17,
                    height: 1.3,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '$direction · $result',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: attention ? theme.colorScheme.error : null,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '$time · ${voWifiL10n(context).voWifiDuration} $duration',
                  style: theme.textTheme.bodySmall,
                ),
                if (widget.lineKey == null && suffix.isNotEmpty)
                  Text(
                    'SIM ····${VoWifiPrivacy.lineSuffix(suffix)}',
                    style: theme.textTheme.labelSmall,
                  ),
                if (error.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 6),
                    child: SelectableText(
                      VoWifiPrivacy.identifiers(error),
                      style: theme.textTheme.bodySmall,
                    ),
                  ),
              ],
            ),
          ),
          if (widget.onSelectNumber != null && peer.isNotEmpty)
            IconButton(
              tooltip: voWifiL10n(context).voWifiUseNumberInDialer,
              color: theme.colorScheme.primary,
              icon: const Icon(CupertinoIcons.phone),
              onPressed: _selection.editing || _selection.busy
                  ? null
                  : () => widget.onSelectNumber!(line, peer),
            ),
        ],
      ),
    );
  }
}
