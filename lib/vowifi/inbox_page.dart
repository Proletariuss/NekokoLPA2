import 'l10n.dart';
import 'dart:async';
import 'record_actions.dart';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'glass_surface.dart';

import 'message_store.dart';
import 'conversations.dart';
import 'privacy_redaction.dart';
import '../settings/app_settings.dart';

/// Reads committed messages without acquiring a reader or starting another IMS
/// session. It remains usable after disconnecting a reader or restarting iOS.
class VoWifiInboxPage extends StatefulWidget {
  const VoWifiInboxPage({
    super.key,
    this.lineKey,
    this.messages,
    this.onReply,
    this.onCompose,
  });

  final String? lineKey;
  final VoWifiMessageStore? messages;
  final void Function(String lineKey, String peer)? onReply;
  final VoidCallback? onCompose;

  @override
  State<VoWifiInboxPage> createState() => _VoWifiInboxPageState();
}

class _VoWifiInboxPageState extends State<VoWifiInboxPage> {
  late VoWifiMessageStore _store;
  StreamSubscription<void>? _updates;
  List<Map<String, Object?>> _messages = [];
  String _direction = 'all';
  (String, String)? _conversation;
  String _query = '';
  bool _loading = true;
  final _selection = RecordSelection();
  void _selectionChanged() {
    if (mounted) setState(() {});
  }

  bool _failed = false;
  int _loadGeneration = 0;
  final AppSettings _appSettings = AppSettings();

  @override
  void initState() {
    super.initState();
    _selection.addListener(_selectionChanged);
    _appSettings.addListener(_onPrivacySettingsChanged);
    _store = widget.messages ?? VoWifiMessageStore();
    _updates = VoWifiMessageStore.changes.listen((_) => unawaited(_load()));
    unawaited(_load());
  }

  void _onPrivacySettingsChanged() {
    if (mounted) _selection.clear();
  }

  @override
  void didUpdateWidget(covariant VoWifiInboxPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.lineKey != widget.lineKey ||
        oldWidget.messages != widget.messages) {
      if (oldWidget.messages != widget.messages) {
        _store = widget.messages ?? VoWifiMessageStore();
      }
      _selection.clear();
      _conversation = null;
      _messages = [];
      _loading = true;
      _failed = false;
      unawaited(_load());
    }
  }

  Future<void> _load() async {
    final generation = ++_loadGeneration;
    try {
      final messages = await _store.list(widget.lineKey);
      if (!mounted || generation != _loadGeneration) return;
      _selection.retain(
        messages.map((row) => row['id']).whereType<int>().toSet(),
      );
      setState(() {
        _messages = messages;
        _failed = false;
        _loading = false;
      });
    } catch (_) {
      if (!mounted || generation != _loadGeneration) return;
      setState(() {
        _failed = true;
        _loading = false;
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
    final theme = Theme.of(context);
    final messages = _messages
        .where(
          (message) =>
              _direction == 'all' || message['direction'] == _direction,
        )
        .toList(growable: false);
    final groups = groupVoWifiMessages(messages)
        .where(
          (group) =>
              VoWifiPrivacy.isEnabled ||
              _query.isEmpty ||
              (!VoWifiPrivacy.isEnabled &&
                  (group.peer.contains(_query) ||
                      group.messages.any(
                        (m) => (m['content'] as String? ?? '')
                            .toLowerCase()
                            .contains(_query.toLowerCase()),
                      ))),
        )
        .toList();
    if (_conversation != null) return _conversationView();
    return Scaffold(
      backgroundColor: CupertinoColors.systemBackground.resolveFrom(context),
      appBar: AppBar(
        backgroundColor: CupertinoColors.systemBackground.resolveFrom(context),
        surfaceTintColor: Colors.transparent,
        actions: [
          PopupMenuButton<String>(
            tooltip: voWifiL10n(context).voWifiFilterMessages,
            icon: const Icon(
              CupertinoIcons.line_horizontal_3_decrease,
              size: 27,
            ),
            initialValue: _direction,
            onSelected: (value) {
              if (value == _direction) return;
              _selection.clear();
              setState(() => _direction = value);
            },
            itemBuilder: (_) => [
              PopupMenuItem(
                value: 'all',
                child: Text(voWifiL10n(context).voWifiAll),
              ),
              PopupMenuItem(
                value: 'incoming',
                child: Text(voWifiL10n(context).voWifiInbox),
              ),
              PopupMenuItem(
                value: 'outgoing',
                child: Text(voWifiL10n(context).voWifiSent),
              ),
            ],
          ),
          const VoWifiPrivacyAction(),
        ],
      ),
      bottomNavigationBar: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 8, 16, 12),
          child: CommunicationGlass(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              child: Row(
                children: [
                  Expanded(
                    child: CupertinoSearchTextField(
                      placeholder: VoWifiPrivacy.isEnabled
                          ? voWifiL10n(context).voWifiUnhideToSearch
                          : voWifiL10n(context).voWifiSearch,
                      enabled: !VoWifiPrivacy.isEnabled,
                      onChanged: (value) {
                        if (value == _query) return;
                        _selection.clear();
                        setState(() => _query = value);
                      },
                    ),
                  ),
                  if (widget.onCompose != null) ...[
                    const SizedBox(width: 12),
                    IconButton(
                      onPressed: widget.onCompose,
                      tooltip: voWifiL10n(context).voWifiNewMessage,
                      icon: const Icon(CupertinoIcons.square_pencil, size: 28),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
      body: SafeArea(
        child: Column(
          children: [
            recordToolbar(
              context,
              _selection,
              groups
                  .expand((group) => group.messages)
                  .map((row) => row['id'])
                  .whereType<int>()
                  .toSet(),
              _store.deleteRecords,
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 8, 20, 0),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  voWifiL10n(context).voWifiMessages,
                  style: theme.textTheme.headlineLarge?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ),
            if (_loading) const LinearProgressIndicator(),
            if (_failed)
              Padding(
                padding: const EdgeInsets.all(20),
                child: Text(
                  voWifiL10n(context).voWifiCouldNotLoadMessagesPullDownToRetry,
                  style: TextStyle(color: theme.colorScheme.error),
                ),
              ),
            Expanded(
              child: RefreshIndicator(
                onRefresh: _load,
                child: ListView.separated(
                  separatorBuilder: (_, _) =>
                      const Divider(height: 1, indent: 64),
                  physics: const AlwaysScrollableScrollPhysics(),
                  padding: const EdgeInsets.all(20),
                  itemCount: groups.isEmpty ? 1 : groups.length,
                  itemBuilder: (context, index) {
                    if (groups.isEmpty) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 48),
                        child: Column(
                          children: [
                            Icon(
                              _direction == 'incoming'
                                  ? CupertinoIcons.tray
                                  : CupertinoIcons.paperplane,
                              size: 36,
                              color: theme.colorScheme.primary,
                            ),
                            const SizedBox(height: 12),
                            Text(
                              _direction == 'all'
                                  ? voWifiL10n(context).voWifiNoConversations
                                  : _direction == 'incoming'
                                  ? voWifiL10n(
                                      context,
                                    ).voWifiNoReceivedMessagesYet
                                  : voWifiL10n(context).voWifiNoSentMessagesYet,
                              style: theme.textTheme.titleMedium,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              voWifiL10n(
                                context,
                              ).voWifiConnectWiFiCallingAndKeepTheAppIn,
                              textAlign: TextAlign.center,
                              style: theme.textTheme.bodySmall,
                            ),
                          ],
                        ),
                      );
                    }
                    final group = groups[index];
                    final latest = group.messages.first;
                    final suffix = group.lineKey.length > 4
                        ? group.lineKey.substring(group.lineKey.length - 4)
                        : group.lineKey;
                    return recordSwipe(
                      context,
                      identity: '${group.lineKey}|${group.peer}',
                      ids: group.messages
                          .map((m) => m['id'])
                          .whereType<int>()
                          .toSet(),
                      unread: group.messages.any(
                        (m) =>
                            m['is_read'] == 0 && m['direction'] == 'incoming',
                      ),
                      selection: _selection,
                      read: _store.markRead,
                      remove: _store.deleteRecords,
                      child: ListTile(
                        contentPadding: const EdgeInsets.symmetric(vertical: 8),
                        leading: CircleAvatar(
                          radius: 24,
                          backgroundColor: theme.colorScheme.primary.withValues(
                            alpha: 0.15,
                          ),
                          child: Icon(
                            CupertinoIcons.person_fill,
                            color: theme.colorScheme.primary,
                            size: 30,
                          ),
                        ),
                        title: Row(
                          children: [
                            Expanded(
                              child: Text(
                                VoWifiPrivacy.phoneNumber(group.peer),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.titleMedium?.copyWith(
                                  fontSize: 17,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Text(
                              _conversationDate(latest['at'] as String? ?? ''),
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                        subtitle: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              VoWifiPrivacy.privateText(
                                latest['content'] as String? ?? '',
                                voWifiL10n(context).voWifiMessageHidden,
                              ),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                            if (widget.lineKey == null)
                              Text(
                                'SIM ····${VoWifiPrivacy.lineSuffix(suffix)}',
                                style: theme.textTheme.bodySmall,
                              ),
                          ],
                        ),
                        trailing: const Icon(
                          CupertinoIcons.chevron_forward,
                          size: 16,
                        ),
                        onTap: () {
                          _selection.clear();
                          setState(
                            () => _conversation = (group.lineKey, group.peer),
                          );
                        },
                      ),
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

  String _conversationDate(String value) {
    final date = DateTime.tryParse(value)?.toLocal();
    if (date == null) return '';
    final now = DateTime.now();
    if (DateUtils.isSameDay(date, now)) {
      return '${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
    }
    if (DateUtils.isSameDay(date, DateTime(now.year, now.month, now.day - 1))) {
      return voWifiL10n(context).voWifiYesterday;
    }
    return '${date.month}/${date.day}';
  }

  Widget _conversationView() {
    final key = _conversation!;
    final rows =
        _messages
            .where((m) => m['line_key'] == key.$1 && m['peer'] == key.$2)
            .toList()
          ..sort(
            (a, b) =>
                (a['at'] as String? ?? '').compareTo(b['at'] as String? ?? ''),
          );
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) setState(() => _conversation = null);
      },
      child: Scaffold(
        backgroundColor: CupertinoColors.systemGroupedBackground.resolveFrom(
          context,
        ),
        appBar: AppBar(
          leading: IconButton(
            icon: const Icon(CupertinoIcons.back),
            tooltip: voWifiL10n(context).voWifiConversations,
            onPressed: () => setState(() => _conversation = null),
          ),
          title: Text(
            VoWifiPrivacy.phoneNumber(key.$2),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          actions: [const VoWifiPrivacyAction()],
        ),
        body: SafeArea(
          child: Column(
            children: [
              Expanded(
                child: ListView(
                  padding: const EdgeInsets.all(16),
                  children: rows
                      .map(
                        (row) => Align(
                          alignment: row['direction'] == 'outgoing'
                              ? Alignment.centerRight
                              : Alignment.centerLeft,
                          child: FractionallySizedBox(
                            widthFactor: .88,
                            child: _messageTile(row),
                          ),
                        ),
                      )
                      .toList(),
                ),
              ),
              if (widget.onReply != null)
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      icon: const Icon(CupertinoIcons.square_pencil),
                      label: Text(voWifiL10n(context).voWifiReply),
                      onPressed: () => widget.onReply!(key.$1, key.$2),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _messageTile(Map<String, Object?> message) {
    final theme = Theme.of(context);
    final date = DateTime.tryParse(message['at'] as String? ?? '')?.toLocal();
    final time = date == null
        ? ''
        : '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')} '
              '${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
    final state = switch (message['state']) {
      'received' => voWifiL10n(context).voWifiReceived,
      'submitted' => voWifiL10n(context).voWifiSubmittedDeliveryUnconfirmed,
      'submitting' => voWifiL10n(context).voWifiSubmitting,
      'failed' => voWifiL10n(context).voWifiFailed,
      _ => message['state'] as String? ?? '',
    };
    final line = message['line_key'] as String? ?? '';
    final suffix = line.length > 4 ? line.substring(line.length - 4) : line;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Card(
        color: message['direction'] == 'outgoing'
            ? CupertinoColors.systemGreen
                  .resolveFrom(context)
                  .withValues(alpha: .16)
            : CupertinoColors.secondarySystemGroupedBackground.resolveFrom(
                context,
              ),
        margin: EdgeInsets.zero,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SelectableText(
                VoWifiPrivacy.phoneNumber(message['peer'] as String? ?? ''),
                style: theme.textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              SelectableText(
                VoWifiPrivacy.privateText(
                  message['content'] as String? ?? '',
                  voWifiL10n(context).voWifiMessageHidden,
                ),
              ),
              const SizedBox(height: 10),
              Text('$state · $time', style: theme.textTheme.bodySmall),
              if (widget.lineKey == null && suffix.isNotEmpty)
                Text(
                  'SIM ····${VoWifiPrivacy.lineSuffix(suffix)}',
                  style: theme.textTheme.labelSmall,
                ),
            ],
          ),
        ),
      ),
    );
  }
}
