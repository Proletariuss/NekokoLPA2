import 'l10n.dart';
import 'dart:async';
import 'apple_dialer.dart';
import 'apple_active_call.dart';
import 'glass_surface.dart';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../adapter/euicc_adapter.dart';
import '../adapter/ccid/ccid_adapter.dart';
import 'vowifi_service.dart';
import 'session_owner.dart';
import 'settings_store.dart';
import 'inbox_page.dart';
import 'call_history_page.dart';
import 'privacy_redaction.dart';
import '../settings/app_settings.dart';

class VoWifiPage extends StatefulWidget {
  const VoWifiPage({
    super.key,
    required this.adapter,
    required this.reader,
    this.profileIccid,
    this.service,
    this.initialSection = 0,
    this.initialPeer,
    this.communicationOnly = false,
    this.connectionOnly = false,
  });

  final Adapter adapter;
  final Reader reader;
  final String? profileIccid;
  final VoWifiService? service;
  final int initialSection;
  final String? initialPeer;
  final bool communicationOnly;
  final bool connectionOnly;

  @override
  State<VoWifiPage> createState() => _VoWifiPageState();
}

class _VoWifiPageState extends State<VoWifiPage> with WidgetsBindingObserver {
  late final VoWifiService _service;
  late final bool _pollStatusInPage;
  final _epdg = TextEditingController();
  final _proxy = TextEditingController();
  final _imei = TextEditingController();
  final _peer = TextEditingController();
  final _message = TextEditingController();
  final _peerFocus = FocusNode();
  final _contentScroll = ScrollController();
  final _keypadController = ExpansibleController();
  final _keypadKey = GlobalKey();
  bool _sending = false;
  bool _preparingStart = false;
  bool _leaving = false;
  bool _background = false;
  bool _settingsLoading = true;
  bool _phoneFieldFocused = false;
  int _lastProgressStep = 0;
  int _section = 0;
  bool _wasIncoming = false;
  Map<String, String> _loadedSettings = {};
  String? _actionError;
  Timer? _statusTimer;
  Timer? _numberCopyTimer;
  String? _copiedNumber;
  final AppSettings _appSettings = AppSettings();

  @override
  void initState() {
    super.initState();
    _section = widget.initialSection;
    _peer.text = widget.initialPeer ?? '';
    WidgetsBinding.instance.addObserver(this);
    _appSettings.addListener(_onPrivacySettingsChanged);
    _peerFocus.addListener(_onPhoneFocusChanged);
    _service =
        (widget.service ??
              VoWifiSessionOwner.instance.obtain(
                widget.adapter,
                widget.reader,
                widget.profileIccid,
              ))
          ..addListener(_onUpdate);
    unawaited(_service.loadMessages().catchError(_showError));
    unawaited(_loadSettings());
    _pollStatusInPage =
        widget.service != null &&
        !identical(VoWifiSessionOwner.instance.service, _service);
    if (_pollStatusInPage) {
      _statusTimer = Timer.periodic(const Duration(seconds: 2), (_) {
        if (!_background) unawaited(_service.refreshStatus());
      });
    }
  }

  Future<void> _loadSettings() async {
    try {
      final settings = await _service.loadSettings();
      if (!mounted) return;
      _loadedSettings = settings;
      _epdg.text = settings['epdg'] ?? '';
      _proxy.text = settings['proxy'] ?? '';
      _imei.text = settings['imei'] ?? '';
    } catch (error) {
      _showError(error);
    } finally {
      if (mounted) setState(() => _settingsLoading = false);
    }
  }

  void _onUpdate() {
    if (!mounted) return;
    final incoming =
        _service.call['direction'] == 'incoming' &&
        const {'incoming', 'ringing'}.contains(_service.call['state']);
    if (incoming && !_wasIncoming) _dismissKeyboard();
    _wasIncoming = incoming;
    final progressStep = _phaseProgressStep(_service.phase);
    if (progressStep >= 0) _lastProgressStep = progressStep;
    setState(() {});
  }

  void _onPrivacySettingsChanged() {
    if (mounted) setState(() {});
  }

  int _phaseProgressStep(String phase) => switch (phase) {
    'sim' => 1,
    'ike' => 2,
    'ims' => 3,
    'ready' => 4,
    'failed' => _lastProgressStep,
    _ => -1,
  };

  void _dismissKeyboard() {
    _peerFocus.unfocus();
    FocusManager.instance.primaryFocus?.unfocus();
  }

  void _onPhoneFocusChanged() {
    if (mounted) setState(() => _phoneFieldFocused = _peerFocus.hasFocus);
  }

  void _showError(Object error) {
    if (mounted) {
      setState(() => _actionError = VoWifiService.describeError(error));
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      _background = true;
    } else if (state == AppLifecycleState.resumed) {
      _background = false;
      // The application owner refreshes shared sessions. Native lifecycle and
      // network observers own connection checks, independently of this route.
      if (_pollStatusInPage) unawaited(_service.refreshStatus());
    }
  }

  Future<void> _start() async {
    if (_preparingStart || _service.busy || _service.active) return;
    final imei = _imei.text.trim();
    if (imei.isNotEmpty && !VoWifiSettingsStore.isValidImei(imei)) {
      _showError(
        StateError('IMEI must have 15 digits and a valid check digit'),
      );
      return;
    }
    setState(() {
      _actionError = null;
      _preparingStart = true;
    });
    try {
      // Permission denial must never prevent IMS registration or SMS storage.
      await _service.requestSmsNotifications();
      if (!mounted || _leaving) return;
      await _service.start({
        if (_epdg.text.trim() != (_loadedSettings['epdg'] ?? ''))
          'epdg': _epdg.text.trim(),
        if (_proxy.text.trim() != (_loadedSettings['proxy'] ?? ''))
          'proxy': _proxy.text.trim(),
        if (imei != (_loadedSettings['imei'] ?? '')) 'imei': imei,
      });
    } catch (error) {
      _showError(error);
    } finally {
      if (mounted) setState(() => _preparingStart = false);
      await _loadSettings();
    }
  }

  Future<void> _stop() async {
    try {
      await _service.stop();
    } catch (error) {
      _showError(error);
    }
  }

  Future<void> _leave() async {
    if (_leaving) return;
    setState(() => _leaving = true);
    try {
      if (mounted) Navigator.of(context).pop();
    } catch (error) {
      _showError(error);
    } finally {
      if (mounted) setState(() => _leaving = false);
    }
  }

  Future<void> _command(
    String action, [
    Map<String, dynamic> values = const {},
  ]) async {
    if (action == 'dial' || action == 'answer') _dismissKeyboard();
    setState(() => _actionError = null);
    try {
      await _service.command(action, values);
    } catch (error) {
      _showError(error);
    }
  }

  Future<void> _send() async {
    if (_peer.text.trim().isEmpty || _message.text.trim().isEmpty) return;
    _dismissKeyboard();
    setState(() {
      _sending = true;
      _actionError = null;
    });
    try {
      await _service.sendSms(_peer.text.trim(), _message.text);
      _message.clear();
    } catch (error) {
      _showError(error);
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _appSettings.removeListener(_onPrivacySettingsChanged);
    _statusTimer?.cancel();
    _numberCopyTimer?.cancel();
    _service.removeListener(_onUpdate);
    _peerFocus.removeListener(_onPhoneFocusChanged);
    _peerFocus.dispose();
    _contentScroll.dispose();
    _keypadController.dispose();
    // The application owner (or injected caller) owns the SIM/native bridge.
    // Disposing a view must not tear down registration or incoming SMS/calls.
    for (final controller in [_epdg, _proxy, _imei, _peer, _message]) {
      controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final incoming =
        _service.call['direction'] == 'incoming' &&
        const {'incoming', 'ringing'}.contains(_service.call['state']);
    final busy =
        _service.busy || _leaving || _settingsLoading || _preparingStart;
    final active = _service.active;
    if (_service.inCall && !incoming) {
      return AppleActiveCall(
        startedAt: DateTime.tryParse(
          _service.call['started_at'] as String? ?? '',
        ),
        audioState: _service.status['audio'] is Map
            ? _service.status['audio'] as Map
            : null,
        peer: VoWifiPrivacy.phoneNumber(_service.call['peer'] as String? ?? ''),
        status: _stateLabel(_service.call['state'] as String? ?? ''),
        error: _actionError == null
            ? null
            : VoWifiPrivacy.identifiers(_errorLabel(_actionError!)),
        command: (action, values) async {
          await _service.command(action, values);
          if (action == 'speaker' || action == 'mute') {
            await _service.refreshStatus();
          }
        },
      );
    }
    if (widget.communicationOnly && _section == 1 && !_service.inCall) {
      return AppleDialer(
        number: _peer.text,
        line: VoWifiPrivacy.phoneNumber(
          _service.ownNumberDisplay ?? voWifiL10n(context).voWifiWiFiCalling,
        ),
        status: _service.checkingConnection ? _statusLabel() : null,
        onBack: _leave,
        error: _actionError == null
            ? null
            : VoWifiPrivacy.identifiers(_errorLabel(_actionError!)),
        onDigit: (digit) => setState(() => _peer.text += digit),
        onDelete: _peer.text.isEmpty
            ? null
            : () => setState(
                () =>
                    _peer.text = _peer.text.substring(0, _peer.text.length - 1),
              ),
        onCall: _service.callReady && !busy && _peer.text.trim().isNotEmpty
            ? () => _command('dial', {'peer': _peer.text.trim()})
            : null,
      );
    }
    if (widget.communicationOnly && _section == 2 && !_service.inCall) {
      final messages = _service.messages
          .where((row) => row['peer'] == _peer.text.trim())
          .toList();
      return Scaffold(
        backgroundColor: CupertinoColors.systemBackground.resolveFrom(context),
        appBar: AppBar(
          backgroundColor: CupertinoColors.systemBackground.resolveFrom(
            context,
          ),
          surfaceTintColor: Colors.transparent,
          title: Text(voWifiL10n(context).voWifiNewMessage),
          actions: [const VoWifiPrivacyAction()],
        ),
        body: SafeArea(
          child: Column(
            children: [
              if (_service.checkingConnection)
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(_statusLabel()),
                ),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
                child: _phoneField(),
              ),
              if (_actionError != null)
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    VoWifiPrivacy.identifiers(_errorLabel(_actionError!)),
                    style: const TextStyle(color: CupertinoColors.systemRed),
                  ),
                ),
              Expanded(
                child: ListView(
                  reverse: true,
                  keyboardDismissBehavior:
                      ScrollViewKeyboardDismissBehavior.onDrag,
                  padding: const EdgeInsets.all(16),
                  children: messages.map(_messageBubble).toList(),
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
                child: _messageEditor(busy),
              ),
            ],
          ),
        ),
      );
    }
    return PopScope(
      canPop: true,
      child: Scaffold(
        backgroundColor: CupertinoColors.systemGroupedBackground.resolveFrom(
          context,
        ),
        appBar: AppBar(
          backgroundColor: CupertinoColors.systemGroupedBackground.resolveFrom(
            context,
          ),
          surfaceTintColor: Colors.transparent,
          elevation: 0,
          scrolledUnderElevation: 0,
          centerTitle: false,
          title: Text(
            widget.communicationOnly
                ? (_section == 1
                      ? voWifiL10n(context).voWifiDial
                      : voWifiL10n(context).voWifiNewMessage)
                : voWifiL10n(context).voWifiWiFiCalling,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          leading: IconButton(
            tooltip: voWifiL10n(context).voWifiBack,
            color: theme.colorScheme.primary,
            icon: const Icon(CupertinoIcons.back),
            onPressed: _leaving ? null : _leave,
          ),
          actions: [
            const VoWifiPrivacyAction(),
            if (!widget.communicationOnly)
              IconButton(
                tooltip: voWifiL10n(context).voWifiConnectionSettings,
                color: theme.colorScheme.primary,
                onPressed: _leaving
                    ? null
                    : () {
                        _dismissKeyboard();
                        setState(() => _section = 0);
                        showModalBottomSheet<void>(
                          context: context,
                          isScrollControlled: true,
                          useSafeArea: true,
                          builder: (context) => AnimatedBuilder(
                            animation: _service,
                            builder: (context, _) => SingleChildScrollView(
                              padding: EdgeInsets.fromLTRB(
                                16,
                                20,
                                16,
                                20 + MediaQuery.viewInsetsOf(context).bottom,
                              ),
                              child: _connectionSettings(
                                _service.busy,
                                _service.active,
                              ),
                            ),
                          ),
                        );
                      },
                icon: const Icon(CupertinoIcons.slider_horizontal_3),
              ),
          ],
        ),
        body: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) => Column(
              children: [
                if (_service.inCall)
                  ConstrainedBox(
                    constraints: BoxConstraints(
                      maxHeight: constraints.maxHeight * 0.48,
                    ),
                    child: SingleChildScrollView(
                      key: const ValueKey('vowifi-active-call'),
                      child: _activeCallPanel(incoming, busy),
                    ),
                  ),
                Expanded(
                  child: ListView(
                    controller: _contentScroll,
                    key: const ValueKey('vowifi-content'),
                    keyboardDismissBehavior:
                        ScrollViewKeyboardDismissBehavior.onDrag,
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
                    children: [
                      if (_section == 0)
                        _connectionCard(busy, active)
                      else if (!widget.communicationOnly)
                        _surface(
                          Row(
                            children: [
                              IconButton(
                                key: const ValueKey('vowifi-overview'),
                                tooltip: voWifiL10n(
                                  context,
                                ).voWifiConnectionOverview,
                                onPressed: () {
                                  _dismissKeyboard();
                                  setState(() => _section = 0);
                                },
                                icon: const Icon(CupertinoIcons.back),
                              ),
                              Expanded(child: Text(_statusLabel())),
                              Icon(
                                CupertinoIcons.wifi,
                                color: theme.colorScheme.primary,
                              ),
                            ],
                          ),
                        ),
                      const SizedBox(height: 18),
                      if (!widget.communicationOnly && !widget.connectionOnly)
                        _pageWidth(
                          Wrap(
                            key: const ValueKey('vowifi-section'),
                            spacing: 16,
                            runSpacing: 8,
                            children: [
                              if (_section != 0)
                                _sectionAction(
                                  0,
                                  CupertinoIcons.wifi,
                                  voWifiL10n(context).voWifiOverview,
                                ),
                              _sectionAction(
                                1,
                                CupertinoIcons.phone,
                                voWifiL10n(context).voWifiDial,
                              ),
                              _sectionAction(
                                2,
                                CupertinoIcons.square_pencil,
                                voWifiL10n(context).voWifiNewMessage,
                              ),
                            ],
                          ),
                        ),
                      const SizedBox(height: 18),
                      if (_section == 0 && !widget.connectionOnly) ...[
                        _surface(
                          Column(
                            children: [
                              _recordLink(
                                icon: CupertinoIcons.clock,
                                title: voWifiL10n(context).voWifiRecentCalls,
                                subtitle: voWifiL10n(
                                  context,
                                ).voWifiIncomingOutgoingAndMissed,
                                onTap: _openCallHistory,
                              ),
                              const Divider(height: 1),
                              _recordLink(
                                icon: CupertinoIcons.chat_bubble_2,
                                title: voWifiL10n(context).voWifiConversations,
                                subtitle: voWifiL10n(
                                  context,
                                ).voWifiGroupedBySIMAndNumber,
                                onTap: _openInbox,
                              ),
                            ],
                          ),
                        ),
                      ],
                      if (_section == 1) _callSection(busy, incoming),
                      if (_section == 2) _messageSection(busy),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _pageWidth(Widget child) => Align(
    alignment: Alignment.topCenter,
    child: ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 640),
      child: SizedBox(width: double.infinity, child: child),
    ),
  );

  Widget _sectionAction(int section, IconData icon, String label) =>
      TextButton.icon(
        key: ValueKey('vowifi-action-$section'),
        onPressed: () {
          _dismissKeyboard();
          if (_contentScroll.hasClients) _contentScroll.jumpTo(0);
          setState(() => _section = section);
        },
        icon: Icon(icon, size: 23),
        label: Text(label),
        style: TextButton.styleFrom(
          minimumSize: const Size(0, 48),
          foregroundColor: Theme.of(context).colorScheme.primary,
          textStyle: Theme.of(context).textTheme.titleMedium,
        ),
      );

  Widget _surface(
    Widget child, {
    EdgeInsets padding = const EdgeInsets.all(18),
  }) => _pageWidth(
    Material(
      color: CupertinoColors.secondarySystemGroupedBackground.resolveFrom(
        context,
      ),
      borderRadius: BorderRadius.circular(18),
      clipBehavior: Clip.antiAlias,
      child: Padding(padding: padding, child: child),
    ),
  );

  Widget _connectionCard(bool busy, bool active) {
    final theme = Theme.of(context);
    final error = _actionError ?? _service.error;
    final ownNumber = _service.registered ? _service.ownNumberDisplay : null;
    final phoneNumber = _service.registered ? _service.ownPhoneNumber : null;
    final copied = phoneNumber != null && phoneNumber == _copiedNumber;
    return _surface(
      Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Icon(
                  CupertinoIcons.wifi,
                  color: theme.colorScheme.primary,
                  size: 25,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Semantics(
                      liveRegion: true,
                      child: Text(
                        _statusLabel(),
                        style: theme.textTheme.titleMedium,
                      ),
                    ),
                    const SizedBox(height: 5),
                    Text(
                      VoWifiPrivacy.identifiers(_service.reader.name),
                      style: theme.textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 2),
                    Text(
                      _service.reader.source is CcidAdapter
                          ? voWifiL10n(context).voWifiUSBCCIDSmartCardReader
                          : voWifiL10n(context).voWifiBluetoothSIMReader,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          if (_service.registered) ...[
            const SizedBox(height: 18),
            Text(
              voWifiL10n(context).voWifiMyNumber,
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 4),
            if (ownNumber != null && phoneNumber != null)
              Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: SelectableText(
                      VoWifiPrivacy.phoneNumber(ownNumber),
                      key: const ValueKey('vowifi-own-number'),
                      onTap: VoWifiPrivacy.isEnabled ? null : _copyOwnNumber,
                      style: theme.textTheme.titleLarge?.copyWith(
                        color: copied
                            ? CupertinoColors.systemGreen
                            : theme.colorScheme.primary,
                      ),
                    ),
                  ),
                  if (!VoWifiPrivacy.isEnabled)
                    IconButton(
                      key: const ValueKey('vowifi-copy-own-number'),
                      tooltip: copied
                          ? voWifiL10n(context).voWifiCopied
                          : voWifiL10n(context).voWifiCopyMyNumber,
                      onPressed: _copyOwnNumber,
                      color: copied
                          ? CupertinoColors.systemGreen
                          : theme.colorScheme.primary,
                      icon: Icon(
                        copied
                            ? CupertinoIcons.check_mark
                            : CupertinoIcons.doc_on_doc,
                        size: 20,
                      ),
                    ),
                ],
              )
            else
              Text(
                voWifiL10n(context).voWifiTheCarrierHasNotSuppliedAPhoneNumber,
                key: const ValueKey('vowifi-own-number-unavailable'),
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
          ],
          const SizedBox(height: 20),
          if (_service.callReady && _service.messagingReady && error == null)
            ExpansionTile(
              key: const ValueKey('vowifi-connection-details'),
              tilePadding: EdgeInsets.zero,
              shape: const Border(),
              collapsedShape: const Border(),
              title: Text(voWifiL10n(context).voWifiConnectionDetails),
              children: [_progress()],
            )
          else
            _progress(),
          const SizedBox(height: 18),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              style: _primaryButtonStyle(),
              onPressed: busy
                  ? null
                  : active
                  ? _stop
                  : _start,
              icon: busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Icon(
                      active ? CupertinoIcons.stop : CupertinoIcons.wifi,
                      size: 20,
                    ),
              label: Text(
                _service.stopping
                    ? voWifiL10n(context).voWifiStoppingWiFiCalling
                    : busy
                    ? voWifiL10n(context).voWifiPleaseWait
                    : active
                    ? voWifiL10n(context).voWifiStopWiFiCalling
                    : voWifiL10n(context).voWifiConnect,
                textAlign: TextAlign.center,
              ),
            ),
          ),
          if (error != null) ...[
            const SizedBox(height: 12),
            _errorText(VoWifiPrivacy.identifiers(_errorLabel(error))),
          ],
        ],
      ),
    );
  }

  Future<void> _copyOwnNumber() async {
    final number = _service.ownPhoneNumber;
    if (!_service.registered || number == null) return;
    try {
      await Clipboard.setData(ClipboardData(text: number));
      if (!mounted ||
          !_service.registered ||
          _service.ownPhoneNumber != number) {
        return;
      }
      _numberCopyTimer?.cancel();
      setState(() => _copiedNumber = number);
      _numberCopyTimer = Timer(const Duration(seconds: 2), () {
        if (mounted) setState(() => _copiedNumber = null);
      });
    } catch (error) {
      _showError(error);
    }
  }

  ButtonStyle _primaryButtonStyle() => FilledButton.styleFrom(
    minimumSize: const Size(0, 48),
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
  );

  Widget _errorText(String message) => Semantics(
    liveRegion: true,
    child: Text(
      message,
      style: TextStyle(color: Theme.of(context).colorScheme.error),
    ),
  );

  Widget _connectionSettings(bool busy, bool active) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _surface(
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            childrenPadding: const EdgeInsets.only(top: 12),
            shape: const Border(),
            collapsedShape: const Border(),
            title: Text(
              voWifiL10n(context).voWifiConnectionSettings,
              style: theme.textTheme.titleMedium,
            ),
            subtitle: Text(
              voWifiL10n(
                context,
              ).voWifiCarrierSettingsAreDetectedFromTheActiveSIM,
              style: theme.textTheme.bodySmall,
            ),
            children: [
              _setting(
                _epdg,
                voWifiL10n(context).voWifiEPDGHostOptional,
                enabled: !active && !busy,
              ),
              _setting(
                _proxy,
                voWifiL10n(context).voWifiProxyURLOptional,
                enabled: !active && !busy,
                hint: 'socks5://host:port',
              ),
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(
                  voWifiL10n(context).voWifi127001RefersToThisIPhoneNot,
                  style: theme.textTheme.bodySmall,
                ),
              ),
              _setting(
                _imei,
                voWifiL10n(context).voWifiIMEIOptional,
                enabled: !active && !busy,
                keyboard: TextInputType.number,
                obscureText: VoWifiPrivacy.isEnabled,
              ),
            ],
          ),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 8),
        ),
        const SizedBox(height: 12),
        _pageWidth(
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (active) ...[
                  Text(
                    voWifiL10n(
                      context,
                    ).voWifiStopWiFiCallingBeforeManagingProfilesOrChanging,
                    style: theme.textTheme.bodySmall,
                  ),
                  const SizedBox(height: 8),
                ],
                Text(
                  voWifiL10n(
                    context,
                  ).voWifiCallsUseTheIPhoneSystemCallScreenReaderSMS,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _phoneField() => TextField(
    key: const ValueKey('vowifi-phone-number'),
    controller: _peer,
    focusNode: _peerFocus,
    keyboardType: TextInputType.phone,
    style: Theme.of(
      context,
    ).textTheme.bodyLarge?.copyWith(fontSize: 17, height: 1.3),
    obscureText: VoWifiPrivacy.isEnabled,
    textInputAction: TextInputAction.done,
    onSubmitted: (_) => _dismissKeyboard(),
    onTapOutside: (_) => _dismissKeyboard(),
    decoration: _fieldDecoration(
      voWifiL10n(context).voWifiPhoneNumber,
      hint: voWifiL10n(context).voWifiCountryCodeAndNumber,
      suffix: _phoneFieldFocused
          ? IconButton(
              tooltip: voWifiL10n(context).voWifiHideKeyboard,
              onPressed: _dismissKeyboard,
              icon: const Icon(Icons.keyboard_hide_rounded),
            )
          : null,
    ),
    onChanged: (_) => setState(() {}),
  );

  InputDecoration _fieldDecoration(
    String label, {
    String? hint,
    Widget? suffix,
  }) => InputDecoration(
    labelText: label,
    floatingLabelBehavior: FloatingLabelBehavior.never,
    labelStyle: Theme.of(context).textTheme.bodyLarge?.copyWith(fontSize: 17),
    hintStyle: Theme.of(context).textTheme.bodyLarge?.copyWith(fontSize: 17),
    hintText: hint,
    suffixIcon: suffix,
    filled: true,
    fillColor: CupertinoColors.tertiarySystemFill.resolveFrom(context),
    contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 16),
    border: OutlineInputBorder(
      borderRadius: BorderRadius.circular(12),
      borderSide: BorderSide.none,
    ),
    enabledBorder: OutlineInputBorder(
      borderRadius: BorderRadius.circular(12),
      borderSide: BorderSide.none,
    ),
  );

  Widget _callSection(bool busy, bool incoming) {
    final theme = Theme.of(context);
    final call = _service.call;
    final state = call['state'] as String? ?? 'idle';
    final error =
        _actionError ??
        call['last_error'] as String? ??
        call['error'] as String?;
    return _surface(
      Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            voWifiL10n(context).voWifiCalls,
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          if (!_service.inCall) ...[
            Text(
              _service.callReady
                  ? voWifiL10n(
                      context,
                    ).voWifiReadyForIncomingCallsSystemAnswerDecline
                  : voWifiL10n(context).voWifiConnectWiFiCallingToReceiveCalls,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 16),
            _phoneField(),
            const SizedBox(height: 12),
            if (widget.communicationOnly) ...[
              LayoutBuilder(
                builder: (context, constraints) => Wrap(
                  spacing: 12,
                  runSpacing: 14,
                  children: [
                    for (final digit in '123456789*0#'.split(''))
                      SizedBox(
                        width: (constraints.maxWidth - 24) / 3,
                        child: Center(
                          child: SizedBox(
                            width: ((constraints.maxWidth - 24) / 3).clamp(
                              48.0,
                              82.0,
                            ),
                            child: AspectRatio(
                              aspectRatio: 1,
                              child: TextButton(
                                onPressed: () {
                                  _dismissKeyboard();
                                  setState(() => _peer.text += digit);
                                },
                                onLongPress: digit == '0'
                                    ? () {
                                        _dismissKeyboard();
                                        setState(() => _peer.text += '+');
                                      }
                                    : null,
                                style: TextButton.styleFrom(
                                  padding: EdgeInsets.zero,
                                  backgroundColor: CupertinoColors
                                      .tertiarySystemFill
                                      .resolveFrom(context),
                                  foregroundColor: theme.colorScheme.onSurface,
                                  shape: const CircleBorder(),
                                ),
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Text(
                                      digit,
                                      style: theme.textTheme.headlineMedium
                                          ?.copyWith(
                                            fontSize: 32,
                                            fontWeight: FontWeight.w400,
                                          ),
                                    ),
                                    Text(
                                      const {
                                            '2': 'ABC',
                                            '3': 'DEF',
                                            '4': 'GHI',
                                            '5': 'JKL',
                                            '6': 'MNO',
                                            '7': 'PQRS',
                                            '8': 'TUV',
                                            '9': 'WXYZ',
                                            '0': '+',
                                          }[digit] ??
                                          '',
                                      style: theme.textTheme.labelSmall
                                          ?.copyWith(
                                            fontSize: 10,
                                            letterSpacing: 2,
                                          ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
              ),
              Align(
                alignment: Alignment.centerRight,
                child: IconButton(
                  tooltip: voWifiL10n(context).voWifiDeleteDigit,
                  icon: const Icon(CupertinoIcons.delete_left),
                  onPressed: _peer.text.isEmpty
                      ? null
                      : () => setState(() {
                          _peer.text = _peer.text.substring(
                            0,
                            _peer.text.length - 1,
                          );
                        }),
                ),
              ),
            ],
            Center(
              child: IconButton.filled(
                tooltip: voWifiL10n(context).voWifiCall,
                style: IconButton.styleFrom(
                  backgroundColor: CupertinoColors.systemGreen,
                  foregroundColor: Colors.white,
                  minimumSize: const Size(72, 72),
                  shape: const CircleBorder(),
                ),
                onPressed:
                    _service.callReady && !busy && _peer.text.trim().isNotEmpty
                    ? () => _command('dial', {'peer': _peer.text.trim()})
                    : null,
                icon: const Icon(CupertinoIcons.phone_fill, size: 32),
              ),
            ),
          ],
          if (error != null && error.isNotEmpty) ...[
            const SizedBox(height: 12),
            _errorText(VoWifiPrivacy.identifiers(_errorLabel(error))),
          ],
          if (_service.callHistoryError != null) ...[
            const SizedBox(height: 12),
            _errorText(
              voWifiL10n(context).voWifiCallHistoryCouldNotBeSavedOnThisDevice,
            ),
          ],
          if (const {'failed', 'rejected', 'busy'}.contains(state))
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(_stateLabel(state), style: theme.textTheme.bodySmall),
            ),
          if (_service.inCall && !incoming)
            ExpansionTile(
              key: _keypadKey,
              controller: _keypadController,
              tilePadding: EdgeInsets.zero,
              shape: const Border(),
              collapsedShape: const Border(),
              title: Text(voWifiL10n(context).voWifiKeypad),
              children: [
                LayoutBuilder(
                  builder: (context, constraints) => Wrap(
                    spacing: 10,
                    runSpacing: 10,
                    children: [
                      for (final digit in '123456789*0#'.split(''))
                        SizedBox(
                          width: (constraints.maxWidth - 20) / 3,
                          child: OutlinedButton(
                            style: OutlinedButton.styleFrom(
                              minimumSize: const Size(0, 52),
                              padding: const EdgeInsets.symmetric(vertical: 12),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(12),
                              ),
                            ),
                            onPressed: busy
                                ? null
                                : () => _command('dtmf', {'digit': digit}),
                            child: Text(
                              digit,
                              style: theme.textTheme.titleLarge?.copyWith(
                                color: theme.colorScheme.primary,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ],
            ),
          const SizedBox(height: 16),
          const Divider(height: 1),
          _recordLink(
            icon: CupertinoIcons.clock,
            title: voWifiL10n(context).voWifiCallHistory,
            subtitle: voWifiL10n(context).voWifiIncomingOutgoingAndMissedCalls,
            onTap: _openCallHistory,
          ),
        ],
      ),
    );
  }

  Widget _messageSection(bool busy) {
    final theme = Theme.of(context);
    final recent = _service.messages.take(4).toList(growable: false);
    return _surface(
      Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 8,
            runSpacing: 2,
            children: [
              Text(
                voWifiL10n(context).voWifiMessages,
                style: theme.textTheme.titleMedium,
              ),
              TextButton.icon(
                onPressed: _leaving ? null : _openInbox,
                icon: const Icon(CupertinoIcons.tray_full, size: 18),
                label: Text(voWifiL10n(context).voWifiAllMessages),
              ),
            ],
          ),
          const SizedBox(height: 8),
          if (recent.isEmpty)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
              decoration: BoxDecoration(
                color: CupertinoColors.tertiarySystemGroupedBackground
                    .resolveFrom(context),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Row(
                children: [
                  Icon(
                    CupertinoIcons.bubble_left_bubble_right,
                    color: theme.colorScheme.primary,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      voWifiL10n(
                        context,
                      ).voWifiYourRecentReaderMessagesWillAppearHere,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                ],
              ),
            )
          else
            ...recent.reversed.map(_messageBubble),
          const SizedBox(height: 18),
          Text(
            voWifiL10n(context).voWifiNewMessage,
            style: theme.textTheme.labelLarge?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 10),
          _phoneField(),
          const SizedBox(height: 12),
          _messageEditor(busy),
          const SizedBox(height: 12),
          Text(
            voWifiL10n(
              context,
            ).voWifiStoredOnThisDeviceSubmittedMessagesAreNotConfirmed,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  Widget _messageEditor(bool busy) {
    final theme = Theme.of(context);
    return CommunicationGlass(
      child: Padding(
        padding: const EdgeInsets.all(10),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Expanded(
              child: TextField(
                key: const ValueKey('vowifi-message-composer'),
                controller: _message,
                style: theme.textTheme.bodyLarge?.copyWith(
                  fontSize: 17,
                  height: 1.4,
                ),
                minLines: 1,
                maxLines: VoWifiPrivacy.isEnabled ? 1 : 4,
                obscureText: VoWifiPrivacy.isEnabled,
                decoration: _fieldDecoration(
                  voWifiL10n(context).voWifiMessage,
                  hint: voWifiL10n(context).voWifiWriteAMessage,
                ),
                onTapOutside: (_) => _dismissKeyboard(),
                onChanged: (_) => setState(() {}),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              tooltip: _sending
                  ? voWifiL10n(context).voWifiSending
                  : voWifiL10n(context).voWifiSendSMS,
              style: IconButton.styleFrom(
                backgroundColor: CupertinoColors.systemGreen,
                foregroundColor: Colors.white,
              ),
              onPressed:
                  _service.messagingReady &&
                      !busy &&
                      !_sending &&
                      _peer.text.trim().isNotEmpty &&
                      _message.text.trim().isNotEmpty
                  ? _send
                  : null,
              icon: _sending
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(CupertinoIcons.arrow_up, size: 22),
            ),
          ],
        ),
      ),
    );
  }

  Widget _messageBubble(Map<String, Object?> message) {
    final theme = Theme.of(context);
    final outgoing = message['direction'] == 'outgoing';
    final state = message['state'] as String? ?? '';
    final at = DateTime.tryParse(message['at'] as String? ?? '')?.toLocal();
    final time = at == null
        ? ''
        : '${at.hour.toString().padLeft(2, '0')}:${at.minute.toString().padLeft(2, '0')}';
    return Align(
      alignment: outgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 320),
        child: Container(
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          decoration: BoxDecoration(
            color: outgoing
                ? const Color(0xFF248A3D)
                : CupertinoColors.tertiarySystemGroupedBackground.resolveFrom(
                    context,
                  ),
            borderRadius: BorderRadius.only(
              topLeft: const Radius.circular(18),
              topRight: const Radius.circular(18),
              bottomLeft: Radius.circular(outgoing ? 18 : 5),
              bottomRight: Radius.circular(outgoing ? 5 : 18),
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                VoWifiPrivacy.privateText(
                  message['content'] as String? ?? '',
                  voWifiL10n(context).voWifiMessageHidden,
                ),
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: outgoing
                      ? theme.colorScheme.onPrimary
                      : theme.colorScheme.onSurface,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                '${outgoing ? voWifiL10n(context).voWifiTo : voWifiL10n(context).voWifiFrom} ${VoWifiPrivacy.phoneNumber(message['peer'] as String? ?? '')}  ·  $state${time.isEmpty ? '' : '  ·  $time'}',
                style: theme.textTheme.labelSmall?.copyWith(
                  color: outgoing
                      ? theme.colorScheme.onPrimary.withValues(alpha: 0.78)
                      : theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _recordLink({
    required IconData icon,
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) => ListTile(
    contentPadding: const EdgeInsets.only(top: 8),
    leading: Icon(icon, color: Theme.of(context).colorScheme.primary, size: 22),
    title: Text(title),
    subtitle: Text(subtitle, style: Theme.of(context).textTheme.bodySmall),
    trailing: const Icon(CupertinoIcons.chevron_forward, size: 16),
    onTap: _leaving ? null : onTap,
  );

  void _openInbox() {
    if (_leaving) return;
    _dismissKeyboard();
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => VoWifiInboxPage(
          lineKey: _service.lineKey,
          onReply: (line, peer) {
            if (!mounted || line != _service.lineKey) return;
            Navigator.of(context).pop();
            _peer.text = peer;
            setState(() => _section = 2);
          },
        ),
      ),
    );
  }

  void _openCallHistory() {
    if (_leaving) return;
    _dismissKeyboard();
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => VoWifiCallHistoryPage(
          lineKey: _service.lineKey,
          onSelectNumber: (line, peer) {
            if (!mounted || line != _service.lineKey) return;
            Navigator.of(context).pop();
            _peer.text = peer;
            if (_contentScroll.hasClients) _contentScroll.jumpTo(0);
            setState(() => _section = 1);
          },
        ),
      ),
    );
  }

  void _showKeypad() {
    if (_leaving || !_service.inCall) return;
    _dismissKeyboard();
    setState(() => _section = 1);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || !_service.inCall || _keypadKey.currentContext == null) {
        return;
      }
      _keypadController.expand();
      unawaited(
        Scrollable.ensureVisible(
          _keypadKey.currentContext!,
          alignment: 0,
          duration: const Duration(milliseconds: 200),
        ),
      );
    });
  }

  Widget _activeCallPanel(bool incoming, bool busy) {
    final theme = Theme.of(context);
    final call = _service.call;
    return Semantics(
      liveRegion: true,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 4, 16, 12),
        child: _surface(
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                incoming
                    ? voWifiL10n(context).voWifiIncomingCall
                    : _stateLabel(call['state'] as String? ?? ''),
                style: theme.textTheme.labelLarge?.copyWith(
                  color: theme.colorScheme.primary,
                ),
              ),
              SelectableText(
                VoWifiPrivacy.phoneNumber(call['peer'] as String? ?? ''),
                style: theme.textTheme.titleLarge,
              ),
              if (call['media_ready'] == true)
                Text(voWifiL10n(context).voWifiAudioConnected),
              const SizedBox(height: 8),
              Wrap(
                spacing: 12,
                runSpacing: 8,
                children: [
                  if (incoming)
                    FilledButton.icon(
                      style: _primaryButtonStyle(),
                      onPressed: busy ? null : () => _command('answer'),
                      icon: const Icon(CupertinoIcons.phone_fill),
                      label: Text(voWifiL10n(context).voWifiAnswer),
                    ),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      minimumSize: const Size(0, 48),
                      padding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 12,
                      ),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    onPressed: busy
                        ? null
                        : () => _command(incoming ? 'reject' : 'hangup'),
                    icon: const Icon(CupertinoIcons.phone_down_fill),
                    label: Text(
                      incoming
                          ? voWifiL10n(context).voWifiDecline
                          : voWifiL10n(context).voWifiHangUp,
                    ),
                  ),
                  if (!incoming)
                    TextButton.icon(
                      onPressed: _showKeypad,
                      icon: const Icon(CupertinoIcons.circle_grid_3x3),
                      label: Text(voWifiL10n(context).voWifiKeypad),
                    ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _setting(
    TextEditingController controller,
    String label, {
    required bool enabled,
    String? hint,
    TextInputType? keyboard,
    bool obscureText = false,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 12),
    child: TextField(
      controller: controller,
      enabled: enabled,
      keyboardType: keyboard,
      obscureText: obscureText,
      textInputAction: TextInputAction.done,
      onSubmitted: (_) => _dismissKeyboard(),
      onTapOutside: (_) => _dismissKeyboard(),
      autocorrect: false,
      enableSuggestions: false,
      decoration: _fieldDecoration(label, hint: hint),
    ),
  );

  Widget _progress() {
    final phase = _service.phase;
    final steps = [
      (
        voWifiL10n(context).voWifiReader,
        CupertinoIcons.device_phone_portrait,
        _service.readerReady,
      ),
      ('SIM', CupertinoIcons.creditcard, _service.simReady),
      (
        'ePDG',
        CupertinoIcons.shield,
        const {'ims', 'ready'}.contains(phase) ||
            (phase == 'failed' && _lastProgressStep > 2),
      ),
      (
        'IMS',
        CupertinoIcons.phone,
        _service.registered || (phase == 'failed' && _lastProgressStep > 3),
      ),
      (
        voWifiL10n(context).voWifiReady,
        CupertinoIcons.checkmark_seal,
        _service.messagingReady && _service.callReady,
      ),
    ];
    final currentStep = _phaseProgressStep(phase);
    final working = _service.active || _service.busy;
    final failed = phase == 'failed';
    final theme = Theme.of(context);
    final pending = theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.65);

    Widget step(int index, bool vertical) {
      final completed =
          steps[index].$3 || (failed && index < _lastProgressStep);
      final current = working && !failed && index == currentStep;
      final stepFailed = failed && index == _lastProgressStep;
      final color = stepFailed
          ? theme.colorScheme.error
          : completed || current
          ? theme.colorScheme.primary
          : pending;
      final label = completed
          ? voWifiL10n(context).voWifiComplete
          : stepFailed
          ? voWifiL10n(context).voWifiFailed2
          : current
          ? voWifiL10n(context).voWifiInProgress
          : voWifiL10n(context).voWifiWaiting;
      final icon = Icon(
        stepFailed ? CupertinoIcons.exclamationmark : steps[index].$2,
        size: 23,
        color: color,
      );
      final title = Text(
        steps[index].$1,
        textAlign: vertical ? TextAlign.start : TextAlign.center,
        maxLines: vertical ? null : 2,
        style:
            (vertical ? theme.textTheme.bodySmall : theme.textTheme.labelSmall)
                ?.copyWith(
                  color: color,
                  fontWeight: completed || current
                      ? FontWeight.w600
                      : FontWeight.w400,
                ),
      );
      return Semantics(
        label: '${steps[index].$1}, $label',
        excludeSemantics: true,
        child: vertical
            ? Padding(
                padding: const EdgeInsets.symmetric(vertical: 7),
                child: Row(
                  children: [
                    icon,
                    const SizedBox(width: 12),
                    Expanded(child: title),
                    const SizedBox(width: 8),
                    Text(
                      label,
                      style: theme.textTheme.labelSmall?.copyWith(color: color),
                    ),
                  ],
                ),
              )
            : Column(
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Container(
                          height: 1,
                          color: index == 0
                              ? Colors.transparent
                              : theme.dividerColor,
                        ),
                      ),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 5),
                        child: icon,
                      ),
                      Expanded(
                        child: Container(
                          height: 1,
                          color: index == steps.length - 1
                              ? Colors.transparent
                              : theme.dividerColor,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 7),
                  title,
                  const SizedBox(height: 4),
                  if (current)
                    Text(
                      '···',
                      style: theme.textTheme.labelSmall?.copyWith(color: color),
                    ),
                ],
              ),
      );
    }

    return Semantics(
      container: true,
      label: voWifiL10n(context).voWifiWiFiCallingConnectionProgress,
      child: LayoutBuilder(
        builder: (context, constraints) {
          // Accessibility sizes need room for full stage names instead of
          // shrinking the user's selected font size to fit five columns.
          final vertical =
              constraints.maxWidth /
                  MediaQuery.textScalerOf(context).scale(11) <
              23;
          return vertical
              ? Column(
                  children: [
                    for (var index = 0; index < steps.length; index++)
                      step(index, true),
                  ],
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    for (var index = 0; index < steps.length; index++)
                      Expanded(child: step(index, false)),
                  ],
                );
        },
      ),
    );
  }

  String _statusLabel() => _service.checkingConnection
      ? voWifiL10n(context).voWifiCheckingConnection
      : switch (_service.phase) {
          'sim' => voWifiL10n(context).voWifiReadingTheActiveSIM,
          'ike' => switch (_service.status['ike_stage']) {
            'transport' => voWifiL10n(context).voWifiPreparingEPDGNetworkPath,
            'ike_sa_init' => voWifiL10n(
              context,
            ).voWifiWaitingForTheFirstEPDGResponse,
            'ike_auth' => voWifiL10n(
              context,
            ).voWifiWaitingForCarrierAuthentication,
            'eap_identity' => voWifiL10n(
              context,
            ).voWifiRespondingToCarrierIdentityRequest,
            'eap_aka' => voWifiL10n(
              context,
            ).voWifiProcessingSIMAKAAuthentication,
            'eap_response' => voWifiL10n(
              context,
            ).voWifiWaitingForCarrierAuthenticationResult,
            'eap_success' || 'final_auth' => voWifiL10n(
              context,
            ).voWifiConfirmingTheAuthenticatedTunnel,
            'tunnel_setup' => voWifiL10n(
              context,
            ).voWifiPreparingTheEncryptedTunnel,
            _ => voWifiL10n(context).voWifiConnectingToTheCarrierEPDG,
          },
          'ims' => voWifiL10n(context).voWifiRegisteringWithIMS,
          'ready' =>
            _service.registered
                ? voWifiL10n(context).voWifiIMSRegistered
                : voWifiL10n(context).voWifiWaitingForIMSRegistration,
          'failed' =>
            _service.status['retrying'] == true
                ? voWifiL10n(context).voWifiConnectionInterruptedRetrying
                : voWifiL10n(context).voWifiConnectionFailed,
          'suspended' => voWifiL10n(
            context,
          ).voWifiSessionStoppedWhileTheAppWasInTheBackground,
          'stopped' => voWifiL10n(context).voWifiDisconnected,
          _ => voWifiL10n(context).voWifiReadyToConnectWithTheActiveSIM,
        };

  String _stateLabel(String state) => switch (state) {
    'idle' => voWifiL10n(context).voWifiIdle,
    'outgoing' || 'dialing' => voWifiL10n(context).voWifiCalling,
    'early' || 'ringing' => voWifiL10n(context).voWifiRinging,
    'incoming' => voWifiL10n(context).voWifiIncomingCall,
    'connecting' => voWifiL10n(context).voWifiConnecting,
    'active' ||
    'established' ||
    'connected' => voWifiL10n(context).voWifiInCall,
    'cancelling' => voWifiL10n(context).voWifiEndingCall,
    'ended' => voWifiL10n(context).voWifiCallEnded,
    'rejected' => voWifiL10n(context).voWifiDeclined,
    'busy' => voWifiL10n(context).voWifiBusy,
    'failed' => voWifiL10n(context).voWifiFailed,
    'received' => voWifiL10n(context).voWifiReceived,
    'submitted' => voWifiL10n(context).voWifiSubmitted,
    'submitting' => voWifiL10n(context).voWifiSubmitting,
    _ => state,
  };

  String _errorLabel(String message) => localizedVoWifiError(context, message);
}
