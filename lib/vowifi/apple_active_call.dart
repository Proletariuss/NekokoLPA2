import 'l10n.dart';
import 'dart:async';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'glass_surface.dart';

/// In-app call controls. Audio commands are acknowledged before toggling UI.
class AppleActiveCall extends StatefulWidget {
  const AppleActiveCall({
    super.key,
    required this.peer,
    required this.status,
    required this.command,
    this.error,
    this.audioState,
    this.startedAt,
  });
  final String peer;
  final String status;
  final String? error;
  final Map? audioState;
  final DateTime? startedAt;
  final Future<void> Function(String, Map<String, dynamic>) command;

  @override
  State<AppleActiveCall> createState() => _AppleActiveCallState();
}

class _AppleActiveCallState extends State<AppleActiveCall> {
  bool speaker = false, muted = false, keypad = false, pending = false;
  bool ending = false;
  String? error;
  Timer? _clock;

  void syncAudio() {
    final audio = widget.audioState;
    if (audio?['speaker'] is bool) speaker = audio!['speaker'] as bool;
    if (audio?['muted'] is bool) muted = audio!['muted'] as bool;
  }

  @override
  void initState() {
    super.initState();
    syncAudio();
    _updateClock();
  }

  @override
  void didUpdateWidget(covariant AppleActiveCall oldWidget) {
    super.didUpdateWidget(oldWidget);
    syncAudio();
    _updateClock();
  }

  void _updateClock() {
    if (widget.startedAt == null) {
      _clock?.cancel();
      _clock = null;
    } else {
      _clock ??= Timer.periodic(const Duration(seconds: 1), (_) {
        if (mounted) setState(() {});
      });
    }
  }

  @override
  void dispose() {
    _clock?.cancel();
    super.dispose();
  }

  Widget keypadTransition(Widget child) {
    final duration = communicationMotion(context, 180);
    if (duration == Duration.zero) return child;
    return AnimatedSize(
      duration: duration,
      curve: Curves.easeOutCubic,
      alignment: Alignment.topCenter,
      child: child,
    );
  }

  Future<void> send(
    String action, [
    Map<String, dynamic> values = const {},
  ]) async {
    final hangup = action == 'hangup';
    if (ending || (!hangup && pending)) return;
    setState(() {
      if (hangup) {
        ending = true;
      } else {
        pending = true;
      }
      error = null;
    });
    try {
      await widget.command(action, values);
      if (!mounted) return;
      setState(() {
        if (action == 'speaker') speaker = values['enabled'] == true;
        if (action == 'mute') muted = values['enabled'] == true;
        syncAudio();
      });
    } catch (_) {
      if (mounted) {
        setState(
          () => error = voWifiL10n(
            context,
          ).voWifiTheActionCouldNotBeCompletedTryAgain,
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          if (hangup) {
            ending = false;
          } else {
            pending = false;
          }
        });
      }
    }
  }

  Widget control(
    IconData icon,
    String label,
    VoidCallback action, {
    bool selected = false,
    bool end = false,
    double diameter = 76,
  }) => Semantics(
    container: true,
    button: true,
    label: end && ending ? voWifiL10n(context).voWifiEndingCall : label,
    enabled: !(ending || (!end && pending)),
    onTap: (ending || (!end && pending)) ? null : action,
    excludeSemantics: true,
    toggled: end ? null : selected,
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        SizedBox(
          width: diameter,
          height: diameter,
          child: IconButton(
            tooltip: label,
            onPressed: (ending || (!end && pending)) ? null : action,
            style: IconButton.styleFrom(
              animationDuration: communicationMotion(context),
              backgroundColor: end
                  ? const Color(0xFFFF3B30)
                  : selected
                  ? Colors.white
                  : Colors.white.withValues(alpha: .16),
              foregroundColor: selected ? Colors.black : Colors.white,
              disabledForegroundColor: Colors.white54,
              side: BorderSide(color: Colors.white.withValues(alpha: .2)),
              shape: const CircleBorder(),
            ),
            icon: end && ending
                ? communicationMotion(context) == Duration.zero
                      ? const Icon(CupertinoIcons.ellipsis, size: 32)
                      : const SizedBox.square(
                          dimension: 26,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                : Icon(icon, size: 32),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          label.length == 4 && MediaQuery.textScalerOf(context).scale(15) > 22
              ? '${label.substring(0, 2)}\n${label.substring(2)}'
              : label,
          textAlign: TextAlign.center,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(
            fontFamily: 'CupertinoSystemText',
            color: Colors.white,
            fontSize: 15,
            fontWeight: FontWeight.w400,
            letterSpacing: 0,
            height: 1.2,
          ),
        ),
      ],
    ),
  );

  @override
  Widget build(BuildContext context) => Scaffold(
    backgroundColor: const Color(0xFF49372B),
    body: DecoratedBox(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF796961), Color(0xFF49372B)],
        ),
      ),
      child: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final compact = constraints.maxHeight < 520;
            return Padding(
              padding: EdgeInsets.fromLTRB(
                16,
                compact ? 8 : 32,
                16,
                compact ? 8 : 24,
              ),
              child: Column(
                children: [
                  Expanded(
                    child: SingleChildScrollView(
                      child: Column(
                        children: [
                          Text(
                            widget.status,
                            textAlign: TextAlign.center,
                            style: const TextStyle(
                              fontFamily: 'CupertinoSystemDisplay',
                              color: Colors.white70,
                              fontSize: 22,
                              fontWeight: FontWeight.w400,
                              letterSpacing: 0,
                              height: 1.2,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            widget.peer,
                            textAlign: TextAlign.center,
                            style: const TextStyle(
                              fontFamily: 'CupertinoSystemDisplay',
                              color: Colors.white,
                              fontSize: 40,
                              fontWeight: FontWeight.w600,
                              letterSpacing: 0,
                              height: 1.2,
                            ),
                          ),
                          if (widget.startedAt != null) ...[
                            const SizedBox(height: 12),
                            Text(
                              _duration(),
                              style: const TextStyle(
                                fontFamily: 'CupertinoSystemDisplay',
                                color: Colors.white70,
                                fontSize: 20,
                                fontWeight: FontWeight.w400,
                                letterSpacing: 0,
                                height: 1.2,
                              ),
                            ),
                          ],
                          if (error ?? widget.error case final String message)
                            Semantics(
                              liveRegion: true,
                              child: Padding(
                                padding: const EdgeInsets.all(12),
                                child: Text(
                                  message,
                                  style: const TextStyle(
                                    fontFamily: 'CupertinoSystemText',
                                    color: Colors.white,
                                    fontSize: 15,
                                    fontWeight: FontWeight.w400,
                                    letterSpacing: 0,
                                    height: 1.3,
                                  ),
                                ),
                              ),
                            ),
                          keypadTransition(
                            keypad
                                ? Column(
                                    children: [
                                      const SizedBox(height: 16),
                                      for (final row in [
                                        '123',
                                        '456',
                                        '789',
                                        '*0#',
                                      ])
                                        Row(
                                          mainAxisAlignment:
                                              MainAxisAlignment.spaceEvenly,
                                          children: row
                                              .split('')
                                              .map(
                                                (digit) => SizedBox(
                                                  width: 68,
                                                  height:
                                                      (MediaQuery.textScalerOf(
                                                                    context,
                                                                  ).scale(30) *
                                                                  1.2 +
                                                              16)
                                                          .clamp(
                                                            56.0,
                                                            double.infinity,
                                                          ),
                                                  child: TextButton(
                                                    onPressed: pending || ending
                                                        ? null
                                                        : () => send('dtmf', {
                                                            'digit': digit,
                                                          }),
                                                    child: Text(
                                                      digit,
                                                      style: const TextStyle(
                                                        fontFamily:
                                                            'CupertinoSystemDisplay',
                                                        color: Colors.white,
                                                        fontSize: 30,
                                                        fontWeight:
                                                            FontWeight.w400,
                                                        letterSpacing: 0,
                                                        height: 1.1,
                                                      ),
                                                    ),
                                                  ),
                                                ),
                                              )
                                              .toList(),
                                        ),
                                    ],
                                  )
                                : const SizedBox.shrink(),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 420),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          child: control(
                            CupertinoIcons.speaker_3_fill,
                            voWifiL10n(context).voWifiSpeaker,
                            () => send('speaker', {'enabled': !speaker}),
                            selected: speaker,
                            diameter: compact ? 56 : 76,
                          ),
                        ),
                        Expanded(
                          child: control(
                            CupertinoIcons.mic_slash_fill,
                            voWifiL10n(context).voWifiMute,
                            () => send('mute', {'enabled': !muted}),
                            selected: muted,
                            diameter: compact ? 56 : 76,
                          ),
                        ),
                        Expanded(
                          child: control(
                            CupertinoIcons.circle_grid_3x3_fill,
                            keypad
                                ? voWifiL10n(context).voWifiHideKeypad
                                : voWifiL10n(context).voWifiKeypad,
                            () => setState(() => keypad = !keypad),
                            selected: keypad,
                            diameter: compact ? 56 : 76,
                          ),
                        ),
                      ],
                    ),
                  ),
                  SizedBox(height: compact ? 12 : 24),
                  control(
                    CupertinoIcons.phone_down_fill,
                    voWifiL10n(context).voWifiEndCall,
                    () => send('hangup'),
                    end: true,
                    diameter: compact ? 56 : 76,
                  ),
                ],
              ),
            );
          },
        ),
      ),
    ),
  );

  String _duration() {
    final seconds = DateTime.now()
        .difference(widget.startedAt!)
        .inSeconds
        .clamp(0, 864000);
    return '${(seconds ~/ 60).toString().padLeft(2, '0')}:${(seconds % 60).toString().padLeft(2, '0')}';
  }
}
