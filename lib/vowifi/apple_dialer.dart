import 'l10n.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'privacy_redaction.dart';
import 'glass_surface.dart';

// Explicit system aliases avoid inheriting Material font family or tracking.
const _textStyle = TextStyle(
  inherit: false,
  fontFamily: 'CupertinoSystemText',
  fontSize: 17,
  fontWeight: FontWeight.w400,
  letterSpacing: 0,
);
const _displayStyle = TextStyle(
  inherit: false,
  fontFamily: 'CupertinoSystemDisplay',
  fontSize: 36,
  fontWeight: FontWeight.w400,
  letterSpacing: 0,
  height: 1.05,
);

/// Dial-only presentation; all telephony remains owned by the existing service.
class AppleDialer extends StatelessWidget {
  const AppleDialer({
    super.key,
    required this.number,
    required this.line,
    required this.onDigit,
    required this.onDelete,
    required this.onCall,
    required this.onBack,
    this.error,
    this.status,
  });
  final String number, line;
  final ValueChanged<String> onDigit;
  final VoidCallback? onDelete, onCall;
  final VoidCallback onBack;
  final String? error, status;
  static const _contentWidth = 390.0;

  @override
  Widget build(BuildContext context) {
    final foreground = CupertinoColors.label.resolveFrom(context);
    return Scaffold(
      backgroundColor: CupertinoColors.systemBackground.resolveFrom(context),
      appBar: AppBar(
        backgroundColor: CupertinoColors.systemBackground.resolveFrom(context),
        surfaceTintColor: Colors.transparent,
        automaticallyImplyLeading: false,
        centerTitle: false,
        title: Text(
          line,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: _textStyle.copyWith(color: foreground),
        ),
        actions: [const VoWifiPrivacyAction()],
      ),
      bottomNavigationBar: SafeArea(
        top: false,
        // Consume the home-indicator inset once, outside the glass.
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
          child: Center(
            heightFactor: 1,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: _contentWidth),
              child: CommunicationGlass(
                key: const ValueKey('apple-dial-tabs'),
                child: Padding(
                  padding: const EdgeInsets.all(6),
                  child: LayoutBuilder(
                    builder: (context, constraints) {
                      final labels = [
                        voWifiL10n(context).voWifiRecents,
                        voWifiL10n(context).voWifiKeypad,
                      ];
                      // Use the taller measured label for both cells. Ordinary
                      // text remains one line; accessibility text can wrap.
                      var labelHeight = 0.0;
                      for (var index = 0; index < labels.length; index++) {
                        final painter =
                            TextPainter(
                              text: TextSpan(
                                text: labels[index],
                                style: _tabLabelStyle(index == 1),
                              ),
                              textDirection: Directionality.of(context),
                              textScaler: MediaQuery.textScalerOf(context),
                            )..layout(
                              maxWidth: (constraints.maxWidth / 2 - 18).clamp(
                                1.0,
                                double.infinity,
                              ),
                            );
                        if (painter.height > labelHeight) {
                          labelHeight = painter.height;
                        }
                        painter.dispose();
                      }
                      return Row(
                        children: [
                          _tab(
                            context,
                            CupertinoIcons.clock_fill,
                            labels[0],
                            false,
                            onBack,
                            labelHeight,
                          ),
                          _tab(
                            context,
                            CupertinoIcons.circle_grid_3x3_fill,
                            labels[1],
                            true,
                            () {},
                            labelHeight,
                          ),
                        ],
                      );
                    },
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
      body: SafeArea(
        // Scaffold already reserves the safe bottom navigation area.
        bottom: false,
        child: LayoutBuilder(
          builder: (context, constraints) {
            final width = constraints.maxWidth.clamp(0.0, _contentWidth);
            final messageStyle = _textStyle.copyWith(
              fontSize: 14,
              height: 1.25,
            );
            final messages = [
              if (status != null && status!.isNotEmpty) status!,
              if (error != null && error!.isNotEmpty) error!,
            ];
            var headerHeight = 76.0;
            for (final message in messages) {
              final painter = TextPainter(
                text: TextSpan(text: message, style: messageStyle),
                textDirection: Directionality.of(context),
                textScaler: MediaQuery.textScalerOf(context),
              )..layout(maxWidth: (width - 48).clamp(1.0, double.infinity));
              headerHeight += painter.height + 8;
              painter.dispose();
            }
            // Balance space around the actual key/call group. Its number header
            // is deliberately excluded from the group's visual center.
            final baseDiameter = (width * .195).clamp(48.0, 78.0);
            final textScale = MediaQuery.textScalerOf(context).scale(36) / 36;
            final largeText = textScale > 1.3;
            // Larger text must not make the short-screen keys smaller. Grow
            // within the three-column width and scroll the group instead.
            final preferredDiameter = largeText
                ? (baseDiameter * textScale.clamp(1.0, 1.35)).clamp(
                    baseDiameter,
                    ((width - 48) / 3).clamp(baseDiameter, 98.0),
                  )
                : baseDiameter;
            final diameter =
                ((constraints.maxHeight - 2 * headerHeight - 64) / 5).clamp(
                  largeText ? preferredDiameter : 48.0,
                  preferredDiameter,
                );
            return SingleChildScrollView(
              child: ConstrainedBox(
                constraints: BoxConstraints(minHeight: constraints.maxHeight),
                child: Center(
                  child: SizedBox(
                    width: width,
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        SizedBox(
                          height: headerHeight,
                          child: Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 24),
                            child: Column(
                              children: [
                                SizedBox(
                                  height: 68,
                                  child: Center(
                                    child: FittedBox(
                                      fit: BoxFit.scaleDown,
                                      child: Text(
                                        VoWifiPrivacy.phoneNumber(number),
                                        key: const ValueKey(
                                          'apple-dial-number',
                                        ),
                                        style: _displayStyle.copyWith(
                                          fontSize: 32,
                                          color: foreground,
                                        ),
                                      ),
                                    ),
                                  ),
                                ),
                                if (status != null && status!.isNotEmpty)
                                  Padding(
                                    padding: const EdgeInsets.only(bottom: 8),
                                    child: Text(
                                      status!,
                                      textAlign: TextAlign.center,
                                      style: messageStyle.copyWith(
                                        color: foreground,
                                      ),
                                    ),
                                  ),
                                if (error != null && error!.isNotEmpty)
                                  Padding(
                                    padding: const EdgeInsets.only(bottom: 8),
                                    child: Text(
                                      error!,
                                      textAlign: TextAlign.center,
                                      style: messageStyle.copyWith(
                                        color: CupertinoColors.systemRed
                                            .resolveFrom(context),
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        ),
                        Column(
                          key: const ValueKey('apple-dial-controls'),
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            for (var row = 0; row < 4; row++)
                              Padding(
                                padding: const EdgeInsets.only(bottom: 16),
                                child: Row(
                                  mainAxisAlignment:
                                      MainAxisAlignment.spaceEvenly,
                                  children: [
                                    for (var col = 0; col < 3; col++)
                                      _key(
                                        context,
                                        '123456789*0#'[row * 3 + col],
                                        diameter,
                                      ),
                                  ],
                                ),
                              ),
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                              children: [
                                SizedBox(width: diameter),
                                SizedBox(
                                  width: diameter,
                                  height: diameter,
                                  child: _DialPressButton(
                                    key: const ValueKey('apple-dial-call'),
                                    label: voWifiL10n(context).voWifiCall,
                                    onPressed: onCall,
                                    color: onCall == null
                                        ? CupertinoColors.systemGrey3
                                              .resolveFrom(context)
                                        : CupertinoColors.systemGreen
                                              .resolveFrom(context),
                                    child: const Icon(
                                      CupertinoIcons.phone_fill,
                                      size: 34,
                                      color: CupertinoColors.white,
                                    ),
                                  ),
                                ),
                                SizedBox(
                                  width: diameter,
                                  height: diameter,
                                  child: _DialPressButton(
                                    key: const ValueKey('apple-dial-delete'),
                                    label: voWifiL10n(
                                      context,
                                    ).voWifiDeleteDigit,
                                    onPressed: onDelete,
                                    child: Icon(
                                      CupertinoIcons.delete_left,
                                      color: foreground,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                        SizedBox(height: headerHeight),
                      ],
                    ),
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _key(BuildContext context, String digit, double diameter) {
    final letters =
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
        '';
    final foreground = CupertinoColors.label.resolveFrom(context);
    return SizedBox(
      width: diameter,
      height: diameter,
      child: _DialPressButton(
        key: ValueKey('apple-dial-key-$digit'),
        label: letters.isEmpty ? digit : '$digit, $letters',
        onPressed: () {
          HapticFeedback.selectionClick();
          onDigit(digit);
        },
        onLongPress: digit == '0'
            ? () {
                HapticFeedback.selectionClick();
                onDigit('+');
              }
            : null,
        color: CupertinoColors.tertiarySystemFill.resolveFrom(context),
        child: Padding(
          padding: const EdgeInsets.all(6),
          child: FittedBox(
            fit: BoxFit.scaleDown,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(digit, style: _displayStyle.copyWith(color: foreground)),
                Text(
                  letters,
                  style: _textStyle.copyWith(
                    fontSize: 11,
                    height: 1.1,
                    letterSpacing: 1.5,
                    fontWeight: FontWeight.w500,
                    color: foreground,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  TextStyle _tabLabelStyle(bool selected) => _textStyle.copyWith(
    fontSize: 12,
    height: 1.2,
    fontWeight: selected ? FontWeight.w600 : FontWeight.w400,
  );

  Widget _tab(
    BuildContext context,
    IconData icon,
    String label,
    bool selected,
    VoidCallback onTap,
    double labelHeight,
  ) {
    final color = selected
        ? CupertinoColors.systemBlue.resolveFrom(context)
        : CupertinoColors.secondaryLabel.resolveFrom(context);
    return Expanded(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 3),
        child: _DialPressButton(
          key: ValueKey(
            selected ? 'apple-dial-tab-keypad' : 'apple-dial-tab-recents',
          ),
          label: label,
          selected: selected,
          onPressed: onTap,
          radius: 22,
          color: selected ? color.withValues(alpha: .10) : Colors.transparent,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 8),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, size: 25, color: color),
                const SizedBox(height: 4),
                SizedBox(
                  width: double.infinity,
                  height: labelHeight,
                  child: Center(
                    child: Text(
                      label,
                      textAlign: TextAlign.center,
                      style: _tabLabelStyle(selected).copyWith(color: color),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Feedback changes only opacity and a paint transform, never layout or blur.
/// One gesture recognizer owns tap/long press arbitration.
class _DialPressButton extends StatefulWidget {
  const _DialPressButton({
    super.key,
    required this.label,
    required this.onPressed,
    required this.child,
    this.onLongPress,
    this.color = Colors.transparent,
    this.radius,
    this.selected,
  });
  final String label;
  final VoidCallback? onPressed, onLongPress;
  final Widget child;
  final Color color;
  final double? radius;
  final bool? selected;
  @override
  State<_DialPressButton> createState() => _DialPressButtonState();
}

class _DialPressButtonState extends State<_DialPressButton> {
  bool _pressed = false;
  @override
  void didUpdateWidget(_DialPressButton oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.onPressed == null) _pressed = false;
  }

  void _setPressed(bool value) {
    if (_pressed != value) setState(() => _pressed = value);
  }

  @override
  Widget build(BuildContext context) {
    final enabled = widget.onPressed != null;
    final duration = communicationMotion(context, 90);
    final pressed = enabled && _pressed;
    return Semantics(
      label: widget.label,
      button: true,
      enabled: enabled,
      selected: widget.selected,
      onTap: widget.onPressed,
      onLongPress: enabled ? widget.onLongPress : null,
      excludeSemantics: true,
      child: Tooltip(
        message: widget.label,
        excludeFromSemantics: true,
        // Do not compete with the zero key's long-press plus action.
        triggerMode: TooltipTriggerMode.manual,
        child: GestureDetector(
          behavior: HitTestBehavior.opaque,
          excludeFromSemantics: true,
          onTapDown: enabled ? (_) => _setPressed(true) : null,
          onTapUp: enabled ? (_) => _setPressed(false) : null,
          onTapCancel: enabled ? () => _setPressed(false) : null,
          onTap: widget.onPressed,
          onLongPress: enabled ? widget.onLongPress : null,
          onLongPressEnd: enabled ? (_) => _setPressed(false) : null,
          child: AnimatedScale(
            duration: duration,
            curve: Curves.easeOutCubic,
            scale: pressed && duration != Duration.zero ? .965 : 1,
            child: AnimatedOpacity(
              duration: duration,
              opacity: !enabled
                  ? .35
                  : pressed
                  ? .65
                  : 1,
              child: DecoratedBox(
                decoration: BoxDecoration(
                  color: widget.color,
                  shape: widget.radius == null
                      ? BoxShape.circle
                      : BoxShape.rectangle,
                  borderRadius: widget.radius == null
                      ? null
                      : BorderRadius.circular(widget.radius!),
                ),
                child: Center(
                  widthFactor: 1,
                  heightFactor: 1,
                  child: widget.child,
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
