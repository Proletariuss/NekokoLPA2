import 'dart:ui';
import 'package:flutter/cupertino.dart';
import 'package:flutter/services.dart';

/// Shared short transitions; accessibility must never depend on motion.
Duration communicationMotion(BuildContext context, [int milliseconds = 140]) =>
    MediaQuery.disableAnimationsOf(context) ||
        MediaQuery.accessibleNavigationOf(context)
    ? Duration.zero
    : Duration(milliseconds: milliseconds);

/// Lightweight Flutter material approximation, not native Liquid Glass.
/// Only bounded control surfaces blur; accessibility uses an opaque fallback.
class CommunicationGlass extends StatefulWidget {
  const CommunicationGlass({super.key, required this.child, this.radius = 28});
  final Widget child;
  final double radius;

  @override
  State<CommunicationGlass> createState() => _CommunicationGlassState();
}

class _CommunicationGlassState extends State<CommunicationGlass>
    with WidgetsBindingObserver {
  static final _blur = ImageFilter.blur(sigmaX: 12, sigmaY: 12);
  bool reduceTransparency = true;
  int _appearanceRequest = 0;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _refresh();
  }

  Future<void> _refresh() async {
    final request = ++_appearanceRequest;
    var opaque = true;
    try {
      final value = await const MethodChannel(
        'proletarius/vowifi',
      ).invokeMethod<bool>('reduceTransparency');
      opaque = value ?? true;
    } on PlatformException {
      /* Keep opaque fallback. */
    } on MissingPluginException {
      /* Unsupported platforms stay opaque. */
    }
    if (mounted &&
        request == _appearanceRequest &&
        reduceTransparency != opaque) {
      setState(() => reduceTransparency = opaque);
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _refresh();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final opaque =
        reduceTransparency ||
        MediaQuery.accessibleNavigationOf(context) ||
        MediaQuery.highContrastOf(context);
    final dark = CupertinoTheme.brightnessOf(context) == Brightness.dark;
    final surface = DecoratedBox(
      decoration: BoxDecoration(
        color: (dark ? const Color(0xFF252529) : const Color(0xFFF6F6F8))
            .withValues(alpha: opaque ? 1 : .88),
        borderRadius: BorderRadius.circular(widget.radius),
        border: Border.all(
          color: dark ? const Color(0x33FFFFFF) : const Color(0xFFFFFFFF),
          width: .5,
        ),
      ),
      // Cursor, press and other child repaints stop before the backdrop layer.
      child: RepaintBoundary(child: widget.child),
    );
    return RepaintBoundary(
      child: ClipRRect(
        borderRadius: BorderRadius.circular(widget.radius),
        // Keep the child at the same element path when asynchronous preferences
        // change. Replacing this wrapper would dispose editable child state.
        child: BackdropFilter(enabled: !opaque, filter: _blur, child: surface),
      ),
    );
  }
}
