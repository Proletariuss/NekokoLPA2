import 'l10n.dart';
import 'dart:async';

import 'package:flutter/material.dart';

import '../settings/app_settings.dart';

/// Display-only redaction helpers shared by the VoWiFi screen and its logs.
class VoWifiPrivacy {
  static bool get isEnabled => AppSettings().isSensitiveDataMasked;

  static String phoneNumber(String value) =>
      isEnabled ? value.replaceAll(RegExp(r'\d'), '•') : value;

  static String identifiers(String value) {
    if (!isEnabled) return value;
    final withSerials = value.replaceAllMapped(
      RegExp(r'\b(?=[A-Za-z0-9]{8,}\b)(?=[A-Za-z0-9]*\d)[A-Za-z0-9]+\b'),
      (match) => '•' * match.group(0)!.length,
    );
    return withSerials.replaceAllMapped(
      RegExp(r'\d{5,}'),
      (match) => '•' * match.group(0)!.length,
    );
  }

  static String privateText(String value, String hiddenLabel) =>
      isEnabled ? hiddenLabel : value;

  static String lineSuffix(String value) => isEnabled ? '••••' : value;
}

class VoWifiPrivacyAction extends StatelessWidget {
  const VoWifiPrivacyAction({super.key});

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: AppSettings(),
    builder: (context, _) {
      final masked = VoWifiPrivacy.isEnabled;
      return IconButton(
        key: const ValueKey('vowifi-privacy-toggle'),
        tooltip: masked
            ? voWifiL10n(context).voWifiShowSensitiveInformation
            : voWifiL10n(context).voWifiHideSensitiveInformation,
        color: masked ? const Color(0xFF0088FF) : Colors.grey,
        onPressed: () =>
            unawaited(AppSettings().toggleSensitiveDataVisibility()),
        icon: Icon(
          masked ? Icons.visibility_off_outlined : Icons.visibility_outlined,
        ),
      );
    },
  );
}
