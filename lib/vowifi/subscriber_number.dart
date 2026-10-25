import 'package:dlibphonenumber/dlibphonenumber.dart';

/// Display-only normalization of a number supplied by IMS or the current SIM.
/// This never derives a number from IMSI, ICCID, a nickname, or device locale.
class SubscriberNumber {
  const SubscriberNumber._(this.number, this.countryCode);

  final String number;
  final String? countryCode;

  String get display {
    final country = countryCode;
    final flag = country == null
        ? '🌐'
        : String.fromCharCodes(
            country.codeUnits.map((value) => value + 127397),
          );
    return '$flag $number';
  }

  static SubscriberNumber? parse(String raw, {String? homeRegion}) {
    // Allow ordinary visual phone separators, but never accept embedded SIP
    // identities, extensions or arbitrary text as the subscriber's number.
    final value = raw.trim().replaceAll(RegExp(r'[\s().-]'), '');
    if (!RegExp(r'^\+?[0-9]{7,15}$').hasMatch(value)) return null;
    final digits = value.replaceFirst('+', '');
    if (RegExp(r'^([0-9])\1+$').hasMatch(digits)) return null;
    final util = PhoneNumberUtil.instance;
    final region = homeRegion?.toUpperCase();
    final hasHomeRegion =
        region != null && util.supportedRegions.contains(region);
    // A national SIM number needs its own SIM's region, never the user's
    // current roaming location or iPhone language/locale.
    if (!value.startsWith('+') && !hasHomeRegion) return null;
    try {
      final parsed = util.parse(value, hasHomeRegion ? region : null);
      // Local-only forms (e.g. seven-digit NANP numbers without area code)
      // must not be promoted into a fabricated complete international number.
      if (util.isPossibleNumberWithReason(parsed) !=
          ValidationResult.isPossible) {
        return null;
      }
      final normalized = util.format(parsed, PhoneNumberFormat.e164);
      if (!RegExp(r'^\+[1-9][0-9]{6,14}$').hasMatch(normalized)) return null;
      var country = util.getRegionCodeForNumber(parsed);
      if (country == null) {
        final regions = util.getRegionCodesForCountryCode(parsed.countryCode);
        if (regions.length == 1) country = regions.single;
      }
      // Shared codes without a matching range and global services have no
      // unambiguous national flag. Show the number with a neutral globe.
      if (country == null ||
          !RegExp(r'^[A-Z]{2}$').hasMatch(country) ||
          !util.supportedRegions.contains(country)) {
        country = null;
      }
      return SubscriberNumber._(normalized, country);
    } catch (_) {
      return null;
    }
  }
}
