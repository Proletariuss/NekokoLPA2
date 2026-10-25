import 'dart:convert';

import 'package:logging/logging.dart';

import '../version.dart';

/// Connection transitions for the existing application log/export buffer.
/// Never log a raw status/error: they can contain subscriber or SIP identities.
class VoWifiConnectionDiagnostics {
  static final _log = Logger('VoWifiConnection');
  String? _last;

  void record(Map<String, dynamic> status) {
    final entry = <String, Object>{
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
    };
    for (final key in ['generation', 'attempt']) {
      final value = status[key];
      if (value is int && value >= 0 && value <= 0x1fffffffffffff) {
        entry[key] = value;
      }
    }
    for (final key in [
      'registered',
      'messaging_ready',
      'call_ready',
      'checking_connection',
      'retrying',
      'terminal',
    ]) {
      if (status[key] is bool) entry[key] = status[key] as bool;
    }
    for (final key in ['phase', 'ike_stage', 'carrier']) {
      final value = status[key];
      if (value is String &&
          RegExp(r'^[a-z][a-z0-9_-]{0,63}$').hasMatch(value) &&
          !RegExp(r'\d{8,}').hasMatch(value) &&
          (key != 'phase' || _phases.contains(value)) &&
          (key != 'ike_stage' || _ikeStages.contains(value))) {
        entry[key] = value;
      }
    }
    final error = status['error'];
    entry['error_category'] = error is String && error.isNotEmpty
        ? _errorCategory(error)
        : 'none';
    if (error is String && error.length <= 1024) {
      // The Go REGISTER path owns this exact prefix. Extract only its status
      // number, never the reason/detail text (which may contain SIP headers).
      final rejection = RegExp(
        r'\bauthenticated REGISTER failed: ([3-6]\d{2})(?:\s|$)',
      ).firstMatch(error);
      if (rejection != null) {
        entry['error_category'] = 'ims_register_rejected';
        entry['sip_status'] = int.parse(rejection.group(1)!);
      }
    }
    final diagnostic = _authDiagnostic(status['ike_auth_diagnostic']);
    if (diagnostic.isNotEmpty) {
      entry['ike_auth_diagnostic'] = diagnostic;
      final failure = diagnostic['failure_code'];
      if (failure is String && failure.isNotEmpty) {
        final certificateFailure = diagnostic['certificate_failure'];
        if (failure == 'certificate_validation_failed' &&
            certificateFailure is String &&
            certificateFailure.isNotEmpty) {
          entry['error_category'] = 'ike_auth_$certificateFailure';
        } else {
          entry['error_category'] = failure.startsWith('peer_notify_')
              ? 'ike_auth_peer_rejected'
              : 'ike_auth_$failure';
        }
      }
    }
    final request = _authRequestDiagnostic(
      status['ike_auth_request_diagnostic'],
    );
    if (request.isNotEmpty) entry['ike_auth_request_diagnostic'] = request;
    final policy = _connectionPolicy(status['connection_policy']);
    if (policy.isNotEmpty) entry['connection_policy'] = policy;
    final encoded = jsonEncode(entry);
    if (encoded == _last) return;
    _last = encoded;
    _log.info(encoded);
  }

  static String _errorCategory(String message) {
    if (message.length > 1024) return 'other';
    final value = message.toLowerCase();
    if (value.contains('endpoint is in invalid state') ||
        value.contains('endpoint invalid state')) {
      return 'endpoint_invalid_state';
    }
    if (value.contains('incoming sip listener ended')) {
      return 'sip_listener_ended';
    }
    if (value.contains('timeout') ||
        value.contains('timed out') ||
        value.contains('deadline exceeded')) {
      return 'timeout';
    }
    if (value.contains('authentication') || value.contains('aka')) {
      return 'authentication';
    }
    if (value.contains('resolve') || value.contains('dns')) {
      return 'name_resolution';
    }
    if (value.contains('connection refused')) return 'connection_refused';
    if (value.contains('sim') || value.contains('reader')) return 'sim_reader';
    if (value.contains('audio')) return 'audio';
    return 'other';
  }

  static const _phases = {
    'idle',
    'sim',
    'ike',
    'ims',
    'ready',
    'failed',
    'stopped',
    'suspended',
  };
  static const _ikeStages = {
    'transport',
    'ike_sa_init',
    'ike_auth',
    'eap_identity',
    'eap_aka',
    'eap_response',
    'eap_success',
    'final_auth',
    'tunnel_setup',
  };
  static const _authFailures = {
    '',
    'peer_notify_authentication_failed',
    'peer_notify_invalid_syntax',
    'peer_notify_unsupported_critical_payload',
    'eap_failure',
    'invalid_eap',
    'missing_idr',
    'missing_certificate_auth',
    'certificate_validation_failed',
    'signature_validation_failed',
    'missing_final_auth',
    'final_auth_mismatch',
    'missing_eap',
    'peer_authentication_failed',
    'auth_response_invalid',
    'child_sa_failed',
  };
  static const _certificateFailures = {
    '',
    'certificate_missing',
    'certificate_chain_limit',
    'certificate_encoding',
    'certificate_parse',
    'certificate_duplicate',
    'certificate_expired',
    'certificate_not_yet_valid',
    'certificate_critical_extension',
    'certificate_key_usage',
    'certificate_eku',
    'certificate_hostname_mismatch',
    'certificate_idr_mismatch',
    'certificate_idr_invalid',
    'certificate_expected_identity_invalid',
    'certificate_ca_constraints',
    'certificate_chain_untrusted',
    'certificate_chain_incomplete',
    'certificate_revoked',
    'certificate_chain_invalid',
    'certificate_trust_internal',
    'certificate_chain_extraneous',
    'certificate_verifier_unavailable',
  };

  static Map<String, Object> _authDiagnostic(Object? raw) {
    if (raw is! Map) return {};
    final safe = <String, Object>{};
    _enumField(raw, safe, 'stage', {'initial', 'eap', 'final'});
    _enumField(raw, safe, 'failure_code', _authFailures);
    final certificateFailure = raw['certificate_failure'];
    if (certificateFailure is String) {
      safe['certificate_failure'] =
          _certificateFailures.contains(certificateFailure)
          ? certificateFailure
          : 'certificate_trust_internal';
    }
    _integerField(raw, safe, 'certificate_trust_stage', 16);
    final trustCode = raw['certificate_trust_code'];
    if (trustCode is int &&
        trustCode >= -2147483648 &&
        trustCode <= 2147483647) {
      safe['certificate_trust_code'] = trustCode;
    }
    final fingerprint = raw['certificate_leaf_sha256'];
    if (fingerprint is String &&
        fingerprint.length == 64 &&
        RegExp(r'^[0-9a-f]{64}$').hasMatch(fingerprint)) {
      safe['certificate_leaf_sha256'] = fingerprint;
    }
    _integerField(raw, safe, 'message_id', 0xffffffff);
    _integerField(raw, safe, 'cert_count', 32);
    for (final key in [
      'payload_types',
      'notify_types',
      'eap_codes',
      'eap_types',
      'auth_methods',
      'idr_types',
    ]) {
      final values = raw[key];
      final max = key == 'notify_types' ? 65535 : 255;
      if (values is List &&
          values.length <= 32 &&
          values.every((v) => v is int && v >= 0 && v <= max)) {
        safe[key] = List<int>.from(values);
      }
    }
    _boolFields(raw, safe, [
      'certificate_required',
      'eap_only_offered',
      'peer_authenticated',
    ]);
    return safe;
  }

  // This fixed state reports request construction, not delivery to the peer.
  static Map<String, Object> _authRequestDiagnostic(Object? raw) {
    if (raw is! Map) return {};
    final safe = <String, Object>{};
    _enumField(raw, safe, 'stage', {'initial', 'eap', 'final'});
    _enumField(raw, safe, 'send_state', {'prepared'});
    _integerField(raw, safe, 'message_id', 0xffffffff);
    _integerField(raw, safe, 'certreq_count', 32);
    _integerField(raw, safe, 'certreq_ca_hash_count', 32);
    _integerField(raw, safe, 'packet_count', 255);
    for (final key in [
      'payload_types',
      'notify_types',
      'idi_types',
      'idr_types',
      'certreq_encodings',
      'eap_codes',
      'eap_types',
    ]) {
      final values = raw[key];
      final max = key == 'notify_types' ? 65535 : 255;
      if (values is List &&
          values.length <= 32 &&
          values.every((v) => v is int && v >= 0 && v <= max)) {
        safe[key] = List<int>.from(values);
      }
    }
    _boolFields(raw, safe, [
      'idi_anonymous',
      'idr_is_apn',
      'certificate_required',
      'eap_only_offered',
      'fragmented',
    ]);
    return safe;
  }

  static Map<String, Object> _connectionPolicy(Object? raw) {
    if (raw is! Map) return {};
    final safe = <String, Object>{};
    final revision = raw['registry_revision'];
    if (revision is String && RegExp(r'^[0-9a-f]{40}$').hasMatch(revision)) {
      safe['registry_revision'] = revision;
    }
    _enumField(raw, safe, 'epdg_source', {
      'custom',
      'carrier-override',
      'carrier-template',
      '3gpp-standard',
      'unknown',
    });
    _enumField(raw, safe, 'remote_identity_source', {
      'epdg',
      'certificate-hostname',
    });
    _enumField(raw, safe, 'certificate_profile', {
      'strict_ike',
      'three_uk_server_auth',
    });
    _enumField(raw, safe, 'ip_stack', {'ipv4', 'ipv6', 'ipv4v6', 'unknown'});
    _enumField(raw, safe, 'ims_transport', {'tcp', 'udp'});
    _integerField(raw, safe, 'epdg_port', 65535);
    _boolFields(raw, safe, [
      'proxy_enabled',
      'certificate_required',
      'eap_only_offered',
    ]);
    return safe;
  }

  static void _integerField(
    Map raw,
    Map<String, Object> safe,
    String key,
    int max,
  ) {
    final value = raw[key];
    if (value is int && value >= 0 && value <= max) safe[key] = value;
  }

  static void _enumField(
    Map raw,
    Map<String, Object> safe,
    String key,
    Set<String> allowed,
  ) {
    final value = raw[key];
    if (value is String && allowed.contains(value)) safe[key] = value;
  }

  static void _boolFields(
    Map raw,
    Map<String, Object> safe,
    List<String> keys,
  ) {
    for (final key in keys) {
      final value = raw[key];
      if (value is bool) safe[key] = value;
    }
  }
}
