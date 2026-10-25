import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:logging/logging.dart';
import 'package:nlpa2/vowifi/connection_diagnostics.dart';
import 'package:nlpa2/version.dart';

void main() {
  test(
    'certificate reasons and public fingerprints retain response context',
    () {
      final records = <LogRecord>[];
      final subscription = Logger(
        'VoWifiConnection',
      ).onRecord.listen(records.add);
      addTearDown(subscription.cancel);
      final fingerprint = '0123456789abcdef' * 4;
      final diagnostics = VoWifiConnectionDiagnostics();
      final response = <String, Object>{
        'stage': 'initial',
        'message_id': 1,
        'cert_count': 1,
        'payload_types': [35, 37, 39, 48],
        'eap_codes': [1],
        'eap_types': [1],
        'auth_methods': [1],
        'idr_types': [2],
        'certificate_required': true,
        'peer_authenticated': false,
        'failure_code': 'certificate_validation_failed',
        'certificate_failure': 'certificate_chain_incomplete',
        'certificate_trust_stage': 2,
        'certificate_trust_code': -25318,
        'certificate_leaf_sha256': fingerprint,
      };
      final request = {
        'stage': 'initial',
        'send_state': 'prepared',
        'certreq_count': 1,
        'certreq_encodings': [4],
      };
      diagnostics.record({
        'phase': 'failed',
        'generation': 6,
        'attempt': 2,
        'terminal': true,
        'registered': false,
        'checking_connection': false,
        'ike_auth_diagnostic': {
          ...response,
          'subject': 'subscriber-secret',
          'san': 'subscriber-secret',
          'certificate': 'subscriber-secret',
        },
        'ike_auth_request_diagnostic': {
          ...request,
          'certificate_failure': 'request-secret',
          'certificate_leaf_sha256': fingerprint,
        },
      });
      expect(jsonDecode(records.single.message), {
        'app_version': kAppVersion,
        'app_build': kAppBuildNumber,
        'generation': 6,
        'attempt': 2,
        'registered': false,
        'checking_connection': false,
        'terminal': true,
        'phase': 'failed',
        'error_category': 'ike_auth_certificate_chain_incomplete',
        'ike_auth_diagnostic': response,
        'ike_auth_request_diagnostic': request,
      });
      (response['payload_types'] as List<int>)[0] = 99;
      expect(
        (jsonDecode(records.single.message)
            as Map)['ike_auth_diagnostic']['payload_types'],
        [35, 37, 39, 48],
      );
      for (final code in [-2147483648, 0, 2147483647]) {
        diagnostics.record({
          'ike_auth_diagnostic': {
            'failure_code': 'signature_validation_failed',
            'certificate_failure': 'certificate_revoked',
            'certificate_trust_stage': 16,
            'certificate_trust_code': code,
          },
        });
        final entry = jsonDecode(records.last.message) as Map;
        expect(entry['error_category'], 'ike_auth_signature_validation_failed');
        expect(entry['ike_auth_diagnostic']['certificate_trust_code'], code);
        expect(entry['ike_auth_diagnostic']['certificate_trust_stage'], 16);
      }
    },
  );

  test('certificate diagnostic rejects malformed bounds and injected text', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    final diagnostics = VoWifiConnectionDiagnostics();
    for (final value in [
      {'stage': -1, 'code': -2147483649},
      {'stage': 17, 'code': 2147483648},
      {'stage': 1.0, 'code': -25318.0},
      {'stage': 'subscriber-secret', 'code': 'subscriber-secret'},
    ]) {
      diagnostics.record({
        'attempt': records.length,
        'ike_auth_diagnostic': {
          'failure_code': 'certificate_validation_failed',
          'certificate_failure': 'subscriber-secret\nCN=private-name',
          'certificate_trust_stage': value['stage'],
          'certificate_trust_code': value['code'],
          'certificate_leaf_sha256': 'subscriber-secret',
        },
      });
      final entry = jsonDecode(records.last.message) as Map;
      expect(entry['error_category'], 'ike_auth_certificate_trust_internal');
      expect(entry['ike_auth_diagnostic'], {
        'failure_code': 'certificate_validation_failed',
        'certificate_failure': 'certificate_trust_internal',
      });
      expect(records.last.message, isNot(contains('subscriber-secret')));
    }
    for (final fingerprint in [
      '',
      'a' * 63,
      'a' * 65,
      'A' * 64,
      'g' * 64,
      '${'a' * 64}\n',
    ]) {
      diagnostics.record({
        'attempt': records.length,
        'ike_auth_diagnostic': {
          'stage': 'initial',
          'certificate_leaf_sha256': fingerprint,
          'certificate_failure': 1,
        },
      });
      expect((jsonDecode(records.last.message) as Map)['ike_auth_diagnostic'], {
        'stage': 'initial',
      });
    }
    diagnostics.record({
      'ike_auth_diagnostic': {'certificate_failure': 'certificate_revoked'},
    });
    expect((jsonDecode(records.last.message) as Map)['error_category'], 'none');
  });

  test('prepared request fields export beside the response failure', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    final request = <String, Object>{
      'stage': 'initial',
      'message_id': 0xffffffff,
      'payload_types': [35, 40, 41, 47],
      'notify_types': [16384, 16417, 65535],
      'idi_types': [1],
      'idr_types': [2],
      'idi_anonymous': true,
      'idr_is_apn': true,
      'certreq_count': 1,
      'certreq_encodings': [4],
      'certreq_ca_hash_count': 0,
      'eap_codes': <int>[],
      'eap_types': <int>[],
      'certificate_required': true,
      'eap_only_offered': false,
      'fragmented': false,
      'packet_count': 1,
      'send_state': 'prepared',
    };
    final diagnostics = VoWifiConnectionDiagnostics();
    diagnostics.record({
      'phase': 'failed',
      'ike_auth_request_diagnostic': {
        ...request,
        'idi': 'subscriber-secret@realm-secret',
        'idr': 'endpoint-secret',
        'certreq_ca_hash': 'ca-secret',
        'certificate': 'certificate-secret',
        'credentials': 'password-secret',
        'failure_code': 'request-secret',
        'send_success': true,
      },
      'ike_auth_diagnostic': {
        'stage': 'initial',
        'failure_code': 'missing_certificate_auth',
      },
    });
    expect(jsonDecode(records.single.message), {
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
      'phase': 'failed',
      'error_category': 'ike_auth_missing_certificate_auth',
      'ike_auth_diagnostic': {
        'stage': 'initial',
        'failure_code': 'missing_certificate_auth',
      },
      'ike_auth_request_diagnostic': request,
    });
    // EAP/final snapshots retain only the current request, including bounds.
    for (final stage in ['eap', 'final']) {
      final next = {
        ...request,
        'stage': stage,
        'eap_codes': [2],
        'eap_types': [23],
        'certreq_count': 32,
        'certreq_ca_hash_count': 32,
        'certreq_encodings': List.filled(32, 255),
        'packet_count': 255,
        'fragmented': true,
      };
      diagnostics.record({'ike_auth_request_diagnostic': next});
      expect(
        (jsonDecode(records.last.message)
            as Map)['ike_auth_request_diagnostic'],
        next,
      );
      expect(
        (jsonDecode(records.last.message) as Map)['error_category'],
        'none',
      );
    }
  });

  test('request malformed types, bounds and secret injection are excluded', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    final diagnostics = VoWifiConnectionDiagnostics();
    final malformed = <String, Object?>{
      'stage': 'subscriber-secret',
      'message_id': 0x100000000,
      'payload_types': List.filled(33, 35),
      'notify_types': [65536],
      'idi_types': [-1],
      'idr_types': ['subscriber-secret'],
      'idi_anonymous': 'subscriber-secret',
      'idr_is_apn': 1,
      'certreq_count': 33,
      'certreq_encodings': [4.0],
      'certreq_ca_hash_count': -1,
      'eap_codes': [
        {'secret': 'subscriber-secret'},
      ],
      'eap_types': [256],
      'certificate_required': [],
      'eap_only_offered': 'subscriber-secret',
      'fragmented': null,
      'packet_count': 256,
      'send_state': 'sent-successfully-subscriber-secret',
      'raw': 'subscriber-secret',
    };
    // Every recognized key is rejected on bad types or numeric boundaries.
    diagnostics.record({'ike_auth_request_diagnostic': malformed});
    expect(jsonDecode(records.single.message), {
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
      'error_category': 'none',
    });
    for (final raw in [
      'subscriber-secret',
      ['subscriber-secret'],
      null,
    ]) {
      diagnostics.record({'ike_auth_request_diagnostic': raw});
    }
    expect(records, hasLength(1));
    diagnostics.record({
      'ike_auth_request_diagnostic': {
        ...malformed,
        'stage': 'final',
        'message_id': -1,
        'certreq_count': 1.0,
        'certreq_ca_hash_count': 33,
        'packet_count': -1,
        'notify_types': [1, 'subscriber-secret'],
        'send_state': true,
      },
    });
    expect(
      (jsonDecode(records.last.message) as Map)['ike_auth_request_diagnostic'],
      {'stage': 'final'},
    );
  });

  test('service suspension retains its existing phase in exported logs', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    VoWifiConnectionDiagnostics().record({
      'phase': 'suspended',
      'registered': false,
    });
    expect(jsonDecode(records.single.message), {
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
      'registered': false,
      'phase': 'suspended',
      'error_category': 'none',
    });
  });

  test('IKE details and effective policy export only bounded known fields', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    final diagnostics = VoWifiConnectionDiagnostics();
    final auth = <String, Object>{
      'stage': 'initial',
      'message_id': 1,
      'payload_types': [35, 48],
      'notify_types': [16384, 16417],
      'eap_codes': [1],
      'eap_types': [23],
      'cert_count': 0,
      'auth_methods': <int>[],
      'idr_types': [2],
      'certificate_required': true,
      'eap_only_offered': false,
      'peer_authenticated': false,
      'failure_code': 'missing_certificate_auth',
    };
    final policy = <String, Object>{
      'registry_revision': 'ca030f836d858e59443e8957a844216c179d8677',
      'epdg_source': 'carrier-template',
      'epdg_port': 4500,
      'proxy_enabled': true,
      'certificate_required': true,
      'eap_only_offered': false,
      'certificate_profile': 'strict_ike',
      'remote_identity_source': 'certificate-hostname',
      'ip_stack': 'ipv6',
      'ims_transport': 'tcp',
    };
    diagnostics.record({
      'phase': 'failed',
      'app_version': 'secret-version',
      'app_build': 'secret',
      'ike_auth_diagnostic': {
        ...auth,
        'raw': {'imsi': 'secret'},
        'idr': 'secret',
      },
      'connection_policy': {...policy, 'epdg': 'secret', 'proxy': 'secret'},
      'error': 'secret' * 1000,
    });
    expect(jsonDecode(records.single.message), {
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
      'phase': 'failed',
      'error_category': 'ike_auth_missing_certificate_auth',
      'ike_auth_diagnostic': auth,
      'connection_policy': policy,
    });
    diagnostics.record({
      'ike_auth_diagnostic': {
        ...auth,
        'failure_code': 'peer_notify_authentication_failed',
      },
    });
    expect(
      (jsonDecode(records.last.message) as Map)['error_category'],
      'ike_auth_peer_rejected',
    );
    diagnostics.record({
      'connection_policy': {
        ...policy,
        'certificate_profile': 'three_uk_server_auth',
      },
    });
    expect((jsonDecode(records.last.message) as Map)['connection_policy'], {
      ...policy,
      'certificate_profile': 'three_uk_server_auth',
    });
    diagnostics.record({
      'connection_policy': {
        ...policy,
        'certificate_profile': 'subscriber-secret',
      },
    });
    final safePolicy = Map<String, Object>.from(policy)
      ..remove('certificate_profile');
    expect(
      (jsonDecode(records.last.message) as Map)['connection_policy'],
      safePolicy,
    );
    expect(records.last.message, isNot(contains('subscriber-secret')));
  });

  test('malformed nested diagnostics cannot enter exported logs', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    final diagnostics = VoWifiConnectionDiagnostics();
    diagnostics.record({
      'generation': -1,
      'attempt': 0x20000000000000,
      'phase': 'secret',
      'ike_stage': 'secret',
      'ike_auth_diagnostic': {
        'stage': 'secret',
        'message_id': 0x100000000,
        'cert_count': -1,
        'payload_types': List.filled(33, 35),
        'notify_types': [65536],
        'eap_codes': [-1],
        'eap_types': [1.2],
        'auth_methods': [
          {'raw': 'secret'},
        ],
        'idr_types': ['secret'],
        'certificate_required': 'secret',
        'eap_only_offered': 1,
        'peer_authenticated': {'raw': 'secret'},
        'failure_code': 'secret',
      },
      'connection_policy': {
        'registry_revision': 'secret',
        'epdg_source': 'secret',
        'epdg_port': -1,
        'proxy_enabled': 'secret',
        'certificate_required': 'secret',
        'eap_only_offered': 'secret',
        'remote_identity_source': 'secret',
        'certificate_profile': {'raw': 'secret'},
        'ip_stack': 'secret',
        'ims_transport': 'secret',
      },
      'error': '${'secret' * 200} authentication timeout',
    });
    expect(jsonDecode(records.single.message), {
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
      'error_category': 'other',
    });
  });

  test('REGISTER rejections retain only the fixed-prefix SIP status code', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    final diagnostics = VoWifiConnectionDiagnostics();
    for (final code in [403, 404, 408, 423, 500, 503]) {
      diagnostics.record({
        'phase': 'failed',
        'error':
            'IMS: authenticated REGISTER failed: $code confidential reason '
            'IMSI=001010123456789 Authorization: secret',
      });
      expect(jsonDecode(records.last.message), {
        'app_version': kAppVersion,
        'app_build': kAppBuildNumber,
        'phase': 'failed',
        'error_category': 'ims_register_rejected',
        'sip_status': code,
      });
    }
    for (final error in [
      'Subscriber 403555123456789 rejected',
      'authenticated REGISTER failed: 403555123456789',
      'authenticated REGISTER failed: 403@ims.example.invalid',
    ]) {
      diagnostics.record({'phase': 'failed', 'error': error});
      expect(jsonDecode(records.last.message), {
        'app_version': kAppVersion,
        'app_build': kAppBuildNumber,
        'phase': 'failed',
        'error_category': 'other',
      });
    }
  });

  test('exported transitions omit subscriber, credential and SIP contents', () {
    final records = <LogRecord>[];
    final subscription = Logger(
      'VoWifiConnection',
    ).onRecord.listen(records.add);
    addTearDown(subscription.cancel);
    final diagnostics = VoWifiConnectionDiagnostics();
    final status = <String, dynamic>{
      'phase': 'failed',
      'generation': 42,
      'attempt': 1,
      'carrier': 'apple_hutchison_hk',
      'registered': false,
      'checking_connection': true,
      'retrying': true,
      'imsi': '001010123456789',
      'private_identity': '001010123456789@ims.example.invalid',
      'proxy': 'socks5://username:password@127.0.0.1:1080',
      'epdg': 'private-endpoint.invalid',
      'call': {'audio_token': 'secret-bearer'},
      'error':
          'IMS incoming SIP listener ended: endpoint is in invalid state '
          '001010123456789 RAND=0123456789abcdef Authorization: secret',
    };
    diagnostics.record(status);
    diagnostics.record(status);
    expect(records, hasLength(1));
    final entry = jsonDecode(records.single.message) as Map;
    expect(entry, {
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
      'generation': 42,
      'attempt': 1,
      'registered': false,
      'checking_connection': true,
      'retrying': true,
      'phase': 'failed',
      'carrier': 'apple_hutchison_hk',
      'error_category': 'endpoint_invalid_state',
    });
    diagnostics.record({
      'phase': 'ike',
      'attempt': 2,
      'carrier': 'sip:001010123456789@ims.example.invalid',
      'ike_stage': '001010123456789',
      'checking_connection': '001010123456789',
    });
    expect(records, hasLength(2));
    expect(jsonDecode(records.last.message), {
      'app_version': kAppVersion,
      'app_build': kAppBuildNumber,
      'attempt': 2,
      'phase': 'ike',
      'error_category': 'none',
    });
  });
}
