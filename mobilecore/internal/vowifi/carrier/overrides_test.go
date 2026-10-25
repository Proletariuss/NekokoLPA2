package carrier

import (
	"strings"
	"testing"
)

const completeOverrideYAML = `
carrier_overrides:
  "310/260":
    id: tmobile_custom
    custom_epdg: epdg.epc.mnc260.mcc310.pub.3gppnetwork.org
    epdg_port: 500
    apn: ims
    ip_stack: ipv4v6
    dns_servers: ["8.8.8.8", "1.1.1.1:53"]
    nat_keepalive_seconds: 20
    dpd_interval_seconds: 600
    reauth_interval_seconds: 3600
    algorithm_policy: balanced
    enable_legacy_ciphers: false
    ike_proposals: [aes256-sha256-prfsha1-modp2048, aes128-sha256-modp2048]
    esp_proposals: [aes256-sha256]
    aka_challenge_mode: minimal
    device_model: iphone15,4
    device_identity_enabled: true
    device_identity_imei: "351234567890124"
    ims_domain: ims.mnc260.mcc310.3gppnetwork.org
    ims_realm: ims.mnc260.mcc310.3gppnetwork.org
    ims_phone_context: ims.mnc260.mcc310.3gppnetwork.org
    ims_pcscf: ""
    ims_transport: auto
    ims_identity_source: isim
    ims_local_port: 5060
    ims_tcp_keepalive_seconds: 30
    ims_options_ping_interval_seconds: 45
    ims_register_template:
      id: tmobile_custom_reg
      expires: 600000
      contact_mode: android_default
      sec_agree_mode: auto
      supported_header: path,sec-agree,gruu
      access_type: wlan1
      contact_param_order: [access_type, sip_instance, audio, smsip, icsi_ref]
      include_pani_authenticated: true
      strict_security_server_offer: true
      enable_initial_reject_fallback: true
      security_client_mechanisms:
        - {alg: hmac-sha-1-96, ealg: aes-cbc, prot: esp, mode: trans}
      register_policy:
        temporary_status_codes: [408, 429, 500, 502, 503, 504]
        forbidden_status_codes: [403]
        initial_reject_fallback_status_codes: [400, 403, 500]
        temporary_retry_seconds: 60
    e911:
      enabled: true
      provider: att_entitlement
      entitlement_url: https://example.carrier.net/
      websheet_host_policy: public_https
`

func TestLoadOverridesCompleteExampleAndDeepCopy(t *testing.T) {
	set, err := LoadOverrides([]byte(completeOverrideYAML))
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len()=%d, want 1", set.Len())
	}
	got, ok := set.Match("310", "260")
	if !ok || got == nil {
		t.Fatal("310/260 did not match")
	}
	if got.ID == nil || *got.ID != "tmobile_custom" || got.IMSPCSCF == nil || *got.IMSPCSCF != "" {
		t.Fatalf("unexpected override: %#v", got)
	}
	if got.IMSPhoneContext == nil || *got.IMSPhoneContext != "ims.mnc260.mcc310.3gppnetwork.org" {
		t.Fatalf("IMS phone context=%v", got.IMSPhoneContext)
	}
	if got.DNSServers == nil || len(*got.DNSServers) != 2 || (*got.DNSServers)[0] != "8.8.8.8:53" {
		t.Fatalf("normalized DNS=%v", got.DNSServers)
	}
	(*got.IKEProposals)[0] = "mutated"
	again, _ := set.Match("310", "260")
	if (*again.IKEProposals)[0] == "mutated" {
		t.Fatal("Match returned shared slice storage")
	}
}

func TestOverridePLMNAliasesAndDuplicateDetection(t *testing.T) {
	set, err := LoadOverrides([]byte("carrier_overrides:\n  \"234/033\": {id: test}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Match("234", "33"); !ok {
		t.Fatal("234/033 should match 234/33")
	}
	_, err = LoadOverrides([]byte("carrier_overrides:\n  \"234/033\": {id: one}\n  \"234/33\": {id: two}\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate alias error=%v", err)
	}
}

func TestOverrideRejectsUnknownFieldAndInvalidSecurityValues(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown", "carrier_overrides:\n  \"310/260\": {mystery: true}\n", "field mystery"},
		{"imei_luhn", "carrier_overrides:\n  \"310/260\": {device_identity_imei: \"351234567890123\"}\n", "Luhn"},
		{"legacy_gate", "carrier_overrides:\n  \"310/260\": {algorithm_policy: legacy_prefer, enable_legacy_ciphers: false}\n", "requires"},
		{"private_e911", "carrier_overrides:\n  \"310/260\":\n    e911: {enabled: true, provider: att_entitlement, entitlement_url: https://127.0.0.1/, websheet_host_policy: public_https}\n", "not public"},
		{"incomplete_e911", "carrier_overrides:\n  \"310/260\":\n    e911: {enabled: true, provider: att_entitlement, entitlement_url: https://example.com/}\n", "websheet_host_policy"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadOverrides([]byte(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestExplicitEmptyProposalListPresenceIsPreserved(t *testing.T) {
	set, err := LoadOverrides([]byte("carrier_overrides:\n  \"310/260\":\n    ike_proposals: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := set.Match("310", "260")
	if got.IKEProposals == nil || *got.IKEProposals == nil || len(*got.IKEProposals) != 0 {
		t.Fatalf("explicit empty list lost: %#v", got.IKEProposals)
	}
}
