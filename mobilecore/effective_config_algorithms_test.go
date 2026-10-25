package mobilecore

import (
	"reflect"
	"strings"
	"testing"

	"proletarius.local/core/internal/vowifi"
	"proletarius.local/core/internal/vowifi/carrier"
)

func TestEffectiveCompleteCarrierAlgorithmsAndCustomPrecedence(t *testing.T) {
	p := carrier.FromSIM("216", "70") // Four distinct published IKE alternatives.
	sim := &vowifi.SIMInfo{IMSI: "216701234567890", MCC: "216", MNC: "70"}
	e, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, sim, "", 0, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	if len(e.IKEProposals) != 4 || !reflect.DeepEqual(e.IKEProposals, p.TemplateIKEProposals) {
		t.Fatalf("carrier alternatives lost: %v", e.IKEProposals)
	}
	customIKE := []string{"aes128gcm16-prfsha256-ecp256"}
	override := &carrier.CarrierOverride{IKEProposals: &customIKE}
	e, err = resolveReaderVoWiFiEffectiveConfig(p, override, true, sim, "custom.example", 12345, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.IKEProposals, customIKE) || !reflect.DeepEqual(e.ESPProposals, p.TemplateESPProposals) {
		t.Fatal("per-stage custom priority failed")
	}
	if e.EPDG != "custom.example" || e.EPDGPort != 12345 || !reflect.DeepEqual(e.EPDGCandidates, []string{"custom.example"}) {
		t.Fatal("custom endpoint did not replace full candidate policy")
	}
}

func TestEffectiveUnsupportedCarrierProposalFailsUnlessExplicitlyOverridden(t *testing.T) {
	p := carrier.FromSIM("234", "20")
	p.TemplateIKEProposalError = "fixture unsupported encryption"
	sim := &vowifi.SIMInfo{IMSI: "234201234567890", MCC: "234", MNC: "20"}
	if _, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, sim, "", 0, makeDeviceIMEI()); err == nil || !strings.Contains(err.Error(), "unsupported encryption") {
		t.Fatal("silently ignored unsupported template")
	}
	customIKE := []string{"aes128-sha256-modp2048"}
	e, err := resolveReaderVoWiFiEffectiveConfig(p, &carrier.CarrierOverride{IKEProposals: &customIKE}, true, sim, "", 0, makeDeviceIMEI())
	if err != nil || !reflect.DeepEqual(e.IKEProposals, customIKE) {
		t.Fatal("explicit user override did not supersede unavailable template", err)
	}
}

func TestEffectiveDeclaredLifetimesCertificateAndTransport(t *testing.T) {
	p := carrier.FromSIM("234", "20")
	p.RemoteCertificateHostname = "certificate.example"
	p.EPDGCandidates = []string{"first.example", "second.example"}
	p.TemplateIKELifetime = 7200
	p.TemplateChildLifetime = 3600
	p.TemplateRekeyPFS = 21
	sim := &vowifi.SIMInfo{IMSI: "234201234567890", MCC: "234", MNC: "20"}
	e, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, sim, "", 0, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	if e.IKELifetimeSeconds != 7200 || e.ChildLifetimeSeconds != 3600 || e.RekeyPFS != 21 || e.RemoteCertificateHostname != "certificate.example" || !e.ValidateRemoteCertificate || len(e.EPDGCandidates) != 2 {
		t.Fatalf("metadata lost: %+v", e)
	}
	for _, transport := range []string{"auto", "tcp", "udp"} {
		e.IMSTransport = transport
		if err := validateReaderVoWiFiStartCapabilities(e); err != nil {
			t.Fatal(transport, err)
		}
	}
	e.IMSTransport = "tls"
	if err := validateReaderVoWiFiStartCapabilities(e); err == nil {
		t.Fatal("accepted unimplemented TLS transport")
	}
	e.Profile.TemplateIKEProposals[0] = "mutated"
	if p.TemplateIKEProposals[0] == "mutated" {
		t.Fatal("session metadata aliases carrier source")
	}
}

func TestEffectiveRejectsUnimplementedPFSAndIgnoresUnmatchedPolicy(t *testing.T) {
	for _, group := range []int{1, -1, 65550} {
		if err := validateReaderVoWiFiStartCapabilities(&readerVoWiFiEffectiveConfig{RekeyPFS: group, IMSTransport: "tcp"}); err == nil {
			t.Fatalf("unsupported PFS group %d accepted", group)
		}
	}
	p := carrier.FromSIM("234", "20")
	legacy := true
	e, err := resolveReaderVoWiFiEffectiveConfig(p, &carrier.CarrierOverride{EnableLegacyCiphers: &legacy}, false,
		&vowifi.SIMInfo{IMSI: "234201234567890", MCC: "234", MNC: "20"}, "", 0, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.IKEProposals, p.TemplateIKEProposals) {
		t.Fatal("unmatched override replaced carrier policy")
	}
}
