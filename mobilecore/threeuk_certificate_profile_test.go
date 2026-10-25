package mobilecore

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/swu"
	"proletarius.local/core/internal/vowifi/carrier"
)

func threeUKCertificateFixture() (engineConfig, *readerVoWiFiEffectiveConfig) {
	return engineConfig{cardConfig: cardConfig{MCC: "234", MNC: "20", IMSI: "234201234567890"}}, &readerVoWiFiEffectiveConfig{
		Profile: &carrier.Profile{ID: "apple_hutchison_uk", MCC: "234", MNC: "20", ValidateRemoteCertificate: true},
		EPDG:    threeUKCertificateHostname, EPDGPort: 500, EPDGSource: "carrier-template",
		RemoteCertificateHostname: threeUKCertificateHostname, ValidateRemoteCertificate: true,
		IKELocalIdentifier: "anonymous@nai.epc.mnc020.mcc234.3gppnetwork.org", APN: "ims", IPStack: "ipv6",
	}
}

func TestThreeUKCertificateProfileRequiresExactPublishedScope(t *testing.T) {
	cases := map[string]func(*engineConfig, *readerVoWiFiEffectiveConfig){
		"other_carrier":      func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.Profile.ID = "apple_vodafone_uk" },
		"id_mvno":            func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.Profile.ID = "apple_hutchison_id_uk" },
		"three_hk":           func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.Profile.ID = "apple_hutchison_hk" },
		"wrong_mcc":          func(c *engineConfig, _ *readerVoWiFiEffectiveConfig) { c.MCC = "454" },
		"wrong_mnc_width":    func(c *engineConfig, _ *readerVoWiFiEffectiveConfig) { c.MNC = "020" },
		"wrong_profile_plmn": func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.Profile.MNC = "10" },
		"custom":             func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.EPDGSource = "custom" },
		"carrier_override":   func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.EPDGSource = "carrier-override" },
		"override_matched":   func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.OverrideMatched = true },
		"redirect":           func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.EPDG = "another.example.invalid" },
		"alternate_cert_name": func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) {
			e.RemoteCertificateHostname = "another.example.invalid"
		},
		"custom_port":                  func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.EPDGPort = 4500 },
		"certificate_disabled":         func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.ValidateRemoteCertificate = false },
		"profile_certificate_disabled": func(_ *engineConfig, e *readerVoWiFiEffectiveConfig) { e.Profile.ValidateRemoteCertificate = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config, effective := threeUKCertificateFixture()
			mutate(&config, effective)
			cfg := readerSWUConfig(config, effective, nil)
			if useThreeUKCertificateProfile(config, effective) || cfg.CertificatePurpose != "" || len(cfg.ResponderIDrAliases) != 0 || len(cfg.CertificateIntermediates) != 0 {
				t.Fatal("certificate profile escaped its exact scope")
			}
		})
	}
	config, _ := threeUKCertificateFixture()
	if useThreeUKCertificateProfile(config, nil) || useThreeUKCertificateProfile(config, &readerVoWiFiEffectiveConfig{}) {
		t.Fatal("missing profile admitted")
	}
}

func TestThreeUKCertificateProfileKeepsNameTrustAndRouting(t *testing.T) {
	config, effective := threeUKCertificateFixture()
	config.Proxy = "127.0.0.1:1080"
	cfg := readerSWUConfig(config, effective, nil)
	if cfg.CertificatePurpose != swu.CertificatePurposeServerAuth || len(cfg.ResponderIDrAliases) != 1 || cfg.ResponderIDrAliases[0] != threeUKResponderIdentity {
		t.Fatal("explicit purpose or identity mapping absent")
	}
	if !cfg.ValidateRemoteCertificate || cfg.RemoteIdentifier != threeUKCertificateHostname || cfg.EpDGAddr != threeUKCertificateHostname || cfg.EpDGPort != 500 || cfg.CertificateRoots != nil || cfg.TransportFactory == nil || cfg.IPStack != "ipv6" {
		t.Fatal("certificate profile changed trust anchors, name, or transport")
	}
	if len(cfg.CertificateIntermediates) != 1 {
		t.Fatal("expected one official untrusted issuer candidate")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(cfg.CertificateIntermediates[0]))
	if digest != "a4adfc2917bb1451d312371d441acdb686107fbc0b3156d5570e99e1121974fa" {
		t.Fatal("unexpected intermediate provenance")
	}
	cfg.CertificateIntermediates[0][0] ^= 1
	cfg.ResponderIDrAliases[0] = "mutated.example.invalid"
	next := readerSWUConfig(config, effective, nil)
	if next.ResponderIDrAliases[0] != threeUKResponderIdentity || fmt.Sprintf("%x", sha256.Sum256(next.CertificateIntermediates[0])) != digest {
		t.Fatal("certificate profile reused mutable policy buffers")
	}
}
