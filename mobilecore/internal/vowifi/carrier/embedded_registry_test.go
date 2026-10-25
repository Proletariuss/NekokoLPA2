package carrier

import (
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestEmbeddedRegistryComplete(t *testing.T) {
	selectors, profiles := embeddedCounts()
	if selectors != 853 || profiles != 676 {
		t.Fatalf("registry=%d selectors %d profiles", selectors, profiles)
	}
}

func TestEmbeddedGiffgaffExpansion(t *testing.T) {
	p, err := ResolveWithError(SIMIdentity{MCC: "234", MNC: "10", GID1: "508FFFFF00"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "apple_o2_giffgaff_uk" || p.Bundle != "O2_Giffgaff_UK.bundle" || p.RegistryRevision != EmbeddedRegistryRevision {
		t.Fatalf("profile=%+v", p)
	}
	if p.IPStack != "ipv6" || p.IKEEncryption != "aes256" || p.IKEIntegrity != "sha512" || p.DPDInterval != 600 || !p.DisableDPD {
		t.Fatalf("parameters=%+v", p)
	}
	for _, want := range []string{"+g.3gpp.mid-call", "+g.3gpp.srvcc-alerting", "+g.3gpp.ps2cs-srvcc-orig-pre-alerting"} {
		if !hasString(p.RegisterContactParams, want) {
			t.Fatalf("params=%v", p.RegisterContactParams)
		}
	}
}

func TestEmbeddedGenericFallback(t *testing.T) {
	p, err := ResolveWithError(SIMIdentity{MCC: "234", MNC: "10"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "apple_o2_uk" {
		t.Fatalf("id=%s", p.ID)
	}
}

func TestThreeHKUserTemplateOnlyAppliesToGeneric45403(t *testing.T) {
	profile, err := ResolveWithError(SIMIdentity{MCC: "454", MNC: "03"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.ID != "apple_hutchison_hk" || profile.Source != "user-template" || profile.VoWiFiTemplate == nil {
		t.Fatalf("3HK template was not selected after generic Apple selector: %+v", profile)
	}
	if profile.VoWiFiTemplate.IMS.InitialAuthorization != "eap_direct" || !profile.VoWiFiTemplate.IMS.AllowPlainIMSTransport || profile.VoWiFiTemplate.IKE.RekeyPFS != 14 {
		t.Fatalf("3HK adapted behavior is incomplete: %+v", profile.VoWiFiTemplate)
	}
	for _, sim := range []SIMIdentity{{MCC: "454", MNC: "04"}, {MCC: "454", MNC: "03", GID1: "0009"}} {
		got, err := ResolveWithError(sim)
		if err != nil {
			t.Fatal(err)
		}
		if got.VoWiFiTemplate != nil {
			t.Fatalf("3HK generic template leaked to a different/specific selector: %+v", got)
		}
	}
}

func TestEmbeddedCTExcelAndGiffgaffPublishStandardEPDGAddress(t *testing.T) {
	for _, test := range []struct {
		name string
		sim  SIMIdentity
		want string
	}{
		{
			name: "CTExcel",
			sim:  SIMIdentity{MCC: "234", MNC: "33"},
			want: "epdg.epc.mnc033.mcc234.pub.3gppnetwork.org",
		},
		{
			name: "giffgaff",
			sim:  SIMIdentity{MCC: "234", MNC: "10", GID1: "508FFFFF00"},
			want: "epdg.epc.mnc010.mcc234.pub.3gppnetwork.org",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile, err := ResolveWithError(test.sim)
			if err != nil {
				t.Fatal(err)
			}
			got, source := profile.ResolveEPDG("")
			if got != test.want || source != "carrier-template" {
				t.Fatalf("ResolveEPDG = (%q, %q), want (%q, %q)", got, source, test.want, "carrier-template")
			}
		})
	}
}

func TestEmbeddedTemplateMetadataRejectsRequiredESPESN(t *testing.T) {
	var config bundleConfig
	if err := yaml.Unmarshal([]byte(`
ims:
  ike:
    proposals:
      - encryption: [aes128]
        integrity: [sha256]
        prf: [sha256]
        dh_groups: [14]
    child_sa:
      proposals:
        - encryption: [aes128]
          integrity: [sha256]
          esn: required
`), &config); err != nil {
		t.Fatal(err)
	}
	profile := expandBundle(
		bundleDocument{ID: "fixture", Bundle: "Fixture.bundle"},
		selectedProfile{id: "fixture"}, "23433", config,
	)
	if !profile.TemplateIKEProposalExact {
		t.Fatal("fixture IKE proposal should be exact")
	}
	if profile.TemplateESPProposalExact {
		t.Fatal("required ESN was incorrectly marked as an exact ESP template")
	}
	for _, value := range []string{"required", "esn", "future-value"} {
		if templateESPESNCompatible(value) {
			t.Fatalf("%q was incorrectly accepted as no-ESN compatible", value)
		}
	}
	for _, value := range []string{"", "auto", "noesn"} {
		if !templateESPESNCompatible(value) {
			t.Fatalf("%q should be compatible with the current no-ESN runtime", value)
		}
	}
}

func TestExpandBundleEPDGPrecedenceMatchesNativeParser(t *testing.T) {
	tests := []struct {
		name   string
		yaml   string
		custom string
		want   string
		source string
	}{
		{
			name: "direct address wins over candidates and legacy hostname",
			yaml: `ims:
  epdg:
    address: direct.epdg.example
    candidates:
      - address: first.candidate.example
      - address: second.candidate.example
    remote_certificate_hostname: legacy.epdg.example
`,
			want:   "direct.epdg.example",
			source: "carrier-template",
		},
		{
			name: "first candidate wins over legacy hostname",
			yaml: `ims:
  epdg:
    candidates:
      - address: first.candidate.example
      - address: second.candidate.example
    remote_certificate_hostname: legacy.epdg.example
`,
			want:   "first.candidate.example",
			source: "carrier-template",
		},
		{
			name: "legacy remote certificate hostname",
			yaml: `ims:
  epdg:
    remote_certificate_hostname: legacy.epdg.example
`,
			want:   "legacy.epdg.example",
			source: "carrier-template",
		},
		{
			name: "custom value wins over every carrier form",
			yaml: `ims:
  epdg:
    address: direct.epdg.example
    candidates:
      - address: first.candidate.example
    remote_certificate_hostname: legacy.epdg.example
`,
			custom: "custom.epdg.example",
			want:   "custom.epdg.example",
			source: "custom",
		},
		{
			name: "verizon style nonstandard hostname remains valid",
			yaml: `ims:
  epdg:
    remote_certificate_hostname: wo.vzwwo.com
`,
			want:   "wo.vzwwo.com",
			source: "carrier-template",
		},
		{
			name:   "standard FQDN is final fallback",
			yaml:   "ims: {}\n",
			want:   "epdg.epc.mnc033.mcc234.pub.3gppnetwork.org",
			source: "3gpp-standard",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config bundleConfig
			if err := yaml.Unmarshal([]byte(test.yaml), &config); err != nil {
				t.Fatal(err)
			}
			profile := expandBundle(
				bundleDocument{ID: "fixture", Bundle: "Fixture.bundle"},
				selectedProfile{id: "fixture"}, "23433", config,
			)
			got, source := profile.ResolveEPDG(test.custom)
			if got != test.want || source != test.source {
				t.Fatalf("ResolveEPDG(%q) = (%q, %q), want (%q, %q)", test.custom, got, source, test.want, test.source)
			}
		})
	}
}
