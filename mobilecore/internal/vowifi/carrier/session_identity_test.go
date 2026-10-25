package carrier

import (
	"io/fs"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestSelectorVoWiFiIdentityMetadataAndDomain(t *testing.T) {
	for _, tc := range []struct{ mcc, mnc, iccid, id, rule, domain string }{
		{"204", "04", "8944160001234567890", "apple_lebara_uk", "23487${iccid[9:19]}", "ims.mnc087.mcc234.3gppnetwork.org"},
		{"204", "04", "8963662600123456789", "apple_dito_ph", "capture", "ims.mnc066.mcc515.3gppnetwork.org"},
		{"234", "87", "8944160001234567890", "apple_lebara_uk", "", "ims.mnc087.mcc234.3gppnetwork.org"},
	} {
		p, err := ResolveWithError(SIMIdentity{MCC: tc.mcc, MNC: tc.mnc, ICCID: tc.iccid})
		if err != nil {
			t.Fatal(err)
		}
		if p.ID != tc.id || p.VoWiFiIMSI != tc.rule || p.IMSDomain() != tc.domain {
			t.Fatalf("unexpected selector metadata: %s %q %q", p.ID, p.VoWiFiIMSI, p.IMSDomain())
		}
	}
}

func TestEffectiveVoWiFiIMSIUsesExactReviewedSlice(t *testing.T) {
	p := &Profile{VoWiFiIMSI: "23487${iccid[9:19]}"}
	for _, iccid := range []string{"8944160001234567890", "89441600012345678901"} {
		got, err := p.EffectiveIMSI("204040000000001", iccid)
		if err != nil || got != "234871234567890" {
			t.Fatalf("slice mismatch: %q %v", got, err)
		}
	}
	for _, iccid := range []string{"", "89441600", "894416000123456789", "8944160001234567890F", "894416000123456789012", "894416000123456789x"} {
		if got, err := p.EffectiveIMSI("204040000000001", iccid); err == nil || got != "" {
			t.Fatal("invalid ICCID accepted")
		}
	}
	for _, rule := range []string{"capture", "${imsi}", "23487${iccid[8:18]}"} {
		p.VoWiFiIMSI = rule
		if got, err := p.EffectiveIMSI("204040000000001", "8963662600123456789"); err == nil || got != "" || strings.Contains(err.Error(), "204040000000001") || strings.Contains(err.Error(), "8963662600123456789") {
			t.Fatal("unsupported transform accepted or leaked subscriber data")
		}
	}
	p.VoWiFiIMSI = ""
	if got, err := p.EffectiveIMSI("234870000000001", ""); err != nil || got != "234870000000001" {
		t.Fatal("ordinary SIM changed")
	}
}

func TestIMPIUserExpansionNeedsActualValidatedPrivateIdentity(t *testing.T) {
	p := &Profile{MCC: "262", MNC: "23", LocalIdentifier: "0$impi_user@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org", EAPIdentityTemplate: "0$imsi@nai.epc.mnc$MNC.mcc$MCC.3gppnetwork.org"}
	local, eap, err := p.ExpandSessionIdentities("262230000000001", "actual-user@isim.example")
	if err != nil || local != "0actual-user@nai.epc.mnc023.mcc262.3gppnetwork.org" || eap != "0262230000000001@nai.epc.mnc023.mcc262.3gppnetwork.org" {
		t.Fatalf("identities conflated: %q %q %v", local, eap, err)
	}
	for _, private := range []string{"", "not-an-impi", "@ims.example", "user@", "user@@ims.example", "$imsi@ims.example", "user\r\nInjected@ims.example", "sip:user@ims.example", "user@ims example", "user@-ims.example"} {
		if local, eap, err := p.ExpandSessionIdentities("262230000000001", private); err == nil || local != "" || eap != "" {
			t.Fatalf("invalid IMPI accepted: %q", private)
		}
	}
	if p.ExpandLocalIdentifier("262230000000001") != "" {
		t.Fatal("legacy API emitted unresolved IMPI template")
	}
	p.LocalIdentifier = "0$unknown@ims.example"
	if _, _, err := p.ExpandSessionIdentities("262230000000001", "actual-user@isim.example"); err == nil {
		t.Fatal("unknown variable accepted")
	}
	p.LocalIdentifier = "anonymous@ims.example"
	if local, _, err := p.ExpandSessionIdentities("262230000000001", ""); err != nil || local != "anonymous@ims.example" {
		t.Fatal("anonymous ID incorrectly requires IMPI")
	}
}

func TestEveryPublishedIdentityTemplateExpandsWithoutVariables(t *testing.T) {
	files, err := fs.Glob(embeddedRegistry, "data/selectors/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := embeddedRegistry.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var manifest selectorManifest
		if err := yaml.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		for _, entry := range manifest.Profiles {
			for _, rule := range entry.Selectors {
				p, err := loadBundle(selectedProfile{id: entry.ID, file: entry.Path, raw: rule.Raw, vowifiIMSI: rule.VoWiFiIMSI}, manifest.PLMN)
				if err != nil {
					t.Fatal(err)
				}
				local, eap, err := p.ExpandSessionIdentities("001010000000001", "synthetic-user@ims.example")
				if err != nil || strings.ContainsAny(local+eap, "$\r\n\x00") {
					t.Fatalf("%s / %s invalid template: %v", entry.ID, rule.Raw, err)
				}
				if !ValidIdentityDomain(p.IMSDomain()) {
					t.Fatalf("%s invalid IMS domain", entry.ID)
				}
			}
		}
	}
}
