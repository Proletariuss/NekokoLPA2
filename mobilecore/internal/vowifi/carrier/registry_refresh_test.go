package carrier

import (
	"io/fs"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestEveryPublishedSelectorReferencesExpandableBundle(t *testing.T) {
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
			t.Fatalf("%s: %v", file, err)
		}
		for _, entry := range manifest.Profiles {
			for _, rule := range entry.Selectors {
				p, err := loadBundle(selectedProfile{id: entry.ID, file: entry.Path, raw: rule.Raw, vowifiIMSI: rule.VoWiFiIMSI}, manifest.PLMN)
				if err != nil {
					t.Fatalf("%s / %s: %v", file, rule.Raw, err)
				}
				if p.RegistryRevision != EmbeddedRegistryRevision || p.EPDG() == "" {
					t.Fatalf("incomplete expansion: %s / %s", file, rule.Raw)
				}
			}
		}
	}
}

func TestUKCarrierSelectorsDoNotInferBrandFromSPN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sim     SIMIdentity
		id, raw string
	}{
		{"Orange home PLMN", SIMIdentity{MCC: "234", MNC: "33", SPN: "CTExcel"}, "apple_orange_uk", "23433"},
		{"Vodafone generic", SIMIdentity{MCC: "234", MNC: "15"}, "apple_vodafone_uk", "23415"},
		{"Talkmobile specific", SIMIdentity{MCC: "234", MNC: "15", GID1: "C100"}, "apple_talkmobile_uk", "23415_GID1-C1"},
		{"Three generic", SIMIdentity{MCC: "234", MNC: "20"}, "apple_hutchison_uk", "23420"},
		{"Three iD specific", SIMIdentity{MCC: "234", MNC: "20", GID1: "030500"}, "apple_hutchison_id_uk", "23420_GID1-0305"},
		{"giffgaff complete GID", SIMIdentity{MCC: "234", MNC: "10", GID1: "508fffff00"}, "apple_o2_giffgaff_uk", "23410_GID1-508FFFFF"},
		{"giffgaff SPN insufficient", SIMIdentity{MCC: "234", MNC: "10", SPN: "giffgaff"}, "apple_o2_uk", "23410"},
		{"CMLink SPN on EE does not invent profile", SIMIdentity{MCC: "234", MNC: "30", SPN: "CMLink"}, "apple_tmobile_uk", "23430"},
		{"CMI requires published ICCID prefix", SIMIdentity{MCC: "234", MNC: "10", ICCID: "8985234000000000000"}, "apple_cmcc_cmi", "23410_ID-8985234"},
		{"unknown loop SPN does not invent profile", SIMIdentity{MCC: "234", MNC: "10", SPN: "loop"}, "apple_o2_uk", "23410"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ResolveWithError(tc.sim)
			if err != nil {
				t.Fatal(err)
			}
			if p.ID != tc.id || p.SelectorRaw != tc.raw {
				t.Fatalf("profile=%s selector=%s, want %s / %s", p.ID, p.SelectorRaw, tc.id, tc.raw)
			}
		})
	}
}

func TestThreeUKCertificateProposalAndIdentityArePreserved(t *testing.T) {
	p, err := ResolveWithError(SIMIdentity{MCC: "234", MNC: "20"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.TemplateIKEProposalExact || !p.TemplateESPProposalExact || p.IKEEncryption != "aes256" || p.IKEIntegrity != "sha256" || p.IKEPRF != "sha256" || p.IKEDHGroup != 14 || p.ChildEncryption != "aes128" {
		t.Fatalf("3UK proposal lost: %+v", p)
	}
	if !p.ValidateRemoteCertificate || p.IMSTransport != "tcp" {
		t.Fatalf("3UK certificate or transport metadata lost: %+v", p)
	}
	if p.RemoteCertificateHostname != "epdg.epc.mnc020.mcc234.pub.3gppnetwork.org" {
		t.Fatalf("3UK IKE certificate hostname lost: %q", p.RemoteCertificateHostname)
	}
	if got := p.ExpandLocalIdentifier("234201234567890"); got != "anonymous@nai.epc.mnc020.mcc234.3gppnetwork.org" {
		t.Fatalf("IKE identity = %q", got)
	}
	if got := p.ExpandEAPIdentity("234201234567890"); got != "0234201234567890@nai.epc.mnc020.mcc234.3gppnetwork.org" {
		t.Fatalf("EAP identity = %q", got)
	}
}

func TestSelectorTieFailsAndGenericRetainsOverrideKey(t *testing.T) {
	var manifest selectorManifest
	err := yaml.Unmarshal([]byte(`plmn: "23410"
profiles:
  - id: one
    path: profiles/one.yaml
    generic: true
    selectors:
      - raw: "23410"
      - raw: first
        conditions: [{field: gid1, match: prefix, value: "50"}]
  - id: two
    path: profiles/two.yaml
    selectors:
      - raw: second
        conditions: [{field: gid1, match: prefix, value: "50"}]
`), &manifest)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := selectProfile(manifest, SIMIdentity{GID1: "508FFFFF"}); err == nil || p != nil {
		t.Fatalf("ambiguous selector chosen: %+v, %v", p, err)
	}
	p, err := selectProfile(manifest, SIMIdentity{})
	if err != nil || p == nil || p.raw != "23410" {
		t.Fatalf("generic selector lost override key: %+v, %v", p, err)
	}
}
