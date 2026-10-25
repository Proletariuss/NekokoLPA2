package carrier

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.yaml.in/yaml/v3"
)

func TestEveryPinnedProfileExpandsAllDeclaredProposalAlternatives(t *testing.T) {
	files, err := fs.Glob(embeddedRegistry, "data/profiles/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 676 {
		t.Fatalf("expected 676 profiles, got %d", len(files))
	}
	declared := 0
	for _, file := range files {
		raw, err := embeddedRegistry.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var doc bundleDocument
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, plmn := range doc.SupportedPLMNs {
			p, err := loadBundle(selectedProfile{id: doc.ID, file: strings.TrimPrefix(file, "data/"), raw: plmn}, plmn)
			if err != nil {
				t.Fatalf("%s/%s: %v", file, plmn, err)
			}
			if p.TemplateIKEProposalError != "" || p.TemplateESPProposalError != "" {
				t.Fatalf("%s/%s unsupported initial proposal: %s / %s", file, plmn, p.TemplateIKEProposalError, p.TemplateESPProposalError)
			}
			if len(p.TemplateIKEProposals) > 0 {
				declared++
				if _, err := ikev2.BuildIKEProposals(p.TemplateIKEProposals, nil); err != nil {
					t.Fatalf("%s: %v", file, err)
				}
			}
			if len(p.TemplateESPProposals) > 0 {
				if _, err := ikev2.BuildESPProposals(p.TemplateESPProposals, []byte{1, 2, 3, 4}); err != nil {
					t.Fatalf("%s: %v", file, err)
				}
			}
		}
	}
	if declared == 0 {
		t.Fatal("no carrier proposals checked")
	}
	t.Logf("expanded all %d profiles; %d PLMN expansions declared IKE proposals", len(files), declared)
}

func TestCompleteTemplateAlternativesMetadataAndUnsupportedPolicy(t *testing.T) {
	var c bundleConfig
	if err := yaml.Unmarshal([]byte(`
ims:
  epdg:
    address: primary.example
    remote_certificate_hostname: certificate.example
    candidates:
      - address: second.example
      - address: primary.example
      - address: third.example
  ike:
    validate_remote_certificate: true
    proposals:
      - encryption: [aes256, aes128]
        integrity: [sha512, sha256]
        prf: [sha512, sha256]
        dh_groups: [14, 21]
        lifetime_seconds: 7200
      - encryption: [aes128gcm16]
        prf: [sha256]
        dh_groups: [15]
        lifetime_seconds: 3600
    child_sa:
      lifetime_seconds: 1800
      proposals:
        - encryption: [aes256, aes128]
          integrity: [sha256, sha1]
          rekey_pfs_group: 14
          esn: auto
`), &c); err != nil {
		t.Fatal(err)
	}
	p := expandBundle(bundleDocument{ID: "fixture"}, selectedProfile{}, "23420", c)
	if len(p.EPDGCandidates) != 3 || p.EPDGCandidates[0] != "primary.example" || p.EPDGCandidates[1] != "second.example" || p.EPDGCandidates[2] != "third.example" {
		t.Fatalf("candidates lost: %v", p.EPDGCandidates)
	}
	if p.RemoteCertificateHostname != "certificate.example" || !p.ValidateRemoteCertificate {
		t.Fatal("certificate policy lost")
	}
	if len(p.TemplateIKEProposals) != 2 || p.TemplateIKEProposals[0] != "aes256-aes128-sha512-sha256-prfsha512-prfsha256-modp2048-ecp521" || p.TemplateIKEProposals[1] != "aes128gcm16-prfsha256-modp3072" {
		t.Fatalf("proposal order lost: %v", p.TemplateIKEProposals)
	}
	if p.TemplateIKELifetime != 3600 || p.TemplateChildLifetime != 1800 || p.TemplateRekeyPFS != 14 {
		t.Fatal("explicit lifetime/PFS lost")
	}
	c.IMS.IKE.Proposals[0].Encryption = []string{"futurecipher"}
	bad := expandBundle(bundleDocument{ID: "fixture"}, selectedProfile{}, "23420", c)
	if bad.TemplateIKEProposalError == "" {
		t.Fatal("unrepresentable algorithm silently ignored")
	}
	standard := standardProfile("999", "99")
	if standard.TemplateIKELifetime != 0 || standard.TemplateChildLifetime != 0 || standard.TemplateRekeyPFS != 0 {
		t.Fatal("diagnostic defaults misrepresented as explicit policy")
	}
}

func TestNewDitoAndLebaraProfilesExposeCompleteInitialSuites(t *testing.T) {
	for _, tc := range []struct{ mcc, mnc, id string }{
		{"515", "66", "apple_dito_ph"}, {"234", "87", "apple_lebara_uk"},
	} {
		p, err := ResolveWithError(SIMIdentity{MCC: tc.mcc, MNC: tc.mnc})
		if err != nil {
			t.Fatal(err)
		}
		if p.ID != tc.id || len(p.TemplateIKEProposals) == 0 || len(p.TemplateESPProposals) == 0 || p.TemplateIKEProposalError != "" || p.TemplateESPProposalError != "" {
			t.Fatalf("new carrier initial proposals unavailable: %+v", p)
		}
		if epdg, _ := p.ResolveEPDG("custom.example"); epdg != "custom.example" {
			t.Fatal("new carrier ignored custom ePDG")
		}
	}
}
