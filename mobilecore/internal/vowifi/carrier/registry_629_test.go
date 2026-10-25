package carrier

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The upstream generator used to omit these offers when Apple's source omitted
// an authentication-method field. Never substitute a generic offer for them.
func TestPreviouslyOmittedIKEOffersAreUsed(t *testing.T) {
	for _, tc := range []struct{ file, plmn, offer string }{
		{"globe_ph", "51502", "aes256-sha256-prfsha256-modp2048"},
		{"unicom_hk", "45407", "aes256-sha256-prfsha512-modp4096"},
		{"o2_sk", "23106", "aes256-sha384-prfsha256-modp2048"},
		{"elisa_fi", "24405", "aes128-sha512-prfsha512-modp2048"},
		{"free_fr", "20815", "aes256-sha256-prfsha256-modp1024"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			p, err := loadBundle(selectedProfile{id: "apple_" + tc.file, file: "profiles/" + tc.file + ".yaml", raw: tc.plmn}, tc.plmn)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p.TemplateIKEProposals, []string{tc.offer}) {
				t.Fatalf("offer=%v, want %s", p.TemplateIKEProposals, tc.offer)
			}
		})
	}
}

func TestThreeHKAppOwnedTemplateUnchangedFor629(t *testing.T) {
	raw, err := os.ReadFile("data/user_templates/3_hk.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != "bfb6ba70009899a70e64edcadfbded3948595c4a209244ae3efec43f015fec42" {
		t.Fatal("3HK adaptation changed: review known-working behavior before updating this guard")
	}
}

// Release gate against the preserved 628 registry. This intentionally checks
// connection/security settings, not newly published optional media metadata.
func TestWorkingCarrierConnectionPolicyAgainst628(t *testing.T) {
	root := os.Getenv("VOWIFI_CARRIER_BASELINE")
	if root == "" {
		t.Skip("optional previous-release registry audit")
	}
	for _, tc := range []struct{ file, plmn, raw string }{
		{"hutchison_hk", "45403", "45403"},
		{"hutchison_uk", "23420", "23420"},
		{"vodafone_uk", "23415", "23415"},
		{"o2_giffgaff_uk", "23410", "23410_GID1-508FFFFF"},
		{"orange_uk", "23433", "23433"},
		{"tmobile_uk", "23430", "23430"},
		{"cmcc_cmi", "23410", "23410_ID-8985234"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			selection := selectedProfile{id: "apple_" + tc.file, file: "profiles/" + tc.file + ".yaml", raw: tc.raw}
			current, err := loadBundle(selection, tc.plmn)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(root, selection.file))
			if err != nil {
				t.Fatal(err)
			}
			var doc bundleDocument
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			merged := copyMap(doc.Common)
			mergeMap(merged, doc.PLMNOverrides[tc.plmn])
			mergeMap(merged, doc.SelectorOverrides[tc.raw])
			encoded, err := yaml.Marshal(merged)
			if err != nil {
				t.Fatal(err)
			}
			var config bundleConfig
			if err := yaml.Unmarshal(encoded, &config); err != nil {
				t.Fatal(err)
			}
			previous := expandBundle(doc, selection, tc.plmn, config)
			fields := []string{"EPDGCandidates", "IPStack", "TemplateIKEProposals", "TemplateESPProposals", "ValidateRemoteCertificate", "RemoteCertificateHostname", "LocalIdentifier", "EAPIdentityTemplate", "IMSTransport", "UseIPSec", "DisableSwitchToNATTPort", "NATTKeepalive", "DPDInterval", "DisableDPD", "TemplateRekeyPFS"}
			before, after := reflect.ValueOf(*previous), reflect.ValueOf(*current)
			for _, field := range fields {
				if !reflect.DeepEqual(before.FieldByName(field).Interface(), after.FieldByName(field).Interface()) {
					t.Errorf("%s changed: %v => %v", field, before.FieldByName(field), after.FieldByName(field))
				}
			}
		})
	}
}
