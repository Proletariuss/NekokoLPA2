//go:build darwin && cgo

package swu

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// This is an offline certificate-only test using the public leaf observed on
// 2026-10-24. No transport, EAP, SIM, or operator account is used. Root trust is
// obtained from Security.framework, never from this fixture or local issuer.
func TestThreeUKPublicCertificateOfflineExplicitPolicy(t *testing.T) {
	raw, err := os.ReadFile("testdata/threeuk-public-leaf-20261024.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("missing public leaf")
	}
	if certificateFingerprint(block.Bytes) != "8081bb70fde75cd2dff4852d5c5e7bb8ca375a4d6036314cba472af966a9b423" {
		t.Fatal("public leaf changed")
	}
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	const expected = "epdg.epc.mnc020.mcc234.pub.3gppnetwork.org"
	const alias = "epdg.epc.mnc020.mcc234.3gppnetwork.org"
	for _, mode := range []string{"explicit", "strict_default", "without_alias", "wrong_alias", "wrong_hostname", "unknown_root", "expired"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &Config{EpDGAddr: expected, RemoteIdentifier: expected, CertificatePurpose: CertificatePurposeServerAuth, ResponderIDrAliases: []string{alias}, CertificateIntermediates: ThreeUKCertificateIntermediates()}
			when := now
			want := ""
			switch mode {
			case "strict_default":
				cfg.CertificatePurpose = ""
				want = "certificate_eku"
			case "without_alias":
				cfg.ResponderIDrAliases = nil
				want = "certificate_idr_mismatch"
			case "wrong_alias":
				cfg.ResponderIDrAliases = []string{"other.example.test"}
				want = "certificate_idr_mismatch"
			case "wrong_hostname":
				cfg.RemoteIdentifier = "other.example.test"
				want = "certificate_hostname_mismatch"
			case "unknown_root":
				cfg.CertificateRoots = x509.NewCertPool()
				want = "certificate_chain_untrusted"
			case "expired":
				when = time.Date(2027, 2, 15, 0, 0, 0, 0, time.UTC)
				want = "certificate_expired"
			}
			s := &Session{cfg: cfg}
			leaf, err := s.verifyResponderCertificate([]*ikev2.EncryptedPayloadCert{{Encoding: 4, Data: block.Bytes}}, &ikev2.EncryptedPayloadID{IDType: ikev2.ID_FQDN, IDData: []byte(alias)}, when)
			if want == "" {
				if err != nil || leaf == nil {
					t.Fatalf("offline public chain rejected: %v", err)
				}
				if cfg.CertificateRoots != nil {
					t.Fatal("system anchors were replaced")
				}
				t.Log("public leaf + official intermediate verified by unmodified Apple system anchors; expected public SAN and explicit IDr alias checked")
			} else {
				reason, _, _, _ := certificateDiagnostic(err)
				if err == nil || reason != want {
					t.Fatalf("negative control: got %q %v want=%q", reason, err, want)
				}
			}
		})
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	locals, err := localCertificateIntermediates(ThreeUKCertificateIntermediates(), []*x509.Certificate{leaf}, now)
	if err != nil || len(locals) != 1 {
		t.Fatalf("public issuer linkage: %v", err)
	}
	if err := verifySystemPeerCertificates([]*x509.Certificate{leaf}, locals, "wrong.example.test", now, CertificatePurposeServerAuth); err == nil {
		t.Fatal("native helper bypassed independent configured-name check")
	}
	if err := verifySystemIKECertificates([]*x509.Certificate{leaf}, expected, now); err == nil {
		t.Fatal("legacy system verifier stopped enforcing strict IKE purpose")
	}
}
