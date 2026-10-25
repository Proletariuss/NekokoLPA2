package swu

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

const policyTestAlias = "epdg.private.example.test"

func newCertificatePolicyFixture(t *testing.T, leafUsage, issuerUsage string, mutateLeaf, mutateIssuer func(*x509.Certificate)) (peerFixture, []byte, []byte) {
	t.Helper()
	f := newPeerFixture(t, nil)
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	rootKey, issuerKey := newKey(), newKey()
	issue := func(template, parent *x509.Certificate, public *ecdsa.PublicKey, key *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	setPurpose := func(c *x509.Certificate, usage string) {
		switch usage {
		case CertificatePurposeIKE:
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 17}}
		case CertificatePurposeServerAuth:
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "client_auth":
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case "any":
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "Policy Test Root"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "Policy Test Issuer"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
	setPurpose(issuerTemplate, issuerUsage)
	if mutateIssuer != nil {
		mutateIssuer(issuerTemplate)
	}
	issuer := issue(issuerTemplate, root, &issuerKey.PublicKey, rootKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(103), Subject: pkix.Name{CommonName: "epdg.example.test"}, DNSNames: []string{"epdg.example.test"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	setPurpose(leafTemplate, leafUsage)
	if mutateLeaf != nil {
		mutateLeaf(leafTemplate)
	}
	leaf := issue(leafTemplate, issuer, &f.key.PublicKey, issuerKey)
	f.certs = []*ikev2.EncryptedPayloadCert{{Encoding: 4, Data: leaf.Raw}}
	f.id.IDData = []byte(policyTestAlias)
	f.s.responderIdentityBody, _ = f.id.Encode()
	f.s.cfg.CertificateRoots = x509.NewCertPool()
	f.s.cfg.CertificateRoots.AddCert(root)
	f.s.cfg.CertificatePurpose = CertificatePurposeServerAuth
	f.s.cfg.ResponderIDrAliases = []string{policyTestAlias}
	f.s.cfg.CertificateIntermediates = [][]byte{issuer.Raw}
	return f, issuer.Raw, root.Raw
}

func TestCertificatePolicyExplicitServerAuthAndAliases(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(*peerFixture, []byte, []byte)
	}{
		{"explicit", "", nil},
		{"case_equal_alias", "", func(f *peerFixture, _, _ []byte) {
			f.s.cfg.ResponderIDrAliases = []string{strings.ToUpper(policyTestAlias)}
		}},
		{"default_strict", "certificate_eku", func(f *peerFixture, _, _ []byte) { f.s.cfg.CertificatePurpose = "" }},
		{"explicit_ike", "certificate_eku", func(f *peerFixture, _, _ []byte) { f.s.cfg.CertificatePurpose = CertificatePurposeIKE }},
		{"invalid_purpose", "certificate_expected_identity_invalid", func(f *peerFixture, _, _ []byte) { f.s.cfg.CertificatePurpose = "server_auth_or_ike" }},
		{"without_alias", "certificate_idr_mismatch", func(f *peerFixture, _, _ []byte) { f.s.cfg.ResponderIDrAliases = nil }},
		{"wrong_alias", "certificate_idr_mismatch", func(f *peerFixture, _, _ []byte) { f.s.cfg.ResponderIDrAliases = []string{"other.example.test"} }},
		{"wildcard_alias", "certificate_expected_identity_invalid", func(f *peerFixture, _, _ []byte) { f.s.cfg.ResponderIDrAliases = []string{"*.example.test"} }},
		{"whitespace_alias", "certificate_expected_identity_invalid", func(f *peerFixture, _, _ []byte) { f.s.cfg.ResponderIDrAliases = []string{policyTestAlias + " "} }},
		{"hostname_independent", "certificate_hostname_mismatch", func(f *peerFixture, _, _ []byte) { f.s.cfg.RemoteIdentifier = "wrong.example.test" }},
		{"issuer_missing", "certificate_chain_untrusted", func(f *peerFixture, _, _ []byte) { f.s.cfg.CertificateIntermediates = nil }},
		{"unknown_root", "certificate_chain_untrusted", func(f *peerFixture, _, _ []byte) { f.s.cfg.CertificateRoots = x509.NewCertPool() }},
		{"local_root_not_anchor", "certificate_chain_untrusted", func(f *peerFixture, _, root []byte) {
			f.s.cfg.CertificateRoots = x509.NewCertPool()
			f.s.cfg.CertificateIntermediates = append(f.s.cfg.CertificateIntermediates, root)
		}},
		{"invalid_local_der", "certificate_parse", func(f *peerFixture, _, _ []byte) {
			f.s.cfg.CertificateIntermediates = [][]byte{[]byte("invalid public CA")}
		}},
		{"leaf_as_local_ca", "certificate_ca_constraints", func(f *peerFixture, _, _ []byte) { f.s.cfg.CertificateIntermediates = [][]byte{f.certs[0].Data} }},
		{"forged_intermediate", "certificate_chain_untrusted", func(f *peerFixture, issuer, _ []byte) {
			forged := append([]byte(nil), issuer...)
			forged[len(forged)-1] ^= 1
			f.s.cfg.CertificateIntermediates = [][]byte{forged}
		}},
		{"wrong_same_subject_key", "certificate_chain_untrusted", func(f *peerFixture, _, _ []byte) {
			_, otherIssuer, _ := newCertificatePolicyFixture(t, CertificatePurposeServerAuth, CertificatePurposeServerAuth, nil, nil)
			f.s.cfg.CertificateIntermediates = [][]byte{otherIssuer}
		}},
		{"unrelated_local_ignored", "", func(f *peerFixture, _, _ []byte) {
			other := newPeerFixture(t, nil)
			f.s.cfg.CertificateIntermediates = append(f.s.cfg.CertificateIntermediates, other.certs[1].Data)
		}},
		{"unrelated_peer_rejected", "certificate_chain_extraneous", func(f *peerFixture, _, _ []byte) {
			other := newPeerFixture(t, nil)
			f.certs = append(f.certs, other.certs[1])
		}},
		{"alias_only_fqdn", "certificate_idr_mismatch", func(f *peerFixture, _, _ []byte) {
			f.id.IDType = ikev2.ID_RFC822_ADDR
			f.s.responderIdentityBody, _ = f.id.Encode()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, issuer, root := newCertificatePolicyFixture(t, CertificatePurposeServerAuth, CertificatePurposeServerAuth, nil, nil)
			if tc.mutate != nil {
				tc.mutate(&f, issuer, root)
			}
			err := f.s.checkResponderInitial(f.initial(t))
			if tc.want == "" {
				if err != nil || !f.s.responderCertificateVerified {
					t.Fatalf("explicit policy rejected: %v", err)
				}
			} else {
				reason, _, _, _ := certificateDiagnostic(err)
				if !errors.Is(err, ErrPeerAuthentication) || AuthFailureCode(err) != AuthFailureCertificate || reason != tc.want || f.s.responderCertificateVerified {
					t.Fatalf("policy rejection: %v reason=%q want=%q", err, reason, tc.want)
				}
			}
		})
	}
}

func TestCertificatePolicyOnePurposeAcrossWholeChain(t *testing.T) {
	for _, tc := range []struct {
		purpose, leaf, issuer string
		valid                 bool
	}{
		{CertificatePurposeServerAuth, CertificatePurposeServerAuth, CertificatePurposeServerAuth, true},
		{CertificatePurposeServerAuth, CertificatePurposeServerAuth, "any", true},
		{CertificatePurposeServerAuth, CertificatePurposeServerAuth, "", true},
		{CertificatePurposeServerAuth, CertificatePurposeServerAuth, CertificatePurposeIKE, false},
		{CertificatePurposeServerAuth, CertificatePurposeServerAuth, "client_auth", false},
		{CertificatePurposeServerAuth, CertificatePurposeIKE, CertificatePurposeServerAuth, false},
		{CertificatePurposeServerAuth, "client_auth", CertificatePurposeServerAuth, false},
		{CertificatePurposeIKE, CertificatePurposeIKE, CertificatePurposeIKE, true},
		{CertificatePurposeIKE, CertificatePurposeIKE, CertificatePurposeServerAuth, false},
		{CertificatePurposeIKE, CertificatePurposeServerAuth, CertificatePurposeIKE, false},
		{"", CertificatePurposeServerAuth, CertificatePurposeServerAuth, false},
	} {
		t.Run(tc.purpose+"_"+tc.leaf+"_"+tc.issuer, func(t *testing.T) {
			f, _, _ := newCertificatePolicyFixture(t, tc.leaf, tc.issuer, nil, nil)
			f.s.cfg.CertificatePurpose = tc.purpose
			err := f.s.checkResponderInitial(f.initial(t))
			if (err == nil) != tc.valid {
				t.Fatalf("mixed-purpose acceptance: %v", err)
			}
			if err != nil {
				reason, _, _, _ := certificateDiagnostic(err)
				if reason != "certificate_eku" {
					t.Fatalf("wrong purpose classification: %q", reason)
				}
			}
		})
	}
}

func TestCertificatePolicyPreservesValidityAUTHAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, want   string
		leaf, issuer func(*x509.Certificate)
	}{
		{"expired_leaf", "certificate_expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, nil},
		{"future_leaf", "certificate_not_yet_valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }, nil},
		{"expired_local", "certificate_expired", nil, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"critical_local", "certificate_critical_extension", nil, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _ := newCertificatePolicyFixture(t, CertificatePurposeServerAuth, CertificatePurposeServerAuth, tc.leaf, tc.issuer)
			err := f.s.checkResponderInitial(f.initial(t))
			reason, _, _, _ := certificateDiagnostic(err)
			if reason != tc.want || !errors.Is(err, ErrPeerAuthentication) {
				t.Fatalf("validity/constraints bypass: %q %v", reason, err)
			}
		})
	}
	for _, mode := range []string{"signature", "changed_signed_alias", "final_msk", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _ := newCertificatePolicyFixture(t, CertificatePurposeServerAuth, CertificatePurposeServerAuth, nil, nil)
			payloads := f.initial(t)
			switch mode {
			case "signature":
				payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[3] ^= 1
			case "changed_signed_alias":
				f.s.cfg.ResponderIDrAliases = append(f.s.cfg.ResponderIDrAliases, "other.example.test")
				f.id.IDData = []byte("other.example.test")
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				f.s.ctx = ctx
			}
			err := f.s.checkResponderInitial(payloads)
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				return
			}
			if mode == "final_msk" {
				if err != nil {
					t.Fatal(err)
				}
				f.s.eapSuccessReceived = true
				f.s.MSK = bytes.Repeat([]byte{0x31}, 64)
				final := finalPeerAUTH(t, f.s)
				f.s.MSK[0] ^= 1
				err = f.s.verifyResponderFinal([]ikev2.Payload{final})
				if AuthFailureCode(err) != AuthFailureFinalAUTH {
					t.Fatalf("MSK bypass: %v", err)
				}
			} else if AuthFailureCode(err) != AuthFailureSignature {
				t.Fatalf("signed IDr/AUTH bypass: %v", err)
			}
		})
	}
}

func TestThreeUKIntermediatePinnedPublicIssuerAndCopies(t *testing.T) {
	first := ThreeUKCertificateIntermediates()
	if len(first) != 1 {
		t.Fatal("missing pinned public issuer")
	}
	digest := sha256.Sum256(first[0])
	if hex.EncodeToString(digest[:]) != "a4adfc2917bb1451d312371d441acdb686107fbc0b3156d5570e99e1121974fa" {
		t.Fatal("public issuer hash changed")
	}
	cert, err := x509.ParseCertificate(first[0])
	if err != nil || !cert.IsCA {
		t.Fatal("invalid public issuer")
	}
	first[0][0] ^= 1
	second := ThreeUKCertificateIntermediates()
	if len(second) != 1 || bytes.Equal(first[0], second[0]) {
		t.Fatal("issuer copies share mutable state")
	}
}

func TestCertificatePolicyConfigRejectsInvalidValuesBeforeTransport(t *testing.T) {
	for _, cfg := range []*Config{
		{CertificatePurpose: "IKE"},
		{CertificatePurpose: "server_auth ", ResponderIDrAliases: []string{policyTestAlias}},
		{ResponderIDrAliases: []string{"*.example.test"}},
		{ResponderIDrAliases: []string{"invalid\x00.example.test"}},
		{CertificateIntermediates: make([][]byte, 9)},
	} {
		if err := cfg.validate(); err == nil {
			t.Fatal("invalid certificate policy accepted")
		}
	}
}
