package swu

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestCertificateDiagnosticRejectedPeerCases(t *testing.T) {
	cases := []struct {
		name, reason string
		mutateCert   func(*x509.Certificate)
		mutate       func(*peerFixture)
	}{
		{name: "missing", reason: "certificate_missing", mutate: func(f *peerFixture) { f.certs = nil }},
		{name: "limit", reason: "certificate_chain_limit", mutate: func(f *peerFixture) {
			for len(f.certs) < 9 {
				f.certs = append(f.certs, f.certs[0])
			}
		}},
		{name: "encoding", reason: "certificate_encoding", mutate: func(f *peerFixture) { f.certs[0].Encoding = 12 }},
		{name: "parse", reason: "certificate_parse", mutate: func(f *peerFixture) { f.certs[0].Data = []byte("SECRET-DN-SAN-AIA-IMSI") }},
		{name: "duplicate", reason: "certificate_duplicate", mutate: func(f *peerFixture) { f.certs = append(f.certs, f.certs[0]) }},
		{name: "expired", reason: "certificate_expired", mutateCert: func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{name: "future", reason: "certificate_not_yet_valid", mutateCert: func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{name: "critical", reason: "certificate_critical_extension", mutateCert: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
		{name: "key_usage", reason: "certificate_key_usage", mutateCert: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
		{name: "eku", reason: "certificate_eku", mutateCert: func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = nil
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}},
		{name: "hostname", reason: "certificate_hostname_mismatch", mutate: func(f *peerFixture) { f.s.cfg.RemoteIdentifier = "SECRET-DN-SAN-AIA-IMSI.invalid" }},
		{name: "idr_fqdn", reason: "certificate_idr_mismatch", mutate: func(f *peerFixture) { f.id.IDData = []byte("SECRET-DN-SAN-AIA-IMSI.invalid") }},
		{name: "idr_dn", reason: "certificate_idr_mismatch", mutate: func(f *peerFixture) {
			f.id.IDType = ikev2.ID_DER_ASN1_DN
			f.id.IDData = []byte("SECRET-DN-SAN-AIA-IMSI")
		}},
		{name: "idr_email", reason: "certificate_idr_mismatch", mutate: func(f *peerFixture) {
			f.id.IDType = ikev2.ID_RFC822_ADDR
			f.id.IDData = []byte("SECRET-DN-SAN-AIA-IMSI@example.invalid")
		}},
		{name: "idr_ip", reason: "certificate_idr_mismatch", mutate: func(f *peerFixture) { f.id.IDType = ikev2.ID_IPV4_ADDR; f.id.IDData = []byte{192, 0, 2, 1} }},
		{name: "idr_length", reason: "certificate_idr_invalid", mutate: func(f *peerFixture) { f.id.IDType = ikev2.ID_IPV6_ADDR; f.id.IDData = []byte{1} }},
		{name: "idr_type", reason: "certificate_idr_invalid", mutate: func(f *peerFixture) { f.id.IDType = 255 }},
		{name: "expected_identity", reason: "certificate_expected_identity_invalid", mutate: func(f *peerFixture) { f.s.cfg.RemoteIdentifier = "*.invalid" }},
		{name: "ca_leaf", reason: "certificate_ca_constraints", mutateCert: func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true }},
		{name: "ca_intermediate", reason: "certificate_ca_constraints", mutate: func(f *peerFixture) { other := newPeerFixture(t, nil); f.certs = append(f.certs, other.certs[0]) }},
		{name: "untrusted", reason: "certificate_chain_untrusted", mutate: func(f *peerFixture) { f.s.cfg.CertificateRoots = x509.NewCertPool() }},
		{name: "extraneous", reason: "certificate_chain_extraneous", mutate: func(f *peerFixture) { other := newPeerFixture(t, nil); f.certs = append(f.certs, other.certs[1]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPeerFixture(t, tc.mutateCert)
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			var diagnostics []AuthDiagnostic
			f.s.cfg.OnAuthDiagnostic = func(d AuthDiagnostic) { diagnostics = append(diagnostics, d) }
			_, err := f.s.processAuthEAPResponse(1, f.initial(t))
			if !errors.Is(err, ErrPeerAuthentication) || AuthFailureCode(err) != AuthFailureCertificate || f.s.responderInitialChecked || f.s.responderCertificateVerified {
				t.Fatalf("failure contract changed: %v", err)
			}
			if len(diagnostics) != 1 || diagnostics[0].CertificateFailure != tc.reason || diagnostics[0].PeerAuthenticated {
				t.Fatalf("certificate classification: %+v", diagnostics)
			}
			d := diagnostics[0]
			if d.CertificateTrustStage != 0 || d.CertificateTrustCode != 0 {
				t.Fatalf("non-platform failure has native fields: %+v", d)
			}
			wantFingerprint := tc.reason != "certificate_missing" && tc.reason != "certificate_chain_limit" && tc.reason != "certificate_encoding" && tc.reason != "certificate_parse"
			if wantFingerprint {
				want := sha256.Sum256(f.certs[0].Data)
				if d.CertificateLeafSHA256 != hex.EncodeToString(want[:]) {
					t.Fatal("fingerprint is not the public leaf DER digest")
				}
			} else if d.CertificateLeafSHA256 != "" {
				t.Fatal("fingerprint emitted before parsing a public leaf certificate")
			}
			wire, marshalErr := json.Marshal(d)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if strings.Contains(string(wire), "SECRET") || strings.Contains(err.Error(), "SECRET") || strings.Contains(string(wire), "example.test") {
				t.Fatal("certificate/identity text leaked")
			}
			var typed *certificateValidationError
			if !errors.As(err, &typed) {
				t.Fatal("certificate cause was discarded")
			}
			if tc.name == "untrusted" {
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Fatal("underlying x509 cause was discarded")
				}
			}
		})
	}
}

func TestCertificateDiagnosticNativeMapping(t *testing.T) {
	for _, tc := range []struct {
		stage, code int
		reason      string
	}{
		{1, 0, "certificate_trust_internal"}, {3, 0, "certificate_chain_extraneous"},
		{2, -25318, "certificate_chain_incomplete"}, {2, -67818, "certificate_expired"},
		{2, -67819, "certificate_not_yet_valid"}, {2, -67820, "certificate_revoked"},
		{2, -67843, "certificate_chain_untrusted"}, {2, -67602, "certificate_hostname_mismatch"},
		{2, -67603, "certificate_critical_extension"}, {2, -67604, "certificate_ca_constraints"},
		{2, -67605, "certificate_ca_constraints"}, {2, -67611, "certificate_ca_constraints"},
		{2, -67608, "certificate_key_usage"}, {2, -67609, "certificate_eku"},
		{2, -67606, "certificate_chain_invalid"}, {2, -67607, "certificate_chain_invalid"},
		{2, -67610, "certificate_chain_invalid"}, {2, -67612, "certificate_chain_invalid"},
		{2, -67824, "certificate_chain_invalid"}, {2, -67826, "certificate_chain_invalid"},
		{2, -99999, "certificate_trust_internal"},
	} {
		t.Run(fmt.Sprintf("%d_%d", tc.stage, tc.code), func(t *testing.T) {
			reason, stage, code, fingerprint := certificateDiagnostic(appleCertificateError(tc.stage, tc.code))
			if reason != tc.reason || stage != tc.stage || code != tc.code || fingerprint != "" {
				t.Fatalf("native mapping: %q %d %d %q", reason, stage, code, fingerprint)
			}
		})
	}
}

func TestCertificateDiagnosticTypedX509Mapping(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{x509.UnknownAuthorityError{}, "certificate_chain_untrusted"},
		{x509.HostnameError{Host: "SECRET"}, "certificate_hostname_mismatch"},
		{x509.UnhandledCriticalExtension{}, "certificate_critical_extension"},
		{x509.CertificateInvalidError{Reason: x509.Expired, Cert: &x509.Certificate{NotBefore: now.Add(time.Hour)}}, "certificate_not_yet_valid"},
		{x509.CertificateInvalidError{Reason: x509.Expired}, "certificate_expired"},
		{x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}, "certificate_eku"},
		{x509.CertificateInvalidError{Reason: x509.CANotAuthorizedForExtKeyUsage}, "certificate_eku"},
		{x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}, "certificate_ca_constraints"},
		{x509.CertificateInvalidError{Reason: x509.TooManyIntermediates}, "certificate_ca_constraints"},
		{x509.CertificateInvalidError{Reason: x509.NameMismatch}, "certificate_chain_invalid"},
		{x509.InsecureAlgorithmError(x509.SHA1WithRSA), "certificate_chain_invalid"},
		{x509.ConstraintViolationError{}, "certificate_chain_invalid"},
		{errors.New("SECRET certificate_expired"), "certificate_trust_internal"},
	} {
		err := withCertificateLeaf(tc.err, "", now)
		reason, _, _, _ := certificateDiagnostic(err)
		if reason != tc.reason || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("typed classification: %q %v", reason, err)
		}
		if !errors.Is(err, tc.err) {
			t.Fatal("original cause lost")
		}
	}
}

func TestCertificateDiagnosticSanitizationAndCancellation(t *testing.T) {
	validHash := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		reason              string
		stage, code         int
		fingerprint         string
		wantReason          string
		wantStage, wantCode int
		wantHash            string
	}{
		{"SECRET", 2, -67843, validHash, "certificate_trust_internal", 2, -67843, validHash},
		{"certificate_verifier_unavailable", 0, 0, "", "certificate_verifier_unavailable", 0, 0, ""},
		{"certificate_parse", -1, 123, validHash, "certificate_parse", 0, 0, validHash},
		{"certificate_parse", 17, 123, validHash, "certificate_parse", 0, 0, validHash},
		{"certificate_parse", 2, 2147483648, validHash, "certificate_parse", 0, 0, validHash},
		{"certificate_parse", 2, -2147483649, validHash, "certificate_parse", 0, 0, validHash},
		{"certificate_parse", 0, 123, validHash, "certificate_parse", 0, 0, validHash},
		{"certificate_parse", 0, 0, strings.Repeat("AB", 32), "certificate_parse", 0, 0, ""},
		{"certificate_parse", 0, 0, validHash + "SECRET", "certificate_parse", 0, 0, ""},
	} {
		err := &certificateValidationError{reason: tc.reason, stage: tc.stage, code: tc.code, leafSHA256: tc.fingerprint, cause: errors.New("SECRET")}
		r, s, c, h := certificateDiagnostic(err)
		if r != tc.wantReason || s != tc.wantStage || c != tc.wantCode || h != tc.wantHash {
			t.Fatalf("sanitization: %q %d %d %q", r, s, c, h)
		}
	}
	for _, err := range []error{nil, errors.New("certificate_expired SECRET"), context.Canceled} {
		r, s, c, h := certificateDiagnostic(err)
		if r != "" || s != 0 || c != 0 || h != "" {
			t.Fatal("arbitrary error exported as certificate diagnostic")
		}
	}
	f := newPeerFixture(t, nil)
	f.s.cfg.OnAuthDiagnostic = func(AuthDiagnostic) { t.Fatal("cancelled diagnostics emitted") }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.s.ctx = ctx
	_, err := f.s.processAuthEAPResponse(1, f.initial(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation contract changed: %v", err)
	}
	f.s.emitAuthDiagnostic("initial", 1, nil, false, certificateError("certificate_parse", nil))
	f.s.ctx = nil
	f.s.cfg.OnAuthDiagnostic = nil
	f.s.emitAuthDiagnostic("initial", 1, nil, false, certificateError("certificate_parse", nil))
}

func TestCertificateDiagnosticNativeTrustFailurePreservesPublicFingerprint(t *testing.T) {
	f := newPeerFixture(t, nil)
	digest := sha256.Sum256(f.certs[0].Data)
	wantHash := hex.EncodeToString(digest[:])
	for code, wantReason := range map[int]string{
		-67820: "certificate_revoked",
		-67818: "certificate_expired",
		-67819: "certificate_not_yet_valid",
		-25318: "certificate_chain_incomplete",
		-67843: "certificate_chain_untrusted",
	} {
		cause := withCertificateLeaf(appleCertificateError(2, code), wantHash, f.now)
		err := &AuthFailureError{Code: AuthFailureCertificate, err: errors.Join(ErrPeerAuthentication, cause)}
		var got AuthDiagnostic
		f.s.cfg.OnAuthDiagnostic = func(d AuthDiagnostic) { got = d }
		f.s.emitAuthDiagnostic("initial", 1, f.initial(t), false, err)
		if !errors.Is(err, ErrPeerAuthentication) || got.FailureCode != AuthFailureCertificate || got.CertificateFailure != wantReason || got.CertificateTrustStage != 2 || got.CertificateTrustCode != code || got.CertificateLeafSHA256 != wantHash {
			t.Fatalf("native failure metadata discarded: %+v", got)
		}
		wire, marshalErr := json.Marshal(got)
		if marshalErr != nil || strings.Contains(string(wire), "example.test") || strings.Contains(string(wire), "Test Root") {
			t.Fatal("native failure exported certificate identity")
		}
	}
}
