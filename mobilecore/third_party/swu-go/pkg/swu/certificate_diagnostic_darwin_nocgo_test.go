//go:build darwin && !cgo

package swu

import (
	"testing"
	"time"
)

func TestCertificateDiagnosticNoCGOVerifierUnavailable(t *testing.T) {
	for _, err := range []error{
		verifySystemIKECertificates(nil, "", time.Now()),
		verifySystemPeerCertificates(nil, nil, "", time.Now(), CertificatePurposeServerAuth),
	} {
		reason, stage, code, fingerprint := certificateDiagnostic(err)
		if reason != "certificate_verifier_unavailable" || stage != 0 || code != 0 || fingerprint != "" {
			t.Fatalf("unavailable verifier diagnostic: %q %d %d %q", reason, stage, code, fingerprint)
		}
	}
}
