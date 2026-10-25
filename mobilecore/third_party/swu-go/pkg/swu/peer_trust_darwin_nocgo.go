//go:build darwin && !cgo

package swu

import (
	"crypto/x509"
	"time"
)

func verifySystemIKECertificates(_ []*x509.Certificate, _ string, _ time.Time) error {
	return certificateError("certificate_verifier_unavailable", nil)
}

func verifySystemPeerCertificates(_, _ []*x509.Certificate, _ string, _ time.Time, _ string) error {
	return certificateError("certificate_verifier_unavailable", nil)
}
