//go:build !darwin

package swu

import (
	"crypto/x509"
	"time"
)

func verifySystemIKECertificates(certs []*x509.Certificate, name string, now time.Time) error {
	return verifySystemPeerCertificates(certs, nil, name, now, CertificatePurposeIKE)
}

func verifySystemPeerCertificates(certs, local []*x509.Certificate, name string, now time.Time, purpose string) error {
	if len(certs) == 0 || len(certs) > 8 || len(local) > 8 {
		return certificateError("certificate_chain_limit", nil)
	}
	if purpose != CertificatePurposeIKE && purpose != CertificatePurposeServerAuth {
		return certificateError("certificate_expected_identity_invalid", nil)
	}
	pool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		pool.AddCert(cert)
	}
	for _, cert := range local {
		pool.AddCert(cert)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{Intermediates: pool, DNSName: name, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return err
	}
	return validatePeerCertificateChains(chains, certs, purpose)
}
