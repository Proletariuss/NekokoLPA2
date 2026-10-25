package swu

import (
	"bytes"
	"crypto/x509"
	"strings"
	"time"
)

const (
	CertificatePurposeIKE        = "ike"
	CertificatePurposeServerAuth = "server_auth"
)

func (c *Config) certificatePurpose() (string, error) {
	switch c.CertificatePurpose {
	case "", CertificatePurposeIKE:
		return CertificatePurposeIKE, nil
	case CertificatePurposeServerAuth:
		return CertificatePurposeServerAuth, nil
	default:
		return "", certificateError("certificate_expected_identity_invalid", nil)
	}
}

func (c *Config) validateCertificatePolicy() error {
	if _, err := c.certificatePurpose(); err != nil {
		return err
	}
	if len(c.ResponderIDrAliases) > 8 || len(c.CertificateIntermediates) > 8 {
		return certificateError("certificate_chain_limit", nil)
	}
	for _, alias := range c.ResponderIDrAliases {
		if !validResponderAlias(alias) {
			return certificateError("certificate_expected_identity_invalid", nil)
		}
	}
	return nil
}

func validResponderAlias(alias string) bool {
	if len(alias) == 0 || len(alias) > 253 || !strings.Contains(alias, ".") {
		return false
	}
	for _, label := range strings.Split(alias, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func (c *Config) allowsResponderAlias(received string) bool {
	if !validResponderAlias(received) {
		return false
	}
	for _, alias := range c.ResponderIDrAliases {
		if validResponderAlias(alias) && strings.EqualFold(alias, received) {
			return true
		}
	}
	return false
}

func certificateAllowsPurpose(cert *x509.Certificate, purpose string) bool {
	if purpose == CertificatePurposeIKE {
		return certificateAllowsIKE(cert)
	}
	if purpose != CertificatePurposeServerAuth {
		return false
	}
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// Every peer-supplied CERT must belong to one validated path. Local candidates
// may be unused. One selected purpose is applied to every member of that path;
// a TLS-only leaf cannot be combined with an IKE-only intermediate.
func validatePeerCertificateChains(chains [][]*x509.Certificate, peers []*x509.Certificate, purpose string) error {
	if purpose != CertificatePurposeIKE && purpose != CertificatePurposeServerAuth {
		return certificateError("certificate_expected_identity_invalid", nil)
	}
	purposeRejected := false
	for _, chain := range chains {
		allUsed := true
		for _, cert := range chain {
			if !certificateAllowsPurpose(cert, purpose) {
				allUsed = false
				purposeRejected = true
			}
		}
		for _, peer := range peers {
			found := false
			for _, member := range chain {
				if bytes.Equal(peer.Raw, member.Raw) {
					found = true
					break
				}
			}
			if !found {
				allUsed = false
				break
			}
		}
		if allUsed {
			return nil
		}
	}
	if purposeRejected {
		return certificateError("certificate_eku", nil)
	}
	return certificateError("certificate_chain_extraneous", nil)
}

// Parse local candidates separately from peer CERTs. Only a cryptographically
// linked issuer can enter the building pool. A linked certificate is still
// untrusted until the platform/explicit root verifier builds a valid path.
func localCertificateIntermediates(raws [][]byte, peers []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	if len(raws) > 8 {
		return nil, certificateError("certificate_chain_limit", nil)
	}
	var candidates []*x509.Certificate
	total := 0
	for _, raw := range raws {
		total += len(raw)
		if total > 1024*1024 {
			return nil, certificateError("certificate_chain_limit", nil)
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, certificateError("certificate_parse", err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, certificateError("certificate_ca_constraints", nil)
		}
		if now.Before(cert.NotBefore) {
			return nil, certificateError("certificate_not_yet_valid", nil)
		}
		if now.After(cert.NotAfter) {
			return nil, certificateError("certificate_expired", nil)
		}
		if len(cert.UnhandledCriticalExtensions) != 0 {
			return nil, certificateError("certificate_critical_extension", nil)
		}
		candidates = append(candidates, cert)
	}
	known := append([]*x509.Certificate(nil), peers...)
	seen := make(map[string]bool)
	for _, peer := range peers {
		seen[string(peer.Raw)] = true
	}
	var linked []*x509.Certificate
	for progress := true; progress; {
		progress = false
		for _, candidate := range candidates {
			if seen[string(candidate.Raw)] {
				continue
			}
			for _, child := range known {
				if bytes.Equal(child.RawIssuer, candidate.RawSubject) && child.CheckSignatureFrom(candidate) == nil {
					linked = append(linked, candidate)
					known = append(known, candidate)
					seen[string(candidate.Raw)] = true
					progress = true
					break
				}
			}
		}
	}
	return linked, nil
}
