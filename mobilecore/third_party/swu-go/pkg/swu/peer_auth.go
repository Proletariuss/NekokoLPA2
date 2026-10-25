package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// ErrPeerAuthentication denotes a permanent authentication failure: callers
// should surface it rather than automatically retrying the same peer/config.
var ErrPeerAuthentication = errors.New("ePDG authentication failed")

// The legacy ticket path does not authenticate the resumed transcript. Do not
// offer/use it until RFC 5723 AUTH is implemented; AKA fast reauth is separate
// and still receives the same mandatory final AUTH verification.
func (s *Session) canResumeAuthenticatedSession() bool { return false }

func (s *Session) canUseFastReauth() bool { return false }

func peerAuthError(format string, args ...any) error {
	return &AuthFailureError{Code: AuthFailurePeer, err: fmt.Errorf("%w: %s", ErrPeerAuthentication, fmt.Sprintf(format, args...))}
}

func (s *Session) authContextError() error {
	if s.ctx != nil {
		return s.ctx.Err()
	}
	return nil
}

// checkResponderInitial runs before releasing EAP credentials to the peer.
// RFC 5998 omission of AUTH signals EAP-only acceptance; the responder does
// not echo EAP_ONLY_AUTHENTICATION. A supplied AUTH must always be checked.
func (s *Session) checkResponderInitial(payloads []ikev2.Payload) error {
	if err := s.authContextError(); err != nil {
		return err
	}
	if s.responderInitialChecked {
		return nil
	}
	var id *ikev2.EncryptedPayloadID
	var auth *ikev2.EncryptedPayloadAuth
	var certs []*ikev2.EncryptedPayloadCert
	for _, p := range payloads {
		switch p := p.(type) {
		case *ikev2.EncryptedPayloadID:
			if p.IsInitiator || id != nil {
				return peerAuthError("unexpected or duplicate identity")
			}
			id = p
		case *ikev2.EncryptedPayloadAuth:
			if auth != nil {
				return peerAuthError("duplicate AUTH")
			}
			auth = p
		case *ikev2.EncryptedPayloadCert:
			certs = append(certs, p)
		}
	}
	if id == nil || len(id.IDData) == 0 {
		return authFailure(AuthFailureMissingIDr)
	}
	body, err := id.Encode()
	if err != nil {
		return peerAuthError("invalid IDr")
	}
	s.responderIdentityBody = append([]byte(nil), body...)
	if auth == nil {
		if s.cfg.ValidateRemoteCertificate || len(certs) != 0 {
			return authFailure(AuthFailureMissingCertificateAUTH)
		}
		// Name-based certificate identity is unavailable in EAP-only mode.
		// The exact IDr is still authenticated by the final MSK-based AUTH.
		s.responderInitialChecked = true
		return nil
	}
	leaf, err := s.verifyResponderCertificate(certs, id, time.Now())
	if err != nil {
		return &AuthFailureError{Code: AuthFailureCertificate, err: errors.Join(ErrPeerAuthentication, err)}
	}
	signed, err := s.responderSignedOctets()
	if err != nil {
		return err
	}
	if err := ikev2.VerifyAuthSignature(leaf, auth, signed); err != nil {
		return authFailure(AuthFailureSignature)
	}
	if err := s.authContextError(); err != nil {
		return err
	}
	s.responderCertificateVerified = true
	s.responderInitialChecked = true
	return nil
}

func (s *Session) verifyResponderCertificate(payloads []*ikev2.EncryptedPayloadCert, id *ikev2.EncryptedPayloadID, now time.Time) (verified *x509.Certificate, err error) {
	leafSHA256 := ""
	defer func() {
		if err != nil {
			err = withCertificateLeaf(err, leafSHA256, now)
		}
	}()
	if len(payloads) == 0 {
		return nil, certificateError("certificate_missing", nil)
	}
	if len(payloads) > 8 {
		return nil, certificateError("certificate_chain_limit", nil)
	}
	if err := s.cfg.validateCertificatePolicy(); err != nil {
		return nil, err
	}
	purpose, err := s.cfg.certificatePurpose()
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	seen := make(map[string]bool)
	intermediates := x509.NewCertPool()
	for i, p := range payloads {
		if p.Encoding != 4 {
			return nil, certificateError("certificate_encoding", nil)
		}
		if seen[string(p.Data)] {
			return nil, certificateError("certificate_duplicate", nil)
		}
		seen[string(p.Data)] = true
		cert, err := x509.ParseCertificate(p.Data)
		if err != nil {
			return nil, certificateError("certificate_parse", err)
		}
		if i == 0 {
			leafSHA256 = certificateFingerprint(cert.Raw)
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
		if i > 0 {
			if !cert.IsCA || !cert.BasicConstraintsValid {
				return nil, certificateError("certificate_ca_constraints", nil)
			}
			intermediates.AddCert(cert)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	if leaf.IsCA {
		return nil, certificateError("certificate_ca_constraints", nil)
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return nil, certificateError("certificate_key_usage", nil)
	}
	for _, cert := range certs {
		if !certificateAllowsPurpose(cert, purpose) {
			return nil, certificateError("certificate_eku", nil)
		}
	}
	name := strings.TrimSpace(s.cfg.RemoteIdentifier)
	if name == "" {
		name = strings.TrimSpace(s.cfg.EpDGAddr)
	}
	if name == "" || strings.Contains(name, "*") {
		return nil, certificateError("certificate_expected_identity_invalid", nil)
	}
	if err := leaf.VerifyHostname(name); err != nil {
		return nil, certificateError("certificate_hostname_mismatch", err)
	}
	// A configured hostname authorizes the peer, and IDr independently binds
	// the protocol identity to the same leaf certificate (RFC 4945 section 3.5).
	switch id.IDType {
	case ikev2.ID_FQDN:
		if err := leaf.VerifyHostname(string(id.IDData)); err != nil {
			if !s.cfg.allowsResponderAlias(string(id.IDData)) {
				return nil, certificateError("certificate_idr_mismatch", err)
			}
		}
	case ikev2.ID_IPV4_ADDR, ikev2.ID_IPV6_ADDR:
		wantLen := net.IPv4len
		if id.IDType == ikev2.ID_IPV6_ADDR {
			wantLen = net.IPv6len
		}
		if len(id.IDData) != wantLen {
			return nil, certificateError("certificate_idr_invalid", nil)
		}
		if err := leaf.VerifyHostname(net.IP(id.IDData).String()); err != nil {
			return nil, certificateError("certificate_idr_mismatch", err)
		}
	case ikev2.ID_DER_ASN1_DN:
		if !bytes.Equal(id.IDData, leaf.RawSubject) {
			return nil, certificateError("certificate_idr_mismatch", nil)
		}
	case ikev2.ID_RFC822_ADDR:
		found := false
		for _, email := range leaf.EmailAddresses {
			if email == string(id.IDData) {
				found = true
			}
		}
		if !found {
			return nil, certificateError("certificate_idr_mismatch", nil)
		}
	default:
		return nil, certificateError("certificate_idr_invalid", nil)
	}
	local, err := localCertificateIntermediates(s.cfg.CertificateIntermediates, certs, now)
	if err != nil {
		return nil, err
	}
	for _, cert := range local {
		intermediates.AddCert(cert)
	}
	if s.cfg.CertificateRoots == nil {
		if err := verifySystemPeerCertificates(certs, local, name, now, purpose); err != nil {
			return nil, err
		}
		return leaf, nil
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: s.cfg.CertificateRoots, Intermediates: intermediates, DNSName: name, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, err
	}
	if err := validatePeerCertificateChains(chains, certs, purpose); err != nil {
		return nil, err
	}
	return leaf, nil
}

func certificateAllowsIKE(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	for _, usage := range cert.UnknownExtKeyUsage {
		if usage.String() == "1.3.6.1.5.5.7.3.17" { // RFC 4945 id-kp-ipsecIKE.
			return true
		}
	}
	return false
}

func (s *Session) responderSignedOctets() ([]byte, error) {
	if s.PRFAlg == nil || s.Keys == nil || len(s.Keys.SK_pr) == 0 || len(s.ikeInitResponse) == 0 || len(s.ni) == 0 || len(s.responderIdentityBody) < 5 {
		return nil, peerAuthError("missing responder AUTH transcript")
	}
	h := hmac.New(s.PRFAlg.Hash, s.Keys.SK_pr)
	h.Write(s.responderIdentityBody)
	signed := append([]byte(nil), s.ikeInitResponse...)
	signed = append(signed, s.ni...)
	return append(signed, h.Sum(nil)...), nil
}

func (s *Session) verifyResponderFinal(payloads []ikev2.Payload) error {
	if err := s.authContextError(); err != nil {
		return err
	}
	if !s.responderInitialChecked || !s.eapSuccessReceived || len(s.MSK) < 64 {
		return peerAuthError("EAP authentication has not completed")
	}
	if s.cfg.ValidateRemoteCertificate && !s.responderCertificateVerified {
		return peerAuthError("certificate authentication has not completed")
	}
	var auth *ikev2.EncryptedPayloadAuth
	for _, p := range payloads {
		switch p := p.(type) {
		case *ikev2.EncryptedPayloadAuth:
			if auth != nil {
				return peerAuthError("duplicate final AUTH")
			}
			auth = p
		case *ikev2.EncryptedPayloadID:
			body, _ := p.Encode()
			if p.IsInitiator || !bytes.Equal(body, s.responderIdentityBody) {
				return peerAuthError("responder identity changed")
			}
		case *ikev2.EncryptedPayloadCert:
			return peerAuthError("unexpected certificate in final AUTH")
		}
	}
	if auth == nil || auth.AuthMethod != ikev2.AuthMethodSharedKey {
		return authFailure(AuthFailureMissingFinalAUTH)
	}
	signed, err := s.responderSignedOctets()
	if err != nil {
		return err
	}
	h := hmac.New(s.PRFAlg.Hash, s.MSK)
	h.Write([]byte("Key Pad for IKEv2"))
	key := h.Sum(nil)
	defer clear(key)
	h = hmac.New(s.PRFAlg.Hash, key)
	h.Write(signed)
	if !hmac.Equal(h.Sum(nil), auth.AuthData) {
		return authFailure(AuthFailureFinalAUTH)
	}
	return s.authContextError()
}
