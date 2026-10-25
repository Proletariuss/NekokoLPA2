package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// AuthDiagnostic contains protocol enums and the public leaf certificate hash.
// It never contains identities, certificate contents, packet bytes, AKA
// attributes, arbitrary error strings, or key material.
type AuthDiagnostic struct {
	Stage                 string `json:"stage"`
	MessageID             uint32 `json:"message_id"`
	PayloadTypes          []int  `json:"payload_types"`
	NotifyTypes           []int  `json:"notify_types"`
	EAPCodes              []int  `json:"eap_codes"`
	EAPTypes              []int  `json:"eap_types"`
	CertCount             int    `json:"cert_count"`
	AuthMethods           []int  `json:"auth_methods"`
	IDrTypes              []int  `json:"idr_types"`
	CertificateRequired   bool   `json:"certificate_required"`
	EAPOnlyOffered        bool   `json:"eap_only_offered"`
	PeerAuthenticated     bool   `json:"peer_authenticated"`
	FailureCode           string `json:"failure_code"`
	CertificateFailure    string `json:"certificate_failure"`
	CertificateTrustStage int    `json:"certificate_trust_stage"`
	CertificateTrustCode  int    `json:"certificate_trust_code"`
	CertificateLeafSHA256 string `json:"certificate_leaf_sha256"`
}

const (
	AuthFailurePeerNotifyAuthentication = "peer_notify_authentication_failed"
	AuthFailurePeerNotifySyntax         = "peer_notify_invalid_syntax"
	AuthFailurePeerNotifyCritical       = "peer_notify_unsupported_critical_payload"
	AuthFailureEAP                      = "eap_failure"
	AuthFailureInvalidEAP               = "invalid_eap"
	AuthFailureMissingIDr               = "missing_idr"
	AuthFailureMissingCertificateAUTH   = "missing_certificate_auth"
	AuthFailureCertificate              = "certificate_validation_failed"
	AuthFailureSignature                = "signature_validation_failed"
	AuthFailureMissingFinalAUTH         = "missing_final_auth"
	AuthFailureFinalAUTH                = "final_auth_mismatch"
	AuthFailureMissingEAP               = "missing_eap"
	AuthFailurePeer                     = "peer_authentication_failed"
	AuthFailureResponse                 = "auth_response_invalid"
	AuthFailureChildSA                  = "child_sa_failed"
)

// AuthFailureError preserves the permanent ErrPeerAuthentication contract.
// Code is one of the fixed AuthFailure constants, never peer-supplied text.
type AuthFailureError struct {
	Code string
	err  error
}

func (e *AuthFailureError) Error() string { return ErrPeerAuthentication.Error() + ": " + e.Code }
func (e *AuthFailureError) Unwrap() error { return e.err }

func authFailure(code string) error {
	return &AuthFailureError{Code: code, err: ErrPeerAuthentication}
}

// AuthFailureCode is safe to export; arbitrary wrapped errors map to a static
// fallback rather than leaking their text through diagnostics.
func AuthFailureCode(err error) string {
	if err == nil {
		return ""
	}
	var failure *AuthFailureError
	if errors.As(err, &failure) {
		switch failure.Code {
		case AuthFailurePeerNotifyAuthentication, AuthFailurePeerNotifySyntax, AuthFailurePeerNotifyCritical,
			AuthFailureEAP, AuthFailureInvalidEAP, AuthFailureMissingIDr, AuthFailureMissingCertificateAUTH,
			AuthFailureCertificate, AuthFailureSignature, AuthFailureMissingFinalAUTH, AuthFailureFinalAUTH,
			AuthFailureMissingEAP, AuthFailurePeer, AuthFailureResponse, AuthFailureChildSA:
			return failure.Code
		}
	}
	if errors.Is(err, ErrPeerAuthentication) {
		return AuthFailurePeer
	}
	return AuthFailureResponse
}

// RFC 7296 section 2.21.2 allows these terminal errors without IDr/CERT/AUTH.
// The caller has verified the encrypted envelope, which alone does not yet
// authenticate the responder's identity. CHILD_SA errors/statuses are excluded.
func terminalAuthFailure(payloads []ikev2.Payload) error {
	for _, p := range payloads {
		if n, ok := p.(*ikev2.EncryptedPayloadNotify); ok {
			switch n.NotifyType {
			case ikev2.AUTHENTICATION_FAILED:
				return authFailure(AuthFailurePeerNotifyAuthentication)
			case ikev2.INVALID_SYNTAX:
				return authFailure(AuthFailurePeerNotifySyntax)
			case ikev2.UNSUPPORTED_CRITICAL_PAYLOAD:
				return authFailure(AuthFailurePeerNotifyCritical)
			}
		}
	}
	var found *ikev2.EncryptedPayloadEAP
	for _, p := range payloads {
		if ep, ok := p.(*ikev2.EncryptedPayloadEAP); ok {
			if found != nil || !validInboundEAP(ep.EAPMessage) {
				return authFailure(AuthFailureInvalidEAP)
			}
			found = ep
		}
	}
	if found != nil && found.EAPMessage[0] == eap.CodeFailure {
		return authFailure(AuthFailureEAP)
	}
	return nil
}

func validInboundEAP(raw []byte) bool {
	if !validEAPPacketLength(raw) {
		return false
	}
	switch raw[0] {
	case eap.CodeSuccess, eap.CodeFailure:
		return len(raw) == 4
	case eap.CodeRequest:
		if len(raw) < 5 {
			return false
		}
		if raw[4] == eap.TypeAKA || raw[4] == eap.TypeAKAPrime {
			return len(raw) >= 8
		}
		return true
	default:
		return false
	}
}

func appendAuthEnum(dst []int, value int) []int {
	if len(dst) < 32 {
		return append(dst, value)
	}
	return dst
}

func (s *Session) emitAuthDiagnostic(stage string, msgID uint32, payloads []ikev2.Payload, authenticated bool, err error) {
	if s.cfg.OnAuthDiagnostic == nil || s.authContextError() != nil {
		return
	}
	d := AuthDiagnostic{Stage: stage, MessageID: msgID, CertificateRequired: s.cfg.ValidateRemoteCertificate,
		EAPOnlyOffered: !s.cfg.ValidateRemoteCertificate, PeerAuthenticated: authenticated, FailureCode: AuthFailureCode(err)}
	d.CertificateFailure, d.CertificateTrustStage, d.CertificateTrustCode, d.CertificateLeafSHA256 = certificateDiagnostic(err)
	for _, p := range payloads {
		d.PayloadTypes = appendAuthEnum(d.PayloadTypes, int(p.Type()))
		switch p := p.(type) {
		case *ikev2.EncryptedPayloadNotify:
			d.NotifyTypes = appendAuthEnum(d.NotifyTypes, int(p.NotifyType))
		case *ikev2.EncryptedPayloadEAP:
			if len(p.EAPMessage) > 0 {
				d.EAPCodes = appendAuthEnum(d.EAPCodes, int(p.EAPMessage[0]))
			}
			if len(p.EAPMessage) >= 5 && (p.EAPMessage[0] == eap.CodeRequest || p.EAPMessage[0] == eap.CodeResponse) {
				d.EAPTypes = appendAuthEnum(d.EAPTypes, int(p.EAPMessage[4]))
			}
		case *ikev2.EncryptedPayloadCert:
			if d.CertCount < 32 {
				d.CertCount++
			}
		case *ikev2.EncryptedPayloadAuth:
			d.AuthMethods = appendAuthEnum(d.AuthMethods, int(p.AuthMethod))
		case *ikev2.EncryptedPayloadID:
			if !p.IsInitiator {
				d.IDrTypes = appendAuthEnum(d.IDrTypes, int(p.IDType))
			}
		}
	}
	// All slices above are newly allocated; observers cannot mutate session or
	// payload state. Synchronous invocation lets the owner fence run/attempt IDs.
	if s.authContextError() == nil {
		s.cfg.OnAuthDiagnostic(d)
	}
}

// processAuthEAPResponse runs only on a fully decrypted, parsed response.
func (s *Session) processAuthEAPResponse(msgID uint32, payloads []ikev2.Payload) (response []ikev2.Payload, err error) {
	stage := "eap"
	if !s.responderInitialChecked {
		stage = "initial"
	}
	defer func() {
		// A combined EAP Success/final AUTH response is reported once by the
		// final verifier, after MSK AUTH and CHILD_SA checks have completed.
		if err != nil || !s.eapSuccessReceived || !hasTerminalAuthPayload(payloads) {
			s.emitAuthDiagnostic(stage, msgID, payloads, s.responderCertificateVerified, err)
		}
	}()
	if err = s.authContextError(); err != nil {
		return nil, err
	}
	if err = terminalAuthFailure(payloads); err != nil {
		return nil, err
	}
	if err = s.checkResponderInitial(payloads); err != nil {
		return nil, err
	}
	for _, p := range payloads {
		if ep, ok := p.(*ikev2.EncryptedPayloadEAP); ok {
			return s.handleEAP(ep.EAPMessage)
		}
	}
	if !s.eapSuccessReceived {
		return nil, authFailure(AuthFailureMissingEAP)
	}
	return nil, nil
}

func hasTerminalAuthPayload(payloads []ikev2.Payload) bool {
	for _, p := range payloads {
		if p.Type() == ikev2.AUTH || p.Type() == ikev2.SA {
			return true
		}
	}
	return false
}
