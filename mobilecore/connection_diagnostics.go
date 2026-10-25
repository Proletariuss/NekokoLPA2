package mobilecore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/1239t/swu-go/pkg/swu"
	"proletarius.local/core/internal/vowifi/carrier"
)

// Prepared describes a built request, not successful network delivery. Never
// include identity, certificate, CA hash bytes, credentials, or endpoint data.
type ikeAuthRequestDiagnosticStatus struct {
	Stage               string `json:"stage"`
	MessageID           uint32 `json:"message_id"`
	PayloadTypes        []int  `json:"payload_types"`
	NotifyTypes         []int  `json:"notify_types"`
	IDiTypes            []int  `json:"idi_types"`
	IDrTypes            []int  `json:"idr_types"`
	IDiAnonymous        bool   `json:"idi_anonymous"`
	IDrIsAPN            bool   `json:"idr_is_apn"`
	CertReqCount        int    `json:"certreq_count"`
	CertReqEncodings    []int  `json:"certreq_encodings"`
	CertReqCAHashCount  int    `json:"certreq_ca_hash_count"`
	EAPCodes            []int  `json:"eap_codes"`
	EAPTypes            []int  `json:"eap_types"`
	CertificateRequired bool   `json:"certificate_required"`
	EAPOnlyOffered      bool   `json:"eap_only_offered"`
	Fragmented          bool   `json:"fragmented"`
	PacketCount         int    `json:"packet_count"`
	SendState           string `json:"send_state"`
}

func cloneAuthRequestDiagnosticStatus(source *ikeAuthRequestDiagnosticStatus) *ikeAuthRequestDiagnosticStatus {
	copy := *source
	copy.PayloadTypes = append([]int{}, source.PayloadTypes...)
	copy.NotifyTypes = append([]int{}, source.NotifyTypes...)
	copy.IDiTypes = append([]int{}, source.IDiTypes...)
	copy.IDrTypes = append([]int{}, source.IDrTypes...)
	copy.CertReqEncodings = append([]int{}, source.CertReqEncodings...)
	copy.EAPCodes = append([]int{}, source.EAPCodes...)
	copy.EAPTypes = append([]int{}, source.EAPTypes...)
	return &copy
}

func (e *Engine) recordAuthRequestDiagnostic(run *runningSession, attempt int, ctx context.Context, source swu.AuthRequestDiagnostic) {
	switch source.Stage {
	case "initial", "eap", "final":
	default:
		return
	}
	if source.SendState != "prepared" {
		return
	}
	diagnostic := &ikeAuthRequestDiagnosticStatus{
		Stage: source.Stage, MessageID: source.MessageID,
		PayloadTypes: diagnosticNumbers(source.PayloadTypes, 255), NotifyTypes: diagnosticNumbers(source.NotifyTypes, 65535),
		IDiTypes: diagnosticNumbers(source.IDiTypes, 255), IDrTypes: diagnosticNumbers(source.IDrTypes, 255),
		IDiAnonymous: source.IDiAnonymous, IDrIsAPN: source.IDrIsAPN,
		CertReqCount: max(0, min(source.CertReqCount, 32)), CertReqEncodings: diagnosticNumbers(source.CertReqEncodings, 255),
		CertReqCAHashCount: max(0, min(source.CertReqCAHashCount, 32)),
		EAPCodes:           diagnosticNumbers(source.EAPCodes, 255), EAPTypes: diagnosticNumbers(source.EAPTypes, 255),
		CertificateRequired: source.CertificateRequired, EAPOnlyOffered: source.EAPOnlyOffered,
		Fragmented: source.Fragmented, PacketCount: max(0, min(source.PacketCount, 255)), SendState: "prepared",
	}
	e.mu.Lock()
	if e.run != run || run.ctx.Err() != nil || ctx.Err() != nil || e.attempt != attempt || e.phase != "ike" {
		e.mu.Unlock()
		return
	}
	e.ikeAuthRequestDiagnostic = diagnostic
	e.mu.Unlock()
	e.host.OnEvent(e.Status())
}

// Deliberately separate the exported schema from wire payloads. []int keeps
// numeric lists as JSON arrays (encoding/json encodes []uint8 as base64).
type ikeAuthDiagnosticStatus struct {
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
	CertificateFailure    string `json:"certificate_failure,omitempty"`
	CertificateTrustStage int    `json:"certificate_trust_stage,omitempty"`
	CertificateTrustCode  int    `json:"certificate_trust_code,omitempty"`
	CertificateLeafSHA256 string `json:"certificate_leaf_sha256,omitempty"`
}

func diagnosticNumbers[T ~uint8 | ~uint16 | ~int](values []T, maximum int) []int {
	result := make([]int, min(len(values), 32))
	for i := range result {
		result[i] = max(0, min(int(values[i]), maximum))
	}
	return result
}

func cloneAuthDiagnosticStatus(source *ikeAuthDiagnosticStatus) *ikeAuthDiagnosticStatus {
	copy := *source
	copy.PayloadTypes = append([]int{}, source.PayloadTypes...)
	copy.NotifyTypes = append([]int{}, source.NotifyTypes...)
	copy.EAPCodes = append([]int{}, source.EAPCodes...)
	copy.EAPTypes = append([]int{}, source.EAPTypes...)
	copy.AuthMethods = append([]int{}, source.AuthMethods...)
	copy.IDrTypes = append([]int{}, source.IDrTypes...)
	return &copy
}

func safeAuthFailureCode(code string) string {
	switch code {
	case "", "peer_notify_authentication_failed", "peer_notify_invalid_syntax", "peer_notify_unsupported_critical_payload", "eap_failure", "invalid_eap", "missing_idr", "missing_certificate_auth", "certificate_validation_failed", "signature_validation_failed", "missing_final_auth", "final_auth_mismatch", "missing_eap", "peer_authentication_failed", "auth_response_invalid", "child_sa_failed":
		return code
	default:
		return "auth_response_invalid"
	}
}

func safeCertificateFailure(reason string) string {
	switch reason {
	case "", "certificate_missing", "certificate_chain_limit", "certificate_encoding", "certificate_parse", "certificate_duplicate",
		"certificate_expired", "certificate_not_yet_valid", "certificate_critical_extension", "certificate_key_usage", "certificate_eku",
		"certificate_hostname_mismatch", "certificate_idr_mismatch", "certificate_idr_invalid", "certificate_expected_identity_invalid",
		"certificate_ca_constraints", "certificate_chain_untrusted", "certificate_chain_incomplete", "certificate_revoked",
		"certificate_chain_invalid", "certificate_trust_internal", "certificate_chain_extraneous", "certificate_verifier_unavailable":
		return reason
	default:
		return "certificate_trust_internal"
	}
}

func safeCertificateFingerprint(value string) string {
	if len(value) != 64 {
		return ""
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return ""
		}
	}
	return value
}

func (e *Engine) recordAuthDiagnostic(run *runningSession, attempt int, source swu.AuthDiagnostic) {
	switch source.Stage {
	case "initial", "eap", "final":
	default:
		return
	}
	diagnostic := &ikeAuthDiagnosticStatus{
		Stage: source.Stage, MessageID: source.MessageID,
		PayloadTypes: diagnosticNumbers(source.PayloadTypes, 255), NotifyTypes: diagnosticNumbers(source.NotifyTypes, 65535),
		EAPCodes: diagnosticNumbers(source.EAPCodes, 255), EAPTypes: diagnosticNumbers(source.EAPTypes, 255),
		CertCount: max(0, min(source.CertCount, 32)), AuthMethods: diagnosticNumbers(source.AuthMethods, 255), IDrTypes: diagnosticNumbers(source.IDrTypes, 255),
		CertificateRequired: source.CertificateRequired, EAPOnlyOffered: source.EAPOnlyOffered,
		PeerAuthenticated: source.PeerAuthenticated, FailureCode: safeAuthFailureCode(source.FailureCode),
		CertificateFailure:    safeCertificateFailure(source.CertificateFailure),
		CertificateTrustStage: max(0, min(source.CertificateTrustStage, 16)),
		CertificateTrustCode:  max(-2147483648, min(source.CertificateTrustCode, 2147483647)),
		CertificateLeafSHA256: safeCertificateFingerprint(source.CertificateLeafSHA256),
	}
	e.mu.Lock()
	if e.run != run || run.ctx.Err() != nil || e.attempt != attempt || e.phase != "ike" {
		e.mu.Unlock()
		return
	}
	e.ikeAuthDiagnostic = diagnostic
	e.mu.Unlock()
	e.host.OnEvent(e.Status())
}

type connectionPolicyStatus struct {
	RegistryRevision     string `json:"registry_revision"`
	EPDGSource           string `json:"epdg_source"`
	EPDGPort             int    `json:"epdg_port"`
	ProxyEnabled         bool   `json:"proxy_enabled"`
	CertificateRequired  bool   `json:"certificate_required"`
	CertificateProfile   string `json:"certificate_profile"`
	EAPOnlyOffered       bool   `json:"eap_only_offered"`
	RemoteIdentitySource string `json:"remote_identity_source"`
	IPStack              string `json:"ip_stack"`
	IMSTransport         string `json:"ims_transport"`
}

func connectionPolicyFor(config engineConfig, effective *readerVoWiFiEffectiveConfig) *connectionPolicyStatus {
	source := effective.EPDGSource
	switch source {
	case "custom", "carrier-override", "carrier-template", "3gpp-standard":
	default:
		source = "unknown"
	}
	identitySource := "epdg"
	if strings.TrimSpace(effective.RemoteCertificateHostname) != "" {
		identitySource = "certificate-hostname"
	}
	ipStack := effective.IPStack
	switch ipStack {
	case "ipv4", "ipv6", "ipv4v6":
	default:
		ipStack = "unknown"
	}
	certificateProfile := "strict_ike"
	if useThreeUKCertificateProfile(config, effective) {
		certificateProfile = "three_uk_server_auth"
	}
	return &connectionPolicyStatus{
		RegistryRevision: carrier.EmbeddedRegistryRevision, EPDGSource: source,
		EPDGPort: max(0, min(effective.EPDGPort, 65535)), ProxyEnabled: config.Proxy != "",
		CertificateRequired: effective.ValidateRemoteCertificate, EAPOnlyOffered: !effective.ValidateRemoteCertificate,
		CertificateProfile:   certificateProfile,
		RemoteIdentitySource: identitySource, IPStack: ipStack, IMSTransport: readerIMSTransport(effective),
	}
}

func terminalSessionError(err error) error {
	if errors.Is(err, swu.ErrPeerAuthentication) {
		return fmt.Errorf("VoWiFi stopped immediately after IKE authentication failure: %w", err)
	}
	if permanentSessionFailure(err) {
		return fmt.Errorf("VoWiFi stopped after a non-retryable session failure: %w", err)
	}
	return fmt.Errorf("VoWiFi stopped after repeated startup failures exhausted retries: %w", err)
}
