package carrier

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
)

// VoWiFiTemplate stores a reviewed app-owned adaptation separately from the
// upstream carrier bundle. The 3HK entry is only attached to the generic
// Hutchison 454/03 selector; more specific MVNO selectors retain precedence.
type VoWiFiTemplate struct {
	ID    string                    `json:"id"`
	Name  string                    `json:"name"`
	MCC   string                    `json:"mcc"`
	MNC   string                    `json:"mnc"`
	IKE   VoWiFiIKETemplate         `json:"ike"`
	EAP   VoWiFiEAPTemplate         `json:"eap"`
	IMS   VoWiFiIMSTemplate         `json:"ims"`
	E911  VoWiFiEntitlementTemplate `json:"e911"`
	Block bool                      `json:"blocked"`
}

type VoWiFiIKETemplate struct {
	Addr              string   `json:"addr"`
	Proposals         []string `json:"proposals"`
	ESPProposals      []string `json:"esp_proposals"`
	ReauthInterval    int      `json:"reauth_interval"`
	IPStack           string   `json:"ip_stack"`
	APN               string   `json:"apn"`
	RFOffDelay        int      `json:"rf_off_delay"`
	RekeyPFS          int      `json:"rekey_pfs"`
	LocalPort         int      `json:"local_port"`
	TicketRequest     bool     `json:"ticket_request"`
	CPInFirstAuth     bool     `json:"cp_in_first_auth"`
	CPInFinalAuth     bool     `json:"cp_in_final_auth"`
	CookiePayloadType string   `json:"cookie_payload_type"`
}

type VoWiFiEAPTemplate struct {
	ChallengeMode  string `json:"challenge_mode"`
	IdentitySource string `json:"identity_source"`
}

type VoWiFiIMSTemplate struct {
	SecAgreeMode              string                    `json:"sec_agree_mode"`
	InitialAuthorization      string                    `json:"initial_authorization"`
	UserAgent                 string                    `json:"user_agent"`
	SupportedHeader           string                    `json:"supported_header"`
	AllowHeader               string                    `json:"allow_header"`
	ContactFeatures           string                    `json:"contact_features"`
	AllowPlainIMSTransport    bool                      `json:"allow_plain_ims_transport"`
	SecurityClientMechanisms  []VoWiFiSecurityMechanism `json:"security_client_mechanisms"`
	SecurityClientFormat      string                    `json:"security_client_format"`
	TransportMode             string                    `json:"transport_mode"`
	StrictSecurityServerOffer bool                      `json:"strict_security_server_offer"`
	Expires                   int                       `json:"expires"`
	IncludeAcceptContact      bool                      `json:"include_accept_contact"`
	IncludePPreferredID       bool                      `json:"include_p_preferred_id"`
	IncludePVisitedNetworkID  bool                      `json:"include_p_visited_network_id"`
	IncludePAccessNetworkInfo bool                      `json:"include_p_access_network_info"`
	IncludePANI               bool                      `json:"include_pani,omitempty"`
	IncludePANIAuthenticated  bool                      `json:"include_pani_authenticated,omitempty"`
	IncludeCellularNetwork    bool                      `json:"include_cellular_network,omitempty"`
	IncludeRoute              bool                      `json:"include_route"`
	RegisterPolicy            VoWiFiRegisterPolicy      `json:"register_policy"`
}

type VoWiFiSecurityMechanism struct {
	Alg  string `json:"alg"`
	EAlg string `json:"ealg"`
	Prot string `json:"prot"`
	Mode string `json:"mode"`
}

type VoWiFiRegisterPolicy struct {
	ID                               string `json:"id"`
	TemporaryStatusCodes             []int  `json:"temporary_status_codes"`
	ForbiddenStatusCodes             []int  `json:"forbidden_status_codes"`
	InitialRejectFallbackStatusCodes []int  `json:"initial_reject_fallback_status_codes"`
}

type VoWiFiEntitlementTemplate struct {
	EntitlementEndpoint string `json:"entitlement_endpoint"`
}

//go:embed data/user_templates/3_hk.json
var threeHKTemplateJSON []byte

func applyUserVoWiFiTemplate(profile *Profile, sim SIMIdentity) *Profile {
	mnc := normalizeDigits(sim.MNC)
	if len(mnc) == 1 {
		mnc = "0" + mnc
	}
	if profile == nil || normalizeDigits(sim.MCC) != "454" || mnc != "03" || profile.ID != "apple_hutchison_hk" {
		return profile
	}
	var template VoWiFiTemplate
	decoder := json.NewDecoder(bytes.NewReader(threeHKTemplateJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&template); err != nil {
		// This is an embedded release input. Silently using the generic Apple
		// profile after a malformed replacement would conceal a protocol change.
		panic(fmt.Sprintf("invalid embedded 3_hk template: %v", err))
	}
	result := *profile
	result.VoWiFiTemplate = &template
	result.Name = "3 HK / SIMworld"
	result.Source = "user-template"
	result.APN = template.IKE.APN
	result.IPStack = template.IKE.IPStack
	result.EPDGCandidates = []string{template.IKE.Addr}
	result.IKEEncryption, result.IKEIntegrity, result.IKEPRF = "aes128", "sha256", "sha256"
	result.IKEDHGroup = 14
	result.ChildEncryption, result.ChildIntegrity, result.ChildDHGroup = "aes256", "sha256", 14
	result.TemplateIKEProposalExact = false
	result.TemplateESPProposalExact = false
	return &result
}

func (template *VoWiFiTemplate) Clone() *VoWiFiTemplate {
	if template == nil {
		return nil
	}
	raw, err := json.Marshal(template)
	if err != nil {
		panic(err)
	}
	var result VoWiFiTemplate
	if err := json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	return &result
}
