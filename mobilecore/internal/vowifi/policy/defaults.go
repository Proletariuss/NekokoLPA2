package policy

import (
	"proletarius.local/core/internal/vowifi/carrier"
	"strings"
)

const (
	DefaultRegisterExpires = 3600
	DefaultRegisterAllow   = "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS"
	DefaultRegisterSupport = "path,sec-agree,gruu"
)

// DefaultSecurityClientMechanisms returns the standard 6-mechanism phone-style
// Security-Client set used when a carrier preset does not override mechanisms.
func DefaultSecurityClientMechanisms() []IPSec3GPPSecurityMechanism {
	return []IPSec3GPPSecurityMechanism{
		{Alg: "hmac-md5-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-md5-96", EAlg: "aes-cbc"},
		{Alg: "hmac-md5-96", EAlg: "null"},
		{Alg: "hmac-sha-1-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "aes-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "null"},
	}
}

// DefaultIMSRegisterTemplate is the interoperable phone-style baseline used
// for carriers without a more specific reviewed REGISTER profile.
func DefaultIMSRegisterTemplate() IMSRegisterTemplate {
	mechanisms := DefaultSecurityClientMechanisms()
	return IMSRegisterTemplate{
		ID:                          "3gpp-default",
		Expires:                     DefaultRegisterExpires,
		Transport:                   "tcp",
		ContactMode:                 "android_default",
		SupportedHeader:             DefaultRegisterSupport,
		AllowHeader:                 DefaultRegisterAllow,
		AccessType:                  "IEEE-802.11",
		ICSIRef:                     IMSMmtelICSIRef,
		SecAgreeMode:                "auto",
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		EnableInitialRejectFallback: false,
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		SecurityClientMechanisms: mechanisms,
	}
}

// DefaultGiffgaffTemplate matches validated ipcc-giffgaff-23410
// REGISTER shape while retaining this project's reviewed sec-agree policy.
func DefaultGiffgaffTemplate() IMSRegisterTemplate {
	template := DefaultIMSRegisterTemplate()
	template.ID = "giffgaff"
	// giffgaff expects the UE to identify the IMS AKA scheme on the first
	// REGISTER. This matches validated ipcc-giffgaff-23410 bootstrap.
	template.InitialAuthorization = "aka_empty"
	template.ContactMode = "gsma"
	template.SupportedHeader = "path,gruu"
	template.AllowHeader = "REGISTER,INVITE,ACK,CANCEL,BYE,OPTIONS,MESSAGE,SUBSCRIBE,NOTIFY"
	template.FixedPANI = "IEEE-802.11;country=GB;i-wlan-node-id=000000000000"
	template.AccessType = ""
	template.ContactParamOrder = []string{"icsi_ref", "mid_call", "smsip", "sip_instance"}
	return template
}

// OrangeUKTemplate adds the REGISTER Contact capabilities published by the
// Apple Orange UK bundle used by CTExcel (home PLMN 234/33).
func OrangeUKTemplate() IMSRegisterTemplate {
	template := DefaultIMSRegisterTemplate()
	template.ID = "apple_orange_uk"
	// validated CTExcel path advertises the IMS AKA scheme on the very
	// first REGISTER so the P-CSCF routes the request to the AKA/sec-agree
	// service rather than its unrelated ordinary-MD5 service.
	template.InitialAuthorization = "aka_empty"
	template.ContactParamOrder = []string{
		"access_type",
		"audio",
		"smsip",
		"icsi_ref",
		"mid_call",
		"srvcc_alerting",
		"ps2cs_srvcc_orig_pre_alerting",
		"sip_instance",
	}
	return template
}

// TemplateForCarrier returns the reviewed IMS REGISTER policy for a carrier.
// Unknown carriers retain the interoperable baseline template.
func TemplateForCarrier(carrierID string) IMSRegisterTemplate {
	switch carrierID {
	case "apple_o2_giffgaff_uk":
		return DefaultGiffgaffTemplate()
	case "apple_orange_uk":
		return OrangeUKTemplate()
	default:
		template := DefaultIMSRegisterTemplate()
		template.ID = carrierID
		return template
	}
}

func TemplateForProfile(profile *carrier.Profile) IMSRegisterTemplate {
	if profile == nil {
		return DefaultIMSRegisterTemplate()
	}
	template := TemplateForCarrier(profile.ID)
	// Apple carrier bundles remain authoritative for ePDG/IKE parameters, but
	// giffgaff's IMS REGISTER shape is supplied by the validated carrier profile.
	// Do not replace that carrier-specific template with the generic baseline.
	if profile.ID == "apple_o2_giffgaff_uk" {
		return template
	}
	if profile.RegisterExpires > 0 {
		template.Expires = profile.RegisterExpires
	}
	template.ReRegisterOn = carrier.CloneReRegisterRules(profile.ReRegisterOn)
	for _, raw := range profile.RegisterContactParams {
		name := contactParamName(raw)
		if name != "" && !hasParam(template.ContactParamOrder, name) {
			template.ContactParamOrder = insertBeforeInstance(template.ContactParamOrder, name)
		}
	}
	if profile.SupportPEarlyMedia {
		template.SupportPEarlyMedia = true
		template.EarlyMediaNeedsHeader = profile.EarlyMediaNeedsHeader
	}
	return template
}

func contactParamName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "+g.3gpp.mid-call":
		return "mid_call"
	case "+g.3gpp.srvcc-alerting":
		return "srvcc_alerting"
	case "+g.3gpp.ps2cs-srvcc-orig-pre-alerting":
		return "ps2cs_srvcc_orig_pre_alerting"
	case "+g.3gpp.smsip":
		return "smsip"
	case "audio":
		return "audio"
	}
	return ""
}
func hasParam(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
func insertBeforeInstance(values []string, value string) []string {
	for i, v := range values {
		if v == "sip_instance" {
			values = append(values, "")
			copy(values[i+1:], values[i:])
			values[i] = value
			return values
		}
	}
	return append(values, value)
}
