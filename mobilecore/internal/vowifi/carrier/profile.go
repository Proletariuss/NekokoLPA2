// Package carrier resolves the VoWiFi parameters that belong to a SIM's
// home network. Built-in profiles are reviewed before shipping; callers can
// override the suggested ePDG without replacing the remaining carrier data.
package carrier

import (
	"fmt"
	"strings"
)

const (
	ProfileSourceBuiltin  = "builtin"
	ProfileSourceStandard = "3gpp-default"
)

// SIMIdentity contains the public SIM fields used by selector manifests.
// GID1, ICCID, and SPN are optional. A constrained MVNO profile is never selected
// when the corresponding value is unavailable.
type SIMIdentity struct {
	MCC   string
	MNC   string
	IMSI  string
	ICCID string
	GID1  string
	GID2  string
	SPN   string
}

// Profile describes the VoWiFi settings expanded for one home PLMN.
type Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
	// VoWiFiTemplate is an app-owned carrier adaptation layered on top of the
	// pinned Apple carrier profile. It is deliberately selected only after the
	// full Apple selector has resolved a generic profile.
	VoWiFiTemplate *VoWiFiTemplate `json:"vowifi_template,omitempty"`

	MCC string `json:"mcc"`
	MNC string `json:"mnc"`

	RouteMCC string `json:"route_mcc,omitempty"`
	RouteMNC string `json:"route_mnc,omitempty"`

	IMS string `json:"ims_domain,omitempty"`
	// VoWiFiIMSI is selector metadata, never a subscriber value. It is resolved
	// against the selected card only when preparing an individual session.
	VoWiFiIMSI string `json:"vowifi_imsi,omitempty"`
	APN        string `json:"apn,omitempty"`
	// CallPhoneContext scopes national and carrier short numbers independently
	// from the subscriber identity domain. MVNOs can route MMTel through a host core.
	CallPhoneContext string `json:"call_phone_context,omitempty"`

	// EPDGCandidates are ordered. The first entry is the carrier suggestion;
	// an empty list means the standard 3GPP FQDN is used.
	EPDGCandidates []string `json:"epdg_candidates,omitempty"`
	IPStack        string   `json:"ip_stack,omitempty"`

	IKEEncryption string `json:"ike_encryption,omitempty"`
	IKEIntegrity  string `json:"ike_integrity,omitempty"`
	IKEPRF        string `json:"ike_prf,omitempty"`
	IKEDHGroup    int    `json:"ike_dh_group,omitempty"`
	IKELifetime   int    `json:"ike_lifetime,omitempty"`

	ChildEncryption string `json:"child_encryption,omitempty"`
	ChildIntegrity  string `json:"child_integrity,omitempty"`
	ChildDHGroup    int    `json:"child_dh_group,omitempty"`
	ChildLifetime   int    `json:"child_lifetime,omitempty"`
	// TemplateIKEProposalExact and TemplateESPProposalExact record that the
	// expanded carrier source declares one unambiguous initial proposal. They
	// are internal parser metadata, not negotiated capability claims.
	TemplateIKEProposalExact bool `json:"-"`
	TemplateESPProposalExact bool `json:"-"`
	// Complete ordered source proposals; absent means the bundle did not
	// declare this stage. Errors prohibit silent substitution with defaults.
	TemplateIKEProposals     []string `json:"template_ike_proposals,omitempty"`
	TemplateESPProposals     []string `json:"template_esp_proposals,omitempty"`
	TemplateIKEProposalError string   `json:"template_ike_proposal_error,omitempty"`
	TemplateESPProposalError string   `json:"template_esp_proposal_error,omitempty"`
	// Explicit values remain distinct from historical diagnostic defaults.
	TemplateIKELifetime   int `json:"template_ike_lifetime,omitempty"`
	TemplateChildLifetime int `json:"template_child_lifetime,omitempty"`
	TemplateRekeyPFS      int `json:"template_rekey_pfs,omitempty"`

	NATTKeepalive int `json:"natt_keepalive,omitempty"`
	DPDInterval   int `json:"dpd_interval,omitempty"`
	// DisableDPD mirrors carrier bundles that publish a diagnostic interval
	// while explicitly disabling active IKE DPD probes.
	DisableDPD bool `json:"disable_dpd,omitempty"`

	LocalIdentifier string `json:"local_identifier,omitempty"`
	// EAPIdentityTemplate is the permanent EAP username, distinct from an
	// anonymous IKE local identifier published by certificate-authenticated carriers.
	EAPIdentityTemplate       string `json:"eap_identity_template,omitempty"`
	IMSTransport              string `json:"ims_transport,omitempty"`
	UseIPSec                  bool   `json:"use_ipsec,omitempty"`
	IMSAuthAlgorithm          string `json:"ims_auth_algorithm,omitempty"`
	ValidateRemoteCertificate bool   `json:"validate_remote_certificate,omitempty"`
	RemoteCertificateHostname string `json:"remote_certificate_hostname,omitempty"`
	DisableSwitchToNATTPort   bool   `json:"disable_switch_to_natt_port,omitempty"`

	PCSCF                 []string            `json:"pcscf,omitempty"`
	Bundle                string              `json:"bundle,omitempty"`
	SelectorRaw           string              `json:"selector_raw,omitempty"`
	RegistryRevision      string              `json:"registry_revision,omitempty"`
	RegisterContactParams []string            `json:"register_contact_params,omitempty"`
	RegisterExpires       int                 `json:"register_expires,omitempty"`
	ReRegisterOn          []SIPReRegisterRule `json:"re_register_on,omitempty"`
	// Signaling capabilities from the carrier bundle. Some IMS cores require
	// the P-Early-Media header on originating INVITEs (notably Orange/CTExcel).
	SupportPEarlyMedia    bool `json:"support_p_early_media,omitempty"`
	EarlyMediaNeedsHeader bool `json:"early_media_needs_header,omitempty"`
}

// SIPReRegisterRule retains source status expressions. Runtime support is
// deliberately restricted; a range must never silently become a wildcard.
type SIPReRegisterRule struct {
	Method   string   `yaml:"method" json:"method"`
	Statuses []string `yaml:"statuses" json:"statuses"`
}

func CloneReRegisterRules(source []SIPReRegisterRule) []SIPReRegisterRule {
	if source == nil {
		return nil
	}
	out := make([]SIPReRegisterRule, len(source))
	for i, rule := range source {
		out[i] = rule
		out[i].Statuses = append([]string(nil), rule.Statuses...)
	}
	return out
}

type selector struct {
	profile     Profile
	gid1Prefix  string
	iccidPrefix string
	spn         string
}

// Values are transcribed from ios-carrier-profiles commit 29f5e2f
// (2026-08-24). A PLMN with multiple Apple bundles only gets a constrained
// entry when this application can read the selector field.
var builtinSelectors = map[string][]selector{
	"23410": {
		{profile: profile("apple_o2_giffgaff_uk", "giffgaff UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14), gid1Prefix: "508"},
		{profile: profile("apple_o2_giffgaff_uk", "giffgaff UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14), spn: "giffgaff"},
		{profile: profile("apple_o2_prepaid_uk", "O2 Prepaid UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14), gid1Prefix: "61FFFF"},
		{profile: profile("apple_o2_prepaid_uk", "O2 Prepaid UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14), gid1Prefix: "67FFFF"},
		{profile: profile("apple_o2_prepaid_uk", "O2 Prepaid UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14), gid1Prefix: "85FFFF"},
		{profile: profile("apple_o2_prepaid_uk", "O2 Prepaid UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14), gid1Prefix: "99FFFF"},
		{profile: profile("apple_o2_tesco_uk", "Tesco Mobile UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14), gid1Prefix: "0AFFFF"},
		{profile: profile("apple_o2_uk", "O2 UK", "234", "10", "ipv6", "aes256", "sha512", "sha512", 14)},
	},
	"23415": {
		{profile: profile("apple_talkmobile_uk", "Talkmobile UK", "234", "15", "ipv4", "aes256", "sha256", "sha256", 14), gid1Prefix: "C1"},
		{profile: profile("apple_vodafone_uk", "Vodafone UK", "234", "15", "ipv4", "aes256", "sha256", "sha256", 14)},
	},
	"23420": {{profile: withLocalID(profile("apple_hutchison_uk", "Three UK", "234", "20", "ipv6", "aes128", "sha256", "sha256", 14), "anonymous@nai.epc.mnc020.mcc234.3gppnetwork.org", true)}},
	"23430": {
		{profile: profile("apple_bt_business_uk", "BT Business UK", "234", "30", "ipv6", "aes128", "sha256", "sha256", 14), gid1Prefix: "B3"},
		{profile: profile("apple_bt_consumer_uk", "BT Consumer UK", "234", "30", "ipv6", "aes128", "sha256", "sha256", 14), gid1Prefix: "C3"},
		{profile: profile("apple_bt_onephone_uk", "BT One Phone UK", "234", "30", "ipv6", "aes128", "sha256", "sha256", 14), gid1Prefix: "B2"},
		{profile: profile("apple_tmobile_uk", "EE UK", "234", "30", "ipv6", "aes128", "sha256", "sha256", 14)},
	},
	"23433": {{profile: orangeUK()}},

	"310160": {{profile: tmobileUS("310", "160")}},
	"310200": {{profile: tmobileUS("310", "200")}},
	"310210": {{profile: tmobileUS("310", "210")}},
	"310220": {{profile: tmobileUS("310", "220")}},
	"310230": {{profile: tmobileUS("310", "230")}},
	"310240": {{profile: tmobileUS("310", "240"), gid1Prefix: "54"}},
	"310250": {{profile: tmobileUS("310", "250")}},
	"310260": {{profile: tmobileUS("310", "260"), gid1Prefix: "54"}},
	"310270": {{profile: tmobileUS("310", "270")}},
	"310310": {{profile: tmobileUS("310", "310")}},
	"310490": {{profile: tmobileUS("310", "490")}},
	"310660": {{profile: tmobileUS("310", "660")}},
	"310800": {{profile: tmobileUS("310", "800")}},

	"310030": {{profile: attUS("310", "030")}},
	"310170": {{profile: attUS("310", "170")}},
	"310280": {{profile: attUS("310", "280"), gid1Prefix: "FFFF"}},
	"310410": {{profile: attUS("310", "410"), gid1Prefix: "FFFF"}},
	"310560": {{profile: attUS("310", "560"), gid1Prefix: "FFFF"}},
	"310950": {{profile: attUS("310", "950"), gid1Prefix: "FFFF"}},

	"20404":  {{profile: verizon("204", "04"), iccidPrefix: "891480"}},
	"310590": {{profile: verizon("310", "590")}},
	"310599": {{profile: verizon("310", "599")}},
	"311480": {{profile: verizon("311", "480")}},

	"26201": {{profile: profile("apple_tmobile_germany", "Telekom Germany", "262", "01", "ipv6", "aes256", "sha256", "sha256", 2)}},
	"26202": {{profile: profile("apple_vodafone_de", "Vodafone Germany", "262", "02", "ipv6", "aes256", "sha512", "sha512", 14)}},
	"21407": {{profile: profile("apple_telefonica_es", "Movistar Spain", "214", "07", "ipv6", "aes256", "sha512", "sha512", 14)}},
	"50501": {{profile: withEPDG(profile("apple_telstra_au", "Telstra Australia", "505", "01", "ipv4v6", "aes256", "sha256", "sha256", 14), "epdg.epc.mnc001.mcc505.pub.3gppnetwork.org")}},
	"50503": {{profile: withLocalID(profile("apple_vodafone_au", "Vodafone Australia", "505", "03", "ipv4v6", "aes256", "sha512", "sha512", 14), "vha@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org", true)}},
	"44010": {{profile: profile("apple_docomo_jp", "NTT DOCOMO", "440", "10", "ipv6", "aes128", "sha256", "sha256", 14)}},
	"44020": {{profile: profile("apple_softbank_jp", "SoftBank Japan", "440", "20", "ipv6", "aes128", "sha256", "sha256", 14)}},

	"46000": {{profile: profile("apple_cmcc_cn", "中国移动", "460", "00", "ipv4v6", "aes128", "sha256", "sha256", 14)}},
	"46002": {{profile: profile("apple_cmcc_cn", "中国移动", "460", "02", "ipv4v6", "aes128", "sha256", "sha256", 14)}},
	"46007": {{profile: profile("apple_cmcc_cn", "中国移动", "460", "07", "ipv4v6", "aes128", "sha256", "sha256", 14)}},
	"46008": {{profile: profile("apple_cmcc_cn", "中国移动", "460", "08", "ipv4v6", "aes128", "sha256", "sha256", 14)}},
	"46001": {{profile: profile("apple_unicom_cn", "中国联通", "460", "01", "ipv6", "aes128", "sha256", "sha256", 14)}},
	"46009": {{profile: profile("apple_unicom_cn", "中国联通", "460", "09", "ipv6", "aes128", "sha256", "sha256", 14)}},
	"46003": {{profile: profile("apple_chinatelecom_usim_cn", "中国电信", "460", "03", "ipv6", "aes128", "sha256", "sha256", 14)}},
	"46011": {{profile: profile("apple_chinatelecom_usim_cn", "中国电信", "460", "11", "ipv6", "aes128", "sha256", "sha256", 14)}},
}

func profile(id, name, mcc, mnc, ipStack, enc, integ, prf string, dh int) Profile {
	return Profile{
		ID: id, Name: name, Source: ProfileSourceBuiltin,
		MCC: mcc, MNC: mnc, RouteMCC: mcc, RouteMNC: mnc,
		APN: "ims", IPStack: ipStack,
		IKEEncryption: enc, IKEIntegrity: integ, IKEPRF: prf,
		IKEDHGroup: dh, IKELifetime: 80000,
		ChildEncryption: enc, ChildIntegrity: integ,
		ChildDHGroup: dh, ChildLifetime: 80000,
		NATTKeepalive:   20,
		DPDInterval:     120,
		LocalIdentifier: "0$imsi@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org",
		UseIPSec:        true, IMSAuthAlgorithm: "akav1-md5",
	}
}

func orangeUK() Profile {
	p := profile("apple_orange_uk", "Orange / CTExcel UK", "234", "33", "ipv6", "aes128", "sha256", "sha256", 14)
	// Orange_uk.bundle (ios-carrier-profiles 29f5e2f) publishes a 600s DPD
	// interval and 86400s Child SA lifetime for PLMN 234/33.
	p.DPDInterval = 600
	p.DisableDPD = true
	p.ChildLifetime = 86400
	p.SupportPEarlyMedia = true
	p.EarlyMediaNeedsHeader = true
	return p
}

func withEPDG(p Profile, fqdn string) Profile {
	p.EPDGCandidates = []string{fqdn}
	return p
}

func withLocalID(p Profile, localID string, validateCertificate bool) Profile {
	p.LocalIdentifier = localID
	p.ValidateRemoteCertificate = validateCertificate
	return p
}

func tmobileUS(mcc, mnc string) Profile {
	return withEPDG(profile("apple_tmobile_us", "T-Mobile US", mcc, mnc, "ipv4v6", "aes256", "sha256", "sha256", 14), "ss.epdg.epc.mnc260.mcc310.pub.3gppnetwork.org")
}

func attUS(mcc, mnc string) Profile {
	return withEPDG(profile("apple_att_us", "AT&T US", mcc, mnc, "ipv4v6", "aes128", "sha256", "sha256", 14), "epdg.epc.att.net")
}

func verizon(mcc, mnc string) Profile {
	p := withEPDG(profile("apple_verizon_lte_us", "Verizon US", mcc, mnc, "ipv6", "aes256", "sha256", "sha256", 14), "wo.vzwwo.com")
	p.LocalIdentifier = "anonymous@nai.epc.mnc480.mcc311.3gppnetwork.org"
	p.ValidateRemoteCertificate = true
	p.DisableSwitchToNATTPort = true
	return p
}

// Resolve selects the pinned registry profile. Constrained selectors are
// evaluated before the generic entry, matching ios-carrier-profiles semantics.
// Errors or no match use the standard profile, never the older hand-written
// selector table whose broader prefixes could guess an unsupported MVNO.
func Resolve(sim SIMIdentity) *Profile {
	if embedded, err := resolveEmbeddedProfile(sim); err == nil && embedded != nil {
		return applyUserVoWiFiTemplate(embedded, sim)
	}
	return standardProfile(normalizeDigits(sim.MCC), normalizeDigits(sim.MNC))
}

func ResolveWithError(sim SIMIdentity) (*Profile, error) {
	if embedded, err := resolveEmbeddedProfile(sim); err != nil {
		return nil, err
	} else if embedded != nil {
		return applyUserVoWiFiTemplate(embedded, sim), nil
	}
	return standardProfile(normalizeDigits(sim.MCC), normalizeDigits(sim.MNC)), nil
}

func resolveLegacyBuiltin(sim SIMIdentity) *Profile {
	mcc := normalizeDigits(sim.MCC)
	mnc := normalizeDigits(sim.MNC)
	entries := builtinSelectors[mcc+mnc]
	for _, entry := range entries {
		if entry.gid1Prefix == "" && entry.iccidPrefix == "" && entry.spn == "" {
			continue
		}
		if entry.gid1Prefix != "" && !hasHexPrefix(sim.GID1, entry.gid1Prefix) {
			continue
		}
		if entry.iccidPrefix != "" && !strings.HasPrefix(normalizeDigits(sim.ICCID), normalizeDigits(entry.iccidPrefix)) {
			continue
		}
		if entry.spn != "" && !strings.EqualFold(strings.TrimSpace(sim.SPN), strings.TrimSpace(entry.spn)) {
			continue
		}
		return cloneProfile(entry.profile)
	}
	for _, entry := range entries {
		if entry.gid1Prefix == "" && entry.iccidPrefix == "" && entry.spn == "" {
			return cloneProfile(entry.profile)
		}
	}
	return standardProfile(mcc, mnc)
}

// FromSIM is kept for existing callers that do not have selector metadata.
func FromSIM(mcc, mnc string) *Profile {
	return Resolve(SIMIdentity{MCC: mcc, MNC: mnc})
}

func standardProfile(mcc, mnc string) *Profile {
	p := profile("auto-"+mcc+"-"+mnc, "3GPP Auto ("+mcc+"/"+mnc+")", mcc, mnc, "ipv4v6", "aes128", "sha256", "sha256", 14)
	p.Source = ProfileSourceStandard
	p.ChildLifetime = 86400
	return &p
}

func cloneProfile(p Profile) *Profile {
	p.EPDGCandidates = append([]string(nil), p.EPDGCandidates...)
	p.TemplateIKEProposals = append([]string(nil), p.TemplateIKEProposals...)
	p.TemplateESPProposals = append([]string(nil), p.TemplateESPProposals...)
	p.PCSCF = append([]string(nil), p.PCSCF...)
	p.RegisterContactParams = append([]string(nil), p.RegisterContactParams...)
	p.ReRegisterOn = CloneReRegisterRules(p.ReRegisterOn)
	p.VoWiFiTemplate = p.VoWiFiTemplate.Clone()
	return &p
}

func hasHexPrefix(value, prefix string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	prefix = strings.ToUpper(strings.TrimSpace(prefix))
	return value != "" && prefix != "" && strings.HasPrefix(value, prefix)
}

// IMSDomain returns the registrar realm. ISIM HomeDomain should still take
// precedence at the call site when the card provides it.
func (p *Profile) IMSDomain() string {
	if strings.TrimSpace(p.IMS) != "" {
		return strings.TrimSpace(p.IMS)
	}
	rmnc := normalizeDigits(p.RouteMNC)
	if rmnc == "" {
		rmnc = normalizeDigits(p.MNC)
	}
	rmcc := normalizeDigits(p.RouteMCC)
	if rmcc == "" {
		rmcc = normalizeDigits(p.MCC)
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", pad3(rmnc), pad3(rmcc))
}

// EPDG returns the carrier candidate, or the standard 3GPP FQDN when the
// carrier bundle does not publish a special address.
func (p *Profile) EPDG() string {
	for _, candidate := range p.EPDGCandidates {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			return candidate
		}
	}
	return ConstructEPDGFQDN(p.MCC, p.MNC)
}

// ResolveEPDG applies the required precedence: explicit user value first,
// then carrier template, finally the standard FQDN.
func (p *Profile) ResolveEPDG(custom string) (fqdn, source string) {
	if custom = strings.TrimSpace(custom); custom != "" {
		return custom, "custom"
	}
	if len(p.EPDGCandidates) > 0 && strings.TrimSpace(p.EPDGCandidates[0]) != "" {
		return strings.TrimSpace(p.EPDGCandidates[0]), "carrier-template"
	}
	return ConstructEPDGFQDN(p.MCC, p.MNC), "3gpp-standard"
}

// ExpandLocalIdentifier substitutes the variables used by Apple carrier
// bundles. MNC is padded only inside the NAI/FQDN, never for profile lookup.
func (p *Profile) ExpandLocalIdentifier(imsi string) string {
	localID := strings.TrimSpace(p.LocalIdentifier)
	if localID == "" {
		localID = "0$imsi@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org"
	}
	identity, _ := p.expandIdentity(localID, imsi, "")
	return identity
}

// ExpandEAPIdentity returns only a published username. An absent username
// keeps the transport's normal permanent identity derivation unchanged.
func (p *Profile) ExpandEAPIdentity(imsi string) string {
	identity, _ := p.expandIdentity(strings.TrimSpace(p.EAPIdentityTemplate), imsi, "")
	return identity
}

// EffectiveIMSI implements only reviewed selector transforms. In particular,
// capture has no defined source in the published registry and must not guess
// from the ICCID, current IMSI, or IMPI.
func (p *Profile) EffectiveIMSI(imsi, iccid string) (string, error) {
	switch strings.TrimSpace(p.VoWiFiIMSI) {
	case "":
		return strings.TrimSpace(imsi), nil
	case "23487${iccid[9:19]}":
		iccid = strings.TrimSpace(iccid)
		if len(iccid) < 19 || len(iccid) > 20 || normalizeDigits(iccid) != iccid {
			return "", fmt.Errorf("运营商 VoWiFi IMSI 推导要求完整的 19–20 位数字 ICCID")
		}
		return "23487" + iccid[9:19], nil
	case "capture":
		return "", fmt.Errorf("运营商要求 vowifi_imsi=capture，但未提供可验证的 VoWiFi IMSI 捕获来源")
	default:
		return "", fmt.Errorf("运营商 vowifi_imsi 表达式尚不受支持")
	}
}

// ExpandSessionIdentities is the checked runtime entry point. A missing IMPI
// is an error only for a template that explicitly references $impi_user.
func (p *Profile) ExpandSessionIdentities(imsi, privateIdentity string) (local, eap string, err error) {
	localTemplate := strings.TrimSpace(p.LocalIdentifier)
	if localTemplate == "" {
		localTemplate = "0$imsi@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org"
	}
	local, err = p.expandIdentity(localTemplate, imsi, privateIdentity)
	if err != nil {
		return "", "", err
	}
	eap, err = p.expandIdentity(strings.TrimSpace(p.EAPIdentityTemplate), imsi, privateIdentity)
	if err != nil {
		return "", "", err
	}
	return local, eap, nil
}

func (p *Profile) expandIdentity(value, imsi, privateIdentity string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "$impi_user") {
		if err := ValidatePrivateIdentity(privateIdentity); err != nil {
			return "", fmt.Errorf("运营商 $impi_user 需要有效的实际 ISIM IMPI: %w", err)
		}
		user, _, _ := strings.Cut(privateIdentity, "@")
		value = strings.ReplaceAll(value, "$impi_user", user)
	}
	if strings.Contains(value, "$imsi") && (imsi == "" || normalizeDigits(imsi) != imsi || len(imsi) > 15) {
		return "", fmt.Errorf("运营商身份模板需要有效的数字 IMSI")
	}
	value = strings.NewReplacer("$imsi", imsi, "$mcc", pad3(normalizeDigits(p.MCC)), "$mnc", pad3(normalizeDigits(p.MNC)),
		"$MCC", pad3(normalizeDigits(p.MCC)), "$MNC", pad3(normalizeDigits(p.MNC))).Replace(value)
	if err := ValidatePrivateIdentity(value); err != nil {
		return "", fmt.Errorf("运营商身份模板包含未解析变量或无效身份: %w", err)
	}
	return value, nil
}

// ValidatePrivateIdentity rejects unresolved templates and SIP/control syntax
// without including subscriber identifiers in errors.
func ValidatePrivateIdentity(value string) error {
	user, domain, found := strings.Cut(value, "@")
	if !found || user == "" || len(value) > 253 || strings.ContainsAny(user, "$@<>:;\"\\/?") || !ValidIdentityDomain(domain) {
		return fmt.Errorf("IMPI/NAI 格式无效")
	}
	for _, c := range user {
		if c <= ' ' || c >= 127 {
			return fmt.Errorf("IMPI/NAI 用户部分格式无效")
		}
	}
	return nil
}

func ValidIdentityDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ConstructEPDGFQDN constructs the 3GPP public ePDG name. It intentionally
// performs no DNS resolution; the system resolver/fake-IP pipeline owns that.
func ConstructEPDGFQDN(mcc, mnc string) string {
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", pad3(normalizeDigits(mnc)), pad3(normalizeDigits(mcc)))
}

func pad3(s string) string {
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

func normalizeDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}
