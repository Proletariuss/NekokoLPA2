package mobilecore

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"

	"proletarius.local/core/internal/vowifi"
	"proletarius.local/core/internal/vowifi/carrier"
	"proletarius.local/core/internal/vowifi/policy"
)

const readerProfileSourceOverride = "carrier-override"

// readerVoWiFiEffectiveConfig is a per-session immutable snapshot shared by
// module and PC/SC VoWiFi. Editing the YAML while connected affects only the
// next session.
type readerVoWiFiEffectiveConfig struct {
	Profile         *carrier.Profile
	IMSI            string // session-only VoWiFi identity; the physical card stays unchanged
	OverrideMatched bool
	OverrideID      string

	EPDG                      string
	EPDGPort                  int
	EPDGSource                string
	EPDGCandidates            []string
	RemoteCertificateHostname string
	ValidateRemoteCertificate bool
	APN                       string
	IPStack                   string
	DNSServers                []string // diagnostic only; never used to pre-resolve the ePDG

	NATTKeepaliveSeconds  int
	DPDIntervalSeconds    int
	DisableDPD            bool
	ReauthIntervalSeconds int
	IKELifetimeSeconds    int
	ChildLifetimeSeconds  int
	AlgorithmPolicy       string
	EnableLegacyCiphers   bool
	IKEProposals          []string
	ESPProposals          []string
	IKELocalPort          int
	CPInFinalAuth         bool
	CookiePayloadType     string
	RekeyPFS              int
	AKAChallengeMode      string
	EAPIdentitySource     string
	EAPIdentity           string
	IKELocalIdentifier    string
	AllowPlainIMS         bool
	DeviceModel           string
	DeviceIdentityEnabled bool
	DeviceIdentityIMEI    string

	IMSDomain                     string
	IMSRealm                      string
	IMSPhoneContext               string
	IMSPCSCF                      string
	IMSTransport                  string
	IMSIdentitySource             string
	IMSUserAgent                  string
	IMSLocalPort                  int
	IMSTCPKeepaliveSeconds        int
	IMSOptionsPingIntervalSeconds int
	IMSRegisterTemplate           policy.IMSRegisterTemplate

	E911Enabled            bool
	E911Provider           string
	E911EntitlementURL     string
	E911WebsheetHostPolicy string
}

// resolveSharedVoWiFiEffectiveConfig keeps carrier template selection and
// user overrides identical across the module and PC/SC reader transports.
// Hardware-specific SIM/APDU transport is resolved before this boundary; all
// ePDG, IKE/ESP, IMS, AKA policy and carrier overrides are shared here.
func resolveReaderVoWiFiEffectiveConfig(
	base *carrier.Profile,
	override *carrier.CarrierOverride,
	overrideMatched bool,
	simInfo *vowifi.SIMInfo,
	requestEPDG string,
	requestEPDGPort int,
	generatedIMEI string,
) (*readerVoWiFiEffectiveConfig, error) {
	if base == nil || simInfo == nil {
		return nil, fmt.Errorf("VoWiFi 运营商或 SIM 配置不可用")
	}
	profile := cloneReaderCarrierProfile(base)
	imsi, err := profile.EffectiveIMSI(simInfo.IMSI, simInfo.ICCID)
	if err != nil {
		return nil, err
	}
	domain := strings.TrimSpace(simInfo.HomeDomain)
	if domain == "" {
		domain = profile.IMSDomain()
	}
	apn := strings.TrimSpace(profile.APN)
	if apn == "" {
		apn = "ims"
	}
	ipStack := strings.ToLower(strings.TrimSpace(profile.IPStack))
	if ipStack == "" {
		ipStack = "ipv4v6"
	}
	natt := profile.NATTKeepalive
	if natt <= 0 {
		natt = 20
	}
	dpd := profile.DPDInterval
	if dpd <= 0 {
		dpd = 120
	}
	phoneContext := strings.TrimSpace(profile.CallPhoneContext)
	if phoneContext == "" {
		phoneContext = domain
	}

	effective := &readerVoWiFiEffectiveConfig{
		Profile:                   profile,
		IMSI:                      imsi,
		APN:                       apn,
		IPStack:                   ipStack,
		NATTKeepaliveSeconds:      natt,
		DPDIntervalSeconds:        dpd,
		DisableDPD:                profile.DisableDPD,
		RemoteCertificateHostname: profile.RemoteCertificateHostname,
		ValidateRemoteCertificate: profile.ValidateRemoteCertificate,
		IKELifetimeSeconds:        profile.TemplateIKELifetime,
		ChildLifetimeSeconds:      profile.TemplateChildLifetime,
		RekeyPFS:                  profile.TemplateRekeyPFS,
		AlgorithmPolicy:           "balanced",
		AKAChallengeMode:          "minimal",
		DeviceIdentityEnabled:     true,
		DeviceIdentityIMEI:        strings.TrimSpace(generatedIMEI),
		IMSDomain:                 domain,
		IMSRealm:                  domain,
		IMSPhoneContext:           phoneContext,
		IMSTransport:              "auto",
		IMSIdentitySource:         "derived",
		IMSLocalPort:              5060,
		IMSTCPKeepaliveSeconds:    30,
		// A SIP response validates the complete IKE/ESP/IPsec/IMS path rather
		// than merely proving that a local timer is still running. Together
		// with the 12-second acknowledgement deadline this detects a stale
		// session within 42 seconds in the worst phase alignment.
		IMSOptionsPingIntervalSeconds: 30,
		IMSRegisterTemplate:           policy.TemplateForProfile(profile),
	}
	if transport := strings.TrimSpace(profile.IMSTransport); transport != "" {
		effective.IMSTransport = transport
		effective.IMSRegisterTemplate.Transport = transport
	}
	localIdentity, identity, err := profile.ExpandSessionIdentities(imsi, strings.TrimSpace(simInfo.PrivateIdentity))
	if err != nil {
		return nil, err
	}
	effective.IKELocalIdentifier = localIdentity
	if identity == "" && profile.VoWiFiIMSI != "" {
		// SWu otherwise asks the physical SIM for its IMSI. Keep its default NAI
		// construction, but use the explicitly selected VoWiFi IMSI.
		fallback := *profile
		fallback.EAPIdentityTemplate = "0$imsi@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org"
		_, identity, err = fallback.ExpandSessionIdentities(imsi, strings.TrimSpace(simInfo.PrivateIdentity))
		if err != nil {
			return nil, err
		}
	}
	if identity != "" {
		effective.EAPIdentity = identity
		effective.EAPIdentitySource = "carrier-template"
	}
	if profile.VoWiFiTemplate != nil {
		applyReaderUserVoWiFiTemplate(effective, profile.VoWiFiTemplate)
		if strings.EqualFold(effective.EAPIdentitySource, "isim") {
			identity := strings.TrimSpace(simInfo.PrivateIdentity)
			publicID := strings.TrimSpace(simInfo.PublicIdentity)
			homeDomain := strings.TrimSpace(simInfo.HomeDomain)
			if identity == "" && publicID == "" && homeDomain == "" {
				// Some SIMs don't expose ISIM. Preserve the previously working
				// 0IMSI@nai.epc identity path rather than inventing an identity.
				effective.EAPIdentitySource = "derived"
			} else if identity == "" || publicID == "" || homeDomain == "" || !strings.Contains(identity, "@") || strings.ContainsAny(identity, "\r\n\x00") {
				return nil, fmt.Errorf("3 HK ISIM 身份不完整或格式无效")
			} else {
				effective.EAPIdentity = identity
				effective.IKELocalIdentifier = identity
				effective.IMSIdentitySource = "isim"
				effective.IMSDomain = homeDomain
				effective.IMSRealm = homeDomain
				effective.IMSPhoneContext = homeDomain
			}
		}
	}

	if overrideMatched && override != nil {
		effective.OverrideMatched = true
		applyReaderCarrierOverride(effective, override)
	}

	// Preserve the existing in-app custom ePDG controls as the highest-priority
	// source. They override YAML without changing the rest of the matched preset.
	requestEPDG = strings.TrimSpace(requestEPDG)
	switch {
	case requestEPDG != "":
		effective.EPDG = trimAddressBrackets(requestEPDG)
		effective.EPDGSource = "custom"
	case overrideMatched && override != nil && override.CustomEPDG != nil && strings.TrimSpace(*override.CustomEPDG) != "":
		effective.EPDG = trimAddressBrackets(*override.CustomEPDG)
		effective.EPDGSource = "carrier-override"
	default:
		effective.EPDG, effective.EPDGSource = profile.ResolveEPDG("")
		effective.EPDG = trimAddressBrackets(effective.EPDG)
	}
	effective.EPDGPort = 500
	if overrideMatched && override != nil && override.EPDGPort != nil && *override.EPDGPort > 0 {
		effective.EPDGPort = *override.EPDGPort
	}
	if requestEPDGPort > 0 {
		effective.EPDGPort = requestEPDGPort
	}
	// An explicit address is the complete destination policy. Candidate
	// metadata never allows fallback around the configured proxy or address.
	effective.EPDGCandidates = []string{effective.EPDG}
	if effective.EPDGSource == "carrier-template" {
		effective.EPDGCandidates = append([]string(nil), profile.EPDGCandidates...)
	}

	if effective.EPDG == "" {
		return nil, fmt.Errorf("ePDG 地址为空")
	}
	if effective.EPDGPort < 1 || effective.EPDGPort > 65535 {
		return nil, fmt.Errorf("ePDG 端口无效: %d", effective.EPDGPort)
	}
	if effective.IKEProposals != nil && len(effective.IKEProposals) == 0 {
		return nil, fmt.Errorf("ike_proposals 已显式配置但列表为空")
	}
	if effective.ESPProposals != nil && len(effective.ESPProposals) == 0 {
		return nil, fmt.Errorf("esp_proposals 已显式配置但列表为空")
	}
	if overrideMatched && overrideRequestsAlgorithmDefaults(override) {
		defaultIKE, defaultESP := readerAlgorithmProposals(effective)
		if effective.IKEProposals == nil {
			effective.IKEProposals = defaultIKE
		}
		if effective.ESPProposals == nil {
			effective.ESPProposals = defaultESP
		}
	} else {
		if effective.IKEProposals == nil && profile.TemplateIKEProposalError != "" {
			return nil, fmt.Errorf("运营商 IKE proposal 无法表达: %s", profile.TemplateIKEProposalError)
		}
		if effective.ESPProposals == nil && profile.TemplateESPProposalError != "" {
			return nil, fmt.Errorf("运营商 ESP proposal 无法表达: %s", profile.TemplateESPProposalError)
		}
		if effective.IKEProposals == nil && len(profile.TemplateIKEProposals) > 0 {
			effective.IKEProposals = append([]string(nil), profile.TemplateIKEProposals...)
		}
		if effective.ESPProposals == nil && len(profile.TemplateESPProposals) > 0 {
			effective.ESPProposals = append([]string(nil), profile.TemplateESPProposals...)
		}
		// A user-supplied proposal list is authoritative. When no proposal,
		// algorithm policy, or legacy-default request exists, prefer an exact
		// carrier template only if the embedded source proves that our runtime
		// can express its complete initial IKE/ESP transform set.
		if templateIKE, templateESP, ok := carrierTemplateProposals(profile); ok {
			if effective.IKEProposals == nil {
				effective.IKEProposals = templateIKE
			}
			if effective.ESPProposals == nil {
				effective.ESPProposals = templateESP
			}
		}
	}
	if _, err := ikev2.BuildIKEProposals(effective.IKEProposals, nil); err != nil {
		return nil, fmt.Errorf("IKE proposal 配置无效: %w", err)
	}
	if _, err := ikev2.BuildESPProposals(effective.ESPProposals, []byte{0, 0, 0, 1}); err != nil {
		return nil, fmt.Errorf("ESP proposal 配置无效: %w", err)
	}
	if effective.IMSPCSCF != "" {
		normalized, err := normalizeReaderPCSCF(effective.IMSPCSCF)
		if err != nil {
			return nil, err
		}
		effective.IMSPCSCF = normalized
	}
	if effective.DeviceIdentityEnabled {
		if err := validateReaderIMEI(effective.DeviceIdentityIMEI); err != nil {
			return nil, err
		}
	} else {
		effective.DeviceIdentityIMEI = ""
	}
	if !carrier.ValidIdentityDomain(effective.IMSDomain) || !carrier.ValidIdentityDomain(effective.IMSRealm) || strings.ContainsAny(effective.IMSPhoneContext, "$\r\n\x00\t ") {
		return nil, fmt.Errorf("IMS 域或 phone-context 格式无效或包含未解析变量")
	}
	if err := carrier.ValidatePrivateIdentity(effective.IKELocalIdentifier); err != nil {
		return nil, fmt.Errorf("IKE 本地身份无效: %w", err)
	}
	if effective.EAPIdentity != "" {
		if err := carrier.ValidatePrivateIdentity(effective.EAPIdentity); err != nil {
			return nil, fmt.Errorf("EAP 身份无效: %w", err)
		}
	}
	return effective, nil
}

// applyReaderUserVoWiFiTemplate maps the reviewed Switch user-template
// contract onto the iOS Go runtime before per-carrier YAML is merged.
func applyReaderUserVoWiFiTemplate(effective *readerVoWiFiEffectiveConfig, source *carrier.VoWiFiTemplate) {
	if effective == nil || source == nil {
		return
	}
	effective.APN = source.IKE.APN
	effective.IPStack = source.IKE.IPStack
	effective.ReauthIntervalSeconds = source.IKE.ReauthInterval
	effective.IKEProposals = append([]string(nil), source.IKE.Proposals...)
	effective.ESPProposals = append([]string(nil), source.IKE.ESPProposals...)
	effective.IKELocalPort = source.IKE.LocalPort
	effective.CPInFinalAuth = source.IKE.CPInFinalAuth
	effective.CookiePayloadType = source.IKE.CookiePayloadType
	effective.RekeyPFS = source.IKE.RekeyPFS
	effective.AKAChallengeMode = source.EAP.ChallengeMode
	effective.EAPIdentitySource = source.EAP.IdentitySource
	effective.IMSUserAgent = source.IMS.UserAgent
	effective.AllowPlainIMS = source.IMS.AllowPlainIMSTransport

	template := &effective.IMSRegisterTemplate
	ims := source.IMS
	template.ID = source.ID
	template.InitialAuthorization = ims.InitialAuthorization
	template.SecAgreeMode = ims.SecAgreeMode
	if strings.EqualFold(template.SecAgreeMode, "off") {
		template.SecAgreeMode = "disabled"
	}
	template.Expires = ims.Expires
	template.Transport = ims.TransportMode
	template.SupportedHeader = ims.SupportedHeader
	template.AllowHeader = ims.AllowHeader
	template.ContactFeatures = ims.ContactFeatures
	template.AllowPlainIMS = ims.AllowPlainIMSTransport
	template.IncludePANI = ims.IncludePANI
	template.IncludePANIAuthenticated = ims.IncludePANIAuthenticated
	template.IncludePAccessNetworkInfo = ims.IncludePAccessNetworkInfo
	template.StrictSecurityServerOffer = ims.StrictSecurityServerOffer
	template.ContactParamOrder = []string{"access_type", "sip_instance", "audio", "smsip", "icsi_ref"}
	template.RegisterPolicy = policy.IMSRegisterPolicy{
		ID:                               ims.RegisterPolicy.ID,
		TemporaryStatusCodes:             cloneReaderStatusCodes(ims.RegisterPolicy.TemporaryStatusCodes),
		ForbiddenStatusCodes:             cloneReaderStatusCodes(ims.RegisterPolicy.ForbiddenStatusCodes),
		InitialRejectFallbackStatusCodes: cloneReaderStatusCodes(ims.RegisterPolicy.InitialRejectFallbackStatusCodes),
	}
	template.EnableInitialRejectFallback = len(ims.RegisterPolicy.InitialRejectFallbackStatusCodes) > 0
	template.SecurityClientMechanisms = make([]policy.IPSec3GPPSecurityMechanism, len(ims.SecurityClientMechanisms))
	for i, mechanism := range ims.SecurityClientMechanisms {
		template.SecurityClientMechanisms[i] = policy.IPSec3GPPSecurityMechanism{
			Alg: mechanism.Alg, EAlg: mechanism.EAlg, Prot: mechanism.Prot, Mode: mechanism.Mode,
		}
	}
}

func applyReaderCarrierOverride(effective *readerVoWiFiEffectiveConfig, override *carrier.CarrierOverride) {
	if override.ID != nil {
		effective.OverrideID = strings.TrimSpace(*override.ID)
		if effective.OverrideID != "" {
			effective.Profile.ID = effective.OverrideID
		}
	}
	effective.Profile.Source = readerProfileSourceOverride
	if override.APN != nil && strings.TrimSpace(*override.APN) != "" {
		effective.APN = strings.TrimSpace(*override.APN)
	}
	if override.IPStack != nil {
		effective.IPStack = *override.IPStack
	}
	if override.DNSServers != nil {
		effective.DNSServers = append([]string(nil), (*override.DNSServers)...)
	}
	if override.NATKeepaliveSeconds != nil {
		effective.NATTKeepaliveSeconds = *override.NATKeepaliveSeconds
	}
	if override.DPDIntervalSeconds != nil {
		effective.DPDIntervalSeconds = *override.DPDIntervalSeconds
		// An explicit custom interval is an explicit request to run DPD and
		// therefore overrides a built-in carrier's disabled flag.
		effective.DisableDPD = false
	}
	if override.ReauthIntervalSeconds != nil && *override.ReauthIntervalSeconds > 0 {
		effective.ReauthIntervalSeconds = *override.ReauthIntervalSeconds
	}
	if override.AlgorithmPolicy != nil {
		effective.AlgorithmPolicy = *override.AlgorithmPolicy
	}
	if override.EnableLegacyCiphers != nil {
		effective.EnableLegacyCiphers = *override.EnableLegacyCiphers
	}
	if override.IKEProposals != nil {
		effective.IKEProposals = append([]string(nil), (*override.IKEProposals)...)
		if len(*override.IKEProposals) == 0 {
			effective.IKEProposals = make([]string, 0)
		}
	}
	if override.ESPProposals != nil {
		effective.ESPProposals = append([]string(nil), (*override.ESPProposals)...)
		if len(*override.ESPProposals) == 0 {
			effective.ESPProposals = make([]string, 0)
		}
	}
	if override.AKAChallengeMode != nil {
		effective.AKAChallengeMode = *override.AKAChallengeMode
	}
	if override.DeviceModel != nil {
		effective.DeviceModel = strings.TrimSpace(*override.DeviceModel)
	}
	if override.DeviceIdentityEnabled != nil {
		effective.DeviceIdentityEnabled = *override.DeviceIdentityEnabled
	}
	if override.DeviceIdentityIMEI != nil && strings.TrimSpace(*override.DeviceIdentityIMEI) != "" {
		effective.DeviceIdentityIMEI = strings.TrimSpace(*override.DeviceIdentityIMEI)
	}
	if override.IMSDomain != nil && strings.TrimSpace(*override.IMSDomain) != "" {
		effective.IMSDomain = strings.TrimSpace(*override.IMSDomain)
	}
	if override.IMSRealm != nil && strings.TrimSpace(*override.IMSRealm) != "" {
		effective.IMSRealm = strings.TrimSpace(*override.IMSRealm)
	} else if override.IMSDomain != nil && strings.TrimSpace(*override.IMSDomain) != "" {
		effective.IMSRealm = effective.IMSDomain
	}
	if override.IMSPhoneContext != nil && strings.TrimSpace(*override.IMSPhoneContext) != "" {
		effective.IMSPhoneContext = strings.TrimSpace(*override.IMSPhoneContext)
	}
	if override.IMSPCSCF != nil && strings.TrimSpace(*override.IMSPCSCF) != "" {
		effective.IMSPCSCF = strings.TrimSpace(*override.IMSPCSCF)
	}
	if override.IMSTransport != nil {
		effective.IMSTransport = *override.IMSTransport
	}
	if override.IMSIdentitySource != nil {
		effective.IMSIdentitySource = *override.IMSIdentitySource
	}
	if override.IMSLocalPort != nil {
		effective.IMSLocalPort = *override.IMSLocalPort
	}
	if override.IMSTCPKeepaliveSeconds != nil {
		effective.IMSTCPKeepaliveSeconds = *override.IMSTCPKeepaliveSeconds
	}
	if override.IMSOptionsPingIntervalSeconds != nil {
		effective.IMSOptionsPingIntervalSeconds = *override.IMSOptionsPingIntervalSeconds
	}
	mergeReaderRegisterTemplate(&effective.IMSRegisterTemplate, override.IMSRegisterTemplate)
	if override.E911 != nil {
		if override.E911.Enabled != nil {
			effective.E911Enabled = *override.E911.Enabled
		}
		if override.E911.Provider != nil {
			effective.E911Provider = strings.TrimSpace(*override.E911.Provider)
		}
		if override.E911.EntitlementURL != nil {
			effective.E911EntitlementURL = strings.TrimSpace(*override.E911.EntitlementURL)
		}
		if override.E911.WebsheetHostPolicy != nil {
			effective.E911WebsheetHostPolicy = strings.TrimSpace(*override.E911.WebsheetHostPolicy)
		}
	}
}

func mergeReaderRegisterTemplate(target *policy.IMSRegisterTemplate, source *carrier.IMSRegisterTemplateOverride) {
	if target == nil || source == nil {
		return
	}
	if source.ID != nil {
		target.ID = *source.ID
	}
	if source.Expires != nil && *source.Expires > 0 {
		target.Expires = *source.Expires
	}
	if source.ContactMode != nil {
		target.ContactMode = *source.ContactMode
	}
	if source.SecAgreeMode != nil {
		target.SecAgreeMode = *source.SecAgreeMode
	}
	if source.SupportedHeader != nil {
		target.SupportedHeader = *source.SupportedHeader
	}
	if source.AccessType != nil {
		target.AccessType = *source.AccessType
	}
	if source.ContactParamOrder != nil {
		target.ContactParamOrder = append([]string(nil), (*source.ContactParamOrder)...)
		if len(*source.ContactParamOrder) == 0 {
			target.ContactParamOrder = make([]string, 0)
		}
	}
	if source.IncludePANIAuthenticated != nil {
		target.IncludePANIAuthenticated = *source.IncludePANIAuthenticated
	}
	if source.StrictSecurityServerOffer != nil {
		target.StrictSecurityServerOffer = *source.StrictSecurityServerOffer
	}
	if source.EnableInitialRejectFallback != nil {
		target.EnableInitialRejectFallback = *source.EnableInitialRejectFallback
	}
	if source.SecurityClientMechanisms != nil {
		target.SecurityClientMechanisms = make([]policy.IPSec3GPPSecurityMechanism, 0, len(*source.SecurityClientMechanisms))
		for _, mechanism := range *source.SecurityClientMechanisms {
			target.SecurityClientMechanisms = append(target.SecurityClientMechanisms, policy.IPSec3GPPSecurityMechanism{
				Alg: readerStringValue(mechanism.Alg), EAlg: readerStringValue(mechanism.EAlg),
				Prot: readerStringValue(mechanism.Prot), Mode: readerStringValue(mechanism.Mode),
			})
		}
	}
	if source.RegisterPolicy != nil {
		registerPolicy := source.RegisterPolicy
		if registerPolicy.TemporaryStatusCodes != nil {
			target.RegisterPolicy.TemporaryStatusCodes = cloneReaderStatusCodes(*registerPolicy.TemporaryStatusCodes)
		}
		if registerPolicy.ForbiddenStatusCodes != nil {
			target.RegisterPolicy.ForbiddenStatusCodes = cloneReaderStatusCodes(*registerPolicy.ForbiddenStatusCodes)
		}
		if registerPolicy.InitialRejectFallbackStatusCodes != nil {
			target.RegisterPolicy.InitialRejectFallbackStatusCodes = cloneReaderStatusCodes(*registerPolicy.InitialRejectFallbackStatusCodes)
		}
		if registerPolicy.TemporaryRetrySeconds != nil {
			target.RegisterPolicy.TemporaryRetrySeconds = *registerPolicy.TemporaryRetrySeconds
		}
	}
}

func resolveReaderIMSIdentities(effective *readerVoWiFiEffectiveConfig, simInfo *vowifi.SIMInfo) (impi, impu string, err error) {
	if effective == nil || simInfo == nil {
		return "", "", fmt.Errorf("IMS 身份配置不可用")
	}
	privateID := strings.TrimSpace(simInfo.PrivateIdentity)
	publicID := strings.TrimSpace(simInfo.PublicIdentity)
	validateISIM := func() error {
		if err := carrier.ValidatePrivateIdentity(privateID); err != nil {
			return fmt.Errorf("ISIM IMPI 格式无效: %w", err)
		}
		if strings.ContainsAny(publicID, "$\r\n\x00\t ") {
			return fmt.Errorf("ISIM IMPU 格式无效或包含未解析变量")
		}
		return nil
	}
	switch effective.IMSIdentitySource {
	case "isim":
		if privateID == "" || publicID == "" {
			return "", "", fmt.Errorf("ims_identity_source=isim，但卡片没有完整 IMPI/IMPU")
		}
		if err := validateISIM(); err != nil {
			return "", "", err
		}
		return privateID, publicID, nil
	case "auto":
		if privateID != "" && publicID != "" {
			if err := validateISIM(); err != nil {
				return "", "", err
			}
			return privateID, publicID, nil
		}
		if privateID != "" || publicID != "" {
			return "", "", fmt.Errorf("ISIM 身份不完整：IMPI/IMPU 必须同时存在")
		}
	case "derived":
	default:
		return "", "", fmt.Errorf("不支持的 IMS 身份来源 %q", effective.IMSIdentitySource)
	}
	imsi := effective.IMSI
	if imsi == "" {
		// Compatibility for callers constructing an effective config directly.
		imsi = strings.TrimSpace(simInfo.IMSI)
	}
	if imsi == "" || !carrier.ValidIdentityDomain(effective.IMSDomain) || !carrier.ValidIdentityDomain(effective.IMSRealm) {
		return "", "", fmt.Errorf("无法从 IMSI/IMS 域推导 IMS 身份")
	}
	privateID = fmt.Sprintf("%s@%s", imsi, effective.IMSRealm)
	if err := carrier.ValidatePrivateIdentity(privateID); err != nil {
		return "", "", fmt.Errorf("推导 IMS 身份无效: %w", err)
	}
	return privateID, fmt.Sprintf("sip:%s@%s", imsi, effective.IMSDomain), nil
}

func validateReaderVoWiFiStartCapabilities(effective *readerVoWiFiEffectiveConfig) error {
	if effective == nil {
		return fmt.Errorf("VoWiFi 配置不可用")
	}
	if effective.RekeyPFS != 0 {
		if effective.RekeyPFS < 0 || effective.RekeyPFS > 65535 {
			return fmt.Errorf("无效的 CHILD_SA PFS group: %d", effective.RekeyPFS)
		}
		if _, err := crypto.NewDiffieHellman(uint16(effective.RekeyPFS)); err != nil {
			return fmt.Errorf("CHILD_SA PFS group %d 尚不受支持: %w", effective.RekeyPFS, err)
		}
	}
	switch strings.ToLower(strings.TrimSpace(effective.IMSTransport)) {
	case "", "auto", "tcp", "udp":
	default:
		return fmt.Errorf("不支持的 ims_transport=%q；支持 auto、tcp、udp", effective.IMSTransport)
	}
	if effective.E911Enabled {
		return fmt.Errorf("E911 provider %q 尚未实现，已拒绝伪装成启用状态", effective.E911Provider)
	}
	return nil
}

func normalizeReaderPCSCF(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), "5060"), nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("ims_pcscf %q 必须是隧道内数字 IP，可选端口", value)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "", fmt.Errorf("ims_pcscf %q 不能触发宿主机 DNS；请填写隧道内数字 IP 或留空采用 ePDG 下发值", value)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("ims_pcscf 端口无效: %q", portText)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func validateReaderIMEI(imei string) error {
	imei = strings.TrimSpace(imei)
	if len(imei) != 15 {
		return fmt.Errorf("device_identity_imei 必须是 15 位有效 IMEI")
	}
	for _, digit := range imei {
		if digit < '0' || digit > '9' {
			return fmt.Errorf("device_identity_imei 必须是 15 位有效 IMEI")
		}
	}
	if luhnChecksum(imei[:14]) != int(imei[14]-'0') {
		return fmt.Errorf("device_identity_imei 的 Luhn 校验位无效")
	}
	return nil
}

func readerAlgorithmProposals(effective *readerVoWiFiEffectiveConfig) (ike, esp []string) {
	modernIKE := []string{
		"aes256-sha512-prfsha512-modp2048",
		"aes256-sha256-prfsha256-modp2048",
		"aes128-sha256-prfsha256-modp2048",
		"aes256gcm16-prfsha384-modp2048",
		"aes128gcm16-prfsha256-modp2048",
	}
	modernESP := []string{"aes256-sha512", "aes256-sha256", "aes128-sha256", "aes256gcm16", "aes128gcm16"}
	legacyIKE := []string{"aes128-sha1-prfsha1-modp2048"}
	legacyESP := []string{"aes128-sha1"}
	if !effective.EnableLegacyCiphers {
		return modernIKE, modernESP
	}
	if effective.AlgorithmPolicy == "legacy_prefer" {
		return append(legacyIKE, modernIKE...), append(legacyESP, modernESP...)
	}
	return append(modernIKE, legacyIKE...), append(modernESP, legacyESP...)
}

// carrierTemplateProposals converts only complete, single-transform carrier
// templates that the current Go IKE runtime can represent without changing a
// DH group. It intentionally returns false for multi-transform templates,
// non-DH14 groups, AEAD suites, and hashes outside the implemented SHA-2 set;
// those profiles retain the pre-existing generic proposal behavior.
func carrierTemplateProposals(profile *carrier.Profile) (ike, esp []string, ok bool) {
	if profile == nil || !profile.TemplateIKEProposalExact || !profile.TemplateESPProposalExact {
		return nil, nil, false
	}
	if profile.IKEDHGroup != 14 {
		return nil, nil, false
	}

	ikeEncryption := strings.ToLower(strings.TrimSpace(profile.IKEEncryption))
	ikeIntegrity := strings.ToLower(strings.TrimSpace(profile.IKEIntegrity))
	ikePRF := strings.ToLower(strings.TrimSpace(profile.IKEPRF))
	espEncryption := strings.ToLower(strings.TrimSpace(profile.ChildEncryption))
	espIntegrity := strings.ToLower(strings.TrimSpace(profile.ChildIntegrity))
	if !isCarrierTemplateAESCBC(ikeEncryption) || !isCarrierTemplateAESCBC(espEncryption) ||
		!isCarrierTemplateSHA2(ikeIntegrity) || !isCarrierTemplateSHA2(espIntegrity) ||
		!isCarrierTemplateSHA2(ikePRF) {
		return nil, nil, false
	}

	return []string{fmt.Sprintf("%s-%s-prf%s-modp2048", ikeEncryption, ikeIntegrity, ikePRF)},
		[]string{fmt.Sprintf("%s-%s", espEncryption, espIntegrity)}, true
}

func isCarrierTemplateAESCBC(value string) bool {
	return value == "aes128" || value == "aes256"
}

func isCarrierTemplateSHA2(value string) bool {
	return value == "sha256" || value == "sha512"
}

func overrideRequestsAlgorithmDefaults(override *carrier.CarrierOverride) bool {
	return override != nil && (override.AlgorithmPolicy != nil || override.EnableLegacyCiphers != nil)
}

func cloneReaderCarrierProfile(source *carrier.Profile) *carrier.Profile {
	cloned := *source
	cloned.EPDGCandidates = append([]string(nil), source.EPDGCandidates...)
	cloned.TemplateIKEProposals = append([]string(nil), source.TemplateIKEProposals...)
	cloned.TemplateESPProposals = append([]string(nil), source.TemplateESPProposals...)
	cloned.PCSCF = append([]string(nil), source.PCSCF...)
	cloned.RegisterContactParams = append([]string(nil), source.RegisterContactParams...)
	cloned.ReRegisterOn = carrier.CloneReRegisterRules(source.ReRegisterOn)
	return &cloned
}

func trimAddressBrackets(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	return value
}

func readerStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func cloneReaderStatusCodes(source []int) []int {
	if len(source) == 0 {
		return make([]int, 0)
	}
	return append([]int(nil), source...)
}
