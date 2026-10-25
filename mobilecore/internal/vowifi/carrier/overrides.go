package carrier

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// OverrideFile is the strict on-disk carrier override document. Optional
// values deliberately use pointers throughout so callers can distinguish an
// omitted value from an explicit false, zero, empty string, or empty list.
type OverrideFile struct {
	CarrierOverrides map[string]*CarrierOverride `yaml:"carrier_overrides" json:"carrier_overrides"`
}

// CarrierOverride contains every reader VoWiFi setting that may replace a
// built-in carrier value. Slices are pointers because an explicit [] means
// "replace the built-in list with no entries", while nil means "inherit".
type CarrierOverride struct {
	ID         *string `yaml:"id,omitempty" json:"id,omitempty"`
	CustomEPDG *string `yaml:"custom_epdg,omitempty" json:"custom_epdg,omitempty"`
	EPDGPort   *int    `yaml:"epdg_port,omitempty" json:"epdg_port,omitempty"`
	APN        *string `yaml:"apn,omitempty" json:"apn,omitempty"`
	IPStack    *string `yaml:"ip_stack,omitempty" json:"ip_stack,omitempty"`

	DNSServers                    *[]string `yaml:"dns_servers,omitempty" json:"dns_servers,omitempty"`
	NATKeepaliveSeconds           *int      `yaml:"nat_keepalive_seconds,omitempty" json:"nat_keepalive_seconds,omitempty"`
	DPDIntervalSeconds            *int      `yaml:"dpd_interval_seconds,omitempty" json:"dpd_interval_seconds,omitempty"`
	ReauthIntervalSeconds         *int      `yaml:"reauth_interval_seconds,omitempty" json:"reauth_interval_seconds,omitempty"`
	AlgorithmPolicy               *string   `yaml:"algorithm_policy,omitempty" json:"algorithm_policy,omitempty"`
	EnableLegacyCiphers           *bool     `yaml:"enable_legacy_ciphers,omitempty" json:"enable_legacy_ciphers,omitempty"`
	IKEProposals                  *[]string `yaml:"ike_proposals,omitempty" json:"ike_proposals,omitempty"`
	ESPProposals                  *[]string `yaml:"esp_proposals,omitempty" json:"esp_proposals,omitempty"`
	AKAChallengeMode              *string   `yaml:"aka_challenge_mode,omitempty" json:"aka_challenge_mode,omitempty"`
	DeviceModel                   *string   `yaml:"device_model,omitempty" json:"device_model,omitempty"`
	DeviceIdentityEnabled         *bool     `yaml:"device_identity_enabled,omitempty" json:"device_identity_enabled,omitempty"`
	DeviceIdentityIMEI            *string   `yaml:"device_identity_imei,omitempty" json:"device_identity_imei,omitempty"`
	IMSDomain                     *string   `yaml:"ims_domain,omitempty" json:"ims_domain,omitempty"`
	IMSRealm                      *string   `yaml:"ims_realm,omitempty" json:"ims_realm,omitempty"`
	IMSPhoneContext               *string   `yaml:"ims_phone_context,omitempty" json:"ims_phone_context,omitempty"`
	IMSPCSCF                      *string   `yaml:"ims_pcscf,omitempty" json:"ims_pcscf,omitempty"`
	IMSTransport                  *string   `yaml:"ims_transport,omitempty" json:"ims_transport,omitempty"`
	IMSIdentitySource             *string   `yaml:"ims_identity_source,omitempty" json:"ims_identity_source,omitempty"`
	IMSLocalPort                  *int      `yaml:"ims_local_port,omitempty" json:"ims_local_port,omitempty"`
	IMSTCPKeepaliveSeconds        *int      `yaml:"ims_tcp_keepalive_seconds,omitempty" json:"ims_tcp_keepalive_seconds,omitempty"`
	IMSOptionsPingIntervalSeconds *int      `yaml:"ims_options_ping_interval_seconds,omitempty" json:"ims_options_ping_interval_seconds,omitempty"`

	IMSRegisterTemplate *IMSRegisterTemplateOverride `yaml:"ims_register_template,omitempty" json:"ims_register_template,omitempty"`
	E911                *E911Override                `yaml:"e911,omitempty" json:"e911,omitempty"`
}

// IMSRegisterTemplateOverride controls handset-style IMS REGISTER behavior.
type IMSRegisterTemplateOverride struct {
	ID                          *string                    `yaml:"id,omitempty" json:"id,omitempty"`
	Expires                     *int                       `yaml:"expires,omitempty" json:"expires,omitempty"`
	ContactMode                 *string                    `yaml:"contact_mode,omitempty" json:"contact_mode,omitempty"`
	SecAgreeMode                *string                    `yaml:"sec_agree_mode,omitempty" json:"sec_agree_mode,omitempty"`
	SupportedHeader             *string                    `yaml:"supported_header,omitempty" json:"supported_header,omitempty"`
	AccessType                  *string                    `yaml:"access_type,omitempty" json:"access_type,omitempty"`
	ContactParamOrder           *[]string                  `yaml:"contact_param_order,omitempty" json:"contact_param_order,omitempty"`
	IncludePANIAuthenticated    *bool                      `yaml:"include_pani_authenticated,omitempty" json:"include_pani_authenticated,omitempty"`
	StrictSecurityServerOffer   *bool                      `yaml:"strict_security_server_offer,omitempty" json:"strict_security_server_offer,omitempty"`
	EnableInitialRejectFallback *bool                      `yaml:"enable_initial_reject_fallback,omitempty" json:"enable_initial_reject_fallback,omitempty"`
	SecurityClientMechanisms    *[]SecurityClientMechanism `yaml:"security_client_mechanisms,omitempty" json:"security_client_mechanisms,omitempty"`
	RegisterPolicy              *IMSRegisterPolicyOverride `yaml:"register_policy,omitempty" json:"register_policy,omitempty"`
}

// SecurityClientMechanism is one ipsec-3gpp Security-Client offer.
type SecurityClientMechanism struct {
	Alg  *string `yaml:"alg,omitempty" json:"alg,omitempty"`
	EAlg *string `yaml:"ealg,omitempty" json:"ealg,omitempty"`
	Prot *string `yaml:"prot,omitempty" json:"prot,omitempty"`
	Mode *string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// IMSRegisterPolicyOverride controls retry and fallback handling for REGISTER.
type IMSRegisterPolicyOverride struct {
	TemporaryStatusCodes             *[]int `yaml:"temporary_status_codes,omitempty" json:"temporary_status_codes,omitempty"`
	ForbiddenStatusCodes             *[]int `yaml:"forbidden_status_codes,omitempty" json:"forbidden_status_codes,omitempty"`
	InitialRejectFallbackStatusCodes *[]int `yaml:"initial_reject_fallback_status_codes,omitempty" json:"initial_reject_fallback_status_codes,omitempty"`
	TemporaryRetrySeconds            *int   `yaml:"temporary_retry_seconds,omitempty" json:"temporary_retry_seconds,omitempty"`
}

// E911Override contains carrier entitlement settings. EntitlementURL is
// syntactically validated only; loading this file never performs DNS or any
// network request.
type E911Override struct {
	Enabled            *bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Provider           *string `yaml:"provider,omitempty" json:"provider,omitempty"`
	EntitlementURL     *string `yaml:"entitlement_url,omitempty" json:"entitlement_url,omitempty"`
	WebsheetHostPolicy *string `yaml:"websheet_host_policy,omitempty" json:"websheet_host_policy,omitempty"`
}

// OverrideSet is an immutable, normalized lookup table. Match returns a deep
// copy, so a session may safely apply or edit its result without affecting
// later reader sessions.
type OverrideSet struct {
	byPLMN map[string]*CarrierOverride
}

// EmptyOverrideSet returns a usable override set with no entries.
func EmptyOverrideSet() *OverrideSet {
	return &OverrideSet{byPLMN: make(map[string]*CarrierOverride)}
}

// LoadOverrides decodes one strict YAML document rooted at carrier_overrides.
// Unknown fields and additional YAML documents are rejected.
func LoadOverrides(data []byte) (*OverrideSet, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var file OverrideFile
	if err := decoder.Decode(&file); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("carrier overrides: empty YAML document")
		}
		return nil, fmt.Errorf("carrier overrides: decode YAML: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("carrier overrides: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("carrier overrides: decode trailing YAML: %w", err)
	}
	if file.CarrierOverrides == nil {
		return nil, fmt.Errorf("carrier overrides: root field carrier_overrides is required")
	}

	result := EmptyOverrideSet()
	keys := make([]string, 0, len(file.CarrierOverrides))
	for key := range file.CarrierOverrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, sourceKey := range keys {
		canonical, err := normalizePLMNKey(sourceKey)
		if err != nil {
			return nil, fmt.Errorf("carrier overrides: key %q: %w", sourceKey, err)
		}
		if _, exists := result.byPLMN[canonical]; exists {
			return nil, fmt.Errorf("carrier overrides: key %q duplicates normalized PLMN %q", sourceKey, canonical)
		}
		override := file.CarrierOverrides[sourceKey]
		if override == nil {
			return nil, fmt.Errorf("carrier overrides: key %q has a null override", sourceKey)
		}
		cloned := override.Clone()
		if err := cloned.normalizeAndValidate(); err != nil {
			return nil, fmt.Errorf("carrier overrides: key %q: %w", sourceKey, err)
		}
		result.byPLMN[canonical] = cloned
	}
	return result, nil
}

// LoadOverridesFile reads and validates an override file. A missing path is
// reported to the caller; use EmptyOverrideSet when overrides are optional.
func LoadOverridesFile(path string) (*OverrideSet, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("carrier overrides: file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("carrier overrides: read %q: %w", path, err)
	}
	set, err := LoadOverrides(data)
	if err != nil {
		return nil, fmt.Errorf("carrier overrides: load %q: %w", path, err)
	}
	return set, nil
}

// Match finds an override for an MCC/MNC pair. Two- and three-digit forms of
// the same MNC compare equally (for example, 33 and 033). Invalid PLMN input
// simply does not match.
func (set *OverrideSet) Match(mcc, mnc string) (*CarrierOverride, bool) {
	if set == nil {
		return nil, false
	}
	key, err := canonicalPLMN(mcc, mnc)
	if err != nil {
		return nil, false
	}
	override, ok := set.byPLMN[key]
	if !ok || override == nil {
		return nil, false
	}
	return override.Clone(), true
}

// Len returns the number of normalized PLMN entries.
func (set *OverrideSet) Len() int {
	if set == nil {
		return 0
	}
	return len(set.byPLMN)
}

// Clone returns a complete copy of an override, preserving presence and the
// distinction between nil and explicitly empty slices.
func (override *CarrierOverride) Clone() *CarrierOverride {
	if override == nil {
		return nil
	}
	cloned := *override
	cloned.ID = clonePointer(override.ID)
	cloned.CustomEPDG = clonePointer(override.CustomEPDG)
	cloned.EPDGPort = clonePointer(override.EPDGPort)
	cloned.APN = clonePointer(override.APN)
	cloned.IPStack = clonePointer(override.IPStack)
	cloned.DNSServers = cloneSlicePointer(override.DNSServers)
	cloned.NATKeepaliveSeconds = clonePointer(override.NATKeepaliveSeconds)
	cloned.DPDIntervalSeconds = clonePointer(override.DPDIntervalSeconds)
	cloned.ReauthIntervalSeconds = clonePointer(override.ReauthIntervalSeconds)
	cloned.AlgorithmPolicy = clonePointer(override.AlgorithmPolicy)
	cloned.EnableLegacyCiphers = clonePointer(override.EnableLegacyCiphers)
	cloned.IKEProposals = cloneSlicePointer(override.IKEProposals)
	cloned.ESPProposals = cloneSlicePointer(override.ESPProposals)
	cloned.AKAChallengeMode = clonePointer(override.AKAChallengeMode)
	cloned.DeviceModel = clonePointer(override.DeviceModel)
	cloned.DeviceIdentityEnabled = clonePointer(override.DeviceIdentityEnabled)
	cloned.DeviceIdentityIMEI = clonePointer(override.DeviceIdentityIMEI)
	cloned.IMSDomain = clonePointer(override.IMSDomain)
	cloned.IMSRealm = clonePointer(override.IMSRealm)
	cloned.IMSPhoneContext = clonePointer(override.IMSPhoneContext)
	cloned.IMSPCSCF = clonePointer(override.IMSPCSCF)
	cloned.IMSTransport = clonePointer(override.IMSTransport)
	cloned.IMSIdentitySource = clonePointer(override.IMSIdentitySource)
	cloned.IMSLocalPort = clonePointer(override.IMSLocalPort)
	cloned.IMSTCPKeepaliveSeconds = clonePointer(override.IMSTCPKeepaliveSeconds)
	cloned.IMSOptionsPingIntervalSeconds = clonePointer(override.IMSOptionsPingIntervalSeconds)
	cloned.IMSRegisterTemplate = cloneRegisterTemplate(override.IMSRegisterTemplate)
	cloned.E911 = cloneE911(override.E911)
	return &cloned
}

func cloneRegisterTemplate(source *IMSRegisterTemplateOverride) *IMSRegisterTemplateOverride {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.ID = clonePointer(source.ID)
	cloned.Expires = clonePointer(source.Expires)
	cloned.ContactMode = clonePointer(source.ContactMode)
	cloned.SecAgreeMode = clonePointer(source.SecAgreeMode)
	cloned.SupportedHeader = clonePointer(source.SupportedHeader)
	cloned.AccessType = clonePointer(source.AccessType)
	cloned.ContactParamOrder = cloneSlicePointer(source.ContactParamOrder)
	cloned.IncludePANIAuthenticated = clonePointer(source.IncludePANIAuthenticated)
	cloned.StrictSecurityServerOffer = clonePointer(source.StrictSecurityServerOffer)
	cloned.EnableInitialRejectFallback = clonePointer(source.EnableInitialRejectFallback)
	if source.SecurityClientMechanisms != nil {
		var mechanisms []SecurityClientMechanism
		if *source.SecurityClientMechanisms != nil {
			mechanisms = make([]SecurityClientMechanism, len(*source.SecurityClientMechanisms))
			for i, mechanism := range *source.SecurityClientMechanisms {
				mechanisms[i] = SecurityClientMechanism{
					Alg:  clonePointer(mechanism.Alg),
					EAlg: clonePointer(mechanism.EAlg),
					Prot: clonePointer(mechanism.Prot),
					Mode: clonePointer(mechanism.Mode),
				}
			}
		}
		cloned.SecurityClientMechanisms = &mechanisms
	}
	cloned.RegisterPolicy = cloneRegisterPolicy(source.RegisterPolicy)
	return &cloned
}

func cloneRegisterPolicy(source *IMSRegisterPolicyOverride) *IMSRegisterPolicyOverride {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.TemporaryStatusCodes = cloneSlicePointer(source.TemporaryStatusCodes)
	cloned.ForbiddenStatusCodes = cloneSlicePointer(source.ForbiddenStatusCodes)
	cloned.InitialRejectFallbackStatusCodes = cloneSlicePointer(source.InitialRejectFallbackStatusCodes)
	cloned.TemporaryRetrySeconds = clonePointer(source.TemporaryRetrySeconds)
	return &cloned
}

func cloneE911(source *E911Override) *E911Override {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.Enabled = clonePointer(source.Enabled)
	cloned.Provider = clonePointer(source.Provider)
	cloned.EntitlementURL = clonePointer(source.EntitlementURL)
	cloned.WebsheetHostPolicy = clonePointer(source.WebsheetHostPolicy)
	return &cloned
}

func clonePointer[T any](source *T) *T {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func cloneSlicePointer[T any](source *[]T) *[]T {
	if source == nil {
		return nil
	}
	var cloned []T
	if *source != nil {
		cloned = append([]T(nil), (*source)...)
		if len(*source) == 0 {
			cloned = make([]T, 0)
		}
	}
	return &cloned
}

func normalizePLMNKey(raw string) (string, error) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("PLMN must use MCC/MNC form")
	}
	return canonicalPLMN(parts[0], parts[1])
}

func canonicalPLMN(mcc, mnc string) (string, error) {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if len(mcc) != 3 || !isASCIIDigits(mcc) {
		return "", fmt.Errorf("MCC %q must contain exactly 3 ASCII digits", mcc)
	}
	if (len(mnc) != 2 && len(mnc) != 3) || !isASCIIDigits(mnc) {
		return "", fmt.Errorf("MNC %q must contain 2 or 3 ASCII digits", mnc)
	}
	normalizedMNC := strings.TrimLeft(mnc, "0")
	if normalizedMNC == "" {
		normalizedMNC = "0"
	}
	return mcc + "/" + normalizedMNC, nil
}

func (override *CarrierOverride) normalizeAndValidate() error {
	trimOptional(override.ID)
	trimOptional(override.CustomEPDG)
	trimOptional(override.APN)
	trimOptional(override.DeviceModel)
	trimOptional(override.DeviceIdentityIMEI)
	trimOptional(override.IMSDomain)
	trimOptional(override.IMSRealm)
	trimOptional(override.IMSPhoneContext)
	trimOptional(override.IMSPCSCF)

	if override.ID != nil && *override.ID == "" {
		return fmt.Errorf("id must not be empty when specified")
	}
	if override.CustomEPDG != nil && *override.CustomEPDG != "" {
		if err := validateHost(*override.CustomEPDG); err != nil {
			return fmt.Errorf("custom_epdg: %w", err)
		}
	}
	if err := validatePort("epdg_port", override.EPDGPort); err != nil {
		return err
	}
	if err := normalizeEnum("ip_stack", override.IPStack, "ipv4", "ipv6", "ipv4v6"); err != nil {
		return err
	}
	if err := normalizeEnum("algorithm_policy", override.AlgorithmPolicy, "strict", "balanced", "legacy_prefer"); err != nil {
		return err
	}
	if override.AlgorithmPolicy != nil && *override.AlgorithmPolicy == "legacy_prefer" &&
		(override.EnableLegacyCiphers == nil || !*override.EnableLegacyCiphers) {
		return fmt.Errorf("algorithm_policy=legacy_prefer requires enable_legacy_ciphers=true")
	}
	if err := normalizeEnum("aka_challenge_mode", override.AKAChallengeMode, "minimal", "omit", "checkcode", "recompute"); err != nil {
		return err
	}
	if err := normalizeEnum("ims_transport", override.IMSTransport, "auto", "tcp", "udp"); err != nil {
		return err
	}
	if err := normalizeEnum("ims_identity_source", override.IMSIdentitySource, "derived", "isim", "auto"); err != nil {
		return err
	}
	if err := validatePort("ims_local_port", override.IMSLocalPort); err != nil {
		return err
	}

	if override.DeviceIdentityIMEI != nil && *override.DeviceIdentityIMEI != "" {
		if len(*override.DeviceIdentityIMEI) != 15 || !isASCIIDigits(*override.DeviceIdentityIMEI) {
			return fmt.Errorf("device_identity_imei must contain exactly 15 ASCII digits")
		}
		if !validIMEILuhn(*override.DeviceIdentityIMEI) {
			return fmt.Errorf("device_identity_imei has an invalid Luhn check digit")
		}
	}
	if err := validatePositive("nat_keepalive_seconds", override.NATKeepaliveSeconds); err != nil {
		return err
	}
	if err := validatePositive("dpd_interval_seconds", override.DPDIntervalSeconds); err != nil {
		return err
	}
	if err := validateNonNegative("reauth_interval_seconds", override.ReauthIntervalSeconds); err != nil {
		return err
	}
	if err := validateNonNegative("ims_tcp_keepalive_seconds", override.IMSTCPKeepaliveSeconds); err != nil {
		return err
	}
	if err := validateNonNegative("ims_options_ping_interval_seconds", override.IMSOptionsPingIntervalSeconds); err != nil {
		return err
	}

	if override.DNSServers != nil {
		for i, value := range *override.DNSServers {
			normalized, err := normalizeDNSServer(value)
			if err != nil {
				return fmt.Errorf("dns_servers[%d]: %w", i, err)
			}
			(*override.DNSServers)[i] = normalized
		}
	}
	if err := normalizeTokenList("ike_proposals", override.IKEProposals); err != nil {
		return err
	}
	if err := normalizeTokenList("esp_proposals", override.ESPProposals); err != nil {
		return err
	}

	if override.IMSRegisterTemplate != nil {
		if err := override.IMSRegisterTemplate.normalizeAndValidate(); err != nil {
			return fmt.Errorf("ims_register_template: %w", err)
		}
	}
	if override.E911 != nil {
		if err := override.E911.normalizeAndValidate(); err != nil {
			return fmt.Errorf("e911: %w", err)
		}
	}
	return nil
}

func (template *IMSRegisterTemplateOverride) normalizeAndValidate() error {
	trimOptional(template.ID)
	trimOptional(template.SupportedHeader)
	trimOptional(template.AccessType)
	if template.ID != nil && *template.ID == "" {
		return fmt.Errorf("id must not be empty when specified")
	}
	if err := validatePositive("expires", template.Expires); err != nil {
		return err
	}
	if err := normalizeEnum("contact_mode", template.ContactMode, "legacy", "android_default", "gsma"); err != nil {
		return err
	}
	if err := normalizeEnum("sec_agree_mode", template.SecAgreeMode, "auto", "required", "disabled"); err != nil {
		return err
	}
	if template.ContactParamOrder != nil {
		allowed := map[string]struct{}{
			"access_type": {}, "sip_instance": {}, "audio": {}, "smsip": {},
			"icsi_ref": {}, "mid_call": {}, "srvcc_alerting": {},
			"ps2cs_srvcc_orig_pre_alerting": {},
		}
		seen := make(map[string]struct{}, len(*template.ContactParamOrder))
		for i, value := range *template.ContactParamOrder {
			value = strings.ToLower(strings.TrimSpace(value))
			if _, ok := allowed[value]; !ok {
				return fmt.Errorf("contact_param_order[%d] has unsupported value %q", i, value)
			}
			if _, duplicate := seen[value]; duplicate {
				return fmt.Errorf("contact_param_order[%d] duplicates %q", i, value)
			}
			seen[value] = struct{}{}
			(*template.ContactParamOrder)[i] = value
		}
	}
	if template.SecurityClientMechanisms != nil {
		for i := range *template.SecurityClientMechanisms {
			mechanism := &(*template.SecurityClientMechanisms)[i]
			trimOptional(mechanism.Alg)
			trimOptional(mechanism.EAlg)
			trimOptional(mechanism.Prot)
			trimOptional(mechanism.Mode)
			if mechanism.Alg == nil || *mechanism.Alg == "" {
				return fmt.Errorf("security_client_mechanisms[%d].alg is required", i)
			}
			if mechanism.EAlg == nil || *mechanism.EAlg == "" {
				return fmt.Errorf("security_client_mechanisms[%d].ealg is required", i)
			}
			for name, value := range map[string]*string{
				"alg": mechanism.Alg, "ealg": mechanism.EAlg,
				"prot": mechanism.Prot, "mode": mechanism.Mode,
			} {
				if value != nil {
					*value = strings.ToLower(*value)
					if !isToken(*value) {
						return fmt.Errorf("security_client_mechanisms[%d].%s contains invalid characters", i, name)
					}
				}
			}
		}
	}
	if template.RegisterPolicy != nil {
		if err := template.RegisterPolicy.validate(); err != nil {
			return fmt.Errorf("register_policy: %w", err)
		}
	}
	return nil
}

func (policy *IMSRegisterPolicyOverride) validate() error {
	if err := validateStatusCodes("temporary_status_codes", policy.TemporaryStatusCodes); err != nil {
		return err
	}
	if err := validateStatusCodes("forbidden_status_codes", policy.ForbiddenStatusCodes); err != nil {
		return err
	}
	if err := validateStatusCodes("initial_reject_fallback_status_codes", policy.InitialRejectFallbackStatusCodes); err != nil {
		return err
	}
	return validateNonNegative("temporary_retry_seconds", policy.TemporaryRetrySeconds)
}

func (e911 *E911Override) normalizeAndValidate() error {
	trimOptional(e911.Provider)
	trimOptional(e911.EntitlementURL)
	if err := normalizeEnum("websheet_host_policy", e911.WebsheetHostPolicy, "public_https"); err != nil {
		return err
	}
	if e911.EntitlementURL != nil {
		if *e911.EntitlementURL == "" {
			return fmt.Errorf("entitlement_url must not be empty when specified")
		}
		parsed, err := url.Parse(*e911.EntitlementURL)
		if err != nil {
			return fmt.Errorf("entitlement_url is invalid: %w", err)
		}
		if !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("entitlement_url must be an absolute HTTPS URL without user information")
		}
		if parsed.Fragment != "" {
			return fmt.Errorf("entitlement_url must not contain a fragment")
		}
		if port := parsed.Port(); port != "" {
			if err := validatePortText(port); err != nil {
				return fmt.Errorf("entitlement_url: %w", err)
			}
		}
		if err := validatePublicHTTPSHost(parsed.Hostname()); err != nil {
			return fmt.Errorf("entitlement_url: %w", err)
		}
	}
	if e911.Enabled != nil && *e911.Enabled {
		if e911.Provider == nil || *e911.Provider == "" {
			return fmt.Errorf("provider is required when enabled=true")
		}
		if e911.EntitlementURL == nil || *e911.EntitlementURL == "" {
			return fmt.Errorf("entitlement_url is required when enabled=true")
		}
		if e911.WebsheetHostPolicy == nil || *e911.WebsheetHostPolicy != "public_https" {
			return fmt.Errorf("websheet_host_policy=public_https is required when enabled=true")
		}
	}
	return nil
}

func validatePublicHTTPSHost(host string) error {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("host must be public")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("literal IP %s is not public", ip.String())
		}
	}
	return nil
}

func validIMEILuhn(imei string) bool {
	if len(imei) != 15 || !isASCIIDigits(imei) {
		return false
	}
	sum := 0
	for index := 0; index < len(imei); index++ {
		digit := int(imei[index] - '0')
		if index%2 == 1 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

func normalizeEnum(field string, value *string, allowed ...string) error {
	if value == nil {
		return nil
	}
	*value = strings.ToLower(strings.TrimSpace(*value))
	for _, candidate := range allowed {
		if *value == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s has unsupported value %q (allowed: %s)", field, *value, strings.Join(allowed, ", "))
}

func normalizeTokenList(field string, values *[]string) error {
	if values == nil {
		return nil
	}
	for i, value := range *values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !isToken(value) {
			return fmt.Errorf("%s[%d] must be a non-empty token", field, i)
		}
		(*values)[i] = value
	}
	return nil
}

func normalizeDNSServer(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("address must not be empty")
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if err := validateHost(host); err != nil {
			return "", err
		}
		if err := validatePortText(port); err != nil {
			return "", err
		}
		return net.JoinHostPort(strings.ToLower(host), port), nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("address %q has an invalid or missing port", value)
	}
	if err := validateHost(value); err != nil {
		return "", err
	}
	return net.JoinHostPort(strings.ToLower(value), "53"), nil
}

func validateHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return nil
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("host %q is not a valid IP address or DNS name", host)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("host %q is not a valid IP address or DNS name", host)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("host %q is not a valid IP address or DNS name", host)
			}
		}
	}
	return nil
}

func validatePort(field string, value *int) error {
	if value == nil {
		return nil
	}
	if *value < 1 || *value > 65535 {
		return fmt.Errorf("%s must be between 1 and 65535", field)
	}
	return nil
}

func validatePortText(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port %q must be between 1 and 65535", value)
	}
	return nil
}

func validatePositive(field string, value *int) error {
	if value != nil && *value <= 0 {
		return fmt.Errorf("%s must be greater than zero", field)
	}
	return nil
}

func validateNonNegative(field string, value *int) error {
	if value != nil && *value < 0 {
		return fmt.Errorf("%s must not be negative", field)
	}
	return nil
}

func validateStatusCodes(field string, values *[]int) error {
	if values == nil {
		return nil
	}
	seen := make(map[int]struct{}, len(*values))
	for i, status := range *values {
		if status < 100 || status > 699 {
			return fmt.Errorf("%s[%d] must be a SIP status code between 100 and 699", field, i)
		}
		if _, duplicate := seen[status]; duplicate {
			return fmt.Errorf("%s[%d] duplicates status %d", field, i, status)
		}
		seen[status] = struct{}{}
	}
	return nil
}

func trimOptional(value *string) {
	if value != nil {
		*value = strings.TrimSpace(*value)
	}
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}
