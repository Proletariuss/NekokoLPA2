package carrier

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"
)

const EmbeddedRegistryRevision = "ca030f836d858e59443e8957a844216c179d8677"

//go:embed data/selectors/*.yaml data/profiles/*.yaml
var embeddedRegistry embed.FS

type selectorManifest struct {
	PLMN     string `yaml:"plmn"`
	Profiles []struct {
		ID, Path  string
		Generic   bool `yaml:"generic"`
		Selectors []struct {
			Raw        string                                 `yaml:"raw"`
			VoWiFiIMSI string                                 `yaml:"vowifi_imsi"`
			Conditions []struct{ Field, Match, Value string } `yaml:"conditions"`
		} `yaml:"selectors"`
	} `yaml:"profiles"`
}

type selectedProfile struct {
	id, file, raw string
	vowifiIMSI    string
	score         int
}

type bundleDocument struct {
	ID, Bundle        string
	SupportedPLMNs    []string                  `yaml:"supported_plmns"`
	Common            map[string]any            `yaml:"common"`
	PLMNOverrides     map[string]map[string]any `yaml:"plmn_overrides"`
	SelectorOverrides map[string]map[string]any `yaml:"selector_overrides"`
}

type bundleConfig struct {
	IMS struct {
		Domain    string `yaml:"domain"`
		APN       string `yaml:"apn"`
		IPStack   string `yaml:"ip_stack"`
		Transport string `yaml:"transport"`
		EPDG      struct {
			Address                   string `yaml:"address"`
			RemoteCertificateHostname string `yaml:"remote_certificate_hostname"`
			Candidates                []struct {
				Address string `yaml:"address"`
			} `yaml:"candidates"`
		} `yaml:"epdg"`
		IKE struct {
			Proposals []struct {
				Encryption, Integrity, PRF []string
				DHGroups                   []int `yaml:"dh_groups"`
				Lifetime                   int   `yaml:"lifetime_seconds"`
			} `yaml:"proposals"`
			NATKeepalive int `yaml:"nat_keepalive_seconds"`
			DPD          struct {
				Enabled  *bool
				Interval int `yaml:"interval_seconds"`
			} `yaml:"dpd"`
			LocalIdentifier           string `yaml:"local_identifier"`
			Username                  string `yaml:"username"`
			ValidateCertificate       *bool  `yaml:"validate_remote_certificate"`
			RemoteCertificateHostname string `yaml:"remote_certificate_hostname"`
			DisableNATT               *bool  `yaml:"disable_switch_to_natt_port"`
			Child                     struct {
				Lifetime  int `yaml:"lifetime_seconds"`
				Proposals []struct {
					Encryption, Integrity []string
					DH                    int    `yaml:"rekey_pfs_group"`
					ESN                   string `yaml:"esn"`
					Lifetime              int    `yaml:"lifetime_seconds"`
				} `yaml:"proposals"`
			} `yaml:"child_sa"`
		} `yaml:"ike"`
		Register struct {
			UseIPSec *bool `yaml:"use_ipsec"`
			Expires  int   `yaml:"expires"`
		} `yaml:"register"`
		Signaling struct {
			ReRegisterOn          []SIPReRegisterRule `yaml:"re_register_on"`
			SupportPEarlyMedia    bool                `yaml:"support_p_early_media"`
			EarlyMediaNeedsHeader bool                `yaml:"early_media_needs_header"`
			Contact               struct {
				Additional []struct {
					Selector string
					Params   []string
				} `yaml:"additional_contact_params"`
			} `yaml:"contact"`
		} `yaml:"signaling"`
	} `yaml:"ims"`
}

func resolveEmbeddedProfile(sim SIMIdentity) (*Profile, error) {
	plmn := normalizeDigits(sim.MCC) + normalizeDigits(sim.MNC)
	raw, err := embeddedRegistry.ReadFile("data/selectors/" + plmn + ".yaml")
	if err != nil {
		return nil, nil
	}
	var manifest selectorManifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("selector %s: %w", plmn, err)
	}
	selected, err := selectProfile(manifest, sim)
	if err != nil || selected == nil {
		return nil, err
	}
	return loadBundle(*selected, plmn)
}

func selectProfile(manifest selectorManifest, sim SIMIdentity) (*selectedProfile, error) {
	var best *selectedProfile
	var generics []selectedProfile
	ambiguous := false
	for _, profile := range manifest.Profiles {
		if profile.Generic {
			generic := selectedProfile{id: profile.ID, file: profile.Path}
			for _, rule := range profile.Selectors {
				if len(rule.Conditions) == 0 {
					generic.raw = rule.Raw
					generic.vowifiIMSI = rule.VoWiFiIMSI
					break
				}
			}
			generics = append(generics, generic)
		}
		for _, rule := range profile.Selectors {
			if len(rule.Conditions) == 0 {
				if !profile.Generic {
					generics = append(generics, selectedProfile{id: profile.ID, file: profile.Path, raw: rule.Raw, vowifiIMSI: rule.VoWiFiIMSI})
				}
				continue
			}
			score, ok := 100000*len(rule.Conditions), true
			for _, condition := range rule.Conditions {
				actual := selectorValue(sim, condition.Field)
				want := strings.TrimSpace(condition.Value)
				switch strings.ToLower(condition.Field) {
				case "gid1", "gid2":
					actual, want = normalizeHex(actual), normalizeHex(want)
				case "iccid", "imsi":
					actual, want = normalizeDigits(actual), normalizeDigits(want)
				case "spn":
					actual, want = strings.ToLower(strings.TrimSpace(actual)), strings.ToLower(want)
				}
				if actual == "" {
					ok = false
					break
				}
				switch strings.ToLower(condition.Match) {
				case "exact", "exact_casefold":
					if actual != want {
						ok = false
					} else {
						score += 50000 + len(want)
					}
				case "prefix":
					if want == "" || !strings.HasPrefix(actual, want) {
						ok = false
					} else {
						score += len(want)
					}
				default:
					ok = false
				}
				if !ok {
					break
				}
			}
			if !ok {
				continue
			}
			candidate := &selectedProfile{id: profile.ID, file: profile.Path, raw: rule.Raw, score: score, vowifiIMSI: rule.VoWiFiIMSI}
			if best == nil || score > best.score {
				best, ambiguous = candidate, false
			} else if score == best.score && candidate.id != best.id {
				ambiguous = true
			}
		}
	}
	if ambiguous {
		return nil, fmt.Errorf("carrier selector %s is ambiguous", manifest.PLMN)
	}
	if best != nil {
		return best, nil
	}
	if len(generics) == 1 {
		return &generics[0], nil
	}
	if len(generics) > 1 {
		return nil, fmt.Errorf("carrier selector %s has multiple generic profiles", manifest.PLMN)
	}
	return nil, nil
}

func selectorValue(sim SIMIdentity, field string) string {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "gid1":
		return sim.GID1
	case "gid2":
		return sim.GID2
	case "iccid":
		return sim.ICCID
	case "imsi":
		return sim.IMSI
	case "spn":
		return sim.SPN
	}
	return ""
}

func loadBundle(selected selectedProfile, plmn string) (*Profile, error) {
	file := path.Clean(selected.file)
	if !strings.HasPrefix(file, "profiles/") || strings.Contains(file, "..") {
		return nil, fmt.Errorf("invalid carrier profile path %q", file)
	}
	raw, err := embeddedRegistry.ReadFile("data/" + file)
	if err != nil {
		return nil, err
	}
	var document bundleDocument
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if document.ID != selected.id || !hasString(document.SupportedPLMNs, plmn) {
		return nil, fmt.Errorf("carrier profile identity mismatch for %s", selected.id)
	}
	merged := copyMap(document.Common)
	mergeMap(merged, document.PLMNOverrides[plmn])
	mergeMap(merged, document.SelectorOverrides[selected.raw])
	encoded, _ := yaml.Marshal(merged)
	var config bundleConfig
	if err := yaml.Unmarshal(encoded, &config); err != nil {
		return nil, err
	}
	return expandBundle(document, selected, plmn, config), nil
}

func expandBundle(document bundleDocument, selected selectedProfile, plmn string, c bundleConfig) *Profile {
	mcc, mnc := plmn[:3], plmn[3:]
	p := standardProfile(mcc, mnc)
	p.ID, p.Name, p.Source = document.ID, displayName(document.Bundle), ProfileSourceBuiltin
	p.Bundle, p.SelectorRaw, p.RegistryRevision = document.Bundle, selected.raw, EmbeddedRegistryRevision
	p.VoWiFiIMSI = strings.TrimSpace(selected.vowifiIMSI)
	p.IMS = strings.TrimSpace(c.IMS.Domain)
	if c.IMS.APN != "" {
		p.APN = c.IMS.APN
	}
	if c.IMS.IPStack != "" {
		p.IPStack = c.IMS.IPStack
	}
	p.IMSTransport = strings.ToLower(strings.TrimSpace(c.IMS.Transport))
	// Apple carrier bundles have used three ePDG shapes over time. Keep the
	// published precedence stable across the Go transport bridge and Rust
	// native parser: address, then the first candidate, then the legacy
	// certificate hostname. Profile.ResolveEPDG still gives an explicit user
	// override priority over this template result.
	if address := strings.TrimSpace(c.IMS.EPDG.Address); address != "" {
		p.EPDGCandidates = []string{address}
	}
	for _, candidate := range c.IMS.EPDG.Candidates {
		if address := strings.TrimSpace(candidate.Address); address != "" && !hasString(p.EPDGCandidates, address) {
			p.EPDGCandidates = append(p.EPDGCandidates, address)
		}
	}
	p.RemoteCertificateHostname = strings.TrimSpace(c.IMS.EPDG.RemoteCertificateHostname)
	if len(p.EPDGCandidates) == 0 {
		if hostname := strings.TrimSpace(c.IMS.EPDG.RemoteCertificateHostname); hostname != "" {
			p.EPDGCandidates = []string{hostname}
		}
	}
	ike := c.IMS.IKE
	if hostname := strings.TrimSpace(ike.RemoteCertificateHostname); hostname != "" {
		p.RemoteCertificateHostname = hostname
	}
	if len(ike.Proposals) > 0 {
		q := ike.Proposals[0]
		// Only mark a template as exact when the source publishes one initial
		// IKE proposal with one transform of every kind. Callers that cannot
		// express every advertised transform must retain their generic fallback
		// rather than silently selecting this first entry.
		p.TemplateIKEProposalExact = len(ike.Proposals) == 1 &&
			len(q.Encryption) == 1 && len(q.Integrity) == 1 &&
			len(q.PRF) == 1 && len(q.DHGroups) == 1
		p.IKEEncryption = first(q.Encryption, p.IKEEncryption)
		p.IKEIntegrity = first(q.Integrity, p.IKEIntegrity)
		p.IKEPRF = first(q.PRF, p.IKEPRF)
		if len(q.DHGroups) > 0 {
			p.IKEDHGroup = q.DHGroups[0]
		}
		if q.Lifetime > 0 {
			p.IKELifetime = q.Lifetime
		}
	}
	if ike.NATKeepalive > 0 {
		p.NATTKeepalive = ike.NATKeepalive
	}
	if ike.DPD.Interval > 0 {
		p.DPDInterval = ike.DPD.Interval
	}
	if ike.DPD.Enabled != nil {
		p.DisableDPD = !*ike.DPD.Enabled
	}
	if ike.LocalIdentifier != "" {
		p.LocalIdentifier = ike.LocalIdentifier
	}
	p.EAPIdentityTemplate = strings.TrimSpace(ike.Username)
	if ike.ValidateCertificate != nil {
		p.ValidateRemoteCertificate = *ike.ValidateCertificate
	}
	if ike.DisableNATT != nil {
		p.DisableSwitchToNATTPort = *ike.DisableNATT
	}
	if len(ike.Child.Proposals) > 0 {
		q := ike.Child.Proposals[0]
		// The runtime only accepts one encryption and integrity transform for
		// the initial ESP proposal and currently emits NO_ESN. Preserve generic
		// behavior for every other carrier shape, including a future mandatory
		// ESN template that this runtime cannot express.
		p.TemplateESPProposalExact = len(ike.Child.Proposals) == 1 &&
			len(q.Encryption) == 1 && len(q.Integrity) == 1 &&
			templateESPESNCompatible(q.ESN)
		p.ChildEncryption = first(q.Encryption, p.ChildEncryption)
		p.ChildIntegrity = first(q.Integrity, p.ChildIntegrity)
		if q.DH > 0 {
			p.ChildDHGroup = q.DH
		}
		if q.Lifetime > 0 {
			p.ChildLifetime = q.Lifetime
		}
	}
	if ike.Child.Lifetime > 0 {
		p.ChildLifetime = ike.Child.Lifetime
	}
	if c.IMS.Register.UseIPSec != nil {
		p.UseIPSec = *c.IMS.Register.UseIPSec
	}
	if c.IMS.Register.Expires > 0 {
		p.RegisterExpires = c.IMS.Register.Expires
	}
	p.ReRegisterOn = CloneReRegisterRules(c.IMS.Signaling.ReRegisterOn)
	for _, entry := range c.IMS.Signaling.Contact.Additional {
		if strings.Contains(strings.ToUpper(entry.Selector), "REGISTER") {
			for _, value := range entry.Params {
				if !hasString(p.RegisterContactParams, value) {
					p.RegisterContactParams = append(p.RegisterContactParams, value)
				}
			}
		}
	}
	p.SupportPEarlyMedia = c.IMS.Signaling.SupportPEarlyMedia
	p.EarlyMediaNeedsHeader = c.IMS.Signaling.EarlyMediaNeedsHeader
	expandTemplateProposals(p, c)
	return p
}

func copyMap(source map[string]any) map[string]any {
	out := map[string]any{}
	mergeMap(out, source)
	return out
}
func mergeMap(target, source map[string]any) {
	for k, v := range source {
		if nested, ok := v.(map[string]any); ok {
			dst, _ := target[k].(map[string]any)
			if dst == nil {
				dst = map[string]any{}
				target[k] = dst
			}
			mergeMap(dst, nested)
		} else {
			target[k] = v
		}
	}
}
func normalizeHex(value string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(value) {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'F' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func first(values []string, fallback string) string {
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	return fallback
}

func templateESPESNCompatible(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto", "noesn":
		return true
	default:
		return false
	}
}

func hasString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
func displayName(value string) string {
	return strings.ReplaceAll(strings.TrimSuffix(value, ".bundle"), "_", " ")
}
func embeddedCounts() (int, int) {
	a, _ := fs.Glob(embeddedRegistry, "data/selectors/*.yaml")
	b, _ := fs.Glob(embeddedRegistry, "data/profiles/*.yaml")
	return len(a), len(b)
}
