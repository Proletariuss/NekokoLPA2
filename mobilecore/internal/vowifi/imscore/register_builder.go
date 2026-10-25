package imscore

import (
	"strings"

	"proletarius.local/core/internal/vowifi/policy"
)

// buildTemplateSecurityClient renders the template's complete, ordered offer.
// A non-nil carrier override replaces the defaults as a whole; it must not be
// collapsed to one locally preferred mechanism before the P-CSCF selects it.
func buildTemplateSecurityClient(template policy.IMSRegisterTemplate, spiC, spiS uint32, portC, portS int) string {
	template.SecurityClientMechanisms = normalizedSecurityClientMechanisms(template)
	return policy.BuildSecurityClientHeader(template, spiC, spiS, portC, portS)
}

// buildFullSecurityClient renders all template mechanisms for sec-agree verify
// rounds that require the full client capability set.
func buildFullSecurityClient(template policy.IMSRegisterTemplate, spiC, spiS uint32, portC, portS int) string {
	template.SecurityClientMechanisms = normalizedSecurityClientMechanisms(template)
	return policy.BuildSecurityClientHeader(template, spiC, spiS, portC, portS)
}

func normalizedSecurityClientMechanisms(template policy.IMSRegisterTemplate) []policy.IPSec3GPPSecurityMechanism {
	mechanisms := supportedSecurityClientMechanisms(template)
	out := make([]policy.IPSec3GPPSecurityMechanism, len(mechanisms))
	copy(out, mechanisms)
	for i := range out {
		if strings.TrimSpace(out[i].Prot) == "" {
			out[i].Prot = "esp"
		}
		if strings.TrimSpace(out[i].Mode) == "" {
			out[i].Mode = "trans"
		}
	}
	return out
}

func preferredSecurityClientMechanism(template policy.IMSRegisterTemplate) policy.IPSec3GPPSecurityMechanism {
	mechanisms := supportedSecurityClientMechanisms(template)
	for i := len(mechanisms) - 1; i >= 0; i-- {
		m := mechanisms[i]
		if strings.EqualFold(strings.TrimSpace(m.Alg), "hmac-sha-1-96") &&
			strings.EqualFold(canonicalTemplateEAlg(m.EAlg), "aes-cbc") {
			return policy.IPSec3GPPSecurityMechanism{
				Alg:  m.Alg,
				EAlg: m.EAlg,
				Prot: "esp",
				Mode: "trans",
			}
		}
	}
	if len(mechanisms) > 0 {
		m := mechanisms[len(mechanisms)-1]
		if strings.TrimSpace(m.Prot) == "" {
			m.Prot = "esp"
		}
		if strings.TrimSpace(m.Mode) == "" {
			m.Mode = "trans"
		}
		return m
	}
	return policy.IPSec3GPPSecurityMechanism{
		Alg:  "hmac-sha-1-96",
		EAlg: "aes-cbc",
		Prot: "esp",
		Mode: "trans",
	}
}

func supportedSecurityClientMechanisms(template policy.IMSRegisterTemplate) []policy.IPSec3GPPSecurityMechanism {
	if template.SecurityClientMechanisms != nil {
		return template.SecurityClientMechanisms
	}
	return policy.DefaultSecurityClientMechanisms()
}

func securityClientMechanismCount(template policy.IMSRegisterTemplate) int {
	return len(supportedSecurityClientMechanisms(template))
}

func canonicalTemplateEAlg(ealg string) string {
	ealg = strings.TrimSpace(strings.ToLower(ealg))
	if ealg == "" || ealg == "null" {
		return "null"
	}
	return ealg
}

func secAgreeEnabled(template policy.IMSRegisterTemplate) bool {
	return normalizedSecAgreeMode(template) != "disabled"
}

func secAgreeRequired(template policy.IMSRegisterTemplate) bool {
	return normalizedSecAgreeMode(template) == "required"
}

func normalizedSecAgreeMode(template policy.IMSRegisterTemplate) string {
	switch strings.ToLower(strings.TrimSpace(template.SecAgreeMode)) {
	case "disabled", "off", "false", "none":
		return "disabled"
	case "required", "on", "true":
		return "required"
	default:
		return "auto"
	}
}
