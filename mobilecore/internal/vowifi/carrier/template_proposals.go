package carrier

import (
	"fmt"
	"strings"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// Conversion preserves alternatives without a Cartesian explosion. The wire
// encoder retains source order within each transform class.
func expandTemplateProposals(p *Profile, c bundleConfig) {
	ike := c.IMS.IKE
	for _, q := range ike.Proposals {
		tokens := append([]string(nil), q.Encryption...)
		tokens = append(tokens, q.Integrity...)
		for _, prf := range q.PRF {
			tokens = append(tokens, "prf"+strings.TrimPrefix(prf, "prf"))
		}
		for _, group := range q.DHGroups {
			token, ok := templateDHName(group)
			if !ok {
				p.TemplateIKEProposalError = fmt.Sprintf("unsupported carrier DH group %d", group)
			}
			tokens = append(tokens, token)
		}
		p.TemplateIKEProposals = append(p.TemplateIKEProposals, strings.Join(tokens, "-"))
		p.TemplateIKELifetime = minimumPositive(p.TemplateIKELifetime, q.Lifetime)
	}
	for _, q := range ike.Child.Proposals {
		tokens := append([]string(nil), q.Encryption...)
		tokens = append(tokens, q.Integrity...)
		if !templateESPESNCompatible(q.ESN) {
			p.TemplateESPProposalError = fmt.Sprintf("unsupported carrier ESP ESN policy %q", q.ESN)
		}
		p.TemplateESPProposals = append(p.TemplateESPProposals, strings.Join(tokens, "-"))
		p.TemplateChildLifetime = minimumPositive(p.TemplateChildLifetime, q.Lifetime)
		if q.DH != 0 {
			if p.TemplateRekeyPFS != 0 && p.TemplateRekeyPFS != q.DH {
				p.TemplateESPProposalError = "carrier proposals require differing rekey PFS groups"
			}
			p.TemplateRekeyPFS = q.DH
		}
	}
	p.TemplateChildLifetime = minimumPositive(p.TemplateChildLifetime, ike.Child.Lifetime)
	if len(p.TemplateIKEProposals) > 0 {
		if _, err := ikev2.BuildIKEProposals(p.TemplateIKEProposals, nil); err != nil {
			p.TemplateIKEProposalError = err.Error()
		}
	}
	if len(p.TemplateESPProposals) > 0 {
		if _, err := ikev2.BuildESPProposals(p.TemplateESPProposals, []byte{0, 0, 0, 1}); err != nil {
			p.TemplateESPProposalError = err.Error()
		}
	}
}
func minimumPositive(a, b int) int {
	if b > 0 && (a == 0 || b < a) {
		return b
	}
	return a
}
func templateDHName(group int) (string, bool) {
	names := map[int]string{1: "modp768", 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096", 17: "modp6144", 18: "modp8192", 19: "ecp256", 20: "ecp384", 21: "ecp521"}
	name, ok := names[group]
	return name, ok
}
