package policy

import (
	"proletarius.local/core/internal/vowifi/carrier"
	"testing"
)

func TestRegisterSourceLifetimeAndExplicitRulesProjectToRuntime(t *testing.T) {
	profile := &carrier.Profile{ID: "test", RegisterExpires: 7200, ReRegisterOn: []carrier.SIPReRegisterRule{{Method: "REGISTER", Statuses: []string{"500"}}}}
	template := TemplateForProfile(profile)
	if template.Expires != 7200 || len(template.ReRegisterOn) != 1 {
		t.Fatalf("template=%+v", template)
	}
	profile.ReRegisterOn[0].Statuses[0] = "403"
	if template.ReRegisterOn[0].Statuses[0] != "500" {
		t.Fatal("runtime policy aliases carrier data")
	}
	for _, sim := range []carrier.SIMIdentity{{MCC: "454", MNC: "03"}, {MCC: "999", MNC: "99"}} {
		profile := carrier.Resolve(sim)
		if len(TemplateForProfile(profile).ReRegisterOn) != 0 {
			t.Fatalf("unrelated card %s/%s gained retry policy", sim.MCC, sim.MNC)
		}
	}
}
