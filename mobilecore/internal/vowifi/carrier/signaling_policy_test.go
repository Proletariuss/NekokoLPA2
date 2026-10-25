package carrier

import (
	"go.yaml.in/yaml/v3"
	"testing"
)

func TestRegisterLifetimeAndReRegistrationExpressionsPreserved(t *testing.T) {
	var config bundleConfig
	if err := yaml.Unmarshal([]byte("ims:\n  register:\n    expires: 7200\n  signaling:\n    re_register_on:\n      - method: REGISTER\n        statuses: [\"500\", \"500-599\"]\n      - method: INVITE\n        statuses: [\"500\"]\n"), &config); err != nil {
		t.Fatal(err)
	}
	profile := expandBundle(bundleDocument{ID: "fixture"}, selectedProfile{}, "23420", config)
	if profile.RegisterExpires != 7200 || len(profile.ReRegisterOn) != 2 || profile.ReRegisterOn[0].Statuses[1] != "500-599" {
		t.Fatalf("projection = %+v", profile)
	}
	config.IMS.Signaling.ReRegisterOn[0].Statuses[0] = "403"
	if profile.ReRegisterOn[0].Statuses[0] != "500" {
		t.Fatal("profile aliases parser data")
	}
	cloned := cloneProfile(*profile)
	cloned.ReRegisterOn[0].Statuses[0] = "503"
	if profile.ReRegisterOn[0].Statuses[0] != "500" {
		t.Fatal("cloned profile aliases source rules")
	}
	config.IMS.Register.Expires = -1
	profile = expandBundle(bundleDocument{ID: "fixture"}, selectedProfile{}, "23420", config)
	if profile.RegisterExpires != 0 {
		t.Fatal("invalid lifetime became runtime authority")
	}
}
