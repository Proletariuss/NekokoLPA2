package policy

import (
	"testing"

	"proletarius.local/core/internal/vowifi/carrier"
)

func TestDefaultGiffgaffTemplate(t *testing.T) {
	tmpl := DefaultGiffgaffTemplate()

	if tmpl.ID != "giffgaff" {
		t.Fatalf("id = %q, want giffgaff", tmpl.ID)
	}
	if !tmpl.IncludePANIAuthenticated {
		t.Fatal("expected include_pani_authenticated=true")
	}
	if !tmpl.StrictSecurityServerOffer {
		t.Fatal("expected strict_security_server_offer=true")
	}
	if tmpl.EnableInitialRejectFallback {
		t.Fatal("expected enable_initial_reject_fallback=false")
	}
	if tmpl.SecAgreeMode != "auto" {
		t.Fatalf("sec_agree_mode = %q, want auto", tmpl.SecAgreeMode)
	}
	if tmpl.InitialAuthorization != "aka_empty" {
		t.Fatalf("initial_authorization = %q, want aka_empty", tmpl.InitialAuthorization)
	}

	wantOrder := []string{
		"icsi_ref",
		"mid_call",
		"smsip",
		"sip_instance",
	}
	if tmpl.ContactMode != "gsma" || tmpl.SupportedHeader != "path,gruu" {
		t.Fatalf("giffgaff REGISTER shape = mode %q supported %q", tmpl.ContactMode, tmpl.SupportedHeader)
	}
	if tmpl.FixedPANI != "IEEE-802.11;country=GB;i-wlan-node-id=000000000000" {
		t.Fatalf("giffgaff PANI = %q", tmpl.FixedPANI)
	}
	if len(tmpl.ContactParamOrder) != len(wantOrder) {
		t.Fatalf("contact_param_order = %#v", tmpl.ContactParamOrder)
	}
	for i, want := range wantOrder {
		if tmpl.ContactParamOrder[i] != want {
			t.Fatalf("contact_param_order[%d] = %q, want %q", i, tmpl.ContactParamOrder[i], want)
		}
	}

	if len(tmpl.SecurityClientMechanisms) != 6 {
		t.Fatalf("mechanisms = %d, want 6", len(tmpl.SecurityClientMechanisms))
	}
	wantMechs := []struct{ alg, ealg string }{
		{"hmac-md5-96", "des-ede3-cbc"},
		{"hmac-md5-96", "aes-cbc"},
		{"hmac-md5-96", "null"},
		{"hmac-sha-1-96", "des-ede3-cbc"},
		{"hmac-sha-1-96", "aes-cbc"},
		{"hmac-sha-1-96", "null"},
	}
	for i, want := range wantMechs {
		got := tmpl.SecurityClientMechanisms[i]
		if got.Alg != want.alg || got.EAlg != want.ealg {
			t.Fatalf("mechanism[%d] = %+v, want %s/%s", i, got, want.alg, want.ealg)
		}
	}
}

func TestTemplateForEmbeddedGiffgaffProfileKeepsReferenceIMSShape(t *testing.T) {
	profile := &carrier.Profile{
		ID:                    "apple_o2_giffgaff_uk",
		RegistryRevision:      carrier.EmbeddedRegistryRevision,
		RegisterContactParams: []string{"+g.3gpp.mid-call", "+g.3gpp.srvcc-alerting"},
	}
	tmpl := TemplateForProfile(profile)
	if tmpl.ContactMode != "gsma" || tmpl.InitialAuthorization != "aka_empty" {
		t.Fatalf("embedded giffgaff template lost IMS compatibility: %#v", tmpl)
	}
	if tmpl.SupportedHeader != "path,gruu" {
		t.Fatalf("supported = %q, want reference-compatible value", tmpl.SupportedHeader)
	}
	wantOrder := []string{"icsi_ref", "mid_call", "smsip", "sip_instance"}
	if len(tmpl.ContactParamOrder) != len(wantOrder) {
		t.Fatalf("giffgaff Contact parameters inherited Apple-only extras: %#v", tmpl.ContactParamOrder)
	}
	for i, want := range wantOrder {
		if tmpl.ContactParamOrder[i] != want {
			t.Fatalf("contact_param_order[%d] = %q, want %q", i, tmpl.ContactParamOrder[i], want)
		}
	}
}

func TestTemplateForCarrierKeepsGenericAndOrangeSeparateFromGiffgaff(t *testing.T) {
	if got := TemplateForCarrier("apple_o2_giffgaff_uk"); got.ContactMode != "gsma" {
		t.Fatalf("giffgaff contact mode = %q", got.ContactMode)
	}
	for _, id := range []string{"apple_orange_uk", "unknown"} {
		got := TemplateForCarrier(id)
		if got.ContactMode != "android_default" {
			t.Fatalf("%s contact mode = %q, should retain generic format", id, got.ContactMode)
		}
	}
}

func TestOrangeUKTemplateIncludesAppleContactCapabilities(t *testing.T) {
	tmpl := OrangeUKTemplate()
	if tmpl.InitialAuthorization != "aka_empty" {
		t.Fatalf("InitialAuthorization = %q", tmpl.InitialAuthorization)
	}
	if tmpl.ID != "apple_orange_uk" {
		t.Fatalf("id=%q", tmpl.ID)
	}
	got := make(map[string]bool, len(tmpl.ContactParamOrder))
	for _, item := range tmpl.ContactParamOrder {
		got[item] = true
	}
	for _, want := range []string{"mid_call", "srvcc_alerting", "ps2cs_srvcc_orig_pre_alerting", "sip_instance"} {
		if !got[want] {
			t.Fatalf("contact params %v missing %q", tmpl.ContactParamOrder, want)
		}
	}
}
