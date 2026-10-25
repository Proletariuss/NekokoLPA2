package mobilecore

import (
	"testing"

	"proletarius.local/core/internal/vowifi"
	"proletarius.local/core/internal/vowifi/carrier"
)

func TestThreeHKTemplateMapsToRuntimeAndKeepsDerivedIdentityFallback(t *testing.T) {
	profile, err := carrier.ResolveWithError(carrier.SIMIdentity{MCC: "454", MNC: "03"})
	if err != nil {
		t.Fatal(err)
	}
	effective, err := resolveReaderVoWiFiEffectiveConfig(profile, nil, false, &vowifi.SIMInfo{
		IMSI: "454031234567890", MCC: "454", MNC: "03",
	}, "", 0, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	if effective.EPDG != "wlan.three.com.hk" || effective.APN != "ims" || effective.IPStack != "ipv4" || effective.IKELocalPort != 500 {
		t.Fatalf("unexpected 3HK tunnel settings: %+v", effective)
	}
	if effective.IMSRegisterTemplate.InitialAuthorization != "eap_direct" || !effective.AllowPlainIMS || effective.IMSRegisterTemplate.SecAgreeMode != "disabled" {
		t.Fatalf("unexpected 3HK IMS settings: %+v", effective.IMSRegisterTemplate)
	}
	if !effective.CPInFinalAuth {
		t.Fatal("3HK configuration request must be repeated in final IKE_AUTH")
	}
	if effective.IMSRegisterTemplate.IncludePANI || effective.IMSRegisterTemplate.IncludePANIAuthenticated || !effective.IMSRegisterTemplate.IncludePAccessNetworkInfo {
		t.Fatalf("3HK PANI policy mismatch: %+v", effective.IMSRegisterTemplate)
	}
	if effective.EAPIdentitySource != "derived" || effective.EAPIdentity != "" {
		t.Fatalf("missing ISIM should preserve derived identity without inventing an ISIM value: source=%q identity=%q", effective.EAPIdentitySource, effective.EAPIdentity)
	}
}
