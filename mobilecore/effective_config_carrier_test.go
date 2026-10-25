package mobilecore

import (
	"reflect"
	"testing"

	"proletarius.local/core/internal/vowifi"
	"proletarius.local/core/internal/vowifi/carrier"
)

func TestThreeUKPublishedProfileReachesEffectiveConfig(t *testing.T) {
	p, err := carrier.ResolveWithError(carrier.SIMIdentity{MCC: "234", MNC: "20"})
	if err != nil {
		t.Fatal(err)
	}
	customTransport := "udp"
	for _, override := range []*carrier.CarrierOverride{nil, {IMSTransport: &customTransport}} {
		effective, err := resolveReaderVoWiFiEffectiveConfig(p, override, override != nil, &vowifi.SIMInfo{
			IMSI: "234201234567890", MCC: "234", MNC: "20",
		}, "custom.epdg.example", 4500, makeDeviceIMEI())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(effective.IKEProposals, []string{"aes256-sha256-prfsha256-modp2048"}) || !reflect.DeepEqual(effective.ESPProposals, []string{"aes128-sha256"}) {
			t.Fatalf("3UK proposals = %v / %v", effective.IKEProposals, effective.ESPProposals)
		}
		if effective.EAPIdentity != "0234201234567890@nai.epc.mnc020.mcc234.3gppnetwork.org" || effective.Profile.ExpandLocalIdentifier("234201234567890") != "anonymous@nai.epc.mnc020.mcc234.3gppnetwork.org" {
			t.Fatalf("3UK permanent EAP and anonymous IKE identities were conflated: %+v", effective)
		}
		wantTransport := "tcp"
		if override != nil {
			wantTransport = "udp"
		}
		if effective.IMSTransport != wantTransport || effective.EPDG != "custom.epdg.example" || effective.EPDGPort != 4500 || effective.EPDGSource != "custom" {
			t.Fatalf("carrier/user precedence changed: %+v", effective)
		}
	}
}
