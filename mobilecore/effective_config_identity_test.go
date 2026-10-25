package mobilecore

import (
	"strings"
	"testing"

	"proletarius.local/core/internal/vowifi"
	"proletarius.local/core/internal/vowifi/carrier"
)

func TestLebaraSessionIMSIReachesIKEEAPAndIMSWithoutChangingCard(t *testing.T) {
	info := &vowifi.SIMInfo{MCC: "204", MNC: "04", IMSI: "204040000000001", ICCID: "8944160001234567890"}
	p, err := carrier.ResolveWithError(carrier.SIMIdentity{MCC: info.MCC, MNC: info.MNC, ICCID: info.ICCID})
	if err != nil {
		t.Fatal(err)
	}
	e, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, info, "custom.epdg.example", 1443, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	if e.IMSI != "234871234567890" || e.IMSDomain != "ims.mnc087.mcc234.3gppnetwork.org" {
		t.Fatal("effective identity/domain not projected")
	}
	cfg := readerSWUConfig(engineConfig{cardConfig: cardConfig{IMSI: info.IMSI, MCC: info.MCC, MNC: info.MNC}, Proxy: "socks5://127.0.0.1:1080"}, e, nil)
	want := "0234871234567890@nai.epc.mnc087.mcc234.3gppnetwork.org"
	if cfg.IKELocalIdentifier != want || cfg.EAPIdentity != want {
		t.Fatalf("SWu identity mismatch: %q %q", cfg.IKELocalIdentifier, cfg.EAPIdentity)
	}
	if cfg.EpDGAddr != "custom.epdg.example" || cfg.EpDGPort != 1443 || cfg.TransportFactory == nil {
		t.Fatal("custom destination/proxy policy changed")
	}
	impi, impu, err := resolveReaderIMSIdentities(e, info)
	if err != nil || impi != "234871234567890@ims.mnc087.mcc234.3gppnetwork.org" || impu != "sip:"+impi {
		t.Fatalf("IMS identity mismatch: %q %q %v", impi, impu, err)
	}
	if info.IMSI != "204040000000001" || p.MCC != "204" || p.MNC != "04" {
		t.Fatal("physical card/selector mutated")
	}
}

func TestCaptureFailureIsScopedToSelectedDITORoamingProfile(t *testing.T) {
	for _, tc := range []struct {
		mcc, mnc, iccid string
		fail            bool
	}{
		{"204", "04", "8963662600123456789", true},
		{"515", "66", "8963662600123456789", false},
		{"234", "87", "8944160001234567890", false},
		{"454", "03", "", false},
	} {
		p, err := carrier.ResolveWithError(carrier.SIMIdentity{MCC: tc.mcc, MNC: tc.mnc, ICCID: tc.iccid})
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolveReaderVoWiFiEffectiveConfig(p, nil, false, &vowifi.SIMInfo{MCC: tc.mcc, MNC: tc.mnc, IMSI: tc.mcc + tc.mnc + "000000001", ICCID: tc.iccid}, "", 0, makeDeviceIMEI())
		if (err != nil) != tc.fail {
			t.Fatalf("%s/%s unexpected failure: %v", tc.mcc, tc.mnc, err)
		}
		if tc.fail && !strings.Contains(err.Error(), "capture") {
			t.Fatal("capture requirement hidden")
		}
	}
}

func TestSessionIMPIUserAndISIMOverridePrecedence(t *testing.T) {
	p := carrier.FromSIM("262", "23")
	p.LocalIdentifier = "0$impi_user@nai.epc.mnc023.mcc262.3gppnetwork.org"
	info := &vowifi.SIMInfo{IMSI: "262230000000001", MCC: "262", MNC: "23", PrivateIdentity: "actual-user@card.example", PublicIdentity: "sip:public-user@card.example", HomeDomain: "card.example"}
	source := "auto"
	e, err := resolveReaderVoWiFiEffectiveConfig(p, &carrier.CarrierOverride{IMSIdentitySource: &source}, true, info, "", 0, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	if e.IKELocalIdentifier != "0actual-user@nai.epc.mnc023.mcc262.3gppnetwork.org" || e.IMSDomain != "card.example" {
		t.Fatal("actual IMPI or ISIM home domain lost")
	}
	impi, impu, err := resolveReaderIMSIdentities(e, info)
	if err != nil || impi != info.PrivateIdentity || impu != info.PublicIdentity {
		t.Fatal("ISIM identities overwritten")
	}
	info.PrivateIdentity = ""
	if _, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, info, "", 0, makeDeviceIMEI()); err == nil || !strings.Contains(err.Error(), "$impi_user") {
		t.Fatal("missing IMPI did not fail before transport")
	}
}

func TestThreeHKActualISIMStillWinsAndUnresolvedIdentityCannotEscape(t *testing.T) {
	p := carrier.FromSIM("454", "03")
	info := &vowifi.SIMInfo{IMSI: "454030000000001", MCC: "454", MNC: "03", PrivateIdentity: "actual-user@three.example", PublicIdentity: "sip:public-user@three.example", HomeDomain: "three.example"}
	e, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, info, "", 0, makeDeviceIMEI())
	if err != nil || e.EAPIdentity != info.PrivateIdentity || e.IKELocalIdentifier != info.PrivateIdentity || e.IMSIdentitySource != "isim" {
		t.Fatalf("3HK ISIM priority changed: %v", err)
	}
	info.PrivateIdentity = "$imsi@three.example"
	if _, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, info, "", 0, makeDeviceIMEI()); err == nil {
		t.Fatal("unresolved actual ISIM accepted")
	}
	info.PrivateIdentity = "actual-user@three.example"
	info.HomeDomain = "ims.$unknown.example"
	if _, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, info, "", 0, makeDeviceIMEI()); err == nil {
		t.Fatal("unresolved IMS domain accepted")
	}
	info.HomeDomain = "three.example"
	info.PublicIdentity = "sip:$imsi@three.example"
	if _, _, err := resolveReaderIMSIdentities(e, info); err == nil {
		t.Fatal("unresolved IMPU accepted")
	}
}
