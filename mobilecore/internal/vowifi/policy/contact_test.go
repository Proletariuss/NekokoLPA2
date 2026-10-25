package policy

import (
	"net"
	"strings"
	"testing"
)

func TestBuildIMSContactHeaderGiffgaffOrder(t *testing.T) {
	tmpl := DefaultGiffgaffTemplate()
	got := BuildIMSContactHeader(tmpl, ContactBuildInput{
		IMSI:               "001010000000001",
		PublicURI:          "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
		LocalIP:            net.ParseIP("2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646"),
		LocalPort:          5060,
		SIPInstanceURN:     "urn:gsma:imei:8612345-678901-2",
		RegisterExpirySecs: 3600,
	})
	for _, want := range []string{
		`<sip:[2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646]:5060>`,
		`+sip.instance="<urn:gsma:imei:8612345-678901-2>"`,
		"+g.3gpp.mid-call",
		"+g.3gpp.smsip",
		`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("contact %q missing %q", got, want)
		}
	}
	for _, unwanted := range []string{
		"+g.3gpp.accesstype",
		";audio",
		"+g.3gpp.srvcc-alerting",
		"+g.3gpp.ps2cs-srvcc-orig-pre-alerting",
		";transport=",
		"expires=",
	} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("contact %q should not include %q", got, unwanted)
		}
	}
	icsi := strings.Index(got, `+g.3gpp.icsi-ref`)
	midCall := strings.Index(got, `+g.3gpp.mid-call`)
	smsip := strings.Index(got, `+g.3gpp.smsip`)
	instance := strings.Index(got, `+sip.instance`)
	if icsi < 0 || midCall < 0 || smsip < 0 || instance < 0 || !(icsi < midCall && midCall < smsip && smsip < instance) {
		t.Fatalf("param order wrong: %q", got)
	}
}

func TestBuildIMSContactHeaderUsesTemplateOverrides(t *testing.T) {
	tmpl := DefaultIMSRegisterTemplate()
	tmpl.Transport = "TCP"
	tmpl.ContactMode = "android_default"
	tmpl.AccessType = "wlan1"
	tmpl.ICSIRef = "urn:test:voice"
	tmpl.Expires = 600000
	tmpl.ContactParamOrder = []string{"access_type", "icsi_ref", "sip_instance"}

	got := BuildIMSContactHeader(tmpl, ContactBuildInput{
		IMSI:           "310260123456789",
		PublicURI:      "sip:310260123456789@ims.example.test",
		LocalIP:        net.ParseIP("2001:db8::20"),
		LocalPort:      5070,
		SIPInstanceURN: "urn:uuid:test",
	})
	for _, want := range []string{
		"sip:310260123456789@[2001:db8::20]:5070;transport=tcp",
		`+g.3gpp.accesstype="wlan1"`,
		`+g.3gpp.icsi-ref="urn%3Atest%3Avoice"`,
		"expires=600000",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("contact %q missing %q", got, want)
		}
	}
}

func TestBuildIMSContactHeaderLegacyUsesPublicURI(t *testing.T) {
	tmpl := DefaultIMSRegisterTemplate()
	tmpl.ContactMode = "legacy"
	tmpl.ContactParamOrder = []string{"sip_instance"}
	tmpl.ForceHeaderPort5060 = true

	got := BuildIMSContactHeader(tmpl, ContactBuildInput{
		IMSI:           "310260123456789",
		PublicURI:      "sip:subscriber@ims.example.test",
		LocalIP:        net.ParseIP("192.0.2.10"),
		LocalPort:      5099,
		SIPInstanceURN: "urn:uuid:legacy",
	})
	if !strings.HasPrefix(got, "<sip:subscriber@ims.example.test>") {
		t.Fatalf("legacy contact = %q", got)
	}
	if strings.Contains(got, "192.0.2.10") || strings.Contains(got, ":5099") {
		t.Fatalf("legacy contact unexpectedly used local address: %q", got)
	}
}

func TestBuildIMSContactHeaderHonorsExplicitEmptyParamOrder(t *testing.T) {
	tmpl := DefaultIMSRegisterTemplate()
	tmpl.ContactParamOrder = make([]string, 0)

	got := BuildIMSContactHeader(tmpl, ContactBuildInput{
		IMSI:           "310260123456789",
		PublicURI:      "sip:310260123456789@ims.example.test",
		LocalIP:        net.ParseIP("192.0.2.10"),
		LocalPort:      5060,
		SIPInstanceURN: "urn:uuid:empty",
	})
	for _, unwanted := range []string{"+g.3gpp.accesstype", "+sip.instance", ";audio", "+g.3gpp.smsip", "+g.3gpp.icsi-ref"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("contact %q unexpectedly contains %q", got, unwanted)
		}
	}
}
