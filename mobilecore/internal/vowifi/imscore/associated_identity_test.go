package imscore

import (
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestNormalizeAssociatedIdentity(t *testing.T) {
	tests := []struct {
		value string
		want  string
		ok    bool
	}{
		{"<tel:+44 7700-900123>", "+447700900123", true},
		{"<sip:+447700900123@ims.example;user=phone>", "+447700900123", true},
		{`"Phone, primary" <tel:+447700900123>`, "+447700900123", true},
		{`"Phone" <sip:+447700900123@ims.example;user=phone>`, "+447700900123", true},
		{`Home <sips:+447700900123@ims.example>;expires=3600`, "+447700900123", true},
		{"tel:%2B447700900123", "+447700900123", true},
		{"sip:%2B447700900123@ims.example;user=phone", "+447700900123", true},
		{`"Phone" <sips:%2b447700900123@ims.example>`, "+447700900123", true},
		{"sip:234150000000000@ims.example", "", false},
		{"sip:+447700900123", "", false},
		{"sip:+447700900123@", "", false},
		{"sips:+447700900123@;user=phone", "", false},
		{"sip:+447700900123@@ims.example", "", false},
		{"+447700900123", "", false},
		{"tel:447700900123", "", false},
		{"tel:+0447700900123", "", false},
		{"tel:+00000000000", "", false},
		{"tel:+11111111111", "", false},
		{"tel:+234150000000000", "", false},
		{"sip:%2B234150000000000@ims.example", "", false},
		{"tel:+4477009001234567", "", false},
		{"tel:+44not-a-number", "", false},
		{"tel:%2X447700900123", "", false},
		{`"Phone" <tel:+447700900123`, "", false},
	}
	for _, test := range tests {
		got, ok := normalizeAssociatedIdentity(test.value, "234150000000000")
		if got != test.want || ok != test.ok {
			t.Errorf("normalizeAssociatedIdentity(%q) = (%q, %v), want (%q, %v)",
				test.value, got, ok, test.want, test.ok)
		}
	}
}

func TestExtractAssociatedMSISDNSkipsInvalidCandidates(t *testing.T) {
	response := sip.NewResponse(200, "OK")
	response.AppendHeader(sip.NewHeader("P-Associated-URI",
		`<sip:234150000000000@ims.example>, <tel:+234150000000000>`))
	response.AppendHeader(sip.NewHeader("P-Associated-URI",
		`<tel:+00000000000>, <tel:+11111111111>, "Phone, primary" <sips:%2B447700900123@ims.example>`))
	response.AppendHeader(sip.NewHeader("P-Associated-URI", `<tel:+447700900456>`))
	if got := extractAssociatedMSISDN(response, "234150000000000"); got != "+447700900123" {
		t.Fatalf("associated MSISDN = %q, want first valid subscriber identity", got)
	}
}

func TestExtractAssociatedMSISDNWithoutValidCandidate(t *testing.T) {
	for _, response := range []*sip.Response{nil, sip.NewResponse(200, "OK")} {
		if got := extractAssociatedMSISDN(response, "234150000000000"); got != "" {
			t.Fatalf("missing associated identity = %q, want empty", got)
		}
	}
	response := sip.NewResponse(200, "OK")
	response.AppendHeader(sip.NewHeader("P-Associated-URI",
		`<sip:234150000000000@ims.example>, <tel:+234150000000000>, <tel:+00000000000>`))
	if got := extractAssociatedMSISDN(response, "234150000000000"); got != "" {
		t.Fatalf("invalid associated identities = %q, want empty", got)
	}
}

func TestFinalizeRegisterSuccessRejectsKnownIMSIAsMSISDN(t *testing.T) {
	response := sip.NewResponse(200, "OK")
	response.AppendHeader(sip.NewHeader("P-Associated-URI", `<tel:+234150000000000>`))
	result, err := finalizeRegisterSuccess(Config{IMSI: "234150000000000"}, registerState{}, response)
	if err != nil {
		t.Fatal(err)
	}
	if result.registeredMSISDN != "" {
		t.Fatalf("registered MSISDN = %q, want known IMSI excluded", result.registeredMSISDN)
	}
}

func TestSplitAssociatedHeaderValues(t *testing.T) {
	got := splitAssociatedHeaderValues(
		`<sip:234150000000000@ims.example>, "phone" <tel:+447700900123>`)
	if len(got) != 2 {
		t.Fatalf("splitAssociatedHeaderValues() = %#v, want 2 values", got)
	}
}
