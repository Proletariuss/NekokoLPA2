package subscriber

import "testing"

func TestNormalizeMSISDNOnlyUsesPlausibleSubscriberNumbers(t *testing.T) {
	const imsi = "234150123456789"
	tests := []struct {
		name          string
		raw           string
		allowNational bool
		want          string
	}{
		{"international", "+447700900123", false, "+447700900123"},
		{"visual separators", " +44 (7700)-900.123 ", false, "+447700900123"},
		{"national SIM", "07700 900123", true, "07700900123"},
		{"national IMS rejected", "07700900123", false, ""},
		{"international prefix not fabricated", "00447700900123", true, "00447700900123"},
		{"IMSI", imsi, true, ""},
		{"IMSI with plus", "+" + imsi, false, ""},
		{"NAI username", "0" + imsi, true, ""},
		{"SIP identity", "sip:" + imsi + "@ims.example", true, ""},
		{"not a phone URI parser", "tel:+447700900123", true, ""},
		{"unknown", "unknown", true, ""},
		{"empty", "", true, ""},
		{"filler zeros", "0000000000", true, ""},
		{"filler digits", "+99999999999", false, ""},
		{"invalid calling code", "+0447700900123", false, ""},
		{"short service code", "1234", true, ""},
		{"extension", "+447700900123x42", false, ""},
		{"USSD", "*100#", true, ""},
		{"multiple plus", "+44+7700900123", false, ""},
		{"too long", "+1234567890123456", false, ""},
		{"valid length is not assumed to be IMSI", "+881612345678901", false, "+881612345678901"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NormalizeMSISDN(test.raw, imsi, test.allowNational); got != test.want {
				t.Fatalf("normalized subscriber number = %q, want %q", got, test.want)
			}
		})
	}
}
