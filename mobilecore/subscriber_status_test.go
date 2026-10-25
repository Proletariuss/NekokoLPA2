package mobilecore

import (
	"context"
	"encoding/json"
	"testing"

	"proletarius.local/core/internal/vowifi/imscore"
)

func TestSubscriberStatusPrefersRegisteredIdentityOverSIM(t *testing.T) {
	card := cardConfig{IMSI: "234150123456789", MSISDN: "+447700900222", MCC: "234", MNC: "15"}
	status := map[string]any{}
	appendSubscriberStatus(status, map[string]any{"registered": true, "registered_msisdn": "+447700900123"}, card)
	if status["msisdn"] != "+447700900123" || status["msisdn_source"] != "ims" {
		t.Fatalf("registered identity did not win: %#v", status)
	}
	if status["mcc"] != "234" || status["mnc"] != "15" {
		t.Fatalf("home PLMN missing: %#v", status)
	}
}

func TestSubscriberStatusUsesRealSIMNumberWithoutInventingCountryCode(t *testing.T) {
	card := cardConfig{IMSI: "234150123456789", MSISDN: "07700900123", MCC: "234", MNC: "15"}
	for _, registered := range []any{"", "+00000000", "+" + card.IMSI, "sip:" + card.IMSI + "@ims.example", "07700900999", 447700900999} {
		status := map[string]any{}
		appendSubscriberStatus(status, map[string]any{"registered": true, "registered_msisdn": registered}, card)
		if status["msisdn"] != card.MSISDN || status["msisdn_source"] != "sim" {
			t.Fatalf("invalid registered value defeated real SIM evidence: %#v", status)
		}
	}
}

func TestSubscriberStatusNeverFallsBackToAnIMSIOrPublicIdentity(t *testing.T) {
	const imsi = "234150123456789"
	for _, simNumber := range []string{"", imsi, "+" + imsi, "00000000000", "Unknown", "+0447700900123"} {
		status := map[string]any{}
		card := cardConfig{
			IMSI: imsi, MSISDN: simNumber,
			PrivateIdentity: imsi + "@ims.example",
			PublicIdentity:  "sip:" + imsi + "@ims.example",
		}
		appendSubscriberStatus(status, map[string]any{"registered": true, "registered_msisdn": "+" + imsi}, card)
		if status["msisdn"] != "" || status["msisdn_source"] != "" {
			t.Fatalf("unconfirmed identity surfaced as phone number: %#v", status)
		}
	}
}

func TestSubscriberStatusClearsIdentityWhenRegistrationIsAbsent(t *testing.T) {
	card := cardConfig{IMSI: "234150123456789", MSISDN: "+447700900123", MCC: "234", MNC: "15"}
	for _, registered := range []any{false, nil, "true"} {
		status := map[string]any{"msisdn": "+447700900123", "msisdn_source": "ims", "mcc": "234", "mnc": "15"}
		appendSubscriberStatus(status, map[string]any{"registered": registered, "registered_msisdn": card.MSISDN}, card)
		for _, key := range []string{"msisdn", "msisdn_source", "mcc", "mnc"} {
			if status[key] != "" {
				t.Fatalf("unregistered status retains %s: %#v", key, status)
			}
		}
	}
}

func TestSubscriberStatusDoesNotInventHomeRegion(t *testing.T) {
	for _, card := range []cardConfig{
		{MSISDN: "+447700900123"},
		{MSISDN: "+447700900123", MCC: "GB", MNC: "15"},
		{MSISDN: "+447700900123", MCC: "234", MNC: "15x"},
	} {
		status := map[string]any{}
		appendSubscriberStatus(status, map[string]any{"registered": true}, card)
		if status["mcc"] != "" || status["mnc"] != "" {
			t.Fatalf("unknown home PLMN was synthesized: %#v", status)
		}
		if status["msisdn"] != card.MSISDN {
			t.Fatalf("valid global SIM number requires no guessed region: %#v", status)
		}
	}
}

func TestEngineStatusClearsSubscriberFieldsOutsideCurrentRegistration(t *testing.T) {
	engine := NewEngine(&fakeHost{})
	check := func(label string) {
		t.Helper()
		var status map[string]any
		if err := json.Unmarshal([]byte(engine.Status()), &status); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"msisdn", "msisdn_source", "mcc", "mnc"} {
			if status[key] != "" {
				t.Fatalf("%s exposed %s: %#v", label, key, status)
			}
		}
		if status["registered"] != false {
			t.Fatalf("%s reported registration: %#v", label, status)
		}
		if _, exposed := status["imsi"]; exposed {
			t.Fatal("subscriber status must not export the IMSI")
		}
	}
	check("idle")
	ctx, cancel := context.WithCancel(context.Background())
	engine.run = &runningSession{
		ctx: ctx, cancel: cancel, service: &imscore.Service{},
		config: engineConfig{cardConfig: cardConfig{IMSI: "234150123456789", MSISDN: "+447700900123", MCC: "234", MNC: "15"}},
	}
	check("unregistered service")
	cancel()
	check("cancelled session")
	engine.run = nil
	check("stopped")
}
