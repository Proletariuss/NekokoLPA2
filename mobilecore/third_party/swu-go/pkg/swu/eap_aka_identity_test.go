package swu

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func akaIdentityRequest(identifier, requestType uint8) []byte {
	selector := (&eap.Attribute{Type: requestType, Value: []byte{0, 0}}).Encode()
	return (&eap.EAPPacket{
		Code:       eap.CodeRequest,
		Identifier: identifier,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeIdentity,
		Data:       selector,
	}).Encode()
}

func TestEAPAKAIdentityRequestRespondsWithConfiguredIdentityAndCheckcode(t *testing.T) {
	const identity = "45403000004272@isim.example"
	session := NewSession(&Config{SIM: &eapProviderTestSIM{}, EAPIdentity: identity, RequireFullEAP: true}, zap.NewNop())
	request := akaIdentityRequest(37, eap.AT_ANY_ID_REQ)

	payloads, err := session.handleEAP(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("response payload count = %d, want 1", len(payloads))
	}
	eapPayload, ok := payloads[0].(*ikev2.EncryptedPayloadEAP)
	if !ok {
		t.Fatalf("response payload type = %T, want EAP", payloads[0])
	}
	response, err := eap.Parse(eapPayload.EAPMessage)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != eap.CodeResponse || response.Identifier != 37 || response.Type != eap.TypeAKA || response.Subtype != eap.SubtypeIdentity {
		t.Fatalf("response header = code %d id %d type %d subtype %d", response.Code, response.Identifier, response.Type, response.Subtype)
	}
	attrs, err := eap.ParseAttributes(response.Data)
	if err != nil {
		t.Fatal(err)
	}
	identityAttr, ok := attrs[eap.AT_IDENTITY]
	if !ok || len(identityAttr.Value) < 2+len(identity) || int(binary.BigEndian.Uint16(identityAttr.Value[:2])) != len(identity) || string(identityAttr.Value[2:2+len(identity)]) != identity {
		t.Fatalf("AT_IDENTITY = %q, want configured identity", identityAttr.Value)
	}
	if !bytes.Equal(identityAttr.Value[2+len(identity):], make([]byte, len(identityAttr.Value)-2-len(identity))) {
		t.Fatal("AT_IDENTITY padding is not zero-filled")
	}
	if _, ok := attrs[eap.AT_MAC]; ok {
		t.Fatal("EAP-AKA Identity response must not include AT_MAC")
	}
	wantCheckcode := sha1.Sum(append(append([]byte(nil), request...), eapPayload.EAPMessage...))
	if !session.eapIdentityCheckcodeValid || session.eapIdentityCheckcode != wantCheckcode {
		t.Fatal("EAP-AKA Identity transcript checkcode was not retained")
	}
}

func TestEAPAKAIdentityRequestBuildsThreeDigitMNCNAIFromSIM(t *testing.T) {
	session := NewSession(&Config{
		SIM:            &eapProviderTestSIM{},
		MCC:            "454",
		MNC:            "03",
		RequireFullEAP: true,
	}, zap.NewNop())
	payloads, err := session.handleEAP(akaIdentityRequest(12, eap.AT_PERMANENT_ID_REQ))
	if err != nil {
		t.Fatal(err)
	}
	response := payloads[0].(*ikev2.EncryptedPayloadEAP)
	parsed, err := eap.Parse(response.EAPMessage)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := eap.ParseAttributes(parsed.Data)
	if err != nil {
		t.Fatal(err)
	}
	value := attrs[eap.AT_IDENTITY].Value
	length := int(binary.BigEndian.Uint16(value[:2]))
	got := string(value[2 : 2+length])
	const want = "0001010123456789@nai.epc.mnc003.mcc454.3gppnetwork.org"
	if got != want {
		t.Fatalf("SIM-derived EAP identity = %q, want %q", got, want)
	}
}

func TestEAPAKAIdentityRequestRejectsInvalidSelectorsAndOrdering(t *testing.T) {
	for name, data := range map[string][]byte{
		"missing selector": nil,
		"multiple selectors": append(
			(&eap.Attribute{Type: eap.AT_ANY_ID_REQ, Value: []byte{0, 0}}).Encode(),
			(&eap.Attribute{Type: eap.AT_PERMANENT_ID_REQ, Value: []byte{0, 0}}).Encode()...),
	} {
		t.Run(name, func(t *testing.T) {
			session := NewSession(&Config{SIM: &eapProviderTestSIM{}, EAPIdentity: "identity@isim.example"}, zap.NewNop())
			request := (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: 1, Type: eap.TypeAKA, Subtype: eap.SubtypeIdentity, Data: data}).Encode()
			if _, err := session.handleEAP(request); err == nil {
				t.Fatal("invalid AKA Identity selector was accepted")
			}
		})
	}

	session := NewSession(&Config{SIM: &eapProviderTestSIM{}, EAPIdentity: "identity@isim.example"}, zap.NewNop())
	for i, requestType := range []uint8{eap.AT_ANY_ID_REQ, eap.AT_FULLAUTH_ID_REQ, eap.AT_PERMANENT_ID_REQ} {
		if _, err := session.handleEAP(akaIdentityRequest(uint8(i+1), requestType)); err != nil {
			t.Fatalf("identity round %d: %v", i+1, err)
		}
	}
	if _, err := session.handleEAP(akaIdentityRequest(4, eap.AT_PERMANENT_ID_REQ)); err == nil {
		t.Fatal("fourth AKA Identity request was accepted")
	}

	repeatedAny := NewSession(&Config{SIM: &eapProviderTestSIM{}, EAPIdentity: "identity@isim.example"}, zap.NewNop())
	if _, err := repeatedAny.handleEAP(akaIdentityRequest(1, eap.AT_ANY_ID_REQ)); err != nil {
		t.Fatal(err)
	}
	if _, err := repeatedAny.handleEAP(akaIdentityRequest(2, eap.AT_ANY_ID_REQ)); err == nil {
		t.Fatal("repeated AT_ANY_ID_REQ was accepted")
	}
}

func TestEAPAKAIdentityUsesFastReauthOnlyWhenAllowed(t *testing.T) {
	baseConfig := &Config{
		SIM:             &eapProviderTestSIM{},
		EAPIdentity:     "permanent@isim.example",
		FastReauthID:    "cached-reauth@example",
		FastReauthMK:    bytes.Repeat([]byte{1}, 20),
		FastReauthKAut:  bytes.Repeat([]byte{2}, 16),
		FastReauthKEncr: bytes.Repeat([]byte{3}, 16),
	}
	for _, test := range []struct {
		name        string
		requestType uint8
		requireFull bool
		want        string
	}{
		{name: "any ID uses full authentication until safe reauth is supported", requestType: eap.AT_ANY_ID_REQ, want: "permanent@isim.example"},
		{name: "full auth uses permanent identity", requestType: eap.AT_FULLAUTH_ID_REQ, want: "permanent@isim.example"},
		{name: "full EAP does not use cached identity", requestType: eap.AT_ANY_ID_REQ, requireFull: true, want: "permanent@isim.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := *baseConfig
			cfg.RequireFullEAP = test.requireFull
			session := NewSession(&cfg, zap.NewNop())
			payloads, err := session.handleEAP(akaIdentityRequest(9, test.requestType))
			if err != nil {
				t.Fatal(err)
			}
			response := payloads[0].(*ikev2.EncryptedPayloadEAP)
			parsed, err := eap.Parse(response.EAPMessage)
			if err != nil {
				t.Fatal(err)
			}
			attrs, err := eap.ParseAttributes(parsed.Data)
			if err != nil {
				t.Fatal(err)
			}
			value := attrs[eap.AT_IDENTITY].Value
			if len(value) < 2 || int(binary.BigEndian.Uint16(value[:2])) > len(value)-2 {
				t.Fatalf("invalid AT_IDENTITY value %x", value)
			}
			got := string(value[2 : 2+int(binary.BigEndian.Uint16(value[:2]))])
			if got != test.want {
				t.Fatalf("AT_IDENTITY = %q, want %q", got, test.want)
			}
		})
	}
}
