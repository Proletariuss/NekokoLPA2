package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	swucrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestNativeRuntimeChallengeGoldenVector(t *testing.T) {
	input := append([]byte("nai@example"), bytes.Repeat([]byte{0x42}, 16)...)
	input = append(input, bytes.Repeat([]byte{0x31}, 16)...)
	mk := sha1.Sum(input)
	keymat := swucrypto.NewFIPS1862PRFSHA1(mk[:]).Bytes(nil, 96)
	packet := []byte{1, 77, 0, 68, 23, 1, 0, 0}
	packet = append(packet, []byte{1, 5, 0, 0}...)
	packet = append(packet, bytes.Repeat([]byte{0x11}, 16)...)
	packet = append(packet, []byte{2, 5, 0, 0}...)
	packet = append(packet, bytes.Repeat([]byte{0x22}, 16)...)
	packet = append(packet, []byte{11, 5, 0, 0}...)
	packet = append(packet, make([]byte, 16)...)
	mac := hmac.New(sha1.New, keymat[16:32])
	_, _ = mac.Write(packet)
	copy(packet[len(packet)-16:], mac.Sum(nil)[:16])
	const want = "014d004417010000010500001111111111111111111111111111111102050000222222222222222222222222222222220b05000019a5cd42f0c8250e9e34edb24815c777"
	if hex.EncodeToString(packet) != want {
		t.Fatal("Rust runtime challenge fixture diverged from Go key derivation")
	}
}

func TestFinalIKEAuthUsesIdentityActuallySent(t *testing.T) {
	for _, identity := range []string{"", "custom@example", "fast@example"} {
		cfg := &Config{SIM: &effectiveConfigSIM{}, APN: "ims", IPStack: "ipv4"}
		if identity == "fast@example" {
			cfg.FastReauthID = identity
		} else {
			cfg.IKELocalIdentifier = identity
		}
		s := NewSession(cfg, zap.NewNop())
		payloads, err := s.buildIKEAuthInitPayloads()
		if err != nil {
			t.Fatal(err)
		}
		var sent []byte
		for _, payload := range payloads {
			if id, ok := payload.(*ikev2.EncryptedPayloadID); ok && id.IsInitiator {
				sent = append([]byte{id.IDType, 0, 0, 0}, id.IDData...)
			}
		}
		if len(sent) == 0 {
			t.Fatal("missing IDi")
		}
		s.MSK = bytes.Repeat([]byte{1}, 64)
		s.Keys = &ikev2.IKESAKeys{SK_pi: bytes.Repeat([]byte{2}, 32)}
		s.PRFAlg = swucrypto.PRF_HMAC_SHA2_256
		s.msgBuffer = bytes.Repeat([]byte{3}, 28)
		s.nr = bytes.Repeat([]byte{4}, 32)
		cfg.IKELocalIdentifier = "changed-after-send@example"
		mac := hmac.New(s.PRFAlg.Hash, s.MSK)
		mac.Write([]byte("Key Pad for IKEv2"))
		authKey := mac.Sum(nil)
		mac = hmac.New(s.PRFAlg.Hash, s.Keys.SK_pi)
		mac.Write(sent)
		idHash := mac.Sum(nil)
		mac = hmac.New(s.PRFAlg.Hash, authKey)
		mac.Write(s.msgBuffer)
		mac.Write(s.nr)
		mac.Write(idHash)
		final, err := s.buildIKEAuthFinalPayloads()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(final[0].(*ikev2.EncryptedPayloadAuth).AuthData, mac.Sum(nil)) {
			t.Fatal("final AUTH changed the original IDi")
		}
		if identity == "custom@example" {
			if hex.EncodeToString(mac.Sum(nil)) != "f9eb1b3c8b166e136bd843b332f8a2ceab1a169f599c5f6df4a76deda60f0ed2" {
				t.Fatal("Rust final AUTH golden vector differs")
			}
		}
		s.ikeAuthIdentityBody = nil
		if _, err = s.buildIKEAuthFinalPayloads(); err == nil {
			t.Fatal("missing original IDi accepted")
		}
	}
}

type eapProviderTestSIM struct {
	response        EAPAKAResponse
	handled         bool
	err             error
	providerCalls   int
	calculateCalls  int
	identity        EAPIdentityResponse
	identityHandled bool
	identityError   error
	identityCalls   int
	released        []string
}

func (s *eapProviderTestSIM) ReleaseEAPIdentityExchange(id string) error {
	s.released = append(s.released, id)
	return nil
}

func (*eapProviderTestSIM) GetIMSI() (string, error) { return "001010123456789", nil }
func (s *eapProviderTestSIM) CalculateAKA(_, _ []byte) ([]byte, []byte, []byte, []byte, error) {
	s.calculateCalls++
	return nil, nil, nil, nil, errors.New("fallback reached")
}
func (*eapProviderTestSIM) Close() error { return nil }
func (s *eapProviderTestSIM) RespondEAPAKA(_ []byte, _, _ string) (EAPAKAResponse, bool, error) {
	s.providerCalls++
	return s.response, s.handled, s.err
}
func (s *eapProviderTestSIM) RespondEAPIdentity(_, _ []byte) (EAPIdentityResponse, bool, error) {
	s.identityCalls++
	return s.identity, s.identityHandled, s.identityError
}

func eapAKAChallengeForProvider(identifier byte, includeNextReauth bool) []byte {
	attrs := []byte{}
	attrs = append(attrs, (&eap.Attribute{Type: eap.AT_RAND, Value: append([]byte{0, 0}, make([]byte, 16)...)}).Encode()...)
	attrs = append(attrs, (&eap.Attribute{Type: eap.AT_AUTN, Value: append([]byte{0, 0}, make([]byte, 16)...)}).Encode()...)
	attrs = append(attrs, (&eap.Attribute{Type: eap.AT_MAC, Value: append([]byte{0, 0}, make([]byte, 16)...)}).Encode()...)
	if includeNextReauth {
		attrs = append(attrs, (&eap.Attribute{Type: eap.AT_NEXT_REAUTH_ID, Value: []byte{0, 2, 'r', '1'}}).Encode()...)
	}
	return (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: identifier, Type: eap.TypeAKA, Subtype: eap.SubtypeChallenge, Data: attrs}).Encode()
}

func TestNativeEAPAKAProviderResponsePopulatesFinalIKEAuthKeys(t *testing.T) {
	packet := (&eap.EAPPacket{Code: eap.CodeResponse, Identifier: 41, Type: eap.TypeAKA, Subtype: eap.SubtypeChallenge, Data: []byte{}}).Encode()
	sim := &eapProviderTestSIM{
		handled:  true,
		response: EAPAKAResponse{Outcome: "success", Packet: packet, MSK: make([]byte, 64), KAut: make([]byte, 16)},
	}
	session := &Session{
		cfg:                   &Config{SIM: sim, AKAChallengeMode: "minimal"},
		eapIdentityExchangeID: strings.Repeat("ab", 32),
		Logger:                zap.NewNop(),
	}
	challenge := eapAKAChallengeForProvider(41, false)
	payloads, err := session.handleEAP(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 || payloads[0].Type() != ikev2.EAP {
		t.Fatalf("unexpected EAP response payload: %#v", payloads)
	}
	if sim.providerCalls != 1 || sim.calculateCalls != 0 || len(session.MSK) != 64 || len(session.eapKAut) != 16 {
		t.Fatalf("native provider state not propagated: provider=%d GoAKA=%d MSK=%d K_aut=%d", sim.providerCalls, sim.calculateCalls, len(session.MSK), len(session.eapKAut))
	}
}

func TestNativeEAPIdentityProviderBuildsBoundTranscript(t *testing.T) {
	identity := []byte(buildNAI("001010123456789", &Config{}))
	request := []byte{eap.CodeRequest, 19, 0, 5, eap.TypeIdentity}
	responsePacket := (&eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: 19,
		Type:       eap.TypeIdentity,
		Data:       identity,
	}).Encode()
	digest := sha1.Sum(append(append([]byte(nil), request...), responsePacket...))
	sim := &eapProviderTestSIM{
		identityHandled: true,
		identity:        EAPIdentityResponse{Packet: responsePacket, ExchangeID: strings.Repeat("ab", 32), Checkcode: digest[:]},
	}
	session := &Session{
		cfg:    &Config{SIM: sim},
		Logger: zap.NewNop(),
	}
	payloads, err := session.handleEAP(request)
	if err != nil || len(payloads) != 1 || sim.identityCalls != 1 {
		t.Fatalf("native Identity provider failed: payloads=%d calls=%d err=%v", len(payloads), sim.identityCalls, err)
	}
	if !session.eapIdentityCheckcodeValid || session.eapIdentityCheckcode != digest || session.eapIdentityExchangeID != sim.identity.ExchangeID {
		t.Fatal("EAP Identity exchange and checkcode not preserved")
	}
}

func TestNativeEAPIdentityProviderRejectsMismatchedResponse(t *testing.T) {
	identity := buildNAI("001010123456789", &Config{})
	for _, test := range []struct {
		name     string
		response EAPIdentityResponse
	}{
		{
			name: "identifier",
			response: EAPIdentityResponse{Packet: (&eap.EAPPacket{
				Code: eap.CodeResponse, Identifier: 20, Type: eap.TypeIdentity, Data: []byte(identity),
			}).Encode()},
		},
		{
			name: "identity",
			response: EAPIdentityResponse{Packet: (&eap.EAPPacket{
				Code: eap.CodeResponse, Identifier: 19, Type: eap.TypeIdentity, Data: []byte("other@example"),
			}).Encode()},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sim := &eapProviderTestSIM{identityHandled: true, identity: test.response}
			session := &Session{cfg: &Config{SIM: sim}, Logger: zap.NewNop()}
			_, err := session.handleEAP([]byte{eap.CodeRequest, 19, 0, 5, eap.TypeIdentity})
			if err == nil {
				t.Fatal("mismatched native Identity response unexpectedly accepted")
			}
		})
	}
}

func TestNativeEAPAKAFastReauthChallengeKeepsGoPath(t *testing.T) {
	sim := &eapProviderTestSIM{
		handled:  true,
		response: EAPAKAResponse{Outcome: "success", Packet: (&eap.EAPPacket{Code: eap.CodeResponse, Identifier: 42, Type: eap.TypeAKA, Subtype: eap.SubtypeChallenge}).Encode(), MSK: make([]byte, 64), KAut: make([]byte, 16)},
	}
	session := &Session{cfg: &Config{SIM: sim, AKAChallengeMode: "minimal"}, Logger: zap.NewNop()}
	challenge := eapAKAChallengeForProvider(42, true)
	if _, err := session.handleEAP(challenge); err == nil || !strings.Contains(err.Error(), "fallback reached") {
		t.Fatalf("expected retained Go fast-reauth fallback, got %v", err)
	}
	if sim.providerCalls != 0 || sim.calculateCalls != 1 {
		t.Fatalf("fast reauth path was diverted: provider=%d GoAKA=%d", sim.providerCalls, sim.calculateCalls)
	}
}

func TestFastReauthIdentityKeepsGoPath(t *testing.T) {
	sim := &eapProviderTestSIM{
		identityHandled: false,
		identity: EAPIdentityResponse{Packet: (&eap.EAPPacket{
			Code: eap.CodeResponse, Identifier: 31, Type: eap.TypeIdentity, Data: []byte("wrong@example"),
		}).Encode()},
	}
	session := &Session{
		cfg:           &Config{SIM: sim},
		Logger:        zap.NewNop(),
		fastReauthCtx: &eap.FastReauthContext{Enabled: true, ReauthID: "cached-reauth@example"},
	}
	payloads, err := session.handleEAP([]byte{eap.CodeRequest, 31, 0, 5, eap.TypeIdentity})
	if err != nil || len(payloads) != 1 || sim.identityCalls != 1 {
		t.Fatalf("fast re-auth Identity was diverted to Rust: payloads=%d provider=%d err=%v", len(payloads), sim.identityCalls, err)
	}
	response, err := eap.Parse(payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage)
	if err != nil || string(response.Data) != session.permanentEAPIdentity() {
		t.Fatalf("Go fast re-auth identity changed: response=%#v err=%v", response, err)
	}
}

func TestNativeEAPAKASyncFailureReturnsResponseWithoutKeyMaterial(t *testing.T) {
	packet := (&eap.EAPPacket{Code: eap.CodeResponse, Identifier: 43, Type: eap.TypeAKA, Subtype: eap.SubtypeSyncFailure, Data: []byte{1, 4, 0, 0}}).Encode()
	sim := &eapProviderTestSIM{handled: true, response: EAPAKAResponse{Outcome: "synchronization_failure", Packet: packet, NextExchangeID: strings.Repeat("cd", 32)}}
	session := &Session{cfg: &Config{SIM: sim, AKAChallengeMode: "minimal"}, Logger: zap.NewNop()}
	session.eapIdentityExchangeID = strings.Repeat("ab", 32)
	payloads, err := session.handleEAP(eapAKAChallengeForProvider(43, false))
	if err != nil || len(payloads) != 1 || len(session.MSK)+len(session.eapKAut) != 0 {
		t.Fatalf("synchronization failure was not cleanly returned: payloads=%d MSK=%d K_aut=%d err=%v", len(payloads), len(session.MSK), len(session.eapKAut), err)
	}
	if session.eapIdentityExchangeID != sim.response.NextExchangeID {
		t.Fatal("synchronization failure lost native continuation")
	}
	sim.response = EAPAKAResponse{Outcome: "success", Packet: (&eap.EAPPacket{Code: eap.CodeResponse, Identifier: 44, Type: eap.TypeAKA, Subtype: eap.SubtypeChallenge}).Encode(), MSK: make([]byte, 64), KAut: make([]byte, 16)}
	_, err = session.handleEAP(eapAKAChallengeForProvider(44, false))
	if err != nil || sim.providerCalls != 2 || sim.calculateCalls != 0 || session.eapIdentityExchangeID != "" || len(session.MSK) != 64 {
		t.Fatalf("resynchronized challenge did not finish through native provider: %v", err)
	}
}

func TestNativeEAPFailureReleasesExchangeWithoutSecondSIMAuthentication(t *testing.T) {
	sim := &eapProviderTestSIM{handled: true, err: errors.New("native timeout")}
	session := &Session{
		cfg: &Config{SIM: sim, AKAChallengeMode: "minimal"}, Logger: zap.NewNop(),
		eapIdentityExchangeID: strings.Repeat("ab", 32),
	}
	_, err := session.handleEAP(eapAKAChallengeForProvider(43, false))
	if err == nil || sim.calculateCalls != 0 || sim.providerCalls != 1 || len(sim.released) != 1 || session.eapIdentityExchangeID != "" {
		t.Fatal("native failure must release its exchange and avoid a second physical authentication")
	}
}

func TestIdentityResetReleasesOnceAndClearsDigest(t *testing.T) {
	sim := &eapProviderTestSIM{}
	session := &Session{
		cfg: &Config{SIM: sim}, Logger: zap.NewNop(),
		eapIdentityExchangeID: strings.Repeat("ab", 32),
		eapIdentityCheckcode:  sha1.Sum([]byte("identity")), eapIdentityCheckcodeValid: true,
	}
	session.resetEAPIdentityState()
	session.resetEAPIdentityState()
	if len(sim.released) != 1 || session.eapIdentityCheckcodeValid || session.eapIdentityCheckcode != [sha1.Size]byte{} {
		t.Fatal("identity reset did not release once and erase the compatibility digest")
	}
}

func TestNativeMalformedResponseReleasesContinuationAndErasesUnusedKeys(t *testing.T) {
	oldID, nextID := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	msk, kaut := bytes.Repeat([]byte{7}, 64), bytes.Repeat([]byte{9}, 16)
	sim := &eapProviderTestSIM{handled: true, response: EAPAKAResponse{
		Outcome: "success", Packet: []byte{2, 99, 0, 8, 23, 1, 0, 0},
		NextExchangeID: nextID, MSK: msk, KAut: kaut,
	}}
	session := &Session{cfg: &Config{SIM: sim}, Logger: zap.NewNop(), eapIdentityExchangeID: oldID}
	if _, err := session.handleEAP(eapAKAChallengeForProvider(43, false)); err == nil {
		t.Fatal("mismatched native packet accepted")
	}
	if len(sim.released) != 2 || sim.released[0] != oldID || sim.released[1] != nextID {
		t.Fatal("old and unused continuation must both be released")
	}
	if !bytes.Equal(msk, make([]byte, 64)) || !bytes.Equal(kaut, make([]byte, 16)) || len(session.MSK) != 0 {
		t.Fatal("rejected key material was retained")
	}
}
