package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func primeHex(t *testing.T, s string) []byte {
	t.Helper()
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Published independent vectors: RFC 5448 Appendix C, cases 1 through 4.
func TestAKAPrimeRFC5448Vectors(t *testing.T) {
	for i, v := range []struct{ network, ck, ik, autn, ckp, ikp, kEncr, kAut, kRe, msk, emsk string }{
		{"WLAN", "5349fbe098649f948f5d2e973a81c00f", "9744871ad32bf9bbd1dd5ce54e3e2e5a", "bb52e91c747ac3ab2a5c23d15ee351d5", "0093962d0dd84aa5684b045c9edffa04", "ccfc230ca74fcc96c0a5d61164f5a76c", "766fa0a6c317174b812d52fbcd11a179", "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea", "cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a", "67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a", "f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb"},
		{"HRPD", "5349fbe098649f948f5d2e973a81c00f", "9744871ad32bf9bbd1dd5ce54e3e2e5a", "bb52e91c747ac3ab2a5c23d15ee351d5", "3820f0277fa5f77732b1fb1d90c1a0da", "db94a0ab557ef6c9ab48619ca05b9a9f", "05ad73ac915fce89ac77e1520d82187b", "5b4acaef62c6ebb8882b2f3d534c4b35277337a00184f20ff25d224c04be2afd", "3f90bf5c6e5ef325ff04eb5ef6539fa8cca8398194fbd00be425b3f40dba10ac", "87b321570117cd6c95ab6c436fb5073ff15cf85505d2bc5bb7355fc21ea8a75757e8f86a2b138002e05752913bb43b82f868a96117e91a2d95f526677d572900", "c891d5f20f148a1007553e2dea555c9cb672e9675f4a66b4bafa027379f93aee539a5979d0a0042b9d2ae28bed3b17a31dc8ab75072b80bd0c1da612466e402c"},
		{"WLAN", "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", "cd4c8e5c68f57dd1d7d7dfd0c538e577", "3ece6b705dbbf7dfc459a11280c65524", "897d302fa2847416488c28e20dcb7be4", "c40700e7722483ae3dc7139eb0b88bb558cb3081eccd057f9207d1286ee7dd53", "0a591a22dd8b5b1cf29e3d508c91dbbdb4aee23051892c42b6a2de66ea504473", "9f7dca9e37bb22029ed986e7cd09d4a70d1ac76d95535c5cac40a7504699bb8961a29ef6f3e90f183de5861ad1bedc81ce9916391b401aa006c98785a5756df7", "724de00bdb9e568187be3fe746114557d5018779537ee37f4d3c6c738cb97b9dc651bc19bfadc344ffe2b52ca78bd8316b51dacc5f2b1440cb9515521cc7ba23"},
		{"HRPD", "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", "8310a71ce6f754889613da8f64d5fb46", "5adf14360ae838192db23f6fcb7f8c76", "745e7439ba238f50fcac4d15d47cd1d9", "3e1d2aa4e677025cfd862a4be18361a13a645765571463df833a9759e8099879", "99da835e2ae82462576fe6516fad1f802f0fa1191655dd0a273da96d04e0fcd3", "c6d3a6e0ceea951eb20d74f32c3061d0680a04b0b086ee8700ace3e0b95fa02683c287beee44432294ff98af26d2cc783bace75c4b0af7fdfeb5511ba8e4cbd0", "7fb56813838adafa99d140c2f198f6dacebfb6afee444961105402b508c7f363352cb2919644b50463e6a69354150147ae09cbc54b8a651d8787a6893ed8536d"},
	} {
		got, err := deriveAKAPrime(primeHex(t, v.ck), primeHex(t, v.ik), primeHex(t, v.autn), v.network, []byte("0555444333222111"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.ckPrime, primeHex(t, v.ckp)) || !bytes.Equal(got.ikPrime, primeHex(t, v.ikp)) || !bytes.Equal(got.keyMaterial, primeHex(t, v.kEncr+v.kAut+v.kRe+v.msk+v.emsk)) {
			t.Fatalf("RFC 5448 vector %d mismatch", i+1)
		}
	}
}

type primeSIM struct {
	effectiveConfigSIM
	calls int
}

func (s *primeSIM) CalculateAKA(_, _ []byte) ([]byte, []byte, []byte, []byte, error) {
	s.calls++
	ck, _ := hex.DecodeString("5349fbe098649f948f5d2e973a81c00f")
	ik, _ := hex.DecodeString("9744871ad32bf9bbd1dd5ce54e3e2e5a")
	return []byte{0x28, 0xd7, 0xb0, 0xf2, 0xa2, 0xec, 0x3d, 0xe5}, ck, ik, nil, nil
}

func TestAKAPrimeChallengeAndNegativeAuthentication(t *testing.T) {
	for _, mode := range []string{"valid", "bad_mac", "missing_kdf", "wrong_kdf", "missing_name", "wrong_name", "unset_amf", "duplicate_mac"} {
		t.Run(mode, func(t *testing.T) {
			sim := &primeSIM{}
			s := NewSession(&Config{SIM: sim, EAPIdentity: "0555444333222111"}, zap.NewNop())
			autn := primeHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5")
			if mode == "unset_amf" {
				autn[6] &= 0x7f
			}
			attrs := []byte{}
			for _, a := range []*eap.Attribute{{Type: eap.AT_RAND, Value: append([]byte{0, 0}, primeHex(t, "81e92b6c0ee0e12ebceba8d92a99dfa5")...)}, {Type: eap.AT_AUTN, Value: append([]byte{0, 0}, autn...)}} {
				attrs = append(attrs, a.Encode()...)
			}
			if mode != "missing_kdf" {
				kdf := byte(1)
				if mode == "wrong_kdf" {
					kdf = 2
				}
				attrs = append(attrs, (&eap.Attribute{Type: eap.AT_KDF, Value: []byte{0, kdf}}).Encode()...)
			}
			if mode != "missing_name" {
				name := "WLAN"
				if mode == "wrong_name" {
					name = "HRPD"
				}
				attrs = append(attrs, (&eap.Attribute{Type: eap.AT_KDF_INPUT, Value: append([]byte{0, 4}, []byte(name)...)}).Encode()...)
			}
			macOffset := len(attrs)
			attrs = append(attrs, (&eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}).Encode()...)
			if mode == "duplicate_mac" {
				attrs = append(attrs, (&eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}).Encode()...)
			}
			request := (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: 12, Type: eap.TypeAKAPrime, Subtype: eap.SubtypeChallenge, Data: attrs}).Encode()
			mac := hmac.New(sha256.New, primeHex(t, "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea"))
			mac.Write(request)
			copy(request[8+macOffset+4:], mac.Sum(nil)[:16])
			if mode == "bad_mac" {
				request[len(request)-1] ^= 1
			}
			response, err := s.handleEAP(request)
			if mode != "valid" {
				if err == nil || len(s.MSK) != 0 {
					t.Fatal("invalid AKA' accepted")
				}
				return
			}
			if err != nil || len(response) != 1 {
				t.Fatalf("valid challenge failed: %v", err)
			}
			if !bytes.Equal(s.MSK, primeHex(t, "67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a")) {
				t.Fatal("wrong MSK")
			}
			raw := response[0].(*ikev2.EncryptedPayloadEAP).EAPMessage
			parsed, err := eap.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			outAttrs, err := eap.ParseAttributes(parsed.Data)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := outAttrs[eap.AT_KDF]; ok {
				t.Fatal("spurious KDF renegotiation")
			}
			recv, _ := eapAKAAttrTail16(outAttrs[eap.AT_MAC].Value)
			if err := verifyEAPAKAPrimeMAC(raw, parsed.Data, s.eapKAut, recv); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFastReauthUnimplementedPathsFailClosed(t *testing.T) {
	for _, method := range []byte{eap.TypeAKA, eap.TypeAKAPrime} {
		s := NewSession(&Config{SIM: &effectiveConfigSIM{}, FastReauthID: "old@example", FastReauthMK: make([]byte, 32)}, zap.NewNop())
		if s.fastReauthCtx.CanUseReauth() {
			t.Fatal("unsafe cached state enabled")
		}
		req := (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: 1, Type: method, Subtype: eap.SubtypeReauthentication}).Encode()
		if _, err := s.handleEAP(req); err == nil || len(s.MSK) != 0 {
			t.Fatal("unverified fast reauth accepted")
		}
	}
}

func TestAKAPrimeIdentitySyncAndCheckcodeKeepMethod(t *testing.T) {
	s := NewSession(&Config{SIM: &effectiveConfigSIM{}}, zap.NewNop())
	req := (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: 8, Type: eap.TypeAKAPrime, Subtype: eap.SubtypeIdentity, Data: (&eap.Attribute{Type: eap.AT_ANY_ID_REQ, Value: []byte{0, 0}}).Encode()}).Encode()
	payloads, err := s.handleEAP(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage
	packet, err := eap.Parse(raw)
	if err != nil || packet.Type != eap.TypeAKAPrime {
		t.Fatal("AKA' identity used wrong method")
	}
	attrs, err := eap.ParseAttributes(packet.Data)
	if err != nil {
		t.Fatal(err)
	}
	if attrs[eap.AT_IDENTITY].Value[2] != '6' {
		t.Fatal("AKA' permanent identity prefix must be 6")
	}
	digest := sha256.Sum256(append(append([]byte(nil), req...), raw...))
	check := map[uint8]*eap.Attribute{akaPrimeCheckcodeAttribute: {Type: akaPrimeCheckcodeAttribute, Value: append([]byte{0, 0}, digest[:]...)}}
	if _, err := s.primeCheckcodeResponse(check); err != nil {
		t.Fatal(err)
	}
	check[akaPrimeCheckcodeAttribute].Value[2] ^= 1
	if _, err := s.primeCheckcodeResponse(check); err == nil {
		t.Fatal("forged checkcode accepted")
	}
	payloads, err = s.buildEAPSyncFailure(8, make([]byte, 14), eap.TypeAKAPrime)
	if err != nil {
		t.Fatal(err)
	}
	packet, err = eap.Parse(payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage)
	if err != nil || packet.Type != eap.TypeAKAPrime {
		t.Fatal("AKA' sync failure used wrong method")
	}
	attrs, err = eap.ParseAttributes(packet.Data)
	if err != nil || attrs[eap.AT_KDF] == nil {
		t.Fatal("AKA' sync failure omitted KDF")
	}
	s.resetEAPIdentityState()
	if len(s.eapPrimeIdentityTranscript) != 0 {
		t.Fatal("AKA' transcript survived reset")
	}
}
