package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"testing"
)

func TestSKFReassemblyPreservesFirstPayloadInEitherOrder(t *testing.T) {
	for _, aead := range []bool{false, true} {
		for _, order := range [][]int{{0, 1}, {1, 0}, {0, 0, 1}} {
			s := envelopeSession(t, aead)
			s.Logger = zap.NewNop()
			s.fragmentBuf = newFragmentBuffer()
			// One EAP payload, deliberately split inside its generic header.
			plain := []byte{0, 0, 0, 8, 3, 1, 0, 4}
			var packets [][]byte
			for i, part := range [][]byte{plain[:3], plain[3:]} {
				packet, err := s.buildSKFPacket(part, uint16(i+1), 2, 7, ikev2.IKE_AUTH, ikev2.EAP)
				if err != nil {
					t.Fatal(err)
				}
				packets = append(packets, packet)
			}
			for step, index := range order {
				id, payloads, err := s.decryptAndParse(packets[index])
				if err != nil || id != 7 {
					t.Fatalf("order %v: id=%d err=%v", order, id, err)
				}
				if step < len(order)-1 && len(payloads) != 0 {
					t.Fatal("premature delivery")
				}
				if step == len(order)-1 && (len(payloads) != 1 || payloads[0].Type() != ikev2.EAP) {
					t.Fatalf("lost EAP: %v", payloads)
				}
			}
		}
	}
}

func TestEncryptedHeadersCannotMutateSessionOrAcceptOtherSA(t *testing.T) {
	for _, aead := range []bool{false, true} {
		s := envelopeSession(t, aead)
		packet, err := s.encryptAndWrapWithMsgID(nil, ikev2.INFORMATIONAL, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, offset := range []int{0, 8, 17, 27} {
			bad := append([]byte{}, packet...)
			bad[offset] ^= 1
			if offset == 17 {
				bad[offset] = 0x10
			}
			if _, _, err := s.decryptAndParse(bad); err == nil {
				t.Fatalf("invalid header accepted at %d", offset)
			}
			if s.SPIi != 1 || s.SPIr != 2 {
				t.Fatal("invalid packet mutated session SPI")
			}
		}
		other := envelopeSession(t, aead)
		other.SPIi = 3
		other.SPIr = 4
		foreign, err := other.encryptAndWrapWithMsgID(nil, ikev2.INFORMATIONAL, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.decryptAndParse(foreign); err == nil {
			t.Fatal("other SA accepted despite valid key/tag")
		}
		plain := (&ikev2.IKEHeader{SPIi: 1, SPIr: 2, Version: 0x20, NextPayload: ikev2.NoNextPayload, ExchangeType: ikev2.INFORMATIONAL, Length: 28}).Encode()
		if _, _, err := s.decryptAndParse(plain); err == nil {
			t.Fatal("plaintext accepted")
		}
		if _, _, err := s.decryptAndParse(packet); err != nil {
			t.Fatalf("valid packet after failures: %v", err)
		}
	}
}

func envelopeSession(t *testing.T, aead bool) *Session {
	t.Helper()
	id := uint16(12)
	keyLen := 16
	if aead {
		id = 20
		keyLen = 20
	}
	enc, err := crypto.GetEncrypter(id)
	if err != nil {
		t.Fatal(err)
	}
	integ, err := crypto.GetIntegrityAlgorithm(2)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x55}, keyLen)
	return &Session{SPIi: 1, SPIr: 2, EncAlg: enc, IntegAlg: integ, ikeIsAEAD: aead, ikeEncrID: id,
		Keys: &ikev2.IKESAKeys{SK_ei: key, SK_er: key, SK_ai: bytes.Repeat([]byte{3}, 20), SK_ar: bytes.Repeat([]byte{3}, 20)}}
}

func TestIKEEnvelopeGCMStandardAndCBCRegression(t *testing.T) {
	for _, aead := range []bool{false, true} {
		s := envelopeSession(t, aead)
		message := []byte{2, 17, 0, 5, 1}
		packet, err := s.encryptAndWrapWithMsgID([]ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: message}}, ikev2.IKE_AUTH, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		_, payloads, err := s.decryptAndParse(packet)
		if err != nil || len(payloads) != 1 {
			t.Fatalf("round trip: %v", err)
		}
		if !bytes.Equal(payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, message) {
			t.Fatal("EAP changed")
		}
		if aead {
			block, _ := aes.NewCipher(s.Keys.SK_ei[:16])
			gcm, _ := cipher.NewGCM(block)
			nonce := append(append([]byte{}, s.Keys.SK_ei[16:]...), packet[32:40]...)
			plain, err := gcm.Open(nil, nonce, packet[40:], packet[:32])
			if err != nil || !bytes.Equal(plain, []byte{0, 0, 0, 9, 2, 17, 0, 5, 1, 0}) {
				t.Fatalf("RFC 5282 envelope: %v", err)
			}
		}
		packet[28] ^= 1
		if _, _, err := s.decryptAndParse(packet); err == nil {
			t.Fatal("unauthenticated SK header accepted")
		}
		if _, _, err := s.decryptAndParse(packet[:29]); err == nil {
			t.Fatal("truncated SK accepted")
		}
	}
}

func TestSKFEnvelopeGCMAndCBC(t *testing.T) {
	for _, aead := range []bool{false, true} {
		s := envelopeSession(t, aead)
		plain := []byte("fragment bytes")
		packet, err := s.buildSKFPacket(plain, 1, 2, 7, ikev2.IKE_AUTH, ikev2.EAP)
		if err != nil {
			t.Fatal(err)
		}
		decoded, n, total, id, err := s.decryptSKF(packet)
		if err != nil || n != 1 || total != 2 || id != 7 || !bytes.Equal(decoded, plain) {
			t.Fatalf("SKF round trip: %v", err)
		}
		if aead {
			block, _ := aes.NewCipher(s.Keys.SK_ei[:16])
			gcm, _ := cipher.NewGCM(block)
			nonce := append(append([]byte{}, s.Keys.SK_ei[16:]...), packet[36:44]...)
			decoded, err = gcm.Open(nil, nonce, packet[44:], packet[:36])
			if err != nil || !bytes.Equal(decoded, append(append([]byte{}, plain...), 0)) {
				t.Fatalf("RFC 7383 AEAD: %v", err)
			}
		}
		packet[33] ^= 1
		if _, _, _, _, err := s.decryptSKF(packet); err == nil {
			t.Fatal("tampered fragment number accepted")
		}
	}
}
