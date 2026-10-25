package swu

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	corecrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
)

const akaPrimeCheckcodeAttribute = 134 // RFC 4187 section 10.13; 23 is AT_KDF_INPUT.

func (s *Session) primeCheckcodeResponse(attrs map[uint8]*eap.Attribute) (*eap.Attribute, error) {
	received, ok := attrs[akaPrimeCheckcodeAttribute]
	if !ok {
		return nil, nil
	}
	expected := []byte{0, 0}
	if len(s.eapPrimeIdentityTranscript) > 0 {
		digest := sha256.Sum256(s.eapPrimeIdentityTranscript)
		expected = append(expected, digest[:]...)
	}
	if len(received.Value) != len(expected) || !hmac.Equal(received.Value[2:], expected[2:]) {
		return nil, errors.New("identity transcript mismatch")
	}
	return &eap.Attribute{Type: akaPrimeCheckcodeAttribute, Value: expected}, nil
}

// A single supported KDF is accepted. Alternative-KDF negotiation is not
// silently inferred from the map parser's last duplicate attribute.
func validatePrimeAttributes(data []byte) error {
	seen := map[byte]bool{}
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return errors.New("truncated attribute")
		}
		n := int(data[offset+1]) * 4
		if n < 4 || n > len(data)-offset {
			return errors.New("invalid attribute length")
		}
		if seen[data[offset]] {
			return errors.New("duplicate or unsupported multi-KDF attribute")
		}
		seen[data[offset]] = true
		offset += n
	}
	return nil
}

type akaPrimeKeys struct{ ckPrime, ikPrime, keyMaterial []byte }

// deriveAKAPrime implements 3GPP TS 33.402 Annex A.2 and RFC 5448 3.3/3.4.
// AUTN bytes 0..5 contain SQN xor AK; AMF's separation bit must be set.
func deriveAKAPrime(ck, ik, autn []byte, networkName string, identity []byte) (akaPrimeKeys, error) {
	if len(ck) != 16 || len(ik) != 16 || len(autn) != 16 || len(networkName) == 0 || len(networkName) > 65535 || len(identity) == 0 {
		return akaPrimeKeys{}, errors.New("invalid AKA' key input length")
	}
	if autn[6]&0x80 == 0 {
		return akaPrimeKeys{}, errors.New("AKA' AMF separation bit is not set")
	}
	key := append(append([]byte(nil), ck...), ik...)
	defer clear(key)
	seed := append([]byte{0x20}, []byte(networkName)...)
	seed = binary.BigEndian.AppendUint16(seed, uint16(len(networkName)))
	seed = append(seed, autn[:6]...)
	seed = binary.BigEndian.AppendUint16(seed, 6)
	h := hmac.New(sha256.New, key)
	h.Write(seed)
	derived := h.Sum(nil)
	prfKey := append(append([]byte(nil), derived[16:]...), derived[:16]...)
	defer clear(prfKey)
	material, err := corecrypto.PrfPlus(corecrypto.PRF_HMAC_SHA2_256, prfKey, append([]byte("EAP-AKA'"), identity...), 208)
	return akaPrimeKeys{ckPrime: derived[:16], ikPrime: derived[16:], keyMaterial: material}, err
}
