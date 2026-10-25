package ipsec

import (
	"bytes"
	"encoding/hex"
	"github.com/1239t/swu-go/pkg/crypto"
	"testing"
)

func TestESPRustGCMWireVector(t *testing.T) {
	enc, err := crypto.GetEncrypter(20)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x11}, 20)
	header := []byte{0, 0, 0, 42, 0, 0, 0, 1}
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	plain := make([]byte, 20)
	plain[0] = 0x45
	plain[3] = 20
	padded := append(append([]byte{}, plain...), 1, 2, 2, 4)
	ciphertext, err := enc.Encrypt(padded, key, iv, header)
	if err != nil {
		t.Fatal(err)
	}
	packet := append(append(append([]byte{}, header...), iv...), ciphertext...)
	if hex.EncodeToString(packet) != "0000002a0000000100000000000000018f69e264314ff72800a725369ba61872c13efce98c258e052e64125bcb9730f7e0050daf285b4ee5" {
		t.Fatal("ESP wire vector mismatch")
	}
	decoded, err := Decapsulate(packet, NewSecurityAssociation(42, enc, key, nil))
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatalf("ESP vector rejected: %v", err)
	}
}
