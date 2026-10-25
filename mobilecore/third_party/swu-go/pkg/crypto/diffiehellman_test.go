package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestMODP2048FixedKeyGoGoldenDigests(t *testing.T) {
	makeKey := func(privateHex string) *DiffieHellman {
		dh, err := NewDiffieHellman(14)
		if err != nil {
			t.Fatal(err)
		}
		dh.PrivateKey, _ = new(big.Int).SetString(privateHex, 16)
		dh.PublicKey = new(big.Int).Exp(dh.G, dh.PrivateKey, dh.P)
		return dh
	}
	alice := makeKey("d3c4b5a69788776655443322110fedcba98765432100123456789abcdef01234")
	bob := makeKey("a9b8c7d6e5f40312233445566778899abcdef0123456789fedcba98765432109")
	aliceSecret, err := alice.ComputeSharedSecret(bob.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	bobSecret, err := bob.ComputeSharedSecret(alice.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(aliceSecret) != string(bobSecret) {
		t.Fatal("Go DH peers derived different secrets")
	}
	alicePublicHash := sha256.Sum256(alice.PublicKeyBytes())
	bobPublicHash := sha256.Sum256(bob.PublicKeyBytes())
	sharedHash := sha256.Sum256(aliceSecret)
	want := []string{
		"0542c95e95e0bffb8e1e0003e706261b15b0112734da287fa26e2668bd56123c",
		"32c89c937f0be8527b2796afdbe38326a3e4827ae0e4795fb6fd23aff1ebbbab",
		"253a5f642d4dcf8ededf6b9ec01a823a04bb493a997f21b4d6a7a7fa46a3b48e",
	}
	got := []string{
		hex.EncodeToString(alicePublicHash[:]),
		hex.EncodeToString(bobPublicHash[:]),
		hex.EncodeToString(sharedHash[:]),
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("MODP-2048 vector %d mismatch: got %s, want %s", index, got[index], want[index])
		}
	}
}
