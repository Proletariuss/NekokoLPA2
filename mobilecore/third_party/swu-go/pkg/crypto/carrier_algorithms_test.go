package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestAllImplementedDHGroups(t *testing.T) {
	for _, tc := range []struct {
		group          uint16
		public, shared int
	}{{2, 128, 128}, {5, 192, 192}, {14, 256, 256}, {15, 384, 384}, {16, 512, 512}, {17, 768, 768}, {18, 1024, 1024}, {19, 64, 32}, {20, 96, 48}, {21, 132, 66}} {
		t.Run(fmt.Sprint(tc.group), func(t *testing.T) {
			a, err := NewDiffieHellman(tc.group)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := NewDiffieHellman(tc.group)
			if err = a.GenerateKey(); err != nil {
				t.Fatal(err)
			}
			if err = b.GenerateKey(); err != nil {
				t.Fatal(err)
			}
			ap, bp := a.PublicKeyBytes(), b.PublicKeyBytes()
			if len(ap) != tc.public || len(bp) != tc.public {
				t.Fatal("incorrect RFC public encoding length")
			}
			x, err := a.ComputeSharedSecret(bp)
			if err != nil {
				t.Fatal(err)
			}
			y, err := b.ComputeSharedSecret(ap)
			if err != nil {
				t.Fatal(err)
			}
			if len(x) != tc.shared || !bytes.Equal(x, y) {
				t.Fatal("shared secret mismatch")
			}
			for _, bad := range [][]byte{nil, bp[:len(bp)-1], make([]byte, tc.public), bytes.Repeat([]byte{255}, tc.public)} {
				if _, err := a.ComputeSharedSecret(bad); err == nil {
					t.Fatal("accepted invalid public key")
				}
			}
		})
	}
	if _, err := NewDiffieHellman(1); err == nil {
		t.Fatal("DH1 must remain unsupported")
	}
}

func TestMODPPrimeSizesAndKnownGroup14(t *testing.T) {
	for group, bits := range map[uint16]int{2: 1024, 5: 1536, 14: 2048, 15: 3072, 16: 4096, 17: 6144, 18: 8192} {
		if modpPrimes[group].BitLen() != bits {
			t.Fatalf("group %d has wrong bits", group)
		}
		// Verify the safe-prime subgroup relation on the fixed RFC parameters.
		q := new(big.Int).Rsh(new(big.Int).Sub(modpPrimes[group], big.NewInt(1)), 1)
		if new(big.Int).Exp(big.NewInt(2), q, modpPrimes[group]).Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("bad group %d", group)
		}
	}
	if modpPrimes[14].Cmp(prime2048) != 0 {
		t.Fatal("existing RFC3526 group14 changed")
	}
}

func TestGCMAllKeyAndTagLengthsAgainstStandardLibrary(t *testing.T) {
	for _, bits := range []int{128, 192, 256} {
		for _, id := range []uint16{18, 19, 20} {
			t.Run(fmt.Sprintf("%d/%d", bits, id), func(t *testing.T) {
				enc, err := GetEncrypterWithKeyLen(id, bits)
				if err != nil {
					t.Fatal(err)
				}
				key := bytes.Repeat([]byte{0x45}, bits/8+4)
				iv := bytes.Repeat([]byte{0x67}, 8)
				aad := []byte("IKE header")
				plain := bytes.Repeat([]byte("carrier payload"), 17)
				block, _ := aes.NewCipher(key[:bits/8])
				standard, _ := cipher.NewGCM(block)
				nonce := append(append([]byte(nil), key[bits/8:]...), iv...)
				full := standard.Seal(nil, nonce, plain, aad)
				want := full[:len(plain)+AEADTagSize(id)]
				got, err := enc.Encrypt(plain, key, iv, aad)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("wrong GCM wire ciphertext/tag", err)
				}
				decoded, err := enc.Decrypt(want, key, iv, aad)
				if err != nil || !bytes.Equal(decoded, plain) {
					t.Fatal("cannot decode independent ciphertext", err)
				}
				for _, offset := range []int{0, len(want) - 1} {
					bad := append([]byte(nil), want...)
					bad[offset] ^= 1
					if out, err := enc.Decrypt(bad, key, iv, aad); err == nil || out != nil {
						t.Fatal("released unauthenticated plaintext")
					}
				}
				if _, err := enc.Decrypt(want, key, iv, []byte("wrong aad")); err == nil {
					t.Fatal("accepted wrong AAD")
				}
				if _, err := enc.Decrypt(want, key, iv[:7], aad); err == nil {
					t.Fatal("accepted short IV")
				}
			})
		}
	}
}
func TestGCMNISTZeroKeyVector(t *testing.T) {
	decode := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	enc, _ := GetEncrypterWithKeyLen(20, 128)
	got, err := enc.Encrypt(make([]byte, 16), make([]byte, 20), make([]byte, 8), nil)
	want := decode("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("NIST GCM vector: %x %v", got, err)
	}
}
