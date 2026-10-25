package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFIPS1862PRFSHA1GoldenDigest(t *testing.T) {
	key := []byte("eap-aka fixed MK vector")
	result := NewFIPS1862PRFSHA1(key).Bytes(nil, 96)
	digest := sha256.Sum256(result)
	const want = "c1535ef2c0d408d7ee6b70598eaf36502a904c04672682eab956900ff09a0d7c"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("FIPS186-2 PRF digest mismatch: got %s, want %s", got, want)
	}
}
