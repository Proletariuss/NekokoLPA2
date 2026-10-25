package simauth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/icholy/digest"
	"proletarius.local/core/internal/vowifi/sim"
)

// Shared fixture with Rust aka_nonce: includes URL alphabet and server data.
func TestNonceEncodingsMatchNativeFixture(t *testing.T) {
	raw := append(bytes.Repeat([]byte{0xfb}, 16), bytes.Repeat([]byte{0xff}, 19)...)
	for _, nonce := range []string{hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw), base64.URLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw)} {
		decoded, err := DecodeNonceBytes(nonce)
		if err != nil {
			t.Fatal(err)
		}
		rand, autn, err := splitNonce(decoded)
		if err != nil || !bytes.Equal(rand, raw[:16]) || !bytes.Equal(autn, raw[16:32]) {
			t.Fatalf("nonce fixture mismatch: %v", err)
		}
	}
}

func TestComputeDigestWithAKAUsesRawRESOctets(t *testing.T) {
	chal := &digest.Challenge{
		Realm: "ims.example.test", Nonce: strings.Repeat("01", 32), Algorithm: "AKAv1-MD5",
	}
	opts := digest.Options{Method: "REGISTER", URI: "sip:ims.example.test", Username: "user@example.test"}
	res := []byte{0xde, 0xad, 0x00, 0xbe, 0xef}
	got, err := ComputeDigestWithAKA(nil, chal, opts, sim.AKAResult{RES: append([]byte(nil), res...)})
	if err != nil {
		t.Fatal(err)
	}
	mathChallenge := *chal
	mathChallenge.Algorithm = "MD5"
	opts.Password = string(res)
	want, err := digest.Digest(&mathChallenge, opts)
	if err != nil {
		t.Fatal(err)
	}
	if want.Response != "daa545a7774d3ac56e434f9bdd42beea" {
		t.Fatal("shared Rust raw RES fixture changed")
	}
	if !strings.Contains(got.Header, `response="`+want.Response+`"`) {
		t.Fatalf("Authorization used a transformed RES: got %q want response %q", got.Header, want.Response)
	}
}

func TestNativeDigestQopFixtures(t *testing.T) {
	golden := map[string][2]string{
		"":         {"daa545a7774d3ac56e434f9bdd42beea", "1add6ee096dfebc41cb5acd8bddda4b4"},
		"auth":     {"ec22021f8bb98a4b59c216988c2a1fe6", "8a308c6d561c8a53ebba45c351d8033b"},
		"auth-int": {"fa9dd8b3612bd63fafaaa84202325a99", "37182df5cdf94b56b34616a5ceca9e28"},
	}
	for _, qop := range []string{"", "auth", "auth-int"} {
		for _, syncFailure := range []bool{false, true} {
			chal := &digest.Challenge{Realm: "ims.example.test", Nonce: strings.Repeat("01", 32), Algorithm: "AKAv1-MD5"}
			if qop != "" {
				chal.QOP = []string{qop}
			}
			opts := digest.Options{Method: "REGISTER", URI: "sip:ims.example.test", Username: "user@example.test", Cnonce: "fixed-client-nonce", Count: 1, GetBody: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("body\x00data")), nil }}
			aka := sim.AKAResult{RES: []byte{0xde, 0xad, 0, 0xbe, 0xef}}
			if syncFailure {
				aka = sim.AKAResult{AUTS: bytes.Repeat([]byte{0x5a}, 14)}
			}
			got, err := ComputeDigestWithAKA(nil, chal, opts, aka)
			if err != nil {
				t.Fatal(err)
			}
			index := 0
			if syncFailure {
				index = 1
			}
			if !strings.Contains(got.Header, `response="`+golden[qop][index]+`"`) || got.SyncFailure != syncFailure {
				t.Fatalf("shared Rust fixture mismatch qop=%q sync=%v", qop, syncFailure)
			}
			if qop == "auth" && !syncFailure {
				want := `Digest username="user@example.test", realm="ims.example.test", nonce="` + chal.Nonce + `", uri="sip:ims.example.test", algorithm=AKAv1-MD5, cnonce="fixed-client-nonce", qop=auth, nc=00000001, response="ec22021f8bb98a4b59c216988c2a1fe6"`
				if got.Header != want {
					t.Fatal("canonical Authorization header differs from native Rust fixture")
				}
			}
		}
	}
}
