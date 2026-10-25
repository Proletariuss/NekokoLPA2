package imscore

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
	"proletarius.local/core/internal/vowifi/sim"
)

func TestAKAResultFromChallengeAcceptsReferenceBase64Nonce(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	provider := &recordingAKAProvider{}
	_, err := akaResultFromChallenge(provider, &digest.Challenge{
		Nonce: base64.StdEncoding.EncodeToString(raw), Algorithm: "AKAv1-MD5",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(provider.rand, raw[:16]) || !bytes.Equal(provider.autn, raw[16:]) {
		t.Fatal("RAND/AUTN were not split from the Base64 nonce")
	}
}

type recordingAKAProvider struct{ rand, autn []byte }

func (p *recordingAKAProvider) CalculateAKA(rand, autn []byte) (sim.AKAResult, error) {
	p.rand = append([]byte(nil), rand...)
	p.autn = append([]byte(nil), autn...)
	return sim.AKAResult{RES: []byte{1}, CK: make([]byte, 16), IK: make([]byte, 16)}, nil
}

func TestComputeAKAAuthRejectsOrdinaryMD5LikeReference(t *testing.T) {
	req := sip.NewRequest(sip.REGISTER, sip.Uri{Scheme: "sip", Host: "ims.mnc033.mcc234.3gppnetwork.org"})
	chal := &digest.Challenge{
		Realm:     "ims.mnc030.mcc234.3gppnetwork.org",
		Nonce:     "DDE7E3ACFD6B8C6A000000004D3F2B1A",
		Algorithm: "MD5",
		QOP:       []string{"auth"},
	}
	_, _, err := computeAKAAuth(Config{
		IMSI:      "234330000000000",
		PrivateID: "234330000000000@ims.mnc033.mcc234.3gppnetwork.org",
	}, chal, req)
	if err == nil || !strings.Contains(err.Error(), "ordinary MD5") {
		t.Fatalf("computeAKAAuth() error = %v", err)
	}
}
