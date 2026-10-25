package swu

import (
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestChildRekeyProposalsRetain3HKESPAndRequirePFS14(t *testing.T) {
	session := NewSession(&Config{ESPProposals: []string{"aes256-sha256"}, RekeyPFS: 14}, zap.NewNop())
	proposals, dh, err := session.childRekeyProposals([]byte{0, 0, 0, 9})
	if err != nil {
		t.Fatal(err)
	}
	defer eraseChildRekeyDH(dh)
	if len(proposals) != 1 || dh == nil || dh.Group != 14 {
		t.Fatalf("proposals=%d DH=%v", len(proposals), dh)
	}
	var encryption, integrity, pfs bool
	for _, transform := range proposals[0].Transforms {
		switch transform.Type {
		case ikev2.TransformTypeEncr:
			encryption = transform.ID == ikev2.ENCR_AES_CBC
		case ikev2.TransformTypeInteg:
			integrity = transform.ID == ikev2.AUTH_HMAC_SHA2_256_128
		case ikev2.TransformTypeDH:
			pfs = transform.ID == ikev2.MODP_2048_bit
		}
	}
	if !encryption || !integrity || !pfs {
		t.Fatalf("3HK rekey transform offer lost: %+v", proposals[0].Transforms)
	}
}

func TestChildRekeyRejectsUnsupportedConfiguredPFS(t *testing.T) {
	session := NewSession(&Config{ESPProposals: []string{"aes256-sha256"}, RekeyPFS: 1}, zap.NewNop())
	if _, _, err := session.childRekeyProposals([]byte{0, 0, 0, 9}); err == nil {
		t.Fatal("unsupported PFS group accepted")
	}
}
