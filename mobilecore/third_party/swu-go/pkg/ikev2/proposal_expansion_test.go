package ikev2

import (
	"strings"
	"testing"

	swucrypto "github.com/1239t/swu-go/pkg/crypto"
)

func TestOrderedAlternativeTransformsAndRuntimeCapabilities(t *testing.T) {
	offers, err := BuildIKEProposals([]string{"aes256-aes128-sha512-sha256-prfsha512-prfsha256-modp2048-ecp521", "aes192gcm12-prfsha384-modp3072"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []AlgorithmType{ENCR_AES_CBC, ENCR_AES_CBC, AUTH_HMAC_SHA2_512_256, AUTH_HMAC_SHA2_256_128, PRF_HMAC_SHA2_512, PRF_HMAC_SHA2_256, MODP_2048_bit, 21}
	if len(offers[0].Transforms) != len(want) {
		t.Fatal("alternatives lost")
	}
	for i, w := range want {
		if offers[0].Transforms[i].ID != w {
			t.Fatalf("transform order %d", i)
		}
	}
	if group, err := ProposalDHGroup(offers[0]); err != nil || group != MODP_2048_bit {
		t.Fatal("first KE preference changed")
	}
	for _, p := range offers {
		for _, tr := range p.Transforms {
			var err error
			switch tr.Type {
			case TransformTypeEncr:
				_, err = swucrypto.GetEncrypterWithKeyLen(uint16(tr.ID), int(tr.Attributes[0].Val))
			case TransformTypeInteg:
				_, err = swucrypto.GetIntegrityAlgorithm(uint16(tr.ID))
			case TransformTypePRF:
				_, err = swucrypto.GetPRF(uint16(tr.ID))
			case TransformTypeDH:
				_, err = swucrypto.NewDiffieHellman(uint16(tr.ID))
			}
			if err != nil {
				t.Fatalf("advertised unsupported transform: %v", err)
			}
		}
	}
}

func TestSelectedProposalMustBeSubsetOfOneOffer(t *testing.T) {
	offers, _ := BuildIKEProposals([]string{"aes256-aes128-sha512-sha256-prfsha512-prfsha256-modp2048-ecp521", "aes128gcm16-prfsha256-modp2048"}, nil)
	makeSelection := func() *Proposal {
		p, _ := BuildIKEProposals([]string{"aes128-sha256-prfsha256-ecp521"}, nil)
		return p[0]
	}
	if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: []*Proposal{makeSelection()}}, offers); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Proposal){
		"wrong number":         func(p *Proposal) { p.ProposalNum = 9 },
		"wrong protocol":       func(p *Proposal) { p.ProtocolID = ProtoESP; p.SPI = make([]byte, 4) },
		"unoffered encryption": func(p *Proposal) { p.Transforms[0].ID = ENCR_3DES },
		"unoffered key length": func(p *Proposal) { p.Transforms[0].Attributes[0].Val = 192 },
		"missing key length":   func(p *Proposal) { p.Transforms[0].Attributes = nil },
		"duplicate key length": func(p *Proposal) {
			p.Transforms[0].Attributes = append(p.Transforms[0].Attributes, p.Transforms[0].Attributes[0])
		},
		"duplicate transform": func(p *Proposal) { p.Transforms = append(p.Transforms, p.Transforms[0]) },
		"missing PRF":         func(p *Proposal) { p.Transforms = append(p.Transforms[:2], p.Transforms[3:]...) },
		"cross proposal mix":  func(p *Proposal) { p.Transforms[0].ID = ENCR_AES_GCM_16 },
		"nil transform":       func(p *Proposal) { p.Transforms[0] = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := makeSelection()
			mutate(p)
			if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: []*Proposal{p}}, offers); err == nil {
				t.Fatal("accepted invalid selection")
			}
		})
	}
	for _, response := range []*EncryptedPayloadSA{nil, {}, {Proposals: []*Proposal{nil}}, {Proposals: []*Proposal{makeSelection(), makeSelection()}}} {
		if _, err := ValidateSelectedProposal(response, offers); err == nil {
			t.Fatal("accepted invalid SA count")
		}
	}
	aead, _ := BuildIKEProposals([]string{"aes128gcm16-prfsha256-modp2048"}, nil)
	aead[0].ProposalNum = 2
	if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: aead}, offers); err != nil {
		t.Fatal(err)
	}
	aead[0].AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: aead}, offers); err == nil {
		t.Fatal("accepted AEAD+integrity")
	}
}

func TestProposalBoundsAndUnsupportedESN(t *testing.T) {
	for _, raw := range []string{
		strings.Repeat("aes128-", 33) + "sha256-modp2048",
		strings.Repeat("x", MaxProposalTextLength+1),
		"aes128gcm16-aes128-sha256-prfsha256-modp2048",
	} {
		if _, err := BuildIKEProposals([]string{raw}, nil); err == nil {
			t.Fatal("accepted invalid or oversized proposal")
		}
	}
	list := make([]string, MaxConfiguredProposals+1)
	for i := range list {
		list[i] = "aes128-sha256-modp2048"
	}
	if _, err := BuildIKEProposals(list, nil); err == nil {
		t.Fatal("proposal count overflow")
	}
	if _, err := BuildESPProposals([]string{"aes128-sha256-esn"}, nil); err == nil {
		t.Fatal("unsupported ESN accepted")
	}
	for _, p := range append(CreateMultiProposalIKE(nil), CreateMultiProposalESP(nil)...) {
		for _, tr := range p.Transforms {
			if (tr.Type == TransformTypeDH && (tr.ID == 2 || tr.ID == 5)) || (tr.Type == TransformTypeInteg && tr.ID == AUTH_HMAC_SHA1_96) || (tr.Type == TransformTypePRF && tr.ID == PRF_HMAC_SHA1) {
				t.Fatal("legacy algorithm leaked into defaults")
			}
		}
	}
	// Explicit user/carrier policy remains authoritative for compatibility.
	if _, err := BuildIKEProposals([]string{"aes128-sha1-prfsha1-modp1024"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestESPSelectionChecksESNSPIAndPFS(t *testing.T) {
	offers, _ := BuildESPProposals([]string{"aes128-sha256"}, []byte{1, 2, 3, 4})
	selected, _ := BuildESPProposals([]string{"aes128-sha256"}, []byte{5, 6, 7, 8})
	if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: selected}, offers); err != nil {
		t.Fatal(err)
	}
	selected[0].SPI = nil
	if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: selected}, offers); err == nil {
		t.Fatal("accepted missing SPI")
	}
	selected[0].SPI = []byte{5, 6, 7, 8}
	offers[0].AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: selected}, offers); err == nil {
		t.Fatal("omitted required PFS")
	}
	selected[0].AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	if _, err := ValidateSelectedProposal(&EncryptedPayloadSA{Proposals: selected}, offers); err != nil {
		t.Fatal(err)
	}
}
