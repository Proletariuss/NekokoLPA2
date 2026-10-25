package ikev2

import (
	"bytes"
	"strings"
	"testing"
)

func TestNativeRustGCMProposalGolden(t *testing.T) {
	proposals, err := BuildIKEProposals([]string{"aes128gcm16-prfsha256-modp2048"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (&EncryptedPayloadSA{Proposals: proposals}).Encode()
	want := []byte{0, 0, 0, 36, 1, 1, 0, 3, 3, 0, 0, 12, 1, 0, 0, 20, 128, 14, 0, 128, 3, 0, 0, 8, 2, 0, 0, 5, 0, 0, 0, 8, 4, 0, 0, 14}
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("Rust/Go GCM proposal mismatch: %x %v", wire, err)
	}
}

func TestBuildIKEProposalsConfiguredListReplacesDefaults(t *testing.T) {
	got, err := BuildIKEProposals([]string{
		"aes256-sha256-prfsha1-modp2048",
		"aes128-sha256-modp2048",
	}, nil)
	if err != nil {
		t.Fatalf("BuildIKEProposals() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("proposal count = %d, want 2 (configured list must replace defaults)", len(got))
	}
	assertProposalTransform(t, got[0], TransformTypeEncr, ENCR_AES_CBC, 256)
	assertProposalTransform(t, got[0], TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	assertProposalTransform(t, got[0], TransformTypePRF, PRF_HMAC_SHA1, 0)
	assertProposalTransform(t, got[0], TransformTypeDH, MODP_2048_bit, 0)
	// Without an explicit PRF, strongSwan derives the matching SHA-2 PRF.
	assertProposalTransform(t, got[1], TransformTypePRF, PRF_HMAC_SHA2_256, 0)
}

func TestBuildESPProposalsConfiguredListReplacesDefaults(t *testing.T) {
	spi := []byte{1, 2, 3, 4}
	got, err := BuildESPProposals([]string{"aes256-sha256"}, spi)
	if err != nil {
		t.Fatalf("BuildESPProposals() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("proposal count = %d, want 1", len(got))
	}
	if string(got[0].SPI) != string(spi) {
		t.Fatalf("SPI = %v, want %v", got[0].SPI, spi)
	}
	assertProposalTransform(t, got[0], TransformTypeEncr, ENCR_AES_CBC, 256)
	assertProposalTransform(t, got[0], TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	assertProposalTransform(t, got[0], TransformTypeESN, 0, 0)
}

func TestBuildConfiguredProposalRejectsUnknownOrUnsupportedAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
		want string
	}{
		{
			name: "unknown token",
			fn: func() error {
				_, err := BuildIKEProposals([]string{"aes256-sha256-mystery-modp2048"}, nil)
				return err
			},
			want: "unknown or unsupported",
		},
		{
			name: "unsupported DH implementation",
			fn: func() error {
				_, err := BuildIKEProposals([]string{"aes256-sha256-modp768"}, nil)
				return err
			},
			want: "known but not supported",
		},
		{
			name: "non AEAD missing integrity",
			fn: func() error {
				_, err := BuildESPProposals([]string{"aes256"}, nil)
				return err
			},
			want: "requires an integrity",
		},
		{
			name: "AEAD with integrity",
			fn: func() error {
				_, err := BuildIKEProposals([]string{"aes128gcm16-sha256-prfsha256-modp2048"}, nil)
				return err
			},
			want: "must not include",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestProposalDHGroup(t *testing.T) {
	got, err := BuildIKEProposals([]string{"aes128-sha256-modp2048"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	group, err := ProposalDHGroup(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if group != MODP_2048_bit {
		t.Fatalf("group = %d, want %d", group, MODP_2048_bit)
	}
}

func assertProposalTransform(t *testing.T, proposal *Proposal, transformType TransformType, algorithm AlgorithmType, keyLen int) {
	t.Helper()
	for _, transform := range proposal.Transforms {
		if transform.Type != transformType || transform.ID != algorithm {
			continue
		}
		if keyLen == 0 {
			return
		}
		for _, attr := range transform.Attributes {
			if attr.Type == AttributeKeyLength && int(attr.Val) == keyLen {
				return
			}
		}
		t.Fatalf("transform %d/%d missing key length %d", transformType, algorithm, keyLen)
	}
	t.Fatalf("missing transform %d/%d", transformType, algorithm)
}
