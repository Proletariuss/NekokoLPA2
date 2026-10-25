package ikev2

import (
	"bytes"
	"testing"
)

func TestDecodePacketDecodesSA(t *testing.T) {
	prop := NewProposal(1, ProtoIKE, nil)
	prop.AddTransform(TransformTypeEncr, ENCR_AES_GCM_16, 128)
	prop.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	prop.AddTransform(TransformTypeDH, MODP_2048_bit, 0)

	sa := &EncryptedPayloadSA{Proposals: []*Proposal{prop}}

	p := NewIKEPacket()
	p.Header.SPIi = 0x1122334455667788
	p.Header.SPIr = 0
	p.Header.Version = 0x20
	p.Header.ExchangeType = IKE_SA_INIT
	p.Header.Flags = FlagInitiator
	p.Header.MessageID = 0
	p.Payloads = []Payload{sa}

	raw, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	wantSA := []byte{
		0, 0, 0, 36, 1, 1, 0, 3,
		3, 0, 0, 12, 1, 0, 0, 20, 0x80, 14, 0, 128,
		3, 0, 0, 8, 2, 0, 0, 5,
		0, 0, 0, 8, 4, 0, 0, 14,
	}
	if got := raw[IKE_HEADER_LEN+PAYLOAD_HEADER_LEN:]; !bytes.Equal(got, wantSA) {
		t.Fatalf("SA proposal = %x, Rust golden = %x", got, wantSA)
	}

	decoded, err := DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket failed: %v", err)
	}

	if len(decoded.Payloads) != 1 {
		t.Fatalf("payload count mismatch: got %d", len(decoded.Payloads))
	}

	sa2, ok := decoded.Payloads[0].(*EncryptedPayloadSA)
	if !ok {
		t.Fatalf("payload type mismatch: %T", decoded.Payloads[0])
	}
	if len(sa2.Proposals) != 1 || len(sa2.Proposals[0].Transforms) != 3 {
		t.Fatalf("decoded SA missing transforms: proposals=%d transforms=%d", len(sa2.Proposals), len(sa2.Proposals[0].Transforms))
	}
}
