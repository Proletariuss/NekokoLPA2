package ikev2

import (
	"bytes"
	"testing"
)

// Shared golden with proletarius-ike::payload::tests::sa_ke_nonce_chain_matches_go_wire_headers.
func TestPayloadChainRustParityGolden(t *testing.T) {
	packet := NewIKEPacket()
	packet.Header.SPIi = 1
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = IKE_SA_INIT
	packet.Header.Flags = FlagInitiator
	packet.Payloads = []Payload{
		&RawPayload{PType: SA, Data: []byte{1, 2}},
		&RawPayload{PType: KE, Data: []byte{0, 14, 0, 0, 3}},
		&RawPayload{PType: NiNr, Data: []byte{4, 5}},
	}
	encoded, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if packet.Header.NextPayload != SA {
		t.Fatalf("first payload = %d", packet.Header.NextPayload)
	}
	want := []byte{34, 0, 0, 6, 1, 2, 40, 0, 0, 9, 0, 14, 0, 0, 3, 0, 0, 0, 6, 4, 5}
	if !bytes.Equal(encoded[IKE_HEADER_LEN:], want) {
		t.Fatalf("payload chain = %x, want %x", encoded[IKE_HEADER_LEN:], want)
	}
}
