package messaging

import (
	"bytes"
	"testing"
)

func TestParseRPMTData(t *testing.T) {
	data := []byte{
		0x01, 0x2a, // RP-MT-DATA, reference
		0x04, 0x91, 0x44, 0x77, 0xf6, // RP-OA +44776
		0x00, // RP-DA omitted
		0x03, 0x01, 0x02, 0x03,
	}
	reference, originator, tpdu, err := ParseRPMTData(data)
	if err != nil {
		t.Fatalf("ParseRPMTData() error = %v", err)
	}
	if reference != 0x2a || originator != "+44776" || !bytes.Equal(tpdu, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("unexpected parsed RP data: ref=%x originator=%q tpdu=%x", reference, originator, tpdu)
	}
}

func TestParseRPMTDataRejectsInvalidEnvelope(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{0x00, 0x01, 0x00, 0x00, 0x01, 0x02},
		{0x01, 0x01, 0x04, 0x91},
		{0x01, 0x01, 0x00, 0x00, 0x05, 0x01},
	} {
		if _, _, _, err := ParseRPMTData(data); err == nil {
			t.Fatalf("ParseRPMTData(%x) unexpectedly succeeded", data)
		}
	}
}
