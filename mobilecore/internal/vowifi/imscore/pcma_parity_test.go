package imscore

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPCMARustParity protects the Mac audio contract while the codec moves to
// Rust.  The fixture is supplied by CI/build tooling so ordinary Go-only test
// runs remain self-contained.
func TestPCMARustParity(t *testing.T) {
	fixture := os.Getenv("PROLETARIUS_PCMA_FIXTURE")
	if fixture == "" {
		t.Skip("set PROLETARIUS_PCMA_FIXTURE to the Rust pcma_fixture binary")
	}

	frames := [][]byte{
		make([]byte, 320),
		pcmFrame(func(index int) int16 { return int16(index*401 - 30_000) }),
		pcmFrame(func(index int) int16 {
			if index%2 == 0 {
				return -32768
			}
			return 32767
		}),
	}
	for index, frame := range frames {
		encoded, decoded := pcmaFixture(t, fixture, hex.EncodeToString(frame))
		if got := encodeG711(frame, true); string(got) != string(encoded) {
			t.Fatalf("encoded PCMA mismatch for frame %d", index)
		}
		if got := decodeG711(encoded, true); string(got) != string(decoded) {
			t.Fatalf("decoded PCMA mismatch for frame %d", index)
		}
	}

	allSamples := make([]byte, 65_536*2)
	for index := 0; index < 65_536; index++ {
		binary.LittleEndian.PutUint16(allSamples[index*2:], uint16(int16(index-32_768)))
	}
	encoded, decoded := pcmaFixture(t, fixture, "--all-samples")
	if got := encodeG711(allSamples, true); string(got) != string(encoded) {
		for offset := range got {
			if got[offset] != encoded[offset] {
				sample := int16(binary.LittleEndian.Uint16(allSamples[offset*2:]))
				t.Fatalf("encoded PCMA mismatch at PCM %d: Go=%02x Rust=%02x", sample, got[offset], encoded[offset])
			}
		}
		t.Fatal("encoded PCMA output lengths differ")
	}
	if got := decodeG711(encoded, true); string(got) != string(decoded) {
		for offset := range got {
			if got[offset] != decoded[offset] {
				t.Fatalf("decoded PCMA mismatch at byte %d: Go=%02x Rust=%02x", offset, got[offset], decoded[offset])
			}
		}
		t.Fatal("decoded PCMA output lengths differ")
	}
}

func pcmaFixture(t *testing.T, fixture string, argument string) ([]byte, []byte) {
	t.Helper()
	result, err := exec.Command(fixture, argument).Output()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	parts := strings.Fields(string(result))
	if len(parts) != 2 {
		t.Fatalf("fixture returned %q", result)
	}
	encoded, err := hex.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("fixture encoded bytes: %v", err)
	}
	decoded, err := hex.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("fixture decoded bytes: %v", err)
	}
	return encoded, decoded
}

func pcmFrame(sample func(index int) int16) []byte {
	frame := make([]byte, 320)
	for index := 0; index < len(frame)/2; index++ {
		binary.LittleEndian.PutUint16(frame[index*2:], uint16(sample(index)))
	}
	return frame
}
