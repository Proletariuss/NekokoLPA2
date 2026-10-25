package imscore

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestAMRRustParity protects the O2/giffgaff mode-7 RTP framing while its
// deterministic ownership moves to Rust. Live AMR encoding and audio device I/O
// intentionally remain in-process until real incoming-call loops pass.
func TestAMRRustParity(t *testing.T) {
	fixture := os.Getenv("PROLETARIUS_AMR_FIXTURE")
	if fixture == "" {
		t.Skip("set PROLETARIUS_AMR_FIXTURE to the Rust amr_fixture binary")
	}
	for seed := 0; seed < 32; seed++ {
		octetAligned := make([]byte, 33)
		octetAligned[0] = byte(seed&0x0f) << 4
		octetAligned[1] = 7<<3 | 1<<2
		for index := 2; index < len(octetAligned); index++ {
			octetAligned[index] = byte(index*17 + seed*29)
		}
		octetAligned[32] &= 0xf0

		goPacked, err := amrOctetAlignedToBandwidthEfficient(octetAligned)
		if err != nil {
			t.Fatal(err)
		}
		rustPacked := amrRustFixture(t, fixture, "pack", octetAligned)
		if !bytes.Equal(goPacked, rustPacked) {
			t.Fatalf("packed AMR mismatch for seed %d\nGo   %x\nRust %x", seed, goPacked, rustPacked)
		}

		goUnpacked, err := amrBandwidthEfficientToOctetAligned(goPacked)
		if err != nil {
			t.Fatal(err)
		}
		rustUnpacked := amrRustFixture(t, fixture, "unpack", goPacked)
		if !bytes.Equal(goUnpacked, rustUnpacked) || !bytes.Equal(goUnpacked, octetAligned) {
			t.Fatalf("unpacked AMR mismatch for seed %d", seed)
		}
	}
}

func amrRustFixture(t *testing.T, fixture, mode string, input []byte) []byte {
	t.Helper()
	output, err := exec.Command(fixture, mode, hex.EncodeToString(input)).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust AMR fixture: %v: %s", err, output)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatalf("Rust AMR fixture returned invalid hex: %v", err)
	}
	return decoded
}
