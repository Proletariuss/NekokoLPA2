package swu

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

// Fixed public/synthetic 3HK-style configuration pins the entire inner initial
// AUTH wire, including payload ordering and bodies, for certificate=false.
func TestCertReqFalseModeInitialWireBaseline(t *testing.T) {
	s := NewSession(&Config{APN: "ims", IPStack: "ipv4v6", IKELocalIdentifier: "anonymous@wlan.mnc000.mcc454.3gppnetwork.org", ESPProposals: []string{"aes256-sha1"}}, zap.NewNop())
	s.childSPI = 0x12345678
	payloads, err := s.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	p := ikev2.NewIKEPacket()
	p.Payloads = payloads
	wire, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(wire[ikev2.IKE_HEADER_LEN:]))
	if digest != "35ed57f804c934caf2ab94baa3480ff80f2018cead1d9eca060c29a612180e1f" {
		t.Fatalf("false-mode initial wire changed: %s", digest)
	}
	t.Logf("3HK-style false-mode initial inner wire: bytes=%d sha256=%s", len(wire)-ikev2.IKE_HEADER_LEN, digest)
}
