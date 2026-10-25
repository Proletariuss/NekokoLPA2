package ipsec3gpp

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

type recordingPacketDataplane struct {
	rx chan []byte
	tx chan []byte

	mu               sync.Mutex
	innerPacketCalls int
}

func newRecordingPacketDataplane() *recordingPacketDataplane {
	return &recordingPacketDataplane{
		rx: make(chan []byte, 16),
		tx: make(chan []byte, 16),
	}
}

func (d *recordingPacketDataplane) SendInnerPacket(packet []byte) error {
	d.tx <- append([]byte(nil), packet...)
	return nil
}

func (d *recordingPacketDataplane) InnerPackets() <-chan []byte {
	d.mu.Lock()
	d.innerPacketCalls++
	d.mu.Unlock()
	return d.rx
}

func (d *recordingPacketDataplane) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.innerPacketCalls
}

func testTransformingPolicy(t *testing.T, remote string) Policy {
	t.Helper()
	policy, err := NewPolicy(PolicyInput{
		LocalIP:   net.ParseIP("10.0.0.2"),
		RemoteIP:  net.ParseIP(remote),
		LocalSPIC: 0x33333333, LocalSPIS: 0x44444444, LocalPortC: 5064, LocalPortS: 5063,
		CK: bytes.Repeat([]byte{0x11}, 16),
		IK: bytes.Repeat([]byte{0x22}, 16),
		Mech: SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  0x11111111,
			SPIs:  0x22222222,
			PortC: 6054,
			PortS: 6060,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func receivePacket(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case packet, ok := <-ch:
		if !ok {
			t.Fatal("packet channel closed")
		}
		return packet
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet")
		return nil
	}
}

func TestTransformingDataplanePlainInstallAndReplace(t *testing.T) {
	source := newRecordingPacketDataplane()
	dp, err := NewTransformingDataplane(source)
	if err != nil {
		t.Fatal(err)
	}
	defer dp.Close()

	// Repeated consumers of the wrapper never subscribe to the SWu source
	// again. Only the wrapper's one receive pump owns that queue.
	_ = dp.InnerPackets()
	_ = dp.InnerPackets()
	if got := source.calls(); got != 1 {
		t.Fatalf("source InnerPackets calls=%d, want 1", got)
	}

	plain := buildIPv4Packet(
		net.ParseIP("10.0.0.2").To4(),
		net.ParseIP("10.0.0.1").To4(),
		17,
		[]byte("initial-register"),
	)
	if err := dp.SendInnerPacket(plain); err != nil {
		t.Fatal(err)
	}
	if got := receivePacket(t, source.tx); !bytes.Equal(got, plain) {
		t.Fatalf("pre-install outbound changed:\n got %x\nwant %x", got, plain)
	}
	source.rx <- plain
	if got := receivePacket(t, dp.InnerPackets()); !bytes.Equal(got, plain) {
		t.Fatalf("pre-install inbound changed:\n got %x\nwant %x", got, plain)
	}

	policy := testTransformingPolicy(t, "10.0.0.1")
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := dp.Install(transport); err != nil {
		t.Fatal(err)
	}

	protected, err := buildOutboundTCPPacket(policy, []byte("REGISTER sip:ims.example SIP/2.0\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dp.SendInnerPacket(protected); err != nil {
		t.Fatal(err)
	}
	encrypted := receivePacket(t, source.tx)
	parsedEncrypted, err := parseIPPacket(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if parsedEncrypted.nextHeader != ipProtoESP {
		t.Fatalf("installed outbound protocol=%d, want ESP", parsedEncrypted.nextHeader)
	}

	// A non-matching flow remains plain even while the SA is installed.
	nonMatchingTCP := buildIPv4Packet(
		policy.LocalIP,
		policy.RemoteIP,
		ipProtoTCP,
		buildMinimalTCPSegment(65000, 5060, []byte("not-protected")),
	)
	if err := dp.SendInnerPacket(nonMatchingTCP); err != nil {
		t.Fatal(err)
	}
	if got := receivePacket(t, source.tx); !bytes.Equal(got, nonMatchingTCP) {
		t.Fatalf("non-matching flow was changed:\n got %x\nwant %x", got, nonMatchingTCP)
	}

	// Simulate the P-CSCF's protected response. The wrapper must give the same
	// ordinary TCP packet back to gVisor, not SIP bytes inside a TCP stream.
	inboundTCP := buildMinimalTCPSegment(policy.FlowC.RemotePort, policy.FlowC.LocalPort, []byte("SIP/2.0 200 OK\r\n\r\n"))
	inboundFlow := policy.FlowC
	inboundFlow.OutboundSPI = inboundFlow.InboundSPI
	serverFlow, err := newTransportFlow(inboundFlow)
	if err != nil {
		t.Fatal(err)
	}
	esp, err := encapsulateTransport(inboundTCP, serverFlow.sa, ipProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	inboundESP := buildIPv4Packet(policy.RemoteIP, policy.LocalIP, ipProtoESP, esp)
	source.rx <- inboundESP
	decrypted := receivePacket(t, dp.InnerPackets())
	parsedDecrypted, err := parseIPPacket(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if parsedDecrypted.nextHeader != ipProtoTCP || !bytes.Equal(parsedDecrypted.transportPayload, inboundTCP) {
		t.Fatalf("inbound ESP did not become the original TCP packet")
	}

	// A replacement negotiation atomically changes selectors. The old flow is
	// rejected, so a stale protected socket cannot send SIP without its SA.
	replacement, err := NewTransport(testTransformingPolicy(t, "10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dp.Install(replacement); err != nil {
		t.Fatal(err)
	}
	if err := dp.SendInnerPacket(protected); err == nil {
		t.Fatal("stale protected registrar flow was not rejected")
	}
	select {
	case <-source.tx:
		t.Fatal("stale protected registrar flow escaped without its SA")
	default:
	}

	dp.Clear()
	if dp.Installed() {
		t.Fatal("Clear left transform installed")
	}
	stats := dp.Stats()
	if stats.OutboundPackets != 3 || stats.InboundPackets != 2 || stats.InboundDropped != 0 {
		t.Fatalf("unexpected transforming dataplane stats: %+v", stats)
	}
}

func TestTransformingDataplaneDropsUnauthenticatedESPAndClosesCleanly(t *testing.T) {
	source := newRecordingPacketDataplane()
	dp, err := NewTransformingDataplane(source)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewTransport(testTransformingPolicy(t, "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dp.Install(transport); err != nil {
		t.Fatal(err)
	}

	badESP := buildIPv4Packet(
		net.ParseIP("10.0.0.1").To4(),
		net.ParseIP("10.0.0.2").To4(),
		ipProtoESP,
		[]byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1},
	)
	source.rx <- badESP
	select {
	case err := <-dp.Errors():
		if err == nil {
			t.Fatal("nil transform error")
		}
	case <-time.After(time.Second):
		t.Fatal("missing inbound transform error")
	}
	select {
	case packet := <-dp.InnerPackets():
		t.Fatalf("unauthenticated ESP reached netstack: %x", packet)
	case <-time.After(20 * time.Millisecond):
	}
	if got := dp.Stats().InboundDropped; got != 1 {
		t.Fatalf("inbound dropped=%d, want 1", got)
	}

	if err := dp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dp.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case _, ok := <-dp.InnerPackets():
		if ok {
			t.Fatal("inbound channel remained open with a packet")
		}
	case <-time.After(time.Second):
		t.Fatal("inbound channel not closed")
	}
	if err := dp.SendInnerPacket([]byte{0x45}); err == nil {
		t.Fatal("send after Close succeeded")
	}
}
