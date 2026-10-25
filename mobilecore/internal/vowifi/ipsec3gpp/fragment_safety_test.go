package ipsec3gpp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func reviewFragment(ipv6 bool, offset int, more bool, protocol uint8) []byte {
	payload := bytes.Repeat([]byte{byte(offset + 1)}, 8)
	if !ipv6 {
		packet := buildIPv4Packet(net.IPv4(10, 0, 0, 2).To4(), net.IPv4(10, 0, 0, 1).To4(), protocol, payload)
		binary.BigEndian.PutUint16(packet[4:6], 99)
		flags := uint16(offset / 8)
		if more {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(packet[6:8], flags)
		updateIPv4HeaderChecksum(packet[:20])
		return packet
	}
	f := make([]byte, 8)
	f[0] = protocol
	flags := uint16(offset)
	if more {
		flags |= 1
	}
	binary.BigEndian.PutUint16(f[2:4], flags)
	binary.BigEndian.PutUint32(f[4:8], 99)
	return buildIPv6Packet(net.ParseIP("2001:db8::2").To16(), net.ParseIP("2001:db8::1").To16(), 44, append(f, payload...))
}
func TestFragmentTerminalTruncationCannotFabricateCompletePacket(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		var r fragmentReassembler
		for _, offset := range []int{0, 32, 16} {
			out, err := r.process(reviewFragment(ipv6, offset, true, ipProtoUDP))
			if err != nil || out != nil {
				t.Fatal("unexpected preliminary result", err)
			}
		}
		if out, err := r.process(reviewFragment(ipv6, 24, false, ipProtoUDP)); err == nil || out != nil {
			t.Fatal("accepted terminal truncation with an offset hole")
		}
	}
}
func TestFragmentKnownTerminalRejectsBeyondEndAndWaitsForHoles(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		var r fragmentReassembler
		if out, err := r.process(reviewFragment(ipv6, 24, false, ipProtoUDP)); err != nil || out != nil {
			t.Fatal(err)
		}
		if out, err := r.process(reviewFragment(ipv6, 40, true, ipProtoUDP)); err == nil || out != nil {
			t.Fatal("accepted bytes beyond known terminal")
		}
		var holes fragmentReassembler
		for _, offset := range []int{0, 24, 16} {
			if out, err := holes.process(reviewFragment(ipv6, offset, offset != 24, ipProtoUDP)); err != nil || out != nil {
				t.Fatal("incomplete packet escaped", err)
			}
		}
		out, err := holes.process(reviewFragment(ipv6, 8, true, ipProtoUDP))
		if err != nil || out == nil {
			t.Fatal("complete coverage not emitted", err)
		}
		parsed, err := parseIPPacket(out)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 32; i++ {
			if parsed.transportPayload[i] != byte((i/8)*8+1) {
				t.Fatal("reassembly fabricated or reordered bytes")
			}
		}
	}
}
func TestIPv6FragmentMetadataAndAtomicIsolation(t *testing.T) {
	for _, change := range []string{"protocol", "extension"} {
		var r fragmentReassembler
		if _, err := r.process(reviewFragment(true, 0, true, ipProtoUDP)); err != nil {
			t.Fatal(err)
		}
		terminal := reviewFragment(true, 8, false, ipProtoUDP)
		if change == "protocol" {
			terminal[40] = ipProtoTCP
		} else {
			hop := make([]byte, 8)
			hop[0] = 44
			terminal = append(append(append([]byte(nil), terminal[:40]...), hop...), terminal[40:]...)
			terminal[6] = 0
			binary.BigEndian.PutUint16(terminal[4:6], uint16(len(terminal)-40))
		}
		if out, err := r.process(terminal); err == nil || out != nil {
			t.Fatal("mixed IPv6 fragment metadata accepted:", change)
		}
	}
	var r fragmentReassembler
	if _, err := r.process(reviewFragment(true, 0, true, ipProtoUDP)); err != nil {
		t.Fatal(err)
	}
	atomic, err := r.process(reviewFragment(true, 0, false, ipProtoUDP))
	if err != nil || atomic == nil || len(r.sets) != 1 {
		t.Fatal("atomic fragment corrupted existing reassembly", err)
	}
	if out, err := r.process(reviewFragment(true, 8, false, ipProtoUDP)); err != nil || out == nil {
		t.Fatal("atomic fragment lost existing datagram", err)
	}
	// A Fragment header remaining in an atomic fragment's body must not be
	// treated as an ordinary 8-byte extension and bypass fragment validation.
	nested := reviewFragment(true, 0, false, 44)
	if out, err := r.process(nested); err == nil || out != nil {
		t.Fatal("nested fragment accepted")
	}
}
func TestProtectedTCPAndUDPPeerMismatchNeverPassthrough(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		p := testTransformingPolicy(t, "10.0.0.1")
		if ipv6 {
			p.LocalIP = net.ParseIP("2001:db8::2").To16()
			p.RemoteIP = net.ParseIP("2001:db8::1").To16()
		}
		tr, err := NewTransport(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, flow := range []Flow{p.FlowC, p.FlowS} {
			for _, protocol := range []uint8{ipProtoUDP, ipProtoTCP} {
				var wrong []byte
				if protocol == ipProtoUDP {
					wrong = testUDPPacket(p, false, flow.LocalPort, flow.RemotePort+1, []byte("private"))
				} else {
					payload := buildMinimalTCPSegment(flow.LocalPort, flow.RemotePort+1, []byte("private"))
					if ipv6 {
						wrong = buildIPv6Packet(p.LocalIP, p.RemoteIP, protocol, payload)
					} else {
						wrong = buildIPv4Packet(p.LocalIP, p.RemoteIP, protocol, payload)
					}
				}
				if out, err := tr.TransformOutbound(wrong); err == nil || out != nil {
					t.Fatal("protected source escaped on peer mismatch")
				}
			}
		}
	}
}
func TestIPv4OptionsChecksumCoversActualHeader(t *testing.T) {
	header := make([]byte, 24)
	header[0] = 0x46
	header[8] = 64
	header[9] = ipProtoUDP
	binary.BigEndian.PutUint16(header[2:4], 24)
	copy(header[20:], []byte{1, 1, 1, 1})
	updateIPv4HeaderChecksum(header)
	if ipv4HeaderChecksum(header) != 0 {
		t.Fatal("IPv4 checksum omitted options")
	}
}
