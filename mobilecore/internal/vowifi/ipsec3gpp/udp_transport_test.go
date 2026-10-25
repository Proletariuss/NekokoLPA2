package ipsec3gpp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func testUDPPacket(p Policy, inbound bool, srcPort, dstPort int, body []byte) []byte {
	udp := make([]byte, 8+len(body))
	copy(udp[8:], body)
	binary.BigEndian.PutUint16(udp[:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	src, dst := p.LocalIP, p.RemoteIP
	if inbound {
		src, dst = dst, src
	}
	if len(src) == 4 {
		return buildIPv4Packet(src, dst, ipProtoUDP, udp)
	}
	return buildIPv6Packet(src, dst, ipProtoUDP, udp)
}

func TestUDPTransformPreservesProtocolAndFailsClosed(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		p := testTransformingPolicy(t, "10.0.0.1")
		if ipv6 {
			p.LocalIP = net.ParseIP("2001:db8::2").To16()
			p.RemoteIP = net.ParseIP("2001:db8::1").To16()
		}
		transport, err := NewTransport(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, flow := range []Flow{p.FlowC, p.FlowS} {
			outbound := testUDPPacket(p, false, flow.LocalPort, flow.RemotePort, []byte("REGISTER"))
			protected, err := transport.TransformOutbound(outbound)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parseIPPacket(protected)
			if err != nil || parsed.nextHeader != ipProtoESP {
				t.Fatalf("UDP escaped ESP: %v", err)
			}
			wrong := testUDPPacket(p, false, flow.LocalPort, flow.RemotePort+1, []byte("secret"))
			if _, err := transport.TransformOutbound(wrong); err == nil {
				t.Fatal("protected UDP source leaked to wrong destination")
			}
			plain := testUDPPacket(p, true, flow.RemotePort, flow.LocalPort, []byte("200 OK"))
			if _, err := transport.TransformInbound(plain); err == nil {
				t.Fatal("plaintext UDP entered protected port")
			}
			peerFlow := flow
			peerFlow.OutboundSPI = flow.InboundSPI
			peer, err := newTransportFlow(peerFlow)
			if err != nil {
				t.Fatal(err)
			}
			plainParsed, _ := parseIPPacket(plain)
			for _, protocol := range []uint8{ipProtoUDP, ipProtoTCP, 1} {
				payload := append([]byte(nil), plainParsed.transportPayload...)
				if protocol == ipProtoTCP {
					binary.BigEndian.PutUint16(payload[2:4], uint16(flow.LocalPort+1))
				}
				esp, err := encapsulateTransport(payload, peer.sa, protocol)
				if err != nil {
					t.Fatal(err)
				}
				packet, err := replaceIPPayload(plainParsed.header, esp, ipProtoESP)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := transport.TransformInbound(packet)
				if protocol != ipProtoUDP {
					if err == nil {
						t.Fatal("authenticated payload with wrong protocol or selector accepted")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := parseIPPacket(decoded)
				if err != nil || parsed.nextHeader != ipProtoUDP || !bytes.Equal(parsed.transportPayload, payload) {
					t.Fatal("UDP protocol/body not preserved")
				}
				if _, err := transport.TransformInbound(packet); err == nil {
					t.Fatal("replayed UDP ESP accepted")
				}
			}
		}
	}
}

func TestUDPFragmentReassemblyThenESP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		p := testTransformingPolicy(t, "10.0.0.1")
		if ipv6 {
			p.LocalIP = net.ParseIP("2001:db8::2").To16()
			p.RemoteIP = net.ParseIP("2001:db8::1").To16()
		}
		plain := testUDPPacket(p, false, p.LocalPortC, p.RemotePortS, bytes.Repeat([]byte("private"), 600))
		pretend := append([]byte(nil), plain...)
		if ipv6 {
			pretend[6] = ipProtoESP
		} else {
			pretend[9] = ipProtoESP
		}
		fragments, err := fragmentProtectedPacket(pretend)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range fragments {
			if ipv6 {
				fragment[40] = ipProtoUDP
			} else {
				fragment[9] = ipProtoUDP
				updateIPv4HeaderChecksum(fragment[:20])
			}
		}
		transport, err := NewTransport(p)
		if err != nil {
			t.Fatal(err)
		}
		for index := len(fragments) - 1; index >= 0; index-- {
			output, err := transport.TransformOutbound(fragments[index])
			if err != nil {
				t.Fatal(err)
			}
			if index > 0 {
				if output != nil {
					t.Fatal("incomplete plaintext fragments escaped transform")
				}
				continue
			}
			parsed, err := parseIPPacket(output)
			if err != nil || parsed.nextHeader != ipProtoESP {
				t.Fatal("reassembled UDP was not encrypted")
			}
			packets, err := fragmentProtectedPacket(output)
			if err != nil {
				t.Fatal(err)
			}
			var reassembly fragmentReassembler
			var result []byte
			for i := len(packets) - 1; i >= 0; i-- {
				if len(packets[i]) > 1280 {
					t.Fatal("ESP fragment exceeds MTU")
				}
				result, err = reassembly.process(packets[i])
				if err != nil {
					t.Fatal(err)
				}
			}
			reassembled, parseErr := parseIPPacket(result)
			if parseErr != nil || reassembled.nextHeader != parsed.nextHeader || !bytes.Equal(reassembled.transportPayload, parsed.transportPayload) {
				t.Fatal("fragmented ESP did not roundtrip")
			}
		}
		var overlapping fragmentReassembler
		if out, err := overlapping.process(fragments[0]); err != nil || out != nil {
			t.Fatal("unexpected first fragment result")
		}
		if out, err := overlapping.process(fragments[0]); err == nil || out != nil {
			t.Fatal("overlapping fragments accepted")
		}
	}
}
