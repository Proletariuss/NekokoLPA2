package ipsec3gpp

import (
	"bytes"
	"net"
	"testing"
)

func TestNewPolicyAndTransport(t *testing.T) {
	ck := bytes.Repeat([]byte{0x01}, 16)
	ik := bytes.Repeat([]byte{0x02}, 16)
	policy, err := NewPolicy(PolicyInput{
		LocalIP:   net.ParseIP("10.0.0.2"),
		RemoteIP:  net.ParseIP("10.0.0.1"),
		LocalSPIC: 0x33333333, LocalSPIS: 0x44444444, LocalPortC: 5064, LocalPortS: 5063,
		CK:      ck,
		IK:      ik,
		AuthAlg: "hmac-sha-1-96",
		EncAlg:  "aes-cbc",
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
		t.Fatalf("NewPolicy: %v", err)
	}
	if policy.FlowC.OutboundSPI != 0x22222222 || policy.FlowS.OutboundSPI != 0x11111111 ||
		policy.FlowC.InboundSPI != 0x33333333 || policy.FlowS.InboundSPI != 0x44444444 {
		t.Fatalf("unexpected flow SPIs: %+v %+v", policy.FlowC, policy.FlowS)
	}
	if _, err := NewTransport(policy); err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
}

func TestTransportOutboundInboundIPv4(t *testing.T) {
	ck := bytes.Repeat([]byte{0x01}, 16)
	ik := bytes.Repeat([]byte{0x02}, 16)
	policy, err := NewPolicy(PolicyInput{
		LocalIP:   net.ParseIP("10.0.0.2"),
		RemoteIP:  net.ParseIP("10.0.0.1"),
		LocalSPIC: 0x33333333, LocalSPIS: 0x44444444, LocalPortC: 5064, LocalPortS: 5063,
		CK:      ck,
		IK:      ik,
		AuthAlg: "hmac-sha-1-96",
		EncAlg:  "aes-cbc",
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
		t.Fatalf("NewPolicy: %v", err)
	}
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	sip := []byte("REGISTER sip:ims.example.org SIP/2.0\r\n\r\n")
	plainPacket, err := buildOutboundTCPPacket(policy, sip)
	if err != nil {
		t.Fatalf("buildOutboundTCPPacket: %v", err)
	}
	encrypted, err := transport.TransformOutbound(plainPacket)
	if err != nil {
		t.Fatalf("TransformOutbound: %v", err)
	}
	parsed, err := parseIPPacket(encrypted)
	if err != nil {
		t.Fatalf("parseIPPacket encrypted: %v", err)
	}
	if parsed.nextHeader != ipProtoESP {
		t.Fatalf("expected ESP protocol, got %d", parsed.nextHeader)
	}

	// Simulate a server-originated ESP packet (SPIs) back to the UE.
	inboundFlow := policy.FlowC
	inboundFlow.OutboundSPI = inboundFlow.InboundSPI
	serverFlow, err := newTransportFlow(inboundFlow)
	if err != nil {
		t.Fatal(err)
	}
	tcpPayload := buildMinimalTCPSegment(policy.FlowC.RemotePort, policy.FlowC.LocalPort, sip)
	esp, err := encapsulateTransport(tcpPayload, serverFlow.sa, ipProtoTCP)
	if err != nil {
		t.Fatalf("encapsulateTransport: %v", err)
	}
	inboundIP := buildIPv4Packet(policy.RemoteIP, policy.LocalIP, ipProtoESP, esp)
	decrypted, err := transport.TransformInbound(inboundIP)
	if err != nil {
		t.Fatalf("TransformInbound: %v", err)
	}
	gotParsed, err := parseIPPacket(decrypted)
	if err != nil {
		t.Fatalf("parseIPPacket decrypted: %v", err)
	}
	if !bytes.Contains(gotParsed.transportPayload, sip) {
		t.Fatalf("missing SIP payload in %x", gotParsed.transportPayload)
	}
}
