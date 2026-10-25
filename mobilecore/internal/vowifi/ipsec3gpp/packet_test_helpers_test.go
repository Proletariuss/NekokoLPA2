package ipsec3gpp

import (
	"encoding/binary"
	"errors"
)

func buildOutboundTCPPacket(policy Policy, sipPayload []byte) ([]byte, error) {
	tcpSegment := buildMinimalTCPSegment(policy.FlowC.LocalPort, policy.FlowC.RemotePort, sipPayload)
	if len(policy.LocalIP) == 4 {
		return buildIPv4Packet(policy.LocalIP, policy.RemoteIP, ipProtoTCP, tcpSegment), nil
	}
	if len(policy.LocalIP) == 16 {
		return buildIPv6Packet(policy.LocalIP, policy.RemoteIP, ipProtoTCP, tcpSegment), nil
	}
	return nil, errors.New("ipsec3gpp: unsupported local IP length")
}

func buildMinimalTCPSegment(srcPort, dstPort int, payload []byte) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(hdr[4:8], 1)
	binary.BigEndian.PutUint32(hdr[8:12], 1)
	hdr[12] = 0x50
	hdr[13] = 0x18
	binary.BigEndian.PutUint16(hdr[14:16], 65535)
	return append(hdr, payload...)
}

func buildIPv4Packet(src, dst []byte, proto uint8, payload []byte) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	total := uint16(20 + len(payload))
	binary.BigEndian.PutUint16(hdr[2:4], total)
	hdr[8] = 64
	hdr[9] = proto
	copy(hdr[12:16], src)
	copy(hdr[16:20], dst)
	updateIPv4HeaderChecksum(hdr)
	return append(hdr, payload...)
}

func buildIPv6Packet(src, dst []byte, nextHeader uint8, payload []byte) []byte {
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(payload)))
	hdr[6] = nextHeader
	hdr[7] = 64
	copy(hdr[8:24], src)
	copy(hdr[24:40], dst)
	return append(hdr, payload...)
}
