package ikev2

import (
	"bytes"
	"testing"
)

func TestCertReqWireAndDetachedCopies(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3276} {
		p := &EncryptedPayloadCertReq{Encoding: 4, CertificateAuthorities: bytes.Repeat([]byte{0x35}, 20*count)}
		body, err := p.Encode()
		if err != nil || len(body) != 1+20*count || body[0] != 4 {
			t.Fatalf("count=%d body length=%d err=%v", count, len(body), err)
		}
		decoded, err := DecodePayloadCertReq(body)
		if err != nil || !bytes.Equal(decoded.CertificateAuthorities, p.CertificateAuthorities) {
			t.Fatal("CERTREQ roundtrip failed", err)
		}
		if count > 0 {
			body[1] ^= 1
			if decoded.CertificateAuthorities[0] != 0x35 || p.CertificateAuthorities[0] != 0x35 {
				t.Fatal("CERTREQ encode/decode aliases input")
			}
		}
	}
	p := NewIKEPacket()
	p.Payloads = []Payload{&EncryptedPayloadCertReq{Encoding: 4}}
	wire, err := p.Encode()
	if err != nil || !bytes.Equal(wire[IKE_HEADER_LEN:], []byte{0, 0, 0, 5, 4}) || wire[16] != 38 {
		t.Fatalf("empty CERTREQ wire=%x err=%v", wire, err)
	}
	decoded, err := DecodePacket(wire)
	if err != nil || len(decoded.Payloads) != 1 {
		t.Fatal("packet parser CERTREQ", err)
	}
	if _, ok := decoded.Payloads[0].(*EncryptedPayloadCertReq); !ok {
		t.Fatal("CERTREQ not typed")
	}
}

func TestCertReqRejectsMalformedAndUnsupportedBodies(t *testing.T) {
	for _, body := range [][]byte{nil, {4, 1}, append([]byte{4}, make([]byte, 19)...), append([]byte{4}, make([]byte, 21)...), append([]byte{4}, make([]byte, 65540)...), {0}, {12}, {13}} {
		if _, err := DecodePayloadCertReq(body); err == nil {
			t.Fatalf("accepted body length=%d", len(body))
		}
		if len(body) > 0 {
			if _, err := (&EncryptedPayloadCertReq{Encoding: body[0], CertificateAuthorities: body[1:]}).Encode(); err == nil {
				t.Fatalf("encoded invalid body length=%d", len(body))
			}
		}
	}
}

func TestPacketPreservesUnsupportedNoncriticalCertReq(t *testing.T) {
	for _, encoding := range []byte{0, 12, 13, 255} {
		p := NewIKEPacket()
		p.Payloads = []Payload{&RawPayload{PType: CERTREQ, Data: []byte{encoding, 7}}}
		wire, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodePacket(wire)
		if err != nil || len(decoded.Payloads) != 1 {
			t.Fatal("unsupported noncritical request rejected", err)
		}
		if raw, ok := decoded.Payloads[0].(*RawPayload); !ok || !bytes.Equal(raw.Data, []byte{encoding, 7}) {
			t.Fatal("opaque request lost")
		}
		wire[IKE_HEADER_LEN+1] = 0x80
		if _, err := DecodePacket(wire); err == nil {
			t.Fatal("unsupported critical CERTREQ accepted")
		}
	}
}
