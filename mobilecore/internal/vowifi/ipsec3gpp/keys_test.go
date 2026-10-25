package ipsec3gpp

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func TestNativePolicyDirectionFixture(t *testing.T) {
	p, err := NewPolicy(PolicyInput{
		LocalIP: net.ParseIP("10.0.0.2"), RemoteIP: net.ParseIP("10.0.0.9"),
		LocalSPIC: 333, LocalSPIS: 444, LocalPortC: 5050, LocalPortS: 5060,
		Mech: SecurityMechanism{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", SPIc: 111, SPIs: 222, PortC: 6050, PortS: 6060},
		CK:   bytes.Repeat([]byte{0x11}, 16), IK: bytes.Repeat([]byte{0x22}, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.FlowC.OutboundSPI != 222 || p.FlowC.InboundSPI != 333 || p.FlowC.LocalPort != 5050 || p.FlowC.RemotePort != 6060 {
		t.Fatal("client flow differs from shared Rust fixture")
	}
	if p.FlowS.OutboundSPI != 111 || p.FlowS.InboundSPI != 444 || p.FlowS.LocalPort != 5060 || p.FlowS.RemotePort != 6050 {
		t.Fatal("server flow differs from shared Rust fixture")
	}
}

func TestNativeCBCWireFixture(t *testing.T) {
	sa, err := newSAForFlow(Flow{OutboundSPI: 42, AuthAlg: "hmac-sha-1-96", EncAlg: "aes-cbc", CK: bytes.Repeat([]byte{0x11}, 16), IK: bytes.Repeat([]byte{0x22}, 16)})
	if err != nil {
		t.Fatal(err)
	}
	// Fixed independent test key/IV, never used by the production sender.
	sa.IntegrityKey = bytes.Repeat([]byte{0x22}, 20)
	payload := bytes.Repeat([]byte{0x33}, 20)
	plain := append([]byte{}, payload...)
	for i := 1; i <= 10; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, 10, 6)
	header := []byte{0, 0, 0, 42, 0, 0, 0, 1}
	iv := bytes.Repeat([]byte{0x44}, 16)
	ciphertext, err := sa.EncryptionAlg.Encrypt(plain, sa.EncryptionKey, iv, header)
	if err != nil {
		t.Fatal(err)
	}
	wire := append(append(append([]byte{}, header...), iv...), ciphertext...)
	wire = append(wire, sa.IntegrityAlg2.Compute(sa.IntegrityKey, wire)...)
	if hex.EncodeToString(wire) != "0000002a0000000144444444444444444444444444444444dc44b424bcb85288ce3be42430864e8b29687bec19b041a7bd700c5353ba8ac3c8dece0d2b98e9920ce61645" {
		t.Fatal("CBC wire differs from Rust fixture")
	}
	decoded, err := decapsulateTransport(wire, sa)
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatal("Go fixture decode failed", err)
	}
}

func TestDeriveSecureChannelKeysAESCBCHMACSHA1(t *testing.T) {
	ck := bytes.Repeat([]byte{0x11}, 16)
	ik := bytes.Repeat([]byte{0x22}, 16)
	keys, err := DeriveSecureChannelKeys(Flow{
		AuthAlg: "hmac-sha-1-96",
		EncAlg:  "aes-cbc",
		CK:      ck,
		IK:      ik,
	})
	if err != nil {
		t.Fatalf("DeriveSecureChannelKeys: %v", err)
	}
	if !bytes.Equal(keys.EncKey, ck) {
		t.Fatalf("enc key mismatch: %x", keys.EncKey)
	}
	if len(keys.AuthKey) != 20 {
		t.Fatalf("auth key len %d, want 20", len(keys.AuthKey))
	}
	if !bytes.Equal(keys.AuthKey[:16], ik) || !bytes.Equal(keys.AuthKey[16:], make([]byte, 4)) {
		t.Fatalf("auth key mismatch: %x", keys.AuthKey)
	}
}
