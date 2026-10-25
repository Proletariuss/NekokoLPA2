package voiceclient

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestSWUUDPPacketRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name        string
		source      net.IP
		destination net.IP
	}{
		{name: "ipv4", source: net.ParseIP("10.0.0.10"), destination: net.ParseIP("10.0.0.20")},
		{name: "ipv6", source: net.ParseIP("2001:db8::10"), destination: net.ParseIP("2001:db8::20")},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("sip-datagram")
			packet, err := buildUDPPacket(test.source, test.destination, 5060, 5070, payload)
			if err != nil {
				t.Fatalf("build packet: %v", err)
			}
			got, source, ok := parseUDPDatagram(packet, test.destination, 5070)
			if !ok {
				t.Fatal("packet was not accepted by local endpoint")
			}
			if !bytes.Equal(got, payload) || source.Port != 5060 || !source.IP.Equal(test.source) {
				t.Fatalf("payload=%q source=%v", got, source)
			}
			if _, _, ok := parseUDPDatagram(packet, test.destination, 5080); ok {
				t.Fatal("packet for another local port was accepted")
			}
		})
	}
}

func TestBuildUDPPacketRejectsMixedAddressFamilies(t *testing.T) {
	if _, err := buildUDPPacket(net.ParseIP("10.0.0.1"), net.ParseIP("2001:db8::1"), 1, 2, nil); err == nil {
		t.Fatal("mixed IPv4/IPv6 packet was accepted")
	}
}

func TestBuildUDPPacketRejectsInvalidPorts(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, err := buildUDPPacket(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), port, 5060, nil); err == nil {
			t.Fatalf("source port %d was accepted", port)
		}
	}
}

func TestRegisterProfileIdentityAndDomainParsing(t *testing.T) {
	domain := "ims.mnc033.mcc234.3gppnetwork.org"
	privateID, publicURI := BuildIMSIdentity("234330123456789", domain, domain, "imsi_home_domain")
	if privateID != "234330123456789@ims.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("private identity=%q", privateID)
	}
	if publicURI != "sip:234330123456789@ims.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("public identity=%q", publicURI)
	}
	if mcc, mnc := mccMncFromIMSDomain(domain); mcc != "234" || mnc != "033" {
		t.Fatalf("MCC/MNC=%s/%s", mcc, mnc)
	}
}

func TestSIPTraceRedactsAuthenticationMaterial(t *testing.T) {
	raw := "REGISTER sip:ims.example SIP/2.0\r\nAuthorization: Digest username=secret,response=abcdef\r\nProxy-Authorization: Digest nonce=hidden\r\n\r\n"
	redacted := redactSIPMessage(raw)
	for _, secret := range []string{"secret", "abcdef", "hidden"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("trace leaked %q: %s", secret, redacted)
		}
	}
}

func TestFormatGSMAIMEIURN(t *testing.T) {
	if got := FormatGSMAIMEIURN("351234567890124"); got != "urn:gsma:imei:35123456-789012-0" {
		t.Fatalf("URN=%q", got)
	}
	if got := FormatGSMAIMEIURN("invalid"); got != "" {
		t.Fatalf("invalid IMEI produced %q", got)
	}
}
