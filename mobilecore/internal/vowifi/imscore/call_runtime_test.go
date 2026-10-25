package imscore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/policy"
)

func TestG711SilenceVectors(t *testing.T) {
	pcm := make([]byte, 2)
	binary.LittleEndian.PutUint16(pcm, 0)
	if got := encodeG711(pcm, false); len(got) != 1 || got[0] != 0xff {
		t.Fatalf("mu-law silence = %x, want ff", got)
	}
	if got := encodeG711(pcm, true); len(got) != 1 || got[0] != 0xd5 {
		t.Fatalf("A-law silence = %x, want d5", got)
	}
}

func TestRTPPayloadStripsCSRCHeaderExtensionAndPadding(t *testing.T) {
	packet := make([]byte, 0, 32)
	packet = append(packet, 0xb1, 0x88) // v2, padding, extension, one CSRC; marker + PT 8
	packet = append(packet, make([]byte, 10)...)
	packet = append(packet, 0, 0, 0, 1)       // one CSRC
	packet = append(packet, 0xbe, 0xde, 0, 1) // extension header, one word
	packet = append(packet, 1, 2, 3, 4)
	packet = append(packet, 0xd5, 0xd5) // G.711 payload
	packet = append(packet, 0, 2)       // two padding bytes

	payload, payloadType, ok := rtpPayload(packet)
	if !ok || payloadType != 8 || len(payload) != 2 || payload[0] != 0xd5 || payload[1] != 0xd5 {
		t.Fatalf("payload=%x type=%d ok=%v", payload, payloadType, ok)
	}
}

func TestRTPPayloadRejectsMalformedExtension(t *testing.T) {
	packet := append([]byte{0x90, 0x08}, make([]byte, 10)...)
	packet = append(packet, 0xbe, 0xde, 0, 4, 1, 2)
	if _, _, ok := rtpPayload(packet); ok {
		t.Fatal("malformed RTP extension was accepted")
	}
}

func TestParsedRTPPacketCarriesSequenceTimestampAndMarker(t *testing.T) {
	packet := append([]byte{0x80, 0x80 | 97, 0x12, 0x34, 0, 0, 0x56, 0x78, 0, 0, 0, 1}, []byte{0xf0, 0x3c}...)
	parsed, ok := parseRTPPacket(packet)
	if !ok || parsed.payloadType != 97 || parsed.sequence != 0x1234 || parsed.timestamp != 0x5678 || parsed.ssrc != 1 || !parsed.marker {
		t.Fatalf("parsed RTP = %#v ok=%v", parsed, ok)
	}
}

func TestConcealPCMFrameAttenuatesPreviousSpeech(t *testing.T) {
	previous := make([]byte, 320)
	for offset := 0; offset < len(previous); offset += 2 {
		binary.LittleEndian.PutUint16(previous[offset:], uint16(int16(10_000)))
	}
	first := concealPCMFrame(previous, 1)
	second := concealPCMFrame(previous, 2)
	third := concealPCMFrame(previous, 3)
	if got := int16(binary.LittleEndian.Uint16(first)); got != 9_000 {
		t.Fatalf("first concealment sample=%d, want 9000", got)
	}
	if end, start := int16(binary.LittleEndian.Uint16(first[318:])), int16(binary.LittleEndian.Uint16(second)); int(end)-int(start) < -1 || int(end)-int(start) > 1 {
		t.Fatalf("concealment boundary jumps: first end=%d second start=%d", end, start)
	}
	if got := int16(binary.LittleEndian.Uint16(third[318:])); got != 0 {
		t.Fatalf("third concealment end=%d, want 0", got)
	}
}

func TestFadeInPCMFrameUsesRaisedCosine(t *testing.T) {
	frame := make([]byte, 320)
	for offset := 0; offset < len(frame); offset += 2 {
		binary.LittleEndian.PutUint16(frame[offset:], uint16(int16(10_000)))
	}
	fadeInPCMFrame(frame, 40)
	first := int16(binary.LittleEndian.Uint16(frame))
	fortieth := int16(binary.LittleEndian.Uint16(frame[78:]))
	unchanged := int16(binary.LittleEndian.Uint16(frame[80:]))
	if first <= 0 || first >= 100 || fortieth != 10_000 || unchanged != 10_000 {
		t.Fatalf("fade samples first=%d fortieth=%d unchanged=%d", first, fortieth, unchanged)
	}
}

func TestDTMFEventMapping(t *testing.T) {
	for digit, want := range map[string]byte{"0": 0, "9": 9, "*": 10, "#": 11} {
		got, ok := dtmfEvent(digit)
		if !ok || got != want {
			t.Fatalf("DTMF %q=%d,%v; want %d,true", digit, got, ok, want)
		}
	}
	if _, ok := dtmfEvent("A"); ok {
		t.Fatal("unsupported DTMF digit accepted")
	}
}

func TestResolveDTMFEventUsesNativeValidatorWithoutFallback(t *testing.T) {
	called := false
	runtime := &callRuntime{service: &Service{cfg: Config{
		DTMFEvent: func(_ context.Context, digit string) (byte, error) {
			called = true
			if digit != "#" {
				t.Fatalf("validator digit=%q", digit)
			}
			return 11, nil
		},
	}}}
	got, err := runtime.resolveDTMFEvent(context.Background(), " # ")
	if err != nil || !called || got != 11 {
		t.Fatalf("native DTMF got=%d called=%v err=%v", got, called, err)
	}

	runtime.service.cfg.DTMFEvent = func(context.Context, string) (byte, error) {
		return 0, errors.New("native unavailable")
	}
	if _, err := runtime.resolveDTMFEvent(context.Background(), "1"); err == nil || !strings.Contains(err.Error(), "native unavailable") {
		t.Fatalf("native DTMF error was not returned: %v", err)
	}
}

func TestSendDTMFUsesNegotiatedRFC4733Payload(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	runtime := &callRuntime{
		state:        CallState{State: "active"},
		media:        sender,
		remoteRTP:    receiver.LocalAddr().(*net.UDPAddr),
		dtmfPayload:  110,
		dtmfReady:    true,
		rtpSeq:       40,
		rtpTimestamp: 8_000,
		ssrc:         99,
	}
	errChannel := make(chan error, 1)
	go func() { errChannel <- runtime.sendDTMF(context.Background(), "1") }()
	_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 128)
	for index := 0; index < 7; index++ {
		n, _, readErr := receiver.ReadFromUDP(buffer)
		if readErr != nil {
			t.Fatal(readErr)
		}
		packet, ok := parseRTPPacket(buffer[:n])
		if !ok || packet.payloadType != 110 || packet.sequence != uint16(40+index) || packet.timestamp != 8_000 {
			t.Fatalf("event packet %d = %#v ok=%v", index, packet, ok)
		}
		if len(packet.payload) != 4 || packet.payload[0] != 1 {
			t.Fatalf("event payload %d = %x", index, packet.payload)
		}
		if (packet.payload[1]&0x80 != 0) != (index >= 4) {
			t.Fatalf("event end bit at packet %d = %x", index, packet.payload[1])
		}
	}
	if err := <-errChannel; err != nil {
		t.Fatal(err)
	}
	if runtime.rtpTimestamp != 9_120 {
		t.Fatalf("RTP timestamp=%d, want 9120", runtime.rtpTimestamp)
	}
}

func TestRemoteSDPStaticPCMAWithoutRTPMap(t *testing.T) {
	runtime := &callRuntime{}
	sdp := []byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 8 101\r\n")
	if err := runtime.applyRemoteSDP(sdp, true); err != nil {
		t.Fatal(err)
	}
	if runtime.state.Codec != "PCMA" || runtime.payloadType != 8 {
		t.Fatalf("codec=%q payload=%d", runtime.state.Codec, runtime.payloadType)
	}
	if runtime.remoteRTP == nil || runtime.remoteRTP.Port != 49170 {
		t.Fatalf("remote RTP = %#v", runtime.remoteRTP)
	}
}

func TestRemoteSDPAllowsBodylessFinalAfterNegotiatedEarlyMedia(t *testing.T) {
	runtime := &callRuntime{
		remoteRTP: &net.UDPAddr{IP: net.ParseIP("192.0.2.8"), Port: 49170},
		state:     CallState{Codec: "PCMA"},
	}
	if err := runtime.applyRemoteSDP(nil, true); err != nil {
		t.Fatalf("bodyless final SDP must reuse negotiated early media: %v", err)
	}
	if err := runtime.applyRemoteSDP(nil, false); err == nil {
		t.Fatal("bodyless offer must not reuse negotiated early media")
	}
}

func TestLocalSDPAdvertisesPCMAFirstWithCTExcelAMRFallback(t *testing.T) {
	runtime := &callRuntime{service: &Service{cfg: Config{LocalIP: net.ParseIP("192.0.2.10")}}}
	sdp := string(runtime.localSDP(49170))
	for _, want := range []string{
		"m=audio 49170 RTP/AVP 8 97 101",
		"a=rtpmap:8 PCMA/8000",
		"a=rtpmap:97 AMR/8000",
		"a=fmtp:97 octet-align=1;mode-set=7;max-red=0",
		"telephone-event/8000",
	} {
		if !strings.Contains(sdp, want) {
			t.Errorf("local SDP missing %q\n%s", want, sdp)
		}
	}
	if strings.Index(sdp, "PCMA/8000") > strings.Index(sdp, "AMR/8000") || strings.Contains(sdp, "PCMU") {
		t.Fatalf("unexpected codec advertised: %s", sdp)
	}
}

func TestRemoteSDPFallsBackToCTExcelAMRMode7(t *testing.T) {
	runtime := &callRuntime{}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP6 2001:db8::8\r\nm=audio 49170 RTP/AVP 97 101\r\na=rtpmap:97 AMR/8000\r\na=fmtp:97 max-red=0; mode-change-capability=2; mode-set=0,2,4,7; octet-align=1\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.state.Codec != "AMR" || runtime.payloadType != 97 || !runtime.dtmfReady {
		t.Fatalf("codec=%q payload=%d dtmf=%v", runtime.state.Codec, runtime.payloadType, runtime.dtmfReady)
	}
}

func TestRemoteSDPAcceptsBandwidthEfficientAMRMode7(t *testing.T) {
	runtime := &callRuntime{
		service: &Service{cfg: Config{LocalIP: net.ParseIP("2001:db8::10")}},
		state:   CallState{Direction: "incoming"},
	}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP6 2001:db8::8\r\nm=audio 49170 RTP/AVP 96 98\r\na=rtpmap:96 AMR/8000\r\na=fmtp:96 mode-set=0,2,4,7;mode-change-period=2;max-red=0\r\na=rtpmap:98 telephone-event/8000\r\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.state.Codec != "AMR" || runtime.payloadType != 96 || runtime.amrOctetAligned {
		t.Fatalf("codec=%q payload=%d octetAligned=%v", runtime.state.Codec, runtime.payloadType, runtime.amrOctetAligned)
	}
	sdp := string(runtime.localSDP(49172))
	if strings.Contains(sdp, "octet-align=1") || !strings.Contains(sdp, "a=fmtp:96 mode-set=7;max-red=0") {
		t.Fatalf("bandwidth-efficient answer mismatch:\n%s", sdp)
	}
}

func TestAMRMode7BandwidthEfficientRoundTrip(t *testing.T) {
	octetAligned := make([]byte, 33)
	octetAligned[0] = 0xf0
	octetAligned[1] = 7<<3 | 1<<2
	for index := 2; index < len(octetAligned); index++ {
		octetAligned[index] = byte(index*17 + 3)
	}
	// The final octet contains only four speech bits for mode 7.
	octetAligned[32] &= 0xf0
	packed, err := amrOctetAlignedToBandwidthEfficient(octetAligned)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) != 32 {
		t.Fatalf("packed length=%d, want 32", len(packed))
	}
	roundTrip, err := amrBandwidthEfficientToOctetAligned(packed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, octetAligned) {
		t.Fatalf("round-trip mismatch\n got %x\nwant %x", roundTrip, octetAligned)
	}
}

func TestIncomingO2ViaResponseRemainsValid(t *testing.T) {
	raw := "INVITE sip:user@example.invalid SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP [2a03:dd00:1f80:1860::4]:6060;oc-algo=\"LOSS\";oc;branch=z9hG4bK-test\r\n" +
		"From: <sip:caller@example.invalid>;tag=caller\r\n" +
		"To: <sip:user@example.invalid>\r\n" +
		"Call-ID: test-call\r\n" +
		"CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	msg, err := sip.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	req, ok := msg.(*sip.Request)
	if !ok {
		t.Fatalf("message type %T", msg)
	}
	response := newIncomingResponse(req, 180, "Ringing", nil)
	if strings.Count(response.Via().Value(), "branch=") != 1 {
		t.Fatalf("malformed response Via: %s", response.Via().Value())
	}
	if !strings.Contains(response.Via().Value(), `oc-algo="LOSS";oc;branch=z9hG4bK-test`) {
		t.Fatalf("response Via lost O2 overload-control parameters: %s", response.Via().Value())
	}
}

func TestRemoteSDPPrefersPCMAWhenBothAreAvailable(t *testing.T) {
	runtime := &callRuntime{}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 97 8\r\na=rtpmap:97 AMR/8000\r\na=fmtp:97 octet-align=1;mode-set=7\r\na=rtpmap:8 PCMA/8000\r\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.state.Codec != "PCMA" || runtime.payloadType != 8 {
		t.Fatalf("codec=%q payload=%d", runtime.state.Codec, runtime.payloadType)
	}
}

func TestRemoteSDPAcceptsDynamicPCMAOffer(t *testing.T) {
	runtime := &callRuntime{}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 97 101\r\na=rtpmap:97 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.state.Codec != "PCMA" || runtime.payloadType != 97 {
		t.Fatalf("codec=%q payload=%d", runtime.state.Codec, runtime.payloadType)
	}
	if !runtime.dtmfReady || runtime.dtmfPayload != 101 {
		t.Fatalf("DTMF ready=%v payload=%d", runtime.dtmfReady, runtime.dtmfPayload)
	}
}

func TestRemoteSDPRejectsUnsupportedAMRWBOnlyOffer(t *testing.T) {
	runtime := &callRuntime{}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n"), false)
	if err == nil || !strings.Contains(err.Error(), "PCMA 或 AMR-NB") {
		t.Fatalf("AMR-WB-only offer error = %v", err)
	}
}

func TestRemoteSDPRejectsHostname(t *testing.T) {
	runtime := &callRuntime{}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 media.example.test\r\nm=audio 49170 RTP/AVP 8\r\n"), false)
	if err == nil {
		t.Fatal("expected hostname SDP to fail closed")
	}
}

func TestPCMAAnswerPreservesDynamicMappingWithoutAddingDTMF(t *testing.T) {
	runtime := &callRuntime{service: &Service{cfg: Config{LocalIP: net.ParseIP("192.0.2.10")}}}
	runtime.state.Direction = "incoming"
	if err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 110\r\na=rtpmap:110 PCMA/8000/1\r\nm=video 49172 RTP/AVP 96\r\nc=IN IP4 192.0.2.99\r\na=rtpmap:96 H264/90000\r\n"), false); err != nil {
		t.Fatal(err)
	}
	sdp := string(runtime.localSDP(49174))
	if !strings.Contains(sdp, "m=audio 49174 RTP/AVP 110\r\n") || strings.Contains(sdp, "telephone-event") {
		t.Fatalf("answer changed offered mappings: %s", sdp)
	}
	if !runtime.remoteRTP.IP.Equal(net.ParseIP("192.0.2.8")) {
		t.Fatalf("video address overwrote audio: %v", runtime.remoteRTP)
	}
}

func TestPCMARejectsUnadvertisedAnswerMapping(t *testing.T) {
	runtime := &callRuntime{}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 110\r\na=rtpmap:110 PCMA/8000\r\n"), true)
	if err == nil || runtime.remoteRTP != nil {
		t.Fatal("answer must not introduce an unoffered payload type")
	}
}

func TestEmergencyNumberGuard(t *testing.T) {
	for _, value := range []string{"112", "911", "999", "+1 911"} {
		if !isEmergencyNumber(value) {
			t.Fatalf("%q was not classified as emergency", value)
		}
	}
	if isEmergencyNumber("+447700900123") {
		t.Fatal("ordinary number classified as emergency")
	}
}

func TestInviteUsesRegisteredE164MMTELIdentity(t *testing.T) {
	const domain = "ims.mnc010.mcc234.3gppnetwork.org"
	service := &Service{
		cfg: Config{
			LocalIP:        net.ParseIP("2001:db8::10"),
			PCSCFAddr:      "[2001:db8::20]:5060",
			Realm:          domain,
			HomeDomain:     domain,
			PublicURI:      "sip:234109876543210@" + domain,
			IMSI:           "234109876543210",
			SIPInstanceURN: "urn:gsma:imei:35123456-789012-3",
			UserAgent:      "Proletarius/0.04",
			Template: policy.IMSRegisterTemplate{
				ContactMode:              "gsma",
				ContactParamOrder:        []string{"audio", "icsi_ref"},
				IncludePANIAuthenticated: true,
			},
		},
		registeredMSISDN: "+447831803313",
		transportRuntime: &transportRuntime{policy: ipsec3gpp.Policy{
			LocalPortC: 5064,
			LocalPortS: 5063,
		}},
	}
	runtime := newCallRuntime(service)
	wire, err := runtime.buildRequest(sip.INVITE, "+8618907313060", "call@example.test", 1, []byte("v=0\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	message := string(wire)
	for _, want := range []string{
		"INVITE tel:+8618907313060 SIP/2.0",
		"Via: SIP/2.0/TCP [2001:db8::10]:5064;branch=",
		";rport",
		"From: <sip:+447831803313@" + domain + ";user=phone>;tag=",
		"P-Preferred-Identity: <tel:+447831803313>",
		"P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel",
		`Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
		"P-Access-Network-Info: IEEE-802.11;i-wlan-node-id=000000000000;network-provided",
		"Contact: <sip:[2001:db8::10]:5063>;audio;+g.3gpp.icsi-ref=",
		"Session-Expires: 1800;refresher=uac",
		"Min-SE: 90",
		"Supported: 100rel,timer,replaces",
		"User-Agent: Proletarius/0.04",
		"Accept: application/sdp",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("INVITE missing %q\n%s", want, message)
		}
	}
	if strings.Contains(message, "Supported: 100rel,timer,precondition") {
		t.Fatalf("INVITE advertised unsupported precondition token\n%s", message)
	}
}

func TestInviteIdentityFallsBackToPublicURI(t *testing.T) {
	const publicURI = "sip:234109876543210@ims.example.test"
	runtime := &callRuntime{service: &Service{cfg: Config{PublicURI: publicURI}}}
	from, preferred := runtime.originatingIdentities()
	if from != publicURI || preferred != publicURI {
		t.Fatalf("fallback identities = %q, %q; want %q", from, preferred, publicURI)
	}
}

func TestLocalServiceNumberUsesHomePhoneContext(t *testing.T) {
	service := &Service{
		cfg: Config{
			LocalIP:    net.ParseIP("2001:db8::10"),
			PCSCFAddr:  "[2001:db8::20]:5060",
			HomeDomain: "ims.mnc033.mcc234.3gppnetwork.org",
			PublicURI:  "sip:subscriber@ims.mnc033.mcc234.3gppnetwork.org",
		},
		transportRuntime: &transportRuntime{policy: ipsec3gpp.Policy{LocalPortC: 5064, LocalPortS: 5063}},
	}
	runtime := newCallRuntime(service)
	wire, err := runtime.buildRequest(sip.INVITE, "888", "short@example.test", 1, []byte("v=0\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	message := string(wire)
	target := "tel:888;phone-context=ims.mnc033.mcc234.3gppnetwork.org"
	if !strings.Contains(message, "INVITE "+target+" SIP/2.0") {
		t.Fatalf("local service Request-URI missing phone-context\n%s", message)
	}
	if !strings.Contains(message, "To: <"+target+">") {
		t.Fatalf("local service To missing phone-context\n%s", message)
	}
}

func TestInviteAddsCarrierEarlyMediaHeader(t *testing.T) {
	service := &Service{
		cfg: Config{
			LocalIP:    net.ParseIP("2001:db8::10"),
			PCSCFAddr:  "[2001:db8::20]:5060",
			HomeDomain: "ims.mnc033.mcc234.3gppnetwork.org",
			PublicURI:  "sip:subscriber@ims.mnc033.mcc234.3gppnetwork.org",
			Template:   policy.IMSRegisterTemplate{SupportPEarlyMedia: true, EarlyMediaNeedsHeader: true},
		},
		transportRuntime: &transportRuntime{policy: ipsec3gpp.Policy{LocalPortC: 5064, LocalPortS: 5063}},
	}
	wire, err := newCallRuntime(service).buildRequest(sip.INVITE, "888", "early@example.test", 1, []byte("v=0\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), "P-Early-Media: supported") {
		t.Fatalf("missing P-Early-Media header\n%s", wire)
	}
}

func TestLocalServiceNumberPrefersCarrierPhoneContext(t *testing.T) {
	service := &Service{
		cfg: Config{
			LocalIP:          net.ParseIP("2001:db8::10"),
			PCSCFAddr:        "[2001:db8::20]:5060",
			HomeDomain:       "ims.mnc033.mcc234.3gppnetwork.org",
			CallPhoneContext: "ims.mnc030.mcc234.3gppnetwork.org",
			PublicURI:        "sip:subscriber@ims.mnc033.mcc234.3gppnetwork.org",
		},
		transportRuntime: &transportRuntime{policy: ipsec3gpp.Policy{LocalPortC: 5064, LocalPortS: 5063}},
	}
	runtime := newCallRuntime(service)
	wire, err := runtime.buildRequest(sip.INVITE, "888", "ctexcel@example.test", 1, []byte("v=0\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if target := "tel:888;phone-context=ims.mnc030.mcc234.3gppnetwork.org"; !strings.Contains(string(wire), "INVITE "+target+" SIP/2.0") {
		t.Fatalf("CTExcel short code did not use host IMS context\n%s", wire)
	}
}

func TestNormalizeCallTargetPreservesGlobalNumber(t *testing.T) {
	got, err := normalizeCallTarget("+86 189-0731-3060", "ims.example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "tel:+8618907313060" {
		t.Fatalf("global target=%q", got)
	}
}

func TestNetwork487HasDistinctError(t *testing.T) {
	err := callRejectionError(sip.NewResponse(487, "Request Terminated"))
	if err == nil || !strings.Contains(err.Error(), "运营商终止呼叫") {
		t.Fatalf("487 error=%v", err)
	}
}

func TestLocalCancelStaysStickyAcrossProvisionalRetransmission(t *testing.T) {
	runtime := &callRuntime{
		state:           CallState{State: "cancelling", EarlyMedia: true, MediaReady: true},
		cancelRequested: true,
	}
	if runtime.updateProvisionalState(true) {
		t.Fatal("retransmitted 183 restarted media after local CANCEL")
	}
	if runtime.state.State != "cancelling" {
		t.Fatalf("state=%q, want cancelling", runtime.state.State)
	}
}

func TestRepeatedHangupWhileCancellingIsIdempotent(t *testing.T) {
	runtime := &callRuntime{state: CallState{State: "cancelling"}, cseq: 9, cancelRequested: true}
	if err := runtime.hangup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.cseq != 9 || runtime.state.State != "cancelling" {
		t.Fatalf("repeated hangup mutated transaction: cseq=%d state=%q", runtime.cseq, runtime.state.State)
	}
}

func TestIncomingInvitePublishesCallerAndRinging(t *testing.T) {
	runtime := newCallRuntime(&Service{cfg: Config{LocalIP: net.ParseIP("192.0.2.10")}})
	request := sip.NewRequest(sip.INVITE, sip.Uri{User: "callee", Host: "ims.example.test"})
	request.AppendHeader(sip.NewHeader("From", `"Caller" <sip:+447700900123@ims.example.test;user=phone>;tag=remote`))
	request.AppendHeader(sip.NewHeader("To", "<sip:callee@ims.example.test>"))
	request.AppendHeader(sip.NewHeader("Call-ID", "incoming@example.test"))
	request.AppendHeader(sip.NewHeader("CSeq", "1 INVITE"))
	request.SetBody([]byte("v=0\r\nc=IN IP4 192.0.2.20\r\nm=audio 40000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"))

	var statuses []int
	runtime.handleRequest(request, func(response *sip.Response) error {
		statuses = append(statuses, response.StatusCode)
		return nil
	})
	state := runtime.snapshot()
	if state.State != "incoming" || state.Direction != "incoming" || state.Peer != "+447700900123" || !state.SignalingOK {
		t.Fatalf("incoming state=%+v", state)
	}
	if len(statuses) != 2 || statuses[0] != 100 || statuses[1] != 180 {
		t.Fatalf("responses=%v, want [100 180]", statuses)
	}
}

func TestIncomingInviteResponseWriteFailureDoesNotLeaveGhostCall(t *testing.T) {
	for _, failOn := range []int{100, 180} {
		t.Run(fmt.Sprintf("status_%d", failOn), func(t *testing.T) {
			runtime := newCallRuntime(&Service{cfg: Config{LocalIP: net.ParseIP("192.0.2.10")}})
			runtime.handleRequest(testIncomingInvite(fmt.Sprintf("write-failure-%d@example.test", failOn), 1), func(response *sip.Response) error {
				if response.StatusCode == failOn {
					return net.ErrClosed
				}
				return nil
			})

			state := runtime.snapshot()
			if state.State != "failed" || state.LastError == "" {
				t.Fatalf("state after %d write failure = %+v", failOn, state)
			}
			runtime.mu.Lock()
			if runtime.incoming != nil || runtime.respond != nil || runtime.remoteRTP != nil || runtime.media != nil || runtime.audioConn != nil {
				runtime.mu.Unlock()
				t.Fatalf("write failure %d left incoming call resources allocated", failOn)
			}
			runtime.mu.Unlock()

			var retryStatuses []int
			runtime.handleRequest(testIncomingInvite(fmt.Sprintf("after-write-failure-%d@example.test", failOn), 1), func(response *sip.Response) error {
				retryStatuses = append(retryStatuses, response.StatusCode)
				return nil
			})
			if len(retryStatuses) != 2 || retryStatuses[0] != 100 || retryStatuses[1] != 180 {
				t.Fatalf("responses after %d write failure = %v, want [100 180]", failOn, retryStatuses)
			}
			if state := runtime.snapshot(); state.State != "incoming" {
				t.Fatalf("new INVITE after %d write failure state = %+v", failOn, state)
			}
		})
	}
}

func TestInitialIncomingTryingFailureCannotTerminateQueuedLocalDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Keep the outbound SIP write pending after dial has claimed its own call
	// slot. This makes the assertion sensitive to the old race: an initial
	// inbound 100 failure used to run finish() after a concurrent local dial had
	// already populated this runtime.
	runtime := newCallRuntime(&Service{
		cfg: Config{
			LocalIP:    net.ParseIP("192.0.2.10"),
			HomeDomain: "ims.example.test",
			Realm:      "ims.example.test",
		},
		network:      localMediaIMSNetwork{},
		lifecycleCtx: ctx,
		transportRuntime: &transportRuntime{
			policy:     ipsec3gpp.Policy{LocalPortC: 5064, LocalPortS: 5063},
			responses:  make(map[string]map[uint64]chan *sip.Response),
			tcpWriteCh: make(chan sipWriteTask),
		},
	})
	defer runtime.finish("ended", nil)

	tryingStarted := make(chan struct{})
	allowTryingFailure := make(chan struct{})
	incomingDone := make(chan struct{})
	go func() {
		runtime.handleRequest(testIncomingInvite("blocked-trying@example.test", 1), func(response *sip.Response) error {
			if response.StatusCode == 100 {
				close(tryingStarted)
				<-allowTryingFailure
				return net.ErrClosed
			}
			return nil
		})
		close(incomingDone)
	}()
	select {
	case <-tryingStarted:
	case <-time.After(time.Second):
		t.Fatal("initial 100 Trying did not start")
	}

	dialDone := make(chan error, 1)
	go func() { dialDone <- runtime.dial(ctx, "+447700900123") }()
	// dial must wait at the call-slot boundary, rather than replace idle state
	// while the first INVITE's responder is still unresolved.
	select {
	case err := <-dialDone:
		t.Fatalf("local dial escaped inbound transaction reservation early: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	if state := runtime.snapshot(); state.State != "idle" || state.CallID != "" {
		t.Fatalf("queued local dial mutated inbound reservation state: %+v", state)
	}

	close(allowTryingFailure)
	select {
	case <-incomingDone:
	case <-time.After(time.Second):
		t.Fatal("initial INVITE did not finish after response failure")
	}
	// The intentionally unserved write channel is released by cancellation.
	// Its terminal state must still retain the local call identity; the failed
	// inbound transaction is no longer allowed to clear it.
	cancel()
	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("queued local dial did not observe cancellation")
	}
	state := runtime.snapshot()
	if state.Direction != "outgoing" || state.CallID == "" || state.CallID == "blocked-trying@example.test" {
		t.Fatalf("inbound failure cleared later local dial: %+v", state)
	}
}

func TestIncomingDuplicateRingingCannotFollowFinalAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := newCallRuntime(&Service{
		cfg:          Config{LocalIP: net.ParseIP("192.0.2.10")},
		network:      localMediaIMSNetwork{},
		lifecycleCtx: ctx,
	})
	defer runtime.finish("ended", nil)

	invite := testIncomingInvite("duplicate-before-answer@example.test", 1)
	var responsesMu sync.Mutex
	var responses []int
	ringingCount := 0
	duplicateRingingStarted := make(chan struct{})
	allowDuplicateRinging := make(chan struct{})
	respond := func(response *sip.Response) error {
		if response.StatusCode == 180 {
			responsesMu.Lock()
			ringingCount++
			duplicate := ringingCount == 2
			responsesMu.Unlock()
			if duplicate {
				close(duplicateRingingStarted)
				<-allowDuplicateRinging
			}
		}
		responsesMu.Lock()
		responses = append(responses, response.StatusCode)
		responsesMu.Unlock()
		return nil
	}

	runtime.handleRequest(invite, respond)
	duplicateDone := make(chan struct{})
	go func() {
		runtime.handleRequest(invite, respond)
		close(duplicateDone)
	}()
	select {
	case <-duplicateRingingStarted:
	case <-time.After(time.Second):
		t.Fatal("duplicate INVITE did not reach its ringing response")
	}

	answerDone := make(chan error, 1)
	go func() { answerDone <- runtime.answer(ctx) }()
	// A duplicate provisional response is serialized with the final answer. If
	// it was allowed to unlock before write, the 200 could be emitted first and
	// the delayed 180 would violate SIP transaction ordering.
	select {
	case err := <-answerDone:
		t.Fatalf("answer completed before duplicate 180 committed: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	close(allowDuplicateRinging)
	select {
	case <-duplicateDone:
	case <-time.After(time.Second):
		t.Fatal("duplicate INVITE did not complete")
	}
	if err := <-answerDone; err != nil {
		t.Fatalf("answer incoming call: %v", err)
	}
	responsesMu.Lock()
	got := append([]int(nil), responses...)
	responsesMu.Unlock()
	if want := []int{100, 180, 180, 200}; !slices.Equal(got, want) {
		t.Fatalf("responses=%v, want %v", got, want)
	}
}

func TestIncomingRetransmitAndUnrelatedDialogCannotInterruptCall(t *testing.T) {
	runtime := newCallRuntime(&Service{cfg: Config{LocalIP: net.ParseIP("192.0.2.10")}})
	invite := sip.NewRequest(sip.INVITE, sip.Uri{User: "callee", Host: "ims.example.test"})
	invite.AppendHeader(sip.NewHeader("From", "<sip:caller@ims.example.test>;tag=remote"))
	invite.AppendHeader(sip.NewHeader("To", "<sip:callee@ims.example.test>"))
	invite.AppendHeader(sip.NewHeader("Call-ID", "first@example.test"))
	invite.AppendHeader(sip.NewHeader("CSeq", "1 INVITE"))
	invite.SetBody([]byte("v=0\r\nc=IN IP4 192.0.2.20\r\nm=audio 40000 RTP/AVP 8\r\n"))
	var responses []*sip.Response
	respond := func(response *sip.Response) error {
		responses = append(responses, response)
		return nil
	}
	runtime.handleRequest(invite, respond)
	if len(responses) != 2 || responses[0].StatusCode != 100 || responses[1].StatusCode != 180 {
		t.Fatalf("initial INVITE responses=%v", responses)
	}
	tag, _ := responses[1].To().Params.Get("tag")
	runtime.handleRequest(invite, respond)
	if len(responses) != 3 || responses[2].StatusCode != 180 {
		t.Fatalf("retransmitted INVITE responses=%v, want another 180", responses)
	}
	duplicateTag, _ := responses[2].To().Params.Get("tag")
	if tag == "" || duplicateTag != tag {
		t.Fatalf("retransmitted INVITE changed To tag: %q -> %q", tag, duplicateTag)
	}
	newTransaction := sip.NewRequest(sip.INVITE, sip.Uri{User: "callee", Host: "ims.example.test"})
	newTransaction.AppendHeader(sip.NewHeader("Call-ID", "first@example.test"))
	newTransaction.AppendHeader(sip.NewHeader("CSeq", "2 INVITE"))
	runtime.handleRequest(newTransaction, respond)
	if responses[len(responses)-1].StatusCode != 486 || runtime.snapshot().State != "incoming" {
		t.Fatal("different INVITE transaction was treated as a retransmission")
	}

	for _, method := range []sip.RequestMethod{sip.CANCEL, sip.BYE, sip.ACK} {
		unrelated := sip.NewRequest(method, sip.Uri{User: "callee", Host: "ims.example.test"})
		unrelated.AppendHeader(sip.NewHeader("Call-ID", "other@example.test"))
		unrelated.AppendHeader(sip.NewHeader("CSeq", "1 "+string(method)))
		before := len(responses)
		runtime.handleRequest(unrelated, respond)
		if method == sip.ACK {
			if len(responses) != before {
				t.Fatal("ACK must not receive a SIP response")
			}
		} else if len(responses) != before+1 || responses[before].StatusCode != 481 {
			t.Fatalf("unrelated %s responses=%v, want 481", method, responses[before:])
		}
		if got := runtime.snapshot().State; got != "incoming" {
			t.Fatalf("unrelated %s ended current call: %s", method, got)
		}
	}
	wrongSequence := sip.NewRequest(sip.CANCEL, sip.Uri{User: "callee", Host: "ims.example.test"})
	wrongSequence.AppendHeader(sip.NewHeader("Call-ID", "first@example.test"))
	wrongSequence.AppendHeader(sip.NewHeader("CSeq", "2 CANCEL"))
	runtime.handleRequest(wrongSequence, respond)
	if responses[len(responses)-1].StatusCode != 481 || runtime.snapshot().State != "incoming" {
		t.Fatal("CANCEL with the right Call-ID but wrong CSeq ended the call")
	}
	validCancel := sip.NewRequest(sip.CANCEL, sip.Uri{User: "callee", Host: "ims.example.test"})
	validCancel.AppendHeader(sip.NewHeader("Call-ID", "first@example.test"))
	validCancel.AppendHeader(sip.NewHeader("CSeq", "1 CANCEL"))
	before := len(responses)
	runtime.handleRequest(validCancel, respond)
	if len(responses) != before+2 || responses[before].StatusCode != 200 || responses[before+1].StatusCode != 487 || runtime.snapshot().State != "ended" {
		t.Fatalf("matching CANCEL responses=%v, state=%s", responses[before:], runtime.snapshot().State)
	}
}

func TestIncomingAnsweredInviteRetransmitResendsOK(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := newCallRuntime(&Service{
		cfg:          Config{LocalIP: net.ParseIP("192.0.2.10")},
		network:      localMediaIMSNetwork{},
		lifecycleCtx: ctx,
	})
	defer runtime.finish("ended", nil)

	newInvite := func() *sip.Request {
		invite := sip.NewRequest(sip.INVITE, sip.Uri{User: "callee", Host: "ims.example.test"})
		invite.AppendHeader(sip.NewHeader("From", "<sip:caller@ims.example.test>;tag=remote"))
		invite.AppendHeader(sip.NewHeader("To", "<sip:callee@ims.example.test>"))
		invite.AppendHeader(sip.NewHeader("Call-ID", "answered-retransmit@example.test"))
		invite.AppendHeader(sip.NewHeader("CSeq", "1 INVITE"))
		invite.SetBody([]byte("v=0\r\nc=IN IP4 192.0.2.20\r\nm=audio 40000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"))
		return invite
	}

	var responses []*sip.Response
	respond := func(response *sip.Response) error {
		responses = append(responses, response)
		return nil
	}
	runtime.handleRequest(newInvite(), respond)
	if err := runtime.answer(context.Background()); err != nil {
		t.Fatalf("answer incoming call: %v", err)
	}
	if got := runtime.snapshot().State; got != "connecting" {
		t.Fatalf("state after answer=%q, want connecting", got)
	}
	if len(responses) != 3 || responses[2].StatusCode != 200 {
		t.Fatalf("initial answer responses=%v, want [100 180 200]", responses)
	}
	firstAnswer := responses[2]
	firstTag, _ := firstAnswer.To().Params.Get("tag")

	// The same transaction must be answered with the cached final response until
	// its ACK arrives; replying 486 here makes a successfully answered call fail.
	runtime.handleRequest(newInvite(), respond)
	if len(responses) != 4 || responses[3].StatusCode != 200 {
		t.Fatalf("answered INVITE retransmit responses=%v, want a second 200", responses)
	}
	retransmittedAnswer := responses[3]
	retransmittedTag, _ := retransmittedAnswer.To().Params.Get("tag")
	if firstTag == "" || retransmittedTag != firstTag {
		t.Fatalf("retransmitted final response changed To tag: %q -> %q", firstTag, retransmittedTag)
	}
	if !bytes.Equal(firstAnswer.Body(), retransmittedAnswer.Body()) {
		t.Fatalf("retransmitted final response changed SDP:\nfirst=%q\nsecond=%q", firstAnswer.Body(), retransmittedAnswer.Body())
	}
}

type localMediaIMSNetwork struct{}

func (localMediaIMSNetwork) DialContext(context.Context, string, net.Addr, string, DialOptions) (net.Conn, error) {
	return nil, errors.New("dial is not used by incoming-call media tests")
}

func (localMediaIMSNetwork) HasLocalIP([]byte) bool { return true }

func (localMediaIMSNetwork) ListenPacket(context.Context, string, net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
}

func (localMediaIMSNetwork) ListenTCP(context.Context, *net.TCPAddr) (net.Listener, error) {
	return nil, errors.New("TCP is not used by incoming-call media tests")
}

func (localMediaIMSNetwork) LocalIP() []byte { return net.ParseIP("192.0.2.10") }

func (localMediaIMSNetwork) ResolveIP(context.Context, string, bool) ([]byte, error) {
	return net.ParseIP("192.0.2.20"), nil
}

func TestIncomingCancelDuringMediaAllocationReleasesLocalSockets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	network := &blockingMediaIMSNetwork{
		listenSignal: make(chan struct{}),
		allowListen:  make(chan struct{}),
	}
	runtime := newCallRuntime(&Service{
		cfg:          Config{LocalIP: net.ParseIP("192.0.2.10")},
		network:      network,
		lifecycleCtx: ctx,
	})
	invite := testIncomingInvite("cancel-during-media@example.test", 1)
	var responses []int
	respond := func(response *sip.Response) error {
		responses = append(responses, response.StatusCode)
		return nil
	}
	runtime.handleRequest(invite, respond)

	answerResult := make(chan error, 1)
	go func() { answerResult <- runtime.answer(context.Background()) }()
	select {
	case <-network.listenSignal:
	case <-time.After(time.Second):
		t.Fatal("answer did not begin media allocation")
	}

	cancelRequest := sip.NewRequest(sip.CANCEL, invite.Recipient)
	cancelRequest.AppendHeader(sip.NewHeader("Call-ID", "cancel-during-media@example.test"))
	cancelRequest.AppendHeader(sip.NewHeader("CSeq", "1 CANCEL"))
	runtime.handleRequest(cancelRequest, respond)
	close(network.allowListen)
	if err := <-answerResult; err == nil || !strings.Contains(err.Error(), "no longer pending") {
		t.Fatalf("answer after matching CANCEL error=%v, want pending rejection", err)
	}
	if network.packet == nil {
		t.Fatal("media packet socket was never created")
	}
	select {
	case <-network.packet.closed:
	case <-time.After(time.Second):
		t.Fatal("media packet socket leaked after matching CANCEL")
	}
	runtime.mu.Lock()
	state, media, audio := runtime.state.State, runtime.media, runtime.audioConn
	runtime.mu.Unlock()
	if state != "ended" || media != nil || audio != nil {
		t.Fatalf("runtime after matching CANCEL: state=%q media=%v audio=%v", state, media, audio)
	}
	if got := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(responses)), " "), "[]"); got != "100 180 200 487" {
		t.Fatalf("CANCEL responses=%v, want [100 180 200 487]", responses)
	}
}

func TestIncomingCancelWaitsForFinalAnswerCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := newCallRuntime(&Service{
		cfg:          Config{LocalIP: net.ParseIP("192.0.2.10")},
		network:      localMediaIMSNetwork{},
		lifecycleCtx: ctx,
	})
	defer runtime.finish("ended", nil)
	invite := testIncomingInvite("cancel-during-answer@example.test", 1)

	var mu sync.Mutex
	var responses []int
	answerWriteStarted := make(chan struct{})
	allowAnswerWrite := make(chan struct{})
	respond := func(response *sip.Response) error {
		if response.StatusCode == 200 && response.CSeq() != nil && strings.EqualFold(string(response.CSeq().MethodName), "INVITE") {
			close(answerWriteStarted)
			<-allowAnswerWrite
		}
		mu.Lock()
		responses = append(responses, response.StatusCode)
		mu.Unlock()
		return nil
	}
	runtime.handleRequest(invite, respond)
	answerResult := make(chan error, 1)
	go func() { answerResult <- runtime.answer(context.Background()) }()
	select {
	case <-answerWriteStarted:
	case <-time.After(time.Second):
		t.Fatal("answer did not start final response write")
	}

	cancelRequest := sip.NewRequest(sip.CANCEL, invite.Recipient)
	cancelRequest.AppendHeader(sip.NewHeader("Call-ID", "cancel-during-answer@example.test"))
	cancelRequest.AppendHeader(sip.NewHeader("CSeq", "1 CANCEL"))
	cancelDone := make(chan struct{})
	go func() {
		runtime.handleRequest(cancelRequest, respond)
		close(cancelDone)
	}()
	select {
	case <-cancelDone:
		t.Fatal("CANCEL completed before the initial 200 OK write committed")
	case <-time.After(100 * time.Millisecond):
	}

	close(allowAnswerWrite)
	if err := <-answerResult; err != nil {
		t.Fatalf("answer incoming call: %v", err)
	}
	select {
	case <-cancelDone:
	case <-time.After(time.Second):
		t.Fatal("CANCEL did not finish after final response committed")
	}
	mu.Lock()
	got := append([]int(nil), responses...)
	mu.Unlock()
	if len(got) != 4 || got[0] != 100 || got[1] != 180 || got[2] != 200 || got[3] != 481 {
		t.Fatalf("responses=%v, want [100 180 200 481]", got)
	}
}

func testIncomingInvite(callID string, sequence uint32) *sip.Request {
	invite := sip.NewRequest(sip.INVITE, sip.Uri{User: "callee", Host: "ims.example.test"})
	invite.AppendHeader(sip.NewHeader("From", "<sip:caller@ims.example.test>;tag=remote"))
	invite.AppendHeader(sip.NewHeader("To", "<sip:callee@ims.example.test>"))
	invite.AppendHeader(sip.NewHeader("Call-ID", callID))
	invite.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d INVITE", sequence)))
	invite.SetBody([]byte("v=0\r\nc=IN IP4 192.0.2.20\r\nm=audio 40000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"))
	return invite
}

type trackedPacketConn struct {
	net.PacketConn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *trackedPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

type blockingMediaIMSNetwork struct {
	listenStarted sync.Once
	listenSignal  chan struct{}
	allowListen   chan struct{}
	packet        *trackedPacketConn
}

func (n *blockingMediaIMSNetwork) DialContext(context.Context, string, net.Addr, string, DialOptions) (net.Conn, error) {
	return nil, errors.New("dial is not used by incoming-call media tests")
}

func (n *blockingMediaIMSNetwork) HasLocalIP([]byte) bool { return true }

func (n *blockingMediaIMSNetwork) ListenPacket(context.Context, string, net.Addr) (net.PacketConn, error) {
	n.listenStarted.Do(func() { close(n.listenSignal) })
	<-n.allowListen
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, err
	}
	n.packet = &trackedPacketConn{PacketConn: conn, closed: make(chan struct{})}
	return n.packet, nil
}

func (n *blockingMediaIMSNetwork) ListenTCP(context.Context, *net.TCPAddr) (net.Listener, error) {
	return nil, errors.New("TCP is not used by incoming-call media tests")
}

func (n *blockingMediaIMSNetwork) LocalIP() []byte { return net.ParseIP("192.0.2.10") }

func (n *blockingMediaIMSNetwork) ResolveIP(context.Context, string, bool) ([]byte, error) {
	return net.ParseIP("192.0.2.20"), nil
}

func TestIncomingO2BandwidthEfficientAMRInviteRings(t *testing.T) {
	body := "v=0\r\n" +
		"o=ccs 1 1 IN IP6 2001:db8::47\r\n" +
		"s=-\r\nc=IN IP6 2001:db8::47\r\nt=0 0\r\n" +
		"m=audio 41268 RTP/AVP 96 97 99 98\r\n" +
		"a=ptime:20\r\na=rtpmap:96 AMR/8000\r\n" +
		"a=fmtp:96 mode-set=0,2,4,7;mode-change-period=2;mode-change-neighbor=1;max-red=0\r\n" +
		"a=rtpmap:97 AMR/8000\r\na=fmtp:97 mode-set=7;max-red=0\r\n" +
		"a=rtpmap:99 AMR-WB/16000\r\na=rtpmap:98 telephone-event/8000\r\n"
	raw := "INVITE sip:[2001:db8::10]:5063 SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP [2001:db8::4]:6060;oc-algo=\"LOSS\";oc;branch=z9hG4bK-o2-real\r\n" +
		"From: <sip:+8618907313060@uk.pri.o2.com;user=phone>;tag=remote\r\n" +
		"To: <sip:+447831803313@ims.mnc010.mcc234.3gppnetwork.org;user=phone>\r\n" +
		"Call-ID: o2-incoming@example.test\r\nCSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" + fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
	message, err := sip.ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	request := message.(*sip.Request)
	runtime := newCallRuntime(&Service{cfg: Config{LocalIP: net.ParseIP("2001:db8::10")}})
	var responses []*sip.Response
	runtime.handleRequest(request, func(response *sip.Response) error {
		responses = append(responses, response)
		return nil
	})
	state := runtime.snapshot()
	if state.State != "incoming" || state.Codec != "AMR" || runtime.amrOctetAligned {
		t.Fatalf("incoming state=%+v octetAligned=%v", state, runtime.amrOctetAligned)
	}
	if len(responses) != 2 || responses[0].StatusCode != 100 || responses[1].StatusCode != 180 {
		t.Fatalf("responses=%v, want [100 180]", responses)
	}
	for _, response := range responses {
		via := response.Via().Value()
		if strings.Count(via, "branch=") != 1 || !strings.Contains(via, `oc-algo="LOSS";oc;branch=z9hG4bK-o2-real`) {
			t.Fatalf("invalid O2 response Via: %s", via)
		}
	}
	ringingTag, ok := responses[1].To().Params.Get("tag")
	if !ok || ringingTag == "" {
		t.Fatal("180 Ringing did not establish a local To tag")
	}
	answer := newIncomingDialogResponse(request, 200, "OK", runtime.localSDP(49170), runtime.incomingToTag)
	answerTag, _ := answer.To().Params.Get("tag")
	if answerTag != ringingTag {
		t.Fatalf("dialog To tag changed between 180 and 200: %q != %q", ringingTag, answerTag)
	}
}

func TestNetwork487UsesProvisionalQ850ReasonWhenFinalHasNone(t *testing.T) {
	response := sip.NewResponse(487, "Request Terminated")
	err := callRejectionErrorWithFallback(response, `Q.850;cause=20;text="Subscriber absent"`)
	if err == nil || !strings.Contains(err.Error(), "Q.850 20") || !strings.Contains(err.Error(), "被叫暂时不可达") {
		t.Fatalf("fallback Q.850 error = %v", err)
	}
}

func TestNetwork487PrefersFinalReasonOverProvisionalReason(t *testing.T) {
	response := sip.NewResponse(487, "Request Terminated")
	response.AppendHeader(sip.NewHeader("Reason", `Q.850;cause=127;text="Interworking"`))
	err := callRejectionErrorWithFallback(response, `Q.850;cause=20;text="Subscriber absent"`)
	if err == nil || !strings.Contains(err.Error(), "Q.850 127") || strings.Contains(err.Error(), "Q.850 20") {
		t.Fatalf("final Q.850 error = %v", err)
	}
}

func TestQ850InterworkingReasonIsPreserved(t *testing.T) {
	response := sip.NewResponse(487, "Request Terminated")
	response.AppendHeader(sip.NewHeader("Reason", `Q.850;cause=127;text="Interworking"`))
	err := callRejectionError(response)
	if err == nil || !strings.Contains(err.Error(), "Q.850 127") || !strings.Contains(err.Error(), "互通失败") {
		t.Fatalf("Q.850 interworking error = %v", err)
	}
}

func TestQ850ReasonDoesNotMatchSubstrings(t *testing.T) {
	for _, reason := range []string{`Q.850;cause=1270`, `SIP;cause=487;text="Q.850 cause=127"`, `Q.850;cause=16;text="cause=127"`} {
		response := sip.NewResponse(487, "Request Terminated")
		response.AppendHeader(sip.NewHeader("Reason", reason))
		if strings.Contains(callRejectionError(response).Error(), "Q.850 127 互通失败") {
			t.Fatalf("misclassified %s", reason)
		}
	}
	response := sip.NewResponse(487, "Request Terminated")
	response.AppendHeader(sip.NewHeader("Reason", `Q.850; cause = 127; text="Interworking"`))
	if !strings.Contains(callRejectionError(response).Error(), "Q.850 127 互通失败") {
		t.Fatal("whitespace cause was not recognized")
	}
}

func TestPRACKUsesEarlyDialogTargetAndRouteSet(t *testing.T) {
	service := &Service{
		cfg: Config{
			LocalIP:    net.ParseIP("2001:db8::10"),
			PCSCFAddr:  "[2001:db8::20]:5060",
			HomeDomain: "ims.example.test",
			PublicURI:  "sip:subscriber@ims.example.test",
			Template: policy.IMSRegisterTemplate{
				IncludePANIAuthenticated: true,
			},
		},
		registeredMSISDN: "+447831803313",
		transportRuntime: &transportRuntime{policy: ipsec3gpp.Policy{
			LocalPortC: 5064,
			LocalPortS: 5063,
		}},
	}
	runtime := newCallRuntime(service)
	runtime.localTag = "local-tag"
	runtime.inviteCSeq = 7
	runtime.lastRSeq = "2"

	response := sip.NewResponse(183, "Session Progress")
	response.AppendHeader(sip.NewHeader("To", "<tel:+8618907313060>;tag=remote-tag"))
	response.AppendHeader(sip.NewHeader("Contact", "<sip:tas@[2001:db8::40]:6060>"))
	response.AppendHeader(sip.NewHeader("Record-Route", "<sip:edge-a.example.test;lr>"))
	response.AppendHeader(sip.NewHeader("Record-Route", "<sip:edge-b.example.test;lr>"))
	runtime.updateDialogFromResponse(response)

	wire, err := runtime.buildRequest(sip.PRACK, "+8618907313060", "call@example.test", 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := string(wire)
	for _, want := range []string{
		"PRACK sip:tas@[2001:db8::40]:6060 SIP/2.0",
		"To: <tel:+8618907313060>;tag=remote-tag",
		"Route: <sip:edge-b.example.test;lr>\r\nRoute: <sip:edge-a.example.test;lr>",
		"RAck: 2 7 INVITE",
		"P-Access-Network-Info: IEEE-802.11;i-wlan-node-id=000000000000;network-provided",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("PRACK missing %q\n%s", want, message)
		}
	}
}

func TestStaleInviteResponseCannotMutateNextCallDialog(t *testing.T) {
	runtime := &callRuntime{state: CallState{State: "outgoing", CallID: "new-call"}}
	response := sip.NewResponse(183, "Session Progress")
	response.AppendHeader(sip.NewHeader("To", "<tel:888>;tag=stale-tag"))
	response.AppendHeader(sip.NewHeader("Contact", "<sip:stale@example.test>"))
	if runtime.updateDialogFromResponseForCall(response, "old-call") {
		t.Fatal("stale response was accepted")
	}
	if runtime.remoteTag != "" || runtime.remoteTarget != "" {
		t.Fatalf("stale dialog leaked: tag=%q target=%q", runtime.remoteTag, runtime.remoteTarget)
	}
}

func TestHeaderAddressURI(t *testing.T) {
	for input, want := range map[string]string{
		"<sip:tas@[2001:db8::40]:6060>;expires=600": "sip:tas@[2001:db8::40]:6060",
		"sip:tas@example.test;expires=600":          "sip:tas@example.test",
	} {
		if got := headerAddressURI(input); got != want {
			t.Errorf("headerAddressURI(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestCancelMatchesOriginalInviteTransaction(t *testing.T) {
	service := &Service{
		cfg: Config{
			LocalIP:    net.ParseIP("2001:db8::10"),
			PCSCFAddr:  "[2001:db8::20]:5060",
			HomeDomain: "ims.example.test",
			PublicURI:  "sip:subscriber@ims.example.test",
		},
		transportRuntime: &transportRuntime{policy: ipsec3gpp.Policy{LocalPortC: 5064}},
	}
	runtime := newCallRuntime(service)
	runtime.localTag = "local-tag"
	runtime.remoteTag = "provisional-tag"
	runtime.inviteBranch = "z9hG4bK.original-branch"
	runtime.inviteCSeq = 7

	wire, err := runtime.buildRequest(sip.CANCEL, "+8618907313060", "call@example.test", 99, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := string(wire)
	for _, want := range []string{
		"CANCEL tel:+8618907313060 SIP/2.0",
		"branch=z9hG4bK.original-branch;rport",
		"To: <tel:+8618907313060>\r\n",
		"CSeq: 7 CANCEL",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("CANCEL missing %q\n%s", want, message)
		}
	}
	if strings.Contains(message, "To: <tel:+8618907313060>;tag=") {
		t.Fatalf("CANCEL must not copy the provisional To-tag\n%s", message)
	}
}
