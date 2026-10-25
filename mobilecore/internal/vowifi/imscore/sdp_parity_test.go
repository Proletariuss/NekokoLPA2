package imscore

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestSDPRustParity prevents the staged Rust migration from changing the live
// Go call path before Rust owns the SIP/RTP session. The external fixture is
// injected by the migration gate so ordinary Go-only tests remain standalone.
//
// A bodyless final response after negotiated reliable early media is deliberately
// not part of this stateless parser parity set: it is callRuntime dialog state
// owned by the current Go route and is locked by TestRemoteSDPAllowsBodylessFinalAfterNegotiatedEarlyMedia.
func TestSDPRustParity(t *testing.T) {
	fixture := os.Getenv("PROLETARIUS_SDP_FIXTURE")
	if fixture == "" {
		t.Skip("set PROLETARIUS_SDP_FIXTURE to the Rust sdp_fixture binary")
	}
	cases := []struct {
		name   string
		answer bool
		sdp    string
	}{
		{
			name:   "static PCMA answer",
			answer: true,
			sdp:    "v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 8 101\r\na=rtpmap:101 telephone-event/8000\r\n",
		},
		{
			name: "dynamic PCMA offer",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.9\r\nm=audio 49171 RTP/AVP 110 112\r\na=rtpmap:110 PCMA/8000/1\r\na=rtpmap:112 telephone-event/8000/1\r\n",
		},
		{
			name: "giffgaff bandwidth efficient AMR offer",
			sdp:  "v=0\r\no=- 1 1 IN IP6 2001:db8::10\r\ns=-\r\nc=IN IP6 2001:db8::20\r\nt=0 0\r\nm=audio 40000 RTP/AVP 96 101\r\na=rtpmap:96 AMR/8000\r\na=fmtp:96 mode-set=0,2,4,7\r\na=rtpmap:101 telephone-event/8000\r\n",
		},
		{
			name:   "octet aligned AMR answer",
			answer: true,
			sdp:    "v=0\r\nc=IN IP6 2001:db8::21\r\nm=audio 40002 RTP/AVP 97 101\r\na=rtpmap:97 AMR/8000\r\na=fmtp:97 octet-align=1;mode-set=7\r\na=rtpmap:101 telephone-event/8000\r\n",
		},
		{
			name: "AMR mode-set accepts Go Atoi spellings",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.11\r\nm=audio 40003 RTP/AVP 97\r\na=rtpmap:97 AMR/8000\r\na=fmtp:97 mode-set=+7,07\r\n",
		},
		{
			name: "mixed case audio token rejected",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.12\r\nm=Audio 40004 RTP/AVP 8\r\n",
		},
		{
			name: "mixed case RTP transport rejected",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.13\r\nm=audio 40005 rtp/avp 8\r\n",
		},
		{
			name: "whitespace after m equals rejected",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.14\r\nm= audio 40006 RTP/AVP 8\r\n",
		},
		{
			name: "unicode Fields whitespace accepted",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.15\r\nm=audio\u00a040007\u00a0RTP/AVP\u00a08\r\n",
		},
		{
			name: "media port accepts Go Atoi plus spelling",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.15\r\nm=audio +40007 RTP/AVP 8\r\n",
		},
		{
			name: "connection extra fields ignored and session address retained",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.16\r\nm=audio 40008 RTP/AVP 8\r\nc=IN IP4 192.0.2.17 ignored\r\n",
		},
		{
			name: "connection noncanonical spacing rejected",
			sdp:  "v=0\r\nc=IN  IP4 192.0.2.18\r\nm=audio 40009 RTP/AVP 8\r\n",
		},
		{
			name: "dynamic PCMA preserves raw rtpmap key mismatch",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.19\r\nm=audio 40010 RTP/AVP 097\r\na=rtpmap:97 PCMA/8000\r\n",
		},
		{
			name: "dynamic PCMA accepts raw plus and leading zero token",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.20\r\nm=audio 40011 RTP/AVP +097\r\na=rtpmap:+097 PCMA/8000\r\n",
		},
		{
			name: "AMR preserves raw fmtp key mismatch",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.21\r\nm=audio 40012 RTP/AVP 097\r\na=rtpmap:097 AMR/8000\r\na=fmtp:97 mode-set=7\r\n",
		},
		{
			name: "AMR fmtp outer whitespace follows Go TrimSpace",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.22\r\nm=audio 40013 RTP/AVP 097\r\na=rtpmap:097 AMR/8000\r\na=fmtp:\t 097 mode-set=7\r\n",
		},
		{
			name: "AMR fmtp tab remains part of raw key",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.23\r\nm=audio 40014 RTP/AVP 097\r\na=rtpmap:097 AMR/8000\r\na=fmtp:097\t mode-set=7\r\n",
		},
		{
			name: "AMR-WB rejected",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 49172 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n",
		},
		{
			name: "hostname rejected",
			sdp:  "v=0\r\nc=IN IP4 media.example.test\r\nm=audio 49173 RTP/AVP 8\r\n",
		},
		{
			name: "invalid media address cannot fall back to session address",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 49173 RTP/AVP 8\r\nc=IN IP4 media.example.test\r\n",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			goRuntime := &callRuntime{}
			goErr := goRuntime.applyRemoteSDP([]byte(test.sdp), test.answer)
			rust := rustSDPFixture(t, fixture, test.answer, test.sdp)
			if goErr != nil {
				if rust[0] != "error" {
					t.Fatalf("Go rejected SDP (%v), Rust accepted it: %v", goErr, rust)
				}
				return
			}
			if rust[0] != "ok" || len(rust) != 7 {
				t.Fatalf("Go accepted SDP, Rust returned %v", rust)
			}
			port, _ := strconv.Atoi(rust[2])
			payload, _ := strconv.Atoi(rust[3])
			if goRuntime.remoteRTP == nil || !goRuntime.remoteRTP.IP.Equal(net.ParseIP(rust[1])) || goRuntime.remoteRTP.Port != port {
				t.Fatalf("endpoint mismatch: Go=%v Rust=%s:%d", goRuntime.remoteRTP, rust[1], port)
			}
			if int(goRuntime.payloadType) != payload || goRuntime.state.Codec != rust[4] {
				t.Fatalf("codec mismatch: Go=%s/%d Rust=%s/%d", goRuntime.state.Codec, goRuntime.payloadType, rust[4], payload)
			}
			if goRuntime.state.Codec == "AMR" && strconv.FormatBool(goRuntime.amrOctetAligned) != rust[5] {
				t.Fatalf("AMR alignment mismatch: Go=%v Rust=%s", goRuntime.amrOctetAligned, rust[5])
			}
			wantDTMF := rust[6] != "-"
			if goRuntime.dtmfReady != wantDTMF || (wantDTMF && strconv.Itoa(int(goRuntime.dtmfPayload)) != rust[6]) {
				t.Fatalf("DTMF mismatch: Go=%v/%d Rust=%s", goRuntime.dtmfReady, goRuntime.dtmfPayload, rust[6])
			}
		})
	}
}

func rustSDPFixture(t *testing.T, fixture string, answer bool, sdp string) []string {
	t.Helper()
	mode := "offer"
	if answer {
		mode = "answer"
	}
	output, err := exec.Command(fixture, mode, sdp).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust SDP fixture: %v: %s", err, output)
	}
	return strings.Split(strings.TrimSpace(string(output)), "|")
}
