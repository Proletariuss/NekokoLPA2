package imscore

import (
	"net"
	"strings"
	"testing"
)

func TestMobileSessionAdvertisesOnlyWorkingPCMA(t *testing.T) {
	runtime := newCallRuntime(&Service{cfg: Config{LocalIP: net.ParseIP("192.0.2.1"), DisableAMR: true}})
	runtime.state.Direction = "outgoing"
	sdp := string(runtime.localSDP(12345))
	if !strings.Contains(sdp, "RTP/AVP 8 101") || strings.Contains(sdp, "AMR/") {
		t.Fatalf("mobile SDP advertises unavailable codec: %s", sdp)
	}
	err := runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 97\r\na=rtpmap:97 AMR/8000\r\na=fmtp:97 octet-align=1;mode-set=7\r\n"), true)
	if err == nil {
		t.Fatal("AMR accepted without mobile codec")
	}
	err = runtime.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"), true)
	if err != nil || runtime.state.Codec != "PCMA" {
		t.Fatalf("PCMA failed: %v", err)
	}
}
