package imscore

import "testing"

func TestDTMFAcceptsAnswerPayloadRemapping(t *testing.T) {
	c := &callRuntime{}
	err := c.applyRemoteSDP([]byte("v=0\r\nc=IN IP4 192.0.2.8\r\nm=audio 49170 RTP/AVP 8 110\r\na=rtpmap:110 telephone-event/8000\r\na=fmtp:110 0-15\r\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !c.dtmfReady || c.dtmfPayload != 110 {
		t.Fatalf("remote DTMF mapping ignored: ready=%v payload=%d", c.dtmfReady, c.dtmfPayload)
	}
}
