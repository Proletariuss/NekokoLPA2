//go:build darwin && arm64 && amrcodec && !ios

package imscore

import "testing"

func TestAMRNBMode7RoundTrip(t *testing.T) {
	codec, err := newAMRNBCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.close()
	pcm := make([]byte, 320)
	payload, err := codec.encode(pcm)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 33 || payload[0] != 0xf0 || (payload[1]>>3)&0x0f != 7 {
		t.Fatalf("unexpected AMR RTP payload: len=%d", len(payload))
	}
	decoded, err := codec.decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 320 {
		t.Fatalf("decoded PCM length=%d", len(decoded))
	}
}
