package imscore

import "testing"

func TestSplitPCMFrames(t *testing.T) {
	for _, n := range []int{320, 640, 960} {
		pcm := make([]byte, n)
		pcm[n-1] = 42
		frames := splitPCMFrames(pcm)
		if len(frames) != n/320 || len(frames[0]) != 320 || frames[len(frames)-1][319] != 42 {
			t.Fatalf("lost PCM samples for %d-byte packet", n)
		}
	}
	for _, n := range []int{0, 319, 321} {
		if len(splitPCMFrames(make([]byte, n))) != 0 {
			t.Fatalf("accepted incomplete PCM packet: %d", n)
		}
	}
}
