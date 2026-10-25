package swu

import (
	"context"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

type authRegressionTransport struct {
	rekeyCaptureTransport
	in chan []byte
}

func (t *authRegressionTransport) IKEPackets() <-chan []byte { return t.in }

// This regression deliberately uses only pre-632 interfaces so the exact same
// test can be run against the archived source and the corrected dispatcher.
func TestAuthDispatcherFragmentCompletionRegression(t *testing.T) {
	s := envelopeSession(t, true)
	s.Logger = zap.NewNop()
	s.cfg = &Config{}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.fragmentBuf = newFragmentBuffer()
	s.ikeWaiters = make(map[ikeWaitKey]chan []byte)
	s.ikePending = make(map[ikeWaitKey][]byte)
	wire := &authRegressionTransport{in: make(chan []byte, 2)}
	s.socket = wire
	s.taskMgr = NewTaskManager(s.ctx, nil, 1, func([][]byte) error { return nil })
	done := make(chan struct{})
	go func() { defer close(done); s.ikeDispatchLoop() }()
	defer func() { s.cancel(); <-done; s.taskMgr.Stop() }()
	packet := func(part []byte, number uint16) []byte {
		data, err := s.buildSKFPacket(part, number, 2, 7, ikev2.IKE_AUTH, ikev2.EAP)
		if err != nil {
			t.Fatal(err)
		}
		end := ikev2.IKE_HEADER_LEN + 8 + s.EncAlg.IVSize()
		iv := data[ikev2.IKE_HEADER_LEN+8 : end]
		padded, err := s.EncAlg.Decrypt(data[end:], s.Keys.SK_er, iv, data[:ikev2.IKE_HEADER_LEN+8])
		if err != nil {
			t.Fatal(err)
		}
		data[19] = ikev2.FlagResponse
		sealed, err := s.EncAlg.Encrypt(padded, s.Keys.SK_er, iv, data[:ikev2.IKE_HEADER_LEN+8])
		if err != nil {
			t.Fatal(err)
		}
		copy(data[end:], sealed)
		return data
	}
	plain := []byte{0, 0, 0, 8, 4, 2, 0, 4}
	ch := s.taskMgr.EnqueueRequest(7, ikev2.IKE_AUTH, nil, nil)
	wire.in <- packet(plain[:3], 1)
	select {
	case <-ch:
		t.Fatal("regression: dispatcher acknowledged the first SKF before the complete IKE_AUTH response")
	case <-time.After(30 * time.Millisecond):
	}
	wire.in <- packet(plain[3:], 2)
	if result := awaitRequest(t, ch); result.Err != nil {
		t.Fatal(result.Err)
	}
}
