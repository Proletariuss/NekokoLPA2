package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

type authResponseTransport struct {
	rekeyCaptureTransport
	in chan []byte
}

func (t *authResponseTransport) IKEPackets() <-chan []byte { return t.in }

// Build independently authenticated responder SKF packets. The shared fixture
// has equal initiator/responder keys so only the direction flag needs resealing.
func authResponseFragment(t *testing.T, s *Session, plain []byte, number, total uint16, msgID uint32, first ikev2.PayloadType) []byte {
	t.Helper()
	packet, err := s.buildSKFPacket(plain, number, total, msgID, ikev2.IKE_AUTH, first)
	if err != nil {
		t.Fatal(err)
	}
	if s.ikeIsAEAD {
		ivEnd := ikev2.IKE_HEADER_LEN + 8 + s.EncAlg.IVSize()
		iv := packet[ikev2.IKE_HEADER_LEN+8 : ivEnd]
		padded, err := s.EncAlg.Decrypt(packet[ivEnd:], s.Keys.SK_er, iv, packet[:ikev2.IKE_HEADER_LEN+8])
		if err != nil {
			t.Fatal(err)
		}
		packet[19] = ikev2.FlagResponse
		sealed, err := s.EncAlg.Encrypt(padded, s.Keys.SK_er, iv, packet[:ikev2.IKE_HEADER_LEN+8])
		if err != nil {
			t.Fatal(err)
		}
		copy(packet[ivEnd:], sealed)
	} else {
		packet[19] = ikev2.FlagResponse
		end := len(packet) - s.IntegAlg.OutputSize()
		copy(packet[end:], s.IntegAlg.Compute(s.Keys.SK_ar, packet[:end]))
	}
	return packet
}

func authDispatchFixture(t *testing.T, aead bool) (*Session, *authResponseTransport, *atomic.Int32) {
	t.Helper()
	s := envelopeSession(t, aead)
	s.cfg = &Config{}
	s.Logger = zap.NewNop()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.ikeWaiters = make(map[ikeWaitKey]chan []byte)
	s.ikePending = make(map[ikeWaitKey][]byte)
	s.fragmentBuf = newFragmentBuffer()
	transport := &authResponseTransport{in: make(chan []byte, 20)}
	s.socket = transport
	var sends atomic.Int32
	s.taskMgr = NewTaskManager(s.ctx, nil, 1, func([][]byte) error { sends.Add(1); return nil })
	done := make(chan struct{})
	go func() { defer close(done); s.ikeDispatchLoop() }()
	t.Cleanup(func() { s.cancel(); <-done; s.taskMgr.Stop() })
	return s, transport, &sends
}

func assertRequestPending(t *testing.T, ch <-chan RequestResult) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("incomplete/invalid response completed request: %+v", r)
	case <-time.After(10 * time.Millisecond):
	}
}

func TestAuthDispatcherWaitsForAllFragmentsAndProcessesOnce(t *testing.T) {
	for _, aead := range []bool{false, true} {
		for _, order := range [][]int{{0, 1}, {1, 0}, {0, 0, 1}} {
			s, wire, sends := authDispatchFixture(t, aead)
			// One terminal EAP Failure payload, split inside the payload header.
			plain := []byte{0, 0, 0, 8, 4, 2, 0, 4}
			parts := [][]byte{
				authResponseFragment(t, s, plain[:3], 1, 2, 17, ikev2.EAP),
				authResponseFragment(t, s, plain[3:], 2, 2, 17, ikev2.EAP),
			}
			ch := s.taskMgr.EnqueueRequest(17, ikev2.IKE_AUTH, nil, nil)
			var diagnostics []AuthDiagnostic
			s.cfg.OnAuthDiagnostic = func(d AuthDiagnostic) { diagnostics = append(diagnostics, d) }
			for step, index := range order {
				wire.in <- parts[index]
				if step < len(order)-1 {
					assertRequestPending(t, ch)
				}
				if step == 0 {
					// Partial SKF must retain the request's retransmission budget.
					s.taskMgr.mu.Lock()
					s.taskMgr.pending[17].Deadline = time.Now().Add(-time.Second)
					s.taskMgr.mu.Unlock()
					s.taskMgr.checkTimeouts()
					if sends.Load() != 2 {
						t.Fatalf("partial response suppressed retransmit: %d", sends.Load())
					}
				}
			}
			result := awaitRequest(t, ch)
			if !result.authParsed || result.authMessageID != 17 || len(result.authPayloads) != 1 {
				t.Fatalf("lost parsed response: %+v", result)
			}
			if _, err := s.processAuthEAPResponse(result.authMessageID, result.authPayloads); AuthFailureCode(err) != AuthFailureEAP {
				t.Fatal(err)
			}
			if len(diagnostics) != 1 || diagnostics[0].MessageID != 17 {
				t.Fatalf("wrong diagnostic count/id: %+v", diagnostics)
			}
			wire.in <- parts[0]
			wire.in <- parts[1]
			assertRequestPending(t, ch)
			s.taskMgr.mu.Lock()
			if len(s.taskMgr.pending) != 0 {
				t.Fatal("completed request retained fragments")
			}
			s.taskMgr.mu.Unlock()
			if len(s.fragmentBuf.frags) != 0 {
				t.Fatal("AUTH used shared fragment cache")
			}
		}
	}
}

func TestAuthDispatcherRejectsWrongEnvelopeAndTampering(t *testing.T) {
	for _, aead := range []bool{false, true} {
		s, wire, _ := authDispatchFixture(t, aead)
		plain := []byte{0, 0, 0, 8, 4, 2, 0, 4}
		first := authResponseFragment(t, s, plain[:3], 1, 2, 4, ikev2.EAP)
		last := authResponseFragment(t, s, plain[3:], 2, 2, 4, ikev2.EAP)
		ch := s.taskMgr.EnqueueRequest(4, ikev2.IKE_AUTH, nil, nil)
		for _, offset := range []int{0, 8, 18, 19, len(first) - 1} {
			bad := append([]byte(nil), first...)
			bad[offset] ^= 1
			wire.in <- bad
			assertRequestPending(t, ch)
		}
		// Correct MACs with invalid responder headers must also be rejected;
		// these cases distinguish the header checks from integrity enforcement.
		for _, mutate := range []func([]byte){
			func(p []byte) { p[19] = ikev2.FlagResponse | ikev2.FlagInitiator },
			func(p []byte) { p[18] = byte(ikev2.INFORMATIONAL) },
			func(p []byte) { p[0] ^= 1 },
			func(p []byte) { p[8] ^= 1 },
		} {
			bad := append([]byte(nil), first...)
			if s.ikeIsAEAD {
				end := ikev2.IKE_HEADER_LEN + 8 + s.EncAlg.IVSize()
				iv := bad[ikev2.IKE_HEADER_LEN+8 : end]
				padded, err := s.EncAlg.Decrypt(bad[end:], s.Keys.SK_er, iv, bad[:ikev2.IKE_HEADER_LEN+8])
				if err != nil {
					t.Fatal(err)
				}
				mutate(bad)
				sealed, err := s.EncAlg.Encrypt(padded, s.Keys.SK_er, iv, bad[:ikev2.IKE_HEADER_LEN+8])
				if err != nil {
					t.Fatal(err)
				}
				copy(bad[end:], sealed)
			} else {
				mutate(bad)
				end := len(bad) - s.IntegAlg.OutputSize()
				copy(bad[end:], s.IntegAlg.Compute(s.Keys.SK_ar, bad[:end]))
			}
			wire.in <- bad
			assertRequestPending(t, ch)
		}
		foreign := append([]byte(nil), first...)
		binary.BigEndian.PutUint32(foreign[20:24], 777)
		wire.in <- foreign
		assertRequestPending(t, ch)
		wire.in <- last
		assertRequestPending(t, ch)
		wire.in <- first
		result := awaitRequest(t, ch)
		if !result.authParsed || len(result.authPayloads) != 1 {
			t.Fatal("valid fragments rejected after invalid packets")
		}
		// A later request cannot consume old-response fragments or old msgIDs.
		next := s.taskMgr.EnqueueRequest(5, ikev2.IKE_AUTH, nil, nil)
		wire.in <- first
		wire.in <- last
		assertRequestPending(t, next)
		valid, err := s.encryptAndWrapWithMsgID([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTHENTICATION_FAILED}}, ikev2.IKE_AUTH, 5, true)
		if err != nil {
			t.Fatal(err)
		}
		// encryptAndWrap emits initiator responses; reseal with responder flags.
		valid = responderSK(t, s, valid)
		wire.in <- valid
		if got := awaitRequest(t, next); !got.authParsed || got.authMessageID != 5 {
			t.Fatalf("wrong next result: %+v", got)
		}
	}
}

func TestAuthSendUsesVerifiedResponseMessageID(t *testing.T) {
	s, wire, sends := authDispatchFixture(t, true)
	s.SequenceNumber.Store(21)
	type outcome struct {
		id       uint32
		payloads []ikev2.Payload
		err      error
	}
	completed := make(chan outcome, 1)
	go func() {
		id, payloads, err := s.sendAuthWithRetry(nil)
		completed <- outcome{id, payloads, err}
	}()
	deadline := time.Now().Add(time.Second)
	for sends.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sends.Load() != 1 {
		t.Fatal("request was not sent")
	}
	packet, err := s.encryptAndWrapWithMsgID([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTHENTICATION_FAILED}}, ikev2.IKE_AUTH, 21, true)
	if err != nil {
		t.Fatal(err)
	}
	wire.in <- responderSK(t, s, packet)
	select {
	case result := <-completed:
		if result.err != nil || result.id != 21 || len(result.payloads) != 1 || s.SequenceNumber.Load() != 22 {
			t.Fatalf("response ID confused with next request: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("AUTH send did not complete")
	}
}

func responderSK(t *testing.T, s *Session, packet []byte) []byte {
	t.Helper()
	if s.ikeIsAEAD {
		end := ikev2.IKE_HEADER_LEN + 4 + s.EncAlg.IVSize()
		iv := packet[ikev2.IKE_HEADER_LEN+4 : end]
		plain, err := s.EncAlg.Decrypt(packet[end:], s.Keys.SK_er, iv, packet[:ikev2.IKE_HEADER_LEN+4])
		if err != nil {
			t.Fatal(err)
		}
		packet[19] = ikev2.FlagResponse
		sealed, err := s.EncAlg.Encrypt(plain, s.Keys.SK_er, iv, packet[:ikev2.IKE_HEADER_LEN+4])
		if err != nil {
			t.Fatal(err)
		}
		copy(packet[end:], sealed)
	} else {
		packet[19] = ikev2.FlagResponse
		end := len(packet) - s.IntegAlg.OutputSize()
		copy(packet[end:], s.IntegAlg.Compute(s.Keys.SK_ar, packet[:end]))
	}
	return packet
}

func TestAuthDispatcherCancellationTimeoutAndLimits(t *testing.T) {
	for _, tc := range []string{"cancel", "timeout", "too_many", "too_large"} {
		t.Run(tc, func(t *testing.T) {
			s, wire, _ := authDispatchFixture(t, true)
			ch := s.taskMgr.EnqueueRequest(2, ikev2.IKE_AUTH, nil, nil)
			first := authResponseFragment(t, s, []byte{0, 0}, 1, 2, 2, ikev2.EAP)
			wire.in <- first
			assertRequestPending(t, ch)
			switch tc {
			case "cancel":
				s.cancel()
				if result := awaitRequest(t, ch); !errors.Is(result.Err, context.Canceled) {
					t.Fatal(result.Err)
				}
			case "timeout":
				s.taskMgr.mu.Lock()
				s.taskMgr.pending[2].MaxRetries = 0
				s.taskMgr.pending[2].Deadline = time.Now().Add(-time.Second)
				s.taskMgr.mu.Unlock()
				s.taskMgr.checkTimeouts()
				if result := awaitRequest(t, ch); !errors.Is(result.Err, ErrWindowTimeout) {
					t.Fatal(result.Err)
				}
			case "too_many":
				wire.in <- authResponseFragment(t, s, []byte{0}, 1, 256, 2, ikev2.EAP)
				assertRequestPending(t, ch)
			case "too_large":
				wire.in <- authResponseFragment(t, s, bytes.Repeat([]byte{0}, 33000), 1, 3, 2, ikev2.EAP)
				wire.in <- authResponseFragment(t, s, bytes.Repeat([]byte{0}, 33000), 2, 3, 2, ikev2.EAP)
				assertRequestPending(t, ch)
			}
			if tc == "cancel" || tc == "timeout" {
				s.taskMgr.mu.Lock()
				if len(s.taskMgr.pending) != 0 {
					t.Fatal("terminal request retained fragments")
				}
				s.taskMgr.mu.Unlock()
			}
		})
	}
}
