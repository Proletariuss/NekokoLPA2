package swu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func authRequestFixture(t *testing.T, aead bool) *Session {
	t.Helper()
	s := envelopeSession(t, aead)
	s.Logger = zap.NewNop()
	s.cfg = &Config{APN: "ims", ValidateRemoteCertificate: true}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.fragmentBuf = newFragmentBuffer()
	s.SequenceNumber.Store(37)
	t.Cleanup(s.cancel)
	return s
}

func requestPayloadTypes(payloads []ikev2.Payload) []int {
	var types []int
	for _, p := range payloads {
		types = append(types, int(p.Type()))
	}
	return types
}

func TestAuthRequestDiagnosticMatchesEncryptedSendWire(t *testing.T) {
	for _, aead := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			for _, stage := range []string{"initial", "eap", "final"} {
				t.Run(fmtRequestCase(aead, fragmented, stage), func(t *testing.T) {
					s := authRequestFixture(t, aead)
					s.fragmentationSupported = fragmented
					s.ikeFragmentMTU = 180
					var payloads []ikev2.Payload
					switch stage {
					case "initial":
						payloads = []ikev2.Payload{
							&ikev2.EncryptedPayloadID{IDType: ikev2.ID_RFC822_ADDR, IDData: []byte("anonymous@private.invalid"), IsInitiator: true},
							&ikev2.EncryptedPayloadID{IDType: ikev2.ID_FQDN, IDData: []byte("ims")},
							&ikev2.EncryptedPayloadCertReq{Encoding: 4, CertificateAuthorities: bytes.Repeat([]byte{0xab}, 40)},
						}
					case "eap":
						payloads = []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{eap.CodeResponse, 8, 0, 5, eap.TypeIdentity}}}
					case "final":
						payloads = []ikev2.Payload{&ikev2.EncryptedPayloadAuth{AuthMethod: 2, AuthData: []byte("secret AUTH")}}
					}
					payloads = append(payloads, &ikev2.RawPayload{PType: 222, Data: bytes.Repeat([]byte{0xaf}, 400)})
					var diagnostics []AuthRequestDiagnostic
					s.cfg.OnAuthRequestDiagnostic = func(d AuthRequestDiagnostic) {
						diagnostics = append(diagnostics, d)
						// Another sequence user must not change the queued wire ID.
						s.SequenceNumber.Add(5)
					}
					var packets [][]byte
					sendErr := errors.New("synthetic send failure")
					s.taskMgr = NewTaskManager(s.ctx, nil, 1, func(p [][]byte) error {
						if len(diagnostics) != 1 {
							t.Error("metadata was not emitted exactly once before enqueue/send")
						}
						packets = p
						return sendErr
					})
					t.Cleanup(s.taskMgr.Stop)
					_, err := s.sendEncryptedRequestWithRetry(payloads, ikev2.IKE_AUTH)
					if !errors.Is(err, sendErr) || len(diagnostics) != 1 || len(packets) == 0 {
						t.Fatalf("send result: %v diagnostics=%d packets=%d", err, len(diagnostics), len(packets))
					}
					var parsed []ikev2.Payload
					for _, packet := range packets {
						header, err := ikev2.DecodeHeader(packet)
						if err != nil || header.MessageID != 37 || header.ExchangeType != ikev2.IKE_AUTH || s.lastEncryptedMsgID != 37 {
							t.Fatal("request message ID not taken from actual wire", err)
						}
						_, part, err := s.decryptAndParse(packet)
						if err != nil {
							t.Fatal(err)
						}
						if part != nil {
							parsed = part
						}
					}
					want := AuthRequestDiagnostic{Stage: stage, MessageID: 37, PayloadTypes: requestPayloadTypes(parsed), CertificateRequired: true, Fragmented: fragmented, PacketCount: len(packets), SendState: "prepared"}
					switch stage {
					case "initial":
						want.IDiTypes, want.IDrTypes = []int{3}, []int{2}
						want.IDiAnonymous, want.IDrIsAPN = true, true
						want.CertReqCount, want.CertReqEncodings, want.CertReqCAHashCount = 1, []int{4}, 2
					case "eap":
						want.EAPCodes, want.EAPTypes = []int{2}, []int{1}
					}
					if !reflect.DeepEqual(diagnostics[0], want) {
						t.Fatalf("diagnostic does not match decrypted wire: got %+v want %+v", diagnostics[0], want)
					}
				})
			}
		}
	}
}

func fmtRequestCase(aead, fragmented bool, stage string) string {
	name := "cbc/"
	if aead {
		name = "gcm/"
	}
	if fragmented {
		name += "fragmented/"
	} else {
		name += "single/"
	}
	return name + stage
}

type changingAuthPayload struct{ count int }

func (p *changingAuthPayload) Type() ikev2.PayloadType { return ikev2.EAP }
func (p *changingAuthPayload) Encode() ([]byte, error) {
	p.count++
	return []byte{eap.CodeResponse, 1, 0, 5, byte(p.count)}, nil
}

func TestAuthRequestFrozenOnceAndDiagnosticDoesNotReencode(t *testing.T) {
	s := authRequestFixture(t, true)
	p := &changingAuthPayload{}
	s.cfg.OnAuthRequestDiagnostic = func(d AuthRequestDiagnostic) {
		if !reflect.DeepEqual(d.EAPTypes, []int{1}) {
			t.Errorf("diagnostic used different serialization: %+v", d)
		}
	}
	s.taskMgr = NewTaskManager(s.ctx, nil, 1, func(packets [][]byte) error {
		_, payloads, err := s.decryptAndParse(packets[0])
		if err != nil || !bytes.Equal(payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, []byte{2, 1, 0, 5, 1}) {
			t.Errorf("wire serialization changed: %v", err)
		}
		return errors.New("stop")
	})
	t.Cleanup(s.taskMgr.Stop)
	_, _ = s.sendEncryptedRequestWithRetry([]ikev2.Payload{p}, ikev2.IKE_AUTH)
	if p.count != 1 {
		t.Fatalf("Encode called %d times", p.count)
	}
}

type cancelledAuthPayload struct{ cancel context.CancelFunc }

func (p *cancelledAuthPayload) Type() ikev2.PayloadType { return 222 }
func (p *cancelledAuthPayload) Encode() ([]byte, error) { p.cancel(); return []byte{1}, nil }

func TestAuthRequestDiagnosticSuppressedOnInvalidSerializationEncryptionAndCancellation(t *testing.T) {
	for _, mode := range []string{"invalid_certreq", "oversized", "encryption", "cancelled", "cancel_during_encode"} {
		t.Run(mode, func(t *testing.T) {
			s := authRequestFixture(t, true)
			s.cfg.OnAuthRequestDiagnostic = func(AuthRequestDiagnostic) { t.Error("callback for failed or cancelled request") }
			payloads := []ikev2.Payload{&ikev2.EncryptedPayloadCertReq{Encoding: 4}}
			switch mode {
			case "invalid_certreq":
				payloads[0] = &ikev2.EncryptedPayloadCertReq{Encoding: 4, CertificateAuthorities: []byte{1}}
			case "oversized":
				payloads[0] = &ikev2.RawPayload{PType: 222, Data: make([]byte, 65532)}
			case "encryption":
				s.Keys.SK_ei = nil
			case "cancelled":
				s.cancel()
			case "cancel_during_encode":
				payloads[0] = &cancelledAuthPayload{cancel: s.cancel}
			}
			s.taskMgr = NewTaskManager(s.ctx, nil, 1, func([][]byte) error { t.Error("invalid/cancelled request enqueued"); return errors.New("stop") })
			t.Cleanup(s.taskMgr.Stop)
			if _, err := s.sendEncryptedRequestWithRetry(payloads, ikev2.IKE_AUTH); err == nil {
				t.Fatal("invalid/cancelled request succeeded")
			}
		})
	}
}

func TestAuthRequestDiagnosticBoundedDetachedAndPrivate(t *testing.T) {
	s := authRequestFixture(t, true)
	secret := "private-realm-very-secret"
	var payloads []ikev2.Payload
	for i := 0; i < 40; i++ {
		payloads = append(payloads,
			&ikev2.EncryptedPayloadID{IsInitiator: true, IDType: 3, IDData: []byte("notanonymous@" + secret)},
			&ikev2.EncryptedPayloadID{IDType: 2, IDData: []byte(secret)},
			&ikev2.EncryptedPayloadCertReq{Encoding: 4, CertificateAuthorities: bytes.Repeat([]byte(secret)[:20], 40)},
			&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.EAP_ONLY_AUTHENTICATION, NotifyData: []byte(secret)},
			&ikev2.EncryptedPayloadEAP{EAPMessage: append([]byte{2, 1, 0, 5, 1}, []byte(secret)...)})
	}
	frozen, err := freezeAuthRequest(payloads)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := s.encryptAndWrap(frozen, ikev2.IKE_AUTH, false)
	if err != nil {
		t.Fatal(err)
	}
	var d AuthRequestDiagnostic
	s.cfg.OnAuthRequestDiagnostic = func(got AuthRequestDiagnostic) { d = got }
	packets := make([][]byte, 300)
	packets[0] = packet
	s.emitAuthRequestDiagnostic(frozen, packets)
	for _, values := range [][]int{d.PayloadTypes, d.NotifyTypes, d.IDiTypes, d.IDrTypes, d.CertReqEncodings, d.EAPCodes, d.EAPTypes} {
		if len(values) != 32 {
			t.Fatalf("unbounded array %d", len(values))
		}
	}
	if d.CertReqCount != 32 || d.CertReqCAHashCount != 32 || d.PacketCount != 255 || d.IDiAnonymous || d.IDrIsAPN || !d.EAPOnlyOffered {
		t.Fatalf("incorrect bounds or identity summary: %+v", d)
	}
	raw, err := json.Marshal(d)
	if err != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "notanonymous") {
		t.Fatal("request diagnostic leaked identity/material", err)
	}
	d.PayloadTypes[0] = -1
	s.emitAuthRequestDiagnostic(frozen, packets)
	if d.PayloadTypes[0] != int(ikev2.IDi) {
		t.Fatal("diagnostic slices not detached")
	}
}

func TestAuthRequestDiagnosticEmittedOnceAcrossRetransmission(t *testing.T) {
	s := authRequestFixture(t, true)
	var diagnosticCount, sends atomic.Int32
	s.cfg.OnAuthRequestDiagnostic = func(AuthRequestDiagnostic) { diagnosticCount.Add(1) }
	sent := make(chan struct{}, 1)
	var first []byte
	stopErr := errors.New("stop on retry")
	s.taskMgr = NewTaskManager(s.ctx, nil, 1, func(packets [][]byte) error {
		if sends.Add(1) == 1 {
			first = append([]byte(nil), packets[0]...)
			sent <- struct{}{}
			return nil
		}
		if !bytes.Equal(first, packets[0]) {
			t.Error("retransmission reserialized/re-encrypted request")
		}
		return stopErr
	})
	t.Cleanup(s.taskMgr.Stop)
	completed := make(chan error, 1)
	go func() {
		_, err := s.sendEncryptedRequestWithRetry([]ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{2, 1, 0, 5, 1}}}, ikev2.IKE_AUTH)
		completed <- err
	}()
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("initial request not enqueued")
	}
	s.taskMgr.mu.Lock()
	s.taskMgr.pending[37].Deadline = time.Now().Add(-time.Second)
	s.taskMgr.mu.Unlock()
	s.taskMgr.checkTimeouts()
	select {
	case err := <-completed:
		if !errors.Is(err, stopErr) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retransmission did not complete")
	}
	if diagnosticCount.Load() != 1 || sends.Load() != 2 {
		t.Fatalf("diagnostic/retry counts=%d/%d", diagnosticCount.Load(), sends.Load())
	}
}

func TestAuthRequestDiagnosticDoesNotObserveOtherExchanges(t *testing.T) {
	s := authRequestFixture(t, true)
	s.cfg.OnAuthRequestDiagnostic = func(AuthRequestDiagnostic) { t.Error("callback for non-AUTH exchange") }
	stopErr := errors.New("stop")
	s.taskMgr = NewTaskManager(s.ctx, nil, 1, func([][]byte) error { return stopErr })
	t.Cleanup(s.taskMgr.Stop)
	if _, err := s.sendEncryptedRequestWithRetry(nil, ikev2.INFORMATIONAL); !errors.Is(err, stopErr) {
		t.Fatal(err)
	}
}
