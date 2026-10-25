package swu

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestSessionGenerationClosesOnEarlyFailureAndCannotBeReused(t *testing.T) {
	for _, cause := range []error{ErrReauth, &RedirectError{NewAddr: "other.example", Authenticated: true}, errors.New("transport failure")} {
		calls := 0
		cfg := &Config{SIM: &effectiveConfigSIM{}, EpDGAddr: "original.example", TransportFactory: func(string, string) (Transport, error) { calls++; return nil, cause }}
		s := NewSession(cfg, zap.NewNop())
		if err := s.Connect(context.Background()); !errors.Is(err, cause) {
			t.Fatalf("cause lost: %v", err)
		}
		if calls != 1 || cfg.EpDGAddr != "original.example" {
			t.Fatal("session internally retried or changed peer")
		}
		select {
		case <-s.done:
		default:
			t.Fatal("early failure did not close completion")
		}
		if !errors.Is(s.ctx.Err(), context.Canceled) {
			t.Fatal("generation context survived return")
		}
		if err := s.Connect(context.Background()); err == nil || calls != 1 {
			t.Fatal("used session restarted")
		}
	}
}

func TestCancelledSessionNeverOpensTransport(t *testing.T) {
	s := NewSession(&Config{SIM: &effectiveConfigSIM{}, TransportFactory: func(string, string) (Transport, error) {
		t.Fatal("cancelled context opened transport")
		return nil, nil
	}}, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Connect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	s.WaitDone()
}

func TestReauthTimerStopsWithGeneration(t *testing.T) {
	s := NewSession(&Config{}, zap.NewNop())
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.startIKEReauthTimer(20 * time.Millisecond)
	s.cancel()
	// Even if a timer is already ready when cancellation is observed, the
	// public trigger checks the cancelled generation before enqueuing work.
	s.Reauthenticate()
	select {
	case <-s.reauthTrigger:
		t.Fatal("cancelled generation reauthenticated")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestUnauthenticatedRedirectCannotChangeTarget(t *testing.T) {
	s := NewSession(&Config{EpDGAddr: "original.example"}, zap.NewNop())
	data := append([]byte{ikev2.RedirectGWFQDN, byte(len("other.example"))}, []byte("other.example")...)
	packet := initResponsePacket(t, s, []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.REDIRECT, NotifyData: data}})
	if err := s.handleIKESAInitResp(packet); !errors.Is(err, ErrPeerAuthentication) {
		t.Fatalf("unauthenticated redirect accepted: %v", err)
	}
	if s.cfg.EpDGAddr != "original.example" {
		t.Fatal("unverified peer changed authentication target")
	}
}
