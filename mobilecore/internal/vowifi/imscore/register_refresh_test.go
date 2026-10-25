package imscore

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/policy"
)

func refreshTestService(t *testing.T, protected bool, respond func(*transportRuntime, *sip.Request)) *Service {
	t.Helper()
	cfg := Config{LocalIP: net.ParseIP("192.0.2.1"), PCSCFAddr: "192.0.2.2:5060", HomeDomain: "ims.example.test", Realm: "ims.example.test", PrivateID: "test@ims.example.test", PublicURI: "sip:test@ims.example.test", Template: policy.DefaultIMSRegisterTemplate(), RegisterExpirySeconds: 3600, AKA: &recordingAKAProvider{}}
	request, err := buildRegisterRequest(cfg, registerState{}, 5063, false, initialRegisterVariant{})
	if err != nil {
		t.Fatal(err)
	}
	request.AppendHeader(sip.NewHeader("Call-ID", "retained-registration"))
	request.AppendHeader(sip.NewHeader("CSeq", "50 REGISTER"))
	request.PrependHeader(sip.NewHeader("Via", "SIP/2.0/TCP 192.0.2.1:5064;branch=z9hG4bKold"))
	request.AppendHeader(sip.NewHeader("Authorization", `Digest nonce="old",response="old"`))
	rt := &transportRuntime{cfg: cfg, policy: ipsec3gpp.Policy{LocalPortC: 5064, LocalPortS: 5063}, tcpWriteCh: make(chan sipWriteTask), responses: make(map[string]map[uint64]chan *sip.Response)}
	if protected {
		rt.cfg.SecurityVerify = "ipsec-3gpp;spi-c=1;spi-s=2"
		request.AppendHeader(sip.NewHeader("Security-Verify", rt.cfg.SecurityVerify))
	}
	rt.healthy.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case task := <-rt.tcpWriteCh:
				message, err := sip.ParseMessage(task.payload)
				if err != nil {
					task.done <- err
					continue
				}
				task.done <- nil
				respond(rt, message.(*sip.Request))
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	service := &Service{cfg: cfg, lifecycleCtx: ctx, lifecycleCancel: cancel, started: true, registered: true, ipsecInstalled: protected, transportRuntime: rt, registerRequest: request, expiresSeconds: 3600}
	if !protected {
		service.sipSecurityMode = "swu_tunnel_only"
	}
	service.calls = newCallRuntime(service)
	service.calls.state = CallState{State: "active", CallID: "live-call", AudioPort: 55555, AudioToken: "live-audio"}
	return service
}

func TestRegistrationRefreshPreservesRuntimeAndActiveCall(t *testing.T) {
	var sequence atomic.Uint32
	service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
		sequence.Store(request.CSeq().SeqNo)
		response := sip.NewResponseFromRequest(request, sip.StatusOK, "OK", nil)
		response.AppendHeader(sip.NewHeader("Expires", "3600"))
		response.AppendHeader(sip.NewHeader("Contact", "<sip:test@192.0.2.1:5063>;expires=1800"))
		// Stale/out-of-dialog responses cannot validate a registration.
		stale := response.Clone()
		stale.CSeq().SeqNo--
		rt.publishResponse(stale)
		wrongBranch := response.Clone()
		wrongBranch.Via().Params.Add("branch", "z9hG4bKwrong")
		rt.publishResponse(wrongBranch)
		rt.publishResponse(response)
	})
	runtime, calls := service.transportRuntime, service.calls
	granted, err := service.RefreshRegistration(context.Background())
	if err != nil || granted != 1800 || sequence.Load() != 51 {
		t.Fatalf("refresh=%d %v sequence=%d", granted, err, sequence.Load())
	}
	if service.transportRuntime != runtime || service.calls != calls || service.CallStatus().AudioPort != 55555 || service.CallStatus().State != "active" {
		t.Fatal("registration renewal replaced live transport/call/audio")
	}
	if got := service.registerRequest.GetHeader("Authorization").Value(); strings.Contains(got, "old") || !strings.Contains(got, "integrity-protected=yes") {
		t.Fatalf("refresh replayed stale proof or lost integrity marker: %s", got)
	}
	if _, err := service.RefreshRegistration(context.Background()); err != nil || sequence.Load() != 52 {
		t.Fatalf("second refresh did not advance CSeq: %d %v", sequence.Load(), err)
	}
}

func TestRegistrationRefreshAKAChallengeUsesSameTransport(t *testing.T) {
	var requests atomic.Int32
	service := refreshTestService(t, false, func(rt *transportRuntime, request *sip.Request) {
		round := requests.Add(1)
		if round == 1 {
			response := sip.NewResponseFromRequest(request, sip.StatusUnauthorized, "Unauthorized", nil)
			response.AppendHeader(sip.NewHeader("WWW-Authenticate", fmt.Sprintf(`Digest realm="ims.example.test",nonce="%s",algorithm=AKAv1-MD5,qop="auth"`, base64.StdEncoding.EncodeToString(make([]byte, 32)))))
			rt.publishResponse(response)
			return
		}
		if request.GetHeader("Authorization") == nil || strings.Contains(request.GetHeader("Authorization").Value(), "old") {
			t.Error("AKA response missing fresh authorization")
		}
		rt.publishResponse(sip.NewResponseFromRequest(request, sip.StatusOK, "OK", nil))
	})
	if _, err := service.RefreshRegistration(context.Background()); err != nil || requests.Load() != 2 {
		t.Fatalf("AKA refresh requests=%d err=%v", requests.Load(), err)
	}
}

func TestRegistrationRefreshFailsClosedForNewSecurityOrRejection(t *testing.T) {
	for _, code := range []int{401, 403} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var requests atomic.Int32
			service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
				requests.Add(1)
				response := sip.NewResponseFromRequest(request, code, "Rejected", nil)
				response.AppendHeader(sip.NewHeader("Security-Server", rt.cfg.SecurityVerify))
				rt.publishResponse(response)
			})
			if _, err := service.RefreshRegistration(context.Background()); err == nil || requests.Load() != 1 {
				t.Fatalf("unsafe refresh accepted: %v", err)
			}
			service.WithdrawRegistration()
			if service.MessagingReady() || service.CallStatus().State != "active" {
				t.Fatal("refresh failure should withdraw new business, not destroy ongoing call")
			}
		})
	}
}

func TestRegistrationRefreshCancellationDoesNotClaimSuccess(t *testing.T) {
	service := refreshTestService(t, false, func(*transportRuntime, *sip.Request) {})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := service.RefreshRegistration(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected canceled refresh, got %v", err)
	}
	if service.expiresSeconds != 3600 || service.CallStatus().State != "active" {
		t.Fatal("canceled renewal changed existing lifetime or call")
	}
}

func TestRegistrationRefreshContactLifetimeBoundaries(t *testing.T) {
	for _, test := range []struct {
		name          string
		currentExpiry string
		globalExpiry  string
		wantFailure   bool
		wantExpiry    int
	}{
		{"matching-zero-without-global", "0", "", true, 0},
		{"matching-zero-overrides-positive-global", "0", "3600", true, 0},
		{"matching-negative", "-1", "3600", true, 0},
		{"matching-invalid", "broken", "3600", true, 0},
		{"current-positive-old-zero", "1200", "3600", false, 1200},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
				response := sip.NewResponseFromRequest(request, sip.StatusOK, "OK", nil)
				if test.globalExpiry != "" {
					response.AppendHeader(sip.NewHeader("Expires", test.globalExpiry))
				}
				response.AppendHeader(sip.NewHeader("Contact", fmt.Sprintf("<sip:old@192.0.2.100:5063>;expires=0,<%s>;Expires=%s", request.Contact().Address.String(), test.currentExpiry)))
				rt.publishResponse(response)
			})
			granted, err := service.RefreshRegistration(context.Background())
			if (err != nil) != test.wantFailure || granted != test.wantExpiry {
				t.Fatalf("granted=%d err=%v, want failure=%v expiry=%d", granted, err, test.wantFailure, test.wantExpiry)
			}
			if test.wantFailure && service.expiresSeconds != 3600 {
				t.Fatal("invalid response committed a registration lifetime")
			}
		})
	}
}
