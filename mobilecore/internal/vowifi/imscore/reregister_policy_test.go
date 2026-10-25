package imscore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"proletarius.local/core/internal/vowifi/policy"
)

func exact500Rules() []policy.SIPReRegisterRule {
	return []policy.SIPReRegisterRule{{Method: "REGISTER", Statuses: []string{"500"}}, {Method: "INVITE", Statuses: []string{"500"}}}
}

func TestReRegisterPolicyDoesNotBroadenUnsupportedExpressions(t *testing.T) {
	for _, test := range []struct {
		method     sip.RequestMethod
		code       int
		expression string
		want       bool
	}{
		{sip.REGISTER, 500, "500", true}, {sip.INVITE, 500, "500", true},
		{sip.REGISTER, 403, "403", false}, {sip.REGISTER, 401, "401", false},
		{sip.INVITE, 503, "503", false}, {sip.MESSAGE, 500, "500", false},
		{sip.REGISTER, 500, "500-599", false}, {sip.REGISTER, 500, "5xx", false},
		{sip.REGISTER, 500, "*", false}, {sip.REGISTER, 500, "+500", false},
	} {
		cfg := Config{Template: policy.IMSRegisterTemplate{ReRegisterOn: []policy.SIPReRegisterRule{{Method: string(test.method), Statuses: []string{test.expression}}}}}
		if got := configuredReRegister500(cfg, test.method, test.code); got != test.want {
			t.Fatalf("%+v got %v", test, got)
		}
	}
	if configuredReRegister500(Config{Template: policy.DefaultIMSRegisterTemplate()}, sip.REGISTER, 500) {
		t.Fatal("default carrier gained retries")
	}
}

func TestRegistrationRefresh500BoundedAndPreservesTransport(t *testing.T) {
	for _, test := range []struct {
		name                 string
		configured, repeated bool
		want                 int32
	}{
		{"success_after_500", true, false, 2}, {"repeated_500", true, true, 2}, {"unconfigured", false, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var count atomic.Int32
			var lastSeq atomic.Uint32
			service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
				n := count.Add(1)
				if request.CSeq().SeqNo <= lastSeq.Swap(request.CSeq().SeqNo) {
					t.Error("retry reused CSeq")
				}
				if !strings.Contains(request.GetHeader("Authorization").Value(), "integrity-protected=yes") {
					t.Error("lost protected context")
				}
				code := sip.StatusOK
				if n == 1 || test.repeated {
					code = 500
				}
				rt.publishResponse(sip.NewResponseFromRequest(request, code, "response", nil))
			})
			if test.configured {
				service.cfg.Template.ReRegisterOn = exact500Rules()
			}
			runtime := service.transportRuntime
			_, err := service.RefreshRegistration(context.Background())
			if (err != nil) != test.repeated || count.Load() != test.want {
				t.Fatalf("requests=%d err=%v", count.Load(), err)
			}
			if service.transportRuntime != runtime || service.CallStatus().State != "active" {
				t.Fatal("retry disrupted runtime or call")
			}
		})
	}
}

func TestRegistrationRefresh500RetryCancellationAndSecurity(t *testing.T) {
	for _, test := range []string{"cancel", "new_security", "invalid_retry_after", "long_retry_after"} {
		t.Run(test, func(t *testing.T) {
			var count atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
				count.Add(1)
				response := sip.NewResponseFromRequest(request, 500, "failure", nil)
				switch test {
				case "new_security":
					response.AppendHeader(sip.NewHeader("Security-Server", "different"))
				case "invalid_retry_after":
					response.AppendHeader(sip.NewHeader("Retry-After", ""))
				case "long_retry_after":
					response.AppendHeader(sip.NewHeader("Retry-After", "1000000000"))
				case "cancel":
					cancel()
				}
				rt.publishResponse(response)
			})
			service.cfg.Template.ReRegisterOn = exact500Rules()
			_, err := service.RefreshRegistration(ctx)
			if err == nil || count.Load() != 1 {
				t.Fatalf("requests=%d err=%v", count.Load(), err)
			}
			if test == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

func TestRegistrationRefresh500BackoffEndsWithServiceLifecycle(t *testing.T) {
	var count atomic.Int32
	rejected := make(chan struct{})
	service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
		count.Add(1)
		rt.publishResponse(sip.NewResponseFromRequest(request, 500, "failure", nil))
		close(rejected)
	})
	service.cfg.Template.ReRegisterOn = exact500Rules()
	done := make(chan error, 1)
	go func() { _, err := service.RefreshRegistration(context.Background()); done <- err }()
	<-rejected
	service.lifecycleCancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || count.Load() != 1 {
			t.Fatalf("requests=%d err=%v", count.Load(), err)
		}
	case <-time.After(time.Second):
		t.Fatal("lifecycle cancellation did not end refresh backoff")
	}
}

func TestInitialRegistration500RetriesSameOfferOnlyOnce(t *testing.T) {
	for _, configured := range []bool{true, false} {
		t.Run(fmt.Sprint(configured), func(t *testing.T) {
			client, server := net.Pipe()
			transport := newConnRegisterTransport(client, "test", "test")
			defer transport.Close()
			defer server.Close()
			cfg := Config{LocalIP: net.ParseIP("192.0.2.1"), PCSCFAddr: "192.0.2.2:5060", HomeDomain: "ims.example", Realm: "ims.example", PrivateID: "test@ims.example", PublicURI: "sip:test@ims.example", Template: policy.DefaultIMSRegisterTemplate()}
			if configured {
				cfg.Template.ReRegisterOn = exact500Rules()
			}
			session := newRegisterSession(cfg, nil, nil, "tcp", 0)
			var count atomic.Int32
			done := make(chan error, 1)
			go func() {
				reader := bufio.NewReader(server)
				var last *sip.Request
				for {
					var payload strings.Builder
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							done <- nil
							return
						}
						payload.WriteString(line)
						if line == "\r\n" {
							break
						}
					}
					message, err := sip.ParseMessage([]byte(payload.String()))
					if err != nil {
						done <- err
						return
					}
					request := message.(*sip.Request)
					count.Add(1)
					if last != nil && (request.CSeq().SeqNo <= last.CSeq().SeqNo || request.Via().Params.GetOr("branch", "") == last.Via().Params.GetOr("branch", "") || request.GetHeader("Security-Client").Value() != last.GetHeader("Security-Client").Value()) {
						done <- fmt.Errorf("retry changed security offer or reused identity")
						return
					}
					last = request
					response := sip.NewResponseFromRequest(request, 500, "failure", nil)
					response.AppendHeader(sip.NewHeader("Content-Length", "0"))
					if _, err := server.Write([]byte(response.String())); err != nil {
						done <- err
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			res, _, err := session.registerInitialWithPolicy(ctx, transport, initialRegisterVariant{})
			want := int32(1)
			if configured {
				want = 2
			}
			if err != nil || res.StatusCode != 500 || count.Load() != want {
				t.Fatalf("requests=%d response=%v err=%v", count.Load(), res, err)
			}
			_ = transport.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvite500FailsCallAndRequestsSingleRefreshWithoutRedial(t *testing.T) {
	var registers, invites, acks atomic.Int32
	service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
		switch request.Method {
		case sip.REGISTER:
			registers.Add(1)
			rt.publishResponse(sip.NewResponseFromRequest(request, 200, "OK", nil))
		case sip.INVITE:
			invites.Add(1)
		case sip.ACK:
			acks.Add(1)
		}
	})
	service.cfg.Template.ReRegisterOn = exact500Rules()
	calls := service.calls
	calls.state = CallState{State: "outgoing", CallID: "failed-call"}
	payload, err := calls.buildRequest(sip.INVITE, "+447700900123", "failed-call", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	message, err := sip.ParseMessage(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := message.(*sip.Request)
	if err := service.transportRuntime.enqueueWrite(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	response := sip.NewResponseFromRequest(request, 500, "failure", nil)
	responses := make(chan *sip.Response, 3)
	stale := response.Clone()
	stale.CSeq().SeqNo++
	responses <- stale
	responses <- response
	responses <- response.Clone()
	done := make(chan struct{})
	go calls.watchInvite(service.lifecycleCtx, "+447700900123", "failed-call", 1, responses, func() { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("INVITE watcher did not finish")
	}
	if service.CallStatus().State != "failed" || invites.Load() != 1 || acks.Load() != 1 || registers.Load() != 0 {
		t.Fatalf("state=%+v invites=%d acks=%d registers=%d", service.CallStatus(), invites.Load(), acks.Load(), registers.Load())
	}
	select {
	case <-service.RegistrationRecoveryRequests():
	default:
		t.Fatal("missing recovery request")
	}
	// Drive the same maintenance entry point used by the engine.
	if _, err := service.CheckConnection(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	service.requestInviteRegistrationRecovery(response)
	select {
	case <-service.RegistrationRecoveryRequests():
		t.Fatal("repeated failure exceeded lifecycle budget")
	default:
	}
	if invites.Load() != 1 || registers.Load() != 1 || service.CallStatus().State != "failed" {
		t.Fatal("recovery replayed the call or changed its failure")
	}
}

func TestInviteRecoveryIgnoresOtherCardsCancelledLifecyclesAndRetryAfter(t *testing.T) {
	for _, mode := range []string{"other_card", "closed", "cancelled", "retry_after", "wrong_status"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &Service{cfg: Config{Template: policy.IMSRegisterTemplate{ReRegisterOn: exact500Rules()}}, registered: true, lifecycleCtx: ctx}
			response := sip.NewResponse(500, "failure")
			switch mode {
			case "other_card":
				s.cfg.Template.ReRegisterOn = nil
			case "closed":
				s.closing = true
			case "cancelled":
				cancel()
			case "retry_after":
				response.AppendHeader(sip.NewHeader("Retry-After", "30"))
			case "wrong_status":
				response.StatusCode = 403
			}
			s.requestInviteRegistrationRecovery(response)
			select {
			case <-s.RegistrationRecoveryRequests():
				t.Fatal("unexpected recovery")
			default:
			}
		})
	}
}
