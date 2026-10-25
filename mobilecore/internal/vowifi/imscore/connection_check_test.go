package imscore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

func startCheckWorker(t *testing.T, service *Service, interval int) {
	t.Helper()
	service.cfg.OptionsPingIntervalSeconds = interval
	rt := service.transportRuntime
	rt.cfg.OptionsPingIntervalSeconds = interval
	rt.optionsChecks = make(chan optionsCheckRequest, 1)
	ctx, cancel := context.WithCancel(service.lifecycleCtx)
	rt.wg.Add(1)
	go rt.runOptionsPing(ctx)
	t.Cleanup(func() { cancel(); rt.wg.Wait() })
}

func TestConnectionCheckRespectsDisabledOptionsAndRevalidatesBinding(t *testing.T) {
	for _, forceRefresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "options_disabled", true: "binding_expired"}[forceRefresh], func(t *testing.T) {
			var count atomic.Int32
			service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
				if request.Method != sip.REGISTER {
					t.Errorf("unexpected request: %s", request.Method)
				}
				count.Add(1)
				response := sip.NewResponseFromRequest(request, 200, "OK", nil)
				response.AppendHeader(sip.NewHeader("Expires", "1800"))
				rt.publishResponse(response)
			})
			if forceRefresh {
				service.cfg.OptionsPingIntervalSeconds = 30
			}
			granted, err := service.CheckConnection(context.Background(), forceRefresh)
			if err != nil || granted != 1800 || count.Load() != 1 {
				t.Fatalf("check: granted=%d count=%d err=%v", granted, count.Load(), err)
			}
			if service.CallStatus().State != "active" {
				t.Fatal("check replaced active call")
			}
		})
	}
}

func TestExplicitConnectionCheckSharesPeriodicHeartbeatWorker(t *testing.T) {
	firstRequest := make(chan *sip.Request, 1)
	var count atomic.Int32
	service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
		if request.Method != sip.OPTIONS {
			t.Errorf("unexpected request: %s", request.Method)
		}
		if count.Add(1) == 1 {
			firstRequest <- request
			return
		}
		rt.publishResponse(sip.NewResponseFromRequest(request, 200, "OK", nil))
	})
	startCheckWorker(t, service, 1)
	var first *sip.Request
	select {
	case first = <-firstRequest:
	case <-time.After(3 * time.Second):
		t.Fatal("periodic heartbeat did not run")
	}
	result := make(chan error, 1)
	go func() { _, err := service.CheckConnection(context.Background(), false); result <- err }()
	deadline := time.Now().Add(time.Second)
	for len(service.transportRuntime.optionsChecks) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(service.transportRuntime.optionsChecks) != 1 || count.Load() != 1 {
		t.Fatal("explicit check ran concurrently with periodic heartbeat")
	}
	service.transportRuntime.publishResponse(sip.NewResponseFromRequest(first, 200, "OK", nil))
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("explicit check did not follow periodic probe")
	}
	if count.Load() != 2 || service.CallStatus().State != "active" || !service.MessagingReady() {
		t.Fatal("check did not restore readiness while preserving call")
	}
}

func TestExplicitConnectionCheckCancellationDoesNotHangTeardown(t *testing.T) {
	requestReceived := make(chan struct{}, 1)
	service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) { requestReceived <- struct{}{} })
	startCheckWorker(t, service, 3600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := service.CheckConnection(ctx, false); result <- err }()
	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("check did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("check cancellation=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("check ignored Stop cancellation")
	}
}

func TestExplicitConnectionCheckFailurePreservesCallAndStopsPeriodicRecovery(t *testing.T) {
	var count atomic.Int32
	service := refreshTestService(t, true, func(rt *transportRuntime, request *sip.Request) {
		count.Add(1)
		rt.publishResponse(sip.NewResponseFromRequest(request, 503, "Unavailable", nil))
	})
	startCheckWorker(t, service, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, err := service.CheckConnection(ctx, false)
	if err == nil {
		t.Fatal("two failed probes passed verification")
	}
	service.transportRuntime.wg.Wait()
	if count.Load() != 2 {
		t.Fatalf("expected exactly two serialized probes, got %d", count.Load())
	}
	if service.CallStatus().State != "active" {
		t.Fatal("verification terminated the call")
	}
	if service.transportRuntime.failed {
		t.Fatal("check forced fatal transport failure before call ended")
	}
	service.WithdrawRegistration()
	if service.MessagingReady() || service.CallReady() {
		t.Fatal("failure left new business ready")
	}
	if _, release, ok := service.acquireOperation(false); !ok {
		t.Fatal("failure blocked existing call controls")
	} else {
		release()
	}
}
