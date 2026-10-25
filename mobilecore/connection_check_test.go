package mobilecore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"proletarius.local/core/internal/vowifi/imscore"
)

func TestInternalCycleCancellationCanRecoverButOwnerStopCannot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	internal := fmt.Errorf("SWu sessionDown: %w", context.Canceled)
	recoverable := classifyCycleFailure(ctx, internal)
	if errors.Is(recoverable, context.Canceled) {
		t.Fatal("internal SWu cancellation still classified as owner cancellation")
	}
	if count, retry, _ := reconnectPolicy(2, true, recoverable); !retry || count != 0 {
		t.Fatalf("registered session did not recover: count=%d retry=%t", count, retry)
	}
	if _, retry, _ := reconnectPolicy(2, false, recoverable); retry {
		t.Fatal("repeated startup failures became unlimited")
	}
	cancel()
	if _, retry, _ := reconnectPolicy(0, true, classifyCycleFailure(ctx, internal)); retry {
		t.Fatal("explicit Stop could revive the session")
	}
	if _, retry, _ := reconnectPolicy(0, true, classifyCycleFailure(context.Background(), errors.New("AUTHENTICATION_FAILED"))); retry {
		t.Fatal("authentication failure became recoverable")
	}
}

func checkTestEngine(t *testing.T) (*Engine, *runningSession) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	run := &runningSession{ctx: ctx, cancel: cancel, done: make(chan struct{}), config: engineConfig{cardConfig: cardConfig{Generation: 42}}, service: &imscore.Service{}, checks: make(chan struct{}, 1)}
	engine := &Engine{host: &fakeHost{}, run: run, generation: 42, phase: "ready"}
	return engine, run
}

func TestConnectionCheckGenerationAndNonblockingCoalescing(t *testing.T) {
	engine, run := checkTestEngine(t)
	for _, command := range []string{`{"action":"check_connection"}`, `{"action":"check_connection","generation":41}`, `{"action":"check_connection","generation":42,"reason":"timer"}`} {
		if _, err := engine.Command(command); err == nil {
			t.Fatalf("accepted invalid request %s", command)
		}
	}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			status, err := engine.Command(`{"action":"check_connection","generation":42,"reason":"foreground"}`)
			if err != nil {
				t.Error(err)
				return
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(status), &parsed); err != nil {
				t.Error(err)
				return
			}
			if parsed["checking_connection"] != true || parsed["call_ready"] != false || parsed["messaging_ready"] != false || parsed["phase"] != "ready" {
				t.Errorf("unexpected checking status %s", status)
			}
		}()
	}
	workers.Wait()
	if len(run.checks) != 1 {
		t.Fatalf("checks were not coalesced: %d", len(run.checks))
	}
	for _, action := range []string{"sms", "dial"} {
		_, err := engine.Command(fmt.Sprintf(`{"action":%q,"generation":42}`, action))
		if err == nil || !strings.Contains(err.Error(), "verification") {
			t.Fatalf("%s bypassed checking: %v", action, err)
		}
	}
	for _, action := range []string{"answer", "hangup", "dtmf"} {
		_, err := engine.Command(fmt.Sprintf(`{"action":%q,"generation":42}`, action))
		if err != nil && strings.Contains(err.Error(), "verification") {
			t.Fatalf("check blocked call control %s", action)
		}
	}
}

func TestConnectionCheckCannotCrossCycleOrRestartStoppedSession(t *testing.T) {
	engine, run := checkTestEngine(t)
	if _, err := engine.Command(`{"action":"check_connection","generation":42}`); err != nil {
		t.Fatal(err)
	}
	oldChecks := run.checks
	engine.mu.Lock()
	run.service = &imscore.Service{}
	run.checks, run.checking = make(chan struct{}, 1), false
	engine.mu.Unlock()
	<-oldChecks
	if len(run.checks) != 0 || run.checking {
		t.Fatal("old cycle event reached new cycle")
	}
	close(run.done)
	if err := engine.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Command(`{"action":"check_connection","generation":42}`); err == nil {
		t.Fatal("accepted event after Stop")
	}
	if len(run.checks) != 0 {
		t.Fatal("Stop queued a revival")
	}
	engine.mu.Lock()
	engine.run, engine.phase, engine.terminal = nil, "failed", true
	engine.mu.Unlock()
	if _, err := engine.Command(`{"action":"check_connection","generation":42}`); err == nil || !strings.Contains(err.Error(), "manually") {
		t.Fatalf("terminal state lacks manual recovery: %v", err)
	}
	if engine.run != nil {
		t.Fatal("check silently started a session")
	}
}

func TestConnectionCheckDuringStartupDoesNotLeakIntoReadyCycle(t *testing.T) {
	engine, run := checkTestEngine(t)
	run.service, run.checks = nil, nil
	if _, err := engine.Command(`{"action":"check_connection","generation":42,"reason":"network_changed"}`); err != nil {
		t.Fatal(err)
	}
	if run.checking {
		t.Fatal("startup check retained a stale event")
	}
}

func TestConnectionCheckRegistrationFreshness(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		remaining time.Duration
		interval  int
		refresh   bool
	}{
		{time.Hour, 30, false}, {time.Hour, 0, true}, {-time.Second, 30, true}, {60 * time.Second, 30, true}, {61 * time.Second, 30, false},
	} {
		if got := connectionCheckNeedsRefresh(now, now.Add(test.remaining), test.interval); got != test.refresh {
			t.Errorf("remaining=%s interval=%d refresh=%t", test.remaining, test.interval, got)
		}
	}
}

func TestConnectionCheckEventsDuringProbeRequireFollowup(t *testing.T) {
	engine, run := checkTestEngine(t)
	command := `{"action":"check_connection","generation":42,"reason":"network_changed"}`
	if _, err := engine.Command(command); err != nil {
		t.Fatal(err)
	}
	<-run.checks
	firstRevision := run.checkRevision
	for i := 0; i < 10; i++ {
		if _, err := engine.Command(command); err != nil {
			t.Fatal(err)
		}
	}
	if !engine.finishConnectionCheck(run, run.service, firstRevision) || !run.checking {
		t.Fatal("old successful probe erased newer network changes")
	}
	if len(run.checks) != 0 {
		t.Fatal("changes during probe were not coalesced")
	}
	if engine.finishConnectionCheck(run, run.service, run.checkRevision) || run.checking {
		t.Fatal("final probe did not restore readiness")
	}
}

func TestConnectionCheckCompletionCannotModifyReplacementOrStoppedCycle(t *testing.T) {
	engine, run := checkTestEngine(t)
	oldService := run.service
	run.service, run.checking = &imscore.Service{}, true
	if engine.finishConnectionCheck(run, oldService, run.checkRevision) || !run.checking {
		t.Fatal("old service changed new cycle")
	}
	run.cancel()
	if engine.finishConnectionCheck(run, run.service, run.checkRevision) || !run.checking {
		t.Fatal("completion after Stop restored readiness")
	}
}

func TestFailedCheckDefersRecoveryWithoutRemainingChecking(t *testing.T) {
	engine, run := checkTestEngine(t)
	command := `{"action":"check_connection","generation":42,"reason":"foreground"}`
	if _, err := engine.Command(command); err != nil {
		t.Fatal(err)
	}
	engine.deferConnectionRecovery(run, run.service)
	if run.checking || !run.recoveryPending || len(run.checks) != 0 {
		t.Fatal("failed check still advertised work in progress")
	}
	if _, err := engine.Command(command); err != nil {
		t.Fatal(err)
	}
	if run.checking || len(run.checks) != 0 {
		t.Fatal("foreground restarted check while preserving failed call")
	}
}

func TestRegistrationFreshnessDeadlineBoundsUntrustedGrant(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		expiry int
		want   time.Duration
	}{
		{0, 0}, {-1, 0}, {10, 10 * time.Second}, {int(^uint(0) >> 1), 24 * time.Hour},
	} {
		if got := registrationFreshUntil(now, test.expiry).Sub(now); got != test.want {
			t.Errorf("expiry=%d got=%s want=%s", test.expiry, got, test.want)
		}
	}
}
