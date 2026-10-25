package imscore

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/sim"
)

type serviceStateTestDialer struct{}

func TestRuntimeCallbacksCannotAcquireReplacementLifecycle(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := serviceStateTestService(0)
	svc.started = true
	svc.lifecycleCtx = ctx
	svc.lifecycleID = 2

	if _, release, ok := svc.acquireRuntimeLease(oldCtx, 1); ok {
		release()
		t.Fatal("old incoming SIP callback acquired the replacement session")
	}
	// No runtime is installed in this fixture. If an old RP-ACK reaches the
	// current messaging path it would access that nil runtime (or send through
	// the new transport in production).
	svc.sendIncomingRPAck(oldCtx, 1, "+441234567890", 7)
	oldCancel()
	svc.sendIncomingRPAck(oldCtx, 2, "+441234567890", 7)

	if op, release, ok := svc.acquireRuntimeLease(ctx, 2); !ok {
		t.Fatal("current runtime callback was rejected")
	} else {
		if op.lifecycleCtx != ctx {
			t.Error("current callback acquired an unrelated context")
		}
		release()
	}
	// Rejected callbacks must release operationMu so Close cannot hang.
	if !svc.operationMu.TryLock() {
		t.Fatal("runtime callback rejection leaked a lifecycle lease")
	}
	svc.operationMu.Unlock()
}

type serviceStateAKAProvider struct{}

func (serviceStateAKAProvider) CalculateAKA([]byte, []byte) (sim.AKAResult, error) {
	return sim.AKAResult{}, nil
}

func (*serviceStateTestDialer) DialContextTCP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*serviceStateTestDialer) ListenContextTCP(context.Context, net.IP, int) (net.Listener, error) {
	return nil, net.ErrClosed
}

func (*serviceStateTestDialer) Close() error { return nil }

type serviceStateBlockingDialer struct {
	once    sync.Once
	dialing chan struct{}
}

func newServiceStateBlockingDialer() *serviceStateBlockingDialer {
	return &serviceStateBlockingDialer{dialing: make(chan struct{})}
}

func (d *serviceStateBlockingDialer) DialContextTCP(ctx context.Context, _ net.IP, _ int, _ net.IP, _ int) (net.Conn, error) {
	d.once.Do(func() { close(d.dialing) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*serviceStateBlockingDialer) ListenContextTCP(context.Context, net.IP, int) (net.Listener, error) {
	return nil, net.ErrClosed
}

func (*serviceStateBlockingDialer) Close() error { return nil }

type serviceStateTrackingListener struct {
	once   sync.Once
	closed chan struct{}
	closes atomic.Int32
}

func newServiceStateTrackingListener() *serviceStateTrackingListener {
	return &serviceStateTrackingListener{closed: make(chan struct{})}
}

func (l *serviceStateTrackingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *serviceStateTrackingListener) Close() error {
	l.closes.Add(1)
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*serviceStateTrackingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5063}
}

type serviceStateTrackingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *serviceStateTrackingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func serviceStateTestTransport(t *testing.T) (ipsec3gpp.Policy, *ipsec3gpp.Transport) {
	t.Helper()
	policy, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{
		LocalIP:    net.ParseIP("192.0.2.10"),
		RemoteIP:   net.ParseIP("192.0.2.20"),
		LocalSPIC:  0x10000001,
		LocalSPIS:  0x10000002,
		LocalPortC: 5064,
		LocalPortS: 5063,
		CK:         bytes.Repeat([]byte{0x11}, 16),
		IK:         bytes.Repeat([]byte{0x22}, 16),
		Mech: ipsec3gpp.SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  0x20000001,
			SPIs:  0x20000002,
			PortC: 6054,
			PortS: 6060,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ipsec3gpp.NewTransport(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy, transport
}

func serviceStateTestService(optionsInterval int) *Service {
	return &Service{cfg: Config{
		DeviceID:                   "state-test-reader",
		TraceID:                    "state-test",
		LocalIP:                    net.ParseIP("192.0.2.10"),
		PCSCFAddr:                  "192.0.2.20:5060",
		HomeDomain:                 "ims.example.test",
		PublicURI:                  "sip:user@ims.example.test",
		OptionsPingIntervalSeconds: optionsInterval,
	}}
}

func requireStatusBool(t *testing.T, status map[string]interface{}, key string, want bool) {
	t.Helper()
	got, ok := status[key].(bool)
	if !ok || got != want {
		t.Fatalf("status[%q]=%#v, want %t", key, status[key], want)
	}
}

// OPTIONS=0 is a legitimate policy setting.  A failed Port-S runtime must
// still fail closed rather than leaving a successfully registered-looking
// Service behind for the session/UI layer.
func TestActivateRegisteredRuntimeFailsClosedWhenOptionsDisabled(t *testing.T) {
	svc := serviceStateTestService(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.stateMu.Lock()
	svc.lifecycleCtx = ctx
	svc.lifecycleCancel = cancel
	svc.stateMu.Unlock()

	policy, transport := serviceStateTestTransport(t)
	policy.LocalPortS = 0 // deterministically rejected before runtime goroutines start
	client, peer := net.Pipe()
	defer peer.Close()
	conn := &serviceStateTrackingConn{Conn: client}
	listener := newServiceStateTrackingListener()

	err := svc.activateRegisteredRuntime(ctx, 0, &serviceStateTestDialer{}, &registerResult{
		pcscfAddr:     "192.0.2.20:5060",
		secureConn:    conn,
		transport:     transport,
		ipsecPolicy:   policy,
		portSListener: listener,
	}, "192.0.2.20:5060")
	if err == nil {
		t.Fatal("runtime start unexpectedly succeeded with port-s=0")
	}
	if conn.closes.Load() == 0 {
		t.Fatal("failed runtime start did not close retained secure connection")
	}
	if listener.closes.Load() == 0 {
		t.Fatal("failed runtime start did not close prepared port-s listener")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("failed runtime start did not cancel lifecycle")
	}

	status := svc.Status()
	requireStatusBool(t, status, "enabled", false)
	requireStatusBool(t, status, "registered", false)
	requireStatusBool(t, status, "signaling_ready", false)
	requireStatusBool(t, status, "transport_ready", false)
	requireStatusBool(t, status, "incoming_ready", false)
	if got := status["reg_status"]; got != "idle" {
		t.Fatalf("reg_status=%#v, want idle", got)
	}
}

func TestServiceStatusDegradesWhenHealthyRuntimeFails(t *testing.T) {
	runtime := &transportRuntime{failureC: make(chan error, 1)}
	runtime.healthy.Store(true)
	runtime.incomingDiagnostics.listenerState(true)
	svc := serviceStateTestService(0)
	svc.stateMu.Lock()
	svc.registered = true
	svc.ipsecInstalled = true
	svc.started = true
	svc.transportRuntime = runtime
	svc.stateMu.Unlock()

	status := svc.Status()
	requireStatusBool(t, status, "enabled", true)
	requireStatusBool(t, status, "registered", true)
	requireStatusBool(t, status, "signaling_ready", true)
	requireStatusBool(t, status, "transport_ready", true)
	requireStatusBool(t, status, "incoming_ready", true)
	if got := status["reg_status"]; got != "registered" {
		t.Fatalf("healthy reg_status=%#v, want registered", got)
	}

	runtime.fail(errors.New("simulated secure transport loss"))
	status = svc.Status()
	// REGISTER remains a historical/protocol result, but it must no longer be
	// used as a readiness signal after the protected transport dies.
	requireStatusBool(t, status, "registered", true)
	requireStatusBool(t, status, "signaling_ready", false)
	requireStatusBool(t, status, "transport_ready", false)
	requireStatusBool(t, status, "incoming_ready", false)
	if got := status["reg_status"]; got != "degraded" {
		t.Fatalf("failed transport reg_status=%#v, want degraded", got)
	}
}

func TestServiceReadinessSupportsExplicitSWUTunnelOnlyMode(t *testing.T) {
	runtime := &transportRuntime{failureC: make(chan error, 1)}
	runtime.healthy.Store(true)
	runtime.incomingDiagnostics.listenerState(true)
	svc := serviceStateTestService(0)
	svc.stateMu.Lock()
	svc.registered = true
	svc.started = true
	svc.sipSecurityMode = "swu_tunnel_only"
	svc.ipsecInstalled = false
	svc.transportRuntime = runtime
	svc.calls = newCallRuntime(svc)
	svc.stateMu.Unlock()
	if !svc.MessagingReady() || !svc.CallReady() {
		t.Fatal("healthy carrier-authorized SWu-tunnel-only IMS was not ready")
	}
	status := svc.Status()
	requireStatusBool(t, status, "ipsec_installed", false)
	requireStatusBool(t, status, "transport_ready", true)
	if got := status["effective_security"]; got != "swu_tunnel_only" {
		t.Fatalf("effective_security=%#v, want swu_tunnel_only", got)
	}
}

func TestCallReadyRequiresProtectedPortSListener(t *testing.T) {
	runtime := &transportRuntime{failureC: make(chan error, 1)}
	runtime.healthy.Store(true)
	svc := serviceStateTestService(0)
	svc.stateMu.Lock()
	svc.started = true
	svc.registered = true
	svc.ipsecInstalled = true
	svc.transportRuntime = runtime
	svc.calls = newCallRuntime(svc)
	svc.stateMu.Unlock()
	if svc.CallReady() {
		t.Fatal("call path reported ready before Port-S listener started")
	}
	runtime.incomingDiagnostics.listenerState(true)
	if !svc.CallReady() {
		t.Fatal("call path did not become ready after protected Port-S listener started")
	}
}

func TestServiceStatusExposesSanitizedPortSDiagnostics(t *testing.T) {
	runtime := &transportRuntime{failureC: make(chan error, 1)}
	runtime.healthy.Store(true)
	runtime.incomingDiagnostics.listenerState(true)
	runtime.incomingDiagnostics.accepted()
	observedAt := time.Date(2026, time.September, 25, 13, 14, 15, 123456789, time.UTC)
	runtime.incomingDiagnostics.inboundSIPObserved(observedAt)
	// A raw write error may contain peer endpoints or SIP identity. The status
	// endpoint must publish only a stable classification.
	runtime.incomingDiagnostics.responseWriteFailed(errors.New("write to sip:+447700900123 via 192.0.2.20 failed"))

	svc := serviceStateTestService(0)
	svc.stateMu.Lock()
	svc.registered = true
	svc.ipsecInstalled = true
	svc.started = true
	svc.transportRuntime = runtime
	svc.stateMu.Unlock()

	status := svc.Status()
	requireStatusBool(t, status, "incoming_listener_started", true)
	if got, ok := status["incoming_accept_count"].(uint64); !ok || got != 1 {
		t.Fatalf("incoming_accept_count=%#v, want uint64(1)", status["incoming_accept_count"])
	}
	if got := status["incoming_last_sip_at"]; got != observedAt.Format(time.RFC3339Nano) {
		t.Fatalf("incoming_last_sip_at=%#v, want %q", got, observedAt.Format(time.RFC3339Nano))
	}
	if got := status["incoming_reachability"]; got != "observed" {
		t.Fatalf("incoming_reachability=%#v, want observed", got)
	}
	if got := status["incoming_last_response_write_error"]; got != "write_failed" {
		t.Fatalf("incoming_last_response_write_error=%#v, want write_failed", got)
	}
}

func TestActivateRegisteredRuntimeReportsReadyOnHealthyTransport(t *testing.T) {
	svc := serviceStateTestService(0)
	ctx, cancel := context.WithCancel(context.Background())
	svc.stateMu.Lock()
	svc.lifecycleCtx = ctx
	svc.lifecycleCancel = cancel
	svc.stateMu.Unlock()
	defer cancel()

	policy, transport := serviceStateTestTransport(t)
	client, peer := net.Pipe()
	defer peer.Close()
	listener := newServiceStateTrackingListener()
	err := svc.activateRegisteredRuntime(ctx, 0, &serviceStateTestDialer{}, &registerResult{
		pcscfAddr:      "192.0.2.20:5060",
		expiresSeconds: 600,
		secureConn:     client,
		transport:      transport,
		ipsecPolicy:    policy,
		portSListener:  listener,
	}, "192.0.2.20:5060")
	if err != nil {
		t.Fatalf("activate registered runtime: %v", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
		defer closeCancel()
		if err := svc.Close(closeCtx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	}()

	deadline := time.Now().Add(time.Second)
	for !svc.CallReady() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := svc.Status()
	requireStatusBool(t, status, "enabled", true)
	requireStatusBool(t, status, "registered", true)
	requireStatusBool(t, status, "signaling_ready", true)
	requireStatusBool(t, status, "transport_ready", true)
	requireStatusBool(t, status, "incoming_ready", true)
	if got := status["reg_status"]; got != "registered" {
		t.Fatalf("reg_status=%#v, want registered", got)
	}
}

// A caller can cancel the lifecycle after REGISTER succeeds but before the
// authenticated runtime is committed. That window must not leave the retained
// Port-C connection or Port-S listener live, nor publish ready status.
func TestActivateRegisteredRuntimeFailsClosedWhenLifecycleCanceledBeforeCommit(t *testing.T) {
	svc := serviceStateTestService(0)
	ctx, cancel := context.WithCancel(context.Background())
	svc.stateMu.Lock()
	svc.lifecycleID = 41
	svc.lifecycleCtx = ctx
	svc.lifecycleCancel = cancel
	svc.starting = true
	svc.stateMu.Unlock()
	cancel()

	policy, transport := serviceStateTestTransport(t)
	client, peer := net.Pipe()
	defer peer.Close()
	conn := &serviceStateTrackingConn{Conn: client}
	listener := newServiceStateTrackingListener()

	err := svc.activateRegisteredRuntime(ctx, 41, &serviceStateTestDialer{}, &registerResult{
		pcscfAddr:     "192.0.2.20:5060",
		secureConn:    conn,
		transport:     transport,
		ipsecPolicy:   policy,
		portSListener: listener,
	}, "192.0.2.20:5060")
	if err == nil {
		t.Fatal("activation unexpectedly succeeded after lifecycle cancellation")
	}
	if conn.closes.Load() == 0 {
		t.Fatal("canceled activation did not close retained secure connection")
	}
	if listener.closes.Load() == 0 {
		t.Fatal("canceled activation did not close prepared port-s listener")
	}

	status := svc.Status()
	requireStatusBool(t, status, "enabled", false)
	requireStatusBool(t, status, "registered", false)
	requireStatusBool(t, status, "signaling_ready", false)
	requireStatusBool(t, status, "transport_ready", false)
	requireStatusBool(t, status, "incoming_ready", false)
	if got := status["reg_status"]; got != "idle" {
		t.Fatalf("reg_status=%#v, want idle", got)
	}

	svc.stateMu.RLock()
	defer svc.stateMu.RUnlock()
	if svc.lifecycleCtx != nil || svc.lifecycleCancel != nil || svc.starting || svc.started {
		t.Fatal("canceled activation left lifecycle state published")
	}
}

// Close first withdraws readiness and cancels work, but it must leave runtime
// pointers intact until an already-admitted operation releases its lease.
func TestCloseWaitsForLifecycleLeaseBeforeDetachingRuntime(t *testing.T) {
	svc := serviceStateTestService(0)
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &transportRuntime{failureC: make(chan error, 1)}
	runtime.healthy.Store(true)
	svc.stateMu.Lock()
	svc.lifecycleID = 7
	svc.lifecycleCtx = ctx
	svc.lifecycleCancel = cancel
	svc.registered = true
	svc.ipsecInstalled = true
	svc.started = true
	svc.transportRuntime = runtime
	svc.calls = newCallRuntime(svc)
	svc.fax = newFaxRuntime(svc)
	svc.stateMu.Unlock()

	_, release, ok := svc.acquireLifecycleLease()
	if !ok {
		t.Fatal("acquire lifecycle lease")
	}
	var releaseOnce sync.Once
	releaseLease := func() { releaseOnce.Do(release) }
	defer releaseLease()
	closeDone := make(chan error, 1)
	go func() { closeDone <- svc.Close(context.Background()) }()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel lifecycle")
	}
	status := svc.Status()
	requireStatusBool(t, status, "enabled", false)
	requireStatusBool(t, status, "signaling_ready", false)

	svc.stateMu.RLock()
	stillAttached := svc.transportRuntime == runtime
	svc.stateMu.RUnlock()
	if !stillAttached {
		t.Fatal("Close detached runtime before active lifecycle lease released")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before active lease released: %v", err)
	default:
	}

	releaseLease()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after lifecycle lease released")
	}

	svc.stateMu.RLock()
	defer svc.stateMu.RUnlock()
	if svc.transportRuntime != nil || svc.calls != nil || svc.fax != nil || svc.lifecycleCtx != nil {
		t.Fatal("Close did not detach lifecycle-owned runtime state")
	}
}

// A completed teardown is terminal for this service instance. Reopening it
// would let an old Start race republish its runtime after Close has withdrawn
// readiness and closed the underlying userspace network.
func TestStartFailsClosedAfterClose(t *testing.T) {
	svc := serviceStateTestService(0)
	svc.cfg.AKA = serviceStateAKAProvider{}
	if err := svc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := svc.Start(context.Background()); err == nil {
		t.Fatal("Start unexpectedly reopened a closed service")
	}
	status := svc.Status()
	requireStatusBool(t, status, "enabled", false)
	requireStatusBool(t, status, "registered", false)
}

// Closing while the REGISTER dial is in flight must cancel that Start and wait
// for it to leave the lifecycle before teardown detaches the network. This
// exercises the generation/startDone guard rather than only a pre-canceled
// activation context.
func TestCloseCancelsInFlightStartWithoutRuntimeResurrection(t *testing.T) {
	svc := serviceStateTestService(0)
	svc.cfg.AKA = serviceStateAKAProvider{}
	svc.imsCfg = IMSConfig{Transport: "tcp"}
	dialer := newServiceStateBlockingDialer()
	svc.swu = dialer

	startResult := make(chan error, 1)
	go func() { startResult <- svc.Start(context.Background()) }()
	select {
	case <-dialer.dialing:
	case <-time.After(time.Second):
		t.Fatal("Start did not reach REGISTER dial")
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- svc.Close(context.Background()) }()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after canceling in-flight Start")
	}
	select {
	case err := <-startResult:
		if err == nil {
			t.Fatal("Start unexpectedly succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not return after Close")
	}

	status := svc.Status()
	requireStatusBool(t, status, "enabled", false)
	requireStatusBool(t, status, "registered", false)
	requireStatusBool(t, status, "signaling_ready", false)
	svc.stateMu.RLock()
	defer svc.stateMu.RUnlock()
	if !svc.closing || svc.started || svc.starting || svc.lifecycleCtx != nil || svc.transportRuntime != nil {
		t.Fatal("Close left a resurrectable lifecycle state")
	}
}
