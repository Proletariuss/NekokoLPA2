package imscore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	imsPolicy "proletarius.local/core/internal/vowifi/policy"
)

type payloadAndEOFConn struct {
	payload []byte
	writes  bytes.Buffer
	read    bool
}

func (c *payloadAndEOFConn) Read(target []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	return copy(target, c.payload), io.EOF
}

func (c *payloadAndEOFConn) Write(payload []byte) (int, error) { return c.writes.Write(payload) }
func (c *payloadAndEOFConn) Close() error                      { return nil }
func (c *payloadAndEOFConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5063}
}
func (c *payloadAndEOFConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 6060}
}
func (c *payloadAndEOFConn) SetDeadline(time.Time) error      { return nil }
func (c *payloadAndEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (c *payloadAndEOFConn) SetWriteDeadline(time.Time) error { return nil }

type failingPortSWriteConn struct {
	payloadAndEOFConn
	err error
}

func (c *failingPortSWriteConn) Write([]byte) (int, error) {
	return 0, c.err
}

// retainedEOFConn models a carrier that delivers an INVITE and half-closes
// its write side. TCP still allows the client to send a delayed final response
// until the local side closes; the tests prove our runtime
// owns that lifecycle explicitly.
type retainedEOFConn struct {
	mu      sync.Mutex
	payload []byte
	read    bool
	closed  bool
	writes  bytes.Buffer
}

func newRetainedEOFConn(payload []byte) *retainedEOFConn {
	return &retainedEOFConn{payload: append([]byte(nil), payload...)}
}

func (c *retainedEOFConn) Read(target []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	return copy(target, c.payload), io.EOF
}

func (c *retainedEOFConn) Write(payload []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.writes.Write(payload)
}

func (c *retainedEOFConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
	}
	c.mu.Unlock()
	return nil
}

func (c *retainedEOFConn) responseText() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes.String()
}

func (c *retainedEOFConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *retainedEOFConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5063}
}

func (c *retainedEOFConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 6060}
}

func (c *retainedEOFConn) SetDeadline(time.Time) error      { return nil }
func (c *retainedEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (c *retainedEOFConn) SetWriteDeadline(time.Time) error { return nil }

type queuedPortSListener struct {
	accepted chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func newQueuedPortSListener() *queuedPortSListener {
	return &queuedPortSListener{
		accepted: make(chan net.Conn, 1),
		closed:   make(chan struct{}),
	}
}

func (l *queuedPortSListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *queuedPortSListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*queuedPortSListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5063}
}

type closeCountingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type blockingTCPListener struct {
	once   sync.Once
	closed chan struct{}
}

func newBlockingTCPListener() *blockingTCPListener {
	return &blockingTCPListener{closed: make(chan struct{})}
}

func (l *blockingTCPListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingTCPListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingTCPListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 6060}
}

type runtimeTestDialer struct {
	listener *blockingTCPListener
}

func (d *runtimeTestDialer) DialContextTCP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (d *runtimeTestDialer) ListenContextTCP(context.Context, net.IP, int) (net.Listener, error) {
	return d.listener, nil
}

func (d *runtimeTestDialer) Close() error { return nil }

func runtimeTestPolicy(t *testing.T) (ipsec3gpp.Policy, *ipsec3gpp.Transport) {
	t.Helper()
	policy, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{
		LocalIP:   net.ParseIP("192.0.2.10"),
		RemoteIP:  net.ParseIP("192.0.2.20"),
		LocalSPIC: 0x20000001, LocalSPIS: 0x20000002, LocalPortC: 5064, LocalPortS: 5063,
		CK: bytes.Repeat([]byte{0x33}, 16),
		IK: bytes.Repeat([]byte{0x44}, 16),
		Mech: ipsec3gpp.SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  0x10000001,
			SPIs:  0x10000002,
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

func TestTransportRuntimeUsesPlainTCPConnectionAndClosesCleanly(t *testing.T) {
	client, peer := net.Pipe()
	counted := &closeCountingConn{Conn: client}
	dialer := &runtimeTestDialer{listener: newBlockingTCPListener()}
	policy, transport := runtimeTestPolicy(t)

	rt, err := startTransportRuntime(context.Background(), Config{
		LocalIP:    net.ParseIP("192.0.2.10"),
		PCSCFAddr:  "192.0.2.20:5060",
		HomeDomain: "ims.example.test",
		PublicURI:  "sip:user@ims.example.test",
	}, dialer, policy, transport, counted)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("OPTIONS sip:ims.example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	writeDone := make(chan error, 1)
	go func() { writeDone <- rt.enqueueWrite(context.Background(), payload) }()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("runtime wrote packet-wrapped bytes:\n got %x\nwant %x", got, payload)
	}

	closed := make(chan struct{})
	go func() {
		rt.Close()
		rt.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("transport runtime Close blocked on port-s Accept")
	}
	if got := counted.closes.Load(); got != 1 {
		t.Fatalf("port-c Close calls=%d, want 1", got)
	}
	_ = peer.Close()
}

func TestTransportRuntimeAllowsExplicitSWUTunnelOnlyMode(t *testing.T) {
	client, peer := net.Pipe()
	dialer := &runtimeTestDialer{listener: newBlockingTCPListener()}
	ipsecPolicy, _ := runtimeTestPolicy(t)
	rt, err := startTransportRuntime(context.Background(), Config{
		LocalIP:    net.ParseIP("192.0.2.10"),
		PCSCFAddr:  "192.0.2.20:5060",
		HomeDomain: "ims.example.test",
		PublicURI:  "sip:user@ims.example.test",
		Template:   imsPolicy.IMSRegisterTemplate{AllowPlainIMS: true, SecAgreeMode: "disabled"},
	}, dialer, ipsecPolicy, nil, client)
	if err != nil {
		t.Fatalf("explicit SWu-tunneled SIP mode rejected: %v", err)
	}
	defer rt.Close()
	if !rt.Healthy() {
		t.Fatal("plain IMS runtime did not start healthy")
	}
	_ = peer.Close()
}

func TestTransportRuntimeReadFailureWithdrawsMessagingReadiness(t *testing.T) {
	client, peer := net.Pipe()
	dialer := &runtimeTestDialer{listener: newBlockingTCPListener()}
	policy, transport := runtimeTestPolicy(t)
	rt, err := startTransportRuntime(context.Background(), Config{
		LocalIP:    net.ParseIP("192.0.2.10"),
		PCSCFAddr:  "192.0.2.20:5060",
		HomeDomain: "ims.example.test",
		PublicURI:  "sip:user@ims.example.test",
	}, dialer, policy, transport, client)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	service := &Service{registered: true, ipsecInstalled: true, transportRuntime: rt}
	if !service.MessagingReady() {
		t.Fatal("new authenticated transport is not ready")
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case failure := <-service.TransportFailure():
		if failure == nil {
			t.Fatal("nil transport failure")
		}
	case <-time.After(time.Second):
		t.Fatal("secure transport EOF was not reported")
	}
	if service.MessagingReady() {
		t.Fatal("SMS remained ready after secure transport EOF")
	}
}

func TestTransportRuntimeHeartbeatRecoveryCannotOverrideFatalFailure(t *testing.T) {
	runtime := &transportRuntime{}
	runtime.healthy.Store(true)
	runtime.markDegraded()
	if runtime.Healthy() {
		t.Fatal("missed authenticated heartbeat left transport healthy")
	}
	runtime.markHealthy(context.Background())
	if !runtime.Healthy() {
		t.Fatal("confirmed heartbeat did not restore transport readiness")
	}
	runtime.fail(errors.New("secure transport closed"))
	runtime.markHealthy(context.Background())
	if runtime.Healthy() {
		t.Fatal("heartbeat recovery overrode a fatal transport failure")
	}
}

func TestOptionsPingTargetsConfirmedPCSCFRoute(t *testing.T) {
	policy, _ := runtimeTestPolicy(t)
	payload, err := buildOptionsPing(Config{
		LocalIP:            net.ParseIP("2001:db8::10"),
		PCSCFAddr:          "[2001:db8::20]:5060",
		TransportPCSCFAddr: "[2001:db8::20]:5063",
		HomeDomain:         "ims.mnc033.mcc234.3gppnetwork.org",
		PublicURI:          "sip:234330123456789@ims.mnc033.mcc234.3gppnetwork.org",
	}, policy, "options-route", 7)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(payload)
	if !strings.HasPrefix(wire, "OPTIONS sip:[2001:db8::20]:5063 SIP/2.0\r\n") {
		t.Fatalf("OPTIONS did not target protected P-CSCF route:\n%s", wire)
	}
	if strings.Contains(wire, "OPTIONS sip:ims.mnc033") {
		t.Fatalf("OPTIONS still targets home registrar domain:\n%s", wire)
	}
}

func TestConfirmOptionsHeartbeatWithdrawsAndRestoresReadinessOnSingleMiss(t *testing.T) {
	ctx := context.Background()
	probes := 0
	misses := 0
	recoveries := 0
	status, err := confirmOptionsHeartbeat(ctx, 0, func() (int, error) {
		probes++
		if probes == 1 {
			return 0, errors.New("temporary packet loss")
		}
		return 200, nil
	}, func() { misses++ }, func() { recoveries++ })
	if err != nil {
		t.Fatalf("confirmation probe failed: %v", err)
	}
	if status != 200 || probes != 2 || misses != 1 || recoveries != 1 {
		t.Fatalf("status=%d probes=%d misses=%d recoveries=%d", status, probes, misses, recoveries)
	}
}

func TestConfirmOptionsHeartbeatFailsAfterTwoMisses(t *testing.T) {
	probes := 0
	misses := 0
	recoveries := 0
	_, err := confirmOptionsHeartbeat(context.Background(), 0, func() (int, error) {
		probes++
		return 0, errors.New("no final response")
	}, func() { misses++ }, func() { recoveries++ })
	if err == nil || !strings.Contains(err.Error(), "confirmation probe") {
		t.Fatalf("error=%v, want confirmation failure", err)
	}
	if probes != 2 || misses != 1 || recoveries != 0 {
		t.Fatalf("probes=%d misses=%d recoveries=%d", probes, misses, recoveries)
	}
}

func TestConfirmOptionsHeartbeatCancellationSkipsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probes := 0
	_, err := confirmOptionsHeartbeat(ctx, time.Second, func() (int, error) {
		probes++
		return 0, errors.New("no final response")
	}, cancel, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
	if probes != 1 {
		t.Fatalf("probe count=%d, want retry skipped after cancellation", probes)
	}
}

func TestOptionsHeartbeatRequiresFinalResponse(t *testing.T) {
	responses := make(chan *sip.Response, 2)
	responses <- &sip.Response{StatusCode: 100}
	responses <- &sip.Response{StatusCode: 200}
	status, err := awaitOptionsFinalResponse(context.Background(), responses, time.Second)
	if err != nil || status != 200 {
		t.Fatalf("final response status=%d, err=%v", status, err)
	}

	onlyProvisional := make(chan *sip.Response, 1)
	onlyProvisional <- &sip.Response{StatusCode: 100}
	if _, err := awaitOptionsFinalResponse(context.Background(), onlyProvisional, 10*time.Millisecond); err == nil {
		t.Fatal("provisional response incorrectly kept IMS online")
	}

	closed := make(chan *sip.Response)
	close(closed)
	if _, err := awaitOptionsFinalResponse(context.Background(), closed, time.Second); err == nil {
		t.Fatal("closed response stream incorrectly kept IMS online")
	}
}

func TestOptionsHeartbeatRejectsNon2xxFinalResponse(t *testing.T) {
	responses := make(chan *sip.Response, 2)
	responses <- &sip.Response{StatusCode: 100}
	responses <- &sip.Response{StatusCode: 403}

	status, err := awaitOptionsFinalResponse(context.Background(), responses, time.Second)
	if status != 403 {
		t.Fatalf("final response status=%d, want 403", status)
	}
	if err == nil || !strings.Contains(err.Error(), "SIP 403") {
		t.Fatalf("non-2xx final response error=%v, want readable SIP 403 failure", err)
	}
}

func TestPortSProcessesInviteBytesReturnedWithEOF(t *testing.T) {
	invite := "INVITE sip:user@ims.example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.20:6060;branch=z9hG4bK-final\r\n" +
		"From: <sip:caller@example.test>;tag=remote\r\n" +
		"To: <sip:user@ims.example.test>\r\n" +
		"Call-ID: final-before-eof\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	conn := &payloadAndEOFConn{payload: []byte(invite)}
	called := make(chan struct{}, 1)
	runtime := &transportRuntime{
		cfg: Config{TraceID: "final-eof", DeviceID: "reader-test"},
		incomingSIP: func(request *sip.Request, respond SIPResponder) {
			if request.Method != sip.INVITE {
				t.Errorf("method=%s", request.Method)
			}
			if err := respond(newIncomingResponse(request, 180, "Ringing", nil)); err != nil {
				t.Errorf("respond: %v", err)
			}
			if err := respond(newIncomingResponse(request, 486, "Busy Here", nil)); err != nil {
				t.Errorf("terminal respond: %v", err)
			}
			called <- struct{}{}
		},
	}
	runtime.wg.Add(1)
	runtime.drainInboundPortS(context.Background(), conn)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("final INVITE bytes were dropped when Read returned payload plus EOF")
	}
	if response := conn.writes.String(); !strings.Contains(response, "SIP/2.0 180 Ringing") || !strings.Contains(response, "SIP/2.0 486 Busy Here") || !strings.Contains(response, "Call-ID: final-before-eof") {
		t.Fatalf("unexpected same-connection response:\n%s", response)
	}
}

func halfClosedIncomingInvite(callID string) []byte {
	body := "v=0\r\nc=IN IP4 192.0.2.20\r\nm=audio 40000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
	return []byte("INVITE sip:callee@ims.example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.20:6060;branch=z9hG4bK-half-close\r\n" +
		"From: <sip:caller@example.test>;tag=remote\r\n" +
		"To: <sip:callee@ims.example.test>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
}

func waitForPortSResponse(t *testing.T, conn *retainedEOFConn, fragment string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(conn.responseText(), fragment) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Port-S response missing %q: %s", fragment, conn.responseText())
}

func waitForPortSDrain(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Port-S connection was not released after terminal response")
	}
}

func halfClosedIncomingCallRuntime() *callRuntime {
	return newCallRuntime(&Service{
		cfg:          Config{LocalIP: net.ParseIP("192.0.2.10")},
		network:      localMediaIMSNetwork{},
		lifecycleCtx: context.Background(),
	})
}

func TestPortSHalfClosedInviteAllowsDelayedAnswer(t *testing.T) {
	calls := halfClosedIncomingCallRuntime()
	calls.incomingDecisionTimeout = time.Second
	defer calls.finish("ended", nil)

	conn := newRetainedEOFConn(halfClosedIncomingInvite("half-close-answer@example.test"))
	runtime := &transportRuntime{
		cfg:         Config{TraceID: "half-close-answer", DeviceID: "reader-test"},
		incomingSIP: calls.handleRequest,
	}
	runtime.wg.Add(1)
	drained := make(chan struct{})
	go func() {
		runtime.drainInboundPortS(context.Background(), conn)
		close(drained)
	}()

	waitForPortSResponse(t, conn, "SIP/2.0 180 Ringing")
	if conn.isClosed() {
		t.Fatal("Port-S connection closed before delayed user answer")
	}
	time.Sleep(20 * time.Millisecond)
	if err := calls.answer(context.Background()); err != nil {
		t.Fatalf("answer half-closed incoming INVITE: %v", err)
	}
	waitForPortSResponse(t, conn, "SIP/2.0 200 OK")
	waitForPortSDrain(t, drained)
	if !conn.isClosed() {
		t.Fatal("Port-S connection remained open after final 200 OK")
	}
}

func TestPortSHalfClosedInviteAllowsReject(t *testing.T) {
	calls := halfClosedIncomingCallRuntime()
	calls.incomingDecisionTimeout = time.Second
	defer calls.finish("ended", nil)

	conn := newRetainedEOFConn(halfClosedIncomingInvite("half-close-reject@example.test"))
	runtime := &transportRuntime{
		cfg:         Config{TraceID: "half-close-reject", DeviceID: "reader-test"},
		incomingSIP: calls.handleRequest,
	}
	runtime.wg.Add(1)
	drained := make(chan struct{})
	go func() {
		runtime.drainInboundPortS(context.Background(), conn)
		close(drained)
	}()

	waitForPortSResponse(t, conn, "SIP/2.0 180 Ringing")
	if conn.isClosed() {
		t.Fatal("Port-S connection closed before user rejection")
	}
	if err := calls.reject(486, "Busy Here"); err != nil {
		t.Fatalf("reject half-closed incoming INVITE: %v", err)
	}
	waitForPortSResponse(t, conn, "SIP/2.0 486 Busy Here")
	waitForPortSDrain(t, drained)
	if !conn.isClosed() {
		t.Fatal("Port-S connection remained open after final rejection")
	}
}

func TestPortSHalfClosedInviteTimesOutWithTerminalResponse(t *testing.T) {
	calls := halfClosedIncomingCallRuntime()
	calls.incomingDecisionTimeout = 20 * time.Millisecond
	defer calls.finish("ended", nil)

	conn := newRetainedEOFConn(halfClosedIncomingInvite("half-close-timeout@example.test"))
	runtime := &transportRuntime{
		cfg:         Config{TraceID: "half-close-timeout", DeviceID: "reader-test"},
		incomingSIP: calls.handleRequest,
	}
	runtime.wg.Add(1)
	drained := make(chan struct{})
	go func() {
		runtime.drainInboundPortS(context.Background(), conn)
		close(drained)
	}()

	waitForPortSResponse(t, conn, "SIP/2.0 180 Ringing")
	waitForPortSResponse(t, conn, "SIP/2.0 408 Request Timeout")
	waitForPortSDrain(t, drained)
	if !conn.isClosed() {
		t.Fatal("Port-S connection remained open after decision timeout")
	}
}

func TestPortSHalfClosedInviteShutdownClosesRetainedConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := newRetainedEOFConn(halfClosedIncomingInvite("half-close-shutdown@example.test"))
	runtime := &transportRuntime{
		cfg: Config{TraceID: "half-close-shutdown", DeviceID: "reader-test"},
		incomingSIP: func(request *sip.Request, respond SIPResponder) {
			_ = respond(newIncomingResponse(request, 180, "Ringing", nil))
		},
	}
	runtime.wg.Add(1)
	drained := make(chan struct{})
	go func() {
		runtime.drainInboundPortS(ctx, conn)
		close(drained)
	}()

	waitForPortSResponse(t, conn, "SIP/2.0 180 Ringing")
	cancel()
	waitForPortSDrain(t, drained)
	if !conn.isClosed() {
		t.Fatal("service shutdown did not close retained Port-S connection")
	}
}

func TestPortSIncomingDiagnosticsObserveListenerAcceptAndSIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listener := newQueuedPortSListener()
	called := make(chan struct{}, 1)
	runtime := &transportRuntime{
		cfg: Config{TraceID: "port-s-diagnostics", DeviceID: "reader-test"},
		incomingSIP: func(request *sip.Request, respond SIPResponder) {
			if err := respond(newIncomingResponse(request, 180, "Ringing", nil)); err != nil {
				t.Errorf("respond: %v", err)
			}
			called <- struct{}{}
		},
		failureC: make(chan error, 1),
		cancel:   cancel,
	}
	runtime.wg.Add(1)
	go runtime.runPortSListener(ctx, nil, listener)

	deadline := time.Now().Add(time.Second)
	for !runtime.incomingPortSDiagnostics().listenerStarted {
		if time.Now().After(deadline) {
			t.Fatal("Port-S listener was not marked started")
		}
		time.Sleep(time.Millisecond)
	}

	server, client := net.Pipe()
	defer client.Close()
	listener.accepted <- server
	invite := "INVITE sip:user@ims.example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.20:6060;branch=z9hG4bK-diag\r\n" +
		"From: <sip:caller@example.test>;tag=remote\r\n" +
		"To: <sip:user@ims.example.test>\r\n" +
		"Call-ID: port-s-diag\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(client, invite); err != nil {
		t.Fatalf("write INVITE: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 1024)
	n, err := client.Read(response)
	if err != nil {
		t.Fatalf("read Ringing: %v", err)
	}
	if !strings.Contains(string(response[:n]), "SIP/2.0 180 Ringing") {
		t.Fatalf("unexpected response: %q", response[:n])
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("inbound INVITE did not reach handler")
	}

	diagnostics := runtime.incomingPortSDiagnostics()
	if !diagnostics.listenerStarted {
		t.Fatal("listener_start=false after active Port-S INVITE")
	}
	if diagnostics.acceptCount != 1 {
		t.Fatalf("accept_count=%d, want 1", diagnostics.acceptCount)
	}
	if diagnostics.reachability != "observed" {
		t.Fatalf("reachability=%q, want observed", diagnostics.reachability)
	}
	if diagnostics.lastInboundSIPAt.IsZero() {
		t.Fatal("last inbound SIP time was not recorded")
	}
	if diagnostics.lastResponseWriteError != "" {
		t.Fatalf("unexpected response write error=%q", diagnostics.lastResponseWriteError)
	}

	cancel()
	_ = listener.Close()
	client.Close()
	done := make(chan struct{})
	go func() {
		runtime.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Port-S diagnostics listener did not stop")
	}
	if runtime.incomingPortSDiagnostics().listenerStarted {
		t.Fatal("listener_start remained true after runtime shutdown")
	}
}

func TestPortSResponseWriteDiagnosticsAreSanitized(t *testing.T) {
	rawWriteError := errors.New("write tcp 192.0.2.10:5063->192.0.2.20:6060 for sip:+447700900123 failed")
	invite := "INVITE sip:user@ims.example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 192.0.2.20:6060;branch=z9hG4bK-write\r\n" +
		"From: <sip:caller@example.test>;tag=remote\r\n" +
		"To: <sip:user@ims.example.test>\r\n" +
		"Call-ID: port-s-write\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	conn := &failingPortSWriteConn{
		payloadAndEOFConn: payloadAndEOFConn{payload: []byte(invite)},
		err:               rawWriteError,
	}
	responseErr := make(chan error, 1)
	runtime := &transportRuntime{
		cfg: Config{TraceID: "port-s-write", DeviceID: "reader-test"},
		incomingSIP: func(request *sip.Request, respond SIPResponder) {
			responseErr <- respond(newIncomingResponse(request, 180, "Ringing", nil))
		},
	}
	runtime.wg.Add(1)
	runtime.drainInboundPortS(context.Background(), conn)
	if err := <-responseErr; err == nil {
		t.Fatal("response write unexpectedly succeeded")
	}

	diagnostics := runtime.incomingPortSDiagnostics()
	if diagnostics.lastInboundSIPAt.IsZero() || diagnostics.reachability != "observed" {
		t.Fatalf("inbound observation=%+v, want a timestamp and observed reachability", diagnostics)
	}
	if diagnostics.lastResponseWriteError != "write_failed" {
		t.Fatalf("response write class=%q, want write_failed", diagnostics.lastResponseWriteError)
	}
	if strings.Contains(diagnostics.lastResponseWriteError, "+447700900123") || strings.Contains(diagnostics.lastResponseWriteError, "192.0.2.20") {
		t.Fatalf("diagnostic leaked raw response write error: %q", diagnostics.lastResponseWriteError)
	}
}
