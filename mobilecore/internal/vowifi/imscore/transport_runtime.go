package imscore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"

	"proletarius.local/core/internal/device"
	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/messaging"
	"proletarius.local/core/internal/vowifi/policy"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

type sipWriteTask struct {
	payload []byte
	done    chan error
}

type optionsCheckRequest struct {
	ctx  context.Context
	done chan error
}

const (
	optionsHeartbeatResponseTimeout = 12 * time.Second
	optionsHeartbeatConfirmDelay    = 3 * time.Second
)

// incomingPortSDiagnostics intentionally records transport facts only.  It
// must never retain a SIP message, peer address, URI, caller number, or other
// subscriber data: this snapshot is exposed through the reader status API to
// help distinguish a healthy REGISTER from an unobserved Port-S callback.
//
// reachability has deliberately narrow semantics:
//   - unverified: the listener has not accepted a protected Port-S connection
//   - observed: an inbound Port-S connection reached this runtime
//
// It is not an assertion that the operator can currently route a new call.
// That remains governed by the authenticated transport/runtime health gate.
type incomingPortSDiagnostics struct {
	mu                     sync.RWMutex
	listenerStarted        bool
	acceptCount            uint64
	lastInboundSIPAt       time.Time
	lastResponseWriteError string
	reachability           string
}

type incomingPortSDiagnosticsSnapshot struct {
	listenerStarted        bool
	acceptCount            uint64
	lastInboundSIPAt       time.Time
	lastResponseWriteError string
	reachability           string
}

func (d *incomingPortSDiagnostics) listenerState(started bool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.listenerStarted = started
	if d.reachability == "" {
		d.reachability = "unverified"
	}
	d.mu.Unlock()
}

func (d *incomingPortSDiagnostics) accepted() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.acceptCount++
	d.reachability = "observed"
	d.mu.Unlock()
}

func (d *incomingPortSDiagnostics) inboundSIPObserved(at time.Time) {
	if d == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	d.lastInboundSIPAt = at.UTC()
	d.reachability = "observed"
	d.mu.Unlock()
}

func (d *incomingPortSDiagnostics) responseWriteFailed(err error) {
	if d == nil || err == nil {
		return
	}
	d.mu.Lock()
	d.lastResponseWriteError = incomingResponseWriteErrorClass(err)
	d.mu.Unlock()
}

func (d *incomingPortSDiagnostics) snapshot() incomingPortSDiagnosticsSnapshot {
	if d == nil {
		return incomingPortSDiagnosticsSnapshot{reachability: "unverified"}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	reachability := d.reachability
	if reachability == "" {
		reachability = "unverified"
	}
	return incomingPortSDiagnosticsSnapshot{
		listenerStarted:        d.listenerStarted,
		acceptCount:            d.acceptCount,
		lastInboundSIPAt:       d.lastInboundSIPAt,
		lastResponseWriteError: d.lastResponseWriteError,
		reachability:           reachability,
	}
}

// incomingResponseWriteErrorClass avoids exposing raw net.OpError text in a
// status endpoint.  Raw errors can include transport endpoints and are not
// useful for the caller-facing health decision; these stable classes are.
func incomingResponseWriteErrorClass(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
		return "timeout"
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return "connection_closed"
	}
	return "write_failed"
}

// A Port-S connection belongs to one inbound SIP transaction. A carrier or
// network failure must not be able to leave its response writer blocked
// forever, because the call runtime serializes an initial INVITE response with
// CANCEL/retransmit handling. This is intentionally local to response writes;
// the long-lived Port-C writer keeps its existing lifecycle supervision.
const incomingSIPResponseWriteTimeout = 4 * time.Second

// incomingPortSDeferredResponseTimeout is deliberately longer than the local
// incoming-call decision timer. A Port-S peer is allowed to half-close its
// write side after delivering an INVITE: TCP still permits us to write the
// eventual 200/4xx final response on that connection. Keep that write side
// alive until the INVITE reaches a terminal outcome, but never indefinitely.
const incomingPortSDeferredResponseTimeout = incomingCallDecisionTimeout + 5*time.Second

// portSResponseLease owns the short interval between an inbound INVITE's
// provisional response and its final response. It contains no SIP payload,
// peer identity, or address; it merely prevents drainInboundPortS from
// closing a TCP connection whose remote side has already sent FIN but can
// still receive our later UAS response.
//
// A final response or transport shutdown releases the lease. The Port-S
// draining goroutine enforces the bounded fallback timeout and closes the
// connection afterwards, so an abandoned ring cannot retain a socket.
type portSResponseLease struct {
	mu       sync.Mutex
	pending  bool
	released bool
	done     chan struct{}
}

func newPortSResponseLease() *portSResponseLease {
	return &portSResponseLease{done: make(chan struct{})}
}

func (l *portSResponseLease) observeResponse(response *sip.Response, err error) {
	if l == nil || response == nil {
		return
	}
	if err != nil || response.StatusCode >= 200 {
		l.release()
		return
	}
	if response.StatusCode < 100 {
		return
	}
	l.mu.Lock()
	if !l.released {
		l.pending = true
	}
	l.mu.Unlock()
}

func (l *portSResponseLease) waitForFinal(ctx context.Context, timeout time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	pending, released, done := l.pending, l.released, l.done
	l.mu.Unlock()
	if !pending || released {
		return
	}
	if timeout <= 0 {
		timeout = incomingPortSDeferredResponseTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (l *portSResponseLease) release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return
	}
	l.released = true
	close(l.done)
	l.mu.Unlock()
}

type transportRuntime struct {
	optionsChecks chan optionsCheckRequest
	cfg           Config
	policy        ipsec3gpp.Policy
	transport     *ipsec3gpp.Transport

	portSListener *singleConnListener
	tcpWriteCh    chan sipWriteTask

	portCConn net.Conn

	// inboundSIPCh 保留给旧的响应等待路径；每条 TCP 连接使用独立 parser。
	inboundSIPCh chan []byte
	incomingReq  func(*sip.Request)
	incomingSIP  func(*sip.Request, SIPResponder)
	sendRPAck    func(target string, reference byte)
	portCParser  *sip.ParserStream
	responseMu   sync.Mutex
	responses    map[string]map[uint64]chan *sip.Response
	nextWaiter   uint64

	cancel      context.CancelFunc
	wg          sync.WaitGroup
	close       sync.Once
	healthy     atomic.Bool
	healthMu    sync.Mutex
	failed      bool
	closed      bool
	failureOnce sync.Once
	failureC    chan error

	incomingDiagnostics incomingPortSDiagnostics
}

func startTransportRuntime(parent context.Context, cfg Config, swu voiceclient.SWUTCPDialer, policy ipsec3gpp.Policy, transport *ipsec3gpp.Transport, portCConn net.Conn, preparedPortS ...net.Listener) (*transportRuntime, error) {
	if portCConn == nil || (transport == nil && !cfg.Template.AllowPlainIMS) {
		return nil, fmt.Errorf("imscore: transport runtime requires a Port-C connection and an explicitly allowed security mode")
	}
	if swu == nil {
		return nil, fmt.Errorf("imscore: transport runtime requires SWu dialer")
	}
	if policy.LocalPortS <= 0 {
		return nil, fmt.Errorf("imscore: transport runtime missing port-s")
	}

	ctx, cancel := context.WithCancel(parent)
	rt := &transportRuntime{
		optionsChecks: make(chan optionsCheckRequest, 1),
		cfg:           cfg,
		policy:        policy,
		transport:     transport,
		portCConn:     portCConn,
		tcpWriteCh:    make(chan sipWriteTask, 8),
		inboundSIPCh:  make(chan []byte, 32),
		incomingReq:   cfg.IncomingSIPRequest,
		incomingSIP:   cfg.IncomingSIPHandler,
		sendRPAck:     cfg.IncomingRPAck,
		portCParser:   sip.NewParser().NewSIPStream(),
		responses:     make(map[string]map[uint64]chan *sip.Response),
		cancel:        cancel,
		failureC:      make(chan error, 1),
	}
	rt.healthy.Store(true)
	if endpoint, ok := portCConn.(*udpSIPEndpoint); ok {
		if endpoint.portS == nil {
			cancel()
			return nil, fmt.Errorf("imscore: UDP Port-S was not prepared")
		}
		rt.incomingDiagnostics.listenerState(true)
		rt.wg.Add(2)
		go rt.runUDPReadLoop(ctx, endpoint, false)
		go rt.runUDPReadLoop(ctx, endpoint.portS, true)
		if cfg.OptionsPingIntervalSeconds > 0 {
			rt.wg.Add(1)
			go rt.runOptionsPing(ctx)
		}
		return rt, nil
	}
	rt.portSListener = newSingleConnListener(&net.TCPAddr{
		IP:   cfg.LocalIP,
		Port: policy.LocalPortS,
	})

	rt.wg.Add(1)
	go rt.runTCPWriteChannel(ctx)

	rt.wg.Add(1)
	go rt.runPortCReadLoop(ctx)

	rt.wg.Add(1)
	var listener net.Listener
	if len(preparedPortS) > 0 {
		listener = preparedPortS[0]
	}
	go rt.runPortSListener(ctx, swu, listener)

	if cfg.OptionsPingIntervalSeconds > 0 {
		rt.wg.Add(1)
		go rt.runOptionsPing(ctx)
	}

	logger.Info("IMS transport runtime started",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.Int("port_c", policy.LocalPortC),
		logger.Int("port_s", policy.LocalPortS),
		logger.String("registrar", cfg.PCSCFAddr),
		logger.String("transport_target", effectiveTransportAddr(cfg)))
	return rt, nil
}

func (rt *transportRuntime) Close() {
	if rt == nil {
		return
	}
	rt.close.Do(func() {
		rt.healthMu.Lock()
		rt.closed = true
		rt.healthy.Store(false)
		rt.healthMu.Unlock()
		if rt.cancel != nil {
			rt.cancel()
		}
		if rt.portSListener != nil {
			_ = rt.portSListener.Close()
		}
		if rt.portCConn != nil {
			_ = rt.portCConn.Close()
		}
		// The read worker may still be parsing bytes returned together with
		// EOF, or running a synchronous SIP callback. Parser.Close resets and
		// pools its buffer, so release it only after that worker has exited.
		rt.wg.Wait()
		if rt.portCParser != nil {
			rt.portCParser.Close()
			rt.portCParser = nil
		}
	})
}

func (rt *transportRuntime) Healthy() bool {
	return rt != nil && rt.healthy.Load()
}

func (rt *transportRuntime) Failure() <-chan error {
	if rt == nil {
		return nil
	}
	return rt.failureC
}

func (rt *transportRuntime) incomingPortSDiagnostics() incomingPortSDiagnosticsSnapshot {
	if rt == nil {
		return incomingPortSDiagnosticsSnapshot{reachability: "unverified"}
	}
	return rt.incomingDiagnostics.snapshot()
}

// fail marks the authenticated SIP transport unusable exactly once. A normal
// Close does not use this path: callers only receive failures that require the
// VoWiFi supervisor to withdraw readiness and establish a fresh IKE/IMS stack.
func (rt *transportRuntime) fail(err error) {
	if rt == nil || err == nil {
		return
	}
	rt.failureOnce.Do(func() {
		rt.healthMu.Lock()
		if rt.closed {
			rt.healthMu.Unlock()
			return
		}
		rt.failed = true
		rt.healthy.Store(false)
		rt.healthMu.Unlock()
		select {
		case rt.failureC <- err:
		default:
		}
		if rt.cancel != nil {
			rt.cancel()
		}
	})
}

func (rt *transportRuntime) markDegraded() {
	if rt == nil {
		return
	}
	rt.healthMu.Lock()
	if !rt.failed && !rt.closed {
		rt.healthy.Store(false)
	}
	rt.healthMu.Unlock()
}

func (rt *transportRuntime) markHealthy(ctx context.Context) {
	if rt == nil || ctx == nil || ctx.Err() != nil {
		return
	}
	rt.healthMu.Lock()
	if !rt.failed && !rt.closed && ctx.Err() == nil {
		rt.healthy.Store(true)
	}
	rt.healthMu.Unlock()
}

func (rt *transportRuntime) runTCPWriteChannel(ctx context.Context) {
	defer rt.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-rt.tcpWriteCh:
			_, err := rt.portCConn.Write(task.payload)
			if task.done != nil {
				task.done <- err
				close(task.done)
			}
			if err != nil {
				logger.Warn("IMS port-c write failed",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
				rt.fail(fmt.Errorf("IMS secure transport write failed: %w", err))
				return
			}
		}
	}
}

func (rt *transportRuntime) enqueueWrite(ctx context.Context, payload []byte) error {
	if rt != nil {
		if endpoint, ok := rt.portCConn.(*udpSIPEndpoint); ok {
			message, err := sip.NewParser().ParseSIP(payload)
			if err != nil {
				return err
			}
			if request, ok := message.(*sip.Request); ok {
				// Call commands return after enqueueing; their short operation
				// contexts end before the SIP transaction does. Keep retransmits
				// tied to the owned socket lifecycle for asynchronous call methods.
				switch request.Method {
				case sip.INVITE, sip.CANCEL, sip.BYE, sip.PRACK, sip.UPDATE:
					if ctx != nil && ctx.Err() != nil {
						return ctx.Err()
					}
					return endpoint.sendRequest(endpoint.ctx, request)
				}
				return endpoint.sendRequest(ctx, request)
			}
			return endpoint.WriteMsg(message)
		}
	}
	if rt == nil || rt.tcpWriteCh == nil {
		return fmt.Errorf("imscore: tcp write channel unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan error, 1)
	task := sipWriteTask{payload: append([]byte(nil), payload...), done: done}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case rt.tcpWriteCh <- task:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (rt *transportRuntime) runPortCReadLoop(ctx context.Context) {
	defer rt.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		n, err := rt.portCConn.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			sipTraceLogger{traceID: rt.cfg.TraceID, deviceID: rt.cfg.DeviceID}.
				SIPTraceRead("tcp", connLocalAddrString(rt.portCConn), connRemoteAddrString(rt.portCConn), data)
			rt.deliverInboundSIP(rt.portCConn, data, rt.portCParser)
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if err != io.EOF && !isTimeoutError(err) {
					logger.Warn("IMS port-c read ended",
						logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
						logger.String("error", err.Error()))
				}
				rt.fail(fmt.Errorf("IMS secure transport read ended: %w", err))
				return
			}
		}
	}
}

func (rt *transportRuntime) runOptionsPing(ctx context.Context) {
	defer rt.wg.Done()
	interval := time.Duration(rt.cfg.OptionsPingIntervalSeconds) * time.Second
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	cseq := nextRegisterTransportAttemptCSeq(0)
	for {
		var requested *optionsCheckRequest
		select {
		case <-ctx.Done():
			return
		case request := <-rt.optionsChecks:
			requested = &request
		case <-ticker.C:
		}
		probeCtx := ctx
		if requested != nil {
			probeCtx = requested.ctx
			if probeCtx.Err() != nil {
				requested.done <- probeCtx.Err()
				continue
			}
		}
		status, err := confirmOptionsHeartbeat(probeCtx, optionsHeartbeatConfirmDelay,
			func() (int, error) { return rt.sendOptionsPing(probeCtx, cseq) },
			func() {
				rt.markDegraded()
				logger.Warn("IMS OPTIONS heartbeat missed; readiness withdrawn while confirming",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("retry_in", optionsHeartbeatConfirmDelay.String()))
			},
			func() {
				rt.markHealthy(ctx)
				logger.Info("IMS OPTIONS heartbeat recovered after one missed probe",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)))
			},
		)
		if ctx.Err() != nil {
			return
		}
		if requested != nil {
			// The engine owns recovery for an explicit check, including
			// preserving an established call until hangup on probe failure.
			requested.done <- err
			if err != nil {
				// Recovery now belongs to the engine. Do not let a later
				// periodic miss tear down a call it is preserving.
				return
			}
			cseq++
			ticker.Reset(interval)
			continue
		}
		if err != nil {
			logger.Warn("IMS OPTIONS heartbeat failed",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("error", err.Error()))
			rt.fail(err)
			return
		}
		logger.Info("IMS OPTIONS heartbeat acknowledged",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.Int("status", status))
		cseq++
	}
}

// checkConnection joins the existing heartbeat worker, so foreground checks
// never race a second OPTIONS transaction against the periodic heartbeat.
func (rt *transportRuntime) checkConnection(ctx context.Context) error {
	request := optionsCheckRequest{ctx: ctx, done: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case rt.optionsChecks <- request:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-request.done:
		return err
	}
}

func (rt *transportRuntime) sendOptionsPing(ctx context.Context, cseq uint32) (int, error) {
	callID := uuid.NewString()
	payload, err := buildOptionsPing(rt.cfg, rt.policy, callID, cseq)
	if err != nil {
		return 0, fmt.Errorf("IMS OPTIONS build failed: %w", err)
	}
	responses, unsubscribe, err := rt.subscribeResponses(callID)
	if err != nil {
		return 0, err
	}
	defer unsubscribe()
	if err := rt.enqueueWrite(ctx, payload); err != nil {
		return 0, fmt.Errorf("IMS OPTIONS write failed: %w", err)
	}
	logger.Info("IMS OPTIONS ping sent",
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.Int("cseq", int(cseq)))
	return awaitOptionsFinalResponse(ctx, responses, optionsHeartbeatResponseTimeout)
}

// confirmOptionsHeartbeat withdraws readiness immediately after a missed
// authenticated probe, then verifies the same protected flow once more before
// the supervisor tears down the whole IKE/IMS session. A brief packet loss
// therefore blocks new SMS/call work but does not cause needless tunnel
// churn; a second failure remains a hard transport failure.
func confirmOptionsHeartbeat(
	ctx context.Context,
	retryDelay time.Duration,
	probe func() (int, error),
	onMiss func(),
	onRecovery func(),
) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if probe == nil {
		return 0, fmt.Errorf("IMS OPTIONS probe is unavailable")
	}
	status, firstErr := probe()
	if firstErr == nil || ctx.Err() != nil {
		return status, firstErr
	}
	if onMiss != nil {
		onMiss()
	}
	if retryDelay > 0 {
		timer := time.NewTimer(retryDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
	status, retryErr := probe()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if retryErr != nil {
		return 0, fmt.Errorf("first probe: %v; confirmation probe: %w", firstErr, retryErr)
	}
	if onRecovery != nil {
		onRecovery()
	}
	return status, nil
}

// A provisional SIP response proves only that the request was received. It
// must not keep IMS marked healthy if the final OPTIONS response never arrives.
func awaitOptionsFinalResponse(ctx context.Context, responses <-chan *sip.Response, wait time.Duration) (int, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case response, ok := <-responses:
			if !ok {
				return 0, fmt.Errorf("IMS OPTIONS response stream closed")
			}
			if response != nil && response.StatusCode >= 200 {
				// A final response proves the TCP connection delivered a packet,
				// but only a 2xx response proves that the registered P-CSCF flow
				// is still usable.  Treating a 4xx/5xx OPTIONS response as
				// healthy leaves the UI advertising SMS/calls after the registrar
				// has rejected or withdrawn the binding.
				if response.StatusCode < 300 {
					return response.StatusCode, nil
				}
				return response.StatusCode, fmt.Errorf("IMS OPTIONS heartbeat rejected: SIP %d", response.StatusCode)
			}
		case <-timer.C:
			return 0, fmt.Errorf("IMS OPTIONS heartbeat timed out after %s", wait)
		}
	}
}

func buildOptionsPing(cfg Config, transportPolicy ipsec3gpp.Policy, callID string, cseq uint32) ([]byte, error) {
	// OPTIONS is a transport liveness probe for the already selected P-CSCF,
	// not a new request for the home registrar.  Some EE/CTExcel P-CSCFs do not
	// resolve the 3GPP home-domain R-URI on this protected hop and answer 502
	// forever.  Address the confirmed protected service route directly so a
	// successful response actually proves the active IPsec/TCP binding.
	target := strings.TrimSpace(effectiveRouteAddr(cfg))
	if target == "" {
		return nil, fmt.Errorf("imscore: P-CSCF route is required for OPTIONS")
	}
	recipient := sip.Uri{}
	if err := sip.ParseUri("sip:"+target, &recipient); err != nil {
		return nil, fmt.Errorf("imscore: parse OPTIONS target: %w", err)
	}
	localPort := transportPolicy.LocalPortC
	if localPort <= 0 {
		localPort = registerSIPLocalPort(cfg)
	}
	if cseq == 0 {
		cseq = 1
	}
	if strings.TrimSpace(callID) == "" {
		callID = uuid.NewString()
	}

	req := sip.NewRequest(sip.OPTIONS, recipient)
	req.AppendHeader(sip.NewHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(registerTransportName(cfg, "")), formatRegisterViaHost(cfg.LocalIP, localPort), sip.GenerateBranchN(16))))
	req.AppendHeader(sip.NewHeader("From", "<"+cfg.PublicURI+">;tag="+sip.GenerateTagN(16)))
	req.AppendHeader(sip.NewHeader("To", "<sip:"+target+">"))
	req.AppendHeader(sip.NewHeader("Call-ID", callID))
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d OPTIONS", cseq)))
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	req.AppendHeader(sip.NewHeader("Route", "<sip:"+effectiveRouteAddr(cfg)+";lr>"))
	if strings.TrimSpace(cfg.PublicURI) != "" {
		req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+cfg.PublicURI+">"))
	}
	if strings.TrimSpace(cfg.UserAgent) != "" {
		req.AppendHeader(sip.NewHeader("User-Agent", cfg.UserAgent))
	}
	if verify := strings.TrimSpace(cfg.SecurityVerify); verify != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", verify))
	}
	req.SetDestination(effectiveTransportAddr(cfg))
	req.SetTransport(strings.ToUpper(registerTransportName(cfg, "")))
	ensureSIPStreamFraming(req)
	return []byte(req.String()), nil
}

func (rt *transportRuntime) runPortSListener(ctx context.Context, swu voiceclient.SWUTCPDialer, listener net.Listener) {
	defer rt.wg.Done()
	if listener == nil {
		var err error
		listener, err = swu.ListenContextTCP(ctx, rt.cfg.LocalIP, rt.policy.LocalPortS)
		if err != nil {
			logger.Warn("IMS port-s listen failed",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.Int("port_s", rt.policy.LocalPortS),
				logger.String("error", err.Error()))
			rt.fail(fmt.Errorf("IMS incoming SIP listener failed: %w", err))
			return
		}
	}
	defer listener.Close()
	// "started" means this runtime owns an active Accept loop, rather than
	// merely that a socket was pre-bound during REGISTER preparation.
	rt.incomingDiagnostics.listenerState(true)
	defer rt.incomingDiagnostics.listenerState(false)
	listenerDone := make(chan struct{})
	defer close(listenerDone)
	go func() {
		select {
		case <-ctx.Done():
			// Accept is not context-aware on net.Listener. Closing the listener
			// is required so Service.Close cannot deadlock while no port-s push
			// connection is pending.
			_ = listener.Close()
		case <-listenerDone:
		}
	}()

	logger.Info(fmt.Sprintf("[%s] 准备启动 IMS TCP 入站监听", strings.TrimSpace(rt.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.Int("port", rt.policy.LocalPortS))

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Warn("IMS port-s accept failed",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
				rt.fail(fmt.Errorf("IMS incoming SIP listener ended: %w", err))
				return
			}
		}
		rt.incomingDiagnostics.accepted()
		logger.Info("IMS port-s accepted inbound push",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("remote", rawConn.RemoteAddr().String()),
			logger.String("local", rawConn.LocalAddr().String()))
		rt.wg.Add(1)
		go rt.drainInboundPortS(ctx, rawConn)
	}
}

func (rt *transportRuntime) drainInboundPortS(ctx context.Context, conn net.Conn) {
	defer rt.wg.Done()
	defer conn.Close()
	// Accepted connections outlive the listening socket. Wake both Read and
	// response Write on cancellation before Close waits for this worker; the
	// userspace network itself cannot close until the runtime has drained.
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	lease := newPortSResponseLease()
	defer lease.release()
	parser := sip.NewParser().NewSIPStream()
	defer parser.Close()
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := conn.Read(buf)
		// A Reader may legally return payload bytes together with io.EOF. Process
		// those bytes before closing the push connection; otherwise a carrier
		// that sends one final INVITE/MESSAGE and immediately half-closes can be
		// acknowledged at TCP level yet disappear before reaching Call/SMS.
		if n > 0 {
			installSIPTrace(rt.cfg.TraceID, rt.cfg.DeviceID)
			data := make([]byte, n)
			copy(data, buf[:n])
			sipTraceLogger{traceID: rt.cfg.TraceID, deviceID: rt.cfg.DeviceID}.
				SIPTraceRead("tcp", conn.LocalAddr().String(), conn.RemoteAddr().String(), data)
			// 将入站 SIP 消息上交 SIP 栈处理，而非丢弃（IMSCORE-3 修复）
			rt.deliverInboundPortSSIP(conn, data, lease, parser)
		}
		if err != nil {
			if err == io.EOF {
				// A TCP EOF only means the carrier has half-closed its write side.
				// If we already sent a provisional INVITE response, preserve the
				// local write side until answer/reject/CANCEL, lifecycle shutdown,
				// or the bounded decision timeout releases it.
				lease.waitForFinal(ctx, incomingPortSDeferredResponseTimeout)
			}
			if err != io.EOF {
				logger.Warn("IMS port-s read ended",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
			}
			return
		}
		if n == 0 {
			continue
		}
	}
}

// deliverInboundSIP 按来源连接解析 SIP，并将 UAS 响应写回同一连接。
func (rt *transportRuntime) deliverInboundSIP(conn net.Conn, data []byte, parsers ...*sip.ParserStream) {
	rt.deliverInboundSIPFrom(conn, data, false, nil, parsers...)
}

// deliverInboundPortSSIP keeps Port-S reachability diagnostics separate from
// port-c REGISTER/MESSAGE responses. Both paths share parser semantics, but
// only this path is evidence that the advertised inbound contact was reached.
func (rt *transportRuntime) deliverInboundPortSSIP(conn net.Conn, data []byte, lease *portSResponseLease, parsers ...*sip.ParserStream) {
	rt.deliverInboundSIPFrom(conn, data, true, lease, parsers...)
}

func (rt *transportRuntime) deliverInboundSIPFrom(conn net.Conn, data []byte, fromPortS bool, lease *portSResponseLease, parsers ...*sip.ParserStream) {
	var parser *sip.ParserStream
	if len(parsers) > 0 {
		parser = parsers[0]
	}
	if parser == nil {
		parser = sip.NewParser().NewSIPStream()
		defer parser.Close()
	}
	err := parser.ParseSIPStream(data, func(msg sip.Message) {
		if fromPortS {
			rt.incomingDiagnostics.inboundSIPObserved(time.Now())
		}
		if req, ok := msg.(*sip.Request); ok {
			rt.dispatchIncomingRequest(conn, req, fromPortS, lease)
			return
		}
		if res, ok := msg.(*sip.Response); ok {
			rt.publishResponse(res)
			rt.enqueueParsedResponse([]byte(res.String()))
		}
	})
	// ParserStream buffers an incomplete TCP frame and finishes it after the
	// next read. Fragmentation is therefore expected transport behaviour, not
	// an IMS failure worth surfacing to the user or diagnostics timeline.
	if err != nil && !errors.Is(err, sip.ErrParseSipPartial) {
		logger.Warn("IMS SIP stream parse failed",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("error", err.Error()))
	}
}

func sipResponseCallID(message *sip.Response) string {
	if message == nil {
		return ""
	}
	header := message.GetHeader("Call-ID")
	if header == nil {
		return ""
	}
	return strings.TrimSpace(header.Value())
}

func (rt *transportRuntime) subscribeResponses(callID string) (<-chan *sip.Response, func(), error) {
	callID = strings.TrimSpace(callID)
	if rt == nil || callID == "" {
		return nil, nil, fmt.Errorf("imscore: response subscription requires Call-ID")
	}
	rt.responseMu.Lock()
	rt.nextWaiter++
	id := rt.nextWaiter
	ch := make(chan *sip.Response, 16)
	if rt.responses[callID] == nil {
		rt.responses[callID] = make(map[uint64]chan *sip.Response)
	}
	rt.responses[callID][id] = ch
	rt.responseMu.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			rt.responseMu.Lock()
			if waiters := rt.responses[callID]; waiters != nil {
				delete(waiters, id)
				if len(waiters) == 0 {
					delete(rt.responses, callID)
				}
			}
			rt.responseMu.Unlock()
		})
	}
	return ch, cancel, nil
}

func (rt *transportRuntime) publishResponse(response *sip.Response) {
	callID := sipResponseCallID(response)
	if callID == "" {
		return
	}
	rt.responseMu.Lock()
	waiters := make([]chan *sip.Response, 0, len(rt.responses[callID]))
	for _, waiter := range rt.responses[callID] {
		waiters = append(waiters, waiter)
	}
	rt.responseMu.Unlock()
	for _, waiter := range waiters {
		select {
		case waiter <- response:
		default:
			logger.Warn("IMS SIP response subscriber overflow",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("call_id", callID))
		}
	}
}

func (rt *transportRuntime) dispatchIncomingRequest(conn net.Conn, req *sip.Request, fromPortS bool, lease *portSResponseLease) {
	if req == nil {
		return
	}
	deferFinalResponse := fromPortS && strings.EqualFold(string(req.Method), "INVITE")
	respond := func(response *sip.Response) error {
		if response == nil {
			return fmt.Errorf("imscore: nil SIP response")
		}
		err := rt.writeToConn(conn, []byte(response.String()), fromPortS)
		if deferFinalResponse {
			lease.observeResponse(response, err)
		}
		return err
	}
	rt.dispatchIncomingRequestWithResponder(req, respond)
}

func (rt *transportRuntime) dispatchIncomingRequestWithResponder(req *sip.Request, respond SIPResponder) {
	respondStatus := func(code int, reason string) {
		if err := respond(sip.NewResponseFromRequest(req, code, reason, nil)); err != nil {
			logger.Warn("IMS SIP request response failed",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("method", string(req.Method)),
				logger.String("error", err.Error()))
		}
	}

	switch strings.ToUpper(string(req.Method)) {
	case "MESSAGE":
		// MESSAGE is acknowledged before decoding so a slow SIM/SMS callback
		// cannot trigger network retransmissions.
		respondStatus(200, "OK")
		rt.handleIncomingRequest(req)
	case "OPTIONS":
		respondStatus(200, "OK")
		if rt.incomingReq != nil {
			rt.incomingReq(req)
		}
	case "ACK":
		// ACK never receives a SIP response.
		if rt.incomingSIP != nil {
			rt.incomingSIP(req, respond)
		}
	case "INVITE", "PRACK", "UPDATE", "CANCEL", "BYE", "INFO":
		if rt.incomingSIP != nil {
			rt.incomingSIP(req, respond)
			return
		}
		if strings.EqualFold(string(req.Method), "INVITE") {
			respondStatus(480, "Temporarily Unavailable")
		} else {
			respondStatus(481, "Call/Transaction Does Not Exist")
		}
	default:
		response := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
		response.AppendHeader(sip.NewHeader("Allow", policy.DefaultRegisterAllow))
		if err := respond(response); err != nil {
			logger.Warn("IMS unsupported SIP method response failed",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("error", err.Error()))
		}
	}
}

func (rt *transportRuntime) handleIncomingRequest(req *sip.Request) {
	if rt.incomingReq != nil {
		rt.incomingReq(req)
	}
	if req == nil || req.Method != sip.MESSAGE || (rt.cfg.IncomingSMS == nil && rt.cfg.IncomingSMSMessage == nil) {
		return
	}
	contentType := req.GetHeader("Content-Type")
	if contentType == nil || !strings.EqualFold(strings.TrimSpace(contentType.Value()), imsSMSContentType) {
		return
	}
	decode := rt.cfg.DecodeIncomingRPDU
	if decode == nil {
		decode = messaging.ParseRPMTData
	}
	reference, originator, tpdu, err := decode(req.Body())
	if err != nil {
		logger.Warn("IMS inbound SMS RP-MT-DATA parse failed",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("error", err.Error()))
		return
	}
	var sender, content string
	var incoming InboundSMS
	at := time.Now()
	nativeHandled := false
	if native := rt.cfg.DecodeIncomingSMS; native != nil && len(tpdu) > 0 && (tpdu[0]&0x03 == 0 || tpdu[0]&0x03 == 2) {
		decoded, handled, decodeErr := native(tpdu)
		if decodeErr != nil {
			logger.Warn("IMS inbound SMS native decode failed",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("error", decodeErr.Error()))
			return
		}
		if handled {
			incoming = decoded
			nativeHandled = true
			if decoded.StatusReport {
				if rt.sendRPAck != nil {
					if target := sipMessagePeer(req); target != "" {
						rt.sendRPAck(target, reference)
					}
				}
				logger.Info("IMS inbound SMS status report decoded natively",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("delivery_status", decoded.DeliveryStatus))
				return
			}
			sender, content = strings.TrimSpace(decoded.Sender), decoded.Content
			if decoded.HasTimestamp {
				at = decoded.Timestamp
			}
		}
	}
	if !nativeHandled {
		message, decodeErr := device.DecodeSMSDeliverTPDU(tpdu)
		if decodeErr != nil {
			logger.Warn("IMS inbound SMS TPDU decode failed",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("error", decodeErr.Error()))
			return
		}
		if message.Direction == device.SMSDirectionStatusReport {
			acknowledge := func() {
				if rt.sendRPAck != nil {
					if target := sipMessagePeer(req); target != "" {
						rt.sendRPAck(target, reference)
					}
				}
			}
			acknowledge()
			logger.Info("IMS inbound SMS status report ignored for message archive",
				logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
				logger.String("originator", originator),
				logger.String("delivery_status", message.DeliveryStatus))
			return
		}
		sender, content = strings.TrimSpace(message.From), message.Text
		if message.Concat != nil {
			if message.ServiceCenterTimestamp == nil {
				logger.Warn("IMS multipart SMS has invalid service-centre timestamp; RP-ACK withheld")
				return
			}
			incoming.ConcatReference = message.Concat.Reference
			incoming.ConcatTotal = message.Concat.Total
			incoming.ConcatSequence = message.Concat.Sequence
		}
		if message.ServiceCenterTimestamp != nil {
			at = *message.ServiceCenterTimestamp
		}
	}
	logger.Info("IMS inbound SMS decoded",
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.Int("tpdu_length", len(tpdu)))
	acknowledge := func() {
		if rt.sendRPAck == nil {
			return
		}
		if target := sipMessagePeer(req); target != "" {
			rt.sendRPAck(target, reference)
		}
	}
	if sender == "" {
		sender = originator
	}
	incoming.Sender, incoming.Content, incoming.Timestamp = sender, content, at
	incoming.HasTimestamp = true
	var storeErr error
	if rt.cfg.IncomingSMSMessage != nil {
		storeErr = rt.cfg.IncomingSMSMessage(incoming)
	} else {
		storeErr = rt.cfg.IncomingSMS(sender, content, at)
	}
	if storeErr != nil {
		logger.Warn("IMS inbound SMS persistence failed; RP-ACK withheld",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)))
		return
	}
	acknowledge()
}

func sipMessagePeer(req *sip.Request) string {
	if req == nil {
		return ""
	}
	header := req.GetHeader("From")
	if header == nil {
		return ""
	}
	value := strings.TrimSpace(header.Value())
	if start := strings.IndexByte(value, '<'); start >= 0 {
		value = value[start+1:]
		if end := strings.IndexByte(value, '>'); end >= 0 {
			value = value[:end]
		}
	} else if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return strings.TrimSpace(value)
}

func (rt *transportRuntime) writeToConn(conn net.Conn, payload []byte, recordPortSFailure bool) error {
	if conn == nil {
		err := fmt.Errorf("imscore: SIP response connection unavailable")
		if recordPortSFailure {
			rt.incomingDiagnostics.responseWriteFailed(err)
		}
		return err
	}
	sipTraceLogger{traceID: rt.cfg.TraceID, deviceID: rt.cfg.DeviceID}.
		SIPTraceWrite("tcp", connLocalAddrString(conn), connRemoteAddrString(conn), payload)
	if err := conn.SetWriteDeadline(time.Now().Add(incomingSIPResponseWriteTimeout)); err != nil {
		if recordPortSFailure {
			rt.incomingDiagnostics.responseWriteFailed(err)
		}
		return fmt.Errorf("imscore: set SIP response write deadline: %w", err)
	}
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	_, err := conn.Write(payload)
	if err != nil && recordPortSFailure {
		rt.incomingDiagnostics.responseWriteFailed(err)
	}
	return err
}

func (rt *transportRuntime) enqueueParsedResponse(data []byte) {
	select {
	case rt.inboundSIPCh <- data:
	default:
		// channel 满，丢弃最旧的消息
		select {
		case <-rt.inboundSIPCh:
		default:
		}
		select {
		case rt.inboundSIPCh <- data:
		default:
		}
		logger.Warn("IMS port-s inbound SIP channel full, dropping old message",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)))
	}
}

// InboundSIPChannel 返回入站 SIP 消息 channel（供上层消费）。
func (rt *transportRuntime) InboundSIPChannel() <-chan []byte {
	return rt.inboundSIPCh
}
