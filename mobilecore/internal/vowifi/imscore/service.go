package imscore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"proletarius.local/core/internal/vowifi/messaging"
	"proletarius.local/core/internal/vowifi/policy"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

// Service is the RE-recovered imscore IMS messaging surface.
type Service struct {
	imsCfg IMSConfig
	cfg    Config

	// stateMu protects the lifecycle state exposed by Status and the readiness
	// predicates.  A successful SIP REGISTER is not sufficient to advertise a
	// usable IMS service: the authenticated transport runtime must still be
	// alive as well.  Keep those values in one snapshot so a concurrent runtime
	// failure cannot produce a mixed "registered and ready" status.
	stateMu sync.RWMutex
	// operationMu pins the service-owned runtime pointers while an IMS operation
	// is using them. Close first marks the service closing and cancels its
	// lifecycle, then waits for outstanding readers before detaching those
	// pointers under stateMu. This keeps lower-level SMS/call/fax code from
	// observing a nil lifecycle context or transport midway through an operation.
	operationMu sync.RWMutex
	// closeMu serializes Close with the small state-publication portion of Start.
	// It is never held while an operation runs.
	closeMu              sync.Mutex
	refreshMu            sync.Mutex
	registerRequest      *sip.Request
	registrationRecovery chan struct{}
	inviteRecoveryUsed   bool

	lifecycleID uint64
	starting    bool
	closing     bool
	// startDone is published with lifecycleCtx before the slow REGISTER flow
	// begins. Close cancels that context and waits for this channel before
	// detaching lifecycle-owned fields, so a Start that began before Close
	// cannot republish a runtime afterward.
	startDone chan struct{}

	registered       bool
	expiresSeconds   int
	verifyHeader     string
	registeredMSISDN string
	sipSecurityMode  string
	ipsecInstalled   bool
	pcscf            string
	localAddr        string
	started          bool

	network          IMSNetwork
	transportRuntime *transportRuntime
	swu              voiceclient.SWUTCPDialer

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	inner       *voiceclient.Client
	messageMu   sync.Mutex
	messageCSeq uint32
	calls       *callRuntime
	fax         *faxRuntime
}

type serviceStateSnapshot struct {
	registered       bool
	expiresSeconds   int
	verifyHeader     string
	registeredMSISDN string
	sipSecurityMode  string
	ipsecInstalled   bool
	plainIMS         bool
	pcscf            string
	localAddr        string
	started          bool
	closing          bool
	transportRuntime *transportRuntime
}

type serviceOperation struct {
	lifecycleCtx context.Context
	runtime      *transportRuntime
	calls        *callRuntime
	fax          *faxRuntime
	inner        *voiceclient.Client
	registered   bool
	ipsec        bool
	plainIMS     bool
	started      bool
	closing      bool
}

func (s *Service) stateSnapshot() serviceStateSnapshot {
	if s == nil {
		return serviceStateSnapshot{}
	}
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.closing {
		return serviceStateSnapshot{}
	}
	return serviceStateSnapshot{
		registered:       s.registered,
		expiresSeconds:   s.expiresSeconds,
		verifyHeader:     s.verifyHeader,
		registeredMSISDN: s.registeredMSISDN,
		sipSecurityMode:  s.sipSecurityMode,
		ipsecInstalled:   s.ipsecInstalled,
		plainIMS:         s.sipSecurityMode == "swu_tunnel_only",
		pcscf:            s.pcscf,
		localAddr:        s.localAddr,
		started:          s.started,
		closing:          s.closing,
		transportRuntime: s.transportRuntime,
	}
}

func (s *Service) runtimeSnapshot() *transportRuntime {
	if s == nil {
		return nil
	}
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.closing {
		return nil
	}
	return s.transportRuntime
}

// acquireLifecycleLease pins pointers that lower-level IMS code reads directly
// (lifecycleCtx, transportRuntime, calls and fax) until release is called.
// Close marks closing before waiting for this lock, so no new operation may be
// admitted once teardown has started.
func (s *Service) acquireLifecycleLease() (serviceOperation, func(), bool) {
	if s == nil {
		return serviceOperation{}, nil, false
	}
	s.operationMu.RLock()
	s.stateMu.RLock()
	op := serviceOperation{
		lifecycleCtx: s.lifecycleCtx,
		runtime:      s.transportRuntime,
		calls:        s.calls,
		fax:          s.fax,
		inner:        s.inner,
		registered:   s.registered,
		ipsec:        s.ipsecInstalled,
		plainIMS:     s.sipSecurityMode == "swu_tunnel_only",
		started:      s.started,
		closing:      s.closing,
	}
	s.stateMu.RUnlock()
	if op.closing || !op.started {
		s.operationMu.RUnlock()
		return serviceOperation{}, nil, false
	}
	return op, s.operationMu.RUnlock, true
}

func (s *Service) acquireOperation(requireReady bool) (serviceOperation, func(), bool) {
	op, release, ok := s.acquireLifecycleLease()
	if !ok {
		return serviceOperation{}, nil, false
	}
	ready := op.started && op.registered && (op.ipsec || op.plainIMS) && op.runtime != nil && op.runtime.Healthy()
	if !op.started || (requireReady && !ready) {
		release()
		return serviceOperation{}, nil, false
	}
	return op, release, true
}

// Delayed runtime callbacks belong to the lifecycle that created them. Pin
// pointers first, then verify that generation and its context before admitting
// work; Close cannot detach the pointers while this lease is held.
func (s *Service) acquireRuntimeLease(ctx context.Context, lifecycleID uint64) (serviceOperation, func(), bool) {
	op, release, ok := s.acquireLifecycleLease()
	if !ok {
		return serviceOperation{}, nil, false
	}
	if !s.lifecycleCurrent(ctx, lifecycleID) {
		release()
		return serviceOperation{}, nil, false
	}
	return op, release, true
}

func (op serviceOperation) context(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if op.lifecycleCtx == nil {
		return ctx, func() {}
	}
	operationCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(op.lifecycleCtx, cancel)
	return operationCtx, func() {
		stop()
		cancel()
	}
}

// Dial is a compatibility wrapper around StartSessionIMSCore for legacy callers.
func Dial(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.AKA == nil {
		return nil, fmt.Errorf("imscore: Config.AKA is required")
	}
	if cfg.LocalIP == nil {
		return nil, fmt.Errorf("imscore: Config.LocalIP is required")
	}
	if strings.TrimSpace(cfg.PCSCFAddr) == "" {
		return nil, fmt.Errorf("imscore: Config.PCSCFAddr is required")
	}
	if strings.TrimSpace(cfg.PrivateID) == "" || strings.TrimSpace(cfg.PublicURI) == "" {
		return nil, fmt.Errorf("imscore: IMS identity is required")
	}

	voiceCfg := voiceclient.Config{
		DeviceID:            cfg.DeviceID,
		TraceID:             cfg.TraceID,
		LocalIP:             cfg.LocalIP,
		Dataplane:           cfg.Dataplane,
		PCSCFAddr:           cfg.PCSCFAddr,
		RegistrarCandidates: cfg.RegistrarCandidates,
		Realm:               cfg.Realm,
		PrivateID:           cfg.PrivateID,
		PublicURI:           cfg.PublicURI,
		HomeDomain:          cfg.HomeDomain,
		IMSI:                cfg.IMSI,
		MCC:                 cfg.MCC,
		MNC:                 cfg.MNC,
		CellID:              cfg.CellID,
		AKA:                 cfg.AKA,
		DeliveryStore:       cfg.DeliveryStore,
		SIPInstanceURN:      cfg.SIPInstanceURN,
		LocalPort:           cfg.LocalPort,
		Transport:           cfg.Transport,
		RegisterProfile:     voiceclient.RegisterProfile{UserAgent: cfg.UserAgent},
	}
	if cfg.RegisterExpirySeconds > 0 {
		voiceCfg.RegisterExpiry = time.Duration(cfg.RegisterExpirySeconds) * time.Second
	}

	network, err := NewUserspaceIMSNetwork(cfg.LocalIP, cfg.Dataplane)
	if err != nil {
		return nil, err
	}
	imsCfg := IMSConfigFromVoice(voiceCfg, cfg.Template, "")
	imsCfg.TCPKeepaliveSeconds = cfg.TCPKeepaliveSeconds
	imsCfg.OptionsPingIntervalSeconds = cfg.OptionsPingIntervalSeconds
	return StartSessionIMSCore(ctx, imsCfg, network, StartSessionInput{
		TraceID:               cfg.TraceID,
		LocalIP:               cfg.LocalIP,
		Dataplane:             cfg.Dataplane,
		RegistrarCandidates:   cfg.RegistrarCandidates,
		AKA:                   cfg.AKA,
		DeliveryStore:         cfg.DeliveryStore,
		IMSI:                  cfg.IMSI,
		MCC:                   cfg.MCC,
		MNC:                   cfg.MNC,
		CellID:                cfg.CellID,
		RegisterExpirySeconds: cfg.RegisterExpirySeconds,
	})
}

func (s *Service) SendSMS(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	op, release, ok := s.acquireOperation(true)
	if !ok {
		return messaging.SendOutcome{}, fmt.Errorf("IMS service not ready")
	}
	defer release()
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return s.sendSMSOnRegisteredTransport(operationCtx, peer, content, parts)
}

// MessagingReady is deliberately stricter than REGISTER success: SMS may only
// be advertised after a healthy, carrier-authorized IMS transport owns the
// registered Port-C connection. That transport is either negotiated 3GPP
// IPsec or an explicitly opted-in SIP stream inside the authenticated SWu tunnel.
func (s *Service) MessagingReady() bool {
	state := s.stateSnapshot()
	return state.registered && (state.ipsecInstalled || state.plainIMS) && state.transportRuntime != nil && state.transportRuntime.Healthy()
}

// CallReady additionally requires the protected Port-S accept loop to be
// running. REGISTER and Port-C readiness alone do not guarantee that inbound
// INVITEs can reach the call state machine.
func (s *Service) CallReady() bool {
	op, release, ok := s.acquireOperation(true)
	if !ok {
		return false
	}
	defer release()
	if op.calls == nil || op.runtime == nil {
		return false
	}
	return op.runtime.incomingPortSDiagnostics().listenerStarted
}

// TransportFailure reports an authenticated IMS transport failure. It remains
// silent during an intentional Service.Close so the caller can distinguish a
// real disconnect from a user-requested stop.
func (s *Service) TransportFailure() <-chan error {
	runtime := s.runtimeSnapshot()
	if runtime == nil {
		return nil
	}
	return runtime.Failure()
}

func (s *Service) CallStatus() CallState {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return CallState{State: "unavailable", SignalingOK: false}
	}
	defer release()
	if op.calls == nil {
		return CallState{State: "unavailable", SignalingOK: false}
	}
	return op.calls.snapshot()
}

func (s *Service) DialCall(ctx context.Context, peer string) error {
	op, release, ok := s.acquireOperation(true)
	if !ok {
		return fmt.Errorf("IMS voice service not ready")
	}
	defer release()
	if op.calls == nil {
		return fmt.Errorf("IMS voice service not ready")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.calls.dial(operationCtx, peer)
}

func (s *Service) AnswerCall(ctx context.Context) error {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return fmt.Errorf("IMS voice service not ready")
	}
	defer release()
	if op.calls == nil {
		return fmt.Errorf("IMS voice service not ready")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.calls.answer(operationCtx)
}

func (s *Service) RejectCall() error {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return fmt.Errorf("IMS voice service not ready")
	}
	defer release()
	if op.calls == nil {
		return fmt.Errorf("IMS voice service not ready")
	}
	return op.calls.reject(486, "Busy Here")
}

func (s *Service) HangupCall(ctx context.Context) error {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return nil
	}
	defer release()
	if op.calls == nil {
		return nil
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.calls.hangup(operationCtx)
}

func (s *Service) SendCallDTMF(ctx context.Context, digit string) error {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return fmt.Errorf("IMS voice service not ready")
	}
	defer release()
	if op.calls == nil {
		return fmt.Errorf("IMS voice service not ready")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.calls.sendDTMF(operationCtx, digit)
}

// DialFax 发起 T.38 传真 SIP INVITE（读卡器路径）。
// 成功返回协商结果；调用方随后通过 StartFaxMedia 绑定媒体通道。
func (s *Service) DialFax(ctx context.Context, peer string, preferT38 bool) (*FaxNegotiation, error) {
	op, release, ok := s.acquireOperation(true)
	if !ok {
		return nil, fmt.Errorf("IMS service not ready for fax")
	}
	defer release()
	if op.fax == nil {
		return nil, fmt.Errorf("IMS service not ready for fax")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.fax.DialFax(operationCtx, peer, preferT38)
}

// StartFaxMedia 绑定传真媒体通道（T.38 UDPTL 或 G.711 RTP）。
func (s *Service) StartFaxMedia(ctx context.Context, neg *FaxNegotiation) error {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return fmt.Errorf("IMS fax runtime unavailable")
	}
	defer release()
	if op.fax == nil {
		return fmt.Errorf("IMS fax runtime unavailable")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.fax.StartMedia(operationCtx, neg)
}

// WriteFaxUDPTL 向远端发送一个 UDPTL 包。
func (s *Service) WriteFaxUDPTL(payload []byte) error {
	op, release, ok := s.acquireLifecycleLease()
	if !ok {
		return fmt.Errorf("IMS fax runtime unavailable")
	}
	defer release()
	if op.fax == nil {
		return fmt.Errorf("IMS fax runtime unavailable")
	}
	return op.fax.WriteUDPTL(payload)
}

// WriteFaxRTP 向远端发送 PCMA 音频数据（G.711 传真模式）。
// PCMA 字节流被分帧为 160 字节（20ms）RTP 包并发送。
func (s *Service) WriteFaxRTP(pcma []byte) error {
	op, release, ok := s.acquireLifecycleLease()
	if !ok {
		return fmt.Errorf("IMS fax runtime unavailable")
	}
	defer release()
	if op.fax == nil {
		return fmt.Errorf("IMS fax runtime unavailable")
	}
	return op.fax.WriteRTP(pcma)
}

// RunFaxMediaLoop 循环读取媒体包，每个包调用 onPacket 回调。
func (s *Service) RunFaxMediaLoop(ctx context.Context, onPacket func([]byte) error) {
	op, release, ok := s.acquireLifecycleLease()
	if !ok {
		return
	}
	defer release()
	if op.fax == nil {
		return
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	op.fax.RunMediaLoop(operationCtx, onPacket)
}

// HangupFax 结束传真会话（SIP BYE 或 CANCEL）。
func (s *Service) HangupFax(ctx context.Context) error {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return nil
	}
	defer release()
	if op.fax == nil {
		return nil
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.fax.Hangup(operationCtx)
}

// FaxSnapshot 返回传真会话当前状态。
func (s *Service) FaxSnapshot() map[string]any {
	op, release, ok := s.acquireLifecycleLease()
	if !ok {
		return map[string]any{"state": "unavailable"}
	}
	defer release()
	if op.fax == nil {
		return map[string]any{"state": "unavailable"}
	}
	return op.fax.Snapshot()
}

func (s *Service) SendUSSD(ctx context.Context, command string) (*messaging.USSDResult, error) {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return nil, fmt.Errorf("IMS service not ready")
	}
	defer release()
	if op.inner == nil {
		return nil, fmt.Errorf("IMS service not ready")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.inner.SendUSSD(operationCtx, command)
}

func (s *Service) ContinueUSSD(ctx context.Context, sessionID, input string) (*messaging.USSDResult, error) {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return nil, fmt.Errorf("IMS service not ready")
	}
	defer release()
	if op.inner == nil {
		return nil, fmt.Errorf("IMS service not ready")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.inner.ContinueUSSD(operationCtx, sessionID, input)
}

func (s *Service) CancelUSSD(ctx context.Context, sessionID string) error {
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return fmt.Errorf("IMS service not ready")
	}
	defer release()
	if op.inner == nil {
		return fmt.Errorf("IMS service not ready")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return op.inner.CancelUSSD(operationCtx, sessionID)
}

// Close tears down this Service permanently. A later reader reconnect creates
// a fresh Service with its own SWu network and lifecycle generation.
func (s *Service) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	// Reject future operations and cancel the operation contexts before waiting
	// for current readers. Do not clear their pointers until operationMu is
	// exclusively held: SMS/call/fax internals intentionally keep using them for
	// the duration of a request.
	s.stateMu.Lock()
	if s.closing {
		s.stateMu.Unlock()
		return nil
	}
	s.closing = true
	s.lifecycleID++ // invalidate an in-flight Start before it can commit.
	cancel := s.lifecycleCancel
	startDone := s.startDone
	s.stateMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if startDone != nil {
		<-startDone
	}

	s.operationMu.Lock()
	// Detach the runtime from status/readiness first.  Existing callers may
	// still hold the runtime while Close finishes its blocking teardown, but no
	// concurrent status read may advertise it as usable.
	s.stateMu.Lock()
	runtime := s.transportRuntime
	fax := s.fax
	calls := s.calls
	swu := s.swu
	inner := s.inner
	s.transportRuntime = nil
	s.lifecycleCtx = nil
	s.lifecycleCancel = nil
	s.registered = false
	s.registerRequest = nil
	s.expiresSeconds = 0
	s.verifyHeader = ""
	s.registeredMSISDN = ""
	s.sipSecurityMode = ""
	s.ipsecInstalled = false
	s.pcscf = ""
	s.localAddr = ""
	s.started = false
	s.starting = false
	s.startDone = nil
	s.calls = nil
	s.fax = nil
	s.swu = nil
	s.inner = nil
	s.stateMu.Unlock()
	// Release the gate before runtime.Close waits for a Port-S handler. A handler
	// arriving after closing was set will acquire the lease, observe closing and
	// return instead of deadlocking behind this writer.
	s.operationMu.Unlock()
	if fax != nil {
		fax.Close()
	}
	if calls != nil {
		calls.close()
	}
	if runtime != nil {
		runtime.Close()
	}
	if us, ok := s.network.(*UserspaceIMSNetwork); ok {
		_ = us.Close()
	} else if swu != nil {
		_ = swu.Close()
	}
	if inner == nil {
		return nil
	}
	return inner.Close(ctx)
}

func (s *Service) Status() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{"enabled": false}
	}
	state := s.stateSnapshot()
	transportReady := state.registered && (state.ipsecInstalled || state.plainIMS) && state.transportRuntime != nil && state.transportRuntime.Healthy()
	incoming := state.transportRuntime.incomingPortSDiagnostics()
	lastInboundSIPAt := ""
	if !incoming.lastInboundSIPAt.IsZero() {
		lastInboundSIPAt = incoming.lastInboundSIPAt.UTC().Format(time.RFC3339Nano)
	}
	regStatus := "idle"
	if state.registered {
		regStatus = "degraded"
		if transportReady {
			regStatus = "registered"
		}
	}
	return map[string]interface{}{
		"enabled":   state.started,
		"device_id": s.cfg.DeviceID,
		// registered intentionally preserves the narrower REGISTER-success
		// meaning.  UI and callers deciding whether calls/SMS/incoming INVITEs
		// are usable must use the *_ready values below.
		"registered":        state.registered,
		"reg_status":        regStatus,
		"registrar":         state.pcscf,
		"local_addr":        state.localAddr,
		"sip_security_mode": state.sipSecurityMode,
		"trace_id":          s.cfg.TraceID,
		"signaling_ready":   transportReady,
		"transport_ready":   transportReady,
		// The protected Port-S listener participates in transportRuntime and
		// calls rt.fail when it exits.  Until a more granular listener metric is
		// available, its readiness has the same safe gate as SIP signaling.
		"incoming_ready": transportReady && incoming.listenerStarted,
		// Port-S observations intentionally exclude caller, URI, connection
		// address, and SIP payload. They diagnose whether an advertised inbound
		// contact has ever been reached without turning the status endpoint into
		// a subscriber-data channel.
		"incoming_listener_started":          incoming.listenerStarted,
		"incoming_accept_count":              incoming.acceptCount,
		"incoming_last_sip_at":               lastInboundSIPAt,
		"incoming_last_response_write_error": incoming.lastResponseWriteError,
		"incoming_reachability":              incoming.reachability,
		"ipsec_installed":                    state.ipsecInstalled,
		"effective_security":                 effectiveServiceSecurityMode(state),
		"register_template":                  s.imsCfg.IMSRegisterTemplate.ID,
		"preset_id":                          s.imsCfg.CarrierPresetID,
		"verify":                             state.verifyHeader,
		"registered_msisdn":                  state.registeredMSISDN,
		"expires_seconds":                    state.expiresSeconds,
	}
}

func effectiveServiceSecurityMode(state serviceStateSnapshot) string {
	if state.ipsecInstalled {
		return "ipsec3gpp"
	}
	if state.plainIMS {
		return "swu_tunnel_only"
	}
	return "plain"
}

func securityModeLabel(ipsec bool) string {
	if ipsec {
		return "ipsec3gpp"
	}
	return "plain"
}

// ConfigFromVoice builds imscore.Config from an established runtimehost voiceclient.Config.
func ConfigFromVoice(v voiceclient.Config, template policy.IMSRegisterTemplate) Config {
	return Config{
		DeviceID:              v.DeviceID,
		TraceID:               v.TraceID,
		LocalIP:               v.LocalIP,
		Dataplane:             v.Dataplane,
		PCSCFAddr:             v.PCSCFAddr,
		RegistrarCandidates:   v.RegistrarCandidates,
		Realm:                 v.Realm,
		PrivateID:             v.PrivateID,
		PublicURI:             v.PublicURI,
		HomeDomain:            v.HomeDomain,
		IMSI:                  v.IMSI,
		AKA:                   v.AKA,
		Template:              template,
		MCC:                   v.MCC,
		MNC:                   v.MNC,
		CellID:                v.CellID,
		SIPInstanceURN:        v.SIPInstanceURN,
		UserAgent:             v.RegisterProfile.UserAgent,
		LocalPort:             v.LocalPort,
		Transport:             v.Transport,
		RegisterExpirySeconds: int(v.RegisterExpiry / time.Second),
		DeliveryStore:         v.DeliveryStore,
	}
}

// ParsePCSCFHostPort splits a P-CSCF address for logging and policy setup.
func ParsePCSCFHostPort(addr string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid P-CSCF host %q", host)
	}
	return ip, port, nil
}
