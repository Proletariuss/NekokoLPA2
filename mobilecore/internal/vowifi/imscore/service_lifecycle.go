package imscore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"

	"proletarius.local/core/internal/vowifi/voiceclient"
)

// Start runs the full IMS Core lifecycle: REGISTER FSM, ipsec transport runtime,
// TCP write scheduler, and post-register messaging attach.
func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("imscore: service is nil")
	}
	if s.cfg.AKA == nil {
		return fmt.Errorf("imscore: Config.AKA is required")
	}
	if s.cfg.LocalIP == nil {
		return fmt.Errorf("imscore: Config.LocalIP is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	addr := strings.TrimSpace(s.imsCfg.Registrar)
	if addr == "" {
		addr = strings.TrimSpace(s.cfg.PCSCFAddr)
	}
	logger.Info(fmt.Sprintf("[%s] IMS Core 正在启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("addr", addr),
		logger.String("transport", strings.TrimSpace(s.imsCfg.Transport)),
		logger.String("preset_id", strings.TrimSpace(s.imsCfg.CarrierPresetID)),
		logger.String("register_template", strings.TrimSpace(s.imsCfg.IMSRegisterTemplate.ID)),
		logger.String("register_policy", registerPolicyID(s.imsCfg.IMSRegisterTemplate)),
		logger.String("register_policy_source", strings.TrimSpace(s.imsCfg.IMSRegisterPolicySource)))

	lifecycleCtx, cancel := context.WithCancel(ctx)
	startDone := make(chan struct{})
	s.closeMu.Lock()
	s.stateMu.Lock()
	if s.closing || s.started || s.starting || s.lifecycleCancel != nil {
		s.stateMu.Unlock()
		s.closeMu.Unlock()
		cancel()
		return fmt.Errorf("imscore: service is already starting or running")
	}
	s.lifecycleID++
	s.inviteRecoveryUsed = false
	s.registrationRecovery = make(chan struct{}, 1)
	lifecycleID := s.lifecycleID
	s.starting = true
	s.lifecycleCtx = lifecycleCtx
	s.lifecycleCancel = cancel
	s.startDone = startDone
	s.stateMu.Unlock()
	s.closeMu.Unlock()
	defer func() {
		// Close waits for startDone before it clears lifecycle-owned pointers.
		// Nothing below this point may touch them after the channel is closed.
		close(startDone)
		s.stateMu.Lock()
		if s.startDone == startDone {
			s.startDone = nil
		}
		s.stateMu.Unlock()
	}()

	swu, err := s.resolveSWUDialer()
	if err != nil {
		s.failRegisteredRuntimeStart(nil, lifecycleID)
		return err
	}
	// Publish even if Close canceled the startup in the meantime. Close waits
	// for startDone and will then own/close this dialer instead of leaking a
	// freshly resolved standalone SWu netstack.
	s.stateMu.Lock()
	s.swu = swu
	current := !s.closing && s.lifecycleID == lifecycleID && lifecycleCtx.Err() == nil
	s.stateMu.Unlock()
	if !current {
		s.failRegisteredRuntimeStart(nil, lifecycleID)
		return fmt.Errorf("imscore: lifecycle stopped before IMS registration could start")
	}

	registerCtx, registerCancel := context.WithTimeout(lifecycleCtx, registerDialTimeout)
	defer registerCancel()

	reg, err := s.runRegisterFlow(registerCtx)
	if err != nil {
		logger.Warn("IMS register failed",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("pcscf", s.cfg.PCSCFAddr),
			logger.Int("registrar_candidates", len(s.cfg.RegistrarCandidates)),
			logger.String("error", err.Error()))
		s.failRegisteredRuntimeStart(nil, lifecycleID)
		return fmt.Errorf("register: %w", err)
	}
	if !s.lifecycleCurrent(lifecycleCtx, lifecycleID) {
		s.failRegisteredRuntimeStart(reg, lifecycleID)
		return fmt.Errorf("imscore: lifecycle stopped before authenticated IMS transport could start")
	}

	winningPCSCF := strings.TrimSpace(reg.pcscfAddr)
	if winningPCSCF == "" {
		winningPCSCF = s.cfg.PCSCFAddr
	}
	s.cfg.PCSCFAddr = winningPCSCF
	s.imsCfg.Registrar = winningPCSCF
	s.imsCfg.PCSCF = winningPCSCF
	return s.activateRegisteredRuntime(lifecycleCtx, lifecycleID, swu, reg, winningPCSCF)
}

// activateRegisteredRuntime commits REGISTER success only after the secure
// runtime that owns Port-C and Port-S has started.  OPTIONS=0 is a supported
// setting that disables the heartbeat; it must never relax this startup gate.
func (s *Service) activateRegisteredRuntime(lifecycleCtx context.Context, lifecycleID uint64, swu voiceclient.SWUTCPDialer, reg *registerResult, winningPCSCF string) error {
	if s == nil || reg == nil {
		return fmt.Errorf("imscore: registered runtime requires a service and registration result")
	}
	if !s.lifecycleCurrent(lifecycleCtx, lifecycleID) {
		s.failRegisteredRuntimeStart(reg, lifecycleID)
		return fmt.Errorf("imscore: lifecycle stopped before authenticated IMS transport could start")
	}

	var runtime *transportRuntime
	var calls *callRuntime
	portCConn := reg.secureConn
	if portCConn == nil && reg.plainConn != nil && s.cfg.Template.AllowPlainIMS {
		portCConn = reg.plainConn
	}
	if portCConn != nil && (reg.transport != nil || s.cfg.Template.AllowPlainIMS) {
		runtimeCfg := s.cfg
		runtimeCfg.SecurityVerify = reg.verifyHeader
		// Install the UAS before any transport goroutine can consume a port-s
		// packet. Previously this callback was assigned after runtime startup;
		// a fast carrier INVITE could land in that race window and receive 480
		// (or no useful response) even though registration and SMS were healthy.
		calls = newCallRuntime(s)
		runtimeCfg.IncomingSIPHandler = func(req *sip.Request, responder SIPResponder) {
			_, release, ok := s.acquireRuntimeLease(lifecycleCtx, lifecycleID)
			if !ok {
				// The runtime may receive a Port-S request in the tiny interval
				// before commit, or after Close has withdrawn readiness. Fail
				// closed with a transaction response instead of silently leaving
				// the carrier retransmitting on an about-to-close connection.
				if req == nil || responder == nil || strings.EqualFold(string(req.Method), "ACK") {
					return
				}
				code, reason := 481, "Call/Transaction Does Not Exist"
				if strings.EqualFold(string(req.Method), "INVITE") {
					code, reason = 480, "Temporarily Unavailable"
				}
				_ = responder(newIncomingResponse(req, code, reason, nil))
				return
			}
			defer release()
			calls.handleRequest(req, responder)
		}
		runtimeCfg.IncomingRPAck = func(target string, reference byte) {
			go s.sendIncomingRPAck(lifecycleCtx, lifecycleID, target, reference)
		}
		var err error
		runtime, err = startTransportRuntime(lifecycleCtx, runtimeCfg, swu, reg.ipsecPolicy, reg.transport, portCConn, reg.portSListener)
		if err != nil {
			s.failRegisteredRuntimeStart(reg, lifecycleID)
			logger.Warn("IMS transport runtime start failed",
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("error", err.Error()))
			return fmt.Errorf("imscore: start authenticated IMS transport: %w", err)
		}
	}
	if !s.lifecycleCurrent(lifecycleCtx, lifecycleID) {
		if runtime != nil {
			runtime.Close()
		}
		s.failRegisteredRuntimeStart(reg, lifecycleID)
		return fmt.Errorf("imscore: lifecycle stopped before authenticated IMS transport could commit")
	}

	// REGISTER, keepalives and MESSAGE must share this single userspace
	// netstack/security association. Creating a second voiceclient here would
	// consume the same SWu packet stream and bypass the negotiated port-c state.
	s.stateMu.Lock()
	if s.closing || s.lifecycleID != lifecycleID || lifecycleCtx.Err() != nil {
		s.stateMu.Unlock()
		if runtime != nil {
			runtime.Close()
		}
		s.failRegisteredRuntimeStart(reg, lifecycleID)
		return fmt.Errorf("imscore: lifecycle stopped before authenticated IMS transport could commit")
	}
	s.registered = true
	s.registerRequest = reg.request
	s.expiresSeconds = reg.expiresSeconds
	s.verifyHeader = reg.verifyHeader
	s.registeredMSISDN = reg.registeredMSISDN
	s.sipSecurityMode = "plain"
	if reg.secureConn != nil {
		s.sipSecurityMode = "ipsec3gpp"
	} else if reg.plainConn != nil && s.cfg.Template.AllowPlainIMS {
		s.sipSecurityMode = "swu_tunnel_only"
	}
	s.ipsecInstalled = reg.secureConn != nil
	s.pcscf = winningPCSCF
	s.localAddr = s.cfg.LocalIP.String()
	s.transportRuntime = runtime
	s.calls = calls
	if runtime != nil {
		s.fax = newFaxRuntime(s)
	} else {
		s.fax = nil
	}
	s.started = true
	s.starting = false
	s.stateMu.Unlock()

	if runtime != nil {
		s.logTCPWriterLoop(lifecycleCtx, portCConn)
	}
	return nil
}

// failRegisteredRuntimeStart releases resources that have escaped the short
// REGISTER transaction but cannot be owned by a transport runtime.  Do this
// before returning the error so direct Start callers cannot observe a usable
// registration after Port-S startup has failed.
func (s *Service) lifecycleCurrent(lifecycleCtx context.Context, lifecycleID uint64) bool {
	if s == nil || lifecycleCtx == nil || lifecycleCtx.Err() != nil {
		return false
	}
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return !s.closing && s.lifecycleID == lifecycleID
}

func (s *Service) failRegisteredRuntimeStart(reg *registerResult, lifecycleID uint64) {
	if reg != nil {
		if reg.portSListener != nil {
			_ = reg.portSListener.Close()
		}
		if reg.secureConn != nil {
			_ = reg.secureConn.Close()
		}
		if reg.plainConn != nil {
			_ = reg.plainConn.Close()
		}
	}

	s.stateMu.Lock()
	if s.lifecycleID != lifecycleID {
		s.stateMu.Unlock()
		return
	}
	cancel := s.lifecycleCancel
	s.lifecycleCtx = nil
	s.lifecycleCancel = nil
	s.registered = false
	s.expiresSeconds = 0
	s.verifyHeader = ""
	s.registeredMSISDN = ""
	s.sipSecurityMode = ""
	s.ipsecInstalled = false
	s.pcscf = ""
	s.localAddr = ""
	s.transportRuntime = nil
	s.calls = nil
	s.fax = nil
	s.started = false
	s.starting = false
	s.stateMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) resolveSWUDialer() (voiceclient.SWUTCPDialer, error) {
	if s == nil {
		return nil, fmt.Errorf("imscore: service is nil")
	}
	s.stateMu.RLock()
	existing := s.swu
	s.stateMu.RUnlock()
	if existing != nil {
		return existing, nil
	}
	if us, ok := s.network.(*UserspaceIMSNetwork); ok && us != nil {
		if dialer := us.SWUDialer(); dialer != nil {
			return dialer, nil
		}
	}
	return newSWUNetstack(s.cfg.LocalIP, s.cfg.Dataplane)
}

func (s *Service) logTCPWriterLoop(ctx context.Context, conn net.Conn) {
	if s == nil || s.runtimeSnapshot() == nil || conn == nil {
		return
	}
	local := ""
	if conn.LocalAddr() != nil {
		local = conn.LocalAddr().String()
	}
	logger.Info(fmt.Sprintf("[%s] TCP 专用写通道调度器已启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("local", local))

	go func() {
		<-ctx.Done()
		logger.Info(fmt.Sprintf("[%s] TCP 专用写通道调度器已退出", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("local", local))
	}()
}

// attachMessaging hooks voiceclient for SMS/USSD after imscore registration.
func (s *Service) attachMessaging(ctx context.Context, winningPCSCF string) error {
	voiceCfg := voiceclient.Config{
		DeviceID:        s.cfg.DeviceID,
		TraceID:         s.cfg.TraceID,
		LocalIP:         s.cfg.LocalIP,
		Dataplane:       s.cfg.Dataplane,
		PCSCFAddr:       winningPCSCF,
		Realm:           s.cfg.Realm,
		PrivateID:       s.cfg.PrivateID,
		PublicURI:       s.cfg.PublicURI,
		HomeDomain:      s.cfg.HomeDomain,
		IMSI:            s.cfg.IMSI,
		LocalPort:       s.cfg.LocalPort,
		Transport:       s.cfg.Transport,
		MCC:             s.cfg.MCC,
		MNC:             s.cfg.MNC,
		CellID:          s.cfg.CellID,
		AKA:             s.cfg.AKA,
		DeliveryStore:   s.cfg.DeliveryStore,
		SIPInstanceURN:  s.cfg.SIPInstanceURN,
		RegisterProfile: voiceclient.SimAdminGBEERegisterProfile(),
		SkipRegister:    true,
	}
	if s.cfg.RegisterExpirySeconds > 0 {
		voiceCfg.RegisterExpiry = time.Duration(s.cfg.RegisterExpirySeconds) * time.Second
	}
	inner, err := voiceclient.Dial(ctx, voiceCfg)
	if err != nil {
		return fmt.Errorf("voiceclient attach: %w", err)
	}
	s.stateMu.Lock()
	s.inner = inner
	s.stateMu.Unlock()
	return nil
}

// Stop tears down the IMS Core lifecycle.
func (s *Service) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stateMu.RLock()
	cancel := s.lifecycleCancel
	s.stateMu.RUnlock()
	if cancel != nil {
		cancel()
	}
	return s.Close(ctx)
}
