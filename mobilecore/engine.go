// Package mobilecore embeds Proletarius reader VoWiFi inside an iOS app.
// Its exported API deliberately uses only gomobile-compatible types.
package mobilecore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/1239t/swu-go/pkg/swu"
	"proletarius.local/core/internal/device"
	"proletarius.local/core/internal/vowifi"
	"proletarius.local/core/internal/vowifi/carrier"
	"proletarius.local/core/internal/vowifi/imscore"
	"proletarius.local/core/internal/vowifi/messaging"
)

// Host must execute every APDU batch under one reader/profile lease, handling
// 61xx/9Fxx GET RESPONSE and 6Cxx corrected Le before returning full R-APDUs.
// Callbacks run on Go workers, never on the audio render thread.
type Host interface {
	ExchangeAPDUs(requestJSON string) (string, error)
	OnEvent(eventJSON string)
	// StoreSMS must return only after durable, idempotent local persistence.
	// Returning an error withholds the network's RP-ACK so delivery can retry.
	StoreSMS(eventJSON string) error
}

type cardConfig struct {
	Generation      int64  `json:"generation"`
	IMSI            string `json:"imsi"`
	MCC             string `json:"mcc"`
	MNC             string `json:"mnc"`
	ICCID           string `json:"iccid"`
	USIMAID         string `json:"usim_aid"`
	ISIMAID         string `json:"isim_aid"`
	MSISDN          string `json:"msisdn"`
	PrivateIdentity string `json:"private_identity"`
	PublicIdentity  string `json:"public_identity"`
	HomeDomain      string `json:"home_domain"`
	SMSC            string `json:"smsc"`
	SMSCTarget      string `json:"smsc_target"`
	GID1            string `json:"gid1"`
	GID2            string `json:"gid2"`
	SPN             string `json:"spn"`
}

type engineConfig struct {
	cardConfig
	IMEI      string `json:"imei"`
	EPDG      string `json:"epdg"`
	EPDGPort  int    `json:"epdg_port"`
	Proxy     string `json:"proxy"`
	Overrides string `json:"carrier_overrides_yaml"`
}

type runningSession struct {
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	config          engineConfig
	service         *imscore.Service // guarded by Engine.mu
	checks          chan struct{}    // replaced for each IMS cycle; guarded by Engine.mu
	checking        bool             // guarded by Engine.mu
	checkRevision   uint64           // events arriving during a probe require another check
	recoveryPending bool             // a failed verification is waiting for an existing call
}

// Engine owns one card generation and one in-process tunnel at a time.
type Engine struct {
	host                     Host
	mu                       sync.Mutex
	apduMu                   sync.Mutex
	audioReadMu              sync.Mutex
	run                      *runningSession
	phase                    string
	lastError                string
	carrierID                string
	epdg                     string
	ikeStage                 string
	attempt                  int
	generation               int64
	retrying                 bool
	terminal                 bool
	imei                     string
	audio                    *net.UDPConn
	audioToken               string
	audioPort                int
	ikeAuthDiagnostic        *ikeAuthDiagnosticStatus
	ikeAuthRequestDiagnostic *ikeAuthRequestDiagnosticStatus
	connectionPolicy         *connectionPolicyStatus
}

func NewEngine(host Host) *Engine {
	// The production logger otherwise defaults to info and may log subscriber
	// identity. Mobile diagnostics are explicit structured events instead.
	_ = logger.Init("error", "json")
	return &Engine{host: host, phase: "idle", imei: makeDeviceIMEI()}
}

func (e *Engine) Start(configJSON string) error {
	if e == nil || e.host == nil {
		return errors.New("VoWiFi host is unavailable")
	}
	var config engineConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid session configuration: %w", err)
	}
	if config.Generation < 0 {
		return errors.New("invalid reader generation")
	}
	if config.EPDGPort < 0 || config.EPDGPort > 65535 {
		return errors.New("invalid ePDG port")
	}
	if config.IMEI == "" {
		config.IMEI = e.imei
	}
	if err := validateReaderIMEI(config.IMEI); err != nil {
		return err
	}
	if config.Proxy != "" {
		config.Proxy = strings.TrimPrefix(strings.TrimSpace(config.Proxy), "socks5://")
		if _, _, err := net.SplitHostPort(config.Proxy); err != nil {
			return errors.New("proxy must be a SOCKS5 host:port")
		}
	}
	e.mu.Lock()
	if e.run != nil {
		e.mu.Unlock()
		return errors.New("stop the current VoWiFi session before starting another")
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &runningSession{ctx: ctx, cancel: cancel, done: make(chan struct{}), config: config}
	e.run, e.phase, e.lastError, e.generation = run, "sim", "", config.Generation
	e.retrying, e.terminal = false, false
	e.ikeStage, e.attempt = "", 0
	e.ikeAuthDiagnostic, e.connectionPolicy = nil, nil
	e.ikeAuthRequestDiagnostic = nil
	e.mu.Unlock()
	go e.serve(run)
	return nil
}

// Stop cancels pending SIM/network work and waits for resource teardown.
// It must be called off the UI and audio render threads.
func (e *Engine) Stop() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	run := e.run
	e.ikeAuthDiagnostic, e.connectionPolicy = nil, nil
	e.ikeAuthRequestDiagnostic = nil
	if run != nil {
		run.cancel()
	}
	e.closeAudioLocked()
	e.mu.Unlock()
	if run != nil {
		select {
		case <-run.done:
		case <-time.After(15 * time.Second):
			return errors.New("VoWiFi teardown is still pending")
		}
	}
	return nil
}

func (e *Engine) Status() string {
	e.mu.Lock()
	status := map[string]any{"type": "status", "phase": e.phase, "generation": e.generation, "registered": false, "messaging_ready": false, "call_ready": false, "carrier": e.carrierID, "epdg": e.epdg}
	status["msisdn"], status["msisdn_source"] = "", ""
	status["mcc"], status["mnc"] = "", ""
	status["retrying"], status["terminal"] = e.retrying, e.terminal
	status["ike_stage"], status["attempt"] = e.ikeStage, e.attempt
	if e.ikeAuthDiagnostic != nil {
		status["ike_auth_diagnostic"] = cloneAuthDiagnosticStatus(e.ikeAuthDiagnostic)
	}
	if e.ikeAuthRequestDiagnostic != nil {
		status["ike_auth_request_diagnostic"] = cloneAuthRequestDiagnosticStatus(e.ikeAuthRequestDiagnostic)
	}
	if e.connectionPolicy != nil {
		policy := *e.connectionPolicy
		status["connection_policy"] = policy
	}
	if e.lastError != "" {
		status["error"] = e.lastError
	}
	var service *imscore.Service
	run := e.run
	var card cardConfig
	if run != nil && run.ctx.Err() == nil {
		service = run.service
		card = run.config.cardConfig
	}
	status["checking_connection"] = run != nil && run.ctx.Err() == nil && run.checking
	e.mu.Unlock()
	if service != nil {
		ims := service.Status()
		messagingReady, callReady := service.MessagingReady(), service.CallReady()
		call := service.CallStatus()
		e.mu.Lock()
		current := e.run == run && run.service == service && run.ctx.Err() == nil
		checking := run.checking
		e.mu.Unlock()
		if !current {
			return marshalJSON(status)
		}
		status["registered"] = ims["registered"]
		status["checking_connection"] = checking
		status["messaging_ready"], status["call_ready"] = messagingReady && !checking, callReady && !checking
		appendSubscriberStatus(status, ims, card)
		// The loopback bearer token is private to this core.
		call.AudioToken, call.AudioPort = "", 0
		status["call"] = call
	}
	return marshalJSON(status)
}

func (e *Engine) emit(value any) {
	if e.host != nil {
		e.host.OnEvent(marshalJSON(value))
	}
}
func marshalJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }

func (e *Engine) phaseChanged(run *runningSession, phase string, err error) {
	e.mu.Lock()
	if e.run != run {
		e.mu.Unlock()
		return
	}
	e.phase = phase
	if phase != "failed" {
		e.retrying, e.terminal = false, false
	}
	if err == nil {
		e.lastError = ""
	} else {
		e.lastError = err.Error()
	}
	e.mu.Unlock()
	e.host.OnEvent(e.Status())
}

func (e *Engine) serve(run *runningSession) {
	defer func() {
		e.mu.Lock()
		if e.run == run {
			e.run = nil
			e.closeAudioLocked()
			if run.ctx.Err() != nil {
				e.phase = "stopped"
				e.lastError = ""
				e.ikeAuthDiagnostic, e.connectionPolicy = nil, nil
				e.ikeAuthRequestDiagnostic = nil
			}
			e.retrying = false
			e.terminal = e.phase == "failed"
		}
		e.mu.Unlock()
		close(run.done)
		e.host.OnEvent(e.Status())
	}()
	e.phaseChanged(run, "sim", nil)
	config := run.config
	if config.IMSI == "" || config.USIMAID == "" || config.MCC == "" || config.MNC == "" {
		card, err := e.readCard(run.ctx, config.Generation)
		if err != nil {
			e.phaseChanged(run, "failed", err)
			return
		}
		config.cardConfig = card
	}
	if err := validateCard(config.cardConfig); err != nil {
		e.phaseChanged(run, "failed", err)
		return
	}
	profile, err := carrier.ResolveWithError(carrier.SIMIdentity{MCC: config.MCC, MNC: config.MNC, IMSI: config.IMSI, ICCID: config.ICCID, GID1: config.GID1, GID2: config.GID2, SPN: config.SPN})
	if err != nil {
		e.phaseChanged(run, "failed", err)
		return
	}
	overrides, err := carrier.LoadOverrides([]byte(config.Overrides))
	if strings.TrimSpace(config.Overrides) == "" {
		overrides = carrier.EmptyOverrideSet()
		err = nil
	}
	if err != nil {
		e.phaseChanged(run, "failed", err)
		return
	}
	override, matched := overrides.Match(config.MCC, config.MNC)
	info := &vowifi.SIMInfo{IMSI: config.IMSI, ICCID: config.ICCID, MCC: config.MCC, MNC: config.MNC, MSISDN: config.MSISDN, PrivateIdentity: config.PrivateIdentity, PublicIdentity: config.PublicIdentity, HomeDomain: config.HomeDomain, SMSC: config.SMSC, SMSCTarget: config.SMSCTarget}
	effective, err := resolveReaderVoWiFiEffectiveConfig(profile, override, matched, info, config.EPDG, config.EPDGPort, config.IMEI)
	if err == nil {
		err = validateReaderVoWiFiStartCapabilities(effective)
	}
	if err != nil {
		e.phaseChanged(run, "failed", err)
		return
	}
	e.mu.Lock()
	run.config = config
	e.carrierID = profile.ID
	e.epdg = effective.EPDG
	e.mu.Unlock()
	failures := 0
	candidateIndex := 0
	redirects := 0
	for run.ctx.Err() == nil {
		cycleEffective := effectiveForEPDGCandidate(effective, candidateIndex)
		if !e.beginConnectionAttempt(run, config, cycleEffective) {
			return
		}
		registered := false
		err = e.connectCycle(run, config, cycleEffective, info, func() { registered = true })
		if run.ctx.Err() != nil {
			return
		}
		var redirect *swu.RedirectError
		if errors.As(err, &redirect) {
			if redirected, redirectErr := effectiveForAuthenticatedRedirect(cycleEffective, redirect, redirects); redirectErr != nil {
				err = redirectErr
			} else {
				effective, candidateIndex = redirected, 0
				redirects++
			}
		}
		// SWu also cancels its own child context on DPD/rekey/sessionDown.
		// Only cancellation of the owning run means the user stopped it.
		err = classifyCycleFailure(run.ctx, err)
		nextFailures, retry, delay := reconnectPolicy(failures, registered, err)
		failures = nextFailures
		e.mu.Lock()
		e.retrying, e.terminal = retry, !retry
		if retry && canAdvanceEPDGCandidate(e.ikeStage, err) && candidateIndex+1 < len(effective.EPDGCandidates) {
			candidateIndex++
		}
		e.mu.Unlock()
		if err != nil {
			if !retry {
				err = terminalSessionError(err)
			}
			e.phaseChanged(run, "failed", err)
		}
		if !retry {
			return
		}
		select {
		case <-run.ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (e *Engine) beginConnectionAttempt(run *runningSession, config engineConfig, effective *readerVoWiFiEffectiveConfig) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.run != run || run.ctx.Err() != nil {
		return false
	}
	e.attempt++
	e.ikeAuthDiagnostic, e.ikeAuthRequestDiagnostic = nil, nil
	e.connectionPolicy = connectionPolicyFor(config, effective)
	e.ikeStage = "transport"
	e.epdg = effective.EPDG
	return true
}

func (e *Engine) connectCycle(run *runningSession, config engineConfig, effective *readerVoWiFiEffectiveConfig, info *vowifi.SIMInfo, onRegistered func()) error {
	ctx, cancel := context.WithCancel(run.ctx)
	defer cancel()
	// The resolved override is authoritative for every IKE/IMS device identity.
	config.IMEI = effective.DeviceIdentityIMEI
	ready := make(chan struct{})
	var readyOnce sync.Once
	aka := &simAdapter{engine: e, ctx: ctx, card: config.cardConfig, imei: config.IMEI}
	cfg := readerSWUConfig(config, effective, aka)
	e.mu.Lock()
	attempt := e.attempt
	e.mu.Unlock()
	cfg.OnReady = func() { readyOnce.Do(func() { close(ready) }) }
	cfg.OnProgress = func(stage string) {
		if ctx.Err() == nil {
			e.ikeProgressForAttempt(run, attempt, stage)
		}
	}
	cfg.OnAuthDiagnostic = func(diagnostic swu.AuthDiagnostic) {
		if ctx.Err() == nil {
			e.recordAuthDiagnostic(run, attempt, diagnostic)
		}
	}
	cfg.OnAuthRequestDiagnostic = func(diagnostic swu.AuthRequestDiagnostic) {
		e.recordAuthRequestDiagnostic(run, attempt, ctx, diagnostic)
	}
	tunnel := swu.NewSession(cfg, nil)
	tunnelDone := make(chan error, 1)
	tunnelEnded := make(chan struct{})
	e.phaseChanged(run, "ike", nil)
	go func() { defer close(tunnelEnded); tunnelDone <- tunnel.Connect(ctx) }()
	defer func() {
		cancel()
		// Stop has its own bounded wait and reports pending teardown. Never
		// report success/release the SIM lease while this owner still runs.
		<-tunnelEnded
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-tunnelDone:
		if err == nil {
			return errors.New("tunnel closed before readiness")
		}
		return err
	case <-time.After(90 * time.Second):
		e.mu.Lock()
		stage := e.ikeStage
		e.mu.Unlock()
		return fmt.Errorf("IKE authentication timed out (stage=%s, limit=90s)", stage)
	case <-ready:
	}
	localIP, candidates, err := selectIMSPath(tunnel.Snapshot(), effective.IPStack, effective.IMSPCSCF)
	if err != nil {
		return err
	}
	privateID, publicID, err := resolveReaderIMSIdentities(effective, info)
	if err != nil {
		return err
	}
	network, err := imscore.NewUserspaceIMSNetwork(localIP, tunnel)
	if err != nil {
		return err
	}
	defer network.Close()
	template := effective.IMSRegisterTemplate
	if !effective.Profile.UseIPSec {
		template.SecAgreeMode = "disabled"
		template.StrictSecurityServerOffer = false
	}
	e.phaseChanged(run, "ims", nil)
	var eapDirectAuth *imscore.EAPDirectAuth
	if strings.EqualFold(strings.TrimSpace(template.InitialAuthorization), "eap_direct") {
		res, rand, autn := tunnel.EAPDirectCredentials()
		eapDirectAuth = &imscore.EAPDirectAuth{RES: res, RAND: rand, AUTN: autn}
		defer clear(res)
		defer clear(rand)
		defer clear(autn)
	}
	userAgent := strings.TrimSpace(effective.IMSUserAgent)
	if userAgent == "" {
		userAgent = readerIMSUserAgent(effective.Profile.ID, effective.DeviceModel)
	}
	service, err := imscore.StartSessionIMSCore(ctx, imscore.IMSConfig{Enabled: true, DeviceID: config.IMEI, PCSCF: candidates[0], Registrar: candidates[0], Domain: effective.IMSDomain, Realm: effective.IMSRealm, CallPhoneContext: effective.IMSPhoneContext, IMPI: privateID, IMPU: publicID, CarrierPresetID: effective.Profile.ID, IMSRegisterTemplate: template, IMSRegisterPolicySource: effective.Profile.Source, LocalAddr: localIP.String(), LocalPort: effective.IMSLocalPort, Transport: readerIMSTransport(effective), UserAgent: userAgent, SIPInstance: sipInstance(config.IMEI), TCPKeepaliveSeconds: effective.IMSTCPKeepaliveSeconds, OptionsPingIntervalSeconds: effective.IMSOptionsPingIntervalSeconds}, network, imscore.StartSessionInput{TraceID: fmt.Sprintf("ios-%d", config.Generation), LocalIP: localIP, Dataplane: tunnel, RegistrarCandidates: candidates, AKA: &imsAdapter{aka}, EAPDirectAuth: eapDirectAuth, IMSI: effective.IMSI, MCC: config.MCC, MNC: config.MNC, DisableAMR: !imscore.AMRNBAvailable(), RegisterExpirySeconds: template.Expires, DecodeIncomingRPDU: messaging.ParseRPMTData, DecodeIncomingSMS: decodeIncomingSMS, IncomingSMS: func(sender, content string, at time.Time) error {
		return e.storeIncomingSMS(ctx, config.cardConfig, sender, content, at)
	}, IncomingSMSMessage: func(message imscore.InboundSMS) error {
		return e.storeIncomingSMSMessage(ctx, config.cardConfig, message)
	}})
	if err != nil {
		return err
	}
	e.mu.Lock()
	checks := make(chan struct{}, 1)
	if ctx.Err() == nil {
		run.service = service
		run.checks, run.checking = checks, false
		run.recoveryPending = false
	}
	e.mu.Unlock()
	defer func() {
		// A concurrent refresh may be awaiting a SIM callback bound to this
		// cycle. Cancel it before Close waits for operation leases to drain.
		cancel()
		e.mu.Lock()
		if run.service == service {
			run.service = nil
			run.checks, run.checking = nil, false
			e.closeAudioLocked()
		}
		e.mu.Unlock()
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer closeCancel()
		_ = service.Close(closeCtx)
	}()
	e.phaseChanged(run, "ready", nil)
	if onRegistered != nil {
		onRegistered()
	}
	expires := template.Expires
	if granted, ok := service.Status()["expires_seconds"].(int); ok && granted > 0 {
		expires = granted
	}
	renew := time.NewTimer(registrationRenewalDelay(expires))
	defer renew.Stop()
	type renewalResult struct {
		expires  int
		err      error
		check    bool
		revision uint64
	}
	renewed := make(chan renewalResult, 1)
	maintenanceBusy := false
	renewPending := false
	registeredUntil := registrationFreshUntil(time.Now(), expires)
	lastRegister := time.Now()
	recoveryRequests := service.RegistrationRecoveryRequests()
	startMaintenance := func(check bool) {
		maintenanceBusy = true
		e.mu.Lock()
		revision := run.checkRevision
		e.mu.Unlock()
		refresh := !check || connectionCheckNeedsRefresh(time.Now(), registeredUntil, effective.IMSOptionsPingIntervalSeconds)
		wait := time.Duration(0)
		if check && refresh {
			wait = time.Until(lastRegister.Add(15 * time.Second))
		}
		go func() {
			if wait > 0 {
				timer := time.NewTimer(wait)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
			}
			refreshCtx, refreshCancel := context.WithTimeout(ctx, 60*time.Second)
			defer refreshCancel()
			granted, refreshErr := service.CheckConnection(refreshCtx, refresh)
			renewed <- renewalResult{expires: granted, err: refreshErr, check: check, revision: revision}
		}()
	}
	var renewalFailure error
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	lastStatus := ""
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-renew.C:
			// Registration renewal must share the live IMS runtime, not tear
			// down a healthy tunnel/audio session every 55 minutes. Run off the
			// status loop so UI and call audio keep being serviced meanwhile.
			if !maintenanceBusy && renewalFailure == nil {
				startMaintenance(false)
			} else {
				renewPending = true
			}
		case <-checks:
			if !maintenanceBusy && renewalFailure == nil {
				startMaintenance(true)
			}
		case <-recoveryRequests:
			if !maintenanceBusy && renewalFailure == nil {
				startMaintenance(false)
			} else if renewalFailure == nil {
				renewPending = true
			}
		case result := <-renewed:
			maintenanceBusy = false
			if result.err == nil {
				// Suspension can outlast even the reserved probe lifetime.
				// OPTIONS proves path liveness, never a renewed IMS binding.
				if result.expires == 0 && !time.Now().Before(registeredUntil) {
					startMaintenance(true)
					continue
				}
				if result.expires > 0 {
					lastRegister = time.Now()
					registeredUntil = registrationFreshUntil(lastRegister, result.expires)
					renew.Reset(registrationRenewalDelay(result.expires))
					renewPending = false
				}
				checking := e.finishConnectionCheck(run, service, result.revision)
				if renewPending {
					renewPending = false
					startMaintenance(false)
				} else if checking {
					startMaintenance(true)
				}
				continue
			}
			operation := "registration renewal"
			if result.check {
				operation = "connection verification"
			}
			renewalFailure = fmt.Errorf("IMS %s failed: %w", operation, result.err)
			service.WithdrawRegistration()
			e.deferConnectionRecovery(run, service)
			// Security reauthentication may need fresh SAs. Never silently
			// downgrade, but don't terminate an established call just to retry.
			if !registrationRecoveryMustWait(service.CallStatus()) {
				return renewalFailure
			}
			e.mu.Lock()
			if e.run == run {
				e.lastError = "IMS " + operation + " failed; current call is preserved, reconnecting after hangup"
			}
			e.mu.Unlock()
		case err := <-tunnelDone:
			if err == nil {
				return errors.New("tunnel disconnected")
			}
			return err
		case err := <-service.TransportFailure():
			if err == nil {
				return errors.New("IMS transport disconnected")
			}
			return err
		case <-ticker.C:
			call := service.CallStatus()
			if renewalFailure != nil && !registrationRecoveryMustWait(call) {
				return renewalFailure
			}
			e.syncAudio(call)
			status := e.Status()
			if status != lastStatus {
				e.host.OnEvent(status)
				lastStatus = status
			}
		}
	}
}

func (e *Engine) Command(requestJSON string) (string, error) {
	var request struct {
		Action     string `json:"action"`
		Reason     string `json:"reason"`
		Generation *int64 `json:"generation"`
		Recipient  string `json:"recipient"`
		Text       string `json:"text"`
		Peer       string `json:"peer"`
		Digit      string `json:"digit"`
	}
	if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
		return "", err
	}
	if request.Action == "status" {
		return e.Status(), nil
	}
	if request.Action == "check_connection" {
		return e.requestConnectionCheck(request.Generation, request.Reason)
	}
	if request.Action == "readCard" {
		e.mu.Lock()
		active := e.run != nil
		e.mu.Unlock()
		if active {
			return "", errors.New("stop VoWiFi before reading another card")
		}
		generation := int64(0)
		if request.Generation != nil {
			generation = *request.Generation
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		card, err := e.readCard(ctx, generation)
		if err != nil {
			return "", err
		}
		return marshalJSON(card), nil
	}
	e.mu.Lock()
	run := e.run
	var service *imscore.Service
	var config engineConfig
	if run != nil {
		service = run.service
		config = run.config
	}
	checking := run != nil && run.checking
	e.mu.Unlock()
	if run == nil || service == nil || run.ctx.Err() != nil {
		return "", errors.New("IMS is not ready")
	}
	if request.Generation != nil && *request.Generation != config.Generation {
		return "", errors.New("reader generation changed")
	}
	if checking && (request.Action == "sms" || request.Action == "dial") {
		return "", errors.New("IMS connection verification is in progress")
	}
	ctx, cancel := context.WithTimeout(run.ctx, 90*time.Second)
	defer cancel()
	var err error
	switch request.Action {
	case "sms":
		if config.SMSC == "" || config.SMSCTarget == "" {
			return "", errors.New("the active SIM did not provide an SMSC address")
		}
		parts, encodeErr := device.PrepareSMSSubmitTPDUs(request.Recipient, request.Text)
		if encodeErr != nil {
			return "", encodeErr
		}
		seed := make([]byte, 1)
		if _, err = rand.Read(seed); err != nil {
			return "", err
		}
		messages := make([]messaging.SMSPart, 0, len(parts))
		for i, part := range parts {
			ref := seed[0] + byte(i)
			part.TPDU[1] = ref
			body, wrapErr := messaging.BuildRPMOData(ref, config.SMSC, part.TPDU)
			if wrapErr != nil {
				return "", wrapErr
			}
			messages = append(messages, messaging.SMSPart{RPMR: ref, Body: body})
		}
		outcome, sendErr := service.SendSMS(ctx, config.SMSCTarget, request.Text, messages)
		if sendErr != nil {
			return "", sendErr
		}
		return marshalJSON(map[string]any{"message_id": outcome.MessageID, "parts": outcome.PartsTotal, "state": outcome.DeliveryState}), nil
	case "dial":
		err = service.DialCall(ctx, request.Peer)
	case "answer":
		err = service.AnswerCall(ctx)
	case "reject":
		err = service.RejectCall()
	case "hangup":
		err = service.HangupCall(ctx)
	case "dtmf":
		err = service.SendCallDTMF(ctx, request.Digit)
	default:
		return "", errors.New("unknown VoWiFi command")
	}
	if err != nil {
		return "", err
	}
	// Command completion can precede the periodic status/audio poll. Prepare
	// PCM before publishing media_ready, otherwise native audio's first frame
	// can fail and terminate a successfully negotiated call.
	e.syncAudio(service.CallStatus())
	e.host.OnEvent(e.Status())
	return e.Status(), nil
}

func decodeIncomingSMS(tpdu []byte) (imscore.InboundSMS, bool, error) {
	message, err := device.DecodeSMSDeliverTPDU(tpdu)
	if err != nil {
		return imscore.InboundSMS{}, false, err
	}
	decoded := imscore.InboundSMS{Sender: message.From, Content: message.Text, StatusReport: message.Direction == device.SMSDirectionStatusReport, DeliveryStatus: message.DeliveryStatus}
	if message.Concat != nil {
		if message.ServiceCenterTimestamp == nil {
			return imscore.InboundSMS{}, false, errors.New("multipart SMS has invalid service-centre timestamp")
		}
		decoded.ConcatReference = message.Concat.Reference
		decoded.ConcatTotal = message.Concat.Total
		decoded.ConcatSequence = message.Concat.Sequence
	}
	if message.StatusCode != nil {
		decoded.StatusCode = byte(*message.StatusCode)
	}
	if message.ServiceCenterTimestamp != nil {
		decoded.Timestamp = *message.ServiceCenterTimestamp
		decoded.HasTimestamp = true
	}
	return decoded, true, nil
}

func (e *Engine) storeIncomingSMS(ctx context.Context, card cardConfig, sender, content string, at time.Time) error {
	return e.storeIncomingSMSMessage(ctx, card, imscore.InboundSMS{Sender: sender, Content: content, Timestamp: at, HasTimestamp: true})
}

func (e *Engine) storeIncomingSMSMessage(ctx context.Context, card cardConfig, message imscore.InboundSMS) error {
	if strings.TrimSpace(card.ICCID) == "" {
		return errors.New("incoming SMS has no verified SIM identity; acknowledgement withheld")
	}
	at := message.Timestamp
	identityFields := []string{card.ICCID, message.Sender, message.Content, at.UTC().Format(time.RFC3339Nano)}
	if message.ConcatTotal != 0 || message.ConcatSequence != 0 || message.ConcatReference != 0 {
		if message.ConcatTotal < 1 || message.ConcatTotal > 255 || message.ConcatSequence < 1 || message.ConcatSequence > message.ConcatTotal || message.ConcatReference < 0 || message.ConcatReference > 65535 {
			return errors.New("invalid incoming SMS concatenation metadata; acknowledgement withheld")
		}
		identityFields = append(identityFields, fmt.Sprintf("%d/%d/%d", message.ConcatReference, message.ConcatTotal, message.ConcatSequence))
	}
	// Include the SIM and service-centre timestamp, so retransmission after a
	// reconnect or app restart keeps the same durable storage identity.
	identity := marshalJSON(identityFields)
	digest := sha256.Sum256([]byte(identity))
	simDigest := sha256.Sum256([]byte(card.ICCID))
	fields := map[string]any{"type": "sms", "message_id": fmt.Sprintf("%x", digest[:]), "sim_id": fmt.Sprintf("%x", simDigest[:]), "sender": message.Sender, "content": message.Content, "at": at.UTC().Format(time.RFC3339Nano), "generation": card.Generation}
	if message.ConcatTotal > 0 {
		fields["concat_reference"], fields["concat_total"], fields["concat_sequence"] = message.ConcatReference, message.ConcatTotal, message.ConcatSequence
	}
	event := marshalJSON(fields)
	stored := make(chan error, 1)
	go func() { stored <- e.host.StoreSMS(event) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(20 * time.Second):
		return errors.New("SMS storage timed out; delivery acknowledgement withheld")
	case err := <-stored:
		return err
	}
}

func selectIMSPath(snapshot swu.SessionSnapshot, stack, override string) (net.IP, []string, error) {
	if override != "" {
		host, _, err := net.SplitHostPort(override)
		if err != nil {
			return nil, nil, err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, errors.New("P-CSCF must be numeric")
		}
		if ip.To4() != nil && snapshot.IPv4 != nil && stack != "ipv6" {
			return snapshot.IPv4, []string{override}, nil
		}
		if ip.To4() == nil && snapshot.IPv6 != nil && stack != "ipv4" {
			return snapshot.IPv6, []string{override}, nil
		}
		return nil, nil, errors.New("P-CSCF address family does not match assigned tunnel")
	}
	var local net.IP
	var candidates []net.IP
	if stack != "ipv4" && snapshot.IPv6 != nil && len(snapshot.PCSCFv6) > 0 {
		local = snapshot.IPv6
		candidates = snapshot.PCSCFv6
	} else if stack != "ipv6" && snapshot.IPv4 != nil && len(snapshot.PCSCFv4) > 0 {
		local = snapshot.IPv4
		candidates = snapshot.PCSCFv4
	}
	if local == nil {
		return nil, nil, errors.New("ePDG did not provide a matching tunnel address and P-CSCF")
	}
	result := make([]string, len(candidates))
	for i, ip := range candidates {
		result[i] = net.JoinHostPort(ip.String(), "5060")
	}
	return local, result, nil
}

func registrationRenewalDelay(expires int) time.Duration {
	if expires <= 0 {
		expires = 3600
	}
	// Clamp the scheduling horizon, not the registrar's accepted lifetime.
	// An untrusted huge Expires must not overflow Duration into an immediate
	// renewal loop; daily refresh is sufficient even for unusually long grants.
	expires = min(expires, 24*60*60)
	// Short grants must not be renewed after their expiry (the old 30-second
	// minimum could outlive a 10-second registration).
	safety := min(max(expires/4, 1), 300)
	return time.Duration(max(expires-safety, 1)) * time.Second
}

func registrationRecoveryMustWait(call imscore.CallState) bool {
	switch call.State {
	case "outgoing", "incoming", "early", "connecting", "active", "cancelling":
		return true
	default:
		return false
	}
}

// Three consecutive failures to establish IMS exhaust startup retries. A real
// registered session resets that budget before recovery from later Wi-Fi loss.
func reconnectPolicy(failures int, registered bool, err error) (int, bool, time.Duration) {
	if err == nil {
		return 0, true, time.Second
	}
	if registered {
		failures = 0
	}
	if permanentSessionFailure(err) {
		return failures, false, 0
	}
	if registered {
		return 0, true, 2 * time.Second
	}
	failures++
	if failures >= 3 {
		return failures, false, 0
	}
	return failures, true, time.Duration(1<<failures) * time.Second
}
func permanentSessionFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, swu.ErrPeerAuthentication) || errors.Is(err, errEPDGRedirectPolicy) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"sim status 69", "sim status 98", "sim status 6a", "sim session changed", "reader generation changed", "invalid sim application", "incomplete sim identity", "sim rejected aka", "invalid aka key", "at_mac 校验失败", "at_checkcode validation failed", "aka' mac", "eap failure", "authentication_failed"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
func sipInstance(imei string) string {
	if len(imei) != 15 {
		return ""
	}
	for _, digit := range imei {
		if digit < '0' || digit > '9' {
			return ""
		}
	}
	// Match the deployed reader instance. EE/O2 terminating Accept-Contact
	// has been observed selecting this exact unnormalised value.
	return "urn:gsma:imei:" + imei + "-0"
}
func readerIMSUserAgent(carrierID, deviceModel string) string {
	if strings.EqualFold(strings.TrimSpace(carrierID), "apple_o2_giffgaff_uk") {
		return "iOS/18.6.2 iPhone"
	}
	if model := strings.TrimSpace(deviceModel); model != "" {
		return "iOS/26.6 " + model
	}
	return "iOS/26.6 iPhone"
}
func makeDeviceIMEI() string {
	digits := "35"
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	for _, b := range raw {
		digits += strconv.Itoa(int(b) % 10)
	}
	return digits + strconv.Itoa(luhnChecksum(digits))
}
func luhnChecksum(digits string) int {
	sum := 0
	for i, v := range []byte(digits) {
		n := int(v - '0')
		if i%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return (10 - sum%10) % 10
}
