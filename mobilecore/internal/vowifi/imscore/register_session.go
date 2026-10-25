package imscore

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"

	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

func resolveStableSIPInstance(cfg Config) string {
	if urn := strings.TrimSpace(cfg.SIPInstanceURN); urn != "" {
		return urn
	}
	return voiceclient.NewSIPInstanceURN()
}

type registerPhase string

const (
	registerPhaseInitial registerPhase = "initial"
	registerPhaseAuth    registerPhase = "auth"
	registerPhaseSecure  registerPhase = "secure"
)

type registerSession struct {
	cfg               Config
	swu               voiceclient.SWUTCPDialer
	network           IMSNetwork
	transportMode     string
	state             *registerState
	phase             registerPhase
	jitter            bool
	initial500Retried bool

	conn      *connRegisterTransport
	callID    string
	cseq      uint32
	localPort int
}

type ipsecPacketTransformInstaller interface {
	InstallIPSec(*ipsec3gpp.Transport) error
}

func (s *registerSession) installIPSecFromChallenge(res *sip.Response) error {
	if s == nil || s.state == nil {
		return fmt.Errorf("imscore: register session is nil")
	}
	if err := installIPSecFromChallenge(s.cfg, s.state, res); err != nil {
		return err
	}
	installer, ok := s.network.(ipsecPacketTransformInstaller)
	if !ok || installer == nil {
		return fmt.Errorf("imscore: ipsec-3gpp requires a transforming userspace packet dataplane")
	}
	if err := installer.InstallIPSec(s.state.transport); err != nil {
		return fmt.Errorf("imscore: install ipsec-3gpp packet transform: %w", err)
	}
	return nil
}

func newRegisterSession(cfg Config, swu voiceclient.SWUTCPDialer, network IMSNetwork, transportMode string, attemptIndex int) *registerSession {
	cfg.Transport = registerTransportName(cfg, transportMode)
	cfg.Template.Transport = cfg.Transport
	state := &registerState{
		spiC:        randomNonZeroUint32(),
		spiS:        randomNonZeroUint32(),
		portC:       5064,
		portS:       5063,
		sipInstance: resolveStableSIPInstance(cfg),
	}
	localPort := registerAttemptLocalPort(cfg, attemptIndex)
	return &registerSession{
		cfg:           cfg,
		swu:           swu,
		network:       network,
		transportMode: strings.TrimSpace(transportMode),
		state:         state,
		phase:         registerPhaseInitial,
		jitter:        true,
		callID:        uuid.NewString(),
		cseq:          nextRegisterTransportAttemptCSeq(0),
		localPort:     localPort,
	}
}

func (s *registerSession) imsNetwork() IMSNetwork {
	if s == nil {
		return nil
	}
	return s.network
}

func (s *registerSession) dialRegisterConn(ctx context.Context) (*connRegisterTransport, error) {
	if s == nil {
		return nil, fmt.Errorf("imscore: register session is nil")
	}
	if s.conn != nil {
		return s.conn, nil
	}

	if s.localPort <= 0 {
		s.localPort = registerSIPLocalPort(s.cfg)
	}
	transportMode := registerTransportName(s.cfg, s.transportMode)
	if transportMode == "udp" {
		peer, err := udpPeer(effectiveTransportAddr(s.cfg))
		if err != nil {
			return nil, err
		}
		endpoint, err := listenSIPUDP(context.Background(), s.cfg, s.network, s.swu, s.localPort, peer)
		if err != nil {
			return nil, err
		}
		endpoint.portS = s.state.portSUDP
		s.state.portSUDP = nil
		s.conn = newConnRegisterTransport(endpoint, s.cfg.TraceID, s.cfg.DeviceID)
		return s.conn, nil
	}
	if transportMode != "tcp" {
		return nil, fmt.Errorf("imscore: REGISTER transport %q is not supported by the stream registrar", transportMode)
	}
	transportAddr := effectiveTransportAddr(s.cfg)
	host, portStr, err := net.SplitHostPort(transportAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(host)
	if rip == nil {
		return nil, fmt.Errorf("invalid transport P-CSCF %q", transportAddr)
	}
	raddr := &net.TCPAddr{IP: rip, Port: port}

	var rawConn net.Conn
	dialCtx := withLocalPort(ctx, s.localPort)
	dialOptions := DialOptions{}
	if s.cfg.TCPKeepaliveSeconds > 0 {
		dialOptions.KeepAlive = int64(time.Duration(s.cfg.TCPKeepaliveSeconds) * time.Second)
	}
	switch {
	case s.network != nil:
		rawConn, err = s.network.DialContext(dialCtx, "tcp", raddr, transportMode, dialOptions)
	case s.swu != nil:
		if dialOptions.KeepAlive > 0 {
			if dialer, ok := s.swu.(voiceclient.SWUTCPKeepaliveDialer); ok {
				rawConn, err = dialer.DialContextTCPWithKeepalive(dialCtx, s.cfg.LocalIP, s.localPort, rip, port, time.Duration(dialOptions.KeepAlive))
				break
			}
		}
		rawConn, err = s.swu.DialContextTCP(dialCtx, s.cfg.LocalIP, s.localPort, rip, port)
	default:
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: s.cfg.LocalIP, Port: s.localPort}}
		if dialOptions.KeepAlive > 0 {
			d.KeepAlive = time.Duration(dialOptions.KeepAlive)
		}
		rawConn, err = d.DialContext(ctx, "tcp", transportAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("register dial %s: %w", transportAddr, err)
	}

	installSIPTrace(s.cfg.TraceID, s.cfg.DeviceID)
	s.conn = newConnRegisterTransport(rawConn, s.cfg.TraceID, s.cfg.DeviceID)
	logger.Info("IMS REGISTER transport connected",
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("transport_mode", transportMode),
		logger.String("local", connLocalAddrString(s.conn.conn)),
		logger.String("remote", connRemoteAddrString(s.conn.conn)),
		logger.Int("local_port_hint", s.localPort))
	return s.conn, nil
}

func (s *registerSession) closeConn() {
	if s == nil || s.conn == nil {
		return
	}
	_ = s.conn.Close()
	s.conn = nil
}

func (s *registerSession) logFSM(event, reason string, variantIndex, variantTotal, mechanismCount int, initialAuth string) {
	logger.Info(fmt.Sprintf("FSM(reg): %s", event),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("phase", string(s.phase)),
		logger.String("registrar", strings.TrimSpace(s.cfg.PCSCFAddr)),
		logger.String("reason", reason),
		logger.Int("variant_index", variantIndex),
		logger.Int("variant_total", variantTotal),
		logger.String("configured_initial_auth", initialAuth),
		logger.Int("security_client_mechanisms", mechanismCount),
	)
}

func (s *registerSession) runInitialRegisterFlow(ctx context.Context) (*registerResult, error) {
	if s.jitter {
		if err := waitInitialRegisterJitter(ctx, s.cfg); err != nil {
			return nil, err
		}
		s.jitter = false
	}
	if err := s.preparePlainIMSTransport(); err != nil {
		return nil, err
	}
	defer func() {
		if s.state != nil && s.state.portSUDP != nil {
			_ = s.state.portSUDP.Close()
			s.state.portSUDP = nil
		}
		if s.state != nil && s.state.portSListener != nil {
			_ = s.state.portSListener.Close()
			s.state.portSListener = nil
		}
	}()

	transport, err := s.dialRegisterConn(ctx)
	if err != nil {
		return nil, err
	}
	defer s.closeConn()

	variants := initialRegisterVariants(s.cfg)
	var lastErr error
	for i, variant := range variants {
		s.logFSM("initial_register_attempt", "", i+1, len(variants), securityClientMechanismCount(s.cfg.Template), variant.initialAuth)

		res, req, err := s.registerInitialWithPolicy(ctx, transport, variant)
		if err != nil {
			s.logRegisterNetworkDiagnostics("initial", nil)
			lastErr = err
			continue
		}

		logger.Info("IMS REGISTER initial response",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("pcscf", s.cfg.PCSCFAddr),
			logger.String("configured_initial_auth", variant.initialAuth),
			logger.Bool("include_pani", variant.includePANI),
			logger.Bool("include_cellular", variant.includeCellular),
			logger.Int("status", res.StatusCode),
			logger.String("reason", res.Reason))

		switch res.StatusCode {
		case sip.StatusOK:
			decision, err := decideInitialRegisterSuccessSecurity(s.cfg, res)
			if err != nil {
				return nil, err
			}
			s.logFSM("initial_register_success", decision.reason, i+1, len(variants), securityClientMechanismCount(s.cfg.Template), variant.initialAuth)
			if decision.requireIPSec {
				if err := s.installIPSecFromChallenge(res); err != nil {
					return nil, err
				}
				s.phase = registerPhaseSecure
				return runSecureAuthenticatedRegister(ctx, s.cfg, s.swu, s.state, nil, res)
			}
			return s.finishRegisterSuccess(req, res)
		case sip.StatusUnauthorized, sip.StatusProxyAuthRequired:
			s.phase = registerPhaseAuth
			return s.runAuthRegisterPhase(ctx, transport, req, res)
		default:
			lastErr = &registrarAttemptError{
				pcscf:      s.cfg.PCSCFAddr,
				statusCode: res.StatusCode,
				reason:     res.Reason,
			}
			outcome := decideRegisterFailureOutcome(s.cfg, res.StatusCode, res.Reason, i, len(variants), false)
			if outcome.retryVariant && i+1 < len(variants) {
				logger.Info("IMS REGISTER initial reject fallback",
					logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
					logger.Int("status", res.StatusCode),
					logger.String("reason", res.Reason),
					logger.Int("variant_index", i+1),
					logger.Int("variant_total", len(variants)),
					logger.String("next_initial_auth", variants[i+1].initialAuth),
					logger.Bool("next_include_pani", variants[i+1].includePANI),
					logger.Bool("next_include_cellular", variants[i+1].includeCellular))
				continue
			}
			return nil, lastErr
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("imscore: initial REGISTER variants exhausted")
}

// preparePlainIMSTransport only permits unprotected SIP inside the already
// authenticated SWu/ePDG tunnel, and only for an explicit carrier template.
func (s *registerSession) preparePlainIMSTransport() error {
	if s == nil || s.state == nil || !s.cfg.Template.AllowPlainIMS {
		return nil
	}
	if normalizedSecAgreeMode(s.cfg.Template) != "disabled" || s.swu == nil {
		return fmt.Errorf("plain IMS requires an explicit disabled sec-agree template and authenticated SWu tunnel")
	}
	s.state.portC = s.localPort
	s.state.ipsecPolicy = ipsec3gpp.Policy{LocalPortC: s.state.portC, LocalPortS: s.state.portS}
	if registerTransportName(s.cfg, "") == "udp" {
		peer, err := udpPeer(effectiveTransportAddr(s.cfg))
		if err != nil {
			return err
		}
		portS, err := listenSIPUDP(context.Background(), s.cfg, s.network, s.swu, s.state.portS, peer)
		if err != nil {
			return err
		}
		s.state.portSUDP = portS
		return nil
	}
	listener, err := s.swu.ListenContextTCP(context.Background(), s.cfg.LocalIP, s.state.portS)
	if err != nil {
		return fmt.Errorf("prepare tunneled IMS Port-S before REGISTER: %w", err)
	}
	s.state.portSListener = listener
	return nil
}

func (s *registerSession) finishRegisterSuccess(req *sip.Request, res *sip.Response) (*registerResult, error) {
	result, err := finalizeRegisterSuccess(s.cfg, *s.state, res)
	if result != nil && req != nil {
		result.request = req.Clone()
	}
	if err != nil || result == nil || result.secureConn != nil || !s.cfg.Template.AllowPlainIMS {
		return result, err
	}
	if s.conn == nil {
		return nil, fmt.Errorf("plain IMS REGISTER has no retained SWu tunnel connection")
	}
	conn := s.conn.ReleaseConn()
	if conn == nil {
		return nil, fmt.Errorf("plain IMS REGISTER could not retain its SWu tunnel connection")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear plain IMS REGISTER deadline: %w", err)
	}
	if s.state.portSListener == nil {
		if endpoint, ok := conn.(*udpSIPEndpoint); ok {
			if endpoint.portS == nil {
				_ = conn.Close()
				return nil, fmt.Errorf("plain UDP Port-S was not prepared")
			}
			result.plainConn = endpoint
			result.ipsecPolicy = s.state.ipsecPolicy
			s.conn = nil
			return result, nil
		}
		_ = conn.Close()
		return nil, fmt.Errorf("plain IMS Port-S listener was not prepared")
	}
	result.plainConn = conn
	result.ipsecPolicy = s.state.ipsecPolicy
	result.portSListener = s.state.portSListener
	s.state.portSListener = nil
	s.conn = nil
	return result, nil
}

func (s *registerSession) runAuthRegisterPhase(ctx context.Context, transport *connRegisterTransport, challengeReq *sip.Request, challengeRes *sip.Response) (*registerResult, error) {
	lastReq := challengeReq
	var lastRes = challengeRes

	for round := 0; round < maxChallengeRounds && (lastRes.StatusCode == 401 || lastRes.StatusCode == 407); round++ {
		plainDigest := false
		challenge, challengeErr := selectDigestChallenge(s.cfg, lastRes)
		if challengeErr == nil {
			plainDigest = strings.EqualFold(strings.TrimSpace(challenge.Algorithm), "MD5") || strings.TrimSpace(challenge.Algorithm) == ""
			logger.Info("IMS REGISTER authentication challenge",
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.Int("round", round+1),
				logger.String("algorithm", strings.TrimSpace(challenge.Algorithm)),
				logger.String("realm", strings.TrimSpace(challenge.Realm)),
				logger.String("qop", strings.Join(challenge.QOP, ",")),
				logger.Bool("security_server", lastRes.GetHeader("Security-Server") != nil))
		}
		decision, decisionErr := decideSecAgreeAfterChallenge(s.cfg, lastRes)
		if decisionErr != nil {
			return nil, decisionErr
		}
		if decision.installIPSec {
			if challengeErr != nil {
				return nil, challengeErr
			}
			akaResult, authHeader, authErr := computeAKAAuth(s.cfg, challenge, lastReq)
			if authErr != nil {
				return nil, fmt.Errorf("challenge round %d: %w", round+1, authErr)
			}
			if len(akaResult.AUTS) > 0 {
				// the peer sends AUTS on the original unprotected association, waits
				// for a fresh RAND/AUTN, and only then derives CK/IK and installs
				// the negotiated SIP IPsec SAs.
				resyncReq := lastReq.Clone()
				resyncReq.RemoveHeader("Via")
				resyncReq.RemoveHeader("Authorization")
				resyncReq.AppendHeader(sip.NewHeader("Authorization", authHeader))
				akaResult.Zero()
				if err := s.decorateRegisterRequest(resyncReq); err != nil {
					return nil, err
				}
				resyncRes, err := s.sendRegisterRequest(ctx, transport, resyncReq)
				if err != nil {
					return nil, err
				}
				lastReq, lastRes = resyncReq, resyncRes
				continue
			}
			s.state.ck, s.state.ik = append([]byte(nil), akaResult.CK...), append([]byte(nil), akaResult.IK...)
			akaResult.Zero()
			if err := s.installIPSecFromChallenge(lastRes); err != nil {
				return nil, fmt.Errorf("ipsec install: %w", err)
			}
			authReq, _, buildErr := buildAuthenticatedRegisterWithHeader(s.cfg, *s.state, lastReq, authHeader)
			if buildErr != nil {
				return nil, buildErr
			}
			// The protected REGISTER is sent by the fixed-connection transport,
			// so no SIP stack layer will synthesize Via/CSeq for us. Rebuild them
			// with the negotiated UE client port using the negotiated UE client port.
			s.localPort = s.state.ipsecPolicy.LocalPortC
			if err := s.decorateRegisterRequest(authReq); err != nil {
				return nil, err
			}
			s.phase = registerPhaseSecure
			result, secureErr := runSecurePreparedRegister(ctx, s.cfg, s.swu, s.state, authReq, s.network)
			if secureErr != nil {
				s.logRegisterNetworkDiagnostics("protected", s.state.transport)
			}
			return result, secureErr
		}
		res, req, ck, ik, err := s.answerRegisterChallenge(ctx, transport, lastReq, lastRes)
		if err != nil {
			return nil, fmt.Errorf("challenge round %d: %w", round+1, err)
		}
		s.state.ck, s.state.ik = ck, ik
		lastReq, lastRes = req, res
		logger.Info("IMS REGISTER authentication response",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("round", round+1), logger.Int("status", res.StatusCode),
			logger.String("reason", res.Reason),
			logger.Bool("security_server", res.GetHeader("Security-Server") != nil))

		if lastRes.StatusCode != sip.StatusUnauthorized && lastRes.StatusCode != sip.StatusProxyAuthRequired {
			break
		}
		// A repeated ordinary MD5 challenge is a rejected password, not an AKA
		// resynchronization exchange. Retrying it six times only burns SIM APDUs
		// and used to end in a misleading sec-agree/IPsec error.
		if plainDigest {
			break
		}
	}

	if lastRes.StatusCode == sip.StatusOK {
		return s.finishRegisterSuccess(lastReq, lastRes)
	}

	if lastRes.StatusCode != sip.StatusUnauthorized && lastRes.StatusCode != sip.StatusProxyAuthRequired {
		return nil, fmt.Errorf("unexpected challenged REGISTER response: %d %s", lastRes.StatusCode, lastRes.Reason)
	}

	decision, err := decideSecAgreeAfterChallenge(s.cfg, lastRes)
	if err != nil {
		return nil, err
	}
	if !decision.installIPSec {
		challenge, challengeErr := selectDigestChallenge(s.cfg, lastRes)
		if challengeErr == nil && (strings.EqualFold(strings.TrimSpace(challenge.Algorithm), "MD5") || strings.TrimSpace(challenge.Algorithm) == "") {
			return nil, fmt.Errorf("IMS authentication rejected: ordinary SIP Digest (MD5) credentials were not accepted; Security-Server was not offered and sec-agree auto mode was correctly disabled")
		}
		return nil, fmt.Errorf("IMS authentication remained challenged after credentials were submitted (sec-agree decision: %s)", decision.reason)
	}
	if err := s.installIPSecFromChallenge(lastRes); err != nil {
		return nil, fmt.Errorf("ipsec install: %w", err)
	}
	return runSecureAuthenticatedRegister(ctx, s.cfg, s.swu, s.state, lastReq, lastRes)
}

func (s *registerSession) logRegisterNetworkDiagnostics(stage string, transport *ipsec3gpp.Transport) {
	if transport != nil {
		transportStats := transport.Stats()
		logger.Warn("IMS REGISTER ESP diagnostics",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("stage", stage),
			logger.Uint64("esp_outbound", transportStats.OutboundPackets),
			logger.Uint64("esp_inbound", transportStats.InboundPackets),
			logger.Uint64("esp_passthrough", transportStats.PassthroughPackets),
			logger.Uint64("esp_errors", transportStats.TransformErrors),
			logger.Int("actual_source_port", transportStats.LastSourcePort),
			logger.Int("actual_destination_port", transportStats.LastDestinationPort),
			logger.String("actual_source_ip", transportStats.LastSourceIP),
			logger.String("actual_destination_ip", transportStats.LastDestinationIP),
			logger.String("expected_source_ip", net.IP(s.state.ipsecPolicy.LocalIP).String()),
			logger.String("expected_destination_ip", net.IP(s.state.ipsecPolicy.RemoteIP).String()),
			logger.Int("expected_source_port", s.state.ipsecPolicy.LocalPortC),
			logger.Int("expected_destination_port", s.state.ipsecPolicy.RemotePortS))
	}
	if provider, ok := s.network.(interface {
		IPSecDataplaneStats() ipsec3gpp.TransformingDataplaneStats
	}); ok {
		dpStats := provider.IPSecDataplaneStats()
		logger.Warn("IMS REGISTER dataplane diagnostics",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("stage", stage),
			logger.Uint64("sent", dpStats.OutboundPackets),
			logger.Uint64("received", dpStats.InboundPackets),
			logger.Uint64("dropped", dpStats.InboundDropped))
	}
	if provider, ok := s.network.(interface {
		SWUNetstackStats() voiceclient.SWUNetstackStats
	}); ok {
		nsStats := provider.SWUNetstackStats()
		logger.Warn("IMS REGISTER netstack diagnostics",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("stage", stage),
			logger.Uint64("outbound_packets", nsStats.OutboundPackets),
			logger.Uint64("outbound_errors", nsStats.OutboundErrors),
			logger.Uint64("max_outbound_bytes", nsStats.MaxOutboundBytes),
			logger.Uint64("over_1280_packets", nsStats.Over1280Packets),
			logger.String("last_outbound_error", nsStats.LastOutboundError),
			logger.Uint64("tcp_segments_sent", nsStats.TCPSegmentsSent),
			logger.Uint64("tcp_valid_received", nsStats.TCPValidReceived),
			logger.Uint64("tcp_failed_connects", nsStats.TCPFailedConnects),
			logger.Uint64("tcp_retransmits", nsStats.TCPRetransmits),
			logger.Uint64("tcp_timeouts", nsStats.TCPTimeouts),
			logger.Uint64("tcp_send_errors", nsStats.TCPSendErrors),
			logger.Uint64("tcp_resets_received", nsStats.TCPResetsReceived))
	}
}

func (s *registerSession) registerInitialWithPolicy(ctx context.Context, transport *connRegisterTransport, variant initialRegisterVariant) (*sip.Response, *sip.Request, error) {
	res, req, err := s.registerOnce(ctx, transport, true, variant)
	if err != nil || res == nil || s.initial500Retried || !configuredReRegister500(s.cfg, sip.REGISTER, res.StatusCode) {
		return res, req, err
	}
	s.initial500Retried = true
	if err := waitReRegisterRetry(ctx, res); err != nil {
		return nil, nil, err
	}
	// Retry the same initial offer once, using a fresh CSeq and branch. Do
	// not restart an AKA challenge or modify the offered security mechanisms.
	return s.registerOnce(ctx, transport, true, variant)
}

func (s *registerSession) registerOnce(ctx context.Context, transport *connRegisterTransport, initial bool, variant initialRegisterVariant) (*sip.Response, *sip.Request, error) {
	contactPort := s.localPort
	if s.cfg.Template.AllowPlainIMS {
		contactPort = s.state.portS
	}
	req, err := buildRegisterRequest(s.cfg, *s.state, contactPort, initial, variant)
	if err != nil {
		return nil, nil, err
	}
	if err := s.decorateRegisterRequest(req); err != nil {
		return nil, nil, err
	}
	if err := transport.Send(ctx, req); err != nil {
		return nil, nil, err
	}
	res, err := readValidatedRegisterResponse(ctx, s.cfg, transport, req)
	return res, req, err
}

func (s *registerSession) answerRegisterChallenge(ctx context.Context, transport *connRegisterTransport, prevReq *sip.Request, prevRes *sip.Response) (*sip.Response, *sip.Request, []byte, []byte, error) {
	if prevReq == nil {
		return nil, nil, nil, nil, fmt.Errorf("missing REGISTER request associated with challenge")
	}

	chal, err := selectDigestChallenge(s.cfg, prevRes)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	akaResult, authHeader, err := computeAKAAuth(s.cfg, chal, prevReq)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	newReq := prevReq.Clone()
	newReq.RemoveHeader("Via")
	newReq.RemoveHeader("Authorization")
	newReq.AppendHeader(sip.NewHeader("Authorization", authHeader))
	// In auto mode the absence of Security-Server is an explicit plain-SIP
	// decision. Do not carry the initial Security-Client offer into the AKA
	// response: doing so asks for sec-agree again and some IMS cores keep
	// returning 401 until the client incorrectly treats auto as required.
	if decision, decisionErr := decideSecAgreeAfterChallenge(s.cfg, prevRes); decisionErr == nil && !decision.installIPSec {
		newReq.RemoveHeader("Security-Client")
		newReq.RemoveHeader("Security-Verify")
		newReq.RemoveHeader("Require")
		newReq.RemoveHeader("Proxy-Require")
	}
	if err := s.decorateRegisterRequest(newReq); err != nil {
		return nil, nil, nil, nil, err
	}

	res, err := s.sendRegisterRequest(ctx, transport, newReq)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return res, newReq, akaResult.CK, akaResult.IK, nil
}

func (s *registerSession) sendRegisterRequest(ctx context.Context, transport *connRegisterTransport, req *sip.Request) (*sip.Response, error) {
	if err := transport.Send(ctx, req); err != nil {
		return nil, err
	}
	return readValidatedRegisterResponse(ctx, s.cfg, transport, req)
}

func (s *registerSession) decorateRegisterRequest(req *sip.Request) error {
	if req == nil {
		return fmt.Errorf("missing REGISTER request")
	}
	req.RemoveHeader("Via")
	req.RemoveHeader("Call-ID")
	req.RemoveHeader("CSeq")
	req.RemoveHeader("Max-Forwards")

	if s.localPort <= 0 {
		s.localPort = registerSIPLocalPort(s.cfg)
	}
	viaHost := formatRegisterViaHost(s.cfg.LocalIP, s.localPort)
	transport := strings.ToUpper(registerTransportName(s.cfg, s.transportMode))
	via := fmt.Sprintf("SIP/2.0/%s %s;branch=%s", transport, viaHost, sip.GenerateBranchN(16))
	req.PrependHeader(sip.NewHeader("Via", via))
	req.AppendHeader(sip.NewHeader("Call-ID", s.callID))
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d REGISTER", s.cseq)))
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	s.cseq = nextRegisterTransportAttemptCSeq(s.cseq)
	return nil
}

func formatRegisterViaHost(ip net.IP, port int) string {
	if ip == nil {
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	return fmt.Sprintf("%s:%d", ip.String(), port)
}
