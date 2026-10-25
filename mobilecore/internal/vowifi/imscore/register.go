package imscore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	"proletarius.local/core/internal/vowifi/imsheaders"
	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/policy"
	"proletarius.local/core/internal/vowifi/sim"
	"proletarius.local/core/internal/vowifi/simauth"
	"proletarius.local/core/internal/vowifi/subscriber"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

const (
	registerTransactionTimeout = 12 * time.Second
	registerCandidateTimeout   = 15 * time.Second
	registerDialTimeout        = 90 * time.Second
	maxChallengeRounds         = 6
)

type registerState struct {
	spiC  uint32
	spiS  uint32
	portC int
	portS int

	ck []byte
	ik []byte

	sipInstance   string
	selectedOffer *imsheaders.SecurityOffer
	ipsecPolicy   ipsec3gpp.Policy
	transport     *ipsec3gpp.Transport
	secureConn    net.Conn
	portSListener net.Listener
	portSUDP      *udpSIPEndpoint

	expiresSeconds int
	verifyHeader   string
}

type registerResult struct {
	request          *sip.Request
	pcscfAddr        string
	expiresSeconds   int
	verifyHeader     string
	registeredMSISDN string
	secureConn       net.Conn
	plainConn        net.Conn
	ipsecPolicy      ipsec3gpp.Policy
	transport        *ipsec3gpp.Transport
	portSListener    net.Listener
}

type initialRegisterVariant struct {
	initialAuth     string
	includePANI     bool
	includeCellular bool
}

func initialRejectFallbackEnabled(cfg Config) bool {
	if cfg.Template.EnableInitialRejectFallback {
		return true
	}
	return strings.TrimSpace(os.Getenv("PROLETARIUS_IMS_INITIAL_REJECT_FALLBACK")) == "1"
}

func initialRegisterVariants(cfg Config) []initialRegisterVariant {
	base := initialRegisterVariant{
		initialAuth:     strings.TrimSpace(cfg.Template.InitialAuthorization),
		includePANI:     templateIncludesPANI(cfg.Template),
		includeCellular: !strings.EqualFold(strings.TrimSpace(cfg.Template.ID), "apple_orange_uk"),
	}
	if !initialRejectFallbackEnabled(cfg) {
		return []initialRegisterVariant{base}
	}
	return []initialRegisterVariant{
		base,
		{initialAuth: "aka_empty_uri_first", includePANI: true, includeCellular: true},
		{initialAuth: "aka_empty", includePANI: true, includeCellular: true},
		{initialAuth: "aka_zero_response_uri_first", includePANI: true, includeCellular: true},
		{initialAuth: "none", includePANI: false, includeCellular: false},
	}
}

func shouldRetryInitialRegisterForStatus(cfg Config, statusCode int) bool {
	if !initialRejectFallbackEnabled(cfg) {
		return false
	}
	codes := cfg.Template.RegisterPolicy.InitialRejectFallbackStatusCodes
	if codes == nil {
		return statusCode == sip.StatusForbidden
	}
	return containsStatusCode(codes, statusCode)
}

func runSecureAuthenticatedRegister(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state *registerState, lastReq *sip.Request, lastRes *sip.Response) (*registerResult, error) {
	authReq, _, err := buildAuthenticatedRegister(cfg, *state, lastReq, lastRes)
	if err != nil {
		return nil, err
	}
	return runSecurePreparedRegister(ctx, cfg, swuTCP, state, authReq)
}

func runSecurePreparedRegister(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state *registerState, authReq *sip.Request, networks ...IMSNetwork) (*registerResult, error) {
	if registerTransportName(cfg, "") == "udp" {
		return runSecureUDPRegister(ctx, cfg, swuTCP, state, authReq, networks...)
	}
	secureConn, err := dialSecureRegisterConn(ctx, cfg, swuTCP, *state)
	if err != nil {
		return nil, fmt.Errorf("secure channel dial: %w", err)
	}

	// 使用 connRegisterTransport 直接读写固定连接，避免依赖 sipgo 传输层的
	// DialContext hook（sipgo v1.4.0/v1.5.0 仅有 DialerCreate，无法注入用户态 SWu 连接）。
	transport := newConnRegisterTransport(secureConn, cfg.TraceID, cfg.DeviceID)
	defer transport.Close()

	// The protected Contact advertises port-s. It must already be listening
	// when the registrar commits that binding; otherwise some IMS cores make a
	// single reverse-connect attempt during REGISTER and never deliver MT calls.
	// The listener deliberately outlives the short REGISTER context and is
	// transferred to transportRuntime on success.
	if state.portSListener == nil {
		listener, listenErr := swuTCP.ListenContextTCP(context.Background(), cfg.LocalIP, state.ipsecPolicy.LocalPortS)
		if listenErr != nil {
			return nil, fmt.Errorf("prepare incoming SIP port-s before REGISTER: %w", listenErr)
		}
		state.portSListener = listener
		logger.Info("IMS port-s ready before protected REGISTER",
			logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
			logger.Int("port_s", state.ipsecPolicy.LocalPortS))
	}
	registerSucceeded := false
	defer func() {
		if !registerSucceeded && state.portSListener != nil {
			_ = state.portSListener.Close()
			state.portSListener = nil
		}
	}()

	finalRes, err := runRegisterTransaction(ctx, cfg, transport, authReq)
	if err != nil {
		return nil, fmt.Errorf("authenticated REGISTER: %w", err)
	}
	if finalRes.StatusCode != sip.StatusOK {
		detail := authenticatedRegisterFailureDetail(finalRes)
		return nil, fmt.Errorf("authenticated REGISTER failed: %d %s%s", finalRes.StatusCode, finalRes.Reason, detail)
	}

	// REGISTER owns the parser wrapper only for the handshake. ESP is applied
	// below the userspace TCP stack at the SWu packet boundary, so the retained
	// port-c object is the original ordinary TCP connection.
	retained := transport.ReleaseConn()
	if retained == nil {
		return nil, fmt.Errorf("authenticated REGISTER did not retain its secure connection")
	}
	if err := retained.SetDeadline(time.Time{}); err != nil {
		_ = retained.Close()
		return nil, fmt.Errorf("clear authenticated REGISTER connection deadline: %w", err)
	}
	state.secureConn = retained
	result, err := finalizeRegisterSuccess(cfg, *state, finalRes)
	if err != nil {
		_ = retained.Close()
		return nil, err
	}
	registerSucceeded = true
	// Transfer Port-S ownership along with Port-C. The outer registration
	// session closes every listener still held in state on return, including
	// successful returns. Leaving this alias there closes the runtime's socket
	// before its first Accept (gVisor reports "endpoint is in invalid state").
	state.portSListener = nil
	result.request = authReq.Clone()
	return result, nil
}

func authenticatedRegisterFailureDetail(res *sip.Response) string {
	if res == nil {
		return ""
	}
	for _, header := range res.GetHeaders("P-Debug-Info") {
		if strings.Contains(strings.ToLower(header.Value()), "no matched security item") {
			return "; carrier detail: no matched IMS security item"
		}
	}
	return ""
}

// runRegisterTransaction 通过 connRegisterTransport 发送请求并读取响应。
func runRegisterTransaction(ctx context.Context, cfg Config, transport *connRegisterTransport, req *sip.Request) (*sip.Response, error) {
	if err := transport.Send(ctx, req); err != nil {
		return nil, err
	}
	return readValidatedRegisterResponse(ctx, cfg, transport, req)
}

func installIPSecFromChallenge(cfg Config, state *registerState, res *sip.Response) error {
	secServer := res.GetHeader("Security-Server")
	if secServer == nil {
		return fmt.Errorf("missing Security-Server on %d", res.StatusCode)
	}
	verify, selected, err := buildSecurityVerifyFromChallenge(cfg, res)
	if err != nil {
		return err
	}
	state.selectedOffer = selected
	state.verifyHeader = verify

	rip := effectiveIPSecRemoteIP(cfg)
	if rip == nil {
		return fmt.Errorf("invalid IPSec remote for registrar %q transport %q", cfg.PCSCFAddr, effectiveTransportAddr(cfg))
	}

	mech := ipsec3gpp.SecurityMechanism{
		Alg:   selected.Alg,
		EAlg:  selected.EAlg,
		Prot:  selected.Prot,
		Mode:  selected.Mode,
		SPIc:  selected.SPIC,
		SPIs:  selected.SPIS,
		PortC: selected.PortC,
		PortS: selected.PortS,
	}
	pol, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{
		LocalIP:    cfg.LocalIP,
		RemoteIP:   rip,
		Mech:       mech,
		LocalSPIC:  state.spiC,
		LocalSPIS:  state.spiS,
		LocalPortC: state.portC,
		LocalPortS: state.portS,
		CK:         state.ck,
		IK:         state.ik,
	})
	if err != nil {
		return err
	}
	state.portC = pol.LocalPortC
	state.portS = pol.LocalPortS
	transport, err := ipsec3gpp.NewTransport(pol)
	if err != nil {
		return err
	}
	state.ipsecPolicy = pol
	state.transport = transport
	return nil
}

func dialSecureRegisterConn(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state registerState) (net.Conn, error) {
	if state.transport == nil {
		return nil, fmt.Errorf("ipsec-3gpp packet transport is not installed")
	}
	transportAddr := effectiveIPSecGatewayAddr(cfg)
	remoteIP, remotePortStr, err := net.SplitHostPort(transportAddr)
	if err != nil {
		return nil, err
	}
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(remoteIP)
	if rip == nil {
		return nil, fmt.Errorf("invalid transport P-CSCF %q", transportAddr)
	}
	portC := state.ipsecPolicy.RemotePortS
	if portC <= 0 && state.selectedOffer != nil {
		portC = state.selectedOffer.PortS
	}
	if portC <= 0 {
		portC = remotePort
	}
	localPort := state.ipsecPolicy.LocalPortC
	if localPort <= 0 {
		localPort = state.portC
	}

	var rawConn net.Conn
	if swuTCP != nil {
		if cfg.TCPKeepaliveSeconds > 0 {
			if dialer, ok := swuTCP.(voiceclient.SWUTCPKeepaliveDialer); ok {
				rawConn, err = dialer.DialContextTCPWithKeepalive(ctx, cfg.LocalIP, localPort, rip, portC, time.Duration(cfg.TCPKeepaliveSeconds)*time.Second)
			} else {
				rawConn, err = swuTCP.DialContextTCP(ctx, cfg.LocalIP, localPort, rip, portC)
			}
		} else {
			rawConn, err = swuTCP.DialContextTCP(ctx, cfg.LocalIP, localPort, rip, portC)
		}
	} else {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: cfg.LocalIP, Port: localPort}}
		if cfg.TCPKeepaliveSeconds > 0 {
			d.KeepAlive = time.Duration(cfg.TCPKeepaliveSeconds) * time.Second
		}
		rawConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(rip.String(), strconv.Itoa(portC)))
	}
	if err != nil {
		return nil, err
	}
	return rawConn, nil
}

func buildAuthenticatedRegister(cfg Config, state registerState, prevReq *sip.Request, prevRes *sip.Response) (*sip.Request, *sip.Request, error) {
	if prevReq == nil {
		return nil, nil, fmt.Errorf("missing previous REGISTER request")
	}
	chal, err := selectDigestChallenge(cfg, prevRes)
	if err != nil {
		return nil, nil, err
	}
	_, authHeader, err := computeAKAAuth(cfg, chal, prevReq)
	if err != nil {
		return nil, nil, err
	}

	return buildAuthenticatedRegisterWithHeader(cfg, state, prevReq, authHeader)
}

func buildAuthenticatedRegisterWithHeader(cfg Config, state registerState, prevReq *sip.Request, authHeader string) (*sip.Request, *sip.Request, error) {
	req := prevReq.Clone()
	req.RemoveHeader("Via")
	req.RemoveHeader("Authorization")
	req.RemoveHeader("Security-Verify")
	req.RemoveHeader("CSeq")
	if state.verifyHeader != "" && !strings.Contains(strings.ToLower(authHeader), "integrity-protected=") {
		authHeader += ", integrity-protected=yes"
	}
	req.AppendHeader(sip.NewHeader("Authorization", authHeader))
	if state.verifyHeader != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", state.verifyHeader))
		req.RemoveHeader("Contact")
		req.AppendHeader(sip.NewHeader("Contact", buildIMSCoreContact(cfg, state, state.portS)))
		if remoteIP := effectiveIPSecRemoteIP(cfg); remoteIP != nil && state.ipsecPolicy.RemotePortS > 0 {
			req.RemoveHeader("Route")
			protectedRoute := net.JoinHostPort(remoteIP.String(), strconv.Itoa(state.ipsecPolicy.RemotePortS))
			req.AppendHeader(sip.NewHeader("Route", "<sip:"+protectedRoute+";transport="+registerTransportName(cfg, "")+";lr>"))
		}
	}
	// 递增 CSeq（修复：authenticated REGISTER 必须使用新 CSeq）
	cseqHeader := prevReq.GetHeader("CSeq")
	if cseqHeader != nil {
		cseqVal := cseqHeader.Value()
		// 解析 "N REGISTER" 格式
		parts := strings.Fields(cseqVal)
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[0]); err == nil {
				req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d %s", n+1, parts[1])))
			} else {
				req.AppendHeader(sip.NewHeader("CSeq", cseqVal))
			}
		} else {
			req.AppendHeader(sip.NewHeader("CSeq", cseqVal))
		}
	}
	return req, prevReq, nil
}

func buildRegisterRequest(cfg Config, state registerState, localPort int, initial bool, variant initialRegisterVariant) (*sip.Request, error) {
	recipient := sip.Uri{}
	rawURI := "sip:" + strings.TrimSpace(cfg.HomeDomain)
	if err := sip.ParseUri(rawURI, &recipient); err != nil {
		return nil, err
	}
	req := sip.NewRequest(sip.REGISTER, recipient)
	req.AppendHeader(sip.NewHeader("From", "<"+cfg.PublicURI+">;tag="+sip.GenerateTagN(16)))
	req.AppendHeader(sip.NewHeader("To", "<"+cfg.PublicURI+">"))
	req.AppendHeader(sip.NewHeader("Contact", buildIMSCoreContact(cfg, state, localPort)))
	if initial {
		auth, err := buildInitialRegisterAuthorization(cfg, variant.initialAuth)
		if err != nil {
			return nil, err
		}
		if auth != "" {
			req.AppendHeader(sip.NewHeader("Authorization", auth))
		}
	}
	req.AppendHeader(sip.NewHeader("Route", "<sip:"+effectiveRouteAddr(cfg)+";lr>"))
	expires := effectiveRegisterExpiry(cfg)
	req.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(expires)))
	if supported := effectiveSupportedHeader(cfg.Template); supported != "" {
		req.AppendHeader(sip.NewHeader("Supported", supported))
	}
	if allow := effectiveAllowHeader(cfg.Template); allow != "" {
		req.AppendHeader(sip.NewHeader("Allow", allow))
	}
	gsmaContact := strings.EqualFold(strings.TrimSpace(cfg.Template.ContactMode), "gsma")
	// The validated giffgaff GSMA profile does not opt into these business headers.
	// Keep the legacy baseline unchanged for CTExcel and all other carriers.
	if !gsmaContact {
		req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+cfg.PublicURI+">"))
		req.AppendHeader(sip.NewHeader("P-Visited-Network-ID", "\""+cfg.HomeDomain+"\""))
	}
	includePANI := templateIncludesPANI(cfg.Template)
	includeCellular := true
	if initial {
		includePANI = variant.includePANI
		includeCellular = variant.includeCellular
	}
	if includePANI {
		pani := effectivePANI(cfg.Template)
		req.AppendHeader(sip.NewHeader("P-Access-Network-Info", pani))
	}
	if includeCellular && !gsmaContact {
		req.AppendHeader(sip.NewHeader("Cellular-Network-Info", buildCellularNetworkInfo(cfg)))
	}
	req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.smsip"))
	req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.icsi-ref=\""+encodedICSIRef(cfg.Template)+"\""))
	var secClient string
	if initial {
		secClient = buildTemplateSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	} else if state.verifyHeader != "" {
		secClient = buildFullSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	} else {
		secClient = buildTemplateSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	}
	if secAgreeEnabled(cfg.Template) {
		req.AppendHeader(sip.NewHeader("Security-Client", secClient))
	}
	// The validated profile advertises sec-agree as a complete bundle whenever security is
	// offered, including optional/auto mode. If the response omits
	// Security-Server, answerRegisterChallenge removes all four headers and
	// continues unprotected, matching the validated declineSecurity transition.
	if secAgreeEnabled(cfg.Template) {
		req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
		req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
	}
	req.AppendHeader(sip.NewHeader("User-Agent", cfg.UserAgent))
	req.SetDestination(effectiveTransportAddr(cfg))
	req.SetTransport(strings.ToUpper(registerTransportName(cfg, "")))
	logRegisterRouting(cfg, req)
	return req, nil
}

func templateIncludesPANI(template policy.IMSRegisterTemplate) bool {
	return template.IncludePANI || template.IncludePANIAuthenticated
}

func templateIncludesCallPANI(template policy.IMSRegisterTemplate) bool {
	return template.IncludePAccessNetworkInfo || template.IncludePANIAuthenticated
}

func effectiveCallPANI(template policy.IMSRegisterTemplate) string {
	value := effectivePANI(template)
	if !template.IncludePANIAuthenticated {
		value = strings.ReplaceAll(value, ";network-provided", "")
	}
	return value
}

func finalizeRegisterSuccess(cfg Config, state registerState, res *sip.Response) (*registerResult, error) {
	expires := effectiveRegisterExpiry(cfg)
	if h := res.GetHeader("Expires"); h != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil && v > 0 {
			expires = v
		}
	}
	// A registrar may grant a shorter lifetime on the matching Contact while
	// echoing the requested value in Expires.  Treat the shortest positive
	// Contact lifetime as authoritative; zero-expiry stale bindings are
	// intentionally ignored.  Missing this value leaves the UI apparently
	// healthy after the carrier has already discarded the terminating-call
	// binding.
	if granted := contactGrantedExpiry(responseHeaderStrings(res, "Contact")); granted > 0 && granted < expires {
		expires = granted
	}
	associatedMSISDN := extractAssociatedMSISDN(res, cfg.IMSI)
	logger.Info(fmt.Sprintf("[%s] IMS REGISTER 成功", strings.TrimSpace(cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.Int("code", res.StatusCode),
		logger.Int("expires_seconds", expires),
		logger.String("sip_security_mode", "ipsec3gpp"),
		logger.String("verify", state.verifyHeader),
		logger.String("registered_contact", responseHeaderValues(res, "Contact")),
		logger.String("service_route", responseHeaderValues(res, "Service-Route")))
	return &registerResult{
		pcscfAddr:        cfg.PCSCFAddr,
		expiresSeconds:   expires,
		verifyHeader:     state.verifyHeader,
		registeredMSISDN: associatedMSISDN,
		secureConn:       state.secureConn,
		ipsecPolicy:      state.ipsecPolicy,
		transport:        state.transport,
		portSListener:    state.portSListener,
	}, nil
}

func responseHeaderStrings(res *sip.Response, name string) []string {
	if res == nil {
		return nil
	}
	values := make([]string, 0, 2)
	for _, header := range res.GetHeaders(name) {
		if value := strings.TrimSpace(header.Value()); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func contactGrantedExpiry(values []string) int {
	granted := 0
	for _, value := range values {
		lower := strings.ToLower(value)
		for offset := 0; offset < len(lower); {
			index := strings.Index(lower[offset:], "expires=")
			if index < 0 {
				break
			}
			start := offset + index + len("expires=")
			end := start
			for end < len(lower) && lower[end] >= '0' && lower[end] <= '9' {
				end++
			}
			if end > start {
				if seconds, err := strconv.Atoi(lower[start:end]); err == nil && seconds > 0 && (granted == 0 || seconds < granted) {
					granted = seconds
				}
			}
			offset = max(end, start+1)
		}
	}
	return granted
}

func responseHeaderValues(res *sip.Response, name string) string {
	if res == nil {
		return ""
	}
	values := make([]string, 0, 2)
	for _, header := range res.GetHeaders(name) {
		if value := strings.TrimSpace(header.Value()); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ",")
}

// extractAssociatedMSISDN accepts only typed tel:/sip:/sips: identities with
// an international subscriber number. Bare SIP users and the known IMSI are
// rejected because IMSI-derived IMPUs are not dialable subscriber numbers.
func extractAssociatedMSISDN(res *sip.Response, imsi string) string {
	if res == nil {
		return ""
	}
	for _, header := range res.GetHeaders("P-Associated-URI") {
		for _, identity := range splitAssociatedHeaderValues(header.Value()) {
			if number, ok := normalizeAssociatedIdentity(identity, imsi); ok {
				return number
			}
		}
	}
	return ""
}

func splitAssociatedHeaderValues(value string) []string {
	var values []string
	start := 0
	angleDepth := 0
	quoted := false
	for index, character := range value {
		switch character {
		case '"':
			quoted = !quoted
		case '<':
			if !quoted {
				angleDepth++
			}
		case '>':
			if !quoted && angleDepth > 0 {
				angleDepth--
			}
		case ',':
			if !quoted && angleDepth == 0 {
				values = append(values, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	values = append(values, strings.TrimSpace(value[start:]))
	return values
}

func normalizeAssociatedIdentity(raw, imsi string) (string, bool) {
	value := strings.TrimSpace(raw)
	if left := strings.IndexByte(value, '<'); left >= 0 {
		right := strings.IndexByte(value[left+1:], '>')
		if right < 0 {
			return "", false
		}
		value = strings.TrimSpace(value[left+1 : left+1+right])
	} else {
		value = strings.Trim(value, "<>\"'")
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "tel:"):
		value = value[len("tel:"):]
	case strings.HasPrefix(lower, "sip:"):
		value = value[len("sip:"):]
	case strings.HasPrefix(lower, "sips:"):
		value = value[len("sips:"):]
	default:
		return "", false
	}
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		at := strings.IndexByte(value, '@')
		if at <= 0 || at == len(value)-1 || strings.Contains(value[at+1:], "@") {
			return "", false
		}
		if host := strings.TrimSpace(strings.SplitN(value[at+1:], ";", 2)[0]); host == "" {
			return "", false
		}
		value = value[:at]
	}
	if separator := strings.IndexAny(value, ";?"); separator >= 0 {
		value = value[:separator]
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", false
	}
	number := subscriber.NormalizeMSISDN(decoded, imsi, false)
	return number, number != ""
}

func doRegisterTransaction(ctx context.Context, client *sipgo.Client, req *sip.Request, opts ...sipgo.ClientRequestOption) (*sip.Response, error) {
	txCtx, cancel := context.WithTimeout(ctx, registerTransactionTimeout)
	defer cancel()
	tx, err := client.TransactionRequest(txCtx, req, opts...)
	if err != nil {
		return nil, err
	}
	defer tx.Terminate()
	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			return nil, fmt.Errorf("transaction ended: %w", err)
		}
		return nil, fmt.Errorf("transaction ended without a response")
	case res := <-tx.Responses():
		return res, nil
	case <-txCtx.Done():
		return nil, txCtx.Err()
	}
}

func buildInitialAuthorization(cfg Config, mode string) string {
	authMode := strings.ToLower(strings.TrimSpace(mode))
	if authMode == "" {
		if strings.EqualFold(strings.TrimSpace(cfg.Template.SecAgreeMode), "auto") {
			authMode = "aka_empty_uri_first"
		} else if !cfg.Template.UsePlainDigestPlaceholder {
			authMode = "none"
		} else {
			authMode = "aka_empty_uri_first"
		}
	}
	requestURI := "sip:" + strings.TrimSpace(cfg.HomeDomain)
	username := authorizationUsername(cfg)
	realm := quoteSipParam(strings.TrimSpace(cfg.Realm))
	switch authMode {
	case "none":
		return ""
	case "digest_empty":
		// Match the IMS bootstrap used by the sysmocom VoLTE implementation:
		// do not preselect an AKA algorithm. The home network chooses it in
		// the 401 challenge. Some EE/CTExcel S-CSCFs route a predeclared
		// AKAv1-MD5 placeholder into their unrelated plain-Digest service.
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",response="",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(username),
			realm,
		)
	case "aka_empty":
		return fmt.Sprintf(
			`Digest username="%s",realm="%s",nonce="",uri="%s",response="",algorithm=AKAv1-MD5`,
			quoteSipParam(username),
			realm,
			quoteSipParam(requestURI),
		)
	case "aka_zero_response_uri_first":
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="00000000000000000000000000000000",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(username),
			realm,
		)
	default:
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(username),
			realm,
		)
	}
}

func authorizationUsername(cfg Config) string {
	if v := strings.TrimSpace(cfg.PrivateID); v != "" {
		return v
	}
	imsi := strings.TrimSpace(cfg.IMSI)
	realm := strings.TrimSpace(cfg.Realm)
	if imsi != "" && realm != "" {
		if privateID, _ := voiceclient.BuildIMSIdentity(imsi, realm, strings.TrimSpace(cfg.HomeDomain), "imsi_home_domain"); privateID != "" {
			return privateID
		}
	}
	return ""
}

func buildIMSCoreContact(cfg Config, state registerState, localPort int) string {
	sipInstance := strings.TrimSpace(state.sipInstance)
	if sipInstance == "" {
		sipInstance = strings.TrimSpace(cfg.SIPInstanceURN)
	}
	if sipInstance == "" {
		sipInstance = voiceclient.NewSIPInstanceURN()
	}
	template := cfg.Template
	template.Transport = registerTransportName(cfg, "")
	return policy.BuildIMSContactHeader(template, policy.ContactBuildInput{
		IMSI:               cfg.IMSI,
		PublicURI:          cfg.PublicURI,
		LocalIP:            cfg.LocalIP,
		LocalPort:          localPort,
		SIPInstanceURN:     sipInstance,
		RegisterExpirySecs: cfg.RegisterExpirySeconds,
	})
}

func effectiveRegisterExpiry(cfg Config) int {
	if cfg.RegisterExpirySeconds > 0 {
		return cfg.RegisterExpirySeconds
	}
	if cfg.Template.Expires > 0 {
		return cfg.Template.Expires
	}
	return policy.DefaultRegisterExpires
}

func effectiveSupportedHeader(template policy.IMSRegisterTemplate) string {
	if value := strings.TrimSpace(template.SupportedHeader); value != "" {
		return value
	}
	return policy.DefaultRegisterSupport
}

func effectiveAllowHeader(template policy.IMSRegisterTemplate) string {
	if value := strings.TrimSpace(template.AllowHeader); value != "" {
		return value
	}
	return policy.DefaultRegisterAllow
}

func effectivePANI(template policy.IMSRegisterTemplate) string {
	if value := strings.TrimSpace(template.FixedPANI); value != "" {
		return value
	}
	if strings.EqualFold(strings.TrimSpace(template.ID), "apple_orange_uk") {
		return "IEEE-802.11;country=GB"
	}
	return "IEEE-802.11;i-wlan-node-id=000000000000;network-provided"
}

func encodedICSIRef(template policy.IMSRegisterTemplate) string {
	value := strings.TrimSpace(template.ICSIRef)
	if value == "" {
		value = policy.IMSMmtelICSIRef
	}
	return strings.ReplaceAll(value, ":", "%3A")
}

func registerTransportName(cfg Config, attempt string) string {
	for _, value := range []string{attempt, cfg.Transport, cfg.Template.Transport} {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && value != "auto" {
			return value
		}
	}
	return "tcp"
}

func buildCellularNetworkInfo(cfg Config) string {
	plmn := strings.TrimSpace(cfg.MCC) + strings.TrimLeft(strings.TrimSpace(cfg.MNC), "0")
	if plmn == "" {
		plmn = "00000"
	}
	cell := strings.TrimSpace(cfg.CellID)
	if cell == "" {
		cell = "0000000"
	}
	return fmt.Sprintf("3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=%s%s;cell-info-age=0", plmn, cell)
}

func computeAKAAuth(cfg Config, chal *digest.Challenge, req *sip.Request) (sim.AKAResult, string, error) {
	algorithm := strings.TrimSpace(chal.Algorithm)
	if algorithm == "" || strings.EqualFold(algorithm, "MD5") {
		// Use a fail-closed rule: ordinary MD5 is not IMS AKA and this
		// client has no carrier-provisioned subscriber password. Never invent a
		// password from USIM GSM material or silently send an empty password.
		return sim.AKAResult{}, "", fmt.Errorf("IMS registrar returned ordinary MD5 instead of AKAv1-MD5")
	}

	// 先执行 AKA 计算，再将其结果用于 digest（IMSCORE-4 修复：避免双重 AKA 计算）
	akaResult, err := akaResultFromChallenge(cfg.AKA, chal)
	if err != nil && !errors.Is(err, sim.ErrSyncFailure) {
		return sim.AKAResult{}, "", fmt.Errorf("AKA calculation: %w", err)
	}

	// 使用 AKA 结果 (RES) 作为密码构建 digest response，不重新计算 AKA
	result, err := simauth.ComputeDigestWithAKA(cfg.AKA, chal, digest.Options{
		Method:   req.Method.String(),
		URI:      req.Recipient.String(),
		Username: cfg.PrivateID,
	}, akaResult, err)
	if err != nil {
		akaResult.Zero() // 清零敏感数据
		return sim.AKAResult{}, "", err
	}

	// 调用方负责在使用完毕后调用 akaResult.Zero()
	return akaResult, result.Header, nil
}

func akaResultFromChallenge(provider sim.AKAProvider, chal *digest.Challenge) (sim.AKAResult, error) {
	if provider == nil {
		return sim.AKAResult{}, fmt.Errorf("AKA provider required")
	}
	rawNonce, err := simauth.DecodeNonceBytes(chal.Nonce)
	if err != nil {
		return sim.AKAResult{}, err
	}
	if len(rawNonce) < 32 {
		return sim.AKAResult{}, fmt.Errorf("nonce too short for RAND||AUTN")
	}
	return provider.CalculateAKA(rawNonce[:16], rawNonce[16:32])
}

func selectDigestChallenge(cfg Config, res *sip.Response) (*digest.Challenge, error) {
	headers := res.GetHeaders("WWW-Authenticate")
	if len(headers) == 0 && res.StatusCode == sip.StatusProxyAuthRequired {
		headers = res.GetHeaders("Proxy-Authenticate")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("%d response with no authenticate header", res.StatusCode)
	}
	for _, header := range headers {
		chal, err := digest.ParseChallenge(header.Value())
		if err == nil {
			return chal, nil
		}
	}
	return nil, fmt.Errorf("parse challenge failed")
}

func quoteSipParam(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

func registerSIPLocalPort(cfg Config) int {
	return registerAttemptLocalPort(cfg, 0)
}

func registerAttemptLocalPort(cfg Config, attemptIndex int) int {
	if attemptIndex == 0 && cfg.LocalPort > 0 && cfg.LocalPort <= 65535 {
		return cfg.LocalPort
	}
	if attemptIndex > 0 || !registrarHostEqualsLocalIP(cfg.PCSCFAddr, cfg.LocalIP) {
		return randomEphemeralSIPPort()
	}
	return 5060
}

func randomEphemeralSIPPort() int {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(50000))
		if err != nil {
			return 5062
		}
		port := 10000 + int(n.Int64())
		if port != 5060 && port != 5061 {
			return port
		}
	}
}

func randomNonZeroUint32() uint32 {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(1<<32-1))
		if err != nil {
			return 0xc0ffee01
		}
		if v := uint32(n.Int64()) + 1; v != 0 {
			return v
		}
	}
}
