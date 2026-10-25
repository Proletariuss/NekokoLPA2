package imscore

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/policy"
)

func TestInternalConfigFromIMSCarriesRuntimeTuning(t *testing.T) {
	tmpl := policy.DefaultGiffgaffTemplate()
	tmpl.Expires = 600000
	tmpl.Transport = "tcp"
	cfg := internalConfigFromIMS(IMSConfig{
		PCSCF:                      "192.0.2.10:5060",
		IMSRegisterTemplate:        tmpl,
		LocalPort:                  5070,
		Transport:                  "auto",
		TCPKeepaliveSeconds:        30,
		OptionsPingIntervalSeconds: 45,
	}, StartSessionInput{})
	if cfg.LocalPort != 5070 || cfg.Transport != "tcp" {
		t.Fatalf("local_port=%d transport=%q", cfg.LocalPort, cfg.Transport)
	}
	if cfg.TCPKeepaliveSeconds != 30 || cfg.OptionsPingIntervalSeconds != 45 {
		t.Fatalf("keepalive=%d options=%d", cfg.TCPKeepaliveSeconds, cfg.OptionsPingIntervalSeconds)
	}
	if cfg.RegisterExpirySeconds != 600000 {
		t.Fatalf("expires=%d", cfg.RegisterExpirySeconds)
	}
}

func TestSecAgreeRequiredRejectsMissingSecurityServer(t *testing.T) {
	res := sip.NewResponse(sip.StatusOK, "OK")
	cfg := Config{Template: policy.IMSRegisterTemplate{SecAgreeMode: "required"}}
	if _, err := decideInitialRegisterSuccessSecurity(cfg, res); err == nil {
		t.Fatal("required sec-agree accepted initial 200 without Security-Server")
	}

	challenge := sip.NewResponse(sip.StatusUnauthorized, "Unauthorized")
	if _, err := decideSecAgreeAfterChallenge(cfg, challenge); err == nil {
		t.Fatal("required sec-agree accepted challenge without Security-Server")
	}
}

func TestSecAgreeAutoDowngradesWithoutSecurityServer(t *testing.T) {
	res := sip.NewResponse(sip.StatusOK, "OK")
	cfg := Config{Template: policy.IMSRegisterTemplate{SecAgreeMode: "auto"}}
	decision, err := decideInitialRegisterSuccessSecurity(cfg, res)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.plainOK || decision.requireIPSec {
		t.Fatalf("initial decision = %+v", decision)
	}

	challenge := sip.NewResponse(sip.StatusUnauthorized, "Unauthorized")
	authDecision, err := decideSecAgreeAfterChallenge(cfg, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if authDecision.installIPSec || authDecision.reason != "security_server_missing_auto_disable" {
		t.Fatalf("challenge decision = %+v", authDecision)
	}
}

func TestSecurityVerifyPreservesExactServerOffer(t *testing.T) {
	raw := "ipsec-3gpp;q=0.9;alg=hmac-sha-1-96;mod=trans;ealg=null," +
		"ipsec-3gpp;q=1.0;alg=hmac-sha-1-96;mod=trans;prot=esp;ealg=aes-cbc;spi-c=111060141;spi-s=117229022;port-c=6050;port-s=6060"
	res := sip.NewResponse(sip.StatusUnauthorized, "Unauthorized")
	res.AppendHeader(sip.NewHeader("Security-Server", raw))
	tmpl := policy.DefaultGiffgaffTemplate()
	verify, selected, err := buildSecurityVerifyFromChallenge(Config{Template: tmpl}, res)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil || verify != raw {
		t.Fatalf("verify = %q, selected = %#v", verify, selected)
	}
}

func TestRegisterPolicyStatusOverrides(t *testing.T) {
	cfg := Config{Template: policy.IMSRegisterTemplate{RegisterPolicy: policy.IMSRegisterPolicy{
		TemporaryStatusCodes:  []int{429},
		ForbiddenStatusCodes:  []int{404},
		TemporaryRetrySeconds: 60,
	}}}
	if !isTemporaryRegisterSIPResponse(cfg, 429) || isTemporaryRegisterSIPResponse(cfg, sip.StatusServiceUnavailable) {
		t.Fatal("temporary status-code replacement was not honored")
	}
	if !isForbiddenRegisterSIPResponse(cfg, 404) || isForbiddenRegisterSIPResponse(cfg, sip.StatusForbidden) {
		t.Fatal("forbidden status-code replacement was not honored")
	}
	if got := registerPolicyRetryDelay(cfg, 429); got != 60*time.Second {
		t.Fatalf("retry delay = %s", got)
	}
	if !shouldAdvanceRegistrarForNextRetry(cfg, 429, "rate limited", true) {
		t.Fatal("configured temporary response did not advance registrar")
	}
}

func TestRegisterPolicyExplicitEmptyStatusListsDisableDefaults(t *testing.T) {
	cfg := Config{Template: policy.IMSRegisterTemplate{
		EnableInitialRejectFallback: true,
		RegisterPolicy: policy.IMSRegisterPolicy{
			TemporaryStatusCodes:             make([]int, 0),
			ForbiddenStatusCodes:             make([]int, 0),
			InitialRejectFallbackStatusCodes: make([]int, 0),
		},
	}}
	if isTemporaryRegisterSIPResponse(cfg, sip.StatusServiceUnavailable) {
		t.Fatal("explicit empty temporary list restored the default")
	}
	if isForbiddenRegisterSIPResponse(cfg, sip.StatusForbidden) {
		t.Fatal("explicit empty forbidden list restored the default")
	}
	if shouldRetryInitialRegisterForStatus(cfg, sip.StatusForbidden) {
		t.Fatal("explicit empty fallback list restored the default 403")
	}
}

type captureIMSNetwork struct {
	localPort int
	transport string
	opts      DialOptions
	peer      net.Conn
}

func (n *captureIMSNetwork) DialContext(ctx context.Context, network string, addr net.Addr, transport string, opts DialOptions) (net.Conn, error) {
	n.localPort, _ = ctx.Value(localPortContextKey{}).(int)
	n.transport = transport
	n.opts = opts
	client, peer := net.Pipe()
	n.peer = peer
	return client, nil
}

func (n *captureIMSNetwork) HasLocalIP([]byte) bool { return true }
func (n *captureIMSNetwork) ListenPacket(context.Context, string, net.Addr) (net.PacketConn, error) {
	return nil, nil
}
func (n *captureIMSNetwork) ListenTCP(context.Context, *net.TCPAddr) (net.Listener, error) {
	return nil, nil
}
func (n *captureIMSNetwork) LocalIP() []byte { return net.ParseIP("192.0.2.1") }
func (n *captureIMSNetwork) ResolveIP(context.Context, string, bool) ([]byte, error) {
	return net.ParseIP("192.0.2.2"), nil
}

func TestDialRegisterConnUsesLocalPortAndTCPKeepalive(t *testing.T) {
	network := &captureIMSNetwork{}
	cfg := Config{
		LocalIP:             net.ParseIP("192.0.2.1"),
		PCSCFAddr:           "192.0.2.2:5060",
		LocalPort:           5070,
		Transport:           "tcp",
		TCPKeepaliveSeconds: 30,
		Template:            policy.DefaultGiffgaffTemplate(),
	}
	session := newRegisterSession(cfg, nil, network, "tcp", 0)
	conn, err := session.dialRegisterConn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer network.peer.Close()
	if network.localPort != 5070 || network.transport != "tcp" {
		t.Fatalf("local_port=%d transport=%q", network.localPort, network.transport)
	}
	if network.opts.KeepAlive != int64(30*time.Second) {
		t.Fatalf("keepalive=%d", network.opts.KeepAlive)
	}
}

func TestBuildOptionsPingUsesSecurePortAndStableTransactionFields(t *testing.T) {
	payload, err := buildOptionsPing(Config{
		LocalIP:        net.ParseIP("2001:db8::10"),
		PCSCFAddr:      "[2001:db8::20]:5060",
		HomeDomain:     "ims.example.test",
		PublicURI:      "sip:310260123456789@ims.example.test",
		UserAgent:      "iphone15,4",
		SecurityVerify: "ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc",
	}, ipsec3gpp.Policy{LocalPortC: 5064}, "options-call-id", 77)
	if err != nil {
		t.Fatal(err)
	}
	got := string(payload)
	for _, want := range []string{
		"OPTIONS sip:[2001:db8::20]:5060 SIP/2.0",
		"Via: SIP/2.0/TCP [2001:db8::10]:5064",
		"Call-ID: options-call-id",
		"CSeq: 77 OPTIONS",
		"Route: <sip:[2001:db8::20]:5060;lr>",
		"Content-Length: 0",
		"Security-Verify: ipsec-3gpp;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("OPTIONS payload %q missing %q", got, want)
		}
	}
}
