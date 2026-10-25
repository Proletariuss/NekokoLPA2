package imscore

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/policy"
)

func udpTestSocket(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func udpReadMessage(t *testing.T, c *net.UDPConn) (sip.Message, *net.UDPAddr) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 65536)
	n, addr, err := c.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sip.ParseMessage(b[:n])
	if err != nil {
		t.Fatal(err)
	}
	return m, addr
}

func udpWriteMessage(t *testing.T, c *net.UDPConn, dest net.Addr, m sip.Message) {
	t.Helper()
	if _, err := c.WriteTo([]byte(m.String()), dest); err != nil {
		t.Fatal(err)
	}
}

func udpTestRequest(t *testing.T, method sip.RequestMethod, id string) *sip.Request {
	t.Helper()
	wire := fmt.Sprintf("%s sip:user@ims.example.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK%s\r\nFrom: <sip:peer@ims.example.test>;tag=peer\r\nTo: <sip:user@ims.example.test>\r\nCall-ID: %s\r\nCSeq: 1 %s\r\nContent-Length: 0\r\n\r\n", method, id, id, method)
	m, err := sip.ParseMessage([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	r := m.(*sip.Request)
	r.SetTransport("UDP")
	return r
}

func TestUDPClientRetransmitMatchingAndCancellation(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			server, local, attacker := udpTestSocket(t, ip), udpTestSocket(t, ip), udpTestSocket(t, ip)
			e := newUDPSIPEndpoint(local, server.LocalAddr().(*net.UDPAddr))
			defer e.Close()
			request := udpTestRequest(t, sip.MESSAGE, "outgoing")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := e.sendRequest(ctx, request); err != nil {
				t.Fatal(err)
			}
			first, addr := udpReadMessage(t, server)
			repeated, _ := udpReadMessage(t, server)
			if first.String() != repeated.String() {
				t.Fatal("retransmission changed transaction")
			}
			response := sip.NewResponseFromRequest(first.(*sip.Request), 200, "OK", nil)
			udpWriteMessage(t, attacker, addr, response)
			wrong := response.Clone()
			wrong.CSeq().SeqNo++
			udpWriteMessage(t, server, addr, wrong)
			wrong = response.Clone()
			wrong.Via().Params.Add("branch", "z9hG4bKwrong")
			udpWriteMessage(t, server, addr, wrong)
			wrong = response.Clone()
			wrong.RemoveHeader("Call-ID")
			wrong.AppendHeader(sip.NewHeader("Call-ID", "wrong"))
			udpWriteMessage(t, server, addr, wrong)
			select {
			case <-e.messages:
				t.Fatal("accepted wrong source/transaction")
			case <-time.After(50 * time.Millisecond):
			}
			udpWriteMessage(t, server, addr, response)
			select {
			case got := <-e.messages:
				if got.(*sip.Response).StatusCode != 200 {
					t.Fatal(got)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			udpWriteMessage(t, server, addr, response)
			select {
			case <-e.messages:
				t.Fatal("duplicate response escaped transaction")
			case <-time.After(40 * time.Millisecond):
			}
			cancelCtx, stop := context.WithCancel(context.Background())
			if err := e.sendRequest(cancelCtx, udpTestRequest(t, sip.OPTIONS, "cancelled")); err != nil {
				t.Fatal(err)
			}
			_, _ = udpReadMessage(t, server)
			stop()
			deadline := time.Now().Add(time.Second)
			for {
				e.mu.Lock()
				_, exists := e.clients["z9hG4bKcancelled"+sip.TxSeperator+"OPTIONS"]
				e.mu.Unlock()
				if !exists {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("cancelled transaction retained")
				}
				time.Sleep(time.Millisecond)
			}
			done := make(chan struct{})
			go func() { _ = e.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("UDP close failed to wake worker")
			}
		})
	}
}

func TestUDPDatagramBoundariesAndIncomingDedup(t *testing.T) {
	server, local := udpTestSocket(t, "127.0.0.1"), udpTestSocket(t, "127.0.0.1")
	e := newUDPSIPEndpoint(local, server.LocalAddr().(*net.UDPAddr))
	defer e.Close()
	request := udpTestRequest(t, sip.MESSAGE, "incoming")
	request.SetBody([]byte("payload"))
	wire := []byte(request.String())
	_, _ = server.WriteTo(wire[:len(wire)-3], local.LocalAddr())
	_, _ = server.WriteTo(wire[len(wire)-3:], local.LocalAddr())
	select {
	case <-e.requests:
		t.Fatal("partial datagrams were accepted")
	case <-time.After(40 * time.Millisecond):
	}
	udpWriteMessage(t, server, local.LocalAddr(), request)
	msg := <-e.requests
	respond, fresh := e.incomingRequest(msg)
	if !fresh {
		t.Fatal("new request suppressed")
	}
	if err := respond(sip.NewResponseFromRequest(msg, 200, "OK", nil)); err != nil {
		t.Fatal(err)
	}
	first, _ := udpReadMessage(t, server)
	udpWriteMessage(t, server, local.LocalAddr(), request)
	msg = <-e.requests
	if _, fresh := e.incomingRequest(msg); fresh {
		t.Fatal("duplicate MESSAGE dispatched")
	}
	second, _ := udpReadMessage(t, server)
	if first.String() != second.String() {
		t.Fatal("duplicate MESSAGE did not reuse response")
	}
}

type udpRegisterNetwork struct {
	captureIMSNetwork
	mu        sync.Mutex
	packets   map[int]*net.UDPConn
	installed *ipsec3gpp.Transport
	ip        string
}

func (n *udpRegisterNetwork) ListenPacket(ctx context.Context, network string, addr net.Addr) (net.PacketConn, error) {
	if network != "udp" {
		return nil, fmt.Errorf("unexpected network %s", network)
	}
	packet, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(n.ip)})
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.packets[addr.(*net.UDPAddr).Port] = packet
	n.mu.Unlock()
	return packet, nil
}
func (n *udpRegisterNetwork) InstallIPSec(transport *ipsec3gpp.Transport) error {
	n.mu.Lock()
	n.installed = transport
	n.mu.Unlock()
	return nil
}
func (n *udpRegisterNetwork) packet(port int) *net.UDPConn {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.packets[port]
}

// This test exercises the complete REGISTER/AKA/runtime lifecycle on actual
// UDP sockets. Crypto is independently tested at the transforming dataplane;
// the fake network records installation and preserves negotiated port intent.
func TestUDPRegisterAKAProtectedRuntime(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			initial, remoteS, remoteC := udpTestSocket(t, ip), udpTestSocket(t, ip), udpTestSocket(t, ip)
			network := &udpRegisterNetwork{ip: ip, packets: make(map[int]*net.UDPConn)}
			cfg := Config{Transport: "udp", LocalIP: net.ParseIP(ip), PCSCFAddr: initial.LocalAddr().String(), HomeDomain: "ims.example.test", Realm: "ims.example.test", PrivateID: "user@ims.example.test", PublicURI: "sip:user@ims.example.test", AKA: &recordingAKAProvider{}, Template: policy.DefaultIMSRegisterTemplate()}
			cfg.Template.Transport = "udp"
			session := newRegisterSession(cfg, &registerLifecycleDialer{}, network, "udp", 0)
			session.jitter = false
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			type outcome struct {
				result *registerResult
				err    error
			}
			finished := make(chan outcome, 1)
			go func() { result, err := session.runInitialRegisterFlow(ctx); finished <- outcome{result, err} }()
			m, addr := udpReadMessage(t, initial)
			first := m.(*sip.Request)
			if first.Transport() != "UDP" || !strings.Contains(first.GetHeader("Contact").Value(), "transport=udp") {
				t.Fatal("initial REGISTER did not advertise UDP")
			}
			challenge := sip.NewResponseFromRequest(first, 401, "Unauthorized", nil)
			challenge.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest realm="ims.example.test",nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`",algorithm=AKAv1-MD5,qop="auth"`))
			challenge.AppendHeader(sip.NewHeader("Security-Server", fmt.Sprintf("ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;spi-c=111;spi-s=222;port-c=%d;port-s=%d", remoteC.LocalAddr().(*net.UDPAddr).Port, remoteS.LocalAddr().(*net.UDPAddr).Port)))
			udpWriteMessage(t, initial, addr, challenge)
			m, protectedAddr := udpReadMessage(t, remoteS)
			auth := m.(*sip.Request)
			if auth.Transport() != "UDP" || auth.CSeq().SeqNo <= first.CSeq().SeqNo || auth.GetHeader("Authorization") == nil || auth.GetHeader("Security-Verify") == nil || !strings.Contains(auth.GetHeader("Route").Value(), "transport=udp") {
				t.Fatalf("invalid protected REGISTER: %s", auth.String())
			}
			if network.packet(5063) == nil || network.packet(5064) == nil {
				t.Fatal("secure REGISTER sent before dual ports were bound")
			}
			udpWriteMessage(t, remoteS, protectedAddr, sip.NewResponseFromRequest(auth, 200, "OK", nil))
			var result *registerResult
			select {
			case done := <-finished:
				if done.err != nil {
					t.Fatal(done.err)
				}
				result = done.result
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			defer result.secureConn.Close()
			if result.transport == nil || network.installed == nil {
				t.Fatal("IPsec installation bypassed")
			}
			var incoming atomic.Int32
			cfg.IncomingSIPRequest = func(*sip.Request) { incoming.Add(1) }
			rt, err := startTransportRuntime(ctx, cfg, &registerLifecycleDialer{}, result.ipsecPolicy, result.transport, result.secureConn)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close()
			for _, method := range []sip.RequestMethod{sip.MESSAGE, sip.OPTIONS} {
				req := udpTestRequest(t, method, string(method))
				for repeat := 0; repeat < 2; repeat++ {
					udpWriteMessage(t, remoteC, network.packet(5063).LocalAddr(), req)
					response, _ := udpReadMessage(t, remoteC)
					if response.(*sip.Response).StatusCode != 200 {
						t.Fatal(response)
					}
				}
			}
			if incoming.Load() != 2 {
				t.Fatalf("callbacks including duplicates=%d", incoming.Load())
			}
			if !rt.incomingPortSDiagnostics().listenerStarted || rt.incomingPortSDiagnostics().reachability != "observed" {
				t.Fatal("UDP Port-S diagnostics missing")
			}
			refresh, err := buildRegistrationRefresh(cfg, result.request, rt, true)
			if err != nil {
				t.Fatal(err)
			}
			refreshDone := make(chan error, 1)
			go func() { _, err := rt.exchangeRegistrationRefresh(ctx, refresh); refreshDone <- err }()
			m, addr = udpReadMessage(t, remoteS)
			if m.(*sip.Request).Transport() != "UDP" {
				t.Fatal("refresh switched to TCP")
			}
			udpWriteMessage(t, remoteS, addr, sip.NewResponseFromRequest(m.(*sip.Request), 200, "OK", nil))
			if err := <-refreshDone; err != nil {
				t.Fatal(err)
			}
			optionsDone := make(chan error, 1)
			go func() { _, err := rt.sendOptionsPing(ctx, 17); optionsDone <- err }()
			m, addr = udpReadMessage(t, remoteS)
			if m.(*sip.Request).Transport() != "UDP" || m.(*sip.Request).Method != sip.OPTIONS {
				t.Fatal("OPTIONS switched transport")
			}
			udpWriteMessage(t, remoteS, addr, sip.NewResponseFromRequest(m.(*sip.Request), 200, "OK", nil))
			if err := <-optionsDone; err != nil {
				t.Fatal(err)
			}
			service := &Service{cfg: cfg, transportRuntime: rt, verifyHeader: result.verifyHeader}
			sms, err := service.buildSMSMessage("sip:smsc@ims.example.test", "udp-sms", 1, []byte{1, 2, 3})
			if err != nil {
				t.Fatal(err)
			}
			calls := newCallRuntime(service)
			invite, err := calls.buildRequest(sip.INVITE, "+1234567890", "udp-call", 1, []byte("v=0\r\n"))
			if err != nil {
				t.Fatal(err)
			}
			for _, payload := range [][]byte{sms, invite} {
				if err := rt.enqueueWrite(ctx, payload); err != nil {
					t.Fatal(err)
				}
				m, addr = udpReadMessage(t, remoteS)
				if m.(*sip.Request).Transport() != "UDP" {
					t.Fatal("SMS/call used TCP")
				}
				udpWriteMessage(t, remoteS, addr, sip.NewResponseFromRequest(m.(*sip.Request), 200, "OK", nil))
			}
		})
	}
}

func TestUDPInvite2xxRetransmissionAndACK(t *testing.T) {
	server, local := udpTestSocket(t, "127.0.0.1"), udpTestSocket(t, "127.0.0.1")
	e := newUDPSIPEndpoint(local, server.LocalAddr().(*net.UDPAddr))
	defer e.Close()
	invite := udpTestRequest(t, sip.INVITE, "invite")
	respond, fresh := e.incomingRequest(invite)
	if !fresh {
		t.Fatal("INVITE suppressed")
	}
	response := sip.NewResponseFromRequest(invite, 200, "OK", nil)
	response.To().Params.Add("tag", "local")
	if err := respond(response); err != nil {
		t.Fatal(err)
	}
	first, _ := udpReadMessage(t, server)
	repeated, _ := udpReadMessage(t, server)
	if first.String() != repeated.String() {
		t.Fatal("2xx retransmission changed response")
	}
	ack := invite.Clone()
	ack.Method = sip.ACK
	ack.CSeq().MethodName = sip.ACK
	ack.Via().Params.Add("branch", "z9hG4bKnew-ack")
	ack.To().Params.Add("tag", "local")
	e.incomingRequest(ack)
	e.mu.Lock()
	count := len(e.accepted)
	e.mu.Unlock()
	if count != 0 {
		t.Fatal("ACK did not stop accepted INVITE retransmission")
	}
}

func TestUDPOutgoingInviteCachesACKForLostACK(t *testing.T) {
	server, local := udpTestSocket(t, "127.0.0.1"), udpTestSocket(t, "127.0.0.1")
	e := newUDPSIPEndpoint(local, server.LocalAddr().(*net.UDPAddr))
	defer e.Close()
	request := udpTestRequest(t, sip.INVITE, "outgoing-invite")
	if err := e.sendRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	m, addr := udpReadMessage(t, server)
	response := sip.NewResponseFromRequest(m.(*sip.Request), 200, "OK", nil)
	response.To().Params.Add("tag", "remote")
	udpWriteMessage(t, server, addr, response)
	select {
	case <-e.messages:
	case <-time.After(time.Second):
		t.Fatal("INVITE response missing")
	}
	ack := request.Clone()
	ack.Method = sip.ACK
	ack.CSeq().MethodName = sip.ACK
	ack.To().Params.Add("tag", "remote")
	ack.Via().Params.Add("branch", "z9hG4bKdialog-ack")
	if err := e.sendRequest(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	first, _ := udpReadMessage(t, server)
	udpWriteMessage(t, server, addr, response)
	repeated, _ := udpReadMessage(t, server)
	if first.String() != repeated.String() {
		t.Fatal("lost ACK was not retransmitted")
	}
}

func TestUDPRegisterWaitCancellationAndMalformedLengths(t *testing.T) {
	server, local := udpTestSocket(t, "127.0.0.1"), udpTestSocket(t, "127.0.0.1")
	e := newUDPSIPEndpoint(local, server.LocalAddr().(*net.UDPAddr))
	defer e.Close()
	transport := newConnRegisterTransport(e, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := transport.Send(ctx, udpTestRequest(t, sip.REGISTER, "timeout")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := transport.ReadResponse(ctx); err != context.DeadlineExceeded {
		t.Fatalf("cancel error=%v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("registration cancellation did not wake")
	}
	for _, length := range []string{"4294967295", "-1", "bogus"} {
		wire := strings.Replace(udpTestRequest(t, sip.MESSAGE, "malformed").String(), "Content-Length: 0", "Content-Length: "+length, 1)
		if _, err := parseSIPDatagram([]byte(wire)); err == nil {
			t.Fatal("malformed Content-Length accepted")
		}
	}
	if _, err := listenSIPUDP(context.Background(), Config{}, nil, nil, 5060, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 5060}); err == nil {
		t.Fatal("UDP fell back to OS network")
	}
}

func TestUDPPlainTunnelRegistrationPreparesPortS(t *testing.T) {
	server := udpTestSocket(t, "127.0.0.1")
	network := &udpRegisterNetwork{ip: "127.0.0.1", packets: make(map[int]*net.UDPConn)}
	cfg := Config{Transport: "udp", LocalIP: net.IPv4(127, 0, 0, 1), PCSCFAddr: server.LocalAddr().String(), HomeDomain: "ims.example.test", Realm: "ims.example.test", PrivateID: "test@ims.example.test", PublicURI: "sip:test@ims.example.test", AKA: &recordingAKAProvider{}, Template: policy.DefaultGiffgaffTemplate()}
	cfg.Template.AllowPlainIMS = true
	cfg.Template.SecAgreeMode = "disabled"
	session := newRegisterSession(cfg, &registerLifecycleDialer{}, network, "udp", 0)
	session.jitter = false
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan *registerResult, 1)
	failed := make(chan error, 1)
	go func() {
		reg, err := session.runInitialRegisterFlow(ctx)
		if err != nil {
			failed <- err
			return
		}
		result <- reg
	}()
	m, addr := udpReadMessage(t, server)
	if network.packet(5063) == nil {
		t.Fatal("plain UDP REGISTER advertised an unbound Port-S")
	}
	udpWriteMessage(t, server, addr, sip.NewResponseFromRequest(m.(*sip.Request), 200, "OK", nil))
	select {
	case err := <-failed:
		t.Fatal(err)
	case reg := <-result:
		if reg.secureConn != nil || reg.plainConn == nil {
			t.Fatal("plain tunnel incorrectly became IPsec")
		}
		endpoint := reg.plainConn.(*udpSIPEndpoint)
		if endpoint.portS == nil {
			t.Fatal("Port-S ownership was lost")
		}
		if err := reg.plainConn.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := network.packet(5063).WriteTo([]byte("closed"), server.LocalAddr()); err == nil {
			t.Fatal("Port-S leaked after close")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
