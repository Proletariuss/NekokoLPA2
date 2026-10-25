package imscore

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	imsPolicy "proletarius.local/core/internal/vowifi/policy"
)

type teardownReadConn struct {
	net.Conn
	once      sync.Once
	reading   chan struct{}
	writeOnce sync.Once
	writing   chan struct{}
}

func (c *teardownReadConn) Write(p []byte) (int, error) {
	if c.writing != nil {
		c.writeOnce.Do(func() { close(c.writing) })
	}
	return c.Conn.Write(p)
}

func TestServiceCloseDrainsAcceptedPortS(t *testing.T) {
	for _, mode := range []string{"secure", "plain"} {
		for _, blocked := range []string{"read", "write"} {
			t.Run(mode+"/"+blocked, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				portC, portCPeer := net.Pipe()
				defer portCPeer.Close()
				portS, portSPeer := net.Pipe()
				defer portSPeer.Close()
				conn := &teardownReadConn{Conn: portS, reading: make(chan struct{}), writing: make(chan struct{})}
				listener := newQueuedPortSListener()
				policy, transport := runtimeTestPolicy(t)
				cfg := Config{LocalIP: net.ParseIP("192.0.2.10"), PCSCFAddr: "192.0.2.20:5060"}
				if mode == "plain" {
					transport = nil
					cfg.Template = imsPolicy.IMSRegisterTemplate{AllowPlainIMS: true, SecAgreeMode: "disabled"}
				}
				rt, err := startTransportRuntime(ctx, cfg, &runtimeTestDialer{}, policy, transport, portC, listener)
				if err != nil {
					t.Fatal(err)
				}
				defer rt.Close()
				svc := &Service{started: true, registered: true, lifecycleCtx: ctx, lifecycleCancel: cancel, transportRuntime: rt}
				listener.accepted <- conn
				select {
				case <-conn.reading:
				case <-time.After(time.Second):
					t.Fatal("accepted Port-S was not read")
				}
				if blocked == "write" {
					request := "OPTIONS sip:ims.example.test SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.20:6060;branch=z9hG4bKstop\r\nFrom: <sip:a@ims.example.test>;tag=one\r\nTo: <sip:b@ims.example.test>\r\nCall-ID: stop-test\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
					portSPeer.SetWriteDeadline(time.Now().Add(time.Second))
					if _, err := portSPeer.Write([]byte(request)); err != nil {
						t.Fatal(err)
					}
					// The peer deliberately never reads the OPTIONS response.
					select {
					case <-conn.writing:
					case <-time.After(time.Second):
						t.Fatal("Port-S response did not start")
					}
				}
				closed := make(chan error, 1)
				go func() { closed <- svc.Close(context.Background()) }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					portS.Close()
					<-closed
					t.Fatal("Service.Close did not drain accepted Port-S")
				}
				if svc.MessagingReady() || rt.Healthy() {
					t.Fatal("closed service remains ready")
				}
			})
		}
	}
}

func (c *teardownReadConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}

// A carrier can keep its accepted Port-S connection open without sending any
// more SIP. Closing the listening socket does not close that accepted socket.
func TestRuntimeCloseUnblocksIdleAcceptedPortS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	defer local.Close()
	conn := &teardownReadConn{Conn: local, reading: make(chan struct{})}
	rt := &transportRuntime{cancel: cancel}
	rt.wg.Add(1)
	go rt.drainInboundPortS(ctx, conn)
	select {
	case <-conn.reading:
	case <-time.After(time.Second):
		t.Fatal("Port-S did not start reading")
	}
	closed := make(chan struct{})
	go func() { rt.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		// Release the old implementation's blocked reader before failing.
		local.Close()
		<-closed
		t.Fatal("Close blocked on an idle accepted Port-S connection")
	}
}

func TestMissingOptionalRuntimeReleasesLifecycleLease(t *testing.T) {
	ctx := context.Background()
	operations := map[string]func(*Service){
		"CallStatus":      func(s *Service) { s.CallStatus() },
		"DialCall":        func(s *Service) { s.DialCall(ctx, "123") },
		"AnswerCall":      func(s *Service) { s.AnswerCall(ctx) },
		"RejectCall":      func(s *Service) { s.RejectCall() },
		"HangupCall":      func(s *Service) { s.HangupCall(ctx) },
		"SendCallDTMF":    func(s *Service) { s.SendCallDTMF(ctx, "1") },
		"DialFax":         func(s *Service) { s.DialFax(ctx, "123", false) },
		"StartFaxMedia":   func(s *Service) { s.StartFaxMedia(ctx, nil) },
		"WriteFaxUDPTL":   func(s *Service) { s.WriteFaxUDPTL(nil) },
		"WriteFaxRTP":     func(s *Service) { s.WriteFaxRTP(nil) },
		"RunFaxMediaLoop": func(s *Service) { s.RunFaxMediaLoop(ctx, nil) },
		"HangupFax":       func(s *Service) { s.HangupFax(ctx) },
		"FaxSnapshot":     func(s *Service) { s.FaxSnapshot() },
		"SendUSSD":        func(s *Service) { s.SendUSSD(ctx, "*123#") },
		"ContinueUSSD":    func(s *Service) { s.ContinueUSSD(ctx, "", "") },
		"CancelUSSD":      func(s *Service) { s.CancelUSSD(ctx, "") },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			rt := &transportRuntime{}
			rt.healthy.Store(true)
			s := &Service{started: true, registered: true, ipsecInstalled: true, transportRuntime: rt}
			operation(s)
			if !s.operationMu.TryLock() {
				t.Fatal("missing runtime leaked the lifecycle lease and would block Close")
			}
			s.operationMu.Unlock()
			if err := s.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRefreshUnavailableRuntimeReleasesLifecycleLease(t *testing.T) {
	for _, rt := range []*transportRuntime{nil, {}} {
		svc := &Service{started: true, transportRuntime: rt}
		if _, err := svc.RefreshRegistration(context.Background()); err == nil {
			t.Fatal("refresh accepted unavailable transport")
		}
		if !svc.operationMu.TryLock() {
			t.Fatal("unavailable refresh transport leaked lifecycle lease")
		}
		svc.operationMu.Unlock()
	}
}

func TestRuntimeCloseWaitsForActivePortCParser(t *testing.T) {
	portC, peer := net.Pipe()
	defer peer.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	policy, transport := runtimeTestPolicy(t)
	rt, err := startTransportRuntime(context.Background(), Config{
		IncomingSIPHandler: func(_ *sip.Request, _ SIPResponder) { close(entered); <-release },
	}, &runtimeTestDialer{listener: newBlockingTCPListener()}, policy, transport, portC)
	if err != nil {
		t.Fatal(err)
	}
	request := "ACK sip:ims.example.test SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.20:6060;branch=z9hG4bKstop\r\nFrom: <sip:a@ims.example.test>;tag=one\r\nTo: <sip:b@ims.example.test>\r\nCall-ID: parser-stop-test\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
	peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Port-C callback did not start")
	}
	closed := make(chan struct{})
	go func() { rt.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while SIP callback was active")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close failed to drain Port-C parser")
	}
}
