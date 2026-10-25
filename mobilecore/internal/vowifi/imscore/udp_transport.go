package imscore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

func runSecureUDPRegister(ctx context.Context, cfg Config, swu voiceclient.SWUTCPDialer, state *registerState, request *sip.Request, networks ...IMSNetwork) (*registerResult, error) {
	if state.transport == nil {
		return nil, fmt.Errorf("SIP UDP requires installed ipsec-3gpp transform")
	}
	var network IMSNetwork
	if len(networks) > 0 {
		network = networks[0]
	}
	policy := state.ipsecPolicy
	portC, err := listenSIPUDP(context.Background(), cfg, network, swu, policy.LocalPortC, &net.UDPAddr{IP: net.IP(policy.RemoteIP), Port: policy.RemotePortS})
	if err != nil {
		return nil, err
	}
	portS, err := listenSIPUDP(context.Background(), cfg, network, swu, policy.LocalPortS, &net.UDPAddr{IP: net.IP(policy.RemoteIP), Port: policy.RemotePortC})
	if err != nil {
		_ = portC.Close()
		return nil, err
	}
	portC.portS = portS
	adapter := newConnRegisterTransport(portC, cfg.TraceID, cfg.DeviceID)
	defer adapter.Close()
	response, err := runRegisterTransaction(ctx, cfg, adapter, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != sip.StatusOK {
		return nil, fmt.Errorf("authenticated UDP REGISTER failed: %d %s", response.StatusCode, response.Reason)
	}
	state.secureConn = adapter.ReleaseConn()
	result, err := finalizeRegisterSuccess(cfg, *state, response)
	if err != nil {
		_ = portC.Close()
		return nil, err
	}
	result.request = request.Clone()
	return result, nil
}

// udpSIPEndpoint owns one tunnel socket. The transaction layer never opens a
// socket or resolves a hostname: every write, including retransmissions and
// transaction ACKs, goes to the negotiated peer on this same PacketConn.
type udpSIPEndpoint struct {
	net.PacketConn
	peer     *net.UDPAddr
	portS    *udpSIPEndpoint
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	writeMu  sync.Mutex
	clients  map[string]*sip.ClientTx
	servers  map[string]*sip.ServerTx
	accepted map[string]*udpAcceptedInvite
	acks     map[string][]byte
	messages chan sip.Message
	requests chan *sip.Request
	errors   chan error
	wg       sync.WaitGroup
	once     sync.Once
	closed   bool
}

type udpAcceptedInvite struct {
	response *sip.Response
	done     chan struct{}
}

func udpDialogKey(m sip.Message) string {
	if m.CallID() == nil || m.CSeq() == nil || m.From() == nil || m.To() == nil {
		return ""
	}
	return fmt.Sprintf("%s/%d/%s/%s", m.CallID().Value(), m.CSeq().SeqNo, m.From().Params.GetOr("tag", ""), m.To().Params.GetOr("tag", ""))
}

func listenSIPUDP(ctx context.Context, cfg Config, network IMSNetwork, swu voiceclient.SWUTCPDialer, localPort int, peer *net.UDPAddr) (*udpSIPEndpoint, error) {
	var packet net.PacketConn
	var err error
	if network != nil {
		packet, err = network.ListenPacket(ctx, "udp", &net.UDPAddr{IP: cfg.LocalIP, Port: localPort})
	} else if dialer, ok := swu.(voiceclient.SWUUDPDialer); ok {
		packet, err = dialer.ListenPacketUDP(ctx, cfg.LocalIP, localPort)
	} else {
		return nil, fmt.Errorf("imscore: SIP UDP requires the SWu userspace packet network")
	}
	if err != nil {
		return nil, err
	}
	return newUDPSIPEndpoint(packet, peer), nil
}

func newUDPSIPEndpoint(packet net.PacketConn, peer *net.UDPAddr) *udpSIPEndpoint {
	ctx, cancel := context.WithCancel(context.Background())
	e := &udpSIPEndpoint{PacketConn: packet, peer: peer, ctx: ctx, cancel: cancel,
		clients: make(map[string]*sip.ClientTx), servers: make(map[string]*sip.ServerTx), accepted: make(map[string]*udpAcceptedInvite), acks: make(map[string][]byte),
		messages: make(chan sip.Message, 64), requests: make(chan *sip.Request, 64), errors: make(chan error, 1)}
	e.wg.Add(1)
	go e.readPackets()
	return e
}

func (e *udpSIPEndpoint) RemoteAddr() net.Addr { return e.peer }
func (e *udpSIPEndpoint) Read([]byte) (int, error) {
	return 0, fmt.Errorf("SIP UDP must be read as datagrams")
}
func (e *udpSIPEndpoint) Write(p []byte) (int, error) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	if err := e.PacketConn.SetWriteDeadline(time.Now().Add(incomingSIPResponseWriteTimeout)); err != nil {
		return 0, err
	}
	n, err := e.PacketConn.WriteTo(p, e.peer)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
func (e *udpSIPEndpoint) WriteMsg(m sip.Message) error {
	_, err := e.Write([]byte(m.String()))
	return err
}
func (e *udpSIPEndpoint) Ref(int) int            { return 1 }
func (e *udpSIPEndpoint) TryClose() (int, error) { return 1, nil }

func (e *udpSIPEndpoint) Close() error {
	e.once.Do(func() {
		e.cancel()
		_ = e.PacketConn.Close() // wake reads/writes, including an in-progress Init
		e.mu.Lock()
		e.closed = true
		clients := make([]*sip.ClientTx, 0, len(e.clients))
		servers := make([]*sip.ServerTx, 0, len(e.servers))
		for _, tx := range e.clients {
			clients = append(clients, tx)
		}
		for _, tx := range e.servers {
			servers = append(servers, tx)
		}
		e.mu.Unlock()
		for _, tx := range clients {
			tx.Terminate()
		}
		for _, tx := range servers {
			tx.Terminate()
		}
		if e.portS != nil {
			_ = e.portS.Close()
		}
		e.wg.Wait()
	})
	return nil
}

func (e *udpSIPEndpoint) sendRequest(ctx context.Context, req *sip.Request) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	req = req.Clone()
	req.SetTransport("UDP")
	req.SetDestination(e.peer.String())
	ensureSIPStreamFraming(req)
	if req.Method == sip.ACK {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return net.ErrClosed
		}
		if len(e.acks) < 128 {
			e.acks[udpDialogKey(req)] = []byte(req.String())
		}
		e.mu.Unlock()
		return e.WriteMsg(req)
	}
	key, err := sip.ClientTxKeyMake(req)
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return net.ErrClosed
	}
	if _, exists := e.clients[key]; exists {
		e.mu.Unlock()
		return nil
	}
	if len(e.clients) >= 128 {
		e.mu.Unlock()
		return fmt.Errorf("imscore: too many pending UDP client transactions")
	}
	tx := sip.NewClientTx(key, req, e, slog.Default())
	if req.Method == sip.INVITE {
		tx.OnRetransmission(func(res *sip.Response) {
			if !res.IsSuccess() {
				return
			}
			e.mu.Lock()
			ack := append([]byte(nil), e.acks[udpDialogKey(res)]...)
			e.mu.Unlock()
			if len(ack) > 0 {
				_, _ = e.Write(ack)
			}
		})
	}
	// Init is serialized with receive: a fast loopback response must not enter
	// the FSM until Init has installed its state and timers.
	e.clients[key] = tx
	err = tx.Init()
	if err != nil {
		delete(e.clients, key)
		e.mu.Unlock()
		tx.Terminate()
		return err
	}
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer func() {
			tx.Terminate()
			e.mu.Lock()
			delete(e.clients, key)
			if req.Method == sip.INVITE && req.CallID() != nil {
				prefix := fmt.Sprintf("%s/%d/", req.CallID().Value(), req.CSeq().SeqNo)
				for dialog := range e.acks {
					if strings.HasPrefix(dialog, prefix) {
						delete(e.acks, dialog)
					}
				}
			}
			e.mu.Unlock()
		}()
		cancelled := ctx.Done()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-cancelled:
				return
			case <-tx.Done():
				return
			case res := <-tx.Responses():
				if res.StatusCode >= 200 {
					cancelled = nil
				}
				select {
				case e.messages <- res:
				case <-e.ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}

func sameSIPTransaction(req *sip.Request, res *sip.Response) bool {
	if req == nil || res == nil || req.CallID() == nil || res.CallID() == nil || req.CSeq() == nil || res.CSeq() == nil {
		return false
	}
	return req.CallID().Value() == res.CallID().Value() && req.CSeq().SeqNo == res.CSeq().SeqNo && req.CSeq().MethodName == res.CSeq().MethodName
}

func (e *udpSIPEndpoint) readPackets() {
	defer e.wg.Done()
	buffer := make([]byte, 65536)
	for {
		n, source, err := e.PacketConn.ReadFrom(buffer)
		if err != nil {
			select {
			case e.errors <- err:
			default:
			}
			return
		}
		peer, ok := source.(*net.UDPAddr)
		if !ok || !peer.IP.Equal(e.peer.IP) || peer.Port != e.peer.Port || peer.Zone != e.peer.Zone {
			continue
		}
		data := buffer[:n]
		if len(bytesTrim(data, "\r\n")) == 0 {
			continue
		}
		// ParseSIP consumes one datagram, never carries partial bytes into the
		// next packet, and validates Content-Length below against the packet.
		msg, err := parseSIPDatagram(data)
		if err != nil {
			continue
		}
		if length := msg.ContentLength(); length != nil && int(*length) != len(msg.Body()) {
			continue
		}
		msg.SetTransport("UDP")
		msg.SetSource(peer.String())
		if res, ok := msg.(*sip.Response); ok {
			key, err := sip.ClientTxKeyMake(res)
			if err != nil {
				continue
			}
			e.mu.Lock()
			tx := e.clients[key]
			e.mu.Unlock()
			if tx != nil && sameSIPTransaction(tx.Origin(), res) {
				tx.Receive(res)
			}
			continue
		}
		if req, ok := msg.(*sip.Request); ok {
			if req.CallID() == nil || req.CSeq() == nil || req.Via() == nil || req.From() == nil || req.To() == nil {
				continue
			}
			select {
			case e.requests <- req:
			case <-e.ctx.Done():
				return
			default:
			}
		}
	}
}

// incomingRequest returns false for retransmissions after asking sipgo to
// resend the cached transaction response. A MESSAGE therefore reaches SMS
// processing exactly once, while a lost 200 can still be recovered.
func (e *udpSIPEndpoint) incomingRequest(req *sip.Request) (SIPResponder, bool) {
	if req.Method == sip.ACK {
		e.mu.Lock()
		if accepted := e.accepted[udpDialogKey(req)]; accepted != nil {
			close(accepted.done)
			delete(e.accepted, udpDialogKey(req))
		}
		e.mu.Unlock()
		key, err := sip.ServerTxKeyMake(req)
		if err == nil {
			e.mu.Lock()
			tx := e.servers[key]
			e.mu.Unlock()
			if tx != nil {
				_ = tx.Receive(req)
			}
		}
		return func(*sip.Response) error { return nil }, true
	}
	key, err := sip.ServerTxKeyMake(req)
	if err != nil {
		return nil, false
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, false
	}
	if tx := e.servers[key]; tx != nil {
		e.mu.Unlock()
		origin := tx.Origin()
		if origin.CallID() == nil || req.CallID() == nil || origin.CSeq() == nil || req.CSeq() == nil || origin.CallID().Value() != req.CallID().Value() || origin.CSeq().SeqNo != req.CSeq().SeqNo {
			return nil, false
		}
		_ = tx.Receive(req)
		return nil, false
	}
	if len(e.servers) >= 256 {
		e.mu.Unlock()
		_ = e.WriteMsg(sip.NewResponseFromRequest(req, 503, "Service Unavailable", nil))
		return nil, false
	}
	tx := sip.NewServerTx(key, req.Clone(), e, slog.Default())
	if err := tx.Init(); err != nil {
		e.mu.Unlock()
		tx.Terminate()
		return nil, false
	}
	e.servers[key] = tx
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		// A handler that never responds must not retain a server transaction.
		timer := time.NewTimer(incomingPortSDeferredResponseTimeout + 32*time.Second)
		defer timer.Stop()
	wait:
		for {
			select {
			case <-tx.Done():
				break wait
			case <-e.ctx.Done():
				break wait
			case <-timer.C:
				break wait
			case <-tx.Acks(): // application already sees ACK via incomingRequest
			}
		}
		tx.Terminate()
		e.mu.Lock()
		delete(e.servers, key)
		e.mu.Unlock()
	}()
	return func(response *sip.Response) error {
		if response == nil {
			return fmt.Errorf("nil SIP response")
		}
		err := tx.Respond(response)
		if err == nil && req.Method == sip.INVITE && response.IsSuccess() {
			e.retransmitAcceptedInvite(response)
		}
		return err
	}, true
}

// RFC 3261 13.3.1.4 assigns INVITE 2xx retransmission to the transaction
// user. sipgo deliberately leaves it to us; ACK matching uses dialog tags
// because the 2xx ACK has a new Via branch.
func (e *udpSIPEndpoint) retransmitAcceptedInvite(response *sip.Response) {
	key := udpDialogKey(response)
	if key == "" {
		return
	}
	e.mu.Lock()
	if e.closed || e.accepted[key] != nil {
		e.mu.Unlock()
		return
	}
	accepted := &udpAcceptedInvite{response: response.Clone(), done: make(chan struct{})}
	e.accepted[key] = accepted
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			if e.accepted[key] == accepted {
				delete(e.accepted, key)
			}
			e.mu.Unlock()
		}()
		interval := sip.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(64 * sip.T1)
		defer deadline.Stop()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-accepted.done:
				return
			case <-deadline.C:
				return
			case <-timer.C:
				if err := e.WriteMsg(accepted.response); err != nil {
					return
				}
				interval = min(interval*2, sip.T2)
				timer.Reset(interval)
			}
		}
	}()
}

func (rt *transportRuntime) runUDPReadLoop(ctx context.Context, endpoint *udpSIPEndpoint, portS bool) {
	defer rt.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-endpoint.ctx.Done():
			return
		case err := <-endpoint.errors:
			rt.fail(fmt.Errorf("IMS UDP read: %w", err))
			return
		case msg := <-endpoint.messages:
			switch m := msg.(type) {
			case *sip.Response:
				rt.publishResponse(m)
				rt.enqueueParsedResponse([]byte(m.String()))
			}
		case request := <-endpoint.requests:
			if portS {
				rt.incomingDiagnostics.inboundSIPObserved(time.Now())
			}
			respond, fresh := endpoint.incomingRequest(request)
			if fresh {
				rt.dispatchIncomingRequestWithResponder(request, respond)
			}
		}
	}
}

func udpPeer(addr string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("imscore: SIP UDP requires a numeric tunnel peer")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid SIP UDP port")
	}
	return &net.UDPAddr{IP: ip, Port: p}, nil
}

func parseSIPDatagram(data []byte) (sip.Message, error) {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, fmt.Errorf("incomplete SIP datagram headers")
	}
	length := -1
	for _, line := range bytes.Split(data[:end], []byte("\r\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || (!strings.EqualFold(strings.TrimSpace(string(name)), "Content-Length") && !strings.EqualFold(string(name), "l")) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(value)))
		if err != nil || n < 0 || n > len(data)-end-4 || (length >= 0 && length != n) {
			return nil, fmt.Errorf("invalid SIP datagram Content-Length")
		}
		length = n
	}
	return sip.NewParser().ParseSIP(data)
}
