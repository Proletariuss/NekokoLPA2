package voiceclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const swuNetstackNICID = 1

// swuNetstackMTU 是 gvisor 用户态网络栈的内层链路 MTU。
//
// 受保护 IMS 通道（AKA port-c / SIP）经过双层 ESP 封装：
//   ipsec3gpp ESP (~50 B) + SWu 隧道 ESP (~50 B) + 外层 IP/UDP NAT-T (28 B v4 / 48 B v6)
// 加上 SOCKS5 代理转发开销（~30-40 B），实际可用内层 MTU 远低于 1500。
// 若沿用 1500，>~1.2 KB 的 SIP 消息（带 AKA 响应 + Security-Verify + 完整 Contact
// 头的受保护 REGISTER 约 1.4 KB）封装后外层超过代理路径 MTU 被丢弃，
// P-CSCF 收不到完整消息，约 5 秒后空闲 FIN，表现为
// "register connection closed before response"。
//
// 取 1280：IPv6 最小 MTU，gvisor 可正常建立 IPv6 TCP 连接（CTExcel/Giffgaff）；
// 同时 TCP MSS ≈ 1240，1.4 KB REGISTER 拆 2 段，每段封装后 ≈ 1428 < 1500（IPv4），
// 避免 VDF 受保护 REGISTER 被丢弃。
const swuNetstackMTU = 1280

// SWUTCPDialer opens TCP connections through the userspace SWu dataplane.
type SWUTCPDialer interface {
	DialContextTCP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (net.Conn, error)
	ListenContextTCP(ctx context.Context, localIP net.IP, localPort int) (net.Listener, error)
	Close() error
}

// SWUUDPDialer is the optional media extension implemented by the production
// userspace stack. Keeping it separate preserves TCP-only test doubles.
type SWUUDPDialer interface {
	ListenPacketUDP(ctx context.Context, localIP net.IP, localPort int) (net.PacketConn, error)
}

// SWUTCPKeepaliveDialer is implemented by SWu dialers that can configure TCP
// keepalive inside the userspace netstack. Callers must fall back to
// SWUTCPDialer when an alternate implementation does not provide it.
type SWUTCPKeepaliveDialer interface {
	DialContextTCPWithKeepalive(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int, keepalive time.Duration) (net.Conn, error)
}

// SWUNetstackStats exposes packet-send and TCP counters for registration diagnostics.
type SWUNetstackStats struct {
	OutboundPackets   uint64
	OutboundErrors    uint64
	MaxOutboundBytes  uint64
	Over1280Packets   uint64
	LastOutboundError string
	TCPSegmentsSent   uint64
	TCPValidReceived  uint64
	TCPFailedConnects uint64
	TCPRetransmits    uint64
	TCPTimeouts       uint64
	TCPSendErrors     uint64
	TCPResetsReceived uint64
}

type SWUNetstackStatsProvider interface {
	SWUNetstackStats() SWUNetstackStats
}

// NewSWUTCPDialer returns a dialer bound to the tunnel virtual IP.
func NewSWUTCPDialer(localIP net.IP, dp PacketDataplane) (SWUTCPDialer, error) {
	return newSWUNetstack(localIP, dp)
}

type swuNetstack struct {
	dp      PacketDataplane
	linkEP  *channel.Endpoint
	stack   *stack.Stack
	localIP net.IP

	closeOnce        sync.Once
	closed           chan struct{}
	outboundPackets  atomic.Uint64
	outboundErrors   atomic.Uint64
	maxOutboundBytes atomic.Uint64
	over1280Packets  atomic.Uint64
	lastOutboundErr  atomic.Value
}

func newSWUNetstack(localIP net.IP, dp PacketDataplane) (*swuNetstack, error) {
	if dp == nil {
		return nil, fmt.Errorf("voiceclient: SWu netstack requires dataplane")
	}
	if localIP == nil {
		return nil, fmt.Errorf("voiceclient: SWu netstack requires local IP")
	}

	ns := &swuNetstack{
		dp:      dp,
		linkEP:  channel.New(512, swuNetstackMTU, ""),
		localIP: append(net.IP(nil), localIP...),
		closed:  make(chan struct{}),
	}

	ns.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol, gudp.NewProtocol},
	})
	if err := ns.stack.CreateNIC(swuNetstackNICID, ns.linkEP); err != nil {
		return nil, fmt.Errorf("voiceclient: SWu netstack create NIC: %v", err)
	}

	if err := ns.addLocalAddress(); err != nil {
		return nil, err
	}
	ns.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         swuNetstackNICID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         swuNetstackNICID,
		},
	})

	go ns.inboundLoop()
	go ns.outboundLoop()
	return ns, nil
}

func (n *swuNetstack) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed)
		n.linkEP.Close()
		n.stack.Close()
		n.stack.Wait()
	})
	return nil
}

func (n *swuNetstack) DialContextTCP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (net.Conn, error) {
	return n.dialContextTCP(ctx, localIP, localPort, remoteIP, remotePort, 0)
}

func (n *swuNetstack) DialContextTCPWithKeepalive(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int, keepalive time.Duration) (net.Conn, error) {
	return n.dialContextTCP(ctx, localIP, localPort, remoteIP, remotePort, keepalive)
}

func (n *swuNetstack) dialContextTCP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int, keepalive time.Duration) (net.Conn, error) {
	if remoteIP == nil {
		return nil, fmt.Errorf("voiceclient: remote IP is required")
	}
	networkProto := networkProtocolForIP(remoteIP)
	if networkProto == 0 {
		return nil, fmt.Errorf("voiceclient: unsupported TCP remote IP %s", remoteIP.String())
	}

	localAddr := tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(localIP),
		Port: uint16(localPort),
	}
	remoteAddr := tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(remoteIP),
		Port: uint16(remotePort),
	}
	conn, err := dialTCPWithBindKeepalive(ctx, n.stack, localAddr, remoteAddr, networkProto, keepalive)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: SWu userspace TCP dial %s:%d: %w", remoteIP.String(), remotePort, err)
	}
	logger.Info("IMS SWu TCP connected",
		logger.String("local_ip", localIP.String()),
		logger.Int("local_port", localPort),
		logger.String("remote_ip", remoteIP.String()),
		logger.Int("remote_port", remotePort),
		logger.Int("keepalive_seconds", int(keepalive/time.Second)))
	return conn, nil
}

func dialTCPWithBindKeepalive(ctx context.Context, s *stack.Stack, localAddr, remoteAddr tcpip.FullAddress, network tcpip.NetworkProtocolNumber, keepalive time.Duration) (*gonet.TCPConn, error) {
	var wq waiter.Queue
	ep, tcpErr := s.NewEndpoint(gtcp.ProtocolNumber, network, &wq)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}
	connected := false
	defer func() {
		if !connected {
			ep.Close()
		}
	}()

	// IMS 注册与受保护通道（AKA port-c / SIP 本地端口）使用协商确定的本地端口。
	// registrar 候选切换、AKA 变体重试、VoWiFi 快速重启都会在同一共享
	// netstack 上于 60s TIME_WAIT 窗口内重拨同一端口。gvisor 遵循 Linux
	// 语义：只有新旧端点都设置 SO_REUSEADDR 时才允许复用端口，因此每次
	// 拨号统一启用，避免 "bind userspace TCP endpoint: port is in use"。
	ep.SocketOptions().SetReuseAddress(true)

	if keepalive > 0 {
		idle := tcpip.KeepaliveIdleOption(keepalive)
		if tcpErr := ep.SetSockOpt(&idle); tcpErr != nil {
			return nil, fmt.Errorf("set TCP keepalive idle: %s", tcpErr)
		}
		interval := tcpip.KeepaliveIntervalOption(keepalive)
		if tcpErr := ep.SetSockOpt(&interval); tcpErr != nil {
			return nil, fmt.Errorf("set TCP keepalive interval: %s", tcpErr)
		}
		ep.SocketOptions().SetKeepAlive(true)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if localAddr != (tcpip.FullAddress{}) {
		if tcpErr := ep.Bind(localAddr); tcpErr != nil {
			return nil, fmt.Errorf("bind userspace TCP endpoint: %s", tcpErr)
		}
	}

	tcpErr = ep.Connect(remoteAddr)
	if _, ok := tcpErr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notifyCh:
		}
		tcpErr = ep.LastError()
	}
	if tcpErr != nil {
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: &net.TCPAddr{IP: net.IP(remoteAddr.Addr.AsSlice()), Port: int(remoteAddr.Port)},
			Err:  errors.New(tcpErr.String()),
		}
	}

	connected = true
	return gonet.NewTCPConn(&wq, ep), nil
}

func (n *swuNetstack) ListenContextTCP(ctx context.Context, localIP net.IP, localPort int) (net.Listener, error) {
	if localIP == nil {
		return nil, fmt.Errorf("voiceclient: local IP is required")
	}
	networkProto := networkProtocolForIP(localIP)
	if networkProto == 0 {
		return nil, fmt.Errorf("voiceclient: unsupported listen IP %s", localIP.String())
	}
	localAddr := tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(localIP),
		Port: uint16(localPort),
	}
	ln, err := gonet.ListenTCP(n.stack, localAddr, networkProto)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: SWu userspace TCP listen %s:%d: %w", localIP.String(), localPort, err)
	}
	logger.Info("IMS SWu TCP listening",
		logger.String("local_ip", localIP.String()),
		logger.Int("local_port", localPort))
	return &swuTCPListener{inner: ln, ctx: ctx}, nil
}

// ListenPacketUDP binds an RTP/RTCP socket inside the same userspace stack as
// SIP. This is intentionally not a system socket: packets must stay inside the
// established SWu/ePDG dataplane and follow the configured proxy path.
func (n *swuNetstack) ListenPacketUDP(ctx context.Context, localIP net.IP, localPort int) (net.PacketConn, error) {
	if localIP == nil {
		return nil, fmt.Errorf("voiceclient: local UDP IP is required")
	}
	networkProto := networkProtocolForIP(localIP)
	if networkProto == 0 {
		return nil, fmt.Errorf("voiceclient: unsupported UDP listen IP %s", localIP.String())
	}
	localAddr := &tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(localIP),
		Port: uint16(localPort),
	}
	conn, err := gonet.DialUDP(n.stack, localAddr, nil, networkProto)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: SWu userspace UDP listen %s:%d: %w", localIP.String(), localPort, err)
	}
	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()
	}
	return conn, nil
}

type swuTCPListener struct {
	inner *gonet.TCPListener
	ctx   context.Context
}

func (l *swuTCPListener) Accept() (net.Conn, error) {
	if l.ctx != nil {
		select {
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		default:
		}
	}
	return l.inner.Accept()
}

func (l *swuTCPListener) Close() error {
	return l.inner.Close()
}

func (l *swuTCPListener) Addr() net.Addr {
	return l.inner.Addr()
}

func (n *swuNetstack) addLocalAddress() error {
	addr := addrFromNetIP(n.localIP)
	if addr.Len() == 0 {
		return fmt.Errorf("voiceclient: invalid SWu local IP %v", n.localIP)
	}
	protocol := networkProtocolForIP(n.localIP)
	if protocol == 0 {
		return fmt.Errorf("voiceclient: unsupported SWu local IP %s", n.localIP.String())
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: prefixLenForIP(n.localIP),
		},
	}
	if err := n.stack.AddProtocolAddress(swuNetstackNICID, protocolAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("voiceclient: add SWu local IP %s to userspace netstack: %v", n.localIP.String(), err)
	}
	return nil
}

func (n *swuNetstack) inboundLoop() {
	for {
		select {
		case <-n.closed:
			return
		case packet, ok := <-n.dp.InnerPackets():
			if !ok {
				return
			}
			if len(packet) == 0 {
				continue
			}
			proto := networkProtocolForPacket(packet)
			if proto == 0 {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append([]byte(nil), packet...)),
			})
			n.linkEP.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}
}

func (n *swuNetstack) outboundLoop() {
	for {
		select {
		case <-n.closed:
			return
		default:
		}
		pkt := n.linkEP.ReadContext(context.Background())
		if pkt == nil {
			select {
			case <-n.closed:
				return
			default:
				continue
			}
		}
		payload := packetBufferToBytes(pkt)
		pkt.DecRef()
		if len(payload) == 0 {
			continue
		}
		packetBytes := uint64(len(payload))
		if packetBytes > 1280 {
			n.over1280Packets.Add(1)
		}
		for previous := n.maxOutboundBytes.Load(); packetBytes > previous; previous = n.maxOutboundBytes.Load() {
			if n.maxOutboundBytes.CompareAndSwap(previous, packetBytes) {
				break
			}
		}
		if err := n.dp.SendInnerPacket(payload); err != nil {
			n.outboundErrors.Add(1)
			n.lastOutboundErr.Store(err.Error())
			continue
		}
		n.outboundPackets.Add(1)
	}
}

func (n *swuNetstack) SWUNetstackStats() SWUNetstackStats {
	if n == nil {
		return SWUNetstackStats{}
	}
	stats := SWUNetstackStats{
		OutboundPackets:  n.outboundPackets.Load(),
		OutboundErrors:   n.outboundErrors.Load(),
		MaxOutboundBytes: n.maxOutboundBytes.Load(),
		Over1280Packets:  n.over1280Packets.Load(),
	}
	if value := n.lastOutboundErr.Load(); value != nil {
		stats.LastOutboundError, _ = value.(string)
	}
	tcpStats := n.stack.Stats().TCP
	stats.TCPSegmentsSent = tcpStats.SegmentsSent.Value()
	stats.TCPValidReceived = tcpStats.ValidSegmentsReceived.Value()
	stats.TCPFailedConnects = tcpStats.FailedConnectionAttempts.Value()
	stats.TCPRetransmits = tcpStats.Retransmits.Value()
	stats.TCPTimeouts = tcpStats.Timeouts.Value()
	stats.TCPSendErrors = tcpStats.SegmentSendErrors.Value()
	stats.TCPResetsReceived = tcpStats.ResetsReceived.Value()
	return stats
}

func packetBufferToBytes(pkt *stack.PacketBuffer) []byte {
	if pkt == nil {
		return nil
	}
	sz := pkt.Size()
	if sz == 0 {
		return nil
	}
	buf := make([]byte, sz)
	v := pkt.ToBuffer()
	defer v.Release()
	flat := v.Flatten()
	if len(flat) == 0 {
		return nil
	}
	copy(buf, flat)
	return buf[:len(flat)]
}

func networkProtocolForPacket(packet []byte) tcpip.NetworkProtocolNumber {
	if len(packet) == 0 {
		return 0
	}
	switch packet[0] >> 4 {
	case 4:
		return ipv4.ProtocolNumber
	case 6:
		return ipv6.ProtocolNumber
	default:
		return 0
	}
}

func networkProtocolForIP(ip net.IP) tcpip.NetworkProtocolNumber {
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return ipv4.ProtocolNumber
	}
	if ip.To16() != nil {
		return ipv6.ProtocolNumber
	}
	return 0
}

func addrFromNetIP(ip net.IP) tcpip.Address {
	if ip == nil {
		return tcpip.Address{}
	}
	if v4 := ip.To4(); v4 != nil {
		return tcpip.AddrFromSlice(v4)
	}
	if v6 := ip.To16(); v6 != nil {
		return tcpip.AddrFromSlice(v6)
	}
	return tcpip.Address{}
}

func prefixLenForIP(ip net.IP) int {
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 32
	}
	return 128
}
