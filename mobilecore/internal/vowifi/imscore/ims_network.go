package imscore

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

// IMSNetwork abstracts userspace or system IMS dataplane sockets.
type IMSNetwork interface {
	DialContext(ctx context.Context, network string, addr net.Addr, transport string, opts DialOptions) (net.Conn, error)
	HasLocalIP(ip []byte) bool
	ListenPacket(ctx context.Context, network string, addr net.Addr) (net.PacketConn, error)
	ListenTCP(ctx context.Context, laddr *net.TCPAddr) (net.Listener, error)
	LocalIP() []byte
	ResolveIP(ctx context.Context, host string, preferIPv6 bool) ([]byte, error)
}

// UserspaceIMSNetwork routes IMS sockets through the SWu userspace netstack.
type UserspaceIMSNetwork struct {
	localIP          net.IP
	swu              voiceclient.SWUTCPDialer
	packetTransforms *ipsec3gpp.TransformingDataplane
	ownsTransforms   bool
}

// NewUserspaceIMSNetwork builds an IMSNetwork backed by the established SWu dataplane.
func NewUserspaceIMSNetwork(localIP net.IP, dataplane voiceclient.PacketDataplane) (*UserspaceIMSNetwork, error) {
	if localIP == nil {
		return nil, fmt.Errorf("imscore: local IP is required")
	}
	if dataplane == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network requires dataplane")
	}

	transforms, alreadyWrapped := dataplane.(*ipsec3gpp.TransformingDataplane)
	if !alreadyWrapped {
		var err error
		transforms, err = ipsec3gpp.NewTransformingDataplane(dataplane)
		if err != nil {
			return nil, fmt.Errorf("imscore: create IMS packet transform: %w", err)
		}
	}

	swu, err := newSWUNetstack(localIP, transforms)
	if err != nil {
		if !alreadyWrapped {
			_ = transforms.Close()
		}
		return nil, err
	}
	return &UserspaceIMSNetwork{
		localIP:          append(net.IP(nil), localIP...),
		swu:              swu,
		packetTransforms: transforms,
		ownsTransforms:   !alreadyWrapped,
	}, nil
}

// InstallIPSec installs the negotiated ipsec-3gpp transform at the packet
// boundary shared by every TCP endpoint in this userspace network.
func (n *UserspaceIMSNetwork) InstallIPSec(transport *ipsec3gpp.Transport) error {
	if n == nil || n.packetTransforms == nil {
		return fmt.Errorf("imscore: userspace IMS packet transform unavailable")
	}
	return n.packetTransforms.Install(transport)
}

func (n *UserspaceIMSNetwork) ClearIPSec() {
	if n != nil && n.packetTransforms != nil {
		n.packetTransforms.Clear()
	}
}

func (n *UserspaceIMSNetwork) IPSecInstalled() bool {
	return n != nil && n.packetTransforms != nil && n.packetTransforms.Installed()
}

func (n *UserspaceIMSNetwork) IPSecDataplaneStats() ipsec3gpp.TransformingDataplaneStats {
	if n == nil || n.packetTransforms == nil {
		return ipsec3gpp.TransformingDataplaneStats{}
	}
	return n.packetTransforms.Stats()
}

func (n *UserspaceIMSNetwork) SWUNetstackStats() voiceclient.SWUNetstackStats {
	if n == nil || n.swu == nil {
		return voiceclient.SWUNetstackStats{}
	}
	if provider, ok := n.swu.(voiceclient.SWUNetstackStatsProvider); ok {
		return provider.SWUNetstackStats()
	}
	return voiceclient.SWUNetstackStats{}
}

func (n *UserspaceIMSNetwork) DialContext(ctx context.Context, network string, addr net.Addr, transport string, opts DialOptions) (net.Conn, error) {
	if n == nil || n.swu == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network unavailable")
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return nil, fmt.Errorf("imscore: invalid TCP addr %v", addr)
	}
	localPort := 5060
	if l, ok := ctx.Value(localPortContextKey{}).(int); ok && l > 0 {
		localPort = l
	}
	keepalive := time.Duration(opts.KeepAlive)
	if keepalive > 0 {
		if dialer, ok := n.swu.(voiceclient.SWUTCPKeepaliveDialer); ok {
			return dialer.DialContextTCPWithKeepalive(ctx, n.localIP, localPort, tcpAddr.IP, tcpAddr.Port, keepalive)
		}
	}
	return n.swu.DialContextTCP(ctx, n.localIP, localPort, tcpAddr.IP, tcpAddr.Port)
}

func (n *UserspaceIMSNetwork) HasLocalIP(ip []byte) bool {
	if n == nil || n.localIP == nil || len(ip) == 0 {
		return false
	}
	return n.localIP.Equal(net.IP(ip))
}

func (n *UserspaceIMSNetwork) ListenPacket(ctx context.Context, network string, addr net.Addr) (net.PacketConn, error) {
	if n == nil || n.swu == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network unavailable")
	}
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("imscore: unsupported packet network %q", network)
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return nil, fmt.Errorf("imscore: invalid UDP listen addr %v", addr)
	}
	if udpAddr.IP != nil && !udpAddr.IP.IsUnspecified() && !n.localIP.Equal(udpAddr.IP) {
		return nil, fmt.Errorf("imscore: UDP listen IP %s is outside the SWu tunnel", udpAddr.IP)
	}
	udpDialer, ok := n.swu.(voiceclient.SWUUDPDialer)
	if !ok {
		return nil, fmt.Errorf("imscore: userspace IMS network has no UDP media support")
	}
	return udpDialer.ListenPacketUDP(ctx, n.localIP, udpAddr.Port)
}

func (n *UserspaceIMSNetwork) ListenTCP(ctx context.Context, laddr *net.TCPAddr) (net.Listener, error) {
	if n == nil || n.swu == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network unavailable")
	}
	if laddr == nil {
		return nil, fmt.Errorf("imscore: listen addr is required")
	}
	port := laddr.Port
	if port <= 0 {
		port = 5060
	}
	return n.swu.ListenContextTCP(ctx, n.localIP, port)
}

func (n *UserspaceIMSNetwork) LocalIP() []byte {
	if n == nil || n.localIP == nil {
		return nil
	}
	return append([]byte(nil), n.localIP...)
}

func (n *UserspaceIMSNetwork) ResolveIP(ctx context.Context, host string, preferIPv6 bool) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("imscore: refusing direct DNS for %q; use the P-CSCF address supplied by ePDG, or configure DoH/proxy bypass so the front proxy does not hijack ePDG", host)
}

func (n *UserspaceIMSNetwork) SWUDialer() voiceclient.SWUTCPDialer {
	if n == nil {
		return nil
	}
	return n.swu
}

func (n *UserspaceIMSNetwork) Close() error {
	if n == nil {
		return nil
	}
	var firstErr error
	if n.swu != nil {
		firstErr = n.swu.Close()
	}
	if n.ownsTransforms && n.packetTransforms != nil {
		if err := n.packetTransforms.Close(); firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type localPortContextKey struct{}

func withLocalPort(ctx context.Context, port int) context.Context {
	if port <= 0 {
		return ctx
	}
	return context.WithValue(ctx, localPortContextKey{}, port)
}

func splitHostPortAddr(addr string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid host %q", host)
	}
	return ip, port, nil
}
