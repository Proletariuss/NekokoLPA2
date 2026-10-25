package imscore

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/emiago/sipgo"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

func newSWUNetstack(localIP net.IP, dp voiceclient.PacketDataplane) (voiceclient.SWUTCPDialer, error) {
	if dp == nil {
		return nil, nil
	}
	return voiceclient.NewSWUTCPDialer(localIP, dp)
}

func dialPlainTCP(ctx context.Context, cfg Config, swu voiceclient.SWUTCPDialer) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(cfg.PCSCFAddr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(host)
	if rip == nil {
		return nil, fmt.Errorf("imscore: invalid P-CSCF %q", cfg.PCSCFAddr)
	}
	if swu != nil {
		return swu.DialContextTCP(ctx, cfg.LocalIP, 5060, rip, port)
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: cfg.LocalIP, Port: 5060}}
	return d.DialContext(ctx, "tcp", cfg.PCSCFAddr)
}

type fixedConnDialer struct {
	mu   sync.Mutex
	conn net.Conn
}

func (d *fixedConnDialer) set(conn net.Conn) {
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
}

func (d *fixedConnDialer) dial(ctx context.Context, laddr net.Addr, raddr net.Addr) (net.Conn, error) {
	d.mu.Lock()
	conn := d.conn
	d.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("imscore: SIP connection not ready")
	}
	return conn, nil
}

func newRegisterSIPStack(cfg Config, conn net.Conn, swu voiceclient.SWUTCPDialer, localPort int) (*sipgo.UserAgent, *sipgo.Client, error) {
	if localPort <= 0 {
		localPort = 5060
	}
	dialer := &fixedConnDialer{}
	if conn != nil {
		dialer.set(conn)
	}
	return newSIPStack(cfg, dialer, swu, localPort)
}

func newSecureRegisterSIPStack(cfg Config, conn net.Conn) (*sipgo.UserAgent, *sipgo.Client, error) {
	localPort := 5060
	if conn != nil && conn.LocalAddr() != nil {
		if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok && ta.Port > 0 {
			localPort = ta.Port
		}
	}
	dialer := &fixedConnDialer{}
	if conn != nil {
		dialer.set(conn)
	}
	return newSIPStack(cfg, dialer, nil, localPort)
}

func newSIPStack(cfg Config, dialer *fixedConnDialer, swu voiceclient.SWUTCPDialer, localPort int) (*sipgo.UserAgent, *sipgo.Client, error) {
	installSIPTrace(cfg.TraceID, cfg.DeviceID)
	// 注意：sipgo v1.4.0/v1.5.0 的 sip.TransportTCP 只有 DialerCreate（返回 net.Dialer），
	// 无法注入用户态 SWu 自定义连接（参考实现的 DialContext hook 在该版本不存在）。
	// SWu TCP 场景由 connRegisterTransport 直接处理（register_session.go / register.go），
	// 此处使用标准 TCP dial 以保证兼容。
	_ = dialer
	_ = swu
	uaOpts := []sipgo.UserAgentOption{
		sipgo.WithUserAgent(cfg.UserAgent),
	}
	ua, err := sipgo.NewUA(uaOpts...)
	if err != nil {
		return nil, nil, err
	}
	client, err := sipgo.NewClient(ua,
		sipgo.WithClientHostname(cfg.LocalIP.String()),
		sipgo.WithClientPort(localPort),
		sipgo.WithClientConnectionAddr(net.JoinHostPort(cfg.LocalIP.String(), fmt.Sprintf("%d", localPort))),
	)
	if err != nil {
		_ = ua.Close()
		return nil, nil, err
	}
	return ua, client, nil
}
