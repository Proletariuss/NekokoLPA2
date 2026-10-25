// Package socks5 提供通过 SOCKS5 代理转发 UDP 流量的能力。
//
// VoWiFi 的 IKE/ESP 使用 UDP 500/4500。用户显式配置 SOCKS5 前置代理时，
// UDP ASSOCIATE 会把 ePDG 域名原样交给代理解析和路由，不在本地查找或替换
// 所谓“真实 ePDG IP”。未配置显式代理时不会使用本包。
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// UDPRelay 表示一个 SOCKS5 UDP 关联。
type UDPRelay struct {
	proxyAddr  string       // 用户手动填写的 SOCKS5 代理地址
	relayConn  *net.UDPConn // 连接到 SOCKS5 代理的 UDP 连接
	clientConn net.Conn     // SOCKS5 TCP 控制连接
	// rwMu 保护 relayConn 的读写互斥（UDP socket 并发读写本身安全，
	// 但 SendTo/ReadFrom 与 Close 之间的竞态需要保护）。
	// 注意：ReadFrom 不能持有 mu 做 30 秒阻塞读，否则 SendTo/Close 会被卡死。
	mu     sync.Mutex
	closed bool
}

// NewUDPRelay 建立 SOCKS5 UDP 关联。
// proxyAddr 为 SOCKS5 代理地址，不需要认证。
func NewUDPRelay(proxyAddr string) (*UDPRelay, error) {
	// 1. 建立 TCP 控制连接
	tcpConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks5 tcp dial: %w", err)
	}
	// Bound the complete handshake too. An HTTP-only/mixed local listener may
	// accept TCP but never answer SOCKS5 UDP ASSOCIATE.
	if err := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 set handshake deadline: %w", err)
	}

	// 2. SOCKS5 握手 - 无认证
	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting response: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting failed: method=%d", resp[1])
	}

	// 3. UDP ASSOCIATE 命令
	// 请求: VER=5, CMD=3(UDP_ASSOCIATE), RSV=0, ATYP=1(IPv4), DST=0.0.0.0, PORT=0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate: %w", err)
	}

	// 响应: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	rep := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, rep); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate response: %w", err)
	}
	if rep[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp associate failed: rep=%d", rep[1])
	}

	// 解析 BND.ADDR 和 BND.PORT
	var relayHost string
	var relayPortStr string

	switch rep[3] {
	case 0x01: // IPv4
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(tcpConn, addrBytes); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read relay addr: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(tcpConn, portBytes); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read relay port: %w", err)
		}
		port := binary.BigEndian.Uint16(portBytes)
		relayHost = net.IP(addrBytes).String()
		relayPortStr = fmt.Sprintf("%d", port)
	case 0x03: // Domain
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lenByte); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read domain length: %w", err)
		}
		domain := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(tcpConn, domain); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read domain: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(tcpConn, portBytes); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read relay port: %w", err)
		}
		port := binary.BigEndian.Uint16(portBytes)
		relayHost = string(domain)
		relayPortStr = fmt.Sprintf("%d", port)
	case 0x04: // IPv6
		addrBytes := make([]byte, 16)
		if _, err := io.ReadFull(tcpConn, addrBytes); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read ipv6 addr: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(tcpConn, portBytes); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read relay port: %w", err)
		}
		port := binary.BigEndian.Uint16(portBytes)
		relayHost = net.IP(addrBytes).String()
		relayPortStr = fmt.Sprintf("%d", port)
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 unsupported ATYP: %d", rep[3])
	}

	// 如果代理返回 0.0.0.0 或端口为 0，使用代理 TCP 连接的地址/端口
	if relayHost == "0.0.0.0" || relayHost == "::" {
		relayHost, _, _ = net.SplitHostPort(tcpConn.RemoteAddr().String())
	}
	if relayPortStr == "0" {
		_, tcpPort, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
		relayPortStr = tcpPort
	}

	relayAddr := net.JoinHostPort(relayHost, relayPortStr)

	// 4. 建立 UDP 连接到 relay 地址
	relayUDPAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 resolve udp relay %s: %w", relayAddr, err)
	}
	if relayUDPAddr.Port == 0 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp relay returned port 0")
	}
	network := "udp4"
	if relayUDPAddr.IP != nil && relayUDPAddr.IP.To4() == nil {
		network = "udp6"
	}
	relayUDP, err := net.DialUDP(network, nil, relayUDPAddr)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp dial relay %s: %w", relayAddr, err)
	}
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		relayUDP.Close()
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 clear handshake deadline: %w", err)
	}

	return &UDPRelay{
		proxyAddr:  proxyAddr,
		relayConn:  relayUDP,
		clientConn: tcpConn,
	}, nil
}

// SendTo 通过 SOCKS5 UDP 关联发送数据到目标地址。
// SOCKS5 UDP 包格式: RSV(2B) + FRAG(1B) + ATYP(1B) + DST.ADDR + DST.PORT + DATA
func (r *UDPRelay) SendTo(data []byte, dstIP net.IP, dstPort int) error {
	if dstIP == nil {
		return errors.New("socks5: dstIP is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return errors.New("relay closed")
	}

	var buf []byte
	if dstIP.To4() != nil {
		// IPv4: ATYP=1
		buf = make([]byte, 4+4+2+len(data))
		buf[0] = 0x00 // RSV
		buf[1] = 0x00 // RSV
		buf[2] = 0x00 // FRAG
		buf[3] = 0x01 // ATYP = IPv4
		copy(buf[4:8], dstIP.To4())
		binary.BigEndian.PutUint16(buf[8:10], uint16(dstPort))
		copy(buf[10:], data)
	} else {
		// IPv6: ATYP=4
		buf = make([]byte, 4+16+2+len(data))
		buf[0] = 0x00
		buf[1] = 0x00
		buf[2] = 0x00
		buf[3] = 0x04 // ATYP = IPv6
		copy(buf[4:20], dstIP.To16())
		binary.BigEndian.PutUint16(buf[20:22], uint16(dstPort))
		copy(buf[22:], data)
	}

	_, err := r.relayConn.Write(buf)
	return err
}

// SendToDomain 通过 SOCKS5 UDP 关联发送数据到域名目标。
// 使用 ATYP=3 (DOMAINNAME)，让代理服务器按域名做规则路由和 DNS 解析。
func (r *UDPRelay) SendToDomain(data []byte, domain string, dstPort int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return errors.New("relay closed")
	}

	domainBytes := []byte(domain)
	if len(domainBytes) > 255 {
		return errors.New("domain too long")
	}

	// ATYP=3 (DOMAINNAME): RSV(2B) + FRAG(1B) + ATYP(1B) + LEN(1B) + DOMAIN + PORT(2B) + DATA
	buf := make([]byte, 4+1+len(domainBytes)+2+len(data))
	buf[0] = 0x00 // RSV
	buf[1] = 0x00 // RSV
	buf[2] = 0x00 // FRAG
	buf[3] = 0x03 // ATYP = Domain
	buf[4] = byte(len(domainBytes))
	copy(buf[5:], domainBytes)
	binary.BigEndian.PutUint16(buf[5+len(domainBytes):], uint16(dstPort))
	copy(buf[5+len(domainBytes)+2:], data)

	_, err := r.relayConn.Write(buf)
	return err
}

// ReadFrom 从 SOCKS5 UDP 关联读取数据，返回 payload 和源地址。
// 注意：不持有 mu 锁，避免阻塞读期间 SendTo/Close 被卡死。
func (r *UDPRelay) ReadFrom(buf []byte) (data []byte, srcIP net.IP, srcPort int, err error) {
	r.mu.Lock()
	closed := r.closed
	relayConn := r.relayConn
	r.mu.Unlock()

	if closed || relayConn == nil {
		return nil, nil, 0, errors.New("relay closed")
	}

	relayConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, _, err := relayConn.ReadFrom(buf)
	if err != nil {
		return nil, nil, 0, err
	}

	if n < 10 {
		return nil, nil, 0, fmt.Errorf("socks5 udp packet too short: %d", n)
	}

	// 解析 SOCKS5 UDP 头: RSV(2B) + FRAG(1B) + ATYP(1B) + ADDR + PORT + DATA
	frag := buf[2]
	if frag != 0 {
		return nil, nil, 0, fmt.Errorf("socks5 udp fragmentation not supported (FRAG=%d)", frag)
	}
	atyp := buf[3]
	var addrLen int
	var ip net.IP
	var port int

	switch atyp {
	case 0x01: // IPv4
		addrLen = 4
		if n < 4+4+2 {
			return nil, nil, 0, fmt.Errorf("socks5 udp ipv4 header too short")
		}
		ip = net.IP(buf[4 : 4+4])
		port = int(binary.BigEndian.Uint16(buf[8:10]))
	case 0x03: // Domain
		if n < 5 {
			return nil, nil, 0, fmt.Errorf("socks5 udp domain header too short")
		}
		domainLen := int(buf[4])
		if n < 4+1+domainLen+2 {
			return nil, nil, 0, fmt.Errorf("socks5 udp domain too short")
		}
		addrLen = 1 + domainLen // 含 1 字节长度字段本身
		port = int(binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2]))
	case 0x04: // IPv6
		addrLen = 16
		if n < 4+16+2 {
			return nil, nil, 0, fmt.Errorf("socks5 udp ipv6 header too short")
		}
		ip = net.IP(buf[4 : 4+16])
		port = int(binary.BigEndian.Uint16(buf[20:22]))
	default:
		return nil, nil, 0, fmt.Errorf("socks5 udp unknown ATYP: %d", atyp)
	}

	dataStart := 4 + addrLen + 2
	if dataStart > n {
		return nil, nil, 0, fmt.Errorf("socks5 udp data offset out of range")
	}
	data = buf[dataStart:n]
	return data, ip, port, nil
}

// SetReadDeadline 设置读取超时。
func (r *UDPRelay) SetReadDeadline(t time.Time) {
	r.relayConn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入超时。
func (r *UDPRelay) SetWriteDeadline(t time.Time) {
	r.relayConn.SetWriteDeadline(t)
}

// Close 关闭 UDP 关联。
func (r *UDPRelay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	if r.relayConn != nil {
		r.relayConn.Close()
	}
	if r.clientConn != nil {
		r.clientConn.Close()
	}
	return nil
}

// SOCKS5Conn 包装 SOCKS5 UDP relay，实现 net.Conn 接口。
// 用于替代 IKE client 中的 net.UDPConn，使 IKE/ESP 流量通过 SOCKS5 代理。
type SOCKS5Conn struct {
	relay     *UDPRelay
	dstIP     net.IP
	dstDomain string // 域名模式（ATYP=3），为空则用 dstIP
	dstPort   int
}

// NewSOCKS5Conn 创建一个面向固定目标的 SOCKS5 UDP 连接。
// 行为类似于 net.DialUDP 返回的连接，但所有流量经过 SOCKS5 代理。
func NewSOCKS5Conn(proxyAddr string, dstIP net.IP, dstPort int) (*SOCKS5Conn, error) {
	relay, err := NewUDPRelay(proxyAddr)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Conn{
		relay:   relay,
		dstIP:   dstIP,
		dstPort: dstPort,
	}, nil
}

// NewSOCKS5ConnByDomain 创建一个用域名目标的 SOCKS5 UDP 连接。
// 使用 ATYP=3 (DOMAINNAME)，让代理服务器按域名路由和解析。
func NewSOCKS5ConnByDomain(proxyAddr, domain string, dstPort int) (*SOCKS5Conn, error) {
	relay, err := NewUDPRelay(proxyAddr)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Conn{
		relay:     relay,
		dstDomain: domain,
		dstPort:   dstPort,
	}, nil
}

// Write 发送数据到固定目标。
func (d *SOCKS5Conn) Write(data []byte) (int, error) {
	var err error
	if d.dstDomain != "" {
		err = d.relay.SendToDomain(data, d.dstDomain, d.dstPort)
	} else {
		err = d.relay.SendTo(data, d.dstIP, d.dstPort)
	}
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// Read 读取数据。
func (d *SOCKS5Conn) Read(buf []byte) (int, error) {
	data, _, _, err := d.relay.ReadFrom(buf)
	if err != nil {
		return 0, err
	}
	copy(buf, data)
	return len(data), nil
}

// SetDeadline 设置读写超时。
func (d *SOCKS5Conn) SetDeadline(t time.Time) error {
	d.relay.SetReadDeadline(t)
	d.relay.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline 设置读取超时。
func (d *SOCKS5Conn) SetReadDeadline(t time.Time) error {
	d.relay.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline 设置写入超时。
func (d *SOCKS5Conn) SetWriteDeadline(t time.Time) error {
	d.relay.SetWriteDeadline(t)
	return nil
}

// Close 关闭连接。
func (d *SOCKS5Conn) Close() error {
	return d.relay.Close()
}

// LocalAddr 返回本地地址（用于兼容）。
func (d *SOCKS5Conn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// RemoteAddr 返回目标地址。
func (d *SOCKS5Conn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: d.dstIP, Port: d.dstPort}
}

// -----------------------------------------------------------------------
// SOCKS5 TCP CONNECT — 用于 IKE over TCP (RFC 8229)
// -----------------------------------------------------------------------

// SOCKS5TCPConn 通过 SOCKS5 TCP CONNECT 建立的隧道连接。
// 用于 IKE over TCP (RFC 8229)，在 TCP 4500 上传输 IKE 消息。
// TCP 模式下不需要 Non-ESP Marker，但 ePDG 在 TCP 4500 上仍然期望它。
type SOCKS5TCPConn struct {
	conn net.Conn
}

// NewSOCKS5TCPConn 通过 SOCKS5 代理建立到 dstIP:dstPort 的 TCP 连接。
func NewSOCKS5TCPConn(proxyAddr string, dstIP net.IP, dstPort int) (*SOCKS5TCPConn, error) {
	tcpConn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks5 tcp dial: %w", err)
	}

	// SOCKS5 握手 - 无认证
	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting response: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting failed: method=%d", resp[1])
	}

	// SOCKS5 CONNECT 命令
	var req []byte
	if dstIP.To4() != nil {
		// IPv4: ATYP=1
		req = make([]byte, 4+4+2)
		req[0] = 0x05 // VER
		req[1] = 0x01 // CMD=CONNECT
		req[2] = 0x00 // RSV
		req[3] = 0x01 // ATYP=IPv4
		copy(req[4:8], dstIP.To4())
		binary.BigEndian.PutUint16(req[8:10], uint16(dstPort))
	} else {
		// IPv6: ATYP=4
		req = make([]byte, 4+16+2)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x04
		copy(req[4:20], dstIP.To16())
		binary.BigEndian.PutUint16(req[20:22], uint16(dstPort))
	}

	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}

	// 读取响应
	rep := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, rep); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 connect response: %w", err)
	}
	if rep[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 connect failed: rep=%d", rep[1])
	}

	// 读取并丢弃 BND.ADDR + BND.PORT
	switch rep[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(tcpConn, make([]byte, 4+2)); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd ipv4 addr: %w", err)
		}
	case 0x03: // Domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lb); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd domain len: %w", err)
		}
		if _, err := io.ReadFull(tcpConn, make([]byte, int(lb[0])+2)); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd domain: %w", err)
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(tcpConn, make([]byte, 16+2)); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd ipv6 addr: %w", err)
		}
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 unsupported BND ATYP: %d", rep[3])
	}

	return &SOCKS5TCPConn{conn: tcpConn}, nil
}

// NewSOCKS5TCPConnByDomain 通过 SOCKS5 代理建立到 domain:dstPort 的 TCP 连接。
// 使用 ATYP=3 (DOMAINNAME)，让代理服务器按域名路由和解析。
func NewSOCKS5TCPConnByDomain(proxyAddr, domain string, dstPort int) (*SOCKS5TCPConn, error) {
	tcpConn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks5 tcp dial: %w", err)
	}

	// SOCKS5 握手 - 无认证
	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, resp); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting response: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 greeting failed: method=%d", resp[1])
	}

	// SOCKS5 CONNECT 命令，ATYP=3 (DOMAINNAME)
	domainBytes := []byte(domain)
	if len(domainBytes) > 255 {
		tcpConn.Close()
		return nil, fmt.Errorf("domain too long")
	}
	req := make([]byte, 4+1+len(domainBytes)+2)
	req[0] = 0x05 // VER
	req[1] = 0x01 // CMD=CONNECT
	req[2] = 0x00 // RSV
	req[3] = 0x03 // ATYP=Domain
	req[4] = byte(len(domainBytes))
	copy(req[5:], domainBytes)
	binary.BigEndian.PutUint16(req[5+len(domainBytes):], uint16(dstPort))

	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}

	// 读取响应
	rep := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, rep); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 connect response: %w", err)
	}
	if rep[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 connect failed: rep=%d", rep[1])
	}

	// 读取并丢弃 BND.ADDR + BND.PORT
	switch rep[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(tcpConn, make([]byte, 4+2)); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd ipv4 addr: %w", err)
		}
	case 0x03: // Domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(tcpConn, lb); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd domain len: %w", err)
		}
		if _, err := io.ReadFull(tcpConn, make([]byte, int(lb[0])+2)); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd domain: %w", err)
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(tcpConn, make([]byte, 16+2)); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 read bnd ipv6 addr: %w", err)
		}
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 unsupported BND ATYP: %d", rep[3])
	}

	return &SOCKS5TCPConn{conn: tcpConn}, nil
}

// Write 发送数据。
func (c *SOCKS5TCPConn) Write(data []byte) (int, error) {
	return c.conn.Write(data)
}

// Read 读取数据。
func (c *SOCKS5TCPConn) Read(buf []byte) (int, error) {
	return c.conn.Read(buf)
}

// SetDeadline 设置读写超时。
func (c *SOCKS5TCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline 设置读取超时。
func (c *SOCKS5TCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入超时。
func (c *SOCKS5TCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Close 关闭连接。
func (c *SOCKS5TCPConn) Close() error {
	return c.conn.Close()
}

// LocalAddr 返回本地地址。
func (c *SOCKS5TCPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr 返回远端地址。
func (c *SOCKS5TCPConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
