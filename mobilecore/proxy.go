package mobilecore

import (
	"encoding/binary"
	"fmt"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/swu"
	"net"
	"proletarius.local/core/internal/vowifi/socks5"
	"strconv"
	"sync"
)

func newReaderSWUProxyTransportFactory(proxy string) func(string, string) (swu.Transport, error) {
	return func(_, remote string) (swu.Transport, error) {
		host, portText, err := net.SplitHostPort(remote)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid ePDG port")
		}
		relay, err := socks5.NewUDPRelay(proxy)
		if err != nil {
			return nil, err
		}
		return &proxyTransport{relay: relay, host: host, port: port, ike: make(chan []byte, 100), esp: make(chan []byte, 1000), events: make(chan ipsec.NetEvent, 4), closed: make(chan struct{})}, nil
	}
}

type proxyTransport struct {
	relay       *socks5.UDPRelay
	mu          sync.RWMutex
	host        string
	port        int
	ike, esp    chan []byte
	events      chan ipsec.NetEvent
	closed      chan struct{}
	start, stop sync.Once
	wg          sync.WaitGroup
}

func (t *proxyTransport) Start() { t.start.Do(func() { t.wg.Add(1); go t.readLoop() }) }
func (t *proxyTransport) Stop() {
	t.stop.Do(func() {
		close(t.closed)
		_ = t.relay.Close()
		t.wg.Wait()
		close(t.ike)
		close(t.esp)
		close(t.events)
	})
}
func (t *proxyTransport) IKEPackets() <-chan []byte            { return t.ike }
func (t *proxyTransport) ESPPackets() <-chan []byte            { return t.esp }
func (t *proxyTransport) NetEventsChan() <-chan ipsec.NetEvent { return t.events }
func (t *proxyTransport) SendIKE(data []byte) error {
	if t.RemotePort() == 4500 {
		data = append(make([]byte, 4), data...)
	}
	return t.send(data)
}
func (t *proxyTransport) SendESP(data []byte) error { return t.send(data) }
func (t *proxyTransport) SendNATKeepalive() error   { return t.send([]byte{0xff}) }
func (t *proxyTransport) send(data []byte) error {
	t.mu.RLock()
	host, port := t.host, t.port
	t.mu.RUnlock()
	if ip := net.ParseIP(host); ip != nil {
		return t.relay.SendTo(data, ip, port)
	}
	return t.relay.SendToDomain(data, host, port)
}
func (t *proxyTransport) SetRemotePort(port int) {
	if port > 0 && port <= 65535 {
		t.mu.Lock()
		t.port = port
		t.mu.Unlock()
	}
}
func (t *proxyTransport) RemotePort() int         { t.mu.RLock(); defer t.mu.RUnlock(); return t.port }
func (t *proxyTransport) LocalPort() uint16       { return 0 }
func (t *proxyTransport) LocalIP() net.IP         { return nil }
func (t *proxyTransport) RemoteIP() net.IP        { return net.ParseIP(t.host) }
func (t *proxyTransport) LocalAddrString() string { return "socks5://dynamic" }
func (t *proxyTransport) RemoteAddrString() string {
	return net.JoinHostPort(t.host, strconv.Itoa(t.RemotePort()))
}
func (t *proxyTransport) readLoop() {
	defer t.wg.Done()
	buffer := make([]byte, 65535)
	for {
		data, _, port, err := t.relay.ReadFrom(buffer)
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			select {
			case t.events <- ipsec.NetEvent{Type: ipsec.EventNetworkDown, Reason: "SOCKS5 relay disconnected"}:
			default:
			}
			return
		}
		if port > 0 {
			t.SetRemotePort(port)
		}
		if len(data) == 0 || (len(data) == 1 && data[0] == 255) {
			continue
		}
		packet := append([]byte(nil), data...)
		if len(packet) >= 4 && binary.BigEndian.Uint32(packet[:4]) == 0 {
			packet = packet[4:]
		}
		isIKE := len(packet) >= 28 && packet[17]>>4 == 2 && packet[18] >= 34 && packet[18] <= 37 && int(binary.BigEndian.Uint32(packet[24:28])) == len(packet)
		target := t.esp
		if isIKE {
			target = t.ike
		} else {
			packet = append([]byte(nil), data...)
		}
		select {
		case target <- packet:
		case <-t.closed:
			return
		}
	}
}
