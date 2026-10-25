package voiceclient

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type stubSWUDataplane struct{}

func (stubSWUDataplane) SendInnerPacket([]byte) error { return nil }
func (stubSWUDataplane) InnerPackets() <-chan []byte {
	ch := make(chan []byte)
	close(ch)
	return ch
}

func newTestSWUNetstack(t *testing.T, localIP net.IP) *swuNetstack {
	t.Helper()
	ns, err := newSWUNetstack(localIP, stubSWUDataplane{})
	if err != nil {
		t.Fatalf("newSWUNetstack: %v", err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func bindTestReservation(t *testing.T, ns *swuNetstack, ip net.IP, port int, reuse bool) tcpip.Endpoint {
	t.Helper()
	var wq waiter.Queue
	ep, err := ns.stack.NewEndpoint(gtcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if reuse {
		ep.SocketOptions().SetReuseAddress(true)
	}
	addr := tcpip.FullAddress{NIC: swuNetstackNICID, Addr: addrFromNetIP(ip), Port: uint16(port)}
	if tcpErr := ep.Bind(addr); tcpErr != nil {
		t.Fatalf("Bind: %v", tcpErr)
	}
	return ep
}

// 回归测试：AKA 受保护端口（port-c）在重试时必须能穿过同一共享 netstack
// 上残留的端口预留（等价 60s TIME_WAIT 场景）。修复后
// dialTCPWithBindKeepalive 对每个端点设置 SO_REUSEADDR（TupleOnly flag），
// 新旧预留共享该 flag 时 gvisor 允许复用端口，
// 不再出现 "bind userspace TCP endpoint: port is in use"。
func TestSWUNetstackDialReusesPortWithSharedReuseFlag(t *testing.T) {
	localIP := net.ParseIP("10.127.199.98")
	ns := newTestSWUNetstack(t, localIP)
	// 模拟上一次拨号留下的同 flag 端口预留（修复后的拨号均带 SO_REUSEADDR）
	prev := bindTestReservation(t, ns, localIP, 5064, true)
	defer prev.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	local := tcpip.FullAddress{NIC: swuNetstackNICID, Addr: addrFromNetIP(localIP), Port: 5064}
	remote := tcpip.FullAddress{NIC: swuNetstackNICID, Addr: addrFromNetIP(net.ParseIP("10.127.199.99")), Port: 50600}
	_, err := dialTCPWithBindKeepalive(ctx, ns.stack, local, remote, ipv4.ProtocolNumber, 0)
	if err == nil {
		t.Fatal("dial without a dataplane peer should not succeed")
	}
	if strings.Contains(err.Error(), "port is in use") {
		t.Fatalf("port reuse blocked by lingering reservation: %v", err)
	}
	// bind 已通过，失败应来自连接超时
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected connect timeout after successful bind, got: %v", err)
	}
}

// 语义守护：gvisor 遵循 Linux 语义——旧预留未设置 SO_REUSEADDR 时，
// 即使新端点设置了也不允许复用。该测试证明上一条测试的通过确实来自
// dialTCPWithBindKeepalive 为新端点设置了 SO_REUSEADDR。
func TestSWUNetstackDialBlockedByLegacyReservation(t *testing.T) {
	localIP := net.ParseIP("10.127.199.98")
	ns := newTestSWUNetstack(t, localIP)
	prev := bindTestReservation(t, ns, localIP, 5065, false)
	defer prev.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	local := tcpip.FullAddress{NIC: swuNetstackNICID, Addr: addrFromNetIP(localIP), Port: 5065}
	remote := tcpip.FullAddress{NIC: swuNetstackNICID, Addr: addrFromNetIP(net.ParseIP("10.127.199.99")), Port: 50600}
	_, err := dialTCPWithBindKeepalive(ctx, ns.stack, local, remote, ipv4.ProtocolNumber, 0)
	if err == nil || !strings.Contains(err.Error(), "port is in use") {
		t.Fatalf("expected port-in-use against a legacy reservation, got: %v", err)
	}
}
