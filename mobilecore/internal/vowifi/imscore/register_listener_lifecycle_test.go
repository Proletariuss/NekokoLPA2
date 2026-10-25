package imscore

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/policy"
)

// Exercise the complete initial -> AKA -> protected REGISTER call stack:
// testing only runSecurePreparedRegister misses the outer session's cleanup.
func TestRegisterSessionTransfersPortSOwnership(t *testing.T) {
	for _, ip := range []string{"192.0.2.10", "2001:db8::10"} {
		for _, plain := range []bool{false, true} {
			for _, status := range []int{sip.StatusOK, sip.StatusForbidden} {
				t.Run(fmt.Sprintf("%s/plain=%t/status=%d", ip, plain, status), func(t *testing.T) {
					remote := "192.0.2.20"
					if strings.Contains(ip, ":") {
						remote = "2001:db8::20"
					}
					cfg := Config{
						LocalIP: net.ParseIP(ip), PCSCFAddr: net.JoinHostPort(remote, "5060"),
						HomeDomain: "ims.example.test", Realm: "ims.example.test",
						PrivateID: "user@ims.example.test", PublicURI: "sip:user@ims.example.test",
						AKA: &recordingAKAProvider{}, Template: policy.DefaultGiffgaffTemplate(),
					}
					if plain {
						cfg.Template.AllowPlainIMS = true
						cfg.Template.SecAgreeMode = "disabled"
					}
					listener := newServiceStateTrackingListener()
					initial := &registerLifecycleConn{challenge: true, plain: plain, status: status}
					protected := &registerLifecycleConn{status: status}
					dialer := &registerLifecycleDialer{listener: listener, conn: protected}
					network := &registerLifecycleNetwork{conn: initial}
					session := newRegisterSession(cfg, dialer, network, "tcp", 0)
					session.jitter = false
					result, err := session.runInitialRegisterFlow(context.Background())
					if status != sip.StatusOK {
						if err == nil || !strings.Contains(err.Error(), "403") {
							t.Fatalf("registration failure was lost: result=%v err=%v", result, err)
						}
						if listener.closes.Load() == 0 {
							t.Fatal("failed REGISTER leaked its prepared listener")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					defer result.portSListener.Close()
					if result.portSListener != listener || listener.closes.Load() != 0 {
						t.Fatalf("successful REGISTER returned a closed or lost Port-S listener: closes=%d", listener.closes.Load())
					}
					if session.state.portSListener != nil {
						t.Fatal("session retained ownership of the runtime's Port-S listener")
					}
					retained := protected
					if plain {
						retained = initial
					} else if network.installed == nil {
						t.Fatal("secure REGISTER bypassed IPsec installation")
					}
					if retained.closed {
						t.Fatal("successful REGISTER closed retained Port-C connection")
					}
					_ = retained.Close()
				})
			}
		}
	}
}

type registerLifecycleNetwork struct {
	captureIMSNetwork
	conn      net.Conn
	installed *ipsec3gpp.Transport
}

func (n *registerLifecycleNetwork) DialContext(context.Context, string, net.Addr, string, DialOptions) (net.Conn, error) {
	return n.conn, nil
}

func (n *registerLifecycleNetwork) InstallIPSec(transport *ipsec3gpp.Transport) error {
	n.installed = transport
	return nil
}

type registerLifecycleDialer struct {
	listener net.Listener
	conn     net.Conn
}

func (d *registerLifecycleDialer) DialContextTCP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return d.conn, nil
}
func (d *registerLifecycleDialer) ListenContextTCP(context.Context, net.IP, int) (net.Listener, error) {
	return d.listener, nil
}
func (*registerLifecycleDialer) Close() error { return nil }

type registerLifecycleConn struct {
	response                 bytes.Buffer
	challenge, plain, closed bool
	status                   int
}

func (c *registerLifecycleConn) Write(payload []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	message, err := sip.ParseMessage(payload)
	if err != nil {
		return 0, err
	}
	req := message.(*sip.Request)
	status, reason := c.status, "OK"
	if status != sip.StatusOK {
		reason = "Forbidden"
	}
	if c.challenge {
		status, reason = sip.StatusUnauthorized, "Unauthorized"
	}
	res := sip.NewResponseFromRequest(req, status, reason, nil)
	if c.challenge {
		res.AppendHeader(sip.NewHeader("WWW-Authenticate", `Digest realm="ims.example.test",nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`",algorithm=AKAv1-MD5,qop="auth"`))
		if !c.plain {
			res.AppendHeader(sip.NewHeader("Security-Server", "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;spi-c=111;spi-s=222;port-c=6050;port-s=6060"))
		}
		c.challenge = false
	}
	c.response.WriteString(res.String())
	return len(payload), nil
}
func (c *registerLifecycleConn) Read(b []byte) (int, error) { return c.response.Read(b) }
func (c *registerLifecycleConn) Close() error               { c.closed = true; return nil }
func (*registerLifecycleConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5064}
}
func (*registerLifecycleConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 6060}
}
func (*registerLifecycleConn) SetDeadline(time.Time) error      { return nil }
func (*registerLifecycleConn) SetReadDeadline(time.Time) error  { return nil }
func (*registerLifecycleConn) SetWriteDeadline(time.Time) error { return nil }
