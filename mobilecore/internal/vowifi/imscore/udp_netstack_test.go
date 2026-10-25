package imscore

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"proletarius.local/core/internal/vowifi/ipsec3gpp"
)

// Paired SWu boundaries carry real gVisor IP packets without any OS socket.
type udpPacketLink struct {
	rx, tx               chan []byte
	plaintext, oversized atomic.Int32
}

func (d *udpPacketLink) InnerPackets() <-chan []byte { return d.rx }
func (d *udpPacketLink) SendInnerPacket(packet []byte) error {
	if len(packet) > 1280 {
		d.oversized.Add(1)
	}
	protocol := packet[9]
	if packet[0]>>4 == 6 {
		protocol = packet[6]
		if protocol == 44 && len(packet) > 40 {
			protocol = packet[40]
		}
	}
	if protocol != 50 {
		d.plaintext.Add(1)
	}
	select {
	case d.tx <- append([]byte(nil), packet...):
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("test link saturated")
	}
}

func TestUDPUserspaceNetstackProtectedLargeDatagrams(t *testing.T) {
	for _, ips := range [][2]string{{"192.0.2.10", "192.0.2.20"}, {"2001:db8::10", "2001:db8::20"}} {
		t.Run(ips[0], func(t *testing.T) {
			leftRX, rightRX := make(chan []byte, 64), make(chan []byte, 64)
			leftLink := &udpPacketLink{rx: leftRX, tx: rightRX}
			rightLink := &udpPacketLink{rx: rightRX, tx: leftRX}
			left, err := NewUserspaceIMSNetwork(net.ParseIP(ips[0]), leftLink)
			if err != nil {
				t.Fatal(err)
			}
			defer left.Close()
			right, err := NewUserspaceIMSNetwork(net.ParseIP(ips[1]), rightLink)
			if err != nil {
				t.Fatal(err)
			}
			defer right.Close()
			makeTransport := func(local, remote string, localC, localS, remoteC, remoteS int, spiC, spiS, peerC, peerS uint32) *ipsec3gpp.Transport {
				p, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{LocalIP: net.ParseIP(local), RemoteIP: net.ParseIP(remote), LocalPortC: localC, LocalPortS: localS, LocalSPIC: spiC, LocalSPIS: spiS, CK: bytes.Repeat([]byte{1}, 16), IK: bytes.Repeat([]byte{2}, 16), Mech: ipsec3gpp.SecurityMechanism{SPIc: peerC, SPIs: peerS, PortC: remoteC, PortS: remoteS, Alg: "hmac-sha-1-96", EAlg: "aes-cbc"}})
				if err != nil {
					t.Fatal(err)
				}
				transport, err := ipsec3gpp.NewTransport(p)
				if err != nil {
					t.Fatal(err)
				}
				return transport
			}
			if err := left.InstallIPSec(makeTransport(ips[0], ips[1], 5064, 5063, 6050, 6060, 3333, 4444, 1111, 2222)); err != nil {
				t.Fatal(err)
			}
			if err := right.InstallIPSec(makeTransport(ips[1], ips[0], 6050, 6060, 5064, 5063, 1111, 2222, 3333, 4444)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, ports := range [][2]int{{5064, 6060}, {5063, 6050}} {
				leftConn, err := left.ListenPacket(ctx, "udp", &net.UDPAddr{IP: net.ParseIP(ips[0]), Port: ports[0]})
				if err != nil {
					t.Fatal(err)
				}
				defer leftConn.Close()
				rightConn, err := right.ListenPacket(ctx, "udp", &net.UDPAddr{IP: net.ParseIP(ips[1]), Port: ports[1]})
				if err != nil {
					t.Fatal(err)
				}
				defer rightConn.Close()
				for _, size := range []int{200, 1800, 4000} {
					payload := bytes.Repeat([]byte("U"), size)
					if _, err := leftConn.WriteTo(payload, rightConn.LocalAddr()); err != nil {
						t.Fatal(err)
					}
					_ = rightConn.SetReadDeadline(time.Now().Add(time.Second))
					buf := make([]byte, 8192)
					n, peer, err := rightConn.ReadFrom(buf)
					if err != nil {
						t.Fatalf("size %d forward: %v left=%+v right=%+v", size, err, left.IPSecDataplaneStats(), right.IPSecDataplaneStats())
					}
					if !bytes.Equal(buf[:n], payload) {
						t.Fatal("datagram changed during protected fragmentation")
					}
					if _, err := rightConn.WriteTo(buf[:n], peer); err != nil {
						t.Fatal(err)
					}
					_ = leftConn.SetReadDeadline(time.Now().Add(time.Second))
					n, _, err = leftConn.ReadFrom(buf)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(buf[:n], payload) {
						t.Fatal("reverse datagram changed")
					}
				}
			}
			if leftLink.plaintext.Load() != 0 || rightLink.plaintext.Load() != 0 {
				t.Fatalf("protected UDP leaked plaintext: %d/%d", leftLink.plaintext.Load(), rightLink.plaintext.Load())
			}
			if leftLink.oversized.Load() != 0 || rightLink.oversized.Load() != 0 {
				t.Fatal("encrypted UDP exceeded SWu packet budget")
			}
		})
	}
}
