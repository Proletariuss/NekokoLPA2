package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestUDPRelayPreservesDomainTargetAndPayload(t *testing.T) {
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	serverErr := make(chan error, 1)
	go serveUDPAssociateOnce(tcpListener, udpConn.LocalAddr().(*net.UDPAddr), serverErr)

	relay, err := NewUDPRelay(tcpListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	wantPayload := []byte("ike-payload")
	if err := relay.SendToDomain(wantPayload, "epdg.example", 4500); err != nil {
		t.Fatal(err)
	}

	packet := make([]byte, 2048)
	if err := udpConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, sender, err := udpConn.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	packet = packet[:n]
	if len(packet) < 5 || packet[3] != 0x03 {
		t.Fatalf("SOCKS5 UDP header = %x", packet)
	}
	domainLength := int(packet[4])
	if len(packet) < 7+domainLength {
		t.Fatalf("SOCKS5 UDP domain packet too short: %d", len(packet))
	}
	if got := string(packet[5 : 5+domainLength]); got != "epdg.example" {
		t.Fatalf("domain = %q", got)
	}
	if got := int(binary.BigEndian.Uint16(packet[5+domainLength : 7+domainLength])); got != 4500 {
		t.Fatalf("port = %d", got)
	}
	if got := packet[7+domainLength:]; !bytes.Equal(got, wantPayload) {
		t.Fatalf("payload = %q", got)
	}

	if _, err := udpConn.WriteToUDP(packet, sender); err != nil {
		t.Fatal(err)
	}
	readBuffer := make([]byte, 2048)
	got, ip, port, err := relay.ReadFrom(readBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if ip != nil || port != 4500 || !bytes.Equal(got, wantPayload) {
		t.Fatalf("relay response = ip:%v port:%d payload:%q", ip, port, got)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	default:
	}
}

func serveUDPAssociateOnce(listener net.Listener, relayAddr *net.UDPAddr, result chan<- error) {
	conn, err := listener.Accept()
	if err != nil {
		result <- err
		return
	}
	defer conn.Close()
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		result <- err
		return
	}
	if !bytes.Equal(greeting, []byte{0x05, 0x01, 0x00}) {
		result <- fmt.Errorf("unexpected greeting: %x", greeting)
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		result <- err
		return
	}
	associate := make([]byte, 10)
	if _, err := io.ReadFull(conn, associate); err != nil {
		result <- err
		return
	}
	if associate[0] != 0x05 || associate[1] != 0x03 {
		result <- fmt.Errorf("unexpected associate request: %x", associate)
		return
	}
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:10], uint16(relayAddr.Port))
	if _, err := conn.Write(reply); err != nil {
		result <- err
		return
	}
	result <- nil
	buffer := make([]byte, 1)
	_, _ = conn.Read(buffer)
}
