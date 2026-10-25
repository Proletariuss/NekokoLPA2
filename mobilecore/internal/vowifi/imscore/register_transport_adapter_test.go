package imscore

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

func TestConnRegisterTransportReleaseTransfersConnectionOwnership(t *testing.T) {
	client, server := net.Pipe()
	transport := newConnRegisterTransport(client, "trace", "device")
	released := transport.ReleaseConn()
	if released != client {
		t.Fatalf("released connection = %T, want original", released)
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := released.Write([]byte("ok"))
		writeDone <- err
	}()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("released connection was closed by transport: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	_ = released.Close()
	_ = server.Close()
}

func TestEnsureSIPStreamFramingAddsZeroContentLength(t *testing.T) {
	req := sip.NewRequest(sip.REGISTER, sip.Uri{Host: "ims.example.test"})
	if req.ContentLength() != nil {
		t.Fatal("new request unexpectedly has Content-Length")
	}
	ensureSIPStreamFraming(req)
	if req.ContentLength() == nil || req.ContentLength().Value() != "0" {
		t.Fatalf("Content-Length=%v", req.ContentLength())
	}
	if !strings.Contains(req.String(), "Content-Length: 0\r\n") {
		t.Fatalf("framed request missing Content-Length: %q", req.String())
	}
}
