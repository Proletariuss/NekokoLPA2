package imscore

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestReadValidatedRegisterResponseGatesTransaction(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	transport := newConnRegisterTransport(client, "trace", "reader")
	defer transport.Close()
	req := sip.NewRequest(sip.REGISTER, sip.Uri{Host: "ims.example"})
	req.AppendHeader(sip.NewHeader("Call-ID", "reg-1"))
	req.AppendHeader(sip.NewHeader("CSeq", "7 REGISTER"))
	validated := false
	cfg := Config{ValidateRegisterResponse: func(_ context.Context, response []byte, callID string, cseq uint32) error {
		if callID != "reg-1" || cseq != 7 || !strings.HasPrefix(string(response), "SIP/2.0 401") {
			t.Fatalf("invalid validation input: %q %d %q", callID, cseq, response)
		}
		validated = true
		return nil
	}}
	go func() {
		_, _ = server.Write([]byte("SIP/2.0 401 Unauthorized\r\nCall-ID: reg-1\r\nCSeq: 7 REGISTER\r\nContent-Length: 0\r\n\r\n"))
	}()
	res, err := readValidatedRegisterResponse(context.Background(), cfg, transport, req)
	if err != nil || res.StatusCode != 401 || !validated {
		t.Fatalf("response=%v validated=%v err=%v", res, validated, err)
	}
}

func TestRegisterRequestIdentityRejectsAmbiguity(t *testing.T) {
	for _, cseq := range []string{"", "0 REGISTER", "7 INVITE", "7 REGISTER extra", "not-a-number REGISTER"} {
		req := sip.NewRequest(sip.REGISTER, sip.Uri{Host: "ims.example"})
		req.AppendHeader(sip.NewHeader("Call-ID", "reg-1"))
		if cseq != "" {
			req.AppendHeader(sip.NewHeader("CSeq", cseq))
		}
		if _, _, err := registerRequestIdentity(req); err == nil {
			t.Fatalf("accepted CSeq %q", cseq)
		}
	}
}
