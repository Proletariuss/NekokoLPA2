package imscore

import (
	"context"
	"github.com/emiago/sipgo/sip"
	"strings"
	"testing"
	"time"
)

func TestDTMFInfoUsesDialogAndRequiresAcknowledgement(t *testing.T) {
	for _, code := range []int{200, 415, 0} {
		rt := &transportRuntime{tcpWriteCh: make(chan sipWriteTask, 1), responses: make(map[string]map[uint64]chan *sip.Response)}
		service := &Service{cfg: Config{HomeDomain: "ims.example.test", Realm: "ims.example.test"}, transportRuntime: rt}
		c := newCallRuntime(service)
		c.state = CallState{State: "active", Peer: "1033", CallID: "dtmf-test"}
		c.remoteTarget = "sip:ivr@192.0.2.5"
		c.routeSet = []string{"<sip:192.0.2.6;lr>"}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- c.sendDTMFInfo(ctx, 11) }()
		var task sipWriteTask
		select {
		case task = <-rt.tcpWriteCh:
		case <-ctx.Done():
			t.Fatal("no INFO sent")
		}
		wire := string(task.payload)
		for _, want := range []string{"INFO sip:ivr@192.0.2.5", "Route: <sip:192.0.2.6;lr>", "application/dtmf-relay", "Signal=#\r\nDuration=160"} {
			if !strings.Contains(wire, want) {
				t.Fatalf("missing %q in INFO", want)
			}
		}
		task.done <- nil
		if code != 0 {
			response := sip.NewResponse(code, "test")
			response.AppendHeader(sip.NewHeader("Call-ID", "dtmf-test"))
			response.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INFO})
			rt.publishResponse(response)
		}
		err := <-done
		cancel()
		if (err == nil) != (code == 200) {
			t.Fatalf("status=%d err=%v", code, err)
		}
	}
}
