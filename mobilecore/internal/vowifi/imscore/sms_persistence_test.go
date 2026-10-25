package imscore

import (
	"errors"
	"github.com/emiago/sipgo/sip"
	"testing"
	"time"
)

func TestIncomingSMSAckRequiresPersistence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		persisted, acknowledged := false, false
		rt := &transportRuntime{}
		rt.cfg.IncomingSMS = func(sender, content string, at time.Time) error {
			if content != "A" {
				t.Fatalf("unexpected decoded fixture: %q", content)
			}
			if fail {
				return errors.New("disk unavailable")
			}
			persisted = true
			return nil
		}
		rt.sendRPAck = func(_ string, _ byte) {
			if !persisted {
				t.Fatal("acknowledged before persistence")
			}
			acknowledged = true
		}
		req := sip.NewRequest(sip.MESSAGE, sip.Uri{Host: "ims.example.test"})
		req.AppendHeader(sip.NewHeader("Content-Type", imsSMSContentType))
		req.AppendHeader(sip.NewHeader("From", "<sip:smsc@ims.example.test>"))
		tpdu := []byte{0, 3, 0x81, 0x88, 0xf8, 0, 8, 0x62, 0x90, 0x60, 0, 0, 0, 0, 2, 0, 0x41}
		req.SetBody(append([]byte{1, 42, 0, 0, byte(len(tpdu))}, tpdu...))
		rt.handleIncomingRequest(req)
		if acknowledged == fail {
			t.Fatalf("ack=%v failure=%v", acknowledged, fail)
		}
	}
}

func TestIncomingSMSUsesNativeDeliveryDecoderBeforeAcknowledging(t *testing.T) {
	persisted, acknowledged := false, false
	rt := &transportRuntime{}
	rt.cfg.DecodeIncomingSMS = func(tpdu []byte) (InboundSMS, bool, error) {
		if len(tpdu) == 0 || tpdu[0]&3 != 0 {
			t.Fatal("unexpected TPDU")
		}
		return InboundSMS{Sender: "native", Content: "decoded", Timestamp: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC), HasTimestamp: true}, true, nil
	}
	rt.cfg.IncomingSMS = func(sender, content string, at time.Time) error {
		if sender != "native" || content != "decoded" || at.Year() != 2026 {
			t.Fatalf("native result lost: %q %q %s", sender, content, at)
		}
		persisted = true
		return nil
	}
	rt.sendRPAck = func(_ string, _ byte) {
		if !persisted {
			t.Fatal("ack before native persistence")
		}
		acknowledged = true
	}
	req := sip.NewRequest(sip.MESSAGE, sip.Uri{Host: "ims.example.test"})
	req.AppendHeader(sip.NewHeader("Content-Type", imsSMSContentType))
	req.AppendHeader(sip.NewHeader("From", "<sip:smsc@ims.example.test>"))
	tpdu := []byte{0, 3, 0x81, 0x88, 0xf8, 0, 8, 0x62, 0x90, 0x60, 0, 0, 0, 0, 2, 0, 0x41}
	req.SetBody(append([]byte{1, 42, 0, 0, byte(len(tpdu))}, tpdu...))
	rt.handleIncomingRequest(req)
	if !acknowledged {
		t.Fatal("native message was not acknowledged")
	}
}

func TestIncomingSMSUsesNativeStatusReportDecoder(t *testing.T) {
	acknowledged := false
	rt := &transportRuntime{}
	rt.cfg.DecodeIncomingSMS = func(tpdu []byte) (InboundSMS, bool, error) {
		if len(tpdu) == 0 || tpdu[0]&3 != 2 {
			t.Fatal("unexpected TPDU")
		}
		return InboundSMS{StatusReport: true, DeliveryStatus: "delivered"}, true, nil
	}
	rt.cfg.IncomingSMS = func(string, string, time.Time) error {
		t.Fatal("status report must not enter the message archive")
		return nil
	}
	rt.sendRPAck = func(_ string, reference byte) {
		if reference != 42 {
			t.Fatalf("unexpected reference: %d", reference)
		}
		acknowledged = true
	}
	req := sip.NewRequest(sip.MESSAGE, sip.Uri{Host: "ims.example.test"})
	req.AppendHeader(sip.NewHeader("Content-Type", imsSMSContentType))
	req.AppendHeader(sip.NewHeader("From", "<sip:smsc@ims.example.test>"))
	tpdu := []byte{2, 1, 4, 0x91, 0x44, 0x77, 0x62, 0x80, 0x62, 0x61, 0x21, 0, 0, 0x62, 0x80, 0x62, 0x61, 0x21, 0, 0, 0}
	req.SetBody(append([]byte{1, 42, 0, 0, byte(len(tpdu))}, tpdu...))
	rt.handleIncomingRequest(req)
	if !acknowledged {
		t.Fatal("native status report was not acknowledged")
	}
}

func TestIncomingMultipartPersistsMetadataBeforeRPAck(t *testing.T) {
	for _, fail := range []bool{false, true} {
		persisted, acked := false, false
		rt := &transportRuntime{}
		rt.cfg.IncomingSMSMessage = func(message InboundSMS) error {
			if message.ConcatReference != 42 || message.ConcatTotal != 2 || message.ConcatSequence != 1 || message.Content != "A" {
				t.Fatalf("multipart metadata lost: %+v", message)
			}
			if fail {
				return errors.New("durable fragment store failed")
			}
			persisted = true
			return nil
		}
		rt.sendRPAck = func(string, byte) {
			if !persisted {
				t.Fatal("fragment acknowledged before durable persistence")
			}
			acked = true
		}
		req := sip.NewRequest(sip.MESSAGE, sip.Uri{Host: "ims.example.test"})
		req.AppendHeader(sip.NewHeader("Content-Type", imsSMSContentType))
		req.AppendHeader(sip.NewHeader("From", "<sip:smsc@ims.example.test>"))
		tpdu := []byte{0x40, 3, 0x81, 0x88, 0xf8, 0, 8, 0x62, 0x90, 0x60, 0, 0, 0, 0, 8, 5, 0, 3, 42, 2, 1, 0, 0x41}
		req.SetBody(append([]byte{1, 42, 0, 0, byte(len(tpdu))}, tpdu...))
		rt.handleIncomingRequest(req)
		if acked == fail {
			t.Fatalf("fragment ack=%v, store failure=%v", acked, fail)
		}
	}
}
