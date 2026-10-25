package device

import "testing"

func TestDecodeSMSDeliverTPDURecognizesStatusReport(t *testing.T) {
	// MTI=2 identifies SMS-STATUS-REPORT. The remaining fields are a
	// minimally valid status report with a successful delivery status.
	tpdu := []byte{
		0x02, 0x01,
		0x04, 0x91, 0x44, 0x77, 0x00,
		0x62, 0x80, 0x62, 0x61, 0x21, 0x00, 0x00,
		0x62, 0x80, 0x62, 0x61, 0x21, 0x00, 0x00,
		0x00,
	}

	message, err := DecodeSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("DecodeSMSDeliverTPDU() error = %v", err)
	}
	if message.Direction != SMSDirectionStatusReport {
		t.Fatalf("Direction = %q, want %q", message.Direction, SMSDirectionStatusReport)
	}
	if message.Text != "" {
		t.Fatalf("Text = %q, want empty status-report text", message.Text)
	}
}
