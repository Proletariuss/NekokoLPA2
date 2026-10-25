package mobilecore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/swu"
	"proletarius.local/core/internal/vowifi/carrier"
	"proletarius.local/core/internal/vowifi/imscore"
	imssim "proletarius.local/core/internal/vowifi/sim"
)

type fakeHost struct {
	exchange func(string) (string, error)
	events   chan string
	store    func(string) error
}

func (h *fakeHost) StoreSMS(input string) error {
	if h.store == nil {
		return errors.New("storage unavailable")
	}
	return h.store(input)
}

func (h *fakeHost) ExchangeAPDUs(input string) (string, error) { return h.exchange(input) }
func (h *fakeHost) OnEvent(event string) {
	if h.events != nil {
		select {
		case h.events <- event:
		default:
		}
	}
}

func TestAKAParsesUSIMSuccessAndSyncFailure(t *testing.T) {
	raw := []byte{0xdb, 4, 1, 2, 3, 4, 16}
	raw = append(raw, bytes.Repeat([]byte{0x11}, 16)...)
	raw = append(raw, 16)
	raw = append(raw, bytes.Repeat([]byte{0x22}, 16)...)
	result, err := parseAKA(raw)
	if err != nil || len(result.RES) != 4 || len(result.CK) != 16 || len(result.IK) != 16 {
		t.Fatalf("invalid success: %+v %v", result, err)
	}
	result.Zero()
	if !bytes.Equal(result.CK, make([]byte, 16)) {
		t.Fatal("keys not cleared")
	}
	raw = append([]byte{0xdc, 14}, bytes.Repeat([]byte{3}, 14)...)
	result, err = parseAKA(raw)
	if !errors.Is(err, imssim.ErrSyncFailure) || len(result.AUTS) != 14 {
		t.Fatalf("sync result: %v", err)
	}
	for _, raw := range [][]byte{{}, {0xdb}, {0xdb, 30, 1}, {0xdc, 3, 1, 2, 3}} {
		if _, err := parseAKA(raw); err == nil {
			t.Fatalf("accepted malformed AKA: %x", raw)
		}
	}
}

func TestAKASelectAndAuthenticateAreOneBatch(t *testing.T) {
	host := &fakeHost{exchange: func(input string) (string, error) {
		var request struct {
			Commands   []string `json:"commands"`
			Generation int64    `json:"generation"`
		}
		if err := json.Unmarshal([]byte(input), &request); err != nil {
			t.Fatal(err)
		}
		if request.Generation != 42 || len(request.Commands) != 2 || !strings.HasPrefix(request.Commands[0], "00A40404") || !strings.HasPrefix(request.Commands[1], "008800812210") {
			t.Fatalf("unsafe AKA batch: %s", input)
		}
		return `{"responses":["9000","DC0E00000000000000000000000000009000"]}`, nil
	}}
	adapter := &simAdapter{engine: NewEngine(host), ctx: context.Background(), card: cardConfig{Generation: 42, USIMAID: "A0000000871002"}}
	result, err := adapter.authenticate(adapter.card.USIMAID, make([]byte, 16), make([]byte, 16))
	if !errors.Is(err, imssim.ErrSyncFailure) || len(result.AUTS) != 14 {
		t.Fatalf("sync failure lost: %v", err)
	}
}

func TestExchangeCancellationAndFraming(t *testing.T) {
	blocked := make(chan struct{})
	entered := make(chan struct{})
	host := &fakeHost{exchange: func(string) (string, error) { close(entered); <-blocked; return "", nil }}
	engine := NewEngine(host)
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { _, err := engine.exchange(ctx, 1, [][]byte{{0, 0xa4}}); returned <- err }()
	<-entered
	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SIM cancellation blocked on host")
	}
	close(blocked)
	for _, response := range []string{`{"responses":[]}`, `{"responses":["GARBAGE"]}`, `{"responses":["6982"]}`} {
		host := &fakeHost{exchange: func(string) (string, error) { return response, nil }}
		if _, err := NewEngine(host).exchange(context.Background(), 1, [][]byte{{0}}); err == nil {
			t.Fatalf("accepted %s", response)
		}
	}
}

func TestCardProbeUsesActualEFADAndSMSC(t *testing.T) {
	aid := []byte{0xa0, 0, 0, 0, 0x87, 0x10, 2}
	directory := append([]byte{0x61, 9, 0x4f, 7}, aid...)
	files := map[uint16][]byte{0x2fe2: {0x98, 0x44, 0x70, 0x10, 0x21, 0x43, 0x65, 0x87, 0x09, 0xf1}, 0x6f07: {8, 0x29, 0x43, 0x03, 0x21, 0x43, 0x65, 0x87, 0xf9}, 0x6fad: {0, 0, 0, 2}}
	smsp := bytes.Repeat([]byte{0xff}, 28)
	smsp[0] = 0xfd
	copy(smsp[13:], []byte{7, 0x91, 0x44, 0x77, 0x58, 0x10, 0, 0xf0})
	files[0x6f42] = smsp
	host := &fakeHost{exchange: func(input string) (string, error) {
		var request struct {
			Commands   []string `json:"commands"`
			Generation int64    `json:"generation"`
		}
		_ = json.Unmarshal([]byte(input), &request)
		if request.Generation != 7 || len(request.Commands) != 3 {
			t.Fatalf("unexpected read batch %s", input)
		}
		selected, _ := hex.DecodeString(request.Commands[1])
		id := uint16(selected[5])<<8 | uint16(selected[6])
		read, _ := hex.DecodeString(request.Commands[2])
		var data []byte
		if id == 0x2f00 {
			if read[2] != 1 {
				return "", errors.New("SIM status 6A83")
			}
			data = directory
		} else {
			var ok bool
			data, ok = files[id]
			if !ok {
				return "", errors.New("SIM status 6A82")
			}
		}
		return fmt.Sprintf(`{"responses":["9000","9000","%s9000"]}`, hex.EncodeToString(data)), nil
	}}
	card, err := NewEngine(host).readCard(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if card.IMSI != "23430123456789" || card.MCC != "234" || card.MNC != "30" {
		t.Fatalf("wrong identity %+v", card)
	}
	if card.SMSC != "+44778501000" || card.SMSCTarget != "tel:+44778501000" {
		t.Fatalf("wrong SMSC %q", card.SMSC)
	}
}

func TestMobilePoliciesAndValidation(t *testing.T) {
	if registrationRenewalDelay(3600) != 3300*time.Second || registrationRenewalDelay(600) != 450*time.Second || registrationRenewalDelay(10) != 8*time.Second {
		t.Fatal("registration renewal must leave a safety margin before expiry")
	}
	if got := registrationRenewalDelay(int(^uint(0) >> 1)); got <= 0 || got > 24*time.Hour {
		t.Fatalf("oversized registration expiry overflowed timer: %s", got)
	}
	if _, _, err := selectIMSPath(swu.SessionSnapshot{}, "ipv6", ""); err == nil {
		t.Fatal("accepted absent tunnel identity")
	}
	if err := validateReaderIMEI(makeDeviceIMEI()); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(&fakeHost{})
	if err := engine.WritePCM(make([]byte, 319)); err == nil {
		t.Fatal("accepted malformed audio")
	}
	if err := engine.Start(`{"imei":"bad"}`); err == nil {
		t.Fatal("accepted invalid IMEI")
	}
	if _, err := engine.Command(`{"action":"dial","peer":"12345"}`); err == nil {
		t.Fatal("allowed call without IMS")
	}
}

func TestSMSPersistenceFailurePropagatesAndIdentitySurvivesReconnect(t *testing.T) {
	want := errors.New("disk full")
	var first string
	host := &fakeHost{store: func(input string) error { first = input; return want }}
	engine := NewEngine(host)
	card := cardConfig{ICCID: "8944000000000000001", Generation: 1}
	at := time.Date(2026, 9, 26, 4, 5, 6, 0, time.UTC)
	if err := engine.storeIncomingSMS(context.Background(), card, "+441234", "hello", at); !errors.Is(err, want) {
		t.Fatalf("persistence failure hidden: %v", err)
	}
	var previous map[string]any
	_ = json.Unmarshal([]byte(first), &previous)
	host.store = func(input string) error {
		var next map[string]any
		_ = json.Unmarshal([]byte(input), &next)
		if next["message_id"] != previous["message_id"] {
			t.Fatal("reconnect changed message identity")
		}
		return nil
	}
	card.Generation = 2
	if err := engine.storeIncomingSMS(context.Background(), card, "+441234", "hello", at); err != nil {
		t.Fatal(err)
	}
}

func TestSMSMultipartMetadataAndIdempotentPartIdentity(t *testing.T) {
	var events []map[string]any
	host := &fakeHost{store: func(input string) error {
		var event map[string]any
		if err := json.Unmarshal([]byte(input), &event); err != nil {
			return err
		}
		events = append(events, event)
		return nil
	}}
	engine := NewEngine(host)
	card := cardConfig{ICCID: "test-sim-a", Generation: 1}
	message := imscore.InboundSMS{Sender: "+441234", Content: "same text", Timestamp: time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC), HasTimestamp: true, ConcatReference: 42, ConcatTotal: 2, ConcatSequence: 1}
	for _, sequence := range []int{1, 2, 1} {
		message.ConcatSequence = sequence
		if err := engine.storeIncomingSMSMessage(context.Background(), card, message); err != nil {
			t.Fatal(err)
		}
	}
	if events[0]["message_id"] == events[1]["message_id"] || events[0]["message_id"] != events[2]["message_id"] {
		t.Fatal("identical-text parts must not collapse, retransmission must deduplicate")
	}
	if events[0]["concat_reference"] != float64(42) || events[0]["concat_total"] != float64(2) || events[0]["concat_sequence"] != float64(1) || events[0]["sim_id"] == "test-sim-a" {
		t.Fatalf("missing multipart fields or raw SIM identity: %+v", events[0])
	}
	card.ICCID = "test-sim-b"
	if err := engine.storeIncomingSMSMessage(context.Background(), card, message); err != nil {
		t.Fatal(err)
	}
	if events[0]["sim_id"] == events[3]["sim_id"] || events[0]["message_id"] == events[3]["message_id"] {
		t.Fatal("multipart identity crossed SIM boundary")
	}
	message.ConcatSequence = 3
	if err := engine.storeIncomingSMSMessage(context.Background(), card, message); err == nil || len(events) != 4 {
		t.Fatal("invalid fragment acknowledged/persisted")
	}
}

func TestDecodedSMSPreservesUDHAndCallRecoveryWaits(t *testing.T) {
	tpdu := []byte{0x40, 3, 0x81, 0x88, 0xf8, 0, 8, 0x62, 0x90, 0x60, 0, 0, 0, 0, 8, 5, 0, 3, 42, 2, 1, 0, 0x41}
	message, handled, err := decodeIncomingSMS(tpdu)
	if err != nil || !handled || message.Content != "A" || message.ConcatReference != 42 || message.ConcatTotal != 2 || message.ConcatSequence != 1 {
		t.Fatalf("UDH lost during native bridge: %+v %v", message, err)
	}
	tpdu[8] = 0xff
	if _, _, err := decodeIncomingSMS(tpdu); err == nil {
		t.Fatal("multipart message with invalid SCTS accepted")
	}
	for _, state := range []string{"outgoing", "incoming", "early", "connecting", "active", "cancelling"} {
		if !registrationRecoveryMustWait(imscore.CallState{State: state}) {
			t.Fatalf("renewal recovery would terminate %s call", state)
		}
	}
	for _, state := range []string{"idle", "ended", "failed", "unavailable"} {
		if registrationRecoveryMustWait(imscore.CallState{State: state}) {
			t.Fatalf("renewal recovery cannot proceed after %s", state)
		}
	}
}

func TestCarrierWireIdentitiesMatchDeployedReader(t *testing.T) {
	if got := sipInstance("356789012345678"); got != "urn:gsma:imei:356789012345678-0" {
		t.Fatalf("terminating contact identity changed: %s", got)
	}
	if sipInstance("") != "" {
		t.Fatal("disabled device identity must omit SIP instance")
	}
	if readerIMSUserAgent("apple_o2_giffgaff_uk", "") != "iOS/18.6.2 iPhone" || readerIMSUserAgent("apple_orange_uk", "") != "iOS/26.6 iPhone" {
		t.Fatal("carrier user-agent changed")
	}
	profile := &carrier.Profile{MCC: "234", MNC: "33", LocalIdentifier: "0$imsi@nai.epc.mnc$mnc.mcc$mcc.3gppnetwork.org"}
	if got := profile.ExpandLocalIdentifier("234331234567890"); got != "0234331234567890@nai.epc.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("unexpanded IKE identity: %s", got)
	}
}

func TestReconnectPolicyBoundsAuthenticationAttempts(t *testing.T) {
	transient := errors.New("ePDG timeout")
	for failures := 0; failures < 3; failures++ {
		next, retry, delay := reconnectPolicy(failures, false, transient)
		if next != failures+1 || retry != (failures < 2) {
			t.Fatalf("unexpected budget at %d: %d %v", failures, next, retry)
		}
		if retry && delay <= 0 {
			t.Fatal("retry without backoff")
		}
	}
	if _, retry, _ := reconnectPolicy(0, false, errors.New("SIM AKA failed: SIM status 6982")); retry {
		t.Fatal("permanent SIM failure retried")
	}
	if _, retry, _ := reconnectPolicy(0, false, errors.New("EAP-AKA AT_MAC 校验失败")); retry {
		t.Fatal("invalid authentication MAC retried")
	}
	if next, retry, _ := reconnectPolicy(2, true, transient); next != 0 || !retry {
		t.Fatal("healthy IMS session failed to reset retry budget")
	}
	if next, retry, _ := reconnectPolicy(2, true, nil); next != 0 || !retry {
		t.Fatal("planned registration renewal exhausted retry budget")
	}
}
