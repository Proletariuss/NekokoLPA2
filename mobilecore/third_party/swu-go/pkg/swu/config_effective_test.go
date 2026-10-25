package swu

import (
	"context"
	"strings"
	"testing"
	"time"

	corecrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

type effectiveConfigSIM struct{}

func (*effectiveConfigSIM) GetIMSI() (string, error) { return "310260123456789", nil }
func (*effectiveConfigSIM) GetIMEI() (string, error) { return "351234567890124", nil }
func (*effectiveConfigSIM) CalculateAKA(rand, autn []byte) ([]byte, []byte, []byte, []byte, error) {
	return nil, nil, nil, nil, nil
}
func (*effectiveConfigSIM) Close() error { return nil }

func TestEffectiveConfigDefaultsAndValidation(t *testing.T) {
	cfg := &Config{}
	ipv4, ipv6, err := cfg.requestedAddressFamilies()
	if err != nil || !ipv4 || !ipv6 {
		t.Fatalf("default families=%t/%t err=%v", ipv4, ipv6, err)
	}
	if cfg.effectiveNATTKeepaliveInterval() != 20*time.Second || cfg.effectiveDPDInterval() != 120*time.Second {
		t.Fatalf("defaults natt=%v dpd=%v", cfg.effectiveNATTKeepaliveInterval(), cfg.effectiveDPDInterval())
	}
	cfg.IPStack = "bad"
	if err := cfg.validate(); err == nil {
		t.Fatal("invalid IP stack accepted")
	}
	cfg.IPStack = "ipv4"
	cfg.IKEProposals = []string{"unknown"}
	if err := cfg.validate(); err == nil {
		t.Fatal("invalid IKE proposal accepted")
	}
}

func TestDisableDPDDoesNotChangePublishedInterval(t *testing.T) {
	cfg := &Config{DisableDPD: true, DPDIntervalSeconds: 600}
	if got := cfg.effectiveDPDInterval(); got != 600*time.Second {
		t.Fatalf("effective interval = %v, want 600s", got)
	}
}

func TestBuildIKEAuthInitPayloadsUsesIPStackProposalsAndDeviceGate(t *testing.T) {
	disabled := false
	session := NewSession(&Config{
		SIM: &effectiveConfigSIM{}, APN: "ims", IPStack: "ipv4",
		ESPProposals: []string{"aes256-sha256"}, DeviceIdentityEnabled: &disabled,
	}, zap.NewNop())
	payloads, err := session.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	var cp *ikev2.EncryptedPayloadCP
	var childSA *ikev2.EncryptedPayloadSA
	var selectors []*ikev2.EncryptedPayloadTS
	for _, payload := range payloads {
		switch value := payload.(type) {
		case *ikev2.EncryptedPayloadCP:
			cp = value
		case *ikev2.EncryptedPayloadSA:
			childSA = value
		case *ikev2.EncryptedPayloadTS:
			selectors = append(selectors, value)
		case *ikev2.EncryptedPayloadNotify:
			if value.NotifyType == ikev2.DEVICE_IDENTITY || value.NotifyType == ikev2.DEVICE_IDENTITY_3GPP {
				t.Fatal("device identity notify present while disabled")
			}
		}
	}
	if cp == nil || len(cp.Attributes) != 3 {
		t.Fatalf("IPv4 CP attributes=%#v", cp)
	}
	for _, attribute := range cp.Attributes {
		if attribute.Type == ikev2.INTERNAL_IP6_ADDRESS || attribute.Type == ikev2.P_CSCF_IP6_ADDRESS {
			t.Fatalf("IPv6 attribute leaked into IPv4 config: %d", attribute.Type)
		}
	}
	if childSA == nil || len(childSA.Proposals) != 1 {
		t.Fatalf("configured ESP list not authoritative: %#v", childSA)
	}
	if len(selectors) != 2 || len(selectors[0].TrafficSelectors) != 1 || selectors[0].TrafficSelectors[0].TSType != ikev2.TS_IPV4_ADDR_RANGE {
		t.Fatalf("traffic selectors=%#v", selectors)
	}
}

func TestBuildIKEAuthFinalPayloadsRepeatsCarrierConfigurationRequest(t *testing.T) {
	prf, err := corecrypto.GetPRF(2)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(&Config{SIM: &effectiveConfigSIM{}, IPStack: "ipv4", APN: "ims", CPInFinalAuth: true}, zap.NewNop())
	session.MSK = make([]byte, 64)
	session.PRFAlg = prf
	session.Keys = &ikev2.IKESAKeys{SK_pi: make([]byte, 20)}
	session.msgBuffer = []byte("ike-sa-init-request")
	session.nr = make([]byte, 32)
	session.ikeAuthIdentityBody = []byte{ikev2.ID_RFC822_ADDR, 0, 0, 0, 'u', '@', 'd'}
	payloads, err := session.buildIKEAuthFinalPayloads()
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("final AUTH payload count=%d, want AUTH+CP", len(payloads))
	}
	if _, ok := payloads[0].(*ikev2.EncryptedPayloadAuth); !ok {
		t.Fatalf("payload[0]=%T, want AUTH", payloads[0])
	}
	cp, ok := payloads[1].(*ikev2.EncryptedPayloadCP)
	if !ok || cp.CFGType != ikev2.CFG_REQUEST || len(cp.Attributes) != 3 {
		t.Fatalf("final CP request=%#v", payloads[1])
	}
}

func TestAKACheckcodeModes(t *testing.T) {
	for _, mode := range []string{"", "minimal", "omit", " MINIMAL ", " OMIT "} {
		t.Run("supported_"+mode, func(t *testing.T) {
			cfg := &Config{AKAChallengeMode: mode}
			if err := cfg.validate(); err != nil {
				t.Fatal(err)
			}
			s := &Session{cfg: cfg}
			for _, attrs := range []map[uint8]*eap.Attribute{nil, {eap.AT_CHECKCODE: {Type: eap.AT_CHECKCODE, Value: []byte{0, 0}}}} {
				if got, err := s.eapAKACheckcodeResponse(attrs); err != nil || got != nil {
					t.Fatalf("mode=%q got=%#v err=%v", mode, got, err)
				}
			}
		})
	}
	for _, mode := range []string{"checkcode", "recompute", " CHECKCODE ", " RECOMPUTE "} {
		t.Run("unsupported_"+mode, func(t *testing.T) {
			cfg := &Config{AKAChallengeMode: mode, SIM: &effectiveConfigSIM{}, TransportFactory: func(string, string) (Transport, error) {
				t.Fatal("unsupported configuration opened transport")
				return nil, nil
			}}
			if value, err := cfg.normalizedAKAChallengeMode(); value != "" || err == nil || !strings.Contains(err.Error(), "unsupported aka_challenge_mode") {
				t.Fatalf("unsupported mode was downgraded: value=%q err=%v", value, err)
			}
			if err := cfg.validate(); err == nil {
				t.Fatal("unsupported configuration accepted")
			}
			s := NewSession(cfg, zap.NewNop())
			if got, err := s.eapAKACheckcodeResponse(nil); err == nil || got != nil {
				t.Fatalf("helper bypassed configuration guard: got=%#v err=%v", got, err)
			}
			if err := s.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "classic EAP-AKA AT_CHECKCODE") {
				t.Fatalf("Connect did not reject configuration: %v", err)
			}
		})
	}
}
