package swu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestAuthTerminalFailurePrecedesMissingIdentityAndAUTH(t *testing.T) {
	for _, stage := range []string{"initial", "eap", "final"} {
		for _, withID := range []bool{false, true} {
			for notify, code := range map[uint16]string{
				ikev2.AUTHENTICATION_FAILED:        AuthFailurePeerNotifyAuthentication,
				ikev2.INVALID_SYNTAX:               AuthFailurePeerNotifySyntax,
				ikev2.UNSUPPORTED_CRITICAL_PAYLOAD: AuthFailurePeerNotifyCritical,
			} {
				f := newPeerFixture(t, nil)
				var diagnostics []AuthDiagnostic
				f.s.cfg.OnAuthDiagnostic = func(d AuthDiagnostic) { diagnostics = append(diagnostics, d) }
				payloads := []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: notify, NotifyData: []byte("secret-domain.example")}}
				if withID {
					payloads = append([]ikev2.Payload{f.id}, payloads...)
				}
				var err error
				if stage == "final" {
					err = f.s.handleIKEAuthFinalPayloads(41, payloads)
				} else {
					f.s.responderInitialChecked = stage == "eap"
					_, err = f.s.processAuthEAPResponse(41, payloads)
				}
				var typed *AuthFailureError
				if !errors.Is(err, ErrPeerAuthentication) || !errors.As(err, &typed) || AuthFailureCode(err) != code {
					t.Fatalf("%s notify=%d classified as %v", stage, notify, err)
				}
				if len(diagnostics) != 1 || diagnostics[0].FailureCode != code || diagnostics[0].MessageID != 41 || diagnostics[0].Stage != stage || diagnostics[0].PeerAuthenticated {
					t.Fatalf("unexpected diagnostics: %+v", diagnostics)
				}
				if f.s.ChildSAIn != nil || f.s.ChildSAOut != nil {
					t.Fatal("error installed a CHILD_SA")
				}
			}
		}
	}
}

func TestAuthEAPFailureAndMalformedPackets(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		code string
	}{
		{"failure", []byte{4, 2, 0, 4}, AuthFailureEAP},
		{"failure_extra", []byte{4, 2, 0, 5, 0}, AuthFailureInvalidEAP},
		{"success_extra", []byte{3, 2, 0, 5, 0}, AuthFailureInvalidEAP},
		{"length_mismatch", []byte{4, 2, 0, 3}, AuthFailureInvalidEAP},
		{"missing_type", []byte{1, 2, 0, 4}, AuthFailureInvalidEAP},
		{"short_aka", []byte{1, 2, 0, 6, 23, 1}, AuthFailureInvalidEAP},
		{"response", []byte{2, 2, 0, 5, 1}, AuthFailureInvalidEAP},
		{"unknown_code", []byte{99, 2, 0, 4}, AuthFailureInvalidEAP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPeerFixture(t, nil)
			_, err := f.s.processAuthEAPResponse(1, []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: tc.raw}})
			if AuthFailureCode(err) != tc.code || !errors.Is(err, ErrPeerAuthentication) {
				t.Fatalf("got %v", err)
			}
			if f.s.responderInitialChecked || f.s.eapSuccessReceived || len(f.s.MSK) != 0 {
				t.Fatal("terminal or malformed EAP advanced authentication")
			}
		})
	}
	f := newPeerFixture(t, nil)
	ep := &ikev2.EncryptedPayloadEAP{EAPMessage: []byte{4, 2, 0, 4}}
	_, err := f.s.processAuthEAPResponse(1, []ikev2.Payload{ep, ep})
	if AuthFailureCode(err) != AuthFailureInvalidEAP {
		t.Fatalf("duplicate EAP accepted: %v", err)
	}
}

func TestAuthStatusNotifyAndEAPOnlyDoNotBypassAuthentication(t *testing.T) {
	for _, mode := range []string{"certificate", "eap_only", "3hk"} {
		t.Run(mode, func(t *testing.T) {
			f := newPeerFixture(t, nil)
			f.s.cfg.SIM = &eapProviderTestSIM{}
			initial := f.initial(t)
			if mode != "certificate" {
				f.s.cfg.ValidateRemoteCertificate = false
				initial = []ikev2.Payload{f.id}
			}
			if mode == "3hk" {
				f.s.cfg.RequireFullEAP = true
			}
			var diagnostics []AuthDiagnostic
			f.s.cfg.OnAuthDiagnostic = func(d AuthDiagnostic) { diagnostics = append(diagnostics, d) }
			initial = append(initial, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.MOBIKE_SUPPORTED},
				&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 1, 0, 5, 1}})
			response, err := f.s.processAuthEAPResponse(3, initial)
			if err != nil || len(response) != 1 || len(diagnostics) != 1 || diagnostics[0].PeerAuthenticated != (mode == "certificate") {
				t.Fatalf("initial response: %v %+v", err, diagnostics)
			}
			f.s.MSK = bytes.Repeat([]byte{0x43}, 64)
			success := []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{3, 2, 0, 4}}}
			if _, err := f.s.processAuthEAPResponse(8, success); err != nil {
				t.Fatal(err)
			}
			f.s.Keys.SK_d = bytes.Repeat([]byte{7}, 32)
			f.s.childSPI = 55
			proposals, err := ikev2.BuildESPProposals([]string{"aes256-sha256"}, []byte{0, 0, 0, 44})
			if err != nil {
				t.Fatal(err)
			}
			f.s.childOffers = proposals
			final := []ikev2.Payload{finalPeerAUTH(t, f.s), &ikev2.EncryptedPayloadSA{Proposals: proposals}, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.MOBIKE_SUPPORTED}}
			if err := f.s.handleIKEAuthFinalPayloads(9, final); err != nil {
				t.Fatal(err)
			}
			if len(diagnostics) != 3 || diagnostics[2].Stage != "final" || diagnostics[2].MessageID != 9 || !diagnostics[2].PeerAuthenticated || diagnostics[2].FailureCode != "" || f.s.ChildSAIn == nil || f.s.ChildSAOut == nil {
				t.Fatalf("successful final authentication not reported: %+v", diagnostics)
			}
		})
	}
	for _, notify := range []uint16{ikev2.MOBIKE_SUPPORTED, ikev2.NO_PROPOSAL_CHOSEN, ikev2.TS_UNACCEPTABLE} {
		if err := terminalAuthFailure([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: notify}}); err != nil {
			t.Fatalf("nonterminal notify %d treated as authentication failure: %v", notify, err)
		}
	}
}

func TestAuthFinalFailuresNeverInstallSA(t *testing.T) {
	for _, tc := range []string{"missing_initial_signature", "missing_final_auth", "forged_msk", "child_notify", "combined"} {
		t.Run(tc, func(t *testing.T) {
			f := newPeerFixture(t, nil)
			var diagnostics []AuthDiagnostic
			f.s.cfg.OnAuthDiagnostic = func(d AuthDiagnostic) { diagnostics = append(diagnostics, d) }
			if tc == "missing_initial_signature" {
				_, err := f.s.processAuthEAPResponse(1, []ikev2.Payload{f.id, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.MOBIKE_SUPPORTED}})
				if AuthFailureCode(err) != AuthFailureMissingCertificateAUTH || f.s.responderInitialChecked {
					t.Fatalf("missing certificate signature accepted: %v", err)
				}
				return
			}
			if err := f.s.checkResponderInitial(f.initial(t)); err != nil {
				t.Fatal(err)
			}
			f.s.MSK = bytes.Repeat([]byte{0x43}, 64)
			f.s.eapSuccessReceived = true
			payloads := []ikev2.Payload{finalPeerAUTH(t, f.s)}
			want := AuthFailureMissingFinalAUTH
			switch tc {
			case "missing_final_auth":
				payloads = nil
			case "forged_msk":
				f.s.MSK[0] ^= 1
				want = AuthFailureFinalAUTH
			case "child_notify":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.NO_PROPOSAL_CHOSEN})
				want = AuthFailureChildSA
			case "combined":
				payloads = append(payloads, &ikev2.EncryptedPayloadEAP{EAPMessage: []byte{eap.CodeSuccess, 2, 0, 4}})
				if _, err := f.s.processAuthEAPResponse(11, payloads); err != nil {
					t.Fatal(err)
				}
				if len(diagnostics) != 0 {
					t.Fatal("combined response diagnosed before final AUTH")
				}
				want = AuthFailureChildSA // AUTH valid, missing CHILD_SA.
			}
			err := f.s.handleIKEAuthFinalPayloads(11, payloads)
			if err == nil || len(diagnostics) != 1 || diagnostics[0].FailureCode != want || f.s.ChildSAIn != nil || f.s.ChildSAOut != nil {
				t.Fatalf("invalid final accepted: %v %+v", err, diagnostics)
			}
			if want == AuthFailureChildSA && (errors.Is(err, ErrPeerAuthentication) || !diagnostics[0].PeerAuthenticated) {
				t.Fatal("CHILD_SA rejection mislabeled peer authentication failure")
			}
		})
	}
}

func TestAuthDiagnosticBoundedDetachedAndNoSecrets(t *testing.T) {
	f := newPeerFixture(t, nil)
	secret := "subscriber-001010123456789-key-secret.example"
	var payloads []ikev2.Payload
	for i := 0; i < 70; i++ {
		payloads = append(payloads,
			&ikev2.EncryptedPayloadID{IDType: ikev2.ID_FQDN, IDData: []byte(secret)},
			&ikev2.EncryptedPayloadAuth{AuthMethod: 14, AuthData: []byte(secret)},
			&ikev2.EncryptedPayloadCert{Encoding: 4, Data: []byte(secret)},
			&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTHENTICATION_FAILED, NotifyData: []byte(secret)},
			&ikev2.EncryptedPayloadEAP{EAPMessage: append([]byte{1, 1, 0, 50, 23}, []byte(secret)...)})
	}
	var diagnostics []AuthDiagnostic
	f.s.cfg.OnAuthDiagnostic = func(d AuthDiagnostic) { diagnostics = append(diagnostics, d) }
	f.s.emitAuthDiagnostic("initial", 0xfedcba98, payloads, false, errors.New(secret))
	d := diagnostics[0]
	if d.CertCount != 32 {
		t.Fatalf("unbounded certificate count %d", d.CertCount)
	}
	for _, enums := range [][]int{d.PayloadTypes, d.NotifyTypes, d.EAPCodes, d.EAPTypes, d.AuthMethods, d.IDrTypes} {
		if len(enums) != 32 {
			t.Fatalf("unbounded enum count %d", len(enums))
		}
	}
	encoded, err := json.Marshal(d)
	if err != nil || strings.Contains(string(encoded), secret) || !strings.Contains(string(encoded), `"payload_types":[`) || d.FailureCode != AuthFailureResponse {
		t.Fatalf("unsafe diagnostic: %s %v", encoded, err)
	}
	d.PayloadTypes[0] = 0
	d.NotifyTypes[0] = 0
	f.s.emitAuthDiagnostic("initial", 2, payloads, false, nil)
	if diagnostics[1].PayloadTypes[0] != int(ikev2.IDr) || diagnostics[1].NotifyTypes[0] != int(ikev2.AUTHENTICATION_FAILED) {
		t.Fatal("callback mutation changed later diagnostic")
	}
	if AuthFailureCode(&AuthFailureError{Code: secret, err: ErrPeerAuthentication}) != AuthFailurePeer {
		t.Fatal("arbitrary failure code escaped allowlist")
	}
}

func TestAuthCancellationSuppressesResultAndDiagnostic(t *testing.T) {
	f := newPeerFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	f.s.ctx = ctx
	f.s.cfg.OnAuthDiagnostic = func(AuthDiagnostic) { t.Fatal("diagnostic after cancellation") }
	cancel()
	if _, err := f.s.processAuthEAPResponse(1, f.initial(t)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := f.s.handleIKEAuthFinalPayloads(2, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.s.ChildSAIn != nil || f.s.ChildSAOut != nil || f.s.responderInitialChecked {
		t.Fatal("canceled response changed state")
	}
}
