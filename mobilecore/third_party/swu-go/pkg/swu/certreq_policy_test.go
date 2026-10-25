package swu

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestCertReqCertificatePolicyInitialOnly(t *testing.T) {
	for _, required := range []bool{false, true} {
		s := NewSession(&Config{APN: "ims", SIM: &effectiveConfigSIM{}, IKELocalIdentifier: "anonymous@private.invalid", ValidateRemoteCertificate: required}, zap.NewNop())
		payloads, err := s.buildIKEAuthInitPayloads()
		if err != nil {
			t.Fatal(err)
		}
		certreqs, eapOnly := 0, false
		for _, p := range payloads {
			if c, ok := p.(*ikev2.EncryptedPayloadCertReq); ok {
				certreqs++
				if c.Encoding != 4 || len(c.CertificateAuthorities) != 0 {
					t.Fatal("initial request must use empty X.509 CA hash list")
				}
			}
			if n, ok := p.(*ikev2.EncryptedPayloadNotify); ok && n.NotifyType == ikev2.EAP_ONLY_AUTHENTICATION {
				eapOnly = true
			}
		}
		if (certreqs == 1) != required || (!required && certreqs != 0) || eapOnly == required {
			t.Fatalf("certificate policy changed: required=%v certreq=%d eapOnly=%v", required, certreqs, eapOnly)
		}
		if s.cfg.CertificateRoots != nil {
			t.Fatal("CERTREQ changed platform trust roots")
		}
		f := newPeerFixture(t, nil)
		s.PRFAlg, s.Keys = f.s.PRFAlg, f.s.Keys
		s.Keys.SK_pi = bytes.Repeat([]byte{3}, 32)
		s.MSK, s.msgBuffer, s.nr = bytes.Repeat([]byte{7}, 64), []byte("SA_INIT request"), bytes.Repeat([]byte{1}, 32)
		final, err := s.buildIKEAuthFinalPayloads()
		if err != nil {
			t.Fatal(err)
		}
		// EAP Identity responses and final MSK AUTH contain no CERTREQ.
		eapPayloads, err := s.handleEAP([]byte{eap.CodeRequest, 1, 0, 5, eap.TypeIdentity})
		if err != nil {
			t.Fatal(err)
		}
		for _, list := range [][]ikev2.Payload{eapPayloads, final} {
			for _, p := range list {
				if p.Type() == ikev2.CERTREQ {
					t.Fatal("CERTREQ repeated after initial IKE_AUTH")
				}
			}
		}
	}
}

func TestCertReqDoesNotWeakenRequiredResponderAuthentication(t *testing.T) {
	for _, mode := range []string{"identity_eap_only", "missing_cert", "invalid_cert", "invalid_auth", "cancelled", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newPeerFixture(t, nil)
			f.s.cfg.IKELocalIdentifier = "anonymous@private.invalid"
			f.s.cfg.APN = "ims"
			if _, err := f.s.buildIKEAuthInitPayloads(); err != nil {
				t.Fatal(err)
			}
			// The real responder signs its IDr. Recreate that responder-side
			// transcript after the builder clears previous peer identity state.
			f.s.responderIdentityBody, _ = f.id.Encode()
			payloads := f.initial(t)
			switch mode {
			case "identity_eap_only":
				payloads = []ikev2.Payload{f.id, &ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 1, 0, 5, 1}}}
			case "missing_cert":
				payloads = payloads[:2]
			case "invalid_cert":
				f.certs[0].Data = []byte{1}
			case "invalid_auth":
				payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[0] ^= 1
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				f.s.ctx = ctx
			}
			response, err := f.s.processAuthEAPResponse(1, payloads)
			if mode == "valid" {
				// The valid certificate is authenticated before the absent EAP is
				// rejected, proving the request hint did not replace AUTH checks.
				if !f.s.responderCertificateVerified || AuthFailureCode(err) != AuthFailureMissingEAP {
					t.Fatalf("valid initial auth failed: %v", err)
				}
			} else if err == nil || f.s.responderCertificateVerified || len(response) != 0 || f.s.eapPermanentIdentity != "" {
				t.Fatal("CERTREQ allowed unauthenticated responder")
			} else if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func TestCertReqInboundUnsupportedHintDoesNotChangeNegotiation(t *testing.T) {
	for _, encoding := range []byte{12, 13, 255} {
		s := NewSession(&Config{EpDGAddr: "epdg.example.test", IKEProposals: []string{"aes128-sha256-prfsha256-ecp256"}}, zap.NewNop())
		if _, err := s.buildIKESAInitPacket(); err != nil {
			t.Fatal(err)
		}
		payloads := append(selectedInitialPayloads(t, s, 32), &ikev2.RawPayload{PType: ikev2.CERTREQ, Data: []byte{encoding, 1}})
		if err := s.handleIKESAInitResp(initResponsePacket(t, s, payloads)); err != nil {
			t.Fatalf("unsupported noncritical init CERTREQ%d changed negotiation: %v", encoding, err)
		}
		if s.cfg.ValidateRemoteCertificate {
			t.Fatal("inbound request changed authentication policy")
		}
		for _, critical := range []bool{false, true} {
			flags := byte(0)
			if critical {
				flags = 0x80
			}
			parsed, err := s.parsePayloads([]byte{0, flags, 0, 6, encoding, 1}, ikev2.CERTREQ)
			if critical {
				if err == nil {
					t.Fatal("unsupported critical CERTREQ accepted")
				}
				continue
			}
			if err != nil || len(parsed) != 1 {
				t.Fatal("unsupported encrypted request rejected", err)
			}
			if _, ok := parsed[0].(*ikev2.RawPayload); !ok {
				t.Fatal("unsupported request not opaque")
			}
		}
	}
	for _, body := range [][]byte{{0, 0, 0, 4}, {0, 0, 0, 6, 4, 1}} {
		if _, err := (&Session{}).parsePayloads(body, ikev2.CERTREQ); err == nil {
			t.Fatal("malformed X.509 CERTREQ accepted")
		}
	}
}
