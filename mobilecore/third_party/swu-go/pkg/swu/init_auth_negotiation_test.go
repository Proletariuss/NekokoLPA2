package swu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	corecrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func initResponsePacket(t *testing.T, s *Session, payloads []ikev2.Payload) []byte {
	t.Helper()
	p := ikev2.NewIKEPacket()
	p.Header.SPIi = s.SPIi
	p.Header.SPIr = 77
	p.Header.Version = 0x20
	p.Header.ExchangeType = ikev2.IKE_SA_INIT
	p.Header.Flags = 0x20
	p.Header.MessageID = 0
	p.Payloads = payloads
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func selectedInitialPayloads(t *testing.T, s *Session, nonceLen int) []ikev2.Payload {
	t.Helper()
	offers, err := ikev2.BuildIKEProposals(s.cfg.IKEProposals, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := offers[0]
	var transforms []*ikev2.Transform
	for _, tr := range selected.Transforms {
		if tr.Type != ikev2.TransformTypeDH || uint16(tr.ID) == s.DH.Group {
			transforms = append(transforms, tr)
		}
	}
	selected.Transforms = transforms
	dh, err := corecrypto.NewDiffieHellman(s.DH.Group)
	if err != nil {
		t.Fatal(err)
	}
	if err = dh.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	return []ikev2.Payload{&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{selected}}, &ikev2.EncryptedPayloadKE{DHGroup: ikev2.AlgorithmType(s.DH.Group), KEData: dh.PublicKeyBytes()}, &ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x52}, nonceLen)}}
}

func TestInitialNegotiationBindsOfferDHNonceAndTranscript(t *testing.T) {
	for _, mode := range []string{"valid", "unoffered", "dh_mismatch", "short_nonce", "oversized_nonce", "bad_header", "duplicate_sa"} {
		t.Run(mode, func(t *testing.T) {
			s := NewSession(&Config{EpDGAddr: "epdg.example.test", IKEProposals: []string{"aes128-sha256-prfsha512-ecp256"}}, zap.NewNop())
			request, err := s.buildIKESAInitPacket()
			if err != nil {
				t.Fatal(err)
			}
			nonceLen := 32
			if mode == "short_nonce" {
				nonceLen = 16
			}
			if mode == "oversized_nonce" {
				nonceLen = 257
			}
			payloads := selectedInitialPayloads(t, s, nonceLen)
			switch mode {
			case "unoffered":
				payloads[0].(*ikev2.EncryptedPayloadSA).Proposals[0].ProposalNum++
			case "dh_mismatch":
				payloads[1].(*ikev2.EncryptedPayloadKE).DHGroup = ikev2.MODP_2048_bit
			case "duplicate_sa":
				payloads = append(payloads, payloads[0])
			}
			response := initResponsePacket(t, s, payloads)
			if mode == "bad_header" {
				response[0] ^= 1
			}
			err = s.handleIKESAInitResp(response)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(s.msgBuffer, request) || !bytes.Equal(s.ikeInitResponse, response) {
					t.Fatal("AUTH transcript not preserved verbatim")
				}
			} else if err == nil || len(s.ikeInitResponse) != 0 {
				t.Fatal("invalid SA_INIT accepted")
			}
		})
	}
}

func TestInvalidKERetriesOnlyOfferedGroupAndReplacesTranscript(t *testing.T) {
	s := NewSession(&Config{EpDGAddr: "epdg.example.test", IKEProposals: []string{"aes128-sha256-prfsha256-ecp256-modp2048"}}, zap.NewNop())
	old, err := s.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	if s.DH.Group != 19 {
		t.Fatal("first KE did not follow proposal preference")
	}
	notify := func(group uint16) []byte {
		return initResponsePacket(t, s, []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: 17, NotifyData: binary.BigEndian.AppendUint16(nil, group)}})
	}
	if err = s.handleIKESAInitResp(notify(2)); err == nil || errors.Is(err, errRetryDH) {
		t.Fatal("unoffered DH requested")
	}
	if err = s.handleIKESAInitResp(notify(14)); !errors.Is(err, errRetryDH) {
		t.Fatalf("offered retry refused: %v", err)
	}
	fresh, err := s.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	if s.DH.Group != 14 || bytes.Equal(old, fresh) || !bytes.Equal(s.msgBuffer, fresh) || len(s.ikeInitResponse) != 0 {
		t.Fatal("retry failed to replace KE/transcript")
	}
	response := initResponsePacket(t, s, selectedInitialPayloads(t, s, 32))
	if err = s.handleIKESAInitResp(response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, s.ikeInitResponse) {
		t.Fatal("retry saved non-final response")
	}
}

func TestCertificatePolicyControlsEAPOnlyOfferAndNeverOffersTickets(t *testing.T) {
	for _, required := range []bool{false, true} {
		s := NewSession(&Config{SIM: &effectiveConfigSIM{}, APN: "ims", ValidateRemoteCertificate: required, FastReauthID: "old@example"}, zap.NewNop())
		s.MSK = bytes.Repeat([]byte{1}, 64)
		payloads, err := s.buildIKEAuthInitPayloads()
		if err != nil {
			t.Fatal(err)
		}
		if len(s.MSK) != 0 {
			t.Fatal("new exchange retained old MSK")
		}
		found := false
		for _, p := range payloads {
			if n, ok := p.(*ikev2.EncryptedPayloadNotify); ok {
				if n.NotifyType == ikev2.EAP_ONLY_AUTHENTICATION {
					found = true
					if n.ProtocolID != 0 || len(n.SPI) != 0 || len(n.NotifyData) != 0 {
						t.Fatal("invalid RFC5998 notify")
					}
				}
				if n.NotifyType == ikev2.TICKET_REQUEST {
					t.Fatal("unsafe resumption advertised")
				}
			}
			if id, ok := p.(*ikev2.EncryptedPayloadID); ok && id.IsInitiator && string(id.IDData) == "old@example" {
				t.Fatal("unsafe fast reauth identity reused")
			}
		}
		if found == required {
			t.Fatal("incorrect EAP-only certificate policy")
		}
	}
}
