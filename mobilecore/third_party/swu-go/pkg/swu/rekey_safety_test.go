package swu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

type rekeyCaptureTransport struct {
	packets [][]byte
	fail    bool
}

func (*rekeyCaptureTransport) Start() {}
func (*rekeyCaptureTransport) Stop()  {}
func (m *rekeyCaptureTransport) SendIKE(b []byte) error {
	if m.fail {
		return errors.New("send failed")
	}
	m.packets = append(m.packets, append([]byte(nil), b...))
	return nil
}
func (*rekeyCaptureTransport) SendESP([]byte) error                 { return nil }
func (*rekeyCaptureTransport) IKEPackets() <-chan []byte            { return nil }
func (*rekeyCaptureTransport) ESPPackets() <-chan []byte            { return nil }
func (*rekeyCaptureTransport) NetEventsChan() <-chan ipsec.NetEvent { return nil }

func rekeyFixture(t *testing.T, suite string, pfs int) *Session {
	s := envelopeSession(t, false)
	s.Logger = zap.NewNop()
	s.cfg = &Config{ESPProposals: []string{suite}, RekeyPFS: pfs}
	s.PRFAlg = crypto.PRF_HMAC_SHA2_256
	s.Keys.SK_d = bytes.Repeat([]byte{7}, 32)
	s.ChildSAIn = &ipsec.SecurityAssociation{SPI: 11}
	s.ChildSAOut = &ipsec.SecurityAssociation{SPI: 22}
	s.tsi = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4([]byte{10, 0, 0, 1}, []byte{10, 0, 0, 1}, 0, 65535)}
	s.tsr = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4([]byte{192, 0, 2, 1}, []byte{192, 0, 2, 1}, 0, 65535)}
	s.socket = &rekeyCaptureTransport{}
	s.childRekeyResetCh = make(chan struct{}, 1)
	s.rekeyResetCh = make(chan struct{}, 1)
	return s
}
func peerRequest(t *testing.T, s *Session, suite string, pfs int) ([]ikev2.Payload, *crypto.DiffieHellman) {
	p, err := ikev2.BuildESPProposals([]string{suite}, []byte{0, 0, 0, 44})
	if err != nil {
		t.Fatal(err)
	}
	request := []ikev2.Payload{&ikev2.EncryptedPayloadSA{Proposals: p}, &ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{1}, 32)},
		&ikev2.EncryptedPayloadNotify{ProtocolID: ikev2.ProtoESP, NotifyType: ikev2.REKEY_SA, SPI: []byte{0, 0, 0, 22}},
		&ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: s.tsr}, &ikev2.EncryptedPayloadTS{TrafficSelectors: s.tsi}}
	var dh *crypto.DiffieHellman
	if pfs != 0 {
		dh, err = crypto.NewDiffieHellman(uint16(pfs))
		if err != nil {
			t.Fatal(err)
		}
		if err = dh.GenerateKey(); err != nil {
			t.Fatal(err)
		}
		p[0].AddTransform(ikev2.TransformTypeDH, ikev2.AlgorithmType(pfs), 0)
		request = append(request, &ikev2.EncryptedPayloadKE{DHGroup: ikev2.AlgorithmType(pfs), KEData: dh.PublicKeyBytes()})
	}
	return request, dh
}
func TestPeerChildRekeyCBCGCMAndECDHPFSDirections(t *testing.T) {
	for _, suite := range []string{"aes256-sha512", "aes192gcm12"} {
		for _, pfs := range []int{0, 14, 21} {
			s := rekeyFixture(t, suite, pfs)
			req, peerDH := peerRequest(t, s, suite, pfs)
			nr := bytes.Repeat([]byte{2}, 32)
			prepared, err := s.preparePeerChildRekey(req, []byte{0, 0, 0, 33}, nr)
			if err != nil {
				t.Fatal(suite, pfs, err)
			}
			if prepared.incoming.SPI != 33 || prepared.outgoing.SPI != 44 || prepared.incoming.RemoteSPI != 44 || prepared.outgoing.RemoteSPI != 33 {
				t.Fatal("reversed ESP SPI direction")
			}
			if s.ChildSAIn.SPI != 11 || s.ChildSAOut.SPI != 22 {
				t.Fatal("prepare changed live SA")
			}
			var shared []byte
			if pfs != 0 {
				for _, pl := range prepared.response {
					if ke, ok := pl.(*ikev2.EncryptedPayloadKE); ok {
						shared, err = peerDH.ComputeSharedSecret(ke.KEData)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				if len(shared) == 0 {
					t.Fatal("missing PFS response")
				}
			}
			encLen, integLen := len(prepared.incoming.EncryptionKey), len(prepared.incoming.IntegrityKey)
			seed := append(append(append([]byte(nil), shared...), bytes.Repeat([]byte{1}, 32)...), nr...)
			material, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, 2*(encLen+integLen))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(prepared.incoming.EncryptionKey, material[:encLen]) || !bytes.Equal(prepared.outgoing.EncryptionKey, material[encLen+integLen:2*encLen+integLen]) {
				t.Fatal("reversed initiator/responder keys or erased key storage")
			}
			if suite == "aes256-sha512" && (prepared.incoming.IsAEAD || integLen != 64 || encLen != 32) {
				t.Fatal("CBC treated as AEAD")
			}
			if suite == "aes192gcm12" && (!prepared.incoming.IsAEAD || integLen != 0 || encLen != 28) {
				t.Fatal("GCM salt/key mapping lost")
			}
			if peerDH != nil {
				peerDH.Destroy()
			}
		}
	}
}
func TestPeerChildRekeyRejectsWrongPolicyAndSendFailureWithoutMutation(t *testing.T) {
	mutations := map[string]func([]ikev2.Payload){
		"wrong suite": func(p []ikev2.Payload) {
			p[0].(*ikev2.EncryptedPayloadSA).Proposals[0].Transforms[0].Attributes[0].Val = 128
		},
		"short nonce":   func(p []ikev2.Payload) { p[1].(*ikev2.EncryptedPayloadNonce).NonceData = []byte{1} },
		"wrong old SPI": func(p []ikev2.Payload) { p[2].(*ikev2.EncryptedPayloadNotify).SPI = []byte{0, 0, 0, 99} },
		"wrong PFS":     func(p []ikev2.Payload) { p[len(p)-1].(*ikev2.EncryptedPayloadKE).DHGroup = 14 },
		"broader selector": func(p []ikev2.Payload) {
			p[3].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4([]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255}, 0, 65535)}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := rekeyFixture(t, "aes256-sha256", 21)
			req, dh := peerRequest(t, s, "aes256-sha256", 21)
			defer dh.Destroy()
			mutate(req)
			if _, err := s.preparePeerChildRekey(req, []byte{0, 0, 0, 33}, bytes.Repeat([]byte{2}, 32)); err == nil {
				t.Fatal("invalid rekey accepted")
			}
			if s.ChildSAIn.SPI != 11 || s.ChildSAOut.SPI != 22 {
				t.Fatal("invalid rekey changed SA")
			}
		})
	}
	s := rekeyFixture(t, "aes256-sha256", 0)
	s.socket.(*rekeyCaptureTransport).fail = true
	req, _ := peerRequest(t, s, "aes256-sha256", 0)
	if err := s.handlePeerChildRekey(4, req); err == nil {
		t.Fatal("send failure ignored")
	}
	if s.ChildSAIn.SPI != 11 || s.ChildSAOut.SPI != 22 {
		t.Fatal("unsent rekey changed SA")
	}
}
func TestPeerIKERekeyRejectsWithoutRoleSwapOrRecursiveLock(t *testing.T) {
	s := rekeyFixture(t, "aes256-sha256", 0)
	keys := s.Keys
	s.rekeyMu.Lock()
	err := s.HandleRekeyIKESARequest(9, nil)
	s.rekeyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if s.Keys != keys || s.SPIi != 1 || s.SPIr != 2 {
		t.Fatal("unsupported peer IKE rekey mutated SA")
	}
	m := s.socket.(*rekeyCaptureTransport)
	if len(m.packets) != 1 {
		t.Fatal("no encrypted rejection")
	}
	id, payloads, err := s.decryptAndParse(m.packets[0])
	if err != nil || id != 9 || len(payloads) != 1 {
		t.Fatal(err)
	}
	n, ok := payloads[0].(*ikev2.EncryptedPayloadNotify)
	if !ok || n.NotifyType != ikev2.NO_ADDITIONAL_SAS {
		t.Fatal("wrong rejection")
	}
}

func TestRekeyCollisionRejectsWithoutWaitingOrChangingSA(t *testing.T) {
	s := rekeyFixture(t, "aes256-sha256", 0)
	request, _ := peerRequest(t, s, "aes256-sha256", 0)
	s.rekeyMu.Lock()
	err := s.handleIncomingCreateChildSAParsed(10, request)
	s.rekeyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if s.ChildSAIn.SPI != 11 || s.ChildSAOut.SPI != 22 {
		t.Fatal("collision changed live SA")
	}
	m := s.socket.(*rekeyCaptureTransport)
	_, payloads, err := s.decryptAndParse(m.packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 || payloads[0].(*ikev2.EncryptedPayloadNotify).NotifyType != ikev2.TEMPORARY_FAILURE {
		t.Fatal("wrong collision reply")
	}
}
func TestActiveChildRekeyKeysSurviveTemporaryMaterialErasure(t *testing.T) {
	s := rekeyFixture(t, "aes256-sha256", 0)
	s.childEncrKeyLenBits = 128
	offers, _, err := s.childRekeyProposals([]byte{0, 0, 0, 33})
	if err != nil {
		t.Fatal(err)
	}
	selected, _ := ikev2.BuildESPProposals([]string{"aes256-sha256"}, []byte{0, 0, 0, 44})
	payloads := []ikev2.Payload{&ikev2.EncryptedPayloadSA{Proposals: selected}, &ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{2}, 32)}, &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: s.tsi}, &ikev2.EncryptedPayloadTS{TrafficSelectors: s.tsr}}
	packet, err := s.encryptAndWrapWithMsgID(payloads, ikev2.CREATE_CHILD_SA, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	ni := bytes.Repeat([]byte{1}, 32)
	if err := s.handleCreateChildSAResp(packet, ni, 33, nil, offers, s.tsi, s.tsr); err != nil {
		t.Fatal(err)
	}
	material, _ := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, append(ni, bytes.Repeat([]byte{2}, 32)...), 128)
	if !bytes.Equal(s.ChildSAOut.EncryptionKey, material[:32]) || !bytes.Equal(s.ChildSAIn.EncryptionKey, material[64:96]) {
		t.Fatal("rekey keys were erased or reversed")
	}
	if len(s.childRekeyResetCh) != 1 || len(s.rekeyResetCh) != 0 {
		t.Fatal("wrong SA lifetime timer reset")
	}
	if s.childEncrKeyLenBits != 256 {
		t.Fatal("active rekey retained obsolete key size")
	}
}

func TestPeerChildRekeyCommitUpdatesKeySize(t *testing.T) {
	for _, suite := range []string{"aes256-sha256", "aes192gcm12"} {
		t.Run(suite, func(t *testing.T) {
			s := rekeyFixture(t, suite, 0)
			s.childEncrKeyLenBits = 128
			request, _ := peerRequest(t, s, suite, 0)
			if err := s.handlePeerChildRekey(4, request); err != nil {
				t.Fatal(err)
			}
			if s.childEncrKeyLenBits != s.ChildSAOut.EncryptionAlg.KeySize()*8 {
				t.Fatal("peer rekey retained obsolete key size")
			}
		})
	}
}
func TestIKERekeyPreservesSHA512AES256AndECDH(t *testing.T) {
	s := rekeyFixture(t, "aes256-sha256", 0)
	s.EncAlg, _ = crypto.GetEncrypterWithKeyLen(12, 256)
	s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(14)
	s.ikeEncrID = 12
	s.ikeIntegID = 14
	s.PRFAlg = crypto.PRF_HMAC_SHA2_512
	s.DH, _ = crypto.NewDiffieHellman(21)
	if err := s.DH.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	defer s.DH.Destroy()
	offer, err := s.currentIKERekeyProposal([]byte{0, 0, 0, 0, 0, 0, 0, 3})
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := ikev2.BuildIKEProposals([]string{"aes256-sha512-prfsha512-ecp521"}, offer.SPI)
	actualWire, _ := offer.Encode()
	wantWire, _ := expected[0].Encode()
	if !bytes.Equal(actualWire, wantWire) {
		t.Fatal("IKE rekey downgraded negotiated suite")
	}
	peer, _ := crypto.NewDiffieHellman(21)
	if err := peer.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	defer peer.Destroy()
	selected := *offer
	selected.SPI = make([]byte, 8)
	binary.BigEndian.PutUint64(selected.SPI, 4)
	response := []ikev2.Payload{&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&selected}}, &ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{2}, 32)}, &ikev2.EncryptedPayloadKE{DHGroup: 21, KEData: peer.PublicKeyBytes()}}
	if _, _, err := validateIKERekeyResponse(response, []*ikev2.Proposal{offer}, s.DH); err != nil {
		t.Fatal(err)
	}
	response[1].(*ikev2.EncryptedPayloadNonce).NonceData = make([]byte, 16)
	if _, _, err := validateIKERekeyResponse(response, []*ikev2.Proposal{offer}, s.DH); err == nil {
		t.Fatal("accepted nonce too short for SHA512")
	}
	response[1].(*ikev2.EncryptedPayloadNonce).NonceData = make([]byte, 32)
	response[2].(*ikev2.EncryptedPayloadKE).DHGroup = 14
	if _, _, err := validateIKERekeyResponse(response, []*ikev2.Proposal{offer}, s.DH); err == nil {
		t.Fatal("accepted mismatched rekey DH")
	}
	selected.ProposalNum = 2
	if _, _, err := validateIKERekeyResponse(response, []*ikev2.Proposal{offer}, s.DH); err == nil {
		t.Fatal("accepted unoffered rekey suite")
	}
}
