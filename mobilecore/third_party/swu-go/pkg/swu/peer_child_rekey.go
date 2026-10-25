package swu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
)

type peerChildRekey struct {
	response           []ikev2.Payload
	incoming, outgoing *ipsec.SecurityAssociation
	tsi, tsr           []*ikev2.TrafficSelector // original IKE initiator's directions
	encrID, integID    uint16
	keyBits            int
}

func (s *Session) rejectCreateChildSA(msgID uint32, notify uint16) error {
	return s.sendEncryptedResponseWithMsgID([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: notify}}, ikev2.CREATE_CHILD_SA, msgID)
}
func (s *Session) handlePeerChildRekey(msgID uint32, payloads []ikev2.Payload) error {
	spi, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	nonce, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	prepared, err := s.preparePeerChildRekey(payloads, spi, nonce)
	if err != nil {
		s.Logger.Warn("rejecting peer CHILD_SA rekey; existing SA unchanged", logger.Err(err))
		return s.rejectCreateChildSA(msgID, ikev2.NO_PROPOSAL_CHOSEN)
	}
	if err := s.sendEncryptedResponseWithMsgID(prepared.response, ikev2.CREATE_CHILD_SA, msgID); err != nil {
		clear(prepared.incoming.EncryptionKey)
		clear(prepared.incoming.IntegrityKey)
		clear(prepared.outgoing.EncryptionKey)
		clear(prepared.outgoing.IntegrityKey)
		return err
	}
	oldOut, oldIn := s.ChildSAOut.SPI, s.ChildSAIn.SPI
	s.ChildSAOut, s.ChildSAIn = prepared.outgoing, prepared.incoming
	s.childEncrID, s.childIntegID = prepared.encrID, prepared.integID
	s.childEncrKeyLenBits = prepared.keyBits
	s.tsi, s.tsr = prepared.tsi, prepared.tsr
	if s.ChildSAsIn == nil {
		s.ChildSAsIn = make(map[uint32]*ipsec.SecurityAssociation)
	}
	s.ChildSAsIn[prepared.incoming.SPI] = prepared.incoming
	if len(s.childOutPolicies) > 0 {
		s.childOutPolicies[0].saOut = prepared.outgoing
		s.childOutPolicies[0].tsr = prepared.tsr
	} else {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: prepared.outgoing, tsr: prepared.tsr})
	}
	if s.xfrmMgr != nil {
		if err := s.rekeyXFRMSA(oldOut, oldIn, prepared.outgoing, prepared.incoming, prepared.encrID, prepared.keyBits); err != nil {
			s.Logger.Warn("peer Child SA accepted but kernel SA update failed", logger.Err(err))
			return err
		}
	}
	s.lastRekeyTime = time.Now()
	select {
	case s.childRekeyResetCh <- struct{}{}:
	default:
	}
	s.Logger.Info("peer CHILD_SA rekey accepted after suite, PFS and selector validation")
	return nil
}

// preparePeerChildRekey performs all validation and key derivation without
// changing the live SA. The response must be sent successfully before commit.
func (s *Session) preparePeerChildRekey(payloads []ikev2.Payload, localSPI, nr []byte) (*peerChildRekey, error) {
	if s.Keys == nil || s.PRFAlg == nil || s.ChildSAIn == nil || s.ChildSAOut == nil || len(localSPI) != 4 {
		return nil, errors.New("no established CHILD_SA to rekey")
	}
	ourSPI := binary.BigEndian.Uint32(localSPI)
	if ourSPI == 0 || ourSPI == s.ChildSAIn.SPI {
		return nil, errors.New("invalid new local Child SA SPI")
	}
	var sa *ikev2.EncryptedPayloadSA
	var ni *ikev2.EncryptedPayloadNonce
	var ke *ikev2.EncryptedPayloadKE
	var tsi, tsr *ikev2.EncryptedPayloadTS
	var rekey *ikev2.EncryptedPayloadNotify
	for _, payload := range payloads {
		switch p := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			if sa != nil {
				return nil, errors.New("duplicate SA")
			}
			sa = p
		case *ikev2.EncryptedPayloadNonce:
			if ni != nil {
				return nil, errors.New("duplicate nonce")
			}
			ni = p
		case *ikev2.EncryptedPayloadKE:
			if ke != nil {
				return nil, errors.New("duplicate KE")
			}
			ke = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				if tsi != nil {
					return nil, errors.New("duplicate TSi")
				}
				tsi = p
			} else {
				if tsr != nil {
					return nil, errors.New("duplicate TSr")
				}
				tsr = p
			}
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return nil, errors.New("error notification in request")
			}
			if p.NotifyType == ikev2.REKEY_SA {
				if rekey != nil {
					return nil, errors.New("duplicate REKEY_SA")
				}
				rekey = p
			}
		}
	}
	minNonce := 16
	if n := s.PRFAlg.KeyLen() / 2; n > minNonce {
		minNonce = n
	}
	if sa == nil || ni == nil || len(ni.NonceData) < minNonce || len(ni.NonceData) > 256 || len(nr) < minNonce || len(nr) > 256 {
		return nil, errors.New("missing SA or invalid nonce")
	}
	if rekey == nil || rekey.ProtocolID != ikev2.ProtoESP || len(rekey.SPI) != 4 || binary.BigEndian.Uint32(rekey.SPI) != s.ChildSAOut.SPI {
		return nil, errors.New("REKEY_SA does not identify established peer inbound SA")
	}
	// The peer is this exchange's initiator, so TSi/TSr reverse directions.
	if tsi == nil || tsr == nil || !childRekeySelectorsWithin(tsi.TrafficSelectors, s.tsr) || !childRekeySelectorsWithin(tsr.TrafficSelectors, s.tsi) {
		return nil, errors.New("peer rekey selectors exceed established policy")
	}
	allowed, dh, err := s.childRekeyProposals(localSPI)
	if err != nil {
		return nil, err
	}
	defer eraseChildRekeyDH(dh)
	chosen, err := ikev2.SelectProposalIntersection(sa.Proposals, allowed)
	if err != nil {
		return nil, err
	}
	if chosen.ProtocolID != ikev2.ProtoESP || len(chosen.SPI) != 4 {
		return nil, errors.New("invalid peer Child SA proposal")
	}
	peerSPI := binary.BigEndian.Uint32(chosen.SPI)
	if peerSPI == 0 || peerSPI == s.ChildSAOut.SPI {
		return nil, errors.New("peer must allocate a fresh nonzero SPI")
	}
	var shared []byte
	if dh == nil {
		if ke != nil {
			return nil, errors.New("unsolicited peer KE")
		}
	} else {
		if ke == nil || uint16(ke.DHGroup) != dh.Group {
			return nil, errors.New("peer PFS group mismatch")
		}
		shared, err = dh.ComputeSharedSecret(ke.KEData)
		if err != nil {
			return nil, err
		}
	}
	prepared := &peerChildRekey{tsi: tsr.TrafficSelectors, tsr: tsi.TrafficSelectors}
	for _, tr := range chosen.Transforms {
		switch tr.Type {
		case ikev2.TransformTypeEncr:
			prepared.encrID = uint16(tr.ID)
			for _, a := range tr.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					prepared.keyBits = int(a.Val)
				}
			}
		case ikev2.TransformTypeInteg:
			prepared.integID = uint16(tr.ID)
		}
	}
	enc, err := crypto.GetEncrypterWithKeyLen(prepared.encrID, prepared.keyBits)
	if err != nil {
		return nil, err
	}
	aead := crypto.AEADTagSize(prepared.encrID) > 0
	encLen, integLen := enc.KeySize(), 0
	var integ crypto.IntegrityAlgorithm
	if aead {
		encLen += 4
	} else {
		integ, err = crypto.GetIntegrityAlgorithm(prepared.integID)
		if err != nil {
			return nil, err
		}
		integLen = integ.KeySize()
	}
	seed := append(append(append([]byte(nil), shared...), ni.NonceData...), nr...)
	defer clear(seed)
	material, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, 2*(encLen+integLen))
	if err != nil {
		return nil, err
	}
	defer clear(material)
	// First half is requester -> responder: inbound for this peer request.
	inEnc := append([]byte(nil), material[:encLen]...)
	inInteg := append([]byte(nil), material[encLen:encLen+integLen]...)
	outEnc := append([]byte(nil), material[encLen+integLen:2*encLen+integLen]...)
	outInteg := append([]byte(nil), material[2*encLen+integLen:]...)
	if aead {
		prepared.incoming = ipsec.NewSecurityAssociation(ourSPI, enc, inEnc, nil)
		prepared.outgoing = ipsec.NewSecurityAssociation(peerSPI, enc, outEnc, nil)
	} else {
		prepared.incoming = ipsec.NewSecurityAssociationCBC(ourSPI, enc, inEnc, integ, inInteg)
		prepared.outgoing = ipsec.NewSecurityAssociationCBC(peerSPI, enc, outEnc, integ, outInteg)
	}
	prepared.incoming.RemoteSPI = peerSPI
	prepared.outgoing.RemoteSPI = ourSPI
	response := *chosen
	response.SPI = append([]byte(nil), localSPI...)
	prepared.response = []ikev2.Payload{&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&response}}, &ikev2.EncryptedPayloadNonce{NonceData: nr}}
	if dh != nil {
		prepared.response = append(prepared.response, &ikev2.EncryptedPayloadKE{DHGroup: ikev2.AlgorithmType(dh.Group), KEData: dh.PublicKeyBytes()})
	}
	prepared.response = append(prepared.response, tsi, tsr)
	if len(prepared.incoming.EncryptionKey) != encLen {
		return nil, fmt.Errorf("invalid derived key length")
	}
	return prepared, nil
}
