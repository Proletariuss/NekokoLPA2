package swu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// childRekeyProposals preserves the historic offer for other carriers, but
// keeps a configured carrier ESP suite authoritative during rekey.
func (s *Session) childRekeyProposals(spi []byte) ([]*ikev2.Proposal, *crypto.DiffieHellman, error) {
	if s.cfg == nil || s.cfg.RekeyPFS < 0 || s.cfg.RekeyPFS > 65535 {
		return nil, nil, errors.New("invalid CHILD_SA PFS policy")
	}
	var proposals []*ikev2.Proposal
	if len(s.cfg.ESPProposals) > 0 {
		var err error
		proposals, err = ikev2.BuildESPProposals(s.cfg.ESPProposals, spi)
		if err != nil {
			return nil, nil, err
		}
	} else if s.ChildSAOut != nil && s.ChildSAOut.EncryptionAlg != nil && s.childEncrID != 0 {
		current := ikev2.NewProposal(1, ikev2.ProtoESP, spi)
		current.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.AlgorithmType(s.childEncrID), s.ChildSAOut.EncryptionAlg.KeySize()*8)
		if !s.ChildSAOut.IsAEAD {
			current.AddTransform(ikev2.TransformTypeInteg, ikev2.AlgorithmType(s.childIntegID), 0)
		}
		current.AddTransform(ikev2.TransformTypeESN, 0, 0)
		proposals = []*ikev2.Proposal{current}
	} else {
		cbc := ikev2.NewProposal(1, ikev2.ProtoESP, spi)
		cbc.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
		cbc.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
		cbc.AddTransform(ikev2.TransformTypeESN, 0, 0)
		gcm := ikev2.NewProposal(2, ikev2.ProtoESP, spi)
		gcm.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_GCM_16, 128)
		gcm.AddTransform(ikev2.TransformTypeESN, 0, 0)
		proposals = []*ikev2.Proposal{cbc, gcm}
	}
	if s.cfg.RekeyPFS == 0 {
		return proposals, nil, nil
	}
	for _, proposal := range proposals {
		proposal.AddTransform(ikev2.TransformTypeDH, ikev2.AlgorithmType(s.cfg.RekeyPFS), 0)
	}
	dh, err := crypto.NewDiffieHellman(uint16(s.cfg.RekeyPFS))
	if err != nil {
		return nil, nil, err
	}
	if err := dh.GenerateKey(); err != nil {
		return nil, nil, err
	}
	return proposals, dh, nil
}

func eraseChildRekeyDH(dh *crypto.DiffieHellman) {
	if dh == nil {
		return
	}
	dh.Destroy()
}

// validateChildRekeyResponse validates the selected suite, PFS exchange and
// traffic selectors against the exact offer before a live SA is replaced.
func validateChildRekeyResponse(payloads []ikev2.Payload, offers []*ikev2.Proposal, dh *crypto.DiffieHellman, offeredTSI, offeredTSR []*ikev2.TrafficSelector) (*ikev2.Proposal, []byte, []byte, []*ikev2.TrafficSelector, []*ikev2.TrafficSelector, error) {
	var sa *ikev2.EncryptedPayloadSA
	var nonce *ikev2.EncryptedPayloadNonce
	var ke *ikev2.EncryptedPayloadKE
	var tsi, tsr *ikev2.EncryptedPayloadTS
	fail := func(message string) (*ikev2.Proposal, []byte, []byte, []*ikev2.TrafficSelector, []*ikev2.TrafficSelector, error) {
		return nil, nil, nil, nil, nil, errors.New(message)
	}
	for _, payload := range payloads {
		switch p := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			if sa != nil {
				return fail("duplicate CHILD_SA rekey SA")
			}
			sa = p
		case *ikev2.EncryptedPayloadNonce:
			if nonce != nil {
				return fail("duplicate CHILD_SA rekey nonce")
			}
			nonce = p
		case *ikev2.EncryptedPayloadKE:
			if ke != nil {
				return fail("duplicate CHILD_SA rekey KE")
			}
			ke = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				if tsi != nil {
					return fail("duplicate CHILD_SA rekey TSi")
				}
				tsi = p
			} else {
				if tsr != nil {
					return fail("duplicate CHILD_SA rekey TSr")
				}
				tsr = p
			}
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return fail(fmt.Sprintf("CREATE_CHILD_SA rejected: notify %d", p.NotifyType))
			}
		}
	}
	if sa == nil || len(sa.Proposals) != 1 || nonce == nil || len(nonce.NonceData) < 16 || len(nonce.NonceData) > 256 {
		return fail("invalid CHILD_SA rekey SA/nonce")
	}
	proposal := sa.Proposals[0]
	if proposal == nil || proposal.ProtocolID != ikev2.ProtoESP || len(proposal.SPI) != 4 || binary.BigEndian.Uint32(proposal.SPI) == 0 {
		return fail("invalid CHILD_SA rekey SPI/protocol")
	}
	if _, err := ikev2.ValidateSelectedProposal(sa, offers); err != nil {
		return fail("CHILD_SA rekey selected an unoffered transform")
	}
	if tsi == nil || tsr == nil || !childRekeySelectorsWithin(tsi.TrafficSelectors, offeredTSI) || !childRekeySelectorsWithin(tsr.TrafficSelectors, offeredTSR) {
		return fail("CHILD_SA rekey traffic selectors missing or broader than offer")
	}
	var shared []byte
	if dh == nil {
		if ke != nil {
			return fail("unexpected CHILD_SA rekey KE")
		}
	} else {
		if ke == nil || uint16(ke.DHGroup) != dh.Group {
			return fail("missing or mismatched CHILD_SA rekey KE")
		}
		var err error
		shared, err = dh.ComputeSharedSecret(ke.KEData)
		if err != nil {
			return fail("invalid CHILD_SA rekey DH public key")
		}
	}
	return proposal, nonce.NonceData, shared, tsi.TrafficSelectors, tsr.TrafficSelectors, nil
}

func childRekeySelectionMatches(selected, offer *ikev2.Proposal) bool {
	_, err := ikev2.ValidateSelectedProposal(&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{selected}}, []*ikev2.Proposal{offer})
	return err == nil
}

func childRekeySelectorsWithin(selected, offered []*ikev2.TrafficSelector) bool {
	if len(selected) == 0 {
		return false
	}
	for _, item := range selected {
		if item == nil {
			return false
		}
		size := 4
		if item.TSType == ikev2.TS_IPV6_ADDR_RANGE {
			size = 16
		} else if item.TSType != ikev2.TS_IPV4_ADDR_RANGE {
			return false
		}
		if len(item.StartAddr) != size || len(item.EndAddr) != size || bytes.Compare(item.StartAddr, item.EndAddr) > 0 || item.StartPort > item.EndPort {
			return false
		}
		found := false
		for _, allowed := range offered {
			if allowed != nil && item.TSType == allowed.TSType && (allowed.IPProtocol == 0 || item.IPProtocol == allowed.IPProtocol) && item.StartPort >= allowed.StartPort && item.EndPort <= allowed.EndPort && bytes.Compare(item.StartAddr, allowed.StartAddr) >= 0 && bytes.Compare(item.EndAddr, allowed.EndAddr) <= 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
