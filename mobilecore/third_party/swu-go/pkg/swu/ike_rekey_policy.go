package swu

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// Offer only the live IKE suite during rekey so changing keys never silently
// changes PRF strength, encryption key size, or the negotiated DH group.
func (s *Session) currentIKERekeyProposal(spi []byte) (*ikev2.Proposal, error) {
	if s.EncAlg == nil || s.DH == nil || s.PRFAlg == nil || len(spi) != 8 {
		return nil, errors.New("incomplete negotiated IKE suite")
	}
	var prf ikev2.AlgorithmType
	switch s.PRFAlg {
	case crypto.PRF_HMAC_MD5:
		prf = ikev2.PRF_HMAC_MD5
	case crypto.PRF_HMAC_SHA1:
		prf = ikev2.PRF_HMAC_SHA1
	case crypto.PRF_HMAC_SHA2_256:
		prf = ikev2.PRF_HMAC_SHA2_256
	case crypto.PRF_HMAC_SHA2_384:
		prf = ikev2.PRF_HMAC_SHA2_384
	case crypto.PRF_HMAC_SHA2_512:
		prf = ikev2.PRF_HMAC_SHA2_512
	default:
		return nil, errors.New("unrecognized negotiated IKE PRF")
	}
	p := ikev2.NewProposal(1, ikev2.ProtoIKE, append([]byte(nil), spi...))
	p.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.AlgorithmType(s.ikeEncrID), s.EncAlg.KeySize()*8)
	if !s.ikeIsAEAD {
		if s.IntegAlg == nil {
			return nil, errors.New("IKE integrity algorithm missing")
		}
		p.AddTransform(ikev2.TransformTypeInteg, ikev2.AlgorithmType(s.ikeIntegID), 0)
	}
	p.AddTransform(ikev2.TransformTypePRF, prf, 0)
	p.AddTransform(ikev2.TransformTypeDH, ikev2.AlgorithmType(s.DH.Group), 0)
	return p, nil
}

func validateIKERekeyResponse(payloads []ikev2.Payload, offers []*ikev2.Proposal, dh *crypto.DiffieHellman) (*ikev2.Proposal, []byte, error) {
	var sa *ikev2.EncryptedPayloadSA
	var nonce *ikev2.EncryptedPayloadNonce
	var ke *ikev2.EncryptedPayloadKE
	for _, p := range payloads {
		switch x := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			if sa != nil {
				return nil, nil, errors.New("duplicate IKE rekey SA")
			}
			sa = x
		case *ikev2.EncryptedPayloadNonce:
			if nonce != nil {
				return nil, nil, errors.New("duplicate IKE rekey nonce")
			}
			nonce = x
		case *ikev2.EncryptedPayloadKE:
			if ke != nil {
				return nil, nil, errors.New("duplicate IKE rekey KE")
			}
			ke = x
		case *ikev2.EncryptedPayloadTS:
			return nil, nil, errors.New("unexpected traffic selectors in IKE rekey")
		case *ikev2.EncryptedPayloadNotify:
			if x.NotifyType < 16384 {
				return nil, nil, fmt.Errorf("IKE rekey rejected: notify %d", x.NotifyType)
			}
		}
	}
	selected, err := ikev2.ValidateSelectedProposal(sa, offers)
	if err != nil {
		return nil, nil, err
	}
	if selected.ProtocolID != ikev2.ProtoIKE || len(selected.SPI) != 8 || binary.BigEndian.Uint64(selected.SPI) == 0 {
		return nil, nil, errors.New("invalid IKE rekey responder SPI")
	}
	minNonce := 16
	for _, t := range selected.Transforms {
		if t.Type == ikev2.TransformTypePRF {
			prf, err := crypto.GetPRF(uint16(t.ID))
			if err != nil {
				return nil, nil, err
			}
			if prf.KeyLen()/2 > minNonce {
				minNonce = prf.KeyLen() / 2
			}
		}
	}
	if nonce == nil || len(nonce.NonceData) < minNonce || len(nonce.NonceData) > 256 {
		return nil, nil, errors.New("invalid IKE rekey nonce length")
	}
	group, err := ikev2.ProposalDHGroup(selected)
	if err != nil || dh == nil || ke == nil || uint16(group) != dh.Group || ke.DHGroup != group {
		return nil, nil, errors.New("IKE rekey DH/KE group mismatch")
	}
	if _, err := dh.ComputeSharedSecret(ke.KEData); err != nil {
		return nil, nil, fmt.Errorf("invalid IKE rekey public key: %w", err)
	}
	return selected, nonce.NonceData, nil
}
