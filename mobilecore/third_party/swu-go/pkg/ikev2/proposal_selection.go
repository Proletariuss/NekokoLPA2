package ikev2

import (
	"bytes"
	"fmt"
)

// SelectProposalIntersection chooses one suite in local policy order from an
// inbound offer. It retains the peer's proposal number and SPI. Unlike response
// validation, an inbound request may offer alternatives of the same type.
func SelectProposalIntersection(requested, allowed []*Proposal) (*Proposal, error) {
	if len(requested) == 0 || len(requested) > MaxConfiguredProposals {
		return nil, fmt.Errorf("invalid request proposal count")
	}
	for _, local := range allowed {
		if local == nil {
			continue
		}
		for _, peer := range requested {
			if peer == nil || peer.ProtocolID != local.ProtocolID || len(peer.Transforms) > MaxProposalTransforms {
				continue
			}
			selected := NewProposal(peer.ProposalNum, peer.ProtocolID, append([]byte(nil), peer.SPI...))
			seen := map[TransformType]bool{}
			valid := true
			for _, pt := range peer.Transforms {
				if pt == nil || pt.Type < TransformTypeEncr || pt.Type > TransformTypeESN {
					valid = false
					break
				}
				// Never silently discard a requested DH or integrity requirement.
				hasType := false
				for _, lt := range local.Transforms {
					if lt != nil && lt.Type == pt.Type {
						hasType = true
						break
					}
				}
				if !hasType {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			for _, lt := range local.Transforms {
				if lt == nil || seen[lt.Type] {
					continue
				}
				for _, pt := range peer.Transforms {
					if sameSelectedTransform(lt, pt) {
						selected.Transforms = append(selected.Transforms, pt)
						seen[lt.Type] = true
						break
					}
				}
			}
			localNumber := *local
			localNumber.ProposalNum = peer.ProposalNum
			response := &EncryptedPayloadSA{Proposals: []*Proposal{selected}}
			if _, err := ValidateSelectedProposal(response, []*Proposal{peer}); err != nil {
				continue
			}
			if _, err := ValidateSelectedProposal(response, []*Proposal{&localNumber}); err != nil {
				continue
			}
			return selected, nil
		}
	}
	return nil, fmt.Errorf("no request proposal intersects local policy")
}

// ValidateSelectedProposal enforces RFC 7296 sections 2.7 and 3.3.6:
// the responder selects exactly one offered proposal and one transform of
// each required type. Inbound SPIs belong to the peer and are not compared.
func ValidateSelectedProposal(response *EncryptedPayloadSA, offered []*Proposal) (*Proposal, error) {
	if response == nil || len(response.Proposals) != 1 || response.Proposals[0] == nil {
		return nil, fmt.Errorf("SA response must select exactly one proposal")
	}
	selected := response.Proposals[0]
	var offer *Proposal
	for _, p := range offered {
		if p != nil && p.ProposalNum == selected.ProposalNum && p.ProtocolID == selected.ProtocolID {
			offer = p
			break
		}
	}
	if offer == nil {
		return nil, fmt.Errorf("response selected an unoffered proposal number or protocol")
	}
	if selected.ProtocolID == ProtoESP && len(selected.SPI) != 4 {
		return nil, fmt.Errorf("ESP response SPI must contain 4 bytes")
	}
	if selected.ProtocolID == ProtoIKE && len(selected.SPI) != len(offer.SPI) {
		return nil, fmt.Errorf("IKE response SPI length differs from exchange")
	}
	if len(selected.Transforms) == 0 || len(selected.Transforms) > 5 {
		return nil, fmt.Errorf("invalid selected transform count")
	}
	seen := map[TransformType]*Transform{}
	for _, s := range selected.Transforms {
		if s == nil || s.Type < TransformTypeEncr || s.Type > TransformTypeESN || seen[s.Type] != nil {
			return nil, fmt.Errorf("duplicate or invalid selected transform type")
		}
		seen[s.Type] = s
		found := false
		for _, o := range offer.Transforms {
			if sameSelectedTransform(s, o) {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("selected transform %d/%d or its attributes were not offered", s.Type, s.ID)
		}
	}
	encr := seen[TransformTypeEncr]
	if encr == nil {
		return nil, fmt.Errorf("selected proposal lacks encryption")
	}
	aead := encr.ID == ENCR_AES_GCM_8 || encr.ID == ENCR_AES_GCM_12 || encr.ID == ENCR_AES_GCM_16
	if aead && seen[TransformTypeInteg] != nil {
		return nil, fmt.Errorf("AEAD selection contains separate integrity")
	}
	if !aead && seen[TransformTypeInteg] == nil {
		return nil, fmt.Errorf("selected CBC proposal lacks integrity")
	}
	switch selected.ProtocolID {
	case ProtoIKE:
		if seen[TransformTypePRF] == nil || seen[TransformTypeDH] == nil || seen[TransformTypeESN] != nil {
			return nil, fmt.Errorf("invalid IKE transform selection")
		}
	case ProtoESP:
		if seen[TransformTypePRF] != nil {
			return nil, fmt.Errorf("ESP response contains PRF")
		}
		if esn := seen[TransformTypeESN]; esn == nil || esn.ID != 0 {
			return nil, fmt.Errorf("ESP requires supported NO_ESN selection")
		}
		// A rekey can offer DH; if offered it must also be selected.
		for _, o := range offer.Transforms {
			if o.Type == TransformTypeDH && seen[TransformTypeDH] == nil {
				return nil, fmt.Errorf("ESP rekey response omitted offered DH")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported selected protocol")
	}
	return selected, nil
}
func sameSelectedTransform(a, b *Transform) bool {
	if a == nil || b == nil || a.Type != b.Type || a.ID != b.ID || len(a.Attributes) != len(b.Attributes) {
		return false
	}
	seen := map[uint16]bool{}
	for _, x := range a.Attributes {
		if x == nil || seen[x.Type] {
			return false
		}
		seen[x.Type] = true
		found := false
		for _, y := range b.Attributes {
			if y != nil && x.Type == y.Type && x.Val == y.Val && bytes.Equal(x.Value, y.Value) {
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
