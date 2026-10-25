package ikev2

import (
	"fmt"
	"strings"
)

const (
	MaxConfiguredProposals = 32
	MaxProposalTransforms  = 32
	MaxProposalTextLength  = 2048
)

// BuildIKEProposals retains ordered alternatives within and across proposals.
// Explicit configuration replaces the defaults; no unsupported token is ignored.
func BuildIKEProposals(configured []string, spi []byte) ([]*Proposal, error) {
	if len(configured) == 0 {
		return CreateMultiProposalIKE(spi), nil
	}
	return buildConfiguredProposals(configured, ProtoIKE, spi)
}
func BuildESPProposals(configured []string, spi []byte) ([]*Proposal, error) {
	if len(configured) == 0 {
		return CreateMultiProposalESP(spi), nil
	}
	return buildConfiguredProposals(configured, ProtoESP, spi)
}
func buildConfiguredProposals(configured []string, protocol ProtocolID, spi []byte) ([]*Proposal, error) {
	if len(configured) > MaxConfiguredProposals {
		return nil, fmt.Errorf("too many proposals (maximum %d)", MaxConfiguredProposals)
	}
	out := make([]*Proposal, 0, len(configured))
	for i, raw := range configured {
		p, err := parseProposalSpec(raw, protocol)
		if err != nil {
			return nil, fmt.Errorf("proposal %d %q: %w", i+1, raw, err)
		}
		p.ProposalNum = uint8(i + 1)
		p.SPI = append([]byte(nil), spi...)
		out = append(out, p)
	}
	return out, nil
}

// ProposalDHGroup returns the preferred group for the initial KE. A responder
// choosing another offered group must use INVALID_KE_PAYLOAD before success.
func ProposalDHGroup(proposal *Proposal) (AlgorithmType, error) {
	if proposal == nil {
		return 0, fmt.Errorf("proposal is nil")
	}
	for _, t := range proposal.Transforms {
		if t != nil && t.Type == TransformTypeDH {
			return t.ID, nil
		}
	}
	return 0, fmt.Errorf("proposal does not contain a DH transform")
}

func parseProposalSpec(raw string, protocol ProtocolID) (*Proposal, error) {
	if len(raw) > MaxProposalTextLength {
		return nil, fmt.Errorf("proposal text exceeds %d bytes", MaxProposalTextLength)
	}
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return nil, fmt.Errorf("proposal must not be empty")
	}
	tokens := strings.Split(raw, "-")
	if len(tokens) > MaxProposalTransforms {
		return nil, fmt.Errorf("too many transforms (maximum %d)", MaxProposalTransforms)
	}
	p := NewProposal(1, protocol, nil)
	var enc, integ, prf, dh []*Transform
	var aead, cbc, esn bool
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("empty algorithm token")
		}
		if id, bits, isAEAD, ok := parseEncryptionToken(token); ok {
			t := NewProposal(1, protocol, nil)
			t.AddTransformWithKeyLen(TransformTypeEncr, id, bits)
			enc = append(enc, t.Transforms[0])
			aead = aead || isAEAD
			cbc = cbc || !isAEAD
			continue
		}
		if id, ok := parseIntegrityToken(token); ok {
			integ = append(integ, &Transform{Type: TransformTypeInteg, ID: id})
			continue
		}
		if id, ok := parsePRFToken(token); ok {
			if protocol != ProtoIKE {
				return nil, fmt.Errorf("PRF is not valid in an ESP proposal")
			}
			prf = append(prf, &Transform{Type: TransformTypePRF, ID: id})
			continue
		}
		if id, known, supported := parseDHToken(token); known {
			if protocol != ProtoIKE {
				return nil, fmt.Errorf("DH group is not valid in an initial ESP proposal")
			}
			if !supported {
				return nil, fmt.Errorf("DH group %q is known but not supported by this runtime", token)
			}
			dh = append(dh, &Transform{Type: TransformTypeDH, ID: id})
			continue
		}
		if token == "esn" || token == "noesn" {
			if protocol != ProtoESP {
				return nil, fmt.Errorf("%s is only valid in an ESP proposal", token)
			}
			if token == "esn" {
				return nil, fmt.Errorf("ESN is not supported by the packet runtime")
			}
			if esn {
				return nil, fmt.Errorf("multiple ESN selections")
			}
			esn = true
			continue
		}
		return nil, fmt.Errorf("unknown or unsupported algorithm token %q", token)
	}
	if len(enc) == 0 {
		return nil, fmt.Errorf("missing encryption algorithm")
	}
	if aead && cbc {
		return nil, fmt.Errorf("AEAD and non-AEAD encryption require separate proposals")
	}
	if aead && len(integ) > 0 {
		return nil, fmt.Errorf("AEAD encryption must not include a separate integrity algorithm")
	}
	if !aead && len(integ) == 0 {
		return nil, fmt.Errorf("non-AEAD encryption requires an integrity algorithm")
	}
	if protocol == ProtoIKE {
		if len(dh) == 0 {
			return nil, fmt.Errorf("IKE proposal requires a DH group")
		}
		if len(prf) == 0 {
			if len(integ) == 0 {
				return nil, fmt.Errorf("AEAD IKE proposal requires an explicit PRF")
			}
			for _, i := range integ {
				prf = append(prf, &Transform{Type: TransformTypePRF, ID: prfForIntegrity(i.ID)})
			}
		}
	}
	// Keep the established single-suite wire order byte-for-byte.
	p.Transforms = append(p.Transforms, enc...)
	p.Transforms = append(p.Transforms, integ...)
	p.Transforms = append(p.Transforms, prf...)
	p.Transforms = append(p.Transforms, dh...)
	if protocol == ProtoESP {
		p.AddTransform(TransformTypeESN, 0, 0)
	}
	if len(p.Transforms) > MaxProposalTransforms {
		return nil, fmt.Errorf("too many expanded transforms (maximum %d)", MaxProposalTransforms)
	}
	return p, nil
}

func parseEncryptionToken(token string) (id AlgorithmType, keyLen int, aead bool, ok bool) {
	switch token {
	case "aes128":
		return ENCR_AES_CBC, 128, false, true
	case "aes192":
		return ENCR_AES_CBC, 192, false, true
	case "aes256":
		return ENCR_AES_CBC, 256, false, true
	}

	for _, item := range []struct {
		name string
		id   AlgorithmType
	}{
		{name: "gcm8", id: ENCR_AES_GCM_8},
		{name: "gcm12", id: ENCR_AES_GCM_12},
		{name: "gcm16", id: ENCR_AES_GCM_16},
	} {
		for _, bits := range []int{128, 192, 256} {
			if token == fmt.Sprintf("aes%d%s", bits, item.name) {
				return item.id, bits, true, true
			}
		}
	}
	return 0, 0, false, false
}

func parseIntegrityToken(token string) (AlgorithmType, bool) {
	switch token {
	case "sha1":
		return AUTH_HMAC_SHA1_96, true
	case "sha256", "sha2_256":
		return AUTH_HMAC_SHA2_256_128, true
	case "sha384", "sha2_384":
		return AUTH_HMAC_SHA2_384_192, true
	case "sha512", "sha2_512":
		return AUTH_HMAC_SHA2_512_256, true
	default:
		return 0, false
	}
}

func parsePRFToken(token string) (AlgorithmType, bool) {
	switch token {
	case "prfmd5":
		return PRF_HMAC_MD5, true
	case "prfsha1":
		return PRF_HMAC_SHA1, true
	case "prfsha256", "prfsha2_256":
		return PRF_HMAC_SHA2_256, true
	case "prfsha384", "prfsha2_384":
		return PRF_HMAC_SHA2_384, true
	case "prfsha512", "prfsha2_512":
		return PRF_HMAC_SHA2_512, true
	default:
		return 0, false
	}
}

func parseDHToken(token string) (id AlgorithmType, known bool, supported bool) {
	switch token {
	case "ecp256":
		return AlgorithmType(19), true, true
	case "ecp384":
		return AlgorithmType(20), true, true
	case "ecp521":
		return AlgorithmType(21), true, true
	case "modp768":
		return MODP_768_bit, true, false
	case "modp1024":
		return MODP_1024_bit, true, true
	case "modp1536":
		return MODP_1536_bit, true, true
	case "modp2048":
		return MODP_2048_bit, true, true
	case "modp3072":
		return MODP_3072_bit, true, true
	case "modp4096":
		return MODP_4096_bit, true, true
	case "modp6144":
		return MODP_6144_bit, true, true
	case "modp8192":
		return MODP_8192_bit, true, true
	default:
		return 0, false, false
	}
}

func prfForIntegrity(integrity AlgorithmType) AlgorithmType {
	switch integrity {
	case AUTH_HMAC_SHA1_96:
		return PRF_HMAC_SHA1
	case AUTH_HMAC_SHA2_256_128:
		return PRF_HMAC_SHA2_256
	case AUTH_HMAC_SHA2_384_192:
		return PRF_HMAC_SHA2_384
	case AUTH_HMAC_SHA2_512_256:
		return PRF_HMAC_SHA2_512
	default:
		return 0
	}
}
