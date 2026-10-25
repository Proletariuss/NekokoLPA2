package ikev2

import "testing"

func TestCarrierProposalIncludesO2GiffgaffSuite(t *testing.T) {
	proposals := CreateMultiProposalIKE(nil)
	if !hasProposalTransforms(proposals, ENCR_AES_CBC, AUTH_HMAC_SHA2_512_256, PRF_HMAC_SHA2_512, MODP_2048_bit) {
		t.Fatal("IKE proposals do not include AES-256/SHA-512/PRF-SHA-512/DH14")
	}

	esp := CreateMultiProposalESP([]byte{1, 2, 3, 4})
	if !hasProposalTransforms(esp, ENCR_AES_CBC, AUTH_HMAC_SHA2_512_256) {
		t.Fatal("ESP proposals do not include AES-256/SHA-512")
	}
}

func hasProposalTransforms(proposals []*Proposal, algorithms ...AlgorithmType) bool {
	for _, proposal := range proposals {
		matched := true
		for _, algorithm := range algorithms {
			found := false
			for _, transform := range proposal.Transforms {
				if transform.ID == algorithm {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
