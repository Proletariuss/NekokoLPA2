package sim

import "testing"

func TestAKAResultZeroClearsAllSecrets(t *testing.T) {
	result := &AKAResult{
		RES: []byte{1, 2, 3}, CK: []byte{4, 5}, IK: []byte{6, 7}, AUTS: []byte{8, 9},
	}
	result.Zero()
	for name, value := range map[string][]byte{
		"RES": result.RES, "CK": result.CK, "IK": result.IK, "AUTS": result.AUTS,
	} {
		for _, item := range value {
			if item != 0 {
				t.Fatalf("%s was not cleared: %x", name, value)
			}
		}
	}
}
