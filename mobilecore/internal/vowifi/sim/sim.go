package sim

import "errors"

var (
	ErrSyncFailure     = errors.New("sync failure")
	ErrISIMUnavailable = errors.New("ISIM application unavailable")
)

type AKAResult struct {
	RES  []byte
	CK   []byte
	IK   []byte
	AUTS []byte
}

// Zero 安全清除密钥材料（RES/CK/IK/AUTS）。
// 应在使用完毕后调用，防止敏感数据残留在内存中。
func (r *AKAResult) Zero() {
	if r == nil {
		return
	}
	for _, b := range [][]byte{r.RES, r.CK, r.IK, r.AUTS} {
		for i := range b {
			b[i] = 0
		}
	}
}

type AKAProvider interface {
	CalculateAKA(rand16, autn16 []byte) (AKAResult, error)
}

// ISIMAKAProvider is implemented by AKA providers that can additionally
// authenticate against an ISIM application (as opposed to USIM). Callers type-assert
// for this when AKAAppPreference is "isim"/"isim_strict"/"auto" and fall back to
// plain AKAProvider (USIM) otherwise.
type ISIMAKAProvider interface {
	AKAProvider
	CalculateISIMAKA(rand16, autn16 []byte) (AKAResult, error)
}
