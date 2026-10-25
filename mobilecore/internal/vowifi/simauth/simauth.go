// Package simauth computes RFC 3310 "Digest AKAv1-MD5" responses for IMS
// SIP authentication (P-CSCF/S-CSCF challenges to SIP REGISTER and other
// requests), using the same sim.AKAProvider that already authenticates the
// SWu tunnel's EAP-AKA exchange (runtimehost.Start already extracts one
// from StartRequest.SIM for exactly that). A real UE does two independent
// AKA runs per VoWiFi call setup -- one for the ePDG (EAP-AKA), one for the
// P-CSCF/S-CSCF (this package) -- against separate RAND/AUTN vectors from
// the same HSS/USIM; there's no new "source" for the provider, it's the
// same one, called again.
//
// The algorithm here was verified against the actual RFC 3310 text rather
// than reconstructed from memory:
//   - nonce = base64(RAND(16) || AUTN(16) [|| server data])
//   - success: HA1 = MD5(username:realm:hex(RES)) -- RES "treated as a
//     password" -- HA2/response otherwise identical to plain RFC 2617
//   - sync failure: client responds using an EMPTY password, and appends
//     an auts="<base64 AUTS>" directive (RFC 3310 S3.4); the server is
//     expected to resync and reissue a fresh challenge, not accept this
//     attempt -- driving that retry loop is the caller's job, this package
//     computes one round's response.
//
// icholy/digest (sipgo's digest dependency) only recognizes a fixed
// algorithm whitelist ("", "MD5", "SHA-256", "SHA-512", "SHA-512-256") and
// rejects "AKAv1-MD5" outright, so the math runs with Algorithm forced to
// "MD5" (an equivalence RFC 3310 itself states: "the Digest AKA operation
// is identical to the Digest operation in RFC 2617") while the wire-visible
// algorithm label is restored before the header is emitted.
package simauth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/icholy/digest"

	"proletarius.local/core/internal/vowifi/sim"
)

// randAUTNLen is the fixed length of each of RAND and AUTN per 3GPP AKA.
const randAUTNLen = 16

// Result is one round's outcome of computing an IMS-AKA digest response.
type Result struct {
	// Header is the full Authorization header value, including the
	// "Digest " prefix -- ready to send as-is.
	Header string

	// SyncFailure is true when the SIM reported a sequence-number mismatch:
	// Header carries the empty-password response plus an auts= directive,
	// and the caller should expect the server to respond with a fresh
	// challenge rather than accept this attempt.
	SyncFailure bool
}

// ComputeDigest runs one round of RFC 3310 Digest AKAv1-MD5: decodes
// RAND/AUTN out of chal.Nonce, asks provider to compute AKA, and builds the
// resulting Authorization header value -- either a normal AKA-derived
// response, or (on sim.ErrSyncFailure) the empty-password + auts= resync
// response.
//
// opts.Password is overwritten; callers only need to supply
// Method/URI/Username/Count/Cnonce as usual for icholy/digest.
func ComputeDigest(provider sim.AKAProvider, chal *digest.Challenge, opts digest.Options) (Result, error) {
	wireAlgorithm := chal.Algorithm
	if wireAlgorithm == "" {
		wireAlgorithm = "AKAv1-MD5"
	}
	mathChal := *chal
	mathChal.Algorithm = "MD5"

	rawNonce, err := DecodeNonceBytes(chal.Nonce)
	if err != nil {
		return Result{}, err
	}
	if strings.EqualFold(wireAlgorithm, "MD5") {
		if len(rawNonce) != randAUTNLen {
			return Result{}, fmt.Errorf("simauth: plain MD5/GSM nonce must be exactly 16 bytes, got %d", len(rawNonce))
		}
		opts.Password = ""
		cred, err := digest.Digest(&mathChal, opts)
		if err != nil {
			return Result{}, fmt.Errorf("simauth: compute plain digest: %w", err)
		}
		cred.Algorithm = wireAlgorithm
		return Result{Header: cred.String()}, nil
	}

	if provider == nil {
		return Result{}, errors.New("simauth: AKAProvider is required")
	}

	rand16, autn16, err := splitNonce(rawNonce)
	if err != nil {
		return Result{}, err
	}

	akaResult, akaErr := provider.CalculateAKA(rand16, autn16)
	// 使用完毕后清零密钥材料，防止敏感数据残留
	defer akaResult.Zero()

	return computeDigestFromAKA(akaResult, akaErr, &mathChal, opts, wireAlgorithm)
}

// ComputeDigestWithAKA runs one round of RFC 3310 Digest AKAv1-MD5 using a
// pre-computed AKA result, avoiding a redundant second AKA calculation
// (IMSCORE-4 fix). The caller is responsible for calling akaResult.Zero()
// after this function returns.
func ComputeDigestWithAKA(provider sim.AKAProvider, chal *digest.Challenge, opts digest.Options, akaResult sim.AKAResult, akaErrors ...error) (Result, error) {
	wireAlgorithm := chal.Algorithm
	if wireAlgorithm == "" {
		wireAlgorithm = "AKAv1-MD5"
	}
	mathChal := *chal
	mathChal.Algorithm = "MD5"

	rawNonce, err := DecodeNonceBytes(chal.Nonce)
	if err != nil {
		return Result{}, err
	}
	if strings.EqualFold(wireAlgorithm, "MD5") {
		if len(rawNonce) != randAUTNLen {
			return Result{}, fmt.Errorf("simauth: plain MD5/GSM nonce must be exactly 16 bytes, got %d", len(rawNonce))
		}
		opts.Password = ""
		cred, err := digest.Digest(&mathChal, opts)
		if err != nil {
			return Result{}, fmt.Errorf("simauth: compute plain digest: %w", err)
		}
		cred.Algorithm = wireAlgorithm
		return Result{Header: cred.String()}, nil
	}
	if _, _, err := splitNonce(rawNonce); err != nil {
		return Result{}, err
	}

	if len(akaErrors) > 1 {
		return Result{}, errors.New("simauth: multiple pre-computed AKA errors")
	}
	var akaErr error
	if len(akaErrors) == 1 {
		akaErr = akaErrors[0]
	} else if len(akaResult.RES) == 0 && len(akaResult.AUTS) != 0 {
		// Preserve synchronization failure for legacy callers that supplied the
		// result before the explicit error parameter was added.
		akaErr = sim.ErrSyncFailure
	}

	// Use the supplied AKA result without asking the physical card a second
	// time. In particular, retain ErrSyncFailure so computeDigestFromAKA emits
	// the RFC 3310 auts directive instead of treating an empty RES as success.
	return computeDigestFromAKA(akaResult, akaErr, &mathChal, opts, wireAlgorithm)
}

// computeDigestFromAKA builds the digest response from a given AKA result.
// Shared logic between ComputeDigest and ComputeDigestWithAKA.
func computeDigestFromAKA(akaResult sim.AKAResult, akaErr error, mathChal *digest.Challenge, opts digest.Options, wireAlgorithm string) (Result, error) {
	switch {
	case akaErr == nil:
		if len(akaResult.RES) == 0 {
			return Result{}, errors.New("simauth: AKA returned empty RES")
		}
		// RFC 3310 treats RES as the password octet string itself. Hex encoding
		// changes the HA1 input and is rejected by real IMS cores even though a
		// simulator using the same mistake appears to interoperate.
		opts.Password = string(akaResult.RES)
		cred, err := digest.Digest(mathChal, opts)
		if err != nil {
			return Result{}, fmt.Errorf("simauth: compute digest: %w", err)
		}
		cred.Algorithm = wireAlgorithm
		return Result{Header: cred.String()}, nil

	case errors.Is(akaErr, sim.ErrSyncFailure):
		// 3GPP AKA AUTS is SQN^AK (6 octets) followed by MAC-S (8 octets),
		// for a total of 14 octets. RFC 3310 carries that complete value in
		// the base64-encoded auts directive.
		if len(akaResult.AUTS) != 14 {
			return Result{}, fmt.Errorf("simauth: invalid AUTS length %d, expected 14", len(akaResult.AUTS))
		}
		opts.Password = ""
		cred, err := digest.Digest(mathChal, opts)
		if err != nil {
			return Result{}, fmt.Errorf("simauth: compute resync digest: %w", err)
		}
		cred.Algorithm = wireAlgorithm
		header := fmt.Sprintf(`%s, auts="%s"`, cred.String(),
			base64.StdEncoding.EncodeToString(akaResult.AUTS))
		return Result{Header: header, SyncFailure: true}, nil

	default:
		return Result{}, fmt.Errorf("simauth: CalculateAKA: %w", akaErr)
	}
}

// DecodeNonceBytes decodes the nonce encodings observed across IMS cores:
// hexadecimal plus padded/raw standard and URL-safe base64. RFC 3310 uses
// base64, while several deployed carrier cores expose the same bytes as hex.
func DecodeNonceBytes(nonce string) ([]byte, error) {
	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return nil, errors.New("simauth: empty nonce")
	}
	if len(trimmed)%2 == 0 && isASCIIHex(trimmed) {
		raw, err := hex.DecodeString(trimmed)
		if err == nil {
			return raw, nil
		}
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		raw, err := encoding.DecodeString(trimmed)
		if err == nil {
			return raw, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("simauth: decode nonce: %w", lastErr)
}

// splitNonce splits an RFC 3310 AKAv1-MD5 nonce
// (base64(RAND || AUTN [|| server data])) into its RAND/AUTN parts.
func splitNonce(raw []byte) (rand16, autn16 []byte, err error) {
	if len(raw) < 2*randAUTNLen {
		return nil, nil, fmt.Errorf("simauth: nonce too short for RAND||AUTN (%d bytes)", len(raw))
	}
	return raw[:randAUTNLen], raw[randAUTNLen : 2*randAUTNLen], nil
}

func isASCIIHex(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}
