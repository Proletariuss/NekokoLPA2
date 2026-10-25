package swu

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

// certificateValidationError retains the internal cause, but its displayed
// message and diagnostic fields never contain peer-supplied certificate text.
type certificateValidationError struct {
	reason     string
	stage      int
	code       int
	leafSHA256 string
	cause      error
}

func (e *certificateValidationError) Error() string { return safeCertificateReason(e.reason) }
func (e *certificateValidationError) Unwrap() error { return e.cause }

func safeCertificateReason(reason string) string {
	switch reason {
	case "certificate_missing", "certificate_chain_limit", "certificate_encoding", "certificate_parse",
		"certificate_duplicate", "certificate_expired", "certificate_not_yet_valid", "certificate_critical_extension",
		"certificate_key_usage", "certificate_eku", "certificate_hostname_mismatch", "certificate_idr_mismatch",
		"certificate_idr_invalid", "certificate_expected_identity_invalid", "certificate_ca_constraints",
		"certificate_chain_untrusted", "certificate_chain_incomplete", "certificate_revoked", "certificate_chain_invalid",
		"certificate_trust_internal", "certificate_chain_extraneous", "certificate_verifier_unavailable":
		return reason
	default:
		return "certificate_trust_internal"
	}
}

func certificateError(reason string, cause error) error {
	return &certificateValidationError{reason: safeCertificateReason(reason), cause: cause}
}

func certificateFingerprint(der []byte) string {
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func validCertificateFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func classifyCertificateError(err error, now time.Time) string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var critical x509.UnhandledCriticalExtension
	var invalid x509.CertificateInvalidError
	var algorithm x509.InsecureAlgorithmError
	var constraint x509.ConstraintViolationError
	switch {
	case errors.As(err, &unknown):
		return "certificate_chain_untrusted"
	case errors.As(err, &hostname):
		return "certificate_hostname_mismatch"
	case errors.As(err, &critical):
		return "certificate_critical_extension"
	case errors.As(err, &invalid):
		switch invalid.Reason {
		case x509.Expired:
			if invalid.Cert != nil && now.Before(invalid.Cert.NotBefore) {
				return "certificate_not_yet_valid"
			}
			return "certificate_expired"
		case x509.IncompatibleUsage, x509.CANotAuthorizedForExtKeyUsage:
			return "certificate_eku"
		case x509.NotAuthorizedToSign, x509.TooManyIntermediates:
			return "certificate_ca_constraints"
		default:
			return "certificate_chain_invalid"
		}
	case errors.As(err, &algorithm), errors.As(err, &constraint):
		return "certificate_chain_invalid"
	default:
		return "certificate_trust_internal"
	}
}

func withCertificateLeaf(err error, fingerprint string, now time.Time) error {
	var typed *certificateValidationError
	if errors.As(err, &typed) {
		// Copy rather than mutate a cause that another observer may retain.
		copy := *typed
		copy.leafSHA256 = fingerprint
		return &copy
	}
	return &certificateValidationError{reason: classifyCertificateError(err, now), leafSHA256: fingerprint, cause: err}
}

// These OSStatus values are defined by Security/SecBase.h. Keep their mapping
// portable so it can be tested without the real system certificate store.
func appleCertificateError(stage, code int) error {
	reason := "certificate_trust_internal"
	if stage == 3 {
		reason = "certificate_chain_extraneous"
	} else if stage == 2 {
		switch code {
		case -25318: // errSecCreateChainFailed: required certificates not found.
			reason = "certificate_chain_incomplete"
		case -67818:
			reason = "certificate_expired"
		case -67819:
			reason = "certificate_not_yet_valid"
		case -67820:
			reason = "certificate_revoked"
		case -67843:
			reason = "certificate_chain_untrusted"
		case -67602:
			reason = "certificate_hostname_mismatch"
		case -67603:
			reason = "certificate_critical_extension"
		case -67604, -67605, -67611:
			reason = "certificate_ca_constraints"
		case -67608:
			reason = "certificate_key_usage"
		case -67609:
			reason = "certificate_eku"
		case -67606, -67607, -67610, -67612, -67824, -67826:
			reason = "certificate_chain_invalid"
		}
	}
	return &certificateValidationError{reason: reason, stage: stage, code: code}
}

func certificateDiagnostic(err error) (reason string, stage, code int, leafSHA256 string) {
	if err == nil {
		return
	}
	var typed *certificateValidationError
	if !errors.As(err, &typed) {
		return
	}
	reason = safeCertificateReason(typed.reason)
	if typed.stage >= 0 && typed.stage <= 16 && int64(typed.code) >= -2147483648 && int64(typed.code) <= 2147483647 {
		stage, code = typed.stage, typed.code
		// A non-platform result carries no platform error code.
		if stage == 0 {
			code = 0
		}
	}
	if validCertificateFingerprint(typed.leafSHA256) {
		leafSHA256 = typed.leafSHA256
	}
	return
}
