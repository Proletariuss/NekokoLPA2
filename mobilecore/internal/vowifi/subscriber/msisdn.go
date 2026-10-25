// Package subscriber validates phone numbers read from subscriber-specific
// evidence. It does not infer a number from an IMS identity or a location.
package subscriber

import (
	"strings"
	"unicode"
)

// NormalizeMSISDN accepts a number already obtained from EF-MSISDN or a typed
// IMS associated identity. It preserves national SIM numbers when requested;
// callers must use the SIM home region for any subsequent E.164 conversion.
// This structural check does not claim numbering-plan validity or ownership.
func NormalizeMSISDN(raw, imsi string, allowNational bool) string {
	var normalized strings.Builder
	for _, character := range strings.TrimSpace(raw) {
		switch {
		case character == '+' && normalized.Len() == 0:
			normalized.WriteRune(character)
		case character >= '0' && character <= '9':
			normalized.WriteRune(character)
		case unicode.IsSpace(character), character == '-', character == '.', character == '(', character == ')':
		default:
			return ""
		}
	}
	number := normalized.String()
	international := strings.HasPrefix(number, "+")
	digits := strings.TrimPrefix(number, "+")
	if len(digits) < 5 || len(digits) > 15 || (!international && !allowNational) {
		return ""
	}
	// International country calling codes cannot begin with zero. National
	// trunk zeroes are retained; inventing '+' here would change the number.
	if international && digits[0] == '0' {
		return ""
	}
	imsi = strings.TrimSpace(imsi)
	if imsi != "" && (digits == imsi || digits == "0"+imsi) {
		return ""
	}
	if strings.Trim(digits, digits[:1]) == "" {
		return ""
	}
	return number
}
