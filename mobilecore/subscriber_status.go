package mobilecore

import (
	"strings"

	"proletarius.local/core/internal/vowifi/subscriber"
)

// appendSubscriberStatus exposes only evidence attached to this successful
// registration. IMSI-derived public/private SIP identities are never a fallback.
func appendSubscriberStatus(status, ims map[string]any, card cardConfig) {
	status["msisdn"], status["msisdn_source"] = "", ""
	status["mcc"], status["mnc"] = "", ""
	if registered, _ := ims["registered"].(bool); !registered {
		return
	}
	if mcc, mnc := strings.TrimSpace(card.MCC), strings.TrimSpace(card.MNC); decimalDigits(mcc, 3, 3) && decimalDigits(mnc, 2, 3) {
		status["mcc"], status["mnc"] = mcc, mnc
	}
	registeredNumber, _ := ims["registered_msisdn"].(string)
	if number := subscriber.NormalizeMSISDN(registeredNumber, card.IMSI, false); number != "" {
		status["msisdn"], status["msisdn_source"] = number, "ims"
		return
	}
	if number := subscriber.NormalizeMSISDN(card.MSISDN, card.IMSI, true); number != "" {
		status["msisdn"], status["msisdn_source"] = number, "sim"
	}
}

func decimalDigits(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
