package imscore

import (
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

type registerFailureOutcome struct {
	advanceRegistrar bool
	retryVariant     bool
	retryTransport   bool
	reason           string
}

// decideRegisterFailureOutcome maps an initial REGISTER failure to the next FSM step.
func decideRegisterFailureOutcome(cfg Config, statusCode int, reason string, variantIndex, variantTotal int, hasMoreRegistrar bool) registerFailureOutcome {
	out := registerFailureOutcome{reason: strings.TrimSpace(reason)}

	if shouldRetryInitialRegisterForStatus(cfg, statusCode) && variantIndex+1 < variantTotal {
		out.retryVariant = true
		out.reason = "initial_reject_fallback"
		return out
	}

	if shouldAdvanceRegistrarForNextRetry(cfg, statusCode, reason, hasMoreRegistrar) {
		out.advanceRegistrar = true
		out.reason = "registrar_candidate_rejected"
		return out
	}

	if statusCode == 0 && hasMoreRegistrar {
		out.advanceRegistrar = true
		out.reason = "registrar_probe_timeout"
		return out
	}

	return out
}

func isForbiddenRegisterSIPResponse(cfg Config, code int) bool {
	codes := cfg.Template.RegisterPolicy.ForbiddenStatusCodes
	if codes == nil {
		return code == sip.StatusForbidden
	}
	return containsStatusCode(codes, code)
}

func isTemporaryRegisterSIPResponse(cfg Config, code int) bool {
	codes := cfg.Template.RegisterPolicy.TemporaryStatusCodes
	if codes != nil {
		return containsStatusCode(codes, code)
	}
	return containsStatusCode([]int{
		sip.StatusRequestTimeout,
		sip.StatusInternalServerError,
		sip.StatusBadGateway,
		sip.StatusServiceUnavailable,
		sip.StatusGatewayTimeout,
		sip.StatusTemporarilyUnavailable,
	}, code)
}

func containsStatusCode(codes []int, code int) bool {
	for _, configured := range codes {
		if configured == code {
			return true
		}
	}
	return false
}

func registerPolicyRetryDelay(cfg Config, statusCode int) time.Duration {
	if isTemporaryRegisterSIPResponse(cfg, statusCode) && cfg.Template.RegisterPolicy.TemporaryRetrySeconds > 0 {
		return time.Duration(cfg.Template.RegisterPolicy.TemporaryRetrySeconds) * time.Second
	}
	return registerTransportCandidateGap
}
