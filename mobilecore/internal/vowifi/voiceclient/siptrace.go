package voiceclient

import (
	"os"
	"strings"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
)

type sipTraceLogger struct {
	traceID  string
	deviceID string
}

func (s sipTraceLogger) SIPTraceRead(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info("IMS SIP read",
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.String("sip", redactSIPMessage(string(sipmsg))))
}

func (s sipTraceLogger) SIPTraceWrite(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info("IMS SIP write",
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.String("sip", redactSIPMessage(string(sipmsg))))
}

// redactSIPMessage replaces sensitive header values (Authorization,
// Proxy-Authorization, and the response field in digest auth lines) with
// "[REDACTED]" to prevent credential leakage in trace logs.
func redactSIPMessage(msg string) string {
	lines := strings.Split(msg, "\r\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "authorization:") ||
			strings.HasPrefix(lower, "proxy-authorization:") {
			if idx := strings.Index(line, ":"); idx >= 0 {
				lines[i] = line[:idx+1] + " [REDACTED]"
			}
		}
	}
	return strings.Join(lines, "\r\n")
}

func installSIPTrace(traceID, deviceID string) {
	// SIPDebug is process-global; only enable for single-session capture/debug.
	if strings.TrimSpace(os.Getenv("PROLETARIUS_SIP_TRACE")) == "" {
		return
	}
	sip.SIPDebug = true
	sip.SIPDebugTracer(sipTraceLogger{
		traceID:  traceID,
		deviceID: deviceID,
	})
}
