package imscore

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
)

// This release implements only explicit REGISTER/INVITE 500 rules. Other
// methods, codes and source ranges remain metadata, not retry authority.
func configuredReRegister500(cfg Config, method sip.RequestMethod, status int) bool {
	if status != sip.StatusInternalServerError || (method != sip.REGISTER && method != sip.INVITE) {
		return false
	}
	for _, rule := range cfg.Template.ReRegisterOn {
		if strings.ToUpper(strings.TrimSpace(rule.Method)) != string(method) {
			continue
		}
		for _, code := range rule.Statuses {
			if strings.TrimSpace(code) == "500" {
				return true
			}
		}
	}
	return false
}

// Respect a server's Retry-After without allowing it to keep a lifecycle
// operation alive indefinitely. Long/invalid delays fail closed to the normal
// recovery path; no extra SIP request is sent.
func waitReRegisterRetry(ctx context.Context, response *sip.Response) error {
	delay := time.Second
	if header := response.GetHeader("Retry-After"); header != nil {
		raw, _, _ := strings.Cut(header.Value(), ";")
		raw, _, _ = strings.Cut(raw, "(")
		seconds, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || seconds < 0 || seconds > 60 {
			return fmt.Errorf("IMS retry has unsupported Retry-After")
		}
		if seconds > 1 {
			delay = time.Duration(seconds) * time.Second
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// RegistrationRecoveryRequests lets the existing engine maintenance worker
// renew the binding after a failed outgoing INVITE. The INVITE itself is never
// replayed. The one-event budget belongs to this service/tunnel lifecycle.
func (s *Service) RegistrationRecoveryRequests() <-chan struct{} {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.registrationRecovery == nil {
		s.registrationRecovery = make(chan struct{}, 1)
	}
	return s.registrationRecovery
}

func (s *Service) requestInviteRegistrationRecovery(response *sip.Response) {
	if response == nil || !configuredReRegister500(s.cfg, sip.INVITE, response.StatusCode) {
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.closing || !s.registered || s.inviteRecoveryUsed || s.lifecycleCtx == nil || s.lifecycleCtx.Err() != nil {
		return
	}
	// Retry-After is handled by REGISTER retries; do not send an immediate
	// recovery REGISTER when the failed INVITE explicitly requests a delay.
	if response.GetHeader("Retry-After") != nil {
		return
	}
	if s.registrationRecovery == nil {
		s.registrationRecovery = make(chan struct{}, 1)
	}
	s.inviteRecoveryUsed = true
	s.registrationRecovery <- struct{}{}
}
