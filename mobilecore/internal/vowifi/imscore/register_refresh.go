package imscore

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"
)

// RefreshRegistration renews the existing binding over its authenticated
// connection. It never replaces the transport, listener, media or call dialog.
// A registrar requiring a new security association must go through the normal
// full authentication path; a refresh must not silently downgrade security.
func (s *Service) RefreshRegistration(ctx context.Context) (int, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return 0, fmt.Errorf("IMS transport unavailable for registration refresh")
	}
	defer release()
	if op.runtime == nil || !op.runtime.Healthy() {
		return 0, fmt.Errorf("IMS transport unavailable for registration refresh")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	s.stateMu.RLock()
	previous := s.registerRequest
	if previous != nil {
		previous = previous.Clone()
	}
	s.stateMu.RUnlock()
	if previous == nil {
		return 0, fmt.Errorf("IMS registration refresh has no retained binding")
	}
	request, err := buildRegistrationRefresh(s.cfg, previous, op.runtime, op.ipsec)
	if err != nil {
		return 0, err
	}
	retried500 := false
	for round := 0; round < 3; round++ {
		// Save every used CSeq, including failures, so a retry never goes back.
		s.stateMu.Lock()
		s.registerRequest = request.Clone()
		s.stateMu.Unlock()
		response, err := op.runtime.exchangeRegistrationRefresh(operationCtx, request)
		if err != nil {
			return 0, err
		}
		if response.StatusCode == sip.StatusOK {
			if responseChangesSecurity(response, op.runtime.cfg.SecurityVerify) {
				return 0, fmt.Errorf("IMS refresh requires new security association")
			}
			// Do not accept a zero-expiry binding as a successful renewal.
			if h := response.GetHeader("Expires"); h != nil && strings.TrimSpace(h.Value()) == "0" {
				return 0, fmt.Errorf("IMS registrar removed the registration binding")
			}
			expires := effectiveRegisterExpiry(s.cfg)
			if h := response.GetHeader("Expires"); h != nil {
				value, parseErr := strconv.Atoi(strings.TrimSpace(h.Value()))
				if parseErr != nil || value <= 0 {
					return 0, fmt.Errorf("IMS registrar returned invalid registration lifetime")
				}
				expires = value
			}
			if granted := contactGrantedExpiry(responseHeaderStrings(response, "Contact")); granted > 0 && granted < expires {
				expires = granted
			}
			if matched, err := matchingContactExpiry(request, response); err != nil {
				return 0, err
			} else if matched > 0 && matched < expires {
				expires = matched
			}
			s.stateMu.Lock()
			if !s.closing && s.transportRuntime == op.runtime && operationCtx.Err() == nil {
				s.expiresSeconds = expires
				s.registered = true
			}
			s.stateMu.Unlock()
			return expires, operationCtx.Err()
		}
		if response.StatusCode != sip.StatusUnauthorized && response.StatusCode != sip.StatusProxyAuthRequired {
			if !retried500 && configuredReRegister500(s.cfg, sip.REGISTER, response.StatusCode) && !responseChangesSecurity(response, op.runtime.cfg.SecurityVerify) {
				retried500 = true
				if err := waitReRegisterRetry(operationCtx, response); err != nil {
					return 0, err
				}
				// Rebuild authorization from the live security context; never
				// replay a previous digest proof on a new transaction.
				request, err = buildRegistrationRefresh(s.cfg, request, op.runtime, op.ipsec)
				if err != nil {
					return 0, err
				}
				round-- // the single server-error retry is separate from AKA rounds
				continue
			}
			return 0, fmt.Errorf("IMS registration refresh rejected (SIP %d)", response.StatusCode)
		}
		if responseChangesSecurity(response, op.runtime.cfg.SecurityVerify) {
			return 0, fmt.Errorf("IMS refresh requires new security association")
		}
		challenge, err := selectDigestChallenge(s.cfg, response)
		if err != nil {
			return 0, err
		}
		result, authorization, err := computeAKAAuth(s.cfg, challenge, request)
		result.Zero()
		if err != nil {
			return 0, err
		}
		request, err = nextRegistrationRefresh(request, op.runtime)
		if err != nil {
			return 0, err
		}
		request.RemoveHeader("Authorization")
		request.RemoveHeader("Proxy-Authorization")
		if op.ipsec {
			authorization += ", integrity-protected=yes"
		}
		header := "Authorization"
		if response.StatusCode == sip.StatusProxyAuthRequired {
			header = "Proxy-Authorization"
		}
		request.AppendHeader(sip.NewHeader(header, authorization))
	}
	return 0, fmt.Errorf("IMS registration refresh authentication rounds exhausted")
}

// A successful REGISTER may include several old bindings. Zero on another
// device is harmless; zero on our own Contact explicitly removes this binding
// and must not be hidden by a positive global Expires or a different Contact.
func matchingContactExpiry(request *sip.Request, response *sip.Response) (int, error) {
	contact := request.Contact()
	if contact == nil {
		return 0, fmt.Errorf("IMS registration refresh has no valid Contact")
	}
	granted := 0
	for _, value := range responseHeaderStrings(response, "Contact") {
		for _, item := range splitAssociatedHeaderValues(value) {
			var address sip.Uri
			var params sip.HeaderParams
			if _, err := sip.ParseAddressValue(item, &address, &params); err != nil {
				continue
			}
			if !sameRegistrationContact(contact.Address, address) {
				continue
			}
			for _, param := range params {
				if !strings.EqualFold(param.K, "expires") {
					continue
				}
				seconds, err := strconv.Atoi(strings.TrimSpace(param.V))
				if err != nil || seconds <= 0 {
					return 0, fmt.Errorf("IMS registrar removed or invalidated the current Contact binding")
				}
				if granted == 0 || seconds < granted {
					granted = seconds
				}
			}
		}
	}
	return granted, nil
}

func sameRegistrationContact(first, second sip.Uri) bool {
	// Ignore decorative Contact parameters (+sip.instance/audio/etc.), but
	// distinguish different transport endpoints and case-sensitive SIP users.
	port := func(uri sip.Uri) int {
		if uri.Port != 0 {
			return uri.Port
		}
		if strings.EqualFold(uri.Scheme, "sips") {
			return 5061
		}
		return 5060
	}
	transport := func(uri sip.Uri) string {
		return strings.ToLower(uri.UriParams.GetOr("transport", "tcp"))
	}
	return first.User == second.User && strings.EqualFold(first.Host, second.Host) &&
		port(first) == port(second) && transport(first) == transport(second) &&
		strings.EqualFold(first.Scheme, second.Scheme)
}

// WithdrawRegistration blocks new SMS/calls after refresh failure but leaves
// an existing dialog controllable (mute, DTMF and hangup) until it ends.
func (s *Service) WithdrawRegistration() {
	s.stateMu.Lock()
	s.registered = false
	s.stateMu.Unlock()
}

func responseChangesSecurity(response *sip.Response, verify string) bool {
	for _, header := range response.GetHeaders("Security-Server") {
		// A challenge with Security-Server starts a fresh key/SA negotiation,
		// even when the advertised ports and SPI parameters happen to match.
		if response.StatusCode == sip.StatusUnauthorized || response.StatusCode == sip.StatusProxyAuthRequired {
			return true
		}
		if strings.TrimSpace(header.Value()) != strings.TrimSpace(verify) {
			return true
		}
	}
	return false
}

func nextRegistrationRefresh(previous *sip.Request, runtime *transportRuntime) (*sip.Request, error) {
	_, cseq, err := registerRequestIdentity(previous)
	if err != nil || cseq == ^uint32(0) {
		return nil, fmt.Errorf("IMS registration refresh invalid CSeq")
	}
	request := previous.Clone()
	request.RemoveHeader("Via")
	request.RemoveHeader("CSeq")
	request.PrependHeader(sip.NewHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(registerTransportName(runtime.cfg, "")), formatRegisterViaHost(runtime.cfg.LocalIP, runtime.policy.LocalPortC), sip.GenerateBranchN(16))))
	request.SetTransport(strings.ToUpper(registerTransportName(runtime.cfg, "")))
	request.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d REGISTER", cseq+1)))
	return request, nil
}

func buildRegistrationRefresh(cfg Config, previous *sip.Request, runtime *transportRuntime, protected bool) (*sip.Request, error) {
	request, err := nextRegistrationRefresh(previous, runtime)
	if err != nil {
		return nil, err
	}
	request.RemoveHeader("Authorization")
	request.RemoveHeader("Proxy-Authorization")
	request.RemoveHeader("Security-Client")
	request.RemoveHeader("Expires")
	request.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(effectiveRegisterExpiry(cfg))))
	if protected {
		request.AppendHeader(sip.NewHeader("Authorization", fmt.Sprintf(`Digest username="%s",realm="%s",uri="%s",nonce="",response="",integrity-protected=yes`, quoteSipParam(authorizationUsername(cfg)), quoteSipParam(cfg.Realm), quoteSipParam(request.Recipient.String()))))
	} else if strings.EqualFold(strings.TrimSpace(cfg.Template.InitialAuthorization), "eap_direct") {
		// EAP-direct carriers bind this proof to the live tunnel generation.
		authorization, err := buildInitialRegisterAuthorization(cfg, "eap_direct")
		if err != nil {
			return nil, err
		}
		request.AppendHeader(sip.NewHeader("Authorization", authorization))
	}
	return request, nil
}

func (rt *transportRuntime) exchangeRegistrationRefresh(ctx context.Context, request *sip.Request) (*sip.Response, error) {
	callID, cseq, err := registerRequestIdentity(request)
	if err != nil {
		return nil, err
	}
	responses, unsubscribe, err := rt.subscribeResponses(callID)
	if err != nil {
		return nil, err
	}
	defer unsubscribe()
	txCtx, cancel := context.WithTimeout(ctx, registerTransactionTimeout)
	defer cancel()
	ensureSIPStreamFraming(request)
	if err := rt.enqueueWrite(txCtx, []byte(request.String())); err != nil {
		return nil, err
	}
	for {
		select {
		case <-txCtx.Done():
			return nil, txCtx.Err()
		case response, ok := <-responses:
			if !ok {
				return nil, fmt.Errorf("IMS registration response stream closed")
			}
			if response == nil || response.CSeq() == nil || response.CSeq().SeqNo != cseq || response.CSeq().MethodName != sip.REGISTER {
				continue
			}
			if request.Via() == nil || response.Via() == nil || request.Via().Params.GetOr("branch", "") == "" || request.Via().Params.GetOr("branch", "") != response.Via().Params.GetOr("branch", "") {
				continue
			}
			if rt.cfg.ValidateRegisterResponse != nil {
				if err := rt.cfg.ValidateRegisterResponse(txCtx, []byte(response.String()), callID, cseq); err != nil {
					return nil, fmt.Errorf("IMS refresh response validation: %w", err)
				}
			}
			if response.StatusCode >= 200 {
				return response, nil
			}
		}
	}
}
