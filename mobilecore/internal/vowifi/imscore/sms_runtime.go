package imscore

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"

	"proletarius.local/core/internal/vowifi/messaging"
)

const imsSMSContentType = "application/vnd.3gpp.sms"

func (s *Service) sendIncomingRPAck(lifecycleCtx context.Context, lifecycleID uint64, target string, reference byte) {
	op, release, ok := s.acquireRuntimeLease(lifecycleCtx, lifecycleID)
	if !ok {
		return
	}
	defer release()
	operationCtx, stop := op.context(context.Background())
	defer stop()
	ctx, cancel := context.WithTimeout(operationCtx, 15*time.Second)
	defer cancel()
	_, err := s.sendSMSOnRegisteredTransport(ctx, target, "", []messaging.SMSPart{{
		RPMR: reference,
		Body: messaging.BuildRPAck(reference),
	}})
	if err != nil {
		logger.Warn("IMS RP-ACK send failed", logger.String("target", target), logger.Int("reference", int(reference)), logger.String("error", err.Error()))
		return
	}
	logger.Info("IMS RP-ACK sent", logger.String("target", target), logger.Int("reference", int(reference)))
}

func (s *Service) sendSMSOnRegisteredTransport(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	if len(parts) == 0 {
		return messaging.SendOutcome{}, fmt.Errorf("imscore: no SMS parts")
	}
	s.messageMu.Lock()
	defer s.messageMu.Unlock()
	messageID := uuid.NewString()
	for i, part := range parts {
		s.messageCSeq++
		if s.messageCSeq == 0 {
			s.messageCSeq = 1
		}
		callID := uuid.NewString()
		payload, err := s.buildSMSMessage(peer, callID, s.messageCSeq, part.Body)
		if err != nil {
			return messaging.SendOutcome{}, err
		}
		responses, unsubscribe, err := s.transportRuntime.subscribeResponses(callID)
		if err != nil {
			return messaging.SendOutcome{}, err
		}
		if err := s.transportRuntime.enqueueWrite(ctx, payload); err != nil {
			unsubscribe()
			return messaging.SendOutcome{}, fmt.Errorf("imscore: send SMS part %d: %w", i+1, err)
		}
		code, err := waitFinalSIPResponse(ctx, responses)
		unsubscribe()
		if err != nil {
			return messaging.SendOutcome{}, fmt.Errorf("imscore: SMS part %d response: %w", i+1, err)
		}
		if code < 200 || code >= 300 {
			return messaging.SendOutcome{}, fmt.Errorf("imscore: SMS part %d rejected with SIP %d", i+1, code)
		}
	}
	return messaging.SendOutcome{MessageID: messageID, PartsTotal: len(parts), DeliveryState: "accepted"}, nil
}

func waitFinalSIPResponse(ctx context.Context, responses <-chan *sip.Response) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-timer.C:
			return 0, fmt.Errorf("timeout")
		case response, ok := <-responses:
			if !ok {
				return 0, fmt.Errorf("transport closed")
			}
			if response != nil && response.StatusCode >= 200 {
				return response.StatusCode, nil
			}
		}
	}
}

func (s *Service) buildSMSMessage(peer, callID string, cseq uint32, body []byte) ([]byte, error) {
	target := strings.TrimSpace(peer)
	if target == "" {
		return nil, fmt.Errorf("imscore: SMSC target is required")
	}
	if !strings.HasPrefix(strings.ToLower(target), "sip:") && !strings.HasPrefix(strings.ToLower(target), "tel:") {
		target = "tel:" + target
	}
	uri := sip.Uri{}
	if err := sip.ParseUri(target, &uri); err != nil {
		return nil, fmt.Errorf("imscore: invalid SMSC target: %w", err)
	}
	localPort := s.transportRuntime.policy.LocalPortC
	req := sip.NewRequest(sip.MESSAGE, uri)
	req.AppendHeader(sip.NewHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", strings.ToUpper(registerTransportName(s.cfg, "")), formatRegisterViaHost(s.cfg.LocalIP, localPort), sip.GenerateBranchN(16))))
	req.AppendHeader(sip.NewHeader("From", "<"+s.cfg.PublicURI+">;tag="+sip.GenerateTagN(16)))
	req.AppendHeader(sip.NewHeader("To", "<"+target+">"))
	req.AppendHeader(sip.NewHeader("Call-ID", callID))
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d MESSAGE", cseq)))
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	req.AppendHeader(sip.NewHeader("Route", "<sip:"+effectiveRouteAddr(s.cfg)+";lr>"))
	if s.verifyHeader != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", s.verifyHeader))
		req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
		req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
	}
	req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+s.cfg.PublicURI+">"))
	if pani := effectivePANI(s.cfg.Template); pani != "" {
		req.AppendHeader(sip.NewHeader("P-Access-Network-Info", pani))
	}
	req.AppendHeader(sip.NewHeader("Content-Type", imsSMSContentType))
	req.SetBody(body)
	req.SetDestination(effectiveTransportAddr(s.cfg))
	req.SetTransport(strings.ToUpper(registerTransportName(s.cfg, "")))
	ensureSIPStreamFraming(req)
	return []byte(req.String()), nil
}

func waitSIPResponse(ctx context.Context, inbound <-chan []byte, callID string) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	var pending []byte
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-timer.C:
			return 0, fmt.Errorf("timeout")
		case chunk, ok := <-inbound:
			if !ok {
				return 0, fmt.Errorf("transport closed")
			}
			pending = append(pending, chunk...)
			for {
				head := bytes.Index(pending, []byte("\r\n\r\n"))
				if head < 0 {
					break
				}
				frameEnd := head + 4
				for _, line := range strings.Split(string(pending[:head]), "\r\n") {
					if strings.HasPrefix(strings.ToLower(line), "content-length:") {
						n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "content-length:")))
						frameEnd += n
					}
				}
				if len(pending) < frameEnd {
					break
				}
				frame := string(pending[:frameEnd])
				pending = pending[frameEnd:]
				if !strings.Contains(strings.ToLower(frame), "call-id: "+strings.ToLower(callID)) {
					continue
				}
				first := strings.Fields(strings.SplitN(frame, "\r\n", 2)[0])
				if len(first) >= 2 {
					code, err := strconv.Atoi(first[1])
					if err == nil {
						return code, nil
					}
				}
			}
		}
	}
}
