package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// dispatchAuthResponse is scoped to a currently pending IKE_AUTH request. All
// metadata and payloads originate from the same integrity-checked response.
func (s *Session) dispatchAuthResponse(msgID uint32, data []byte) bool {
	return s.taskMgr.handleAuthResponse(msgID, func(fragments *fragmentBuffer) (RequestResult, bool, error) {
		header, err := s.validateEncryptedHeader(data)
		if err != nil {
			return RequestResult{}, false, err
		}
		if header.MessageID != msgID || header.ExchangeType != ikev2.IKE_AUTH ||
			header.Flags&ikev2.FlagResponse == 0 || header.Flags&ikev2.FlagInitiator != 0 {
			return RequestResult{}, false, errors.New("invalid IKE_AUTH response header")
		}
		var payloads []ikev2.Payload
		if header.NextPayload == ikev2.EncryptedFragment {
			plain, number, total, id, err := s.decryptSKF(data)
			if err != nil {
				return RequestResult{}, false, err
			}
			complete, err := fragments.addFragment(id, number, total, plain, ikev2.PayloadType(data[ikev2.IKE_HEADER_LEN]))
			if err != nil || !complete {
				return RequestResult{}, false, err
			}
			plain, first, err := fragments.reassemble(id)
			if err != nil {
				return RequestResult{}, false, err
			}
			payloads, err = s.parsePayloads(plain, first)
			if err != nil {
				return RequestResult{}, false, err
			}
		} else {
			_, payloads, err = s.decryptAndParse(data)
			if err != nil {
				return RequestResult{}, false, err
			}
		}
		return RequestResult{authPayloads: payloads, authMessageID: msgID, authParsed: true}, true, nil
	})
}

func (s *Session) sendAuthWithRetry(payloads []ikev2.Payload) (uint32, []ikev2.Payload, error) {
	result, err := s.sendEncryptedRequestWithRetry(payloads, ikev2.IKE_AUTH)
	if err != nil {
		return 0, nil, err
	}
	if err := s.authContextError(); err != nil {
		return 0, nil, err
	}
	if !result.authParsed {
		return 0, nil, errors.New("IKE_AUTH response was not authenticated and parsed")
	}
	return result.authMessageID, result.authPayloads, nil
}
