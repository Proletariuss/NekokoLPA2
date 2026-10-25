package swu

import (
	"bytes"
	"errors"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// AuthRequestDiagnostic describes the exact prepared outbound AUTH request.
// All strings are fixed enums; identities, realms, CA data and keys are absent.
type AuthRequestDiagnostic struct {
	Stage               string `json:"stage"`
	MessageID           uint32 `json:"message_id"`
	PayloadTypes        []int  `json:"payload_types"`
	NotifyTypes         []int  `json:"notify_types"`
	IDiTypes            []int  `json:"idi_types"`
	IDrTypes            []int  `json:"idr_types"`
	IDiAnonymous        bool   `json:"idi_anonymous"`
	IDrIsAPN            bool   `json:"idr_is_apn"`
	CertReqCount        int    `json:"certreq_count"`
	CertReqEncodings    []int  `json:"certreq_encodings"`
	CertReqCAHashCount  int    `json:"certreq_ca_hash_count"`
	EAPCodes            []int  `json:"eap_codes"`
	EAPTypes            []int  `json:"eap_types"`
	CertificateRequired bool   `json:"certificate_required"`
	EAPOnlyOffered      bool   `json:"eap_only_offered"`
	Fragmented          bool   `json:"fragmented"`
	PacketCount         int    `json:"packet_count"`
	SendState           string `json:"send_state"`
}

// Freeze AUTH payload bodies once. Encryption, fragmentation estimation and
// diagnostics then consume identical bytes even for a stateful Encode method.
// This is scoped to AUTH and does not change retransmission or other exchanges.
func freezeAuthRequest(payloads []ikev2.Payload) ([]ikev2.Payload, error) {
	frozen := make([]ikev2.Payload, 0, len(payloads))
	for _, p := range payloads {
		if p == nil {
			return nil, errors.New("nil IKE_AUTH payload")
		}
		body, err := p.Encode()
		if err != nil {
			return nil, err
		}
		if len(body) > 65535-ikev2.PAYLOAD_HEADER_LEN {
			return nil, errors.New("IKE_AUTH payload exceeds length limit")
		}
		frozen = append(frozen, &ikev2.RawPayload{PType: p.Type(), Data: append([]byte(nil), body...)})
	}
	return frozen, nil
}

func (s *Session) emitAuthRequestDiagnostic(payloads []ikev2.Payload, packets [][]byte) {
	if s.cfg == nil || s.cfg.OnAuthRequestDiagnostic == nil || s.authContextError() != nil || len(packets) == 0 {
		return
	}
	header, err := ikev2.DecodeHeader(packets[0])
	if err != nil || header.ExchangeType != ikev2.IKE_AUTH {
		return
	}
	d := AuthRequestDiagnostic{Stage: "eap", MessageID: header.MessageID,
		CertificateRequired: s.cfg.ValidateRemoteCertificate, Fragmented: header.NextPayload == ikev2.EncryptedFragment,
		PacketCount: min(len(packets), 255), SendState: "prepared"}
	// Read only the frozen bodies used for encryption, with length guards.
	// Unknown payloads remain visible by type and never block the request.
	for _, payload := range payloads {
		p, ok := payload.(*ikev2.RawPayload)
		if !ok {
			continue
		}
		d.PayloadTypes = appendAuthEnum(d.PayloadTypes, int(p.PType))
		body := p.Data
		switch p.PType {
		case ikev2.IDi, ikev2.IDr:
			if len(body) < 4 {
				continue
			}
			if p.PType == ikev2.IDi {
				d.Stage = "initial"
				d.IDiTypes = appendAuthEnum(d.IDiTypes, int(body[0]))
				if body[0] == ikev2.ID_RFC822_ADDR {
					at := bytes.IndexByte(body[4:], '@')
					d.IDiAnonymous = d.IDiAnonymous || (at == len("anonymous") && bytes.Equal(body[4:4+at], []byte("anonymous")))
				}
			} else {
				d.IDrTypes = appendAuthEnum(d.IDrTypes, int(body[0]))
				d.IDrIsAPN = d.IDrIsAPN || (body[0] == ikev2.ID_FQDN && len(body) > 4 && bytes.Equal(body[4:], []byte(s.cfg.APN)))
			}
		case ikev2.AUTH:
			if d.Stage != "initial" {
				d.Stage = "final"
			}
		case ikev2.N:
			if len(body) >= 4 {
				notify := int(body[2])<<8 | int(body[3])
				d.NotifyTypes = appendAuthEnum(d.NotifyTypes, notify)
				d.EAPOnlyOffered = d.EAPOnlyOffered || notify == int(ikev2.EAP_ONLY_AUTHENTICATION)
			}
		case ikev2.CERTREQ:
			d.CertReqCount = min(d.CertReqCount+1, 32)
			if len(body) >= 1 {
				d.CertReqEncodings = appendAuthEnum(d.CertReqEncodings, int(body[0]))
				if body[0] == ikev2.CertReqX509Signature && (len(body)-1)%20 == 0 {
					d.CertReqCAHashCount = min(d.CertReqCAHashCount+(len(body)-1)/20, 32)
				}
			}
		case ikev2.EAP:
			if len(body) >= 1 {
				d.EAPCodes = appendAuthEnum(d.EAPCodes, int(body[0]))
			}
			if len(body) >= 5 && (body[0] == eap.CodeRequest || body[0] == eap.CodeResponse) {
				d.EAPTypes = appendAuthEnum(d.EAPTypes, int(body[4]))
			}
		}
	}
	if s.authContextError() == nil {
		s.cfg.OnAuthRequestDiagnostic(d)
	}
}
