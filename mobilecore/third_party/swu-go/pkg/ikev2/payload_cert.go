package ikev2

import "errors"

// EncryptedPayloadCert is RFC 7296 section 3.6. Only inline X.509 DER is
// accepted for authentication; URL/hash certificate retrieval is not used.
type EncryptedPayloadCert struct {
	Encoding uint8
	Data     []byte
}

func (p *EncryptedPayloadCert) Type() PayloadType { return CERT }
func (p *EncryptedPayloadCert) Encode() ([]byte, error) {
	return append([]byte{p.Encoding}, p.Data...), nil
}
func DecodePayloadCert(data []byte) (*EncryptedPayloadCert, error) {
	if len(data) < 2 || len(data) > 65531 {
		return nil, errors.New("invalid CERT length")
	}
	return &EncryptedPayloadCert{Encoding: data[0], Data: append([]byte(nil), data[1:]...)}, nil
}
