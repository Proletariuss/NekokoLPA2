package ikev2

import "errors"

const CertReqX509Signature uint8 = 4

// EncryptedPayloadCertReq requests X.509 signature certificates (RFC 7296
// section 3.7). CertificateAuthorities contains concatenated SHA-1 hashes of
// CA public keys, never CA distinguished names or certificate DER. Empty data
// requests any certificate; it does not add a trust anchor (RFC 4945 3.2.7.2).
type EncryptedPayloadCertReq struct {
	Encoding               uint8
	CertificateAuthorities []byte
}

func (p *EncryptedPayloadCertReq) Type() PayloadType { return CERTREQ }

func validCertReq(encoding uint8, authorities []byte) bool {
	return encoding == CertReqX509Signature && len(authorities)%20 == 0 && len(authorities) <= 65530
}

func (p *EncryptedPayloadCertReq) Encode() ([]byte, error) {
	if !validCertReq(p.Encoding, p.CertificateAuthorities) {
		return nil, errors.New("invalid X.509 CERTREQ encoding or CA hash length")
	}
	return append([]byte{p.Encoding}, p.CertificateAuthorities...), nil
}

func DecodePayloadCertReq(data []byte) (*EncryptedPayloadCertReq, error) {
	if len(data) < 1 || !validCertReq(data[0], data[1:]) {
		return nil, errors.New("invalid X.509 CERTREQ encoding or CA hash length")
	}
	return &EncryptedPayloadCertReq{Encoding: data[0], CertificateAuthorities: append([]byte(nil), data[1:]...)}, nil
}
