package ikev2

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// VerifyAuthSignature verifies the actual IKE SignedOctets, not the signature
// on the certificate. RFC 7427 algorithm identifiers are parsed strictly;
// unknown algorithms and parameters fail closed.
func VerifyAuthSignature(cert *x509.Certificate, auth *EncryptedPayloadAuth, signed []byte) error {
	if cert == nil || auth == nil || len(signed) == 0 || len(auth.AuthData) == 0 {
		return errors.New("missing responder signature input")
	}
	switch auth.AuthMethod {
	case AuthMethodRSASig:
		return cert.CheckSignature(x509.SHA1WithRSA, signed, auth.AuthData)
	case 9, 10, 11: // RFC 4754: fixed-width r || s, not ASN.1.
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ECDSA AUTH requires an EC certificate")
		}
		width := map[uint8]int{9: 32, 10: 48, 11: 66}[auth.AuthMethod]
		bits := map[uint8]int{9: 256, 10: 384, 11: 521}[auth.AuthMethod]
		if pub.Curve.Params().BitSize != bits || len(auth.AuthData) != 2*width {
			return errors.New("ECDSA AUTH curve or signature length mismatch")
		}
		var digest []byte
		switch auth.AuthMethod {
		case 9:
			h := sha256.Sum256(signed)
			digest = h[:]
		case 10:
			h := sha512.Sum384(signed)
			digest = h[:]
		case 11:
			h := sha512.Sum512(signed)
			digest = h[:]
		}
		if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(auth.AuthData[:width]), new(big.Int).SetBytes(auth.AuthData[width:])) {
			return errors.New("invalid ECDSA AUTH signature")
		}
		return nil
	case 14:
		n := int(auth.AuthData[0])
		if n == 0 || 1+n >= len(auth.AuthData) {
			return errors.New("invalid digital-signature AlgorithmIdentifier length")
		}
		alg, err := authSignatureAlgorithm(auth.AuthData[1 : 1+n])
		if err != nil {
			return err
		}
		return cert.CheckSignature(alg, signed, auth.AuthData[1+n:])
	default:
		return fmt.Errorf("unsupported responder signature method %d", auth.AuthMethod)
	}
}

func authSignatureAlgorithm(der []byte) (x509.SignatureAlgorithm, error) {
	var id pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(der, &id)
	if err != nil || len(rest) != 0 {
		return 0, errors.New("malformed signature AlgorithmIdentifier")
	}
	absent := len(id.Parameters.FullBytes) == 0
	null := string(id.Parameters.FullBytes) == "\x05\x00"
	switch id.Algorithm.String() {
	case "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13":
		if !absent && !null {
			return 0, errors.New("invalid RSA signature parameters")
		}
		return map[string]x509.SignatureAlgorithm{
			"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
			"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
			"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
		}[id.Algorithm.String()], nil
	case "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4":
		if !absent {
			return 0, errors.New("ECDSA signature parameters must be absent")
		}
		return map[string]x509.SignatureAlgorithm{
			"1.2.840.10045.4.3.2": x509.ECDSAWithSHA256,
			"1.2.840.10045.4.3.3": x509.ECDSAWithSHA384,
			"1.2.840.10045.4.3.4": x509.ECDSAWithSHA512,
		}[id.Algorithm.String()], nil
	case "1.2.840.113549.1.1.10":
		var p struct {
			Hash       pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
			MGF        pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
			SaltLength int                      `asn1:"explicit,tag:2"`
			Trailer    int                      `asn1:"optional,explicit,tag:3,default:1"`
		}
		rest, err = asn1.Unmarshal(id.Parameters.FullBytes, &p)
		if err != nil || len(rest) != 0 || p.Trailer != 1 || p.MGF.Algorithm.String() != "1.2.840.113549.1.1.8" {
			return 0, errors.New("unsupported RSA-PSS parameters")
		}
		var mgfHash pkix.AlgorithmIdentifier
		rest, err = asn1.Unmarshal(p.MGF.Parameters.FullBytes, &mgfHash)
		validHashParams := func(a pkix.AlgorithmIdentifier) bool {
			return len(a.Parameters.FullBytes) == 0 || string(a.Parameters.FullBytes) == "\x05\x00"
		}
		if err != nil || len(rest) != 0 || !mgfHash.Algorithm.Equal(p.Hash.Algorithm) || !validHashParams(p.Hash) || !validHashParams(mgfHash) {
			return 0, errors.New("RSA-PSS MGF hash mismatch")
		}
		switch p.Hash.Algorithm.String() {
		case "2.16.840.1.101.3.4.2.1":
			if p.SaltLength == 32 {
				return x509.SHA256WithRSAPSS, nil
			}
		case "2.16.840.1.101.3.4.2.2":
			if p.SaltLength == 48 {
				return x509.SHA384WithRSAPSS, nil
			}
		case "2.16.840.1.101.3.4.2.3":
			if p.SaltLength == 64 {
				return x509.SHA512WithRSAPSS, nil
			}
		}
	}
	return 0, errors.New("unsupported signature algorithm or parameters")
}
