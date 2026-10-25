package swu

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
)

// Public issuer retrieved from the official CA distribution URL:
// https://cacerts.digicert.com/DigiCertG2TLSEURSA4096SHA3842022CA1.crt
// It is path-building material only, never an application trust anchor.
//
//go:embed certificates/digicert-g2-tls-eu-rsa4096-sha384-2022-ca1.pem
var threeUKIssuerPEM []byte

// ThreeUKCertificateIntermediates returns fresh DER copies of the public issuer
// observed for the Three UK ePDG. Callers explicitly select the carrier policy;
// this function does not enable any policy or modify the platform trust store.
func ThreeUKCertificateIntermediates() [][]byte {
	block, rest := pem.Decode(threeUKIssuerPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil
	}
	digest := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(digest[:]) != "a4adfc2917bb1451d312371d441acdb686107fbc0b3156d5570e99e1121974fa" {
		return nil
	}
	return [][]byte{append([]byte(nil), block.Bytes...)}
}
