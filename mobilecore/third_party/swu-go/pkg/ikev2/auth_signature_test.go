package ikev2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func digitalAUTH(t *testing.T, id pkix.AlgorithmIdentifier, sig []byte) *EncryptedPayloadAuth {
	t.Helper()
	der, err := asn1.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	return &EncryptedPayloadAuth{AuthMethod: 14, AuthData: append(append([]byte{byte(len(der))}, der...), sig...)}
}

func TestResponderSignatureRSAAndPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	signed := []byte("RealMessage2 | NonceI | prf(SK_pr, IDr)")
	sha1sum := sha1.Sum(signed)
	legacy, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sha1sum[:])
	if err != nil {
		t.Fatal(err)
	}
	legacyAuth := &EncryptedPayloadAuth{AuthMethod: AuthMethodRSASig, AuthData: legacy}
	if err := VerifyAuthSignature(cert, legacyAuth, signed); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		h := hash.New()
		h.Write(signed)
		digest := h.Sum(nil)
		index := map[crypto.Hash]int{crypto.SHA256: 1, crypto.SHA384: 2, crypto.SHA512: 3}[hash]
		for _, pss := range []bool{false, true} {
			var auth *EncryptedPayloadAuth
			if pss {
				sig, err := rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
				if err != nil {
					t.Fatal(err)
				}
				hashID := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, index}, Parameters: asn1.RawValue{FullBytes: []byte{5, 0}}}
				hashDER, _ := asn1.Marshal(hashID)
				params, _ := asn1.Marshal(struct {
					Hash pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
					MGF  pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
					Salt int                      `asn1:"explicit,tag:2"`
				}{hashID, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, Parameters: asn1.RawValue{FullBytes: hashDER}}, hash.Size()})
				auth = digitalAUTH(t, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, Parameters: asn1.RawValue{FullBytes: params}}, sig)
			} else {
				sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
				if err != nil {
					t.Fatal(err)
				}
				auth = digitalAUTH(t, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10 + index}, Parameters: asn1.RawValue{FullBytes: []byte{5, 0}}}, sig)
			}
			if err := VerifyAuthSignature(cert, auth, signed); err != nil {
				t.Fatalf("%v PSS=%v: %v", hash, pss, err)
			}
			if err := VerifyAuthSignature(cert, auth, append(signed, 0)); err == nil {
				t.Fatal("altered transcript accepted")
			}
			auth.AuthData[len(auth.AuthData)-1] ^= 1
			if err := VerifyAuthSignature(cert, auth, signed); err == nil {
				t.Fatal("forged signature accepted")
			}
		}
	}
}

func TestResponderSignatureECDSA(t *testing.T) {
	signed := []byte("signed IKE transcript")
	for _, method := range []uint8{9, 10, 11} {
		curve := map[uint8]elliptic.Curve{9: elliptic.P256(), 10: elliptic.P384(), 11: elliptic.P521()}[method]
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{PublicKey: &key.PublicKey}
		var digest []byte
		switch method {
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
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			t.Fatal(err)
		}
		width := (curve.Params().BitSize + 7) / 8
		sig := make([]byte, 2*width)
		r.FillBytes(sig[:width])
		s.FillBytes(sig[width:])
		auth := &EncryptedPayloadAuth{AuthMethod: method, AuthData: sig}
		if err := VerifyAuthSignature(cert, auth, signed); err != nil {
			t.Fatal(err)
		}
		sig[0] ^= 1
		if err := VerifyAuthSignature(cert, auth, signed); err == nil {
			t.Fatal("forged ECDSA accepted")
		}
		asn1Sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			t.Fatal(err)
		}
		auth = digitalAUTH(t, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, int(method) - 7}}, asn1Sig)
		if err := VerifyAuthSignature(cert, auth, signed); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignatureRejectsMalformedAlgorithms(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	for _, data := range [][]byte{nil, {0}, {1, 0x30}, {0xff, 0x30}, {2, 0x30, 0, 1}, {3, 0x30, 0, 0, 1}} {
		if err := VerifyAuthSignature(cert, &EncryptedPayloadAuth{AuthMethod: 14, AuthData: data}, []byte("signed")); err == nil {
			t.Fatalf("accepted %x", data)
		}
	}
	for _, id := range []pkix.AlgorithmIdentifier{
		{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, Parameters: asn1.RawValue{FullBytes: []byte{5, 0}}},
		{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.RawValue{FullBytes: []byte{2, 1, 0}}},
		{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}},
	} {
		der, _ := asn1.Marshal(id)
		if _, err := authSignatureAlgorithm(der); err == nil {
			t.Fatal("invalid algorithm accepted")
		}
	}
	if err := VerifyAuthSignature(cert, &EncryptedPayloadAuth{AuthMethod: 2, AuthData: []byte{1}}, []byte("signed")); err == nil {
		t.Fatal("shared key treated as signature")
	}
}

func TestIDBodyPreservesReservedTranscriptBytes(t *testing.T) {
	body := []byte{ID_FQDN, 0xaa, 0xbb, 0xcc, 'e', 'p', 'd', 'g'}
	id, err := DecodePayloadID(body, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := id.Encode()
	if err != nil || string(encoded) != string(body) {
		t.Fatal("IDr signed octets changed")
	}
}
