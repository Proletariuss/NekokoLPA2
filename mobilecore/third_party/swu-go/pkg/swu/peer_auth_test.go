package swu

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	corecrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

type peerFixture struct {
	s     *Session
	id    *ikev2.EncryptedPayloadID
	certs []*ikev2.EncryptedPayloadCert
	key   *ecdsa.PrivateKey
	now   time.Time
}

func newPeerFixture(t *testing.T, mutate func(*x509.Certificate)) peerFixture {
	t.Helper()
	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "epdg.example.test"}, DNSNames: []string{"epdg.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 17}}}
	if mutate != nil {
		mutate(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	id := &ikev2.EncryptedPayloadID{IDType: ikev2.ID_FQDN, IDData: []byte("epdg.example.test"), Reserved: [3]byte{0x11, 0x22, 0x33}}
	idBody, _ := id.Encode()
	s := &Session{cfg: &Config{EpDGAddr: "epdg.example.test", CertificateRoots: roots, ValidateRemoteCertificate: true}, PRFAlg: corecrypto.PRF_HMAC_SHA2_256, Keys: &ikev2.IKESAKeys{SK_pr: bytes.Repeat([]byte{0x31}, 32)}, ni: bytes.Repeat([]byte{0x72}, 32), ikeInitResponse: []byte("exact responder IKE_SA_INIT bytes"), responderIdentityBody: idBody, Logger: zap.NewNop()}
	return peerFixture{s: s, id: id, key: key, now: now, certs: []*ikev2.EncryptedPayloadCert{{Encoding: 4, Data: der}, {Encoding: 4, Data: rootDER}}}
}

func (f peerFixture) initial(t *testing.T) []ikev2.Payload {
	t.Helper()
	signed, err := f.s.responderSignedOctets()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}})
	if err != nil {
		t.Fatal(err)
	}
	auth := &ikev2.EncryptedPayloadAuth{AuthMethod: 14, AuthData: append(append([]byte{byte(len(der))}, der...), sig...)}
	out := []ikev2.Payload{f.id, auth}
	for _, cert := range f.certs {
		out = append(out, cert)
	}
	return out
}

func TestResponderCertificateAndTranscript(t *testing.T) {
	for _, name := range []string{"valid", "signature", "transcript", "nonce", "idr", "skpr", "wrong_hostname", "unknown_ca", "system_unknown_ca", "certificate_forgery", "missing_cert", "missing_auth", "duplicate_auth", "duplicate_id", "duplicate_cert", "url_cert", "excessive_chain", "malformed_cert", "unrelated_chain", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newPeerFixture(t, nil)
			payloads := f.initial(t)
			switch name {
			case "signature":
				payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[len(payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData)-1] ^= 1
			case "transcript":
				f.s.ikeInitResponse[0] ^= 1
			case "nonce":
				f.s.ni[0] ^= 1
			case "idr":
				f.id.Reserved[0] ^= 1
			case "skpr":
				f.s.Keys.SK_pr[0] ^= 1
			case "wrong_hostname":
				f.s.cfg.RemoteIdentifier = "other.example.test"
			case "unknown_ca":
				f.s.cfg.CertificateRoots = x509.NewCertPool()
			case "system_unknown_ca":
				f.s.cfg.CertificateRoots = nil
			case "certificate_forgery":
				f.certs[0].Data[len(f.certs[0].Data)-1] ^= 1
			case "missing_cert":
				payloads = payloads[:2]
			case "missing_auth":
				payloads = append(payloads[:1], payloads[2:]...)
			case "duplicate_auth":
				payloads = append(payloads, payloads[1])
			case "duplicate_id":
				payloads = append(payloads, f.id)
			case "duplicate_cert":
				payloads = append(payloads, f.certs[0])
			case "url_cert":
				f.certs[0].Encoding = 12
			case "excessive_chain":
				for i := 0; i < 8; i++ {
					payloads = append(payloads, f.certs[0])
				}
			case "malformed_cert":
				f.certs[0].Data = []byte{0x30, 0}
			case "unrelated_chain":
				other := newPeerFixture(t, nil)
				payloads = append(payloads, other.certs[1])
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				f.s.ctx = ctx
			}
			err := f.s.checkResponderInitial(payloads)
			if name == "valid" {
				if err != nil || !f.s.responderCertificateVerified {
					t.Fatalf("valid cert AUTH: %v", err)
				}
				return
			}
			if err == nil || f.s.responderCertificateVerified || f.s.responderInitialChecked {
				t.Fatalf("invalid auth accepted: %v", err)
			}
			if name == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrPeerAuthentication) {
				t.Fatalf("missing permanent classification: %v", err)
			}
		})
	}
}

func TestResponderCertificateValidityAndUsage(t *testing.T) {
	cases := map[string]func(*x509.Certificate){
		"expired":          func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		"not_yet_valid":    func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) },
		"wrong_san":        func(c *x509.Certificate) { c.DNSNames = []string{"other.example.test"} },
		"cn_only":          func(c *x509.Certificate) { c.DNSNames = nil },
		"no_signing_usage": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		"wrong_eku": func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = nil
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		},
		"tls_only_eku": func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = nil
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		},
		"legacy_nonstandard_eku": func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 8, 2, 2}} },
		"ca_leaf":                func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true },
		"unknown_critical": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPeerFixture(t, mutate)
			if err := f.s.checkResponderInitial(f.initial(t)); !errors.Is(err, ErrPeerAuthentication) {
				t.Fatalf("bad certificate accepted: %v", err)
			}
		})
	}
	for _, eku := range []bool{false, true} {
		f := newPeerFixture(t, func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = nil
			if eku {
				c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 17}}
			}
		})
		if err := f.s.checkResponderInitial(f.initial(t)); err != nil {
			t.Fatalf("valid IKE certificate: %v", err)
		}
	}
}

func TestResponderCertificateContentCommitmentUsage(t *testing.T) {
	f := newPeerFixture(t, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageContentCommitment })
	if err := f.s.checkResponderInitial(f.initial(t)); err != nil {
		t.Fatalf("RFC4945 nonRepudiation usage rejected: %v", err)
	}
}

func finalPeerAUTH(t *testing.T, s *Session) *ikev2.EncryptedPayloadAuth {
	t.Helper()
	// Build independently from protocol pieces to detect order/direction bugs.
	idMAC := hmac.New(sha256.New, s.Keys.SK_pr)
	idMAC.Write(s.responderIdentityBody)
	keyMAC := hmac.New(sha256.New, s.MSK)
	keyMAC.Write([]byte("Key Pad for IKEv2"))
	authMAC := hmac.New(sha256.New, keyMAC.Sum(nil))
	authMAC.Write(s.ikeInitResponse)
	authMAC.Write(s.ni)
	authMAC.Write(idMAC.Sum(nil))
	return &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey, AuthData: authMAC.Sum(nil)}
}

func TestEAPOnlyStillRequiresMutualFinalAUTH(t *testing.T) {
	for _, mode := range []string{"eap_only", "certificate"} {
		for _, test := range []string{"valid", "missing_auth", "bad_auth", "duplicate_auth", "signature_not_msk", "msk", "nonce", "transcript", "idr", "not_success", "short_msk", "cancelled"} {
			t.Run(mode+"/"+test, func(t *testing.T) {
				f := newPeerFixture(t, nil)
				initial := f.initial(t)
				if mode == "eap_only" {
					f.s.cfg.ValidateRemoteCertificate = false
					initial = []ikev2.Payload{f.id}
				}
				if err := f.s.checkResponderInitial(initial); err != nil {
					t.Fatal(err)
				}
				f.s.MSK = bytes.Repeat([]byte{0xab}, 64)
				f.s.eapSuccessReceived = true
				auth := finalPeerAUTH(t, f.s)
				payloads := []ikev2.Payload{auth}
				switch test {
				case "missing_auth":
					payloads = nil
				case "bad_auth":
					auth.AuthData[0] ^= 1
				case "duplicate_auth":
					payloads = append(payloads, auth)
				case "signature_not_msk":
					auth.AuthMethod = 14
				case "msk":
					f.s.MSK[0] ^= 1
				case "nonce":
					f.s.ni[0] ^= 1
				case "transcript":
					f.s.ikeInitResponse[0] ^= 1
				case "idr":
					f.id.Reserved[0] ^= 1
					payloads = append(payloads, f.id)
				case "not_success":
					f.s.eapSuccessReceived = false
				case "short_msk":
					f.s.MSK = f.s.MSK[:32]
				case "cancelled":
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					f.s.ctx = ctx
				}
				err := f.s.verifyResponderFinal(payloads)
				if test == "valid" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("bad final AUTH accepted")
				}
			})
		}
	}
}

func TestEAPOnlyDoesNotDisableCertificateChecks(t *testing.T) {
	f := newPeerFixture(t, nil)
	f.s.cfg.ValidateRemoteCertificate = false
	payloads := f.initial(t)
	payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[4] ^= 1
	if err := f.s.checkResponderInitial(payloads); !errors.Is(err, ErrPeerAuthentication) {
		t.Fatal("false configuration skipped invalid certificate AUTH")
	}
	f = newPeerFixture(t, nil)
	if err := f.s.checkResponderInitial([]ikev2.Payload{f.id}); !errors.Is(err, ErrPeerAuthentication) {
		t.Fatal("required certificate omitted")
	}
	f = newPeerFixture(t, nil)
	f.s.cfg.ValidateRemoteCertificate = false
	if err := f.s.checkResponderInitial(nil); !errors.Is(err, ErrPeerAuthentication) {
		t.Fatal("EAP-only omitted mandatory IDr")
	}
	if _, err := f.s.handleEAP([]byte{eap.CodeSuccess, 1, 0, 4}); !errors.Is(err, ErrPeerAuthentication) {
		t.Fatal("unauthenticated EAP Success accepted")
	}
}

func TestRejectedFinalAUTHDoesNotInstallSAOrPersistTicket(t *testing.T) {
	f := newPeerFixture(t, nil)
	if err := f.s.checkResponderInitial(f.initial(t)); err != nil {
		t.Fatal(err)
	}
	f.s.MSK = bytes.Repeat([]byte{0x42}, 64)
	f.s.eapSuccessReceived = true
	wire := envelopeSession(t, true)
	f.s.SPIi = wire.SPIi
	f.s.SPIr = wire.SPIr
	f.s.EncAlg = wire.EncAlg
	f.s.IntegAlg = wire.IntegAlg
	f.s.ikeIsAEAD = true
	f.s.ikeEncrID = wire.ikeEncrID
	f.s.Keys.SK_ei = wire.Keys.SK_ei
	f.s.Keys.SK_er = wire.Keys.SK_er
	f.s.Keys.SK_ai = wire.Keys.SK_ai
	f.s.Keys.SK_ar = wire.Keys.SK_ar
	f.s.cfg.OnTicketUpdate = func([]byte, []byte) { t.Fatal("unauthenticated ticket persisted") }
	payloads := []ikev2.Payload{&ikev2.EncryptedPayloadAuth{AuthMethod: 2, AuthData: []byte("forged")}, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.TICKET_OPAQUE, NotifyData: []byte("ticket")}, &ikev2.EncryptedPayloadSA{}}
	packet, err := f.s.encryptAndWrapWithMsgID(payloads, ikev2.IKE_AUTH, 4, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.handleIKEAuthFinalResp(packet); !errors.Is(err, ErrPeerAuthentication) {
		t.Fatalf("wrong error: %v", err)
	}
	if f.s.ChildSAIn != nil || f.s.ChildSAOut != nil {
		t.Fatal("unauthenticated SA installed")
	}
}

func TestEncryptedPayloadParserRejectsMalformedChains(t *testing.T) {
	s := &Session{}
	for _, body := range [][]byte{{0, 0, 0, 0}, {0, 0, 0, 3}, {0, 0, 0}, {byte(ikev2.AUTH), 0, 0, 4}, {0, 0, 0, 4, 0}} {
		if _, err := s.parsePayloads(body, ikev2.CERT); err == nil {
			t.Fatalf("accepted malformed chain %x", body)
		}
	}
}
