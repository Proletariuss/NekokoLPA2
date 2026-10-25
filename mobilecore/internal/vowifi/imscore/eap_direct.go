package imscore

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// EAPDirectAuth is the short-lived RES/RAND/AUTN tuple from the current,
// successfully verified SWu EAP-AKA exchange. It cannot be reconstructed by
// issuing another AKA request, and it is not persisted.
type EAPDirectAuth struct {
	RES  []byte
	RAND []byte
	AUTN []byte
}

func (value *EAPDirectAuth) clone() *EAPDirectAuth {
	if value == nil {
		return nil
	}
	return &EAPDirectAuth{
		RES:  append([]byte(nil), value.RES...),
		RAND: append([]byte(nil), value.RAND...),
		AUTN: append([]byte(nil), value.AUTN...),
	}
}

func buildInitialRegisterAuthorization(cfg Config, mode string) (string, error) {
	if !strings.EqualFold(strings.TrimSpace(mode), "eap_direct") {
		return buildInitialAuthorization(cfg, mode), nil
	}
	material := cfg.EAPDirectAuth
	if material == nil || len(material.RES) < 4 || len(material.RES) > 16 || len(material.RAND) != 16 || len(material.AUTN) != 16 {
		return "", fmt.Errorf("IMS eap_direct 缺少本次已验证 EAP 的 RES/RAND/AUTN；已拒绝空 AKA 授权回退")
	}
	domain := strings.TrimSpace(cfg.HomeDomain)
	realm := strings.TrimSpace(cfg.Realm)
	if realm == "" {
		realm = domain
	}
	username := authorizationUsername(cfg)
	if domain == "" || realm == "" || username == "" {
		return "", fmt.Errorf("IMS eap_direct 身份或域缺失")
	}

	nonceBytes := make([]byte, 32)
	copy(nonceBytes, material.RAND)
	copy(nonceBytes[16:], material.AUTN)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	uri := "sip:" + domain
	first := md5.New()
	_, _ = first.Write([]byte(username + ":" + realm + ":"))
	_, _ = first.Write(material.RES)
	ha1 := hex.EncodeToString(first.Sum(nil))
	ha2 := md5.Sum([]byte("REGISTER:" + uri))
	response := md5.Sum([]byte(ha1 + ":" + nonce + ":" + hex.EncodeToString(ha2[:])))
	return fmt.Sprintf(`Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%x",algorithm=AKAv1-MD5`,
		quoteSipParam(username), quoteSipParam(realm), nonce, quoteSipParam(uri), response), nil
}
