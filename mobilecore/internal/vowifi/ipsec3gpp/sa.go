package ipsec3gpp

import (
	"errors"
	"sync/atomic"

	"github.com/1239t/swu-go/pkg/crypto"
)

// SecurityAssociation 表示一条用户态 ESP SA。
// 从参考实现（github.com/1239t/swu-go/pkg/ipsec.SecurityAssociation）移植，
// 仅保留用户态所需字段，去掉依赖内核 xfrm / errqueue 的部分。
type SecurityAssociation struct {
	SPI           uint32
	RemoteSPI     uint32
	EncryptionAlg crypto.Encrypter
	EncryptionKey []byte
	IntegritySalt []byte // 用于 GCM

	IntegrityAlg  crypto.PRF                // 旧接口 (保留兼容性)
	IntegrityAlg2 crypto.IntegrityAlgorithm // 新接口，用于非 AEAD
	IntegrityKey  []byte

	IsAEAD         bool   // 是否使用 AEAD 加密 (GCM 等)
	SequenceNumber uint64 // 使用 64 来模拟 ESN 或只是防止溢出
	ReplayWindow   uint64 // 用于检查重复项
}

// NewSecurityAssociation 创建使用 AEAD (GCM) 的 SA。
func NewSecurityAssociation(spi uint32, enc crypto.Encrypter, encKey []byte, integKey []byte) *SecurityAssociation {
	return &SecurityAssociation{
		SPI:            spi,
		EncryptionAlg:  enc,
		EncryptionKey:  encKey,
		IntegrityKey:   integKey,
		SequenceNumber: 0,
		IsAEAD:         true, // 默认假设 AEAD (GCM)
	}
}

// NewSecurityAssociationCBC 创建使用 CBC + HMAC 的 SA。
func NewSecurityAssociationCBC(spi uint32, enc crypto.Encrypter, encKey []byte, integAlg crypto.IntegrityAlgorithm, integKey []byte) *SecurityAssociation {
	return &SecurityAssociation{
		SPI:            spi,
		EncryptionAlg:  enc,
		EncryptionKey:  encKey,
		IntegrityAlg2:  integAlg,
		IntegrityKey:   integKey,
		SequenceNumber: 0,
		IsAEAD:         false,
	}
}

// NextSequenceNumber 返回下一个 ESP 序列号。
// 序列号不允许为 0 且不能溢出（RFC 4303 §3.3）：溢出前必须重新协商 SA。
func (sa *SecurityAssociation) NextSequenceNumber() (uint32, error) {
	next := atomic.AddUint64(&sa.SequenceNumber, 1)
	if next > 0xFFFFFFFF {
		return 0, errors.New("ipsec3gpp: sequence number overflow, SA must be rekeyed")
	}
	return uint32(next), nil
}
