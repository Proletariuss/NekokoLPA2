package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
)

// 加密接口
type Encrypter interface {
	Encrypt(plaintext []byte, key []byte, iv []byte, aad []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte, iv []byte, aad []byte) ([]byte, error)
	IVSize() int
	BlockSize() int
	KeySize() int // 返回密钥长度 (不含盐)
}

// AEADTagSize is the RFC 4106/5282 authentication tag length in bytes.
// Non-AEAD or unsupported algorithms return zero.
func AEADTagSize(id uint16) int {
	if id >= 18 && id <= 20 {
		return 8 + int(id-18)*4
	}
	return 0
}

// AES-CBC
type aesCBC struct {
	blockSize int
	keySize   int
}

func (e *aesCBC) IVSize() int    { return aes.BlockSize }
func (e *aesCBC) BlockSize() int { return aes.BlockSize }
func (e *aesCBC) KeySize() int   { return e.keySize }

func (e *aesCBC) Encrypt(plaintext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize || len(key) != e.keySize {
		return nil, errors.New("invalid CBC key or IV length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 填充应该由调用者处理 (ESP 填充是特定的)
	// 但标准 AES-CBC 要求输入是块对齐的。
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("明文未对齐块")
	}

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func (e *aesCBC) Decrypt(ciphertext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize || len(key) != e.keySize {
		return nil, errors.New("invalid CBC key or IV length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("密文未对齐块")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// AES-GCM
type aesGCM struct {
	icvSize int
	keySize int
}

func (e *aesGCM) IVSize() int { return 8 } // RFC 4106: ESP 中使用的 8 字节 IV (Nonce)

func (e *aesGCM) BlockSize() int { return 16 } // GCM 流密码，但基于块
func (e *aesGCM) KeySize() int   { return e.keySize }

func (e *aesGCM) Encrypt(plaintext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	// IKEv2/IPsec 中的 GCM 密钥结构: [密钥 (16/24/32 字节) | 盐 (4 字节)]
	if len(key) != e.keySize+4 || len(iv) != 8 {
		return nil, errors.New("GCM 盐的密钥太短")
	}
	realKey := key[:len(key)-4]
	salt := key[len(key)-4:]

	block, err := aes.NewCipher(realKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 12) // 标准 12 字节 nonce (4 盐 + 8 IV)
	if err != nil {
		return nil, err
	}

	nonce := append(append([]byte(nil), salt...), iv...)
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return sealed[:len(sealed)-16+e.icvSize], nil
}

func (e *aesGCM) Decrypt(ciphertext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	if len(key) != e.keySize+4 || len(iv) != 8 || len(ciphertext) < e.icvSize {
		return nil, errors.New("GCM 盐的密钥太短")
	}
	realKey := key[:len(key)-4]
	salt := key[len(key)-4:]

	block, err := aes.NewCipher(realKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, err
	}

	nonce := append(append([]byte(nil), salt...), iv...)
	if e.icvSize == 16 {
		return gcm.Open(nil, nonce, ciphertext, aad)
	}
	// Go's GCM constructor excludes 8-byte tags. Recover the candidate
	// plaintext with GCM's counter stream, then authenticate by recomputing
	// the full tag and comparing only the standardized transmitted prefix.
	// Candidate plaintext is never returned before authentication succeeds.
	n := len(ciphertext) - e.icvSize
	counter := make([]byte, 16)
	copy(counter, nonce)
	counter[15] = 2
	plain := make([]byte, n)
	cipher.NewCTR(block, counter).XORKeyStream(plain, ciphertext[:n])
	sealed := gcm.Seal(nil, nonce, plain, aad)
	if subtle.ConstantTimeCompare(sealed[n:n+e.icvSize], ciphertext[n:]) != 1 {
		return nil, errors.New("GCM authentication failed")
	}
	return plain, nil
}

// 工厂函数
func GetEncrypter(id uint16) (Encrypter, error) {
	return GetEncrypterWithKeyLen(id, 0)
}

func GetEncrypterWithKeyLen(id uint16, keyLenBits int) (Encrypter, error) {
	keySize := 16
	if keyLenBits != 0 {
		if keyLenBits%8 != 0 {
			return nil, errors.New("无效的密钥长度")
		}
		keySize = keyLenBits / 8
	}
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("unsupported AES key length")
	}

	switch id {
	case 12: // AES_CBC
		return &aesCBC{keySize: keySize}, nil
	case 18, 19, 20: // AES_GCM_8/12/16
		return &aesGCM{icvSize: 8 + int(id-18)*4, keySize: keySize}, nil
	default:
		return nil, errors.New("不支持的加密算法")
	}
}

// 随机数生成
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}
