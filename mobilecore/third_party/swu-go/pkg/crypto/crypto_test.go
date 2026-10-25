package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestInitialChildSAKeyMaterialGolden(t *testing.T) {
	seed := append(bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)...)
	for size, want := range map[int]string{
		40: "5bdcd5b059dc47412c71c4d6acd2c39565880eb3edcc8bdf9bf733d9087735aa",
		72: "cac0241e0fad35ca1a2e4ded8d8a2bb6ac1ec9d7226c2c807b3d4e5e666e32e4",
	} {
		keys, err := PrfPlus(PRF_HMAC_SHA2_256, bytes.Repeat([]byte{1}, 32), seed, size)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(keys)
		if hex.EncodeToString(digest[:]) != want {
			t.Fatal("initial CHILD SA key layout mismatch")
		}
	}
}

func TestIKESAKeyMaterialGoGoldenVector(t *testing.T) {
	ni := []byte("initiator nonce")
	nr := []byte("responder nonce")
	dh := []byte("shared dh secret")
	nonceSeed := append(append([]byte{}, ni...), nr...)
	h := hmac.New(sha256.New, nonceSeed)
	_, _ = h.Write(dh)
	skeyseed := h.Sum(nil)
	seed := append(append(append([]byte{}, ni...), nr...), make([]byte, 16)...)
	binary.BigEndian.PutUint64(seed[len(ni)+len(nr):], 0x0102030405060708)
	binary.BigEndian.PutUint64(seed[len(ni)+len(nr)+8:], 0x1112131415161718)
	keymat, err := PrfPlus(PRF_HMAC_SHA2_256, skeyseed, seed, 32*3+32*2+20*2)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(keymat)
	const want = "0df4219b2621bd4e400a3dad1e98eb87194b41a72c5b0a00991d8710869709ac719333acd42d03428cfe78a9adfc6f3fa3d9f9ad339b62143e055f506c27e22cf874de15d05332a45e181a01ccb025c5e768290ab2109ebc0955157e97364db3599badffafeaca277a412f5c736fbc74a2644028ef2e076b83060e00669e376e7bdc9953c64580ed36e6c741323ff6893c2f4043978f453f43eee7e19f4da117ab3ff33dd8262cff33bb6b3b5c39daf1db3243422d6a28ecad73a04db9e281e0f8aa074f0913066e"
	if got != want {
		t.Fatalf("SK_d mismatch: got %s, want %s", got, want)
	}
}

func TestIKESAKeyMaterialSupportedPRFGoldenDigests(t *testing.T) {
	cases := []struct {
		id             uint16
		prf            PRF
		wantKeymatHash string
	}{
		{2, PRF_HMAC_SHA1, "73639edf17a26150fe2549a13b796987113a72db89b300178ebfab0f3cdd29b1"},
		{5, PRF_HMAC_SHA2_256, "5ff2f6669a10aaafd0a0aa1c29bfd6ab310d9ec78d776a6cc0902901a463455b"},
		{6, PRF_HMAC_SHA2_384, "aaf69e443ccd1d4742fde4ac05b9a37cb2a29189133fa387be5427be4e831bf4"},
		{7, PRF_HMAC_SHA2_512, "9724f834c5e28493b32d9850aa8641961679c40bc49677cf5c7dddb8a49d8c6e"},
	}
	ni := []byte("initiator nonce")
	nr := []byte("responder nonce")
	dh := []byte("shared dh secret")
	for _, test := range cases {
		nonceSeed := append(append([]byte{}, ni...), nr...)
		h := hmac.New(test.prf.Hash, nonceSeed)
		_, _ = h.Write(dh)
		seed := append(append(append([]byte{}, ni...), nr...), make([]byte, 16)...)
		binary.BigEndian.PutUint64(seed[len(ni)+len(nr):], 0x0102030405060708)
		binary.BigEndian.PutUint64(seed[len(ni)+len(nr)+8:], 0x1112131415161718)
		keymat, err := PrfPlus(test.prf, h.Sum(nil), seed, test.prf.KeyLen()*3+32*2+20*2)
		if err != nil {
			t.Fatalf("PRF %d: %v", test.id, err)
		}
		digest := sha256.Sum256(keymat)
		if got := hex.EncodeToString(digest[:]); got != test.wantKeymatHash {
			t.Errorf("PRF %d keymat digest mismatch: got %s, want %s", test.id, got, test.wantKeymatHash)
		}
	}
}

// RFC 5282 wire reference, not the legacy swu msg_handler envelope.
func TestIKESKAESGCM16EnvelopeGoldenDigest(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 20)
	iv := bytes.Repeat([]byte{0x22}, 8)
	plaintext := []byte{
		41, 0, 0, 9, 2, 17, 0, 5, 1,
		0, 0, 0, 8, 0, 0, 0, 14,
		0, // Pad Length, even with no padding
	}
	aad := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24,
		46, 32, 35, 8, 0, 0, 0, 1, 0, 0, 0, 74,
		48, 0, 0, 46, // SK header is also authenticated
	}
	enc, err := GetEncrypterWithKeyLen(20, 128)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := enc.Encrypt(plaintext, key, iv, aad)
	if err != nil {
		t.Fatal(err)
	}
	packet := append(append(append([]byte(nil), aad...), iv...), ciphertext...)
	digest := sha256.Sum256(packet)
	const want = "5a12914fe8e827f85fee298e78bc0b832589c0e247367544502ec2e8e519de39"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("IKE SK GCM envelope digest mismatch: got %s, want %s", got, want)
	}
}

// TestPrfPlus 测试 PRF+ 密钥派生函数
func TestPrfPlus(t *testing.T) {
	prf := PRF_HMAC_SHA2_256
	key := []byte("test-key-1234567890")
	seed := []byte("test-seed-data")

	// 生成 64 字节
	result, err := PrfPlus(prf, key, seed, 64)
	if err != nil {
		t.Fatalf("PrfPlus 失败: %v", err)
	}

	if len(result) != 64 {
		t.Errorf("结果长度错误: got %d, want 64", len(result))
	}

	// 再次生成，结果应该相同
	result2, err := PrfPlus(prf, key, seed, 64)
	if err != nil {
		t.Fatalf("PrfPlus 第二次调用失败: %v", err)
	}

	if !bytes.Equal(result, result2) {
		t.Error("相同输入的 PrfPlus 结果不一致")
	}
}

// TestAESGCMEncryptDecrypt 测试 AES-GCM 加解密
func TestAESGCMEncryptDecrypt(t *testing.T) {
	enc, err := GetEncrypter(20) // ENCR_AES_GCM_16
	if err != nil {
		t.Fatalf("获取加密器失败: %v", err)
	}

	// Key: 16 bytes + 4 bytes salt = 20 bytes
	key := []byte("1234567890123456salt")
	plaintext := []byte("Hello, IKEv2 World!")
	aad := []byte("additional-auth-data")

	// 生成 IV
	iv, err := RandomBytes(enc.IVSize())
	if err != nil {
		t.Fatalf("生成 IV 失败: %v", err)
	}

	// 加密
	ciphertext, err := enc.Encrypt(plaintext, key, iv, aad)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 解密
	decrypted, err := enc.Decrypt(ciphertext, key, iv, aad)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("解密结果不匹配: got %s, want %s", decrypted, plaintext)
	}
}

// TestAESCBCEncryptDecrypt 测试 AES-CBC 加解密
func TestAESCBCEncryptDecrypt(t *testing.T) {
	enc, err := GetEncrypter(12) // ENCR_AES_CBC
	if err != nil {
		t.Fatalf("获取加密器失败: %v", err)
	}

	key := []byte("1234567890123456") // 16 bytes
	// 明文必须是块对齐的 (16 bytes)
	plaintext := []byte("HelloIKEv2World!")

	iv, err := RandomBytes(enc.IVSize())
	if err != nil {
		t.Fatalf("生成 IV 失败: %v", err)
	}

	// 加密
	ciphertext, err := enc.Encrypt(plaintext, key, iv, nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 解密
	decrypted, err := enc.Decrypt(ciphertext, key, iv, nil)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("解密结果不匹配: got %s, want %s", decrypted, plaintext)
	}
}

// TestRandomBytes 测试随机字节生成
func TestRandomBytes(t *testing.T) {
	b1, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes 失败: %v", err)
	}

	b2, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes 第二次调用失败: %v", err)
	}

	if bytes.Equal(b1, b2) {
		t.Error("两次 RandomBytes 调用不应返回相同的结果")
	}

	if len(b1) != 32 {
		t.Errorf("长度错误: got %d, want 32", len(b1))
	}
}
