package swu

import (
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

// Encrypted exchanges must belong to the already negotiated SA. Peer SPI
// changes occur only in explicit SA_INIT/rekey/resume state transitions.
func (s *Session) validateEncryptedHeader(data []byte) (*ikev2.IKEHeader, error) {
	header, err := ikev2.DecodeHeader(data)
	if err != nil {
		return nil, err
	}
	if header.Length != uint32(len(data)) || header.Version>>4 != 2 {
		return nil, errors.New("IKE 加密报文长度或版本无效")
	}
	if s.SPIi == 0 || s.SPIr == 0 || header.SPIi != s.SPIi || header.SPIr != s.SPIr {
		return nil, errors.New("IKE 加密报文 SPI 与当前会话不匹配")
	}
	if header.NextPayload != ikev2.SK && header.NextPayload != ikev2.EncryptedFragment {
		return nil, errors.New("IKE 已建会话拒绝未加密载荷")
	}
	return header, nil
}

func (s *Session) decryptAndParse(data []byte) (uint32, []ikev2.Payload, error) {
	header, err := s.validateEncryptedHeader(data)
	if err != nil {
		return 0, nil, err
	}

	// RFC 7383: 处理 Encrypted Fragment (SKF) 载荷
	if header.NextPayload == ikev2.EncryptedFragment {
		plaintext, fragNum, totalFrags, msgID, err := s.decryptSKF(data)
		if err != nil {
			return header.MessageID, nil, fmt.Errorf("SKF 解密失败: %v", err)
		}
		s.Logger.Debug("收到 IKE 分片",
			logger.Int("frag", int(fragNum)),
			logger.Int("total", int(totalFrags)),
			logger.Uint32("msgID", msgID))

		complete, err := s.fragmentBuf.addFragment(msgID, fragNum, totalFrags, plaintext, ikev2.PayloadType(data[ikev2.IKE_HEADER_LEN]))
		if err != nil {
			return msgID, nil, err
		}
		if !complete {
			// 还没收齐，返回空载荷（调用方会继续接收）
			return msgID, nil, nil
		}
		// 所有分片已收齐，重组
		reassembled, firstPayloadType, err := s.fragmentBuf.reassemble(msgID)
		if err != nil {
			return msgID, nil, err
		}
		// 解析第一个分片中记录的 NextPayload 类型
		// SKF Generic Header 中的 NextPayload 指向重组后的第一个载荷
		payloads, err := s.parsePayloads(reassembled, firstPayloadType)
		return msgID, payloads, err
	}

	// 处理 SK 载荷
	offset := ikev2.IKE_HEADER_LEN
	if len(data) < offset+4 {
		return 0, nil, errors.New("SK 载荷头太短")
	}
	genHeader, err := ikev2.DecodePayloadHeader(data[offset : offset+4])
	if err != nil {
		return 0, nil, err
	}

	skBodyLen := int(genHeader.PayloadLength) - 4
	if skBodyLen < 0 || offset+4+skBodyLen != len(data) {
		return 0, nil, errors.New("SK 载荷太短")
	}

	skContent := data[offset+4 : offset+4+skBodyLen]
	ivSize := s.EncAlg.IVSize()

	if len(skContent) < ivSize {
		return 0, nil, errors.New("SK 内容对于 IV 来说太短")
	}
	iv := skContent[:ivSize]
	aad := data[:ikev2.IKE_HEADER_LEN]
	if s.ikeIsAEAD {
		aad = data[:ikev2.IKE_HEADER_LEN+4]
	}
	key := s.Keys.SK_er

	ciphertext := skContent[ivSize:]
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize := s.IntegAlg.OutputSize()
		if len(ciphertext) < icvSize {
			return 0, nil, errors.New("SK 内容对于 ICV 来说太短")
		}
		receivedICV := ciphertext[len(ciphertext)-icvSize:]
		ciphertext = ciphertext[:len(ciphertext)-icvSize]

		dataToVerify := data[:ikev2.IKE_HEADER_LEN+4+ivSize+len(ciphertext)]
		if !s.IntegAlg.Verify(s.Keys.SK_ar, dataToVerify, receivedICV) {
			return 0, nil, errors.New("IKE 完整性校验失败")
		}
	}

	plaintext, err := s.EncAlg.Decrypt(ciphertext, key, iv, aad)
	if err != nil {
		return 0, nil, fmt.Errorf("解密失败: %v", err)
	}

	plaintext, err = stripIKEPadding(plaintext)
	if err != nil {
		return 0, nil, err
	}

	payloads, err := s.parsePayloads(plaintext, genHeader.NextPayload)
	return header.MessageID, payloads, err
}

// RFC 5282 retains the Pad Length byte for AEAD too; padding bytes are opaque.
func stripIKEPadding(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("IKE 加密载荷缺少填充长度")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen+1 > len(plaintext) {
		return nil, errors.New("IKE 加密载荷填充长度无效")
	}
	return plaintext[:len(plaintext)-padLen-1], nil
}

func (s *Session) parsePayloads(data []byte, firstType ikev2.PayloadType) ([]ikev2.Payload, error) {
	var payloads []ikev2.Payload
	offset := 0
	nextType := firstType

	for nextType != ikev2.NoNextPayload && offset < len(data) {
		if offset+4 > len(data) {
			return nil, errors.New("truncated payload header")
		}
		genHeader, err := ikev2.DecodePayloadHeader(data[offset : offset+4])
		if err != nil {
			return nil, err
		}

		length := int(genHeader.PayloadLength)
		if length < 4 || offset+length > len(data) {
			return nil, errors.New("载荷太短")
		}

		body := data[offset+4 : offset+length]
		var p ikev2.Payload

		switch nextType {
		case ikev2.SA:
			p, err = ikev2.DecodePayloadSA(body)
		case ikev2.KE:
			p, err = ikev2.DecodePayloadKE(body)
		case ikev2.IDi, ikev2.IDr:
			p, err = ikev2.DecodePayloadID(body, nextType == ikev2.IDi)
		case ikev2.AUTH:
			p, err = ikev2.DecodePayloadAuth(body)
		case ikev2.CERT:
			p, err = ikev2.DecodePayloadCert(body)
		case ikev2.CERTREQ:
			if len(body) > 0 && body[0] != ikev2.CertReqX509Signature && !genHeader.Critical {
				p = &ikev2.RawPayload{PType: ikev2.CERTREQ, Data: append([]byte(nil), body...)}
			} else {
				p, err = ikev2.DecodePayloadCertReq(body)
			}
		case ikev2.EAP:
			p, err = ikev2.DecodePayloadEAP(body)
		case ikev2.CP:
			p, err = ikev2.DecodePayloadCP(body)
		case ikev2.D:
			p, err = ikev2.DecodePayloadDelete(body)
		case ikev2.TSI:
			p, err = ikev2.DecodePayloadTS(body, true)
		case ikev2.TSR:
			p, err = ikev2.DecodePayloadTS(body, false)
		case ikev2.N:
			p, err = ikev2.DecodePayloadNotify(body)
		case ikev2.NiNr:
			p, err = ikev2.DecodePayloadNonce(body)
		default:
			if genHeader.Critical {
				return nil, errors.New("unsupported critical encrypted IKE payload")
			}
			p = &ikev2.RawPayload{PType: nextType, Data: body}
		}

		if err != nil {
			return nil, err
		}
		if p != nil {
			payloads = append(payloads, p)
		}

		nextType = genHeader.NextPayload
		offset += length
	}
	if nextType != ikev2.NoNextPayload || offset != len(data) {
		return nil, errors.New("incomplete or trailing IKE payload chain")
	}
	return payloads, nil
}

func (s *Session) encryptAndWrap(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, isResponse bool) ([]byte, error) {
	msgID := uint32(s.NextSequenceNumber())
	return s.encryptAndWrapWithMsgID(payloads, exchangeType, msgID, isResponse)
}

func (s *Session) encryptAndWrapWithMsgID(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, msgID uint32, isResponse bool) ([]byte, error) {
	innerData := []byte{}

	for i, pl := range payloads {
		nextType := ikev2.NoNextPayload
		if i < len(payloads)-1 {
			nextType = payloads[i+1].Type()
		}

		body, err := pl.Encode()
		if err != nil {
			return nil, err
		}

		header := &ikev2.PayloadHeader{
			NextPayload:   nextType,
			PayloadLength: uint16(4 + len(body)),
		}
		innerData = append(innerData, header.Encode()...)
		innerData = append(innerData, body...)
	}

	key := s.Keys.SK_ei
	iv, err := crypto.RandomBytes(s.EncAlg.IVSize())
	if err != nil {
		return nil, err
	}

	icvSize := 0
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize = s.IntegAlg.OutputSize()
	}

	plainToEncrypt := innerData
	expectedCipherLen := len(plainToEncrypt)
	if s.ikeIsAEAD {
		plainToEncrypt = append(append([]byte(nil), plainToEncrypt...), 0)
		expectedCipherLen = len(plainToEncrypt) + crypto.AEADTagSize(s.ikeEncrID)
	} else {
		blockSize := s.EncAlg.BlockSize()
		if blockSize <= 0 {
			return nil, errors.New("无效的块大小")
		}
		padLen := 0
		if rem := (len(plainToEncrypt) + 1) % blockSize; rem != 0 {
			padLen = blockSize - rem
		}
		plainToEncrypt = append(plainToEncrypt, make([]byte, padLen)...)
		plainToEncrypt = append(plainToEncrypt, byte(padLen))
		expectedCipherLen = len(plainToEncrypt)
	}

	nextPayload := ikev2.NoNextPayload
	if len(payloads) > 0 {
		nextPayload = payloads[0].Type()
	}

	hdr := &ikev2.IKEHeader{
		SPIi:         s.SPIi,
		SPIr:         s.SPIr,
		NextPayload:  ikev2.SK,
		Version:      0x20,
		ExchangeType: exchangeType,
		Flags:        ikev2.FlagInitiator,
		MessageID:    msgID,
		Length:       uint32(ikev2.IKE_HEADER_LEN + 4 + len(iv) + expectedCipherLen + icvSize),
	}
	if isResponse {
		hdr.Flags |= ikev2.FlagResponse
	}

	skHeader := &ikev2.PayloadHeader{NextPayload: nextPayload, PayloadLength: uint16(4 + len(iv) + expectedCipherLen + icvSize)}
	aad := hdr.Encode()
	if s.ikeIsAEAD {
		aad = append(aad, skHeader.Encode()...)
	}
	ciphertext, err := s.EncAlg.Encrypt(plainToEncrypt, key, iv, aad)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) != expectedCipherLen {
		return nil, errors.New("加密输出长度不匹配")
	}

	packet := append(hdr.Encode(), skHeader.Encode()...)
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icv := s.IntegAlg.Compute(s.Keys.SK_ai, packet)
		packet = append(packet, icv...)
	}
	if uint32(len(packet)) != hdr.Length {
		return nil, errors.New("IKE 长度字段不匹配")
	}
	return packet, nil
}

func (s *Session) NextSequenceNumber() uint32 {
	return s.SequenceNumber.Add(1) - 1
}
