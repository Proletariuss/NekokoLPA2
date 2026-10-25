package swu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
)

// RekeyChildSA 执行 CHILD_SA 密钥轮换 (CREATE_CHILD_SA 交换)
// RFC 7296 1.3.3: 重新协商 CHILD_SA
func (s *Session) RekeyChildSA() error {
	// 防止并发 rekey（两个 SPI 的 expire 会同时触发）
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()

	if s.ChildSAOut == nil || s.ChildSAIn == nil || s.Keys == nil || s.PRFAlg == nil {
		return errors.New("没有活动的 CHILD_SA 可以 Rekey")
	}

	// 冷却期去重（在 mutex 内检查，确保第二个 goroutine 能看到最新的 lastRekeyTime）
	if !s.lastRekeyTime.IsZero() && time.Since(s.lastRekeyTime) < 30*time.Second {
		s.Logger.Debug("Rekey 冷却期内，跳过重复 Rekey",
			logger.Duration("sinceLast", time.Since(s.lastRekeyTime)))
		return nil
	}

	s.Logger.Info("开始 CHILD_SA Rekey")

	// 1. 生成新的 Nonce
	newNonce, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}

	// 2. 生成新的 SPI
	newSPI, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	newSPIValue := binary.BigEndian.Uint32(newSPI)

	// Keep carrier ESP transforms and PFS policy consistent during rekey.
	proposals, newDH, err := s.childRekeyProposals(newSPI)
	if err != nil {
		return err
	}
	defer eraseChildRekeyDH(newDH)
	saPayload := &ikev2.EncryptedPayloadSA{Proposals: proposals}

	// 4. Nonce 载荷
	noncePayload := &ikev2.EncryptedPayloadNonce{NonceData: newNonce}

	// RFC 7296 identifies the old Child SA by our inbound SPI.
	oldSPIBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(oldSPIBytes, s.ChildSAIn.SPI)
	rekeyNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: ikev2.ProtoESP,
		SPI:        oldSPIBytes,
		NotifyType: ikev2.REKEY_SA,
	}

	// 6. TSi / TSr (保持不变，使用全流量)
	tsi := s.tsi
	tsr := s.tsr
	if len(tsi) == 0 || len(tsr) == 0 {
		ts := ikev2.NewTrafficSelectorIPV4(
			[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255},
			0, 65535,
		)
		tsi = []*ikev2.TrafficSelector{ts}
		tsr = []*ikev2.TrafficSelector{ts}
	}
	tsPayloadI := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: tsi}
	tsPayloadR := &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: tsr}

	// 7. 构造并发送 CREATE_CHILD_SA 请求
	payloads := []ikev2.Payload{saPayload, noncePayload}
	if newDH != nil {
		payloads = append(payloads, &ikev2.EncryptedPayloadKE{DHGroup: ikev2.AlgorithmType(newDH.Group), KEData: newDH.PublicKeyBytes()})
	}
	payloads = append(payloads, rekeyNotify, tsPayloadI, tsPayloadR)
	respData, err := s.sendEncryptedWithRetry(payloads, ikev2.CREATE_CHILD_SA)
	if err != nil {
		return fmt.Errorf("CREATE_CHILD_SA 失败: %v", err)
	}

	s.Logger.Info("Rekey 收到 ePDG 响应", logger.Int("len", len(respData)))
	return s.handleCreateChildSAResp(respData, newNonce, newSPIValue, newDH, proposals, tsi, tsr)
}

// handleCreateChildSAResp 处理 CREATE_CHILD_SA 响应
func (s *Session) handleCreateChildSAResp(data []byte, niNonce []byte, newSPI uint32, dh *crypto.DiffieHellman, offers []*ikev2.Proposal, offeredTSI, offeredTSR []*ikev2.TrafficSelector) error {
	s.Logger.Debug("开始解密 Rekey 响应", logger.Int("dataLen", len(data)))
	_, payloads, err := s.decryptAndParse(data)
	if err != nil {
		s.Logger.Warn("Rekey 响应解密失败", logger.Err(err))
		return err
	}

	s.Logger.Info("Rekey 响应解密成功", logger.Int("payloadCount", len(payloads)))
	for i, pl := range payloads {
		s.Logger.Debug("Rekey 响应载荷",
			logger.Int("index", i),
			logger.String("type", fmt.Sprintf("%T", pl)))
	}

	selected, respNonce, shared, tsi, tsr, err := validateChildRekeyResponse(payloads, offers, dh, offeredTSI, offeredTSR)
	if err != nil {
		return err
	}
	defer clear(shared)
	if len(respNonce) < s.PRFAlg.KeyLen()/2 {
		return errors.New("CHILD_SA nonce too short for negotiated IKE PRF")
	}
	respSPI := binary.BigEndian.Uint32(selected.SPI)
	if s.ChildSAIn == nil || s.ChildSAOut == nil || newSPI == 0 || newSPI == s.ChildSAIn.SPI || respSPI == s.ChildSAOut.SPI {
		return errors.New("CHILD_SA rekey must allocate fresh nonzero SPIs")
	}
	var encrID uint16
	var integID uint16
	var encrKeyLenBits int

	for _, transform := range selected.Transforms {
		switch transform.Type {
		case ikev2.TransformTypeEncr:
			encrID = uint16(transform.ID)
			for _, attr := range transform.Attributes {
				if attr.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(attr.Val)
				}
			}
		case ikev2.TransformTypeInteg:
			integID = uint16(transform.ID)
		}
	}
	if encrID == 0 {
		return errors.New("CREATE_CHILD_SA 响应缺少加密算法选择")
	}

	// 密钥派生（与 state_auth.go 一致）
	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}

	isAEAD := encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	encKeyLen := childEnc.KeySize()
	saltLen := 0
	integKeyLen := 0
	var integAlg crypto.IntegrityAlgorithm

	if isAEAD {
		saltLen = 4
	} else {
		integAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("不支持的 Child SA 完整性算法: %d", integID)
		}
		integKeyLen = integAlg.KeySize()
	}

	keyMatLen := 2 * (encKeyLen + saltLen + integKeyLen)
	seed := make([]byte, 0, len(shared)+len(niNonce)+len(respNonce))
	seed = append(seed, shared...)
	defer clear(seed)
	seed = append(seed, niNonce...)
	seed = append(seed, respNonce...)

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}
	defer clear(keyMat)

	// 按 RFC 7296 顺序切分密钥材料
	cursor := 0
	outEncKey := append([]byte(nil), keyMat[cursor:cursor+encKeyLen+saltLen]...)
	cursor += encKeyLen + saltLen
	outIntegKey := []byte(nil)
	if !isAEAD {
		outIntegKey = append([]byte(nil), keyMat[cursor:cursor+integKeyLen]...)
		cursor += integKeyLen
	}
	inEncKey := append([]byte(nil), keyMat[cursor:cursor+encKeyLen+saltLen]...)
	cursor += encKeyLen + saltLen
	inIntegKey := []byte(nil)
	if !isAEAD {
		inIntegKey = append([]byte(nil), keyMat[cursor:cursor+integKeyLen]...)
	}

	// 构造新 SA
	// 注意 SPI 约定（与 state_auth.go 一致）：
	// - ChildSAOut.SPI = respSPI (ePDG 分配，用于出站 ESP 包头)
	// - ChildSAIn.SPI  = newSPI  (本端生成，ePDG 用于发给我们的 ESP 包头)
	var newSAOut, newSAIn *ipsec.SecurityAssociation
	if isAEAD {
		newSAOut = ipsec.NewSecurityAssociation(respSPI, childEnc, outEncKey, nil)
		newSAIn = ipsec.NewSecurityAssociation(newSPI, childEnc, inEncKey, nil)
	} else {
		newSAOut = ipsec.NewSecurityAssociationCBC(respSPI, childEnc, outEncKey, integAlg, outIntegKey)
		newSAIn = ipsec.NewSecurityAssociationCBC(newSPI, childEnc, inEncKey, integAlg, inIntegKey)
	}
	newSAOut.RemoteSPI = newSPI
	newSAIn.RemoteSPI = respSPI

	// 替换内存中的旧 SA
	oldOutSPI := s.ChildSAOut.SPI
	oldInSPI := s.ChildSAIn.SPI
	s.tsi, s.tsr = tsi, tsr
	s.ChildSAOut = newSAOut
	s.ChildSAIn = newSAIn
	s.childEncrID, s.childIntegID = encrID, integID
	s.childEncrKeyLenBits = encrKeyLenBits
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[newSPI] = newSAIn
	}
	if len(s.childOutPolicies) > 0 {
		s.childOutPolicies[0].saOut = newSAOut
		s.childOutPolicies[0].tsr = tsr
	} else if len(s.tsr) > 0 {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: newSAOut, tsr: s.tsr})
	}
	if s.ws != nil {
		s.ws.LogChildSA(newSPI, respSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inEncKey, outEncKey, encrID)
	}

	// 更新内核 XFRM SA（XFRMI 模式）
	if s.xfrmMgr != nil {
		if err := s.rekeyXFRMSA(oldOutSPI, oldInSPI, newSAOut, newSAIn, encrID, encrKeyLenBits); err != nil {
			s.Logger.Warn("Rekey 后更新内核 XFRM SA 失败", logger.Err(err))
		}
	}

	s.Logger.Info("CHILD_SA Rekey 成功", logger.Uint32("oldSPI", oldOutSPI), logger.Uint32("newSPI", newSPI))

	// 更新冷却期时间戳（防止另一个 SPI 的 Soft Expire 再次触发 rekey）
	s.lastRekeyTime = time.Now()

	// 通知 Timer 重置（非阻塞写入）
	select {
	case s.childRekeyResetCh <- struct{}{}:
	default:
	}

	// 同步发送删除旧 SA 的通知（不用 goroutine，避免 msgID 竞争）
	if err := s.sendDeleteChildSA([]uint32{oldInSPI}); err != nil {
		s.Logger.Warn("发送旧 Child SA Delete 通知失败", logger.Err(err))
	}

	return nil
}
