package swu

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"

	//"encoding/hex"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

var errRetryDH = errors.New("retry SA_INIT with offered DH group")

func (s *Session) sendIKESAInit() error {
	data, err := s.buildIKESAInitPacket()
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) buildIKESAInitPacket() ([]byte, error) {
	if len(s.ni) == 0 {
		s.ni = make([]byte, 32)
		rand.Read(s.ni)
	}

	proposals, err := ikev2.BuildIKEProposals(s.cfg.IKEProposals, nil)
	if err != nil {
		return nil, err
	}
	if len(proposals) == 0 {
		return nil, errors.New("IKE proposal list is empty")
	}
	dhGroup, err := ikev2.ProposalDHGroup(proposals[0])
	if err != nil {
		return nil, fmt.Errorf("first IKE proposal: %w", err)
	}
	if s.initRetryDH != 0 {
		dhGroup = ikev2.AlgorithmType(s.initRetryDH)
	}
	s.ikeOffers = proposals

	if s.DH == nil || s.DH.Group != uint16(dhGroup) {
		s.DH, err = crypto.NewDiffieHellman(uint16(dhGroup))
		if err != nil {
			return nil, fmt.Errorf("first IKE proposal DH group %d: %w", dhGroup, err)
		}
		if err := s.DH.GenerateKey(); err != nil {
			return nil, err
		}
	}

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	kePayload := &ikev2.EncryptedPayloadKE{
		DHGroup: dhGroup,
		KEData:  s.DH.PublicKeyBytes(),
	}

	noncePayload := &ikev2.EncryptedPayloadNonce{
		NonceData: s.ni,
	}

	localPort := s.cfg.LocalPort
	if localPort == 0 {
		if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
			localPort = lp.LocalPort()
		}
	}
	remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 500
	}

	if ep, ok := s.socket.(interface {
		LocalIP() net.IP
		RemoteIP() net.IP
		RemotePort() int
	}); ok {
		if rip := ep.RemoteIP(); rip != nil {
			if v4 := rip.To4(); v4 != nil {
				remoteIP = v4
			}
		}
		if rp := ep.RemotePort(); rp != 0 {
			remotePort = uint16(rp)
		}
	}

	localIP := net.ParseIP(s.cfg.LocalAddr).To4()
	if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
		if lip := ep.LocalIP(); lip != nil {
			if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
				localIP = v4
			}
		}
	}
	// An unspecified LocalAddr must stay unspecified. Opening a second UDP
	// socket to infer an outbound address would interfere with transparent
	// fake-IP/TUN routing and is unnecessary: the zero address correctly makes
	// NAT detection select UDP 4500 on the original transport.

	srcHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, localIP, localPort)
	natSrcPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_SOURCE_IP, srcHash)

	dstHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, remoteIP, remotePort)
	natDstPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_DESTINATION_IP, dstHash)

	// IKE Fragmentation (RFC 7383)
	// IKE_SA_INIT 必须携带此通知
	fragNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.IKEV2_FRAGMENTATION_SUPPORTED,
	}

	// Keep the historic wire order for existing carriers. 3HK explicitly
	// requests a COOKIE body encoded with the SA outer payload type.
	payloads := []ikev2.Payload{saPayload, kePayload, noncePayload, fragNotify}
	if s.sendCookie && len(s.cookie) > 0 {
		cookie := &ikev2.EncryptedPayloadNotify{ProtocolID: 0, NotifyType: ikev2.COOKIE, NotifyData: s.cookie}
		if s.cfg.CookiePayloadType == "sa" {
			payloads = []ikev2.Payload{&carrierCookieSA{cookie}, saPayload, kePayload, noncePayload, natSrcPayload, natDstPayload, fragNotify}
		} else {
			payloads = append(payloads, cookie)
			payloads = append(payloads, natSrcPayload, natDstPayload)
		}
	} else {
		payloads = append(payloads, natSrcPayload, natDstPayload)
	}

	packet := ikev2.NewIKEPacket()
	packet.Header.SPIi = s.SPIi
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = ikev2.IKE_SA_INIT
	packet.Header.Flags = ikev2.FlagInitiator
	packet.Header.MessageID = 0
	packet.Payloads = payloads

	data, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	// RFC 7427: advertise SHA-256/384/512 signature hashes, including support
	// for AUTH method 14. The notify is part of the signed SA_INIT transcript.
	packet.Payloads = append(packet.Payloads, &ikev2.EncryptedPayloadNotify{
		NotifyType: 16431, NotifyData: []byte{0, 2, 0, 3, 0, 4},
	})
	data, err = packet.Encode()
	if err != nil {
		return nil, err
	}
	s.msgBuffer = data
	return data, nil
}

func (s *Session) handleIKESAInitResp(data []byte) error {
	packet, err := ikev2.DecodePacket(data)
	if err != nil {
		return fmt.Errorf("解码 SA_INIT 响应失败: %v", err)
	}

	// 检查头部
	if packet.Header.ExchangeType != ikev2.IKE_SA_INIT {
		return fmt.Errorf("意外的交换类型: %d", packet.Header.ExchangeType)
	}
	if packet.Header.SPIi != s.SPIi || packet.Header.MessageID != 0 || packet.Header.Flags&0x20 == 0 || packet.Header.Flags&ikev2.FlagInitiator != 0 || packet.Header.Version != 0x20 || int(packet.Header.Length) != len(data) {
		return errors.New("invalid SA_INIT response header")
	}
	s.SPIr = packet.Header.SPIr

	// 提取载荷
	var saPayload *ikev2.EncryptedPayloadSA
	var kePayload *ikev2.EncryptedPayloadKE
	var noncePayload *ikev2.EncryptedPayloadNonce
	var natSrc []byte
	var natDst []byte

	for _, p := range packet.Payloads {
		switch v := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			if saPayload != nil {
				return errors.New("duplicate SA_INIT SA")
			}
			saPayload = v
		case *ikev2.EncryptedPayloadKE:
			if kePayload != nil {
				return errors.New("duplicate SA_INIT KE")
			}
			kePayload = v
		case *ikev2.EncryptedPayloadNonce:
			if noncePayload != nil {
				return errors.New("duplicate SA_INIT nonce")
			}
			noncePayload = v
		case *ikev2.EncryptedPayloadNotify:
			if v.NotifyType == 17 { // INVALID_KE_PAYLOAD, RFC 7296 section 2.7.
				if len(v.NotifyData) != 2 || len(v.SPI) != 0 || v.ProtocolID != 0 {
					return errors.New("invalid INVALID_KE_PAYLOAD")
				}
				group := binary.BigEndian.Uint16(v.NotifyData)
				if s.DH != nil && group == s.DH.Group {
					return errors.New("peer requested current DH group")
				}
				allowed := false
				for _, offer := range s.ikeOffers {
					for _, tr := range offer.Transforms {
						if tr.Type == ikev2.TransformTypeDH && uint16(tr.ID) == group {
							allowed = true
						}
					}
				}
				if !allowed {
					return errors.New("peer requested unoffered DH group")
				}
				s.initRetryDH = group
				s.SPIr = 0
				return errRetryDH
			}
			if v.NotifyType == ikev2.COOKIE {
				if err := s.handleCookie(v.NotifyData); err != nil {
					return err
				}
				return ErrCookieRequired
			}
			if v.NotifyType == ikev2.NAT_DETECTION_SOURCE_IP {
				natSrc = v.NotifyData
			}
			if v.NotifyType == ikev2.NAT_DETECTION_DESTINATION_IP {
				natDst = v.NotifyData
			}
			// IKE Fragmentation (RFC 7383)
			if v.NotifyType == ikev2.IKEV2_FRAGMENTATION_SUPPORTED {
				s.fragmentationSupported = true
				s.Logger.Info("ePDG 支持 IKE Fragmentation")
			}
			// 检查错误，如 NO_PROPOSAL_CHOSEN
			if v.NotifyType == 14 { // NO_PROPOSAL_CHOSEN
				return errors.New("服务器拒绝了提议 (NO_PROPOSAL_CHOSEN)")
			}
			// RFC 5685: REDIRECT
			if v.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(v.NotifyData)
				if err != nil {
					s.Logger.Warn("解析 REDIRECT 数据失败", logger.Err(err))
				} else {
					_ = addr
					return peerAuthError("unauthenticated SA_INIT redirect is not accepted")
				}
			}
		}
	}

	if saPayload == nil || kePayload == nil || noncePayload == nil {
		return errors.New("SA_INIT 响应中缺少强制性载荷")
	}
	if s.SPIr == 0 {
		return errors.New("SA_INIT responder SPI is zero")
	}

	s.nr = noncePayload.NonceData

	if len(natSrc) > 0 && len(natDst) > 0 {
		localPort := s.cfg.LocalPort
		if localPort == 0 {
			if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
				localPort = lp.LocalPort()
			}
		}
		remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
		remotePort := s.cfg.EpDGPort
		if remotePort == 0 {
			remotePort = 500
		}
		if ep, ok := s.socket.(interface {
			LocalIP() net.IP
			RemoteIP() net.IP
			RemotePort() int
		}); ok {
			if rip := ep.RemoteIP(); rip != nil {
				if v4 := rip.To4(); v4 != nil {
					remoteIP = v4
				}
			}
			if rp := ep.RemotePort(); rp != 0 {
				remotePort = uint16(rp)
			}
		}

		localIP := net.ParseIP(s.cfg.LocalAddr).To4()
		if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
			if lip := ep.LocalIP(); lip != nil {
				if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
					localIP = v4
				}
			}
		}
		expNatSrc := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, localIP, localPort)
		expNatDst := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, remoteIP, remotePort)

		natDetected := !bytes.Equal(natSrc, expNatSrc) || !bytes.Equal(natDst, expNatDst)
		if natDetected {
			if !s.cfg.DisableSwitchToNATTPort {
				if setter, ok := s.socket.(interface{ SetRemotePort(int) }); ok {
					setter.SetRemotePort(4500)
				}
				s.Logger.Debug("检测到 NAT，切换到 UDP 4500")
			} else {
				s.Logger.Debug("检测到 NAT，运营商模板要求保持当前 ePDG 端口")
			}
			s.startNATKeepalive(s.effectiveNATTKeepaliveInterval())
		}
	}

	// 处理 SA 选择 (简化: 假设服务器接受了我们的提议)
	// 我们应该解析 `saPayload.Proposals[0]` 以查看选择了什么。
	// 获取转换。
	selProp, err := ikev2.ValidateSelectedProposal(saPayload, s.ikeOffers)
	if err != nil {
		return fmt.Errorf("IKE SA proposal: %w", err)
	}
	var prfID uint16
	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16

	for _, t := range selProp.Transforms {
		switch t.Type {
		case ikev2.TransformTypeEncr:
			encrID = uint16(t.ID)
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		case ikev2.TransformTypeInteg:
			integID = uint16(t.ID)
		case ikev2.TransformTypePRF:
			prfID = uint16(t.ID)
		case ikev2.TransformTypeDH:
			dhID = uint16(t.ID)
		}
	}

	if s.DH == nil || dhID != s.DH.Group || uint16(kePayload.DHGroup) != dhID {
		return errors.New("responder DH/KE group differs from initiator key exchange")
	}
	s.Logger.Debug("ePDG_SA_INIT: IKE SA 算法协商成功",
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.Int("encr_key_bits", encrKeyLenBits),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.String("prf", ikev2.PRFToString(prfID)),
		logger.String("dh", ikev2.DHToString(dhID)),
	)

	// 设置加密实例
	s.PRFAlg, err = crypto.GetPRF(prfID)
	if err != nil {
		return fmt.Errorf("选择了不支持的 PRF: %d", prfID)
	}
	minNonce := s.PRFAlg.KeyLen() / 2
	if minNonce < 16 {
		minNonce = 16
	}
	if len(s.nr) < minNonce || len(s.nr) > 256 || len(s.ni) < minNonce || len(s.ni) > 256 {
		return errors.New("IKE nonce length violates negotiated PRF requirements")
	}

	s.EncAlg, err = crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("选择了不支持的 Encr: %d", encrID)
	}
	s.ikeEncrID = encrID
	s.ikeIsAEAD = encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	if s.ikeIsAEAD {
		s.ikeIntegID = 0
		s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(0)
	} else {
		s.ikeIntegID = integID
		s.IntegAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("选择了不支持的 Integ: %d", integID)
		}
	}

	// 计算共享密钥
	if _, err := s.DH.ComputeSharedSecret(kePayload.KEData); err != nil {
		return fmt.Errorf("DH 计算失败: %v", err)
	}

	// 计算密钥
	s.Logger.Debug("正在生成密钥材料")
	if err := s.GenerateIKESAKeys(s.nr); err != nil {
		return err
	}

	s.sendCookie = false
	s.ikeInitResponse = append([]byte(nil), data...)
	return nil
}

func ParseRedirectData(data []byte) (string, error) {
	if len(data) < 1 {
		return "", errors.New("empty redirect data")
	}
	gwType := data[0]
	gwData := data[1:]

	switch gwType {
	case ikev2.RedirectGWIPv4: // IPv4
		if len(gwData) != 4 {
			return "", fmt.Errorf("invalid IPv4 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWIPv6: // IPv6
		if len(gwData) != 16 {
			return "", fmt.Errorf("invalid IPv6 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWFQDN: // FQDN
		return string(gwData), nil
	default:
		return "", fmt.Errorf("unknown gateway identity type: %d", gwType)
	}
}

// carrierCookieSA keeps the COOKIE notify body while using SA as the outer
// IKE payload type required by the 3HK ePDG retry exchange.
type carrierCookieSA struct{ *ikev2.EncryptedPayloadNotify }

func (*carrierCookieSA) Type() ikev2.PayloadType { return ikev2.SA }
