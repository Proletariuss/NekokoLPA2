package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
	"github.com/1239t/swu-go/pkg/sim"
)

func (s *Session) configurationRequest() (*ikev2.EncryptedPayloadCP, error) {
	wantIPv4, wantIPv6, err := s.cfg.requestedAddressFamilies()
	if err != nil {
		return nil, err
	}
	attributes := make([]*ikev2.CPAttribute, 0, 7)
	if wantIPv4 {
		attributes = append(attributes,
			&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP4_ADDRESS},
			&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP4_DNS},
			&ikev2.CPAttribute{Type: ikev2.P_CSCF_IP4_ADDRESS},
		)
	}
	if wantIPv6 {
		attributes = append(attributes,
			&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_ADDRESS},
			&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_DNS},
			&ikev2.CPAttribute{Type: ikev2.P_CSCF_IP6_ADDRESS},
			&ikev2.CPAttribute{Type: ikev2.ASSIGNED_PCSCF_IP6_ADDRESS},
		)
	}
	return &ikev2.EncryptedPayloadCP{CFGType: ikev2.CFG_REQUEST, Attributes: attributes}, nil
}

func (s *Session) buildIKEAuthInitPayloads() ([]ikev2.Payload, error) {
	s.responderInitialChecked = false
	s.responderCertificateVerified = false
	s.eapSuccessReceived = false
	s.responderIdentityBody = nil
	clear(s.MSK)
	s.MSK = nil
	// 载荷: IDi, SA, TS, TS, N(EAP_ONLY)

	// 1. IDi
	var nai string
	if s.cfg.IKELocalIdentifier != "" {
		nai = s.cfg.IKELocalIdentifier
		s.Logger.Info("IKE_AUTH: 使用运营商配置的本地标识")
	} else if identity := strings.TrimSpace(s.cfg.EAPIdentity); identity != "" {
		nai = identity
	} else {
		imsi, err := s.cfg.SIM.GetIMSI()
		if err != nil {
			return nil, err
		}
		nai = buildNAI(imsi, s.cfg)
	}
	idPayload := &ikev2.EncryptedPayloadID{
		IDType:      ikev2.ID_RFC822_ADDR,
		IDData:      []byte(nai),
		IsInitiator: true,
	}
	// AUTH must cover the IDi bytes actually sent, including carrier overrides
	// and cached fast-reauth identities. Never reconstruct them from IMSI later.
	clear(s.ikeAuthIdentityBody)
	s.ikeAuthIdentityBody = make([]byte, 4+len(idPayload.IDData))
	s.ikeAuthIdentityBody[0] = idPayload.IDType
	copy(s.ikeAuthIdentityBody[4:], idPayload.IDData)
	idrPayload := &ikev2.EncryptedPayloadID{
		IDType:      ikev2.ID_FQDN,
		IDData:      []byte(s.cfg.APN),
		IsInitiator: false,
	}

	// 1b. CP (CFG_REQUEST)
	cpPayload, err := s.configurationRequest()
	if err != nil {
		return nil, err
	}

	// 2. SA (Child SA)
	var spiBytes []byte
	if s.childSPI == 0 {
		var err error
		spiBytes, err = crypto.RandomBytes(4)
		if err != nil {
			return nil, err
		}
		s.childSPI = binary.BigEndian.Uint32(spiBytes)
	} else {
		spiBytes = make([]byte, 4)
		binary.BigEndian.PutUint32(spiBytes, s.childSPI)
	}

	// A configured list is authoritative and never merged with defaults.
	proposals, err := ikev2.BuildESPProposals(s.cfg.ESPProposals, spiBytes)
	if err != nil {
		return nil, err
	}
	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	// 3. TSi / TSr, restricted to the configured address families.
	wantIPv4, wantIPv6, err := s.cfg.requestedAddressFamilies()
	if err != nil {
		return nil, err
	}
	trafficSelectors := make([]*ikev2.TrafficSelector, 0, 2)
	if wantIPv4 {
		trafficSelectors = append(trafficSelectors, ikev2.NewTrafficSelectorIPV4(
			[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255},
			0, 65535,
		))
	}
	if wantIPv6 {
		ipv6Max := make(net.IP, net.IPv6len)
		for i := range ipv6Max {
			ipv6Max[i] = 0xff
		}
		trafficSelectors = append(trafficSelectors, ikev2.NewTrafficSelectorIPV6(net.IPv6zero, ipv6Max, 0, 65535))
	}
	tsPayloadI := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: trafficSelectors}
	tsPayloadR := &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: trafficSelectors}

	s.childOffers = proposals
	notifyPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.EAP_ONLY_AUTHENTICATION,
	}
	mobikePayload := &ikev2.EncryptedPayloadNotify{ProtocolID: 0, NotifyType: ikev2.MOBIKE_SUPPORTED}
	ticketReqPayload := &ikev2.EncryptedPayloadNotify{ProtocolID: 0, NotifyType: ikev2.TICKET_REQUEST}

	// RFC 7296 §2.4: INITIAL_CONTACT — 告知 ePDG 清除此身份关联的所有旧 IKE SA
	// 防止断网未发 DELETE 导致的僵尸半开隧道占用路由资源
	initialContactPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.INITIAL_CONTACT,
	}
	s.Logger.Debug("IKE_AUTH 已注入 INITIAL_CONTACT，要求 ePDG 清理旧隧道残留")

	payloads := []ikev2.Payload{idPayload, idrPayload}
	if s.cfg.ValidateRemoteCertificate {
		// Platform trust anchors are not enumerated here. An empty CA hash list
		// asks for any certificate, while normal chain/name/AUTH checks still
		// decide whether to trust it (RFC 4945 section 3.2.7.2).
		payloads = append(payloads, &ikev2.EncryptedPayloadCertReq{Encoding: ikev2.CertReqX509Signature})
	}
	payloads = append(payloads, cpPayload, saPayload, tsPayloadI, tsPayloadR, mobikePayload, initialContactPayload)
	if !s.cfg.ValidateRemoteCertificate {
		payloads = append(payloads, notifyPayload)
	}
	if s.canResumeAuthenticatedSession() {
		payloads = append(payloads, ticketReqPayload)
	}
	if s.cfg.deviceIdentityIsEnabled() {
		p, ok := s.cfg.SIM.(sim.IMEIProvider)
		if !ok {
			return payloads, nil
		}
		if imei, err := p.GetIMEI(); err == nil && imei != "" {
			data := append([]byte{0x01}, []byte(imei)...)
			payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
				ProtocolID: ikev2.ProtoIKE,
				NotifyType: ikev2.DEVICE_IDENTITY_3GPP,
				NotifyData: data,
			})
			payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
				ProtocolID: ikev2.ProtoIKE,
				NotifyType: ikev2.DEVICE_IDENTITY,
				NotifyData: data,
			})
		}
	}
	return payloads, nil
}

// handleEAP 处理从 ePDG 接收到的 EAP (Extensible Authentication Protocol) 报文。
// 该方法负责解析 EAP 载荷，并根据 EAP 类型（如 Identity, AKA Challenge 等）生成相应的响应载荷。
func (s *Session) handleEAP(eapRaw []byte) ([]ikev2.Payload, error) {
	if err := s.authContextError(); err != nil {
		return nil, err
	}
	if !validInboundEAP(eapRaw) {
		return nil, authFailure(AuthFailureInvalidEAP)
	}
	pkt, err := eap.Parse(eapRaw)
	if err != nil {
		return nil, authFailure(AuthFailureInvalidEAP)
	}
	if pkt.Code == eap.CodeFailure {
		return nil, authFailure(AuthFailureEAP)
	}

	if pkt.Code == eap.CodeSuccess {
		if err := s.authContextError(); err != nil {
			return nil, err
		}
		if len(s.MSK) < 64 {
			return nil, peerAuthError("EAP Success before mutual AKA authentication")
		}
		s.eapSuccessReceived = true
		s.reportProgress("eap_success")
		// EAP 成功！
		s.Logger.Debug("收到 EAP Success")
		// 在 IKE_AUTH 中，EAP Success 通常伴随着服务器的 AUTH 载荷。
		// 这在 session.go 的循环中处理。
		// 我们这里只返回 nil 以表示不需要 EAP 响应。
		return nil, nil // Stop EAP loop
	}

	if pkt.Code != eap.CodeRequest {
		return nil, fmt.Errorf("unexpected EAP Code: %d", pkt.Code)
	}
	if (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && pkt.Subtype == eap.SubtypeReauthentication {
		return nil, peerAuthError("fast reauthentication is unavailable; full AKA authentication is required")
	}
	if pkt.Type == eap.TypeIdentity || pkt.Subtype == eap.SubtypeIdentity {
		s.reportProgress("eap_identity")
	} else {
		s.reportProgress("eap_aka")
	}
	var credentialEpoch uint64
	if s.cfg.RequireFullEAP && (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) &&
		(pkt.Subtype == eap.SubtypeChallenge || pkt.Subtype == eap.SubtypeReauthentication) {
		credentialEpoch = s.beginEAPDirectExchange()
		if pkt.Subtype == eap.SubtypeReauthentication {
			return nil, errors.New("3 HK direct IMS authorization requires a fresh full EAP-AKA exchange")
		}
	}

	// 处理身份请求
	if pkt.Type == eap.TypeIdentity {
		s.resetEAPIdentityState()
		// 响应身份：若持有快速重连假名则优先使用，绕过物理 SIM 硬鉴权
		var identity string
		useFastReauth := s.canUseFastReauth()
		if useFastReauth {
			identity = s.fastReauthCtx.ReauthID
			s.Logger.Info("EAP Identity: 使用缓存的 Fast Re-auth 假名替代 IMSI")
		} else {
			identity = s.permanentEAPIdentity()
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeIdentity,
			Data:       []byte(identity),
		}

		encodedResponse := respPkt.Encode()
		checkcode := identityTranscriptCheckcode(eapRaw, encodedResponse)
		var exchangeID string
		if !useFastReauth {
			if provider, ok := s.cfg.SIM.(EAPIdentityResponseProvider); ok {
				result, handled, providerErr := provider.RespondEAPIdentity(eapRaw, []byte(identity))
				if handled {
					if providerErr != nil {
						return nil, fmt.Errorf("native EAP Identity response failed: %w", providerErr)
					}
					response, parseErr := eap.Parse(result.Packet)
					if parseErr != nil || !validEAPPacketLength(result.Packet) ||
						response.Code != eap.CodeResponse || response.Identifier != pkt.Identifier ||
						response.Type != eap.TypeIdentity || !bytes.Equal(response.Data, []byte(identity)) ||
						!validEAPExchangeID(result.ExchangeID) || len(result.Checkcode) != sha1.Size ||
						!hmac.Equal(result.Checkcode, checkcode[:]) {
						s.releaseEAPIdentityExchange(result.ExchangeID)
						return nil, errors.New("native EAP Identity response does not match the request")
					}
					encodedResponse = result.Packet
					exchangeID = result.ExchangeID
				}
			}
		}
		if exchangeID == "" {
			checkcode = identityTranscriptCheckcode(eapRaw, encodedResponse)
		}
		s.eapIdentityExchangeID = exchangeID
		s.eapIdentityCheckcode = checkcode
		s.eapIdentityCheckcodeValid = true
		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: encodedResponse}
		return []ikev2.Payload{eapPayload}, nil
	}

	// RFC 4187 permits the peer identity to be requested inside EAP-AKA,
	// independently of the outer EAP-Identity exchange. 3HK/ePDG uses this
	// AKA-Identity subtype (23/5) before sending the SIM challenge.
	if (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && pkt.Subtype == eap.SubtypeIdentity {
		return s.buildEAPAKAIdentityResponse(pkt, eapRaw)
	}

	// 处理 AKA 挑战
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeChallenge {
		s.Logger.Info("收到 EAP-AKA Challenge (4G 模式)")
		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atRand, ok1 := attrs[eap.AT_RAND]
		atAutn, ok2 := attrs[eap.AT_AUTN]
		atMac, ok3 := attrs[eap.AT_MAC]

		// DEBUG: Print all received attributes
		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Debug("Received EAP-AKA Challenge attributes", logger.Any("keys", keys))

		if !ok1 || !ok2 {
			return nil, errors.New("AKA 挑战中缺少 RAND 或 AUTN")
		}
		if !ok3 {
			return nil, errors.New("AKA 挑战中缺少 AT_MAC")
		}

		// During the Rust migration, an opt-in SIM provider may own this
		// standard EAP-AKA Challenge response. Preserve Go's fast-reauth cache
		// path whenever the server supplies a next reauthentication identity.
		if _, hasNextReauthID := attrs[eap.AT_NEXT_REAUTH_ID]; hasNextReauthID {
			s.releaseEAPIdentityExchange(s.eapIdentityExchangeID)
			s.eapIdentityExchangeID = ""
		} else if provider, ok := s.cfg.SIM.(EAPAKAResponseProvider); ok && s.eapIdentityExchangeID != "" {
			mode, modeErr := s.cfg.normalizedAKAChallengeMode()
			if modeErr != nil {
				return nil, modeErr
			}
			exchangeID := s.eapIdentityExchangeID
			result, handled, providerErr := provider.RespondEAPAKA(eapRaw, exchangeID, mode)
			acceptedKeys, acceptedContinuation := false, false
			defer func() {
				if !acceptedKeys {
					clear(result.MSK)
					clear(result.KAut)
				}
				if !acceptedContinuation {
					s.releaseEAPIdentityExchange(result.NextExchangeID)
				}
			}()
			s.releaseEAPIdentityExchange(exchangeID)
			s.eapIdentityExchangeID = ""
			if handled {
				if providerErr != nil {
					return nil, fmt.Errorf("native EAP-AKA response failed: %w", providerErr)
				}
				response, parseErr := eap.Parse(result.Packet)
				if parseErr != nil || !validEAPPacketLength(result.Packet) ||
					response.Code != eap.CodeResponse || response.Identifier != pkt.Identifier ||
					response.Type != eap.TypeAKA {
					return nil, errors.New("native EAP-AKA response does not match the challenge")
				}
				switch result.Outcome {
				case "success":
					if response.Subtype != eap.SubtypeChallenge || len(result.MSK) != 64 || len(result.KAut) != 16 || result.NextExchangeID != "" {
						return nil, errors.New("native EAP-AKA success response is incomplete")
					}
					s.MSK = result.MSK
					s.eapKAut = result.KAut
					acceptedKeys = true
				case "synchronization_failure":
					if response.Subtype != eap.SubtypeSyncFailure || len(result.MSK)+len(result.KAut) != 0 ||
						!validEAPExchangeID(result.NextExchangeID) || result.NextExchangeID == exchangeID {
						return nil, errors.New("native EAP-AKA synchronization response is invalid")
					}
					s.eapIdentityExchangeID = result.NextExchangeID
					acceptedContinuation = true
				default:
					return nil, errors.New("native EAP-AKA provider returned an unsupported outcome")
				}
				return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: result.Packet}}, nil
			}
		}

		randVal, err := eapAKAAttrTail16(atRand.Value)
		if err != nil {
			return nil, err
		}
		autnVal, err := eapAKAAttrTail16(atAutn.Value)
		if err != nil {
			return nil, err
		}

		// 运行 SIM 算法
		res, ck, ik, auts, err := s.cfg.SIM.CalculateAKA(randVal, autnVal)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) {
				// 发送同步失败
				// 载荷: EAP-Response/AKA-Sync-Failure
				// 属性: AT_AUTS
				return s.buildEAPSyncFailure(pkt.Identifier, auts)
			}
			return nil, fmt.Errorf("SIM AKA failed: %v", err)
		}

		identity := []byte(s.permanentEAPIdentity())

		derive := func(order int) (kAut []byte, msk []byte, mk []byte, err error) {
			h := sha1.New()
			h.Write(identity)
			if order == 0 {
				h.Write(ik)
				h.Write(ck)
			} else {
				h.Write(ck)
				h.Write(ik)
			}
			mk = h.Sum(nil)

			keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
			return keyMat[16:32], keyMat[32:96], mk, nil
		}

		tryOrders := []int{0, 1}
		var kAut []byte
		var msk []byte
		var macVerified bool
		var lastMacErr error
		recvMac, err := eapAKAAttrTail16(atMac.Value)
		if err != nil {
			return nil, err
		}
		for _, order := range tryOrders {
			kAutTry, mskTry, _, err := derive(order)
			if err != nil {
				return nil, err
			}
			if err := verifyEAPAKAMAC(eapRaw, pkt.Data, kAutTry, recvMac); err == nil {
				kAut = kAutTry
				msk = mskTry
				macVerified = true
				break
			} else {
				lastMacErr = err
			}
		}
		if !macVerified {
			return nil, lastMacErr
		}
		if s.cfg.RequireFullEAP {
			if err := s.saveEAPDirectCredentials(credentialEpoch, res, randVal, autnVal); err != nil {
				return nil, err
			}
		}

		s.MSK = msk
		s.eapKAut = append([]byte(nil), kAut...)

		// 构造响应：AT_RES [+ AT_RESULT_IND] + AT_MAC（对齐 SimAdmin eap_aka.rs）
		respAttrs := []byte{}

		// AT_RES
		resBits := make([]byte, 2)
		binary.BigEndian.PutUint16(resBits, uint16(len(res)*8))
		resValue := append(resBits, res...)
		atRes := &eap.Attribute{Type: eap.AT_RES, Value: resValue}
		respAttrs = append(respAttrs, atRes.Encode()...)

		if _, ok := attrs[eap.AT_RESULT_IND]; ok {
			atResultInd := &eap.Attribute{Type: eap.AT_RESULT_IND, Value: []byte{0, 0}}
			respAttrs = append(respAttrs, atResultInd.Encode()...)
		}

		checkcode, err := s.eapAKACheckcodeResponse(attrs)
		if err != nil {
			return nil, err
		}
		if checkcode != nil {
			respAttrs = append(respAttrs, checkcode.Encode()...)
		}

		// AT_MAC
		// 初始值为 16 字节零
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		macOffset := len(respAttrs) // AT_MAC 属性开始的位置
		respAttrs = append(respAttrs, respMacAttr.Encode()...)

		// Construct EAP Packet
		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKA,
			Subtype:    eap.SubtypeChallenge,
			Data:       respAttrs,
		}

		eapBytes := respPkt.Encode()

		// 计算 MAC
		// EAP 数据包上的 HMAC-SHA1-128 (前 16 字节)
		mac := hmac.New(sha1.New, kAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 放回数据包中 (在 macOffset + 2 + ??)。
		// 属性头是 2 字节。值头在内部？不。
		// 属性: Type(1), Len(1), Value...
		// AT_MAC 的值是 16 字节。
		// eapBytes 中的偏移量: Header(8) + macOffset + 2 (AttrHdr) = 10 + macOffset
		// 等等，EAP 头是 4 (Code, ID, Len). Type(1), Sub(1), Res(2). 总共 8。
		// 所以数据从 8 开始。
		macPos := 8 + macOffset + 4
		copy(eapBytes[macPos:], fullMac[:16])

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}

		// 捕获 AT_NEXT_REAUTH_ID：若服务端下发了假名，则缓存供下次断线快连用
		if atNextReauthID, ok := attrs[eap.AT_NEXT_REAUTH_ID]; ok && s.canUseFastReauth() && len(atNextReauthID.Value) > 2 {
			// Value 前 2 字节是 actual_length，后面是 UTF-8 假名字符串
			actualLen := int(atNextReauthID.Value[0])<<8 | int(atNextReauthID.Value[1])
			if actualLen > 0 && actualLen+2 <= len(atNextReauthID.Value) {
				reauthID := string(atNextReauthID.Value[2 : 2+actualLen])
				s.Logger.Info("捕获到 EAP-AKA 的快速重连假名 (AT_NEXT_REAUTH_ID)",
					logger.String("reauthID", reauthID))

				// 派生加密密钥 K_encr (MK 的前 16 字节)
				identity := []byte(s.permanentEAPIdentity())
				h := sha1.New()
				h.Write(identity)
				h.Write(ik)
				h.Write(ck)
				mk := h.Sum(nil)
				keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
				kEncr := keyMat[:16]

				if s.fastReauthCtx != nil {
					s.fastReauthCtx.SaveReauthData(reauthID, mk, kEncr, kAut)
				}
				if s.cfg.OnFastReauthUpdate != nil {
					s.cfg.OnFastReauthUpdate(reauthID, mk, kAut, kEncr)
				}
			} else {
				// Failed to parse Actual Length or corrupted Value
				s.Logger.Warn("解析 AT_NEXT_REAUTH_ID 失败：长度校验不通过", logger.Int("valueLen", len(atNextReauthID.Value)), logger.Int("actualLen", actualLen))
			}
		}

		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA' Challenge (RFC 5448, 5G 核心网接入)
	if pkt.Type == eap.TypeAKAPrime && pkt.Subtype == eap.SubtypeChallenge {
		if err := validatePrimeAttributes(pkt.Data); err != nil {
			return nil, peerAuthError("AKA' attributes: %v", err)
		}
		s.Logger.Info("收到 EAP-AKA' Challenge (5G 模式)")

		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}

		atRand, ok1 := attrs[eap.AT_RAND]
		atAutn, ok2 := attrs[eap.AT_AUTN]
		atMac, ok3 := attrs[eap.AT_MAC]
		atKdfInput, ok4 := attrs[eap.AT_KDF_INPUT]
		atKdf, ok5 := attrs[eap.AT_KDF]
		checkcode, err := s.primeCheckcodeResponse(attrs)
		if err != nil {
			return nil, peerAuthError("AKA' checkcode: %v", err)
		}

		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Debug("Received EAP-AKA' Challenge attributes", logger.Any("keys", keys))

		if !ok1 || !ok2 {
			return nil, errors.New("AKA' Challenge 缺少 RAND 或 AUTN")
		}
		if !ok3 {
			return nil, errors.New("AKA' Challenge 缺少 AT_MAC")
		}

		// RFC 5448 requires explicit KDF and the expected SWu access name.
		if !ok4 || len(atKdfInput.Value) < 3 || !ok5 || len(atKdf.Value) != 2 {
			return nil, peerAuthError("AKA' missing or invalid KDF attributes")
		}
		nameLen := int(binary.BigEndian.Uint16(atKdfInput.Value[:2]))
		if nameLen == 0 || nameLen > len(atKdfInput.Value)-2 {
			return nil, peerAuthError("AKA' malformed network name")
		}
		networkName := string(atKdfInput.Value[2 : 2+nameLen])
		if networkName != "WLAN" {
			return nil, peerAuthError("AKA' network name does not match SWu WLAN access")
		}
		kdfID := binary.BigEndian.Uint16(atKdf.Value)
		if kdfID != 1 {
			s.Logger.Warn("AKA' 对端提出非标 KDF，我们只支持 KDF 1 (HMAC-SHA-256)",
				logger.Int("kdf_id", int(kdfID)))
			return nil, fmt.Errorf("unsupported AKA' KDF: %d", kdfID)
		}

		randVal, err := eapAKAAttrTail16(atRand.Value)
		if err != nil {
			return nil, err
		}
		autnVal, err := eapAKAAttrTail16(atAutn.Value)
		if err != nil {
			return nil, err
		}

		// 运行 SIM 算法 (底层 AT+CSIM 与 4G 完全一样)
		res, ck, ik, auts, err := s.cfg.SIM.CalculateAKA(randVal, autnVal)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) {
				return s.buildEAPSyncFailure(pkt.Identifier, auts, eap.TypeAKAPrime)
			}
			return nil, fmt.Errorf("SIM AKA failed: %v", err)
		}

		prime, err := deriveAKAPrime(ck, ik, autnVal, networkName, []byte(s.permanentEAPIdentity()))
		if err != nil {
			return nil, peerAuthError("AKA' key derivation: %v", err)
		}
		defer clear(prime.ckPrime)
		defer clear(prime.ikPrime)
		defer clear(prime.keyMaterial)
		keyMat := prime.keyMaterial
		kAut := keyMat[16:48]
		msk := keyMat[80:144]

		// MAC 校验（使用 HMAC-SHA256-128）
		recvMac, err := eapAKAAttrTail16(atMac.Value)
		if err != nil {
			return nil, err
		}
		if err := verifyEAPAKAPrimeMAC(eapRaw, pkt.Data, kAut, recvMac); err != nil {
			return nil, fmt.Errorf("AKA' MAC 校验失败: %v", err)
		}
		if s.cfg.RequireFullEAP {
			if err := s.saveEAPDirectCredentials(credentialEpoch, res, randVal, autnVal); err != nil {
				return nil, err
			}
		}

		s.MSK = append([]byte(nil), msk...)
		s.eapKAut = append([]byte(nil), kAut...)

		// 构造 AKA' 响应
		respAttrs := []byte{}
		if checkcode != nil {
			respAttrs = append(respAttrs, checkcode.Encode()...)
		}

		// AT_RES
		resBits := make([]byte, 2)
		binary.BigEndian.PutUint16(resBits, uint16(len(res)*8))
		resValue := append(resBits, res...)
		atRes := &eap.Attribute{Type: eap.AT_RES, Value: resValue}
		respAttrs = append(respAttrs, atRes.Encode()...)

		// AT_MAC (占位 16 字节零)
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		macOffset := len(respAttrs)
		respAttrs = append(respAttrs, respMacAttr.Encode()...)

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKAPrime,
			Subtype:    eap.SubtypeChallenge,
			Data:       respAttrs,
		}

		eapBytes := respPkt.Encode()

		// 计算响应 MAC: HMAC-SHA-256-128 (取前 16 字节)
		respMacCalc := hmac.New(sha256.New, kAut)
		respMacCalc.Write(eapBytes)
		fullRespMac := respMacCalc.Sum(nil)

		macPos := 8 + macOffset + 4
		copy(eapBytes[macPos:], fullRespMac[:16])

		s.Logger.Info("EAP-AKA' Challenge 响应构建完成 (5G KDF-SHA256)")

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}
		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA Notification (RFC 4187 §9.3.1；O2 等运营商可能用 subtype 12)
	if (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && s.isAKANotification(pkt) {
		return s.buildEAPAKANotificationResponse(pkt, eapRaw)
	}

	return nil, fmt.Errorf("不支持的 EAP 类型/子类型: %d/%d", pkt.Type, pkt.Subtype)
}

func (s *Session) buildEAPAKAIdentityResponse(pkt *eap.EAPPacket, request []byte) ([]ikev2.Payload, error) {
	attrs, err := eap.ParseAttributes(pkt.Data)
	if err != nil {
		return nil, fmt.Errorf("解析 EAP-AKA Identity 请求: %w", err)
	}

	requestType := uint8(0)
	for _, candidate := range []uint8{eap.AT_PERMANENT_ID_REQ, eap.AT_FULLAUTH_ID_REQ, eap.AT_ANY_ID_REQ} {
		if _, ok := attrs[candidate]; !ok {
			continue
		}
		if requestType != 0 {
			return nil, errors.New("EAP-AKA Identity 请求包含多个身份请求属性")
		}
		requestType = candidate
	}
	if requestType == 0 {
		return nil, errors.New("EAP-AKA Identity 请求缺少身份请求属性")
	}
	if s.eapAKAIdentityRequestCount >= 3 {
		return nil, errors.New("EAP-AKA Identity 请求轮次超过上限")
	}
	if s.eapAKAIdentityRequestCount > 0 {
		previous := s.eapAKAIdentityLastRequest
		if requestType == eap.AT_ANY_ID_REQ || previous == eap.AT_PERMANENT_ID_REQ ||
			(previous == eap.AT_FULLAUTH_ID_REQ && requestType != eap.AT_PERMANENT_ID_REQ) {
			return nil, errors.New("EAP-AKA Identity 请求顺序无效")
		}
	}
	s.eapAKAIdentityRequestCount++
	s.eapAKAIdentityLastRequest = requestType

	identity := ""
	if requestType == eap.AT_ANY_ID_REQ && s.canUseFastReauth() {
		identity = s.fastReauthCtx.ReauthID
	} else {
		identity = s.permanentEAPIdentity()
	}
	if identity == "" {
		return nil, errors.New("EAP-AKA Identity 请求无法取得有效身份")
	}
	if pkt.Type == eap.TypeAKAPrime && s.cfg.EAPIdentity == "" {
		imsi, err := s.cfg.SIM.GetIMSI()
		if err != nil {
			return nil, err
		}
		if identity == buildNAI(imsi, s.cfg) && strings.HasPrefix(identity, "0") {
			identity = "6" + identity[1:]
			s.eapPermanentIdentity = identity
		}
	}

	// AT_IDENTITY contains the actual byte length followed by the identity;
	// Attribute.Length itself is separately encoded in 32-bit words.
	identityValue := make([]byte, 2+len(identity))
	binary.BigEndian.PutUint16(identityValue[:2], uint16(len(identity)))
	copy(identityValue[2:], identity)
	identityAttr := (&eap.Attribute{Type: eap.AT_IDENTITY, Value: identityValue}).Encode()
	response := (&eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: pkt.Identifier,
		Type:       pkt.Type,
		Subtype:    eap.SubtypeIdentity,
		Data:       identityAttr,
	}).Encode()
	if pkt.Type == eap.TypeAKAPrime {
		s.eapPrimeIdentityTranscript = append(s.eapPrimeIdentityTranscript, request...)
		s.eapPrimeIdentityTranscript = append(s.eapPrimeIdentityTranscript, response...)
	}
	s.eapIdentityCheckcode = identityTranscriptCheckcode(request, response)
	s.eapIdentityCheckcodeValid = true
	s.Logger.Info("回复 EAP-AKA Identity 请求", logger.Int("request_attribute", int(requestType)))
	return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: response}}, nil
}

// Classic AT_CHECKCODE support is optional (RFC 4187 section 10.13).
// Only minimal/omit are supported; reject legacy modes even when this helper
// is called without Connect's configuration validation. AT_MAC is mandatory.
func (s *Session) eapAKACheckcodeResponse(_ map[uint8]*eap.Attribute) (*eap.Attribute, error) {
	_, err := s.cfg.normalizedAKAChallengeMode()
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func identityTranscriptCheckcode(request, response []byte) [sha1.Size]byte {
	hasher := sha1.New()
	_, _ = hasher.Write(request)
	_, _ = hasher.Write(response)
	var digest [sha1.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func validEAPExchangeID(exchangeID string) bool {
	if len(exchangeID) != 64 {
		return false
	}
	for _, value := range exchangeID {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	return true
}

func eapAKAAttrTail16(v []byte) ([]byte, error) {
	if len(v) < 16 {
		return nil, errors.New("AKA 属性长度不足")
	}
	return v[len(v)-16:], nil
}

func verifyEAPAKAMAC(eapRaw []byte, attrsData []byte, kAut []byte, recvMac []byte) error {
	macAttrOffset, ok := findEAPAttrOffset(attrsData, eap.AT_MAC)
	if !ok {
		return errors.New("未找到 AT_MAC 的偏移量")
	}
	macPos := 8 + macAttrOffset + 4
	if macPos < 0 || macPos+16 > len(eapRaw) {
		return errors.New("AT_MAC 偏移量越界")
	}

	tmp := make([]byte, len(eapRaw))
	copy(tmp, eapRaw)
	zero := make([]byte, 16)
	copy(tmp[macPos:macPos+16], zero)

	mac := hmac.New(sha1.New, kAut)
	mac.Write(tmp)
	fullMac := mac.Sum(nil)

	if !hmac.Equal(fullMac[:16], recvMac) {
		return errors.New("EAP-AKA AT_MAC 校验失败")
	}
	return nil
}

func findEAPAttrOffset(data []byte, attrType uint8) (int, bool) {
	offset := 0
	for offset+2 <= len(data) {
		t := data[offset]
		l := int(data[offset+1]) * 4
		if l == 0 || offset+l > len(data) {
			return 0, false
		}
		if t == attrType {
			return offset, true
		}
		offset += l
	}
	return 0, false
}

func (s *Session) isAKANotification(pkt *eap.EAPPacket) bool {
	return pkt != nil && (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && pkt.Subtype == eap.SubtypeNotificationAlt
}

func (s *Session) buildEAPAKANotificationResponse(pkt *eap.EAPPacket, wire ...[]byte) ([]ikev2.Payload, error) {
	attrs, err := eap.ParseAttributes(pkt.Data)
	if err != nil {
		return nil, err
	}
	notifCode := uint16(0)
	if atNotif, ok := attrs[eap.AT_NOTIFICATION]; ok {
		if len(atNotif.Value) != 2 {
			return nil, errors.New("EAP-AKA notification 属性长度无效")
		}
		notifCode = uint16(atNotif.Value[0])<<8 | uint16(atNotif.Value[1])
	} else {
		return nil, errors.New("EAP-AKA notification 缺少 AT_NOTIFICATION")
	}
	macRequired := notifCode&0x4000 == 0
	s.Logger.Info("收到 EAP-AKA Notification",
		logger.Int("subtype", int(pkt.Subtype)),
		logger.Int("code", int(notifCode)),
		logger.Bool("mac_required", macRequired),
		logger.Bool("success", notifCode&0x8000 != 0))

	if macRequired && len(s.eapKAut) == 0 {
		return nil, errors.New("EAP-AKA notification 需要 MAC，但 K_aut 不可用")
	}
	macHash := sha1.New
	if pkt.Type == eap.TypeAKAPrime {
		macHash = sha256.New
	}
	if macRequired {
		atMAC, ok := attrs[eap.AT_MAC]
		if !ok {
			return nil, peerAuthError("protected EAP notification is missing MAC")
		}
		recv, err := eapAKAAttrTail16(atMAC.Value)
		if err != nil {
			return nil, err
		}
		raw := pkt.Encode()
		if len(wire) > 0 {
			raw = wire[0]
		}
		if pkt.Type == eap.TypeAKAPrime {
			err = verifyEAPAKAPrimeMAC(raw, pkt.Data, s.eapKAut, recv)
		} else {
			err = verifyEAPAKAMAC(raw, pkt.Data, s.eapKAut, recv)
		}
		if err != nil {
			return nil, peerAuthError("EAP notification MAC mismatch")
		}
	}

	respAttrs := []byte{}
	var macAttrOffset int
	if macRequired {
		macAttrOffset = len(respAttrs)
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		respAttrs = append(respAttrs, respMacAttr.Encode()...)
	}

	respPkt := &eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: pkt.Identifier,
		Type:       pkt.Type,
		Subtype:    eap.SubtypeNotificationAlt,
		Data:       respAttrs,
	}
	eapBytes := respPkt.Encode()

	if macRequired {
		macPos := 8 + macAttrOffset + 4
		if macPos+16 > len(eapBytes) {
			return nil, errors.New("EAP-AKA notification MAC 偏移越界")
		}
		mac := hmac.New(macHash, s.eapKAut)
		mac.Write(eapBytes)
		copy(eapBytes[macPos:macPos+16], mac.Sum(nil)[:16])
	}

	return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}}, nil
}

func (s *Session) buildEAPSyncFailure(id uint8, auts []byte, methods ...uint8) ([]ikev2.Payload, error) {
	if len(auts) != 14 {
		return nil, errors.New("invalid AUTS length")
	}
	method := uint8(eap.TypeAKA)
	if len(methods) > 0 {
		method = methods[0]
	}
	// AT_AUTS
	atAuts := &eap.Attribute{Type: eap.AT_AUTS, Value: auts}
	attrs := atAuts.Encode()
	if method == eap.TypeAKAPrime {
		attrs = append(attrs, (&eap.Attribute{Type: eap.AT_KDF, Value: []byte{0, 1}}).Encode()...)
	}

	respPkt := &eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: id,
		Type:       method,
		Subtype:    eap.SubtypeSyncFailure,
		Data:       attrs,
	}

	eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: respPkt.Encode()}
	return []ikev2.Payload{eapPayload}, nil
}

func (s *Session) sendIKEAuthEAP(payloads []ikev2.Payload) error {
	// 包装载荷在 SK 中
	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) sendIKEAuthFinal() error {
	payloads, err := s.buildIKEAuthFinalPayloads()
	if err != nil {
		return err
	}

	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}

	return s.socket.SendIKE(data)
}

func (s *Session) buildIKEAuthFinalPayloads() ([]ikev2.Payload, error) {
	if err := s.authContextError(); err != nil {
		return nil, err
	}
	// Message 6: SK { AUTH }
	// AUTH = prf( prf(MSK, "Key Pad for IKEv2"), <SignedOctets> )
	// SignedOctets = RealMessage1 | NonceR_Data | prf(SK_pi, IDi_Body)

	if len(s.MSK) < 64 {
		return nil, errors.New("MSK 不可用作 AUTH")
	}

	// 1. 计算 Auth Key
	keyPad := []byte("Key Pad for IKEv2")
	prf := s.PRFAlg
	if prf == nil {
		return nil, errors.New("PRF 不可用")
	}

	mac := hmac.New(prf.Hash, s.MSK)
	mac.Write(keyPad)
	authKey := mac.Sum(nil)
	defer clear(authKey)

	// 2. 计算签名八位字节
	// 2a. RealMessage1 (IKE_SA_INIT 请求)
	// 我们把它存储在 s.msgBuffer 了吗？
	// 确保 s.msgBuffer 正是发送的内容。
	if len(s.msgBuffer) == 0 {
		return nil, errors.New("SA_INIT 请求未存储")
	}

	// 2b. NonceR
	if len(s.nr) == 0 {
		return nil, errors.New("NonceR 不可用")
	}

	// 2c. prf(SK_pi, IDi_Body)
	idiBody := s.ikeAuthIdentityBody
	if len(idiBody) < 5 {
		return nil, errors.New("首次 IKE_AUTH 身份未保存，无法生成最终 AUTH")
	}

	macID := hmac.New(prf.Hash, s.Keys.SK_pi)
	macID.Write(idiBody)
	idHash := macID.Sum(nil)

	// 组合八位字节签名
	macAuth := hmac.New(prf.Hash, authKey)
	macAuth.Write(s.msgBuffer)
	macAuth.Write(s.nr)
	macAuth.Write(idHash)
	authData := macAuth.Sum(nil)

	// 3. 构造 AUTH 载荷
	authPayload := &ikev2.EncryptedPayloadAuth{
		AuthMethod: ikev2.AuthMethodSharedKey, // 2 = Shared Key MIC
		AuthData:   authData,
	}
	payloads := []ikev2.Payload{authPayload}
	if s.cfg.CPInFinalAuth {
		cpPayload, err := s.configurationRequest()
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, cpPayload)
	}
	return payloads, nil
}

func (s *Session) handleIKEAuthFinalResp(data []byte) error {
	msgID, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return fmt.Errorf("解析 IKE_AUTH 最终响应失败: %v", err)
	}
	return s.handleIKEAuthFinalPayloads(msgID, payloads)
}

func (s *Session) handleIKEAuthFinalPayloads(msgID uint32, payloads []ikev2.Payload) (err error) {
	authenticated := false
	defer func() {
		diagnosticErr := err
		if authenticated && err != nil {
			diagnosticErr = &AuthFailureError{Code: AuthFailureChildSA, err: err}
		}
		s.emitAuthDiagnostic("final", msgID, payloads, authenticated, diagnosticErr)
	}()
	if err := s.authContextError(); err != nil {
		return err
	}
	if err := terminalAuthFailure(payloads); err != nil {
		return err
	}
	if err := s.verifyResponderFinal(payloads); err != nil {
		return err
	}
	authenticated = true

	var saPayload *ikev2.EncryptedPayloadSA
	var cpPayload *ikev2.EncryptedPayloadCP
	var tsiPayload *ikev2.EncryptedPayloadTS
	var tsrPayload *ikev2.EncryptedPayloadTS
	var kePayload *ikev2.EncryptedPayloadKE
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			saPayload = p
		case *ikev2.EncryptedPayloadKE:
			kePayload = p
		case *ikev2.EncryptedPayloadCP:
			cpPayload = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				tsiPayload = p
			} else {
				tsrPayload = p
			}
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return fmt.Errorf("IKE_AUTH 返回错误通知: type=%d proto=%d", p.NotifyType, p.ProtocolID)
			}
			// 打印所有收到的状态类型 Notify，便于调试
			s.Logger.Debug("IKE_AUTH 收到状态 Notify",
				logger.Int("type", int(p.NotifyType)),
				logger.Int("dataLen", len(p.NotifyData)))
			// RFC 4478: AUTH_LIFETIME — ePDG 通告 IKE SA 最大生存时间（秒）
			if p.NotifyType == ikev2.AUTH_LIFETIME && len(p.NotifyData) >= 4 {
				lifetime := binary.BigEndian.Uint32(p.NotifyData[:4])
				s.authLifetime = lifetime
				s.Logger.Info("ePDG 通告 AUTH_LIFETIME",
					logger.Uint32("seconds", lifetime),
					logger.String("duration", (time.Duration(lifetime)*time.Second).String()))
			}
			// RFC 5685: REDIRECT
			if p.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(p.NotifyData)
				if err != nil {
					s.Logger.Warn("解析 REDIRECT 数据失败", logger.Err(err))
				} else {
					return &RedirectError{NewAddr: addr, Authenticated: true}
				}
			}
			// RFC 4555: MOBIKE_SUPPORTED
			if p.NotifyType == ikev2.MOBIKE_SUPPORTED {
				s.mobikeSupported = true
				s.Logger.Info("ePDG 支持 MOBIKE")
			}
			// RFC 5723: Session Resumption
			if p.NotifyType == ikev2.TICKET_OPAQUE && len(p.NotifyData) > 0 {
				s.resumeTicket = make([]byte, len(p.NotifyData))
				copy(s.resumeTicket, p.NotifyData)
				if s.Keys != nil && len(s.Keys.SK_d) > 0 {
					s.resumeOldSKd = make([]byte, len(s.Keys.SK_d))
					copy(s.resumeOldSKd, s.Keys.SK_d)
					s.Logger.Info("成功提取到会话恢复车票", logger.Int("ticketLen", len(s.resumeTicket)))
					if s.cfg.OnTicketUpdate != nil {
						s.cfg.OnTicketUpdate(s.resumeTicket, s.resumeOldSKd)
					}
				}
			}
		}
	}

	if saPayload == nil || len(saPayload.Proposals) == 0 {
		return errors.New("IKE_AUTH 最终响应缺少 Child SA")
	}

	respProp, err := ikev2.ValidateSelectedProposal(saPayload, s.childOffers)
	if err != nil {
		return fmt.Errorf("Child SA proposal: %w", err)
	}
	if len(respProp.SPI) < 4 {
		return errors.New("IKE_AUTH 最终响应的 Child SA SPI 缺失")
	}
	remoteSPI := binary.BigEndian.Uint32(respProp.SPI[:4])

	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16
	for _, t := range respProp.Transforms {
		if t.Type == ikev2.TransformTypeEncr {
			encrID = uint16(t.ID)
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		}
		if t.Type == ikev2.TransformTypeInteg {
			integID = uint16(t.ID)
		}
		if t.Type == ikev2.TransformTypeDH {
			dhID = uint16(t.ID)
		}
		// ESN Transform: ID=1 表示使用 ESN，ID=0 表示不使用
		if t.Type == ikev2.TransformTypeESN && t.ID == 1 {
			s.childESN = true
			s.Logger.Info("ePDG 选择了 ESN (扩展序列号)")
		}
	}
	if encrID == 0 {
		return errors.New("IKE_AUTH 最终响应缺少加密算法选择")
	}

	s.Logger.Info("ePDG_SA_AUTH: IPsec ESP (Child SA) 算法协商成功",
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.Bool("esn", s.childESN),
	)

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

	seed := make([]byte, 0, len(s.ni)+len(s.nr))
	seed = append(seed, s.ni...)
	seed = append(seed, s.nr...)
	if dhID != 0 {
		if s.childDH == nil || kePayload == nil || len(kePayload.KEData) == 0 {
			return errors.New("Child SA 需要 PFS，但缺少 KE 载荷")
		}
		if _, err := s.childDH.ComputeSharedSecret(kePayload.KEData); err != nil {
			return fmt.Errorf("Child SA DH 计算失败: %v", err)
		}
		seed = append(seed, s.childDH.SharedKey...)
	}

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	cursor := 0
	outEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	outIntegKey := []byte(nil)
	if !isAEAD {
		outIntegKey = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}
	inEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	inIntegKey := []byte(nil)
	if !isAEAD {
		inIntegKey = keyMat[cursor : cursor+integKeyLen]
	}

	if s.childSPI == 0 {
		return errors.New("本端 Child SA SPI 未初始化")
	}
	if err := s.authContextError(); err != nil {
		return err
	}

	if isAEAD {
		s.ChildSAOut = ipsec.NewSecurityAssociation(remoteSPI, childEnc, outEncKey, nil)
		s.ChildSAOut.RemoteSPI = s.childSPI

		s.ChildSAIn = ipsec.NewSecurityAssociation(s.childSPI, childEnc, inEncKey, nil)
		s.ChildSAIn.RemoteSPI = remoteSPI
	} else {
		s.ChildSAOut = ipsec.NewSecurityAssociationCBC(remoteSPI, childEnc, outEncKey, integAlg, outIntegKey)
		s.ChildSAOut.RemoteSPI = s.childSPI

		s.ChildSAIn = ipsec.NewSecurityAssociationCBC(s.childSPI, childEnc, inEncKey, integAlg, inIntegKey)
		s.ChildSAIn.RemoteSPI = remoteSPI
	}
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[s.childSPI] = s.ChildSAIn
	}

	// 保存 Child SA 算法 ID (供 XFRM 模式使用)
	s.childEncrID = encrID
	s.childIntegID = integID
	s.childEncrKeyLenBits = encrKeyLenBits

	if s.ws != nil {
		s.ws.LogChildSA(s.childSPI, remoteSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inEncKey, outEncKey, encrID)
	}

	if cpPayload != nil {
		if cpPayload.Attributes != nil {
			types := make([]int, 0, len(cpPayload.Attributes))
			for _, a := range cpPayload.Attributes {
				if a == nil {
					continue
				}
				types = append(types, int(a.Type))
			}
			s.Logger.Debug("CP 属性类型", logger.Any("types", types))
		}
		s.cpConfig = ikev2.ParseCPConfig(cpPayload)
		if s.cpConfig != nil {
			toStrings := func(ips []net.IP) []string {
				out := make([]string, 0, len(ips))
				for _, ip := range ips {
					if ip == nil {
						continue
					}
					out = append(out, ip.String())
				}
				return out
			}
			ipv4 := ""
			if len(s.cpConfig.IPv4Addresses) > 0 && s.cpConfig.IPv4Addresses[0] != nil {
				ipv4 = s.cpConfig.IPv4Addresses[0].String()
			}
			ipv6 := ""
			if len(s.cpConfig.IPv6Addresses) > 0 && s.cpConfig.IPv6Addresses[0] != nil {
				ipv6 = s.cpConfig.IPv6Addresses[0].String()
			}
			s.Logger.Debug("CP 配置已下发",
				logger.String("ipv4", ipv4),
				logger.String("ipv6", ipv6),
				logger.Int("dns_v4", len(s.cpConfig.IPv4DNS)),
				logger.Int("dns_v6", len(s.cpConfig.IPv6DNS)),
				logger.Int("pcscf_v4", len(s.cpConfig.IPv4PCSCF)),
				logger.Int("pcscf_v6", len(s.cpConfig.IPv6PCSCF)),
				logger.Any("pcscf_v4_ips", toStrings(s.cpConfig.IPv4PCSCF)),
				logger.Any("pcscf_v6_ips", toStrings(s.cpConfig.IPv6PCSCF)),
			)
		}
	}
	if tsiPayload != nil {
		s.tsi = tsiPayload.TrafficSelectors
	}
	if tsrPayload != nil {
		s.tsr = tsrPayload.TrafficSelectors
	}
	if len(s.tsr) > 0 && s.ChildSAOut != nil {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: s.ChildSAOut, tsr: s.tsr})
	}

	s.Logger.Debug("Child SA 已建立", logger.Uint32("localSPI", s.childSPI), logger.Uint32("remoteSPI", remoteSPI))
	s.peerAuthenticated.Store(true)
	return nil
}

// verifyEAPAKAPrimeMAC 校验 EAP-AKA' 报文中的 AT_MAC (使用 HMAC-SHA256-128，取前 16 字节)。
// eapRaw: 原始的完整 EAP 报文 (包含 header)
// attrData: EAP-AKA 数据域（用于定位 AT_MAC 占位符）
// kAut: 32 字节的 K_aut 密钥
// recvMac: 从 AT_MAC 属性中提取的 16 字节签名
func verifyEAPAKAPrimeMAC(eapRaw []byte, attrData []byte, kAut []byte, recvMac []byte) error {
	// 与 4G AKA 的 verifyEAPAKAMAC 逻辑完全相同，唯一不同是用 sha256.New 代替 sha1.New
	eapCopy := make([]byte, len(eapRaw))
	copy(eapCopy, eapRaw)

	// 寻找并清零 AT_MAC 的值域（Header 偏移 8 字节后的 attrData 中）
	for i := 0; i < len(attrData)-3; {
		attrType := attrData[i]
		attrLen := int(attrData[i+1]) * 4
		if attrLen < 4 {
			break
		}
		if attrType == eap.AT_MAC {
			// 在 eapCopy 中对应的位置清零 MAC 值 (跳过 2 字节保留域 + 16 字节 MAC)
			macStart := 8 + i + 4 // EAP header(8) + attr offset + Type(1)+Len(1)+Reserved(2)
			if macStart+16 <= len(eapCopy) {
				for j := 0; j < 16; j++ {
					eapCopy[macStart+j] = 0
				}
			}
			break
		}
		i += attrLen
	}

	h := hmac.New(sha256.New, kAut)
	h.Write(eapCopy)
	calcMac := h.Sum(nil)[:16] // HMAC-SHA256-128: 取前 16 字节

	if !hmac.Equal(calcMac, recvMac) {
		return errors.New("AKA' MAC mismatch")
	}
	return nil
}
