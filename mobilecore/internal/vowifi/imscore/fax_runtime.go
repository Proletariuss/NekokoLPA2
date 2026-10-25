package imscore

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"
)

// fax_runtime.go — 读卡器路径传真（T.38 FoIP）运行时 [DEPRECATED]
//
// ⚠ 此文件已弃用：Linphone 固话接入传真迁移后，传真功能不再经过读卡器 VoWiFi 路径。
// 代码暂时保留供参考，将在三轮真机验证后删除。
// 新传真路径：Proletarius → Rust 网关 → Go Asterisk SIP 客户端 → 群晖 Asterisk → 电信固话
//
// 历史说明：
//   传真会话在 imscore 中复用 callRuntime 的 SIP 事务底座：
//   - SIP INVITE / 200 / ACK / BYE 通过 callRuntime.buildRequest + transportRuntime.enqueueWrite
//   - 媒体通道复用 callRuntime.allocateMedia 分配的 UDP 端口（T.38 UDPTL）
//   - 传真协议编解码（SDP / T.30 / T.4 / IFP / UDPTL）委托 Rust 网关（cmd 层 native_fax.go 反向调用）
//
// 传真与语音通话互斥：拨号前要求 callRuntime 处于 idle/ended/failed。

// FaxNegotiation 是传真 SDP 协商结果（供 cmd 层转 Rust 或直接使用）。
type FaxNegotiation struct {
	T38Accepted    bool   `json:"t38_accepted"`
	G711Accepted   bool   `json:"g711_accepted"`
	UDPTLPort      int    `json:"udptl_port"`
	RTPPort        int    `json:"rtp_port"`
	RTPPayloadType byte   `json:"rtp_payload_type,omitempty"`
	RemoteIP       string `json:"remote_ip"`
	Protocol       string `json:"protocol"`
}

// faxRuntime 管理读卡器路径传真会话的 SIP 与媒体生命周期。
type faxRuntime struct {
	service *Service

	mu        sync.Mutex
	state     string // idle | dialing | active | ended | failed
	callID    string
	peer      string
	protocol  string // t38 | g711
	udptlConn net.PacketConn
	udptlPeer *net.UDPAddr
	lastError string

	// G.711 RTP 模式
	rtpMedia       net.PacketConn
	rtpRemote      *net.UDPAddr
	rtpPayloadType byte
	rtpSeq         uint16
	rtpTimestamp   uint32
	rtpSSRC        uint32
	amr            *amrNBCodec
}

// faxMediaReadPoll bounds a blocking media read after Service.Close cancels
// the lifecycle. Keeping the Service operation lease through RunMediaLoop
// prevents Close from clearing the fax runtime while a packet/callback is in
// flight; this deadline lets that lease drain without waiting for Close to
// close the underlying socket first.
const faxMediaReadPoll = 250 * time.Millisecond

// newFaxRuntime 创建绑定到已注册 IMS Service 的传真运行时。
func newFaxRuntime(service *Service) *faxRuntime {
	return &faxRuntime{service: service, state: "idle"}
}

// Snapshot 返回传真会话当前状态（供 API 展示）。
func (f *faxRuntime) Snapshot() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]any{
		"state":      f.state,
		"call_id":    f.callID,
		"peer":       f.peer,
		"protocol":   f.protocol,
		"last_error": f.lastError,
	}
}

// State 返回传真状态字符串。
func (f *faxRuntime) State() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (f *faxRuntime) setState(state string, err error) {
	f.mu.Lock()
	f.state = state
	if err != nil {
		f.lastError = err.Error()
	}
	f.mu.Unlock()
}

// DialFax 发起 T.38 传真 SIP INVITE（读卡器路径）。
// 成功返回协商结果；调用方随后通过 RemoteEndpoint 获取媒体地址并用 RunMediaLoop 驱动。
func (f *faxRuntime) DialFax(ctx context.Context, peer string, preferT38 bool) (*FaxNegotiation, error) {
	if f == nil || f.service == nil {
		return nil, fmt.Errorf("imscore: fax runtime unavailable")
	}
	if !f.service.MessagingReady() {
		return nil, fmt.Errorf("imscore: IMS voice service not ready")
	}
	c := f.service.calls
	if c == nil {
		return nil, fmt.Errorf("imscore: IMS call runtime unavailable")
	}

	// 传真与语音互斥
	c.mu.Lock()
	callState := c.state.State
	c.mu.Unlock()
	if callState != "idle" && callState != "ended" && callState != "failed" {
		return nil, fmt.Errorf("imscore: another reader call is already active")
	}

	// 分配媒体端口（复用语音媒体 socket 作为 UDPTL/RTP socket）。
	// 注意：必须使用 service.lifecycleCtx 而非 handler 传入的 ctx，
	// 否则 HTTP handler 返回后 defer cancel() 会销毁 gVisor socket。
	if c.cancel != nil {
		c.cancel()
	}
	callCtx, cancel := context.WithCancel(c.service.lifecycleCtx)
	c.cancel = cancel
	port, err := c.allocateMedia(callCtx)
	if err != nil {
		f.setState("failed", err)
		return nil, err
	}

	// 构造传真 SDP（T.38 优先 + G.711 降级）
	sdp := buildReaderFaxSDP(port, c.service.cfg.LocalIP.String(), preferT38)

	// 初始化 call 状态（outgoing）
	callID := uuid.NewString()
	c.mu.Lock()
	c.cseq++
	cseq := c.cseq
	c.state = CallState{State: "outgoing", Direction: "outgoing", Peer: peer, CallID: callID, SignalingOK: true}
	c.localTag, c.remoteTag, c.inviteBranch = "", "", ""
	c.inviteCSeq = 0
	c.non2xxACK, c.lastRSeq = false, ""
	c.remoteTarget, c.routeSet = "", nil
	c.pracked = make(map[string]bool)
	c.dtmfPayload, c.dtmfReady, c.dtmfSending = 101, false, false
	c.mu.Unlock()

	f.mu.Lock()
	f.state = "dialing"
	f.callID = callID
	f.peer = peer
	f.mu.Unlock()

	payload, err := c.buildRequest(sip.INVITE, peer, callID, cseq, []byte(sdp))
	if err != nil {
		c.finish("failed", err)
		f.setState("failed", err)
		return nil, err
	}
	// 传真 INVITE 发出前打印完整报文（用于排查 487/对端拒绝）
	logger.Info("fax INVITE full",
		logger.String("call_id", callID),
		logger.String("peer", peer),
		logger.String("sip", string(payload)))
	responses, unsubscribe, err := c.service.transportRuntime.subscribeResponses(callID)
	if err != nil {
		c.finish("failed", err)
		f.setState("failed", err)
		return nil, err
	}
	if err := c.service.transportRuntime.enqueueWrite(ctx, payload); err != nil {
		unsubscribe()
		c.finish("failed", err)
		f.setState("failed", err)
		return nil, err
	}

	negotiation, err := f.waitForAnswer(ctx, c, peer, callID, cseq, responses, unsubscribe)
	if err != nil {
		c.finish("failed", err)
		f.setState("failed", err)
		return nil, err
	}

	f.mu.Lock()
	f.state = "active"
	f.protocol = negotiation.Protocol
	f.mu.Unlock()
	return negotiation, nil
}

// waitForAnswer 等待 INVITE 的最终响应并解析远端传真 SDP。
func (f *faxRuntime) waitForAnswer(
	ctx context.Context,
	c *callRuntime,
	peer, callID string,
	cseq uint32,
	responses <-chan *sip.Response,
	unsubscribe func(),
) (*FaxNegotiation, error) {
	defer unsubscribe()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()

	var earlyMediaSDP []byte // 183 Session Progress 中携带的 SDP（200 OK 可能不重复携带）
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("imscore: fax INVITE timed out")
		case response := <-responses:
			if response == nil {
				continue
			}
			if response.CSeq() == nil || response.CSeq().MethodName != sip.INVITE {
				continue
			}
			c.updateDialogFromResponse(response)
			switch {
			case response.StatusCode < 180:
				// 100 Trying
			case response.StatusCode < 200:
				// 180/183 Ringing / Early media — 保存 SDP 供 200 OK 空体时复用
				if len(response.Body()) > 0 {
					earlyMediaSDP = response.Body()
				}
				if headerContainsToken(response.GetHeader("Require"), "100rel") {
					if rseq := response.GetHeader("RSeq"); rseq != nil {
						c.mu.Lock()
						key := strings.TrimSpace(rseq.Value()) + "|" + response.CSeq().Value()
						if c.pracked[key] {
							c.mu.Unlock()
							continue
						}
						c.pracked[key] = true
						c.lastRSeq = strings.TrimSpace(rseq.Value())
						c.cseq++
						prackCSeq := c.cseq
						c.mu.Unlock()
						if prack, err := c.buildRequest(sip.PRACK, peer, callID, prackCSeq, nil); err == nil {
							_ = c.service.transportRuntime.enqueueWrite(ctx, prack)
						}
					}
				}
			case response.StatusCode < 300:
				// 200 OK：如果 body 为空（early media 场景 SDP 已在 183 中提供），
				// 复用之前保存的 early media SDP。
				answerBody := response.Body()
				if len(answerBody) == 0 && earlyMediaSDP != nil {
					answerBody = earlyMediaSDP
				}
				negotiation, err := parseRemoteFax(answerBody)
				if err != nil {
					// 2xx 必须先 ACK，随后 BYE 结束无法建立媒体的对话
					if ack, buildErr := c.buildRequest(sip.ACK, peer, callID, cseq, nil); buildErr == nil {
						_ = c.service.transportRuntime.enqueueWrite(ctx, ack)
					}
					c.mu.Lock()
					c.cseq++
					byeCSeq := c.cseq
					c.mu.Unlock()
					if bye, buildErr := c.buildRequest(sip.BYE, peer, callID, byeCSeq, nil); buildErr == nil {
						_ = c.service.transportRuntime.enqueueWrite(ctx, bye)
					}
					return nil, err
				}
				if ack, err := c.buildRequest(sip.ACK, peer, callID, cseq, nil); err == nil {
					_ = c.service.transportRuntime.enqueueWrite(ctx, ack)
				}
				c.mu.Lock()
				c.state.State = "active"
				c.state.StartedAt = time.Now().UTC().Format(time.RFC3339)
				c.state.MediaReady = true
				c.mu.Unlock()
				return negotiation, nil
			default:
				if ack, err := c.buildRequest(sip.ACK, peer, callID, cseq, nil); err == nil {
					_ = c.service.transportRuntime.enqueueWrite(ctx, ack)
				}
				return nil, callRejectionError(response)
			}
		}
	}
}

// StartMedia 使用协商结果绑定 UDPTL 通道并返回会话。
// 媒体地址来自远端 SDP；本地复用 callRuntime.allocateMedia 的 socket。
func (f *faxRuntime) StartMedia(ctx context.Context, negotiation *FaxNegotiation) error {
	if negotiation == nil {
		return fmt.Errorf("imscore: nil fax negotiation")
	}
	c := f.service.calls
	if c == nil {
		return fmt.Errorf("imscore: IMS call runtime unavailable")
	}
	c.mu.Lock()
	media := c.media
	c.mu.Unlock()
	if media == nil {
		return fmt.Errorf("imscore: fax media socket unavailable")
	}

	// T.38 UDPTL：绑定远端地址
	if negotiation.T38Accepted {
		ip := net.ParseIP(negotiation.RemoteIP)
		if ip == nil {
			return fmt.Errorf("imscore: invalid remote fax IP %q", negotiation.RemoteIP)
		}
		f.mu.Lock()
		f.udptlConn = media
		f.udptlPeer = &net.UDPAddr{IP: ip, Port: negotiation.UDPTLPort}
		f.mu.Unlock()
		return nil
	}

	// G.711 RTP 模式：从协商结果绑定 RTP 通道
	ip := net.ParseIP(negotiation.RemoteIP)
	if ip == nil {
		return fmt.Errorf("imscore: invalid remote RTP IP %q", negotiation.RemoteIP)
	}
	// 远端 200 OK 可能把 PCMA(8) 降级为 AMR(97)（Orange UK P-CSCF 行为）。
	// 按协商结果选择 payload type；AMR 时在 WriteRTP 内做 PCMA→AMR 转码。
	pt := byte(8)
	if negotiation.RTPPayloadType != 0 {
		pt = negotiation.RTPPayloadType
	}
	if pt == 97 && f.amr == nil {
		amr, err := newAMRNBCodec()
		if err != nil {
			return fmt.Errorf("imscore: init AMR codec for fax: %w", err)
		}
		f.amr = amr
	}
	var seed [10]byte
	_, _ = rand.Read(seed[:])
	f.mu.Lock()
	f.rtpMedia = media
	f.rtpRemote = &net.UDPAddr{IP: ip, Port: negotiation.RTPPort}
	f.rtpPayloadType = pt
	f.rtpSeq = binary.BigEndian.Uint16(seed[:2])
	f.rtpTimestamp = binary.BigEndian.Uint32(seed[2:6])
	f.rtpSSRC = binary.BigEndian.Uint32(seed[6:10])
	f.mu.Unlock()
	logger.Info("fax G.711 RTP media bound",
		logger.String("remote", fmt.Sprintf("%s:%d", negotiation.RemoteIP, negotiation.RTPPort)),
		logger.Int("payload_type", int(pt)))
	return nil
}

// WriteRTP 发送传真音频数据。
// 协商为 PCMA(8) 时，分帧为 160 字节（20ms @ 8kHz）RTP 包直接发送；
// 协商为 AMR(97) 时，先把 PCMA 解码为线性 PCM（320 字节/帧），
// 再经 AMR-NB mode-7 编码为 RFC 4867 octet-aligned 载荷后发送。
func (f *faxRuntime) WriteRTP(pcma []byte) error {
	f.mu.Lock()
	media := f.rtpMedia
	remote := f.rtpRemote
	pt := f.rtpPayloadType
	amr := f.amr
	seq := f.rtpSeq
	timestamp := f.rtpTimestamp
	ssrc := f.rtpSSRC
	f.mu.Unlock()
	if media == nil || remote == nil {
		return fmt.Errorf("imscore: fax RTP channel not ready")
	}

	const frameSize = 160 // 20ms @ 8kHz PCMA
	for offset := 0; offset < len(pcma); offset += frameSize {
		end := offset + frameSize
		if end > len(pcma) {
			end = len(pcma)
		}
		frame := pcma[offset:end]
		var payload []byte
		if pt == 97 {
			// 对齐到 160 字节后再转码（AMR 编码器需要 320 字节 PCM = 160 样本）
			if len(frame) < frameSize {
				padded := make([]byte, frameSize)
				copy(padded, frame)
				frame = padded
			}
			pcm := decodeG711(frame, true) // PCMA → linear PCM（320 字节）
			if amr == nil {
				return fmt.Errorf("imscore: fax AMR codec not initialized")
			}
			encoded, err := amr.encode(pcm)
			if err != nil {
				return fmt.Errorf("imscore: fax AMR encode: %w", err)
			}
			payload = encoded
		} else {
			// 最后一帧不足 160 字节时补零
			if len(frame) < frameSize {
				padded := make([]byte, frameSize)
				copy(padded, frame)
				frame = padded
			}
			payload = frame
		}
		packet := make([]byte, 12+len(payload))
		packet[0] = 0x80 // V=2, P=0, X=0, CC=0
		packet[1] = pt & 0x7f
		if offset == 0 {
			packet[1] |= 0x80 // marker bit on first packet
		}
		binary.BigEndian.PutUint16(packet[2:4], seq)
		binary.BigEndian.PutUint32(packet[4:8], timestamp)
		binary.BigEndian.PutUint32(packet[8:12], ssrc)
		copy(packet[12:], payload)
		if _, err := media.WriteTo(packet, remote); err != nil {
			return err
		}
		seq++
		timestamp += uint32(frameSize)
	}

	f.mu.Lock()
	f.rtpSeq = seq
	f.rtpTimestamp = timestamp
	f.mu.Unlock()
	return nil
}

// WriteUDPTL 向远端发送一个 UDPTL 包。
func (f *faxRuntime) WriteUDPTL(payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.udptlConn == nil || f.udptlPeer == nil {
		return fmt.Errorf("imscore: fax UDPTL channel not ready")
	}
	_, err := f.udptlConn.WriteTo(payload, f.udptlPeer)
	return err
}

// RunMediaLoop 循环读取媒体包，每个包调用 onPacket 回调。
// T.38 模式读取 UDPTL 包；G.711 模式读取 RTP 包并提取 PCMA payload。
// 编解码委托给上层（cmd 层 native_fax.go 反向调用 Rust）。
func (f *faxRuntime) RunMediaLoop(ctx context.Context, onPacket func([]byte) error) {
	f.mu.Lock()
	isRTP := f.rtpMedia != nil
	f.mu.Unlock()

	if isRTP {
		f.runRTPMediaLoop(ctx, onPacket)
		return
	}

	// T.38 UDPTL 模式
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		f.mu.Lock()
		conn := f.udptlConn
		f.mu.Unlock()
		if conn == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(faxMediaReadPoll))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		if onPacket != nil {
			_ = onPacket(buf[:n])
		}
	}
}

// runRTPMediaLoop 读取入站 RTP 包，提取音频 payload 调用 onPacket 回调。
// G.711 传真模式下回调收到的是 PCMA 字节流（160 字节/20ms 帧）：
//   - pt=8（PCMA）：RTP payload 本身即 PCMA 字节
//   - pt=97（AMR-NB）：RTP payload 为 AMR 帧，解码为线性 PCM 后
//     再编码为 PCMA 字节，保持回调接口统一
//
// Rust 侧 V.21 解调器通过 /api/v2/fax/audio/decode 解析回调收到的 PCMA。
func (f *faxRuntime) runRTPMediaLoop(ctx context.Context, onPacket func([]byte) error) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		f.mu.Lock()
		conn := f.rtpMedia
		pt := f.rtpPayloadType
		amr := f.amr
		f.mu.Unlock()
		if conn == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(faxMediaReadPoll))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		logger.Info("fax RTP packet received",
			logger.Int("len", n),
			logger.Int("payload_type_hint", int(buf[0]&0x7f)))
		// 解析 RTP 头并提取 payload
		if n < 12 || buf[0]>>6 != 2 {
			continue
		}
		offset := 12 + int(buf[0]&0x0f)*4
		if offset > n {
			continue
		}
		if buf[0]&0x10 != 0 {
			if offset+4 > n {
				continue
			}
			extensionWords := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
			offset += 4 + extensionWords*4
			if offset > n {
				continue
			}
		}
		end := n
		if buf[0]&0x20 != 0 {
			padding := int(buf[n-1])
			if padding == 0 || padding > end-offset {
				continue
			}
			end -= padding
		}
		if offset >= end {
			continue
		}
		payload := buf[offset:end]

		// 按协商 payload type 解码为 PCMA 字节流
		var pcma []byte
		if pt == 97 {
			// AMR-NB → 线性 PCM（320 字节）→ PCMA（160 字节）
			if amr == nil {
				continue
			}
			pcm, err := amr.decode(payload)
			if err != nil {
				logger.Info("fax RTP AMR decode failed",
					logger.Int("payload_len", len(payload)),
					logger.String("err", err.Error()))
				continue
			}
			pcma = encodeG711(pcm, true)
		} else {
			// PCMA 直通
			pcma = payload
		}
		if onPacket != nil && len(pcma) > 0 {
			_ = onPacket(pcma)
		}
	}
}

// Hangup 结束传真会话（SIP BYE，或在尚未接通时 CANCEL）。
func (f *faxRuntime) Hangup(ctx context.Context) error {
	if f == nil || f.service == nil || f.service.calls == nil {
		return nil
	}
	c := f.service.calls
	c.mu.Lock()
	state, peer, callID := c.state.State, c.state.Peer, c.state.CallID
	cseq := c.inviteCSeq
	if state != "outgoing" && state != "early" {
		c.cseq++
		cseq = c.cseq
	}
	c.mu.Unlock()
	if state == "idle" || state == "ended" || state == "failed" {
		return nil
	}
	method := sip.BYE
	if state == "outgoing" || state == "early" {
		method = sip.CANCEL
	}
	payload, err := c.buildRequest(method, peer, callID, cseq, nil)
	if method == sip.CANCEL && err == nil {
		c.setState("cancelling", nil)
	}
	if err == nil {
		err = c.service.transportRuntime.enqueueWrite(ctx, payload)
	}
	c.finish("ended", err)
	f.setState("ended", err)
	return err
}

// Close 释放传真资源。
func (f *faxRuntime) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.udptlConn = nil
	f.udptlPeer = nil
	f.rtpMedia = nil
	f.rtpRemote = nil
	if f.amr != nil {
		f.amr.close()
		f.amr = nil
	}
	f.state = "ended"
}

// buildReaderFaxSDP 构造传真 SDP（与 Rust sdp::build_reader_fax_sdp 保持一致）。
// 根据本地地址自动选择 IP4/IP6 家族（隧道可能只有 IPv6）。
func buildReaderFaxSDP(port int, localIP string, preferT38 bool) string {
	family := "IP4"
	if ip := net.ParseIP(localIP); ip != nil && ip.To4() == nil {
		family = "IP6"
	}
	var sb strings.Builder
	sb.WriteString("v=0\r\n")
	sb.WriteString("o=- 0 0 IN ")
	sb.WriteString(family)
	sb.WriteString(" ")
	sb.WriteString(localIP)
	sb.WriteString("\r\n")
	sb.WriteString("s=Proletarius Fax\r\n")
	sb.WriteString("c=IN ")
	sb.WriteString(family)
	sb.WriteString(" ")
	sb.WriteString(localIP)
	sb.WriteString("\r\n")
	sb.WriteString("t=0 0\r\n")
	if preferT38 {
		// T.38 media line（RFC 2346 标准属性）
		sb.WriteString(fmt.Sprintf("m=image %d udptl t38\r\n", port))
		sb.WriteString("a=T38FaxVersion:19\r\n")
		sb.WriteString("a=T38MaxBitRate:14400\r\n")
		sb.WriteString("a=T38FaxRateManagement:transferred-tcf\r\n")
		sb.WriteString("a=T38FaxMaxBuffer:2048\r\n")
		sb.WriteString("a=T38FaxMaxDatagrams:1408\r\n")
		sb.WriteString("a=T38UDPEC:red\r\n")
		sb.WriteString("a=sendrecv\r\n")
	} else {
		// G.711 降级：offer PCMA（PT 8）+ AMR（PT 97）+ DTMF（PT 101）。
		// 某些 IMS 网络强制要求 AMR，去掉会被 487 拒绝。
		sb.WriteString(fmt.Sprintf("m=audio %d RTP/AVP 8 97 101\r\n", port))
		sb.WriteString("a=rtpmap:8 PCMA/8000\r\n")
		sb.WriteString("a=rtpmap:97 AMR/8000\r\n")
		sb.WriteString("a=fmtp:97 octet-align=1;mode-set=7;max-red=0\r\n")
		sb.WriteString("a=rtpmap:101 telephone-event/8000\r\n")
		sb.WriteString("a=fmtp:101 0-15\r\n")
		sb.WriteString("a=ptime:20\r\n")
		sb.WriteString("a=maxptime:40\r\n")
		sb.WriteString("a=sendrecv\r\n")
	}
	return sb.String()
}

// parseRemoteFax parses a remote fax SDP (T.38 / G.711) from a SIP response body.
func parseRemoteFax(body []byte) (*FaxNegotiation, error) {
	sdp := string(body)
	neg := &FaxNegotiation{}
	remoteIP := ""
	for _, raw := range strings.Split(strings.ReplaceAll(sdp, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "c=IN IP4 ") {
			remoteIP = strings.TrimSpace(strings.TrimPrefix(line, "c=IN IP4 "))
			continue
		}
		if strings.HasPrefix(line, "c=IN IP6 ") {
			remoteIP = strings.TrimSpace(strings.TrimPrefix(line, "c=IN IP6 "))
			continue
		}
		if strings.HasPrefix(line, "m=image ") {
			neg.T38Accepted = true
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				fmt.Sscanf(fields[1], "%d", &neg.UDPTLPort)
			}
			continue
		}
		if strings.HasPrefix(line, "m=audio ") {
			neg.G711Accepted = true
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				fmt.Sscanf(fields[1], "%d", &neg.RTPPort)
			}
			// 解析媒体行中的 payload type 列表（如 "m=audio 40000 RTP/AVP 97 101"），
			// 选择 PCMA(8)/AMR(97) 作为传真编码，其余（DTMF 101 等）跳过。
			for _, field := range fields {
				switch field {
				case "8":
					neg.RTPPayloadType = 8
				case "97":
					if neg.RTPPayloadType == 0 {
						neg.RTPPayloadType = 97
					}
				}
			}
			continue
		}
	}
	neg.RemoteIP = remoteIP
	switch {
	case neg.T38Accepted:
		neg.Protocol = "t38"
	case neg.G711Accepted:
		neg.Protocol = "g711"
	default:
		return nil, fmt.Errorf("imscore: remote SDP has no fax media (T.38/G.711)")
	}
	return neg, nil
}
