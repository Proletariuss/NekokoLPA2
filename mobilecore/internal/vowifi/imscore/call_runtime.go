package imscore

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"
)

type CallState struct {
	State                string `json:"state"`
	Direction            string `json:"direction,omitempty"`
	Peer                 string `json:"peer,omitempty"`
	CallID               string `json:"call_id,omitempty"`
	Codec                string `json:"codec,omitempty"`
	StartedAt            string `json:"started_at,omitempty"`
	LastError            string `json:"last_error,omitempty"`
	MediaReady           bool   `json:"media_ready"`
	EarlyMedia           bool   `json:"early_media"`
	SignalingOK          bool   `json:"signaling_ready"`
	AudioPort            int    `json:"audio_port,omitempty"`
	AudioToken           string `json:"audio_token,omitempty"`
	RTPTransmitted       uint64 `json:"rtp_transmitted"`
	RTPReceived          uint64 `json:"rtp_received"`
	AudioDecodeErrors    uint64 `json:"audio_decode_errors"`
	AudioTransportErrors uint64 `json:"audio_transport_errors"`
}

// incomingCallDecisionTimeout bounds an unanswered inbound INVITE. It is
// intentionally independent from SIP transport write deadlines: the caller
// gets enough time to act, while a half-closed Port-S responder can never be
// retained indefinitely after a carrier stops the transaction.
const incomingCallDecisionTimeout = 90 * time.Second

type callRuntime struct {
	mu sync.Mutex
	// incomingFinalMu serializes a final inbound INVITE response with CANCEL.
	// Holding it across the response write means a CANCEL cannot be judged
	// against a transient state while a 200 OK is still being handed to the
	// transport.
	incomingFinalMu sync.Mutex
	service         *Service
	state           CallState
	incoming        *sip.Request
	respond         SIPResponder
	incomingToTag   string
	// incomingAnswerSDP is populated before the first 200 OK for an inbound
	// INVITE is sent. A UAS must answer a retransmitted INVITE in that narrow
	// pre-ACK window with the same final response, not turn it into a new busy
	// call. Keep only the SDP: a response must be rebuilt from the retransmit so
	// its Via header follows the transaction that actually arrived.
	incomingAnswerSDP []byte
	// incomingAnswerPreparing reserves one pending INVITE while its media
	// sockets are being allocated off-runtime. It prevents two answer actions
	// from racing, while still allowing CANCEL to end the original INVITE.
	incomingAnswerPreparing bool
	// incomingDecisionTimer is armed only after a 180 has been committed for
	// the currently pending INVITE. It is stopped before a 200/final reject
	// changes state and from finish(), which also covers service shutdown.
	incomingDecisionTimer   *time.Timer
	incomingDecisionTimeout time.Duration // test override; zero uses the default.
	media                   net.PacketConn
	remoteRTP               *net.UDPAddr
	audioConn               *net.UDPConn
	audioPeer               *net.UDPAddr
	amr                     *amrNBCodec
	mediaOnce               sync.Once
	rtpMu                   sync.Mutex
	dtmfMu                  sync.Mutex
	payloadType             byte
	amrOctetAligned         bool
	dtmfPayload             byte
	dtmfReady               bool
	dtmfSending             bool
	rtpSeq                  uint16
	rtpTimestamp            uint32
	ssrc                    uint32
	cancel                  context.CancelFunc
	cseq                    uint32
	localTag                string
	remoteTag               string
	inviteBranch            string
	inviteCSeq              uint32
	non2xxACK               bool
	cancelRequested         bool
	lastRSeq                string
	lastInviteReason        string
	remoteTarget            string
	routeSet                []string
	pracked                 map[string]bool
}

func newCallRuntime(service *Service) *callRuntime {
	return &callRuntime{service: service, state: CallState{State: "idle", SignalingOK: true}}
}

func (c *callRuntime) armIncomingDecisionTimer(req *sip.Request, toTag string) {
	if c == nil || req == nil {
		return
	}
	c.mu.Lock()
	if c.state.State != "incoming" || c.incoming != req || c.incomingToTag != toTag {
		c.mu.Unlock()
		return
	}
	if c.incomingDecisionTimer != nil {
		c.incomingDecisionTimer.Stop()
	}
	timeout := c.incomingDecisionTimeout
	if timeout <= 0 {
		timeout = incomingCallDecisionTimeout
	}
	c.incomingDecisionTimer = time.AfterFunc(timeout, func() {
		c.expireIncomingDecision(req, toTag)
	})
	c.mu.Unlock()
}

// expireIncomingDecision sends a terminal response only if the same INVITE is
// still pending. The identity check prevents an old timer from affecting a
// later incoming call after a finish/re-registration cycle.
func (c *callRuntime) expireIncomingDecision(req *sip.Request, toTag string) {
	if c == nil || req == nil {
		return
	}
	c.incomingFinalMu.Lock()
	defer c.incomingFinalMu.Unlock()
	c.mu.Lock()
	pending := c.state.State == "incoming" && c.incoming == req && c.incomingToTag == toTag
	c.mu.Unlock()
	if !pending {
		return
	}
	_ = c.rejectPendingLocked(408, "Request Timeout")
}

// stopIncomingDecisionTimerLocked must be called while c.mu is held.
func (c *callRuntime) stopIncomingDecisionTimerLocked() {
	if c.incomingDecisionTimer == nil {
		return
	}
	c.incomingDecisionTimer.Stop()
	c.incomingDecisionTimer = nil
}

func (c *callRuntime) snapshot() CallState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *callRuntime) setState(state string, err error) {
	c.mu.Lock()
	c.state.State = state
	if err != nil {
		c.state.LastError = err.Error()
	}
	c.mu.Unlock()
}

func (c *callRuntime) allocateMedia(ctx context.Context) (int, error) {
	conn, err := c.service.network.ListenPacket(ctx, "udp", &net.UDPAddr{IP: c.service.cfg.LocalIP, Port: 0})
	if err != nil {
		return 0, err
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.Port == 0 {
		_ = conn.Close()
		return 0, fmt.Errorf("imscore: userspace RTP socket has no local port")
	}
	c.mu.Lock()
	if c.media != nil {
		_ = c.media.Close()
	}
	c.media = conn
	if c.audioConn == nil {
		audioConn, audioErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if audioErr != nil {
			c.mu.Unlock()
			_ = conn.Close()
			return 0, fmt.Errorf("imscore: create local audio bridge: %w", audioErr)
		}
		c.audioConn = audioConn
		c.state.AudioPort = audioConn.LocalAddr().(*net.UDPAddr).Port
		c.state.AudioToken = uuid.NewString()
	}
	c.mu.Unlock()
	return addr.Port, nil
}

func (c *callRuntime) dial(ctx context.Context, peer string) error {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return fmt.Errorf("imscore: call target is required")
	}
	if isEmergencyNumber(peer) {
		return fmt.Errorf("imscore: emergency calling is disabled until E911 entitlement and location are available")
	}
	// An inbound INVITE reserves this mutex from its first provisional response
	// through publication of the dialog (or transaction-scoped cleanup). Do not
	// let a simultaneous local dial replace its state while the inbound handler
	// is still deciding whether the Port-S response reached the carrier.
	//
	// Only hold this lock while claiming the call slot: media allocation and the
	// outbound SIP write must remain independent from inbound response handling.
	c.incomingFinalMu.Lock()
	c.mu.Lock()
	if c.state.State != "idle" && c.state.State != "ended" && c.state.State != "failed" {
		c.mu.Unlock()
		c.incomingFinalMu.Unlock()
		return fmt.Errorf("imscore: another reader call is already active")
	}
	if c.cancel != nil {
		c.cancel()
	}
	callCtx, cancel := context.WithCancel(c.service.lifecycleCtx)
	c.cancel = cancel
	c.state = CallState{State: "outgoing", Direction: "outgoing", Peer: peer, CallID: uuid.NewString(), SignalingOK: true}
	c.localTag, c.remoteTag, c.inviteBranch = "", "", ""
	c.inviteCSeq = 0
	c.non2xxACK, c.cancelRequested, c.lastRSeq, c.lastInviteReason = false, false, "", ""
	c.remoteTarget, c.routeSet = "", nil
	c.pracked = make(map[string]bool)
	c.dtmfPayload, c.dtmfReady, c.dtmfSending = 101, false, false
	callID := c.state.CallID
	c.cseq++
	cseq := c.cseq
	c.mu.Unlock()
	c.incomingFinalMu.Unlock()

	port, err := c.allocateMedia(callCtx)
	if err != nil {
		c.setState("failed", err)
		return err
	}
	payload, err := c.buildRequest(sip.INVITE, peer, callID, cseq, c.localSDP(port))
	if err != nil {
		c.setState("failed", err)
		return err
	}
	responses, unsubscribe, err := c.service.transportRuntime.subscribeResponses(callID)
	if err != nil {
		return err
	}
	if err := c.service.transportRuntime.enqueueWrite(ctx, payload); err != nil {
		unsubscribe()
		c.setState("failed", err)
		return err
	}
	go c.watchInvite(callCtx, peer, callID, cseq, responses, unsubscribe)
	return nil
}

func (c *callRuntime) watchInvite(ctx context.Context, peer, callID string, cseq uint32, responses <-chan *sip.Response, unsubscribe func()) {
	defer unsubscribe()
	// DialCall returns as soon as it has sent the INVITE, but the response
	// watcher continues to use the service transport to send PRACK/ACK/BYE.
	// Keep a lifecycle lease for that asynchronous tail so Close cannot detach
	// the runtime (or lifecycle context) underneath it.
	if c == nil || c.service == nil {
		return
	}
	_, release, ok := c.service.acquireLifecycleLease()
	if !ok {
		return
	}
	defer release()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.mu.Lock()
			if c.state.CallID != callID {
				c.mu.Unlock()
				return
			}
			cancelRequested := c.cancelRequested
			c.mu.Unlock()
			if cancelRequested {
				c.finish("ended", nil)
			} else {
				c.finish("failed", fmt.Errorf("IMS INVITE timed out"))
			}
			return
		case response, ok := <-responses:
			if !ok {
				c.mu.Lock()
				current := c.state.CallID == callID
				cancelRequested := c.cancelRequested
				c.mu.Unlock()
				if current {
					if cancelRequested {
						c.finish("ended", nil)
					} else {
						c.finish("failed", fmt.Errorf("IMS INVITE response stream closed"))
					}
				}
				return
			}
			if response == nil {
				continue
			}
			// A Call-ID is shared by the INVITE transaction and its PRACK. The
			// transport publishes both on this subscription, so a PRACK response
			// must never be mistaken for the final INVITE response.
			if response.CSeq() == nil || response.CSeq().MethodName != sip.INVITE || response.CSeq().SeqNo != cseq {
				continue
			}
			if !c.updateDialogFromResponseForCall(response, callID) {
				return
			}
			c.mu.Lock()
			if c.state.CallID != callID {
				c.mu.Unlock()
				return
			}
			wasCancelling := c.cancelRequested
			if reason := response.GetHeader("Reason"); reason != nil && strings.TrimSpace(reason.Value()) != "" {
				c.lastInviteReason = strings.TrimSpace(reason.Value())
			}
			lastInviteReason := c.lastInviteReason
			c.mu.Unlock()
			switch {
			case response.StatusCode < 180:
				if !wasCancelling {
					c.setState("outgoing", nil)
				}
			case response.StatusCode < 200:
				mediaReady := false
				if !wasCancelling && len(response.Body()) > 0 {
					if err := c.applyRemoteSDP(response.Body(), true); err == nil {
						mediaReady = true
					}
				}
				if c.updateProvisionalState(mediaReady) {
					// 183 may carry network ringback or an announcement before the
					// call is answered. The macOS bridge keeps microphone capture
					// disabled until the final 2xx response.
					c.startMedia()
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
				mediaErr := c.applyRemoteSDP(response.Body(), true)
				ack, err := c.buildRequest(sip.ACK, peer, callID, cseq, nil)
				if err == nil {
					err = c.service.transportRuntime.enqueueWrite(ctx, ack)
				}
				if err != nil {
					c.finish("failed", err)
					return
				}
				if wasCancelling {
					c.mu.Lock()
					c.cseq++
					byeCSeq := c.cseq
					c.mu.Unlock()
					if bye, buildErr := c.buildRequest(sip.BYE, peer, callID, byeCSeq, nil); buildErr == nil {
						_ = c.service.transportRuntime.enqueueWrite(ctx, bye)
					}
					c.finish("ended", nil)
					return
				}
				if mediaErr != nil {
					// 2xx 必须先 ACK；随后用 BYE 结束无法建立媒体的对话，不能
					// 把不支持的编码伪装成“已接通”。
					c.mu.Lock()
					c.cseq++
					byeCSeq := c.cseq
					c.mu.Unlock()
					if bye, buildErr := c.buildRequest(sip.BYE, peer, callID, byeCSeq, nil); buildErr == nil {
						_ = c.service.transportRuntime.enqueueWrite(ctx, bye)
					}
					c.finish("failed", mediaErr)
					return
				}
				c.mu.Lock()
				c.state.State = "active"
				c.state.StartedAt = time.Now().UTC().Format(time.RFC3339)
				c.state.MediaReady = c.remoteRTP != nil
				c.mu.Unlock()
				c.startMedia()
				return
			default:
				c.mu.Lock()
				c.non2xxACK = true
				c.mu.Unlock()
				if ack, err := c.buildRequest(sip.ACK, peer, callID, cseq, nil); err == nil {
					_ = c.service.transportRuntime.enqueueWrite(ctx, ack)
				}
				if wasCancelling {
					c.finish("ended", nil)
					return
				}
				c.finish("failed", callRejectionErrorWithFallback(response, lastInviteReason))
				c.service.requestInviteRegistrationRecovery(response)
				return
			}
		}
	}
}

// updateProvisionalState keeps a local CANCEL sticky across retransmitted 18x
// responses. IMS proxies commonly retransmit a reliable 183 before delivering
// the final 487; that response must not turn a normal local hangup into a call
// failure in the UI.
func (c *callRuntime) updateProvisionalState(mediaReady bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelRequested {
		return false
	}
	c.state.State = "early"
	c.state.EarlyMedia = mediaReady
	c.state.MediaReady = mediaReady
	return mediaReady
}

func (c *callRuntime) handleRequest(req *sip.Request, responder SIPResponder) {
	if req == nil {
		return
	}
	switch strings.ToUpper(string(req.Method)) {
	case "INVITE":
		c.handleInvite(req, responder)
	case "ACK":
		c.mu.Lock()
		matched := c.state.CallID != "" && c.state.CallID == sipCallIDFromRequest(req) && c.state.State == "connecting"
		if matched {
			c.state.State = "active"
			c.state.StartedAt = time.Now().UTC().Format(time.RFC3339)
			c.state.MediaReady = c.remoteRTP != nil
		}
		c.mu.Unlock()
		if matched {
			c.startMedia()
		}
	case "CANCEL":
		// A final 200 OK and a CANCEL cannot race each other. If the final
		// response is already written, the delayed CANCEL correctly sees the
		// connecting dialog; if it has not started, CANCEL keeps the request
		// in incoming state and produces 200/487.
		c.incomingFinalMu.Lock()
		defer c.incomingFinalMu.Unlock()
		c.mu.Lock()
		matched := c.state.State == "incoming" && c.state.CallID != "" && c.state.CallID == sipCallIDFromRequest(req) && c.incoming != nil && c.incoming.CSeq() != nil && req.CSeq() != nil && c.incoming.CSeq().SeqNo == req.CSeq().SeqNo
		c.mu.Unlock()
		if !matched {
			_ = responder(newIncomingResponse(req, 481, "Call/Transaction Does Not Exist", nil))
			return
		}
		_ = responder(newIncomingResponse(req, 200, "OK", nil))
		c.rejectPendingLocked(487, "Request Terminated")
	case "BYE":
		c.mu.Lock()
		matched := c.state.CallID != "" && c.state.CallID == sipCallIDFromRequest(req) && c.state.State != "idle" && c.state.State != "ended" && c.state.State != "failed"
		c.mu.Unlock()
		if !matched {
			_ = responder(newIncomingResponse(req, 481, "Call/Transaction Does Not Exist", nil))
			return
		}
		_ = responder(newIncomingResponse(req, 200, "OK", nil))
		c.finish("ended", nil)
	case "PRACK", "UPDATE":
		_ = responder(newIncomingResponse(req, 200, "OK", nil))
	case "INFO":
		_ = responder(newIncomingResponse(req, 200, "OK", nil))
	}
}

// newIncomingResponse works around a sipgo v1.5 parser defect triggered by
// the quoted overload-control parameter used by the O2/giffgaff IMS edge:
//
//	;oc-algo="LOSS";oc;branch=...
//
// sipgo keeps one malformed synthetic parameter in addition to the real
// branch and serialises it into a duplicated branch.  Such a Via cannot be
// matched by the carrier transaction, so even a locally generated 180 is
// treated as if the handset were unreachable.  Rebuild only the parameters
// that are valid and relevant to response routing while retaining overload
// control when it was present on the request.
func newIncomingResponse(req *sip.Request, statusCode int, reason string, body []byte) *sip.Response {
	response := sip.NewResponseFromRequest(req, statusCode, reason, body)
	via := response.Via()
	requestVia := req.Via()
	if via == nil || requestVia == nil {
		return response
	}

	params := sip.NewParams()
	if requestVia.Params != nil {
		if _, present := requestVia.Params.Get("oc"); present || viaContainsOverloadControl(requestVia.Params) {
			params.Add("oc-algo", `"LOSS"`)
			params.Add("oc", "")
		}
		for _, key := range []string{"branch", "received", "rport", "maddr", "ttl"} {
			if value, ok := requestVia.Params.Get(key); ok {
				params.Add(key, value)
			}
		}
	}
	via.Params = params
	return response
}

func newIncomingDialogResponse(req *sip.Request, statusCode int, reason string, body []byte, toTag string) *sip.Response {
	response := newIncomingResponse(req, statusCode, reason, body)
	if to := response.To(); to != nil && statusCode != 100 && strings.TrimSpace(toTag) != "" {
		to.Params.Remove("tag")
		to.Params.Add("tag", toTag)
	}
	return response
}

func viaContainsOverloadControl(params sip.HeaderParams) bool {
	for _, key := range params.Keys() {
		if strings.HasPrefix(strings.ToLower(key), "oc-algo=") || strings.EqualFold(strings.TrimPrefix(key, ";"), "oc") {
			return true
		}
	}
	return false
}

func (c *callRuntime) handleInvite(req *sip.Request, responder SIPResponder) {
	// Keep one inbound transaction decision serialized from the first 100
	// through the initial 180. This is deliberately wider than final-answer
	// serialization: until that point there is no published dialog, so a
	// concurrent retransmit or local dial could otherwise observe idle state,
	// claim the call slot, and then be torn down by this INVITE's failure path.
	// Production responders have a bounded write deadline, so this lock cannot
	// be held indefinitely by a broken Port-S connection.
	c.incomingFinalMu.Lock()
	defer c.incomingFinalMu.Unlock()
	c.mu.Lock()
	sameTransaction := c.incoming != nil && c.state.CallID != "" && c.state.CallID == sipCallIDFromRequest(req) && c.incoming.CSeq() != nil && req.CSeq() != nil && c.incoming.CSeq().Value() == req.CSeq().Value()
	duplicate := c.state.State == "incoming" && sameTransaction
	answeredRetransmit := (c.state.State == "incoming" || c.state.State == "connecting") && sameTransaction && len(c.incomingAnswerSDP) > 0
	currentToTag := c.incomingToTag
	answerSDP := append([]byte(nil), c.incomingAnswerSDP...)
	busy := c.state.State != "idle" && c.state.State != "ended" && c.state.State != "failed"
	c.mu.Unlock()
	if answeredRetransmit {
		response := newIncomingDialogResponse(req, 200, "OK", answerSDP, currentToTag)
		response.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		_ = responder(response)
		return
	}
	if duplicate {
		_ = responder(newIncomingDialogResponse(req, 180, "Ringing", nil, currentToTag))
		return
	}
	if busy {
		_ = responder(newIncomingResponse(req, 486, "Busy Here", nil))
		return
	}
	if err := responder(newIncomingResponse(req, 100, "Trying", nil)); err != nil {
		// This is the first response for a new Port-S INVITE. Do not publish a
		// local incoming call when the transport cannot deliver even Trying;
		// otherwise no remote CANCEL/BYE may arrive and the stale dialog blocks
		// the next caller. A responder failure is scoped to this transaction,
		// not to the registered IMS session.
		c.finish("failed", fmt.Errorf("imscore: write incoming INVITE Trying: %w", err))
		return
	}
	if err := c.applyRemoteSDP(req.Body(), false); err != nil {
		logger.Warn("IMS incoming call SDP rejected",
			logger.String("error_class", "invalid_sdp"))
		_ = responder(newIncomingResponse(req, 488, "Not Acceptable Here", nil))
		return
	}
	peer := sipRequestPeer(req)
	toTag := uuid.NewString()
	c.mu.Lock()
	c.incoming = req
	c.respond = responder
	c.incomingToTag = toTag
	c.state = CallState{State: "incoming", Direction: "incoming", Peer: peer, CallID: sipCallIDFromRequest(req), Codec: c.state.Codec, SignalingOK: true}
	codec := c.state.Codec
	c.mu.Unlock()
	logger.Info("IMS incoming call ringing",
		logger.String("codec", codec))
	if err := responder(newIncomingDialogResponse(req, 180, "Ringing", nil, toTag)); err != nil {
		// applyRemoteSDP may already have recorded the remote RTP parameters.
		// finish clears those partial fields (and any future media allocation)
		// before another INVITE is admitted.
		c.finish("failed", fmt.Errorf("imscore: write incoming INVITE Ringing: %w", err))
		return
	}
	// Once Ringing is on the wire, retain the Port-S responder until a user
	// decision, CANCEL, service shutdown, or this bounded terminal timeout.
	c.armIncomingDecisionTimer(req, toTag)
}

func (c *callRuntime) answer(ctx context.Context) error {
	c.mu.Lock()
	req, responder, toTag := c.incoming, c.respond, c.incomingToTag
	if req == nil || responder == nil {
		c.mu.Unlock()
		return fmt.Errorf("imscore: no incoming reader call")
	}
	if c.state.State != "incoming" || c.incomingAnswerPreparing || len(c.incomingAnswerSDP) > 0 {
		c.mu.Unlock()
		return fmt.Errorf("imscore: incoming reader call is already being answered")
	}
	c.incomingAnswerPreparing = true
	c.mu.Unlock()
	mediaCtx := c.service.lifecycleCtx
	if mediaCtx == nil {
		mediaCtx = ctx
	}
	if mediaCtx == nil {
		mediaCtx = context.Background()
	}
	allocation, err := c.allocateIncomingMedia(mediaCtx)
	if err != nil {
		c.clearIncomingAnswerReservation(req)
		return err
	}
	answerSDP := c.localSDP(allocation.port)
	response := newIncomingDialogResponse(req, 200, "OK", answerSDP, toTag)
	response.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))

	// Atomically bind freshly allocated media to the still-pending INVITE. The
	// allocation itself is intentionally local: a CANCEL that wins while the
	// userspace socket is opening cannot leave it attached after finish().
	c.incomingFinalMu.Lock()
	c.mu.Lock()
	if c.state.State != "incoming" || c.incoming != req || c.incomingToTag != toTag || !c.incomingAnswerPreparing {
		c.mu.Unlock()
		c.incomingFinalMu.Unlock()
		allocation.Close()
		return fmt.Errorf("imscore: incoming reader call is no longer pending")
	}
	if c.media != nil || c.audioConn != nil {
		c.incomingAnswerPreparing = false
		c.mu.Unlock()
		c.incomingFinalMu.Unlock()
		allocation.Close()
		return fmt.Errorf("imscore: incoming reader media is already allocated")
	}
	c.media = allocation.media
	c.audioConn = allocation.audio
	c.state.AudioPort = allocation.audioPort
	c.state.AudioToken = allocation.audioToken
	c.incomingAnswerSDP = append(c.incomingAnswerSDP[:0], answerSDP...)
	c.mu.Unlock()

	// Commit the final answer before moving to connecting. If that first write
	// is delayed or lost, a carrier retransmission of the same INVITE is
	// answered with this exact dialog identity rather than a 486 Busy Here. The
	// final-response lock also keeps CANCEL from observing a transient state.
	if err := responder(response); err != nil {
		c.finish("failed", err)
		c.incomingFinalMu.Unlock()
		return err
	}
	c.mu.Lock()
	if c.state.State == "incoming" && c.incoming == req && c.incomingToTag == toTag && c.incomingAnswerPreparing {
		c.stopIncomingDecisionTimerLocked()
		c.state.State = "connecting"
		c.incomingAnswerPreparing = false
		c.mu.Unlock()
		c.incomingFinalMu.Unlock()
		return nil
	}
	c.mu.Unlock()
	c.incomingFinalMu.Unlock()
	return fmt.Errorf("imscore: incoming reader call ended before answer completed")
}

type incomingMediaAllocation struct {
	media      net.PacketConn
	audio      *net.UDPConn
	port       int
	audioPort  int
	audioToken string
}

func (a *incomingMediaAllocation) Close() {
	if a == nil {
		return
	}
	if a.media != nil {
		_ = a.media.Close()
	}
	if a.audio != nil {
		_ = a.audio.Close()
	}
}

func (c *callRuntime) allocateIncomingMedia(ctx context.Context) (*incomingMediaAllocation, error) {
	if c == nil || c.service == nil || c.service.network == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network unavailable")
	}
	media, err := c.service.network.ListenPacket(ctx, "udp", &net.UDPAddr{IP: c.service.cfg.LocalIP, Port: 0})
	if err != nil {
		return nil, err
	}
	local, ok := media.LocalAddr().(*net.UDPAddr)
	if !ok || local.Port == 0 {
		_ = media.Close()
		return nil, fmt.Errorf("imscore: userspace RTP socket has no local port")
	}
	audio, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		_ = media.Close()
		return nil, fmt.Errorf("imscore: create local audio bridge: %w", err)
	}
	return &incomingMediaAllocation{
		media:      media,
		audio:      audio,
		port:       local.Port,
		audioPort:  audio.LocalAddr().(*net.UDPAddr).Port,
		audioToken: uuid.NewString(),
	}, nil
}

func (c *callRuntime) clearIncomingAnswerReservation(req *sip.Request) {
	c.mu.Lock()
	if c.incoming == req && c.state.State == "incoming" {
		c.incomingAnswerPreparing = false
	}
	c.mu.Unlock()
}

func (c *callRuntime) reject(code int, reason string) error {
	if code == 0 {
		code, reason = 486, "Busy Here"
	}
	return c.rejectPending(code, reason)
}

func (c *callRuntime) rejectPending(code int, reason string) error {
	c.incomingFinalMu.Lock()
	defer c.incomingFinalMu.Unlock()
	return c.rejectPendingLocked(code, reason)
}

// rejectPendingLocked sends the terminal response for the current inbound
// INVITE. The caller must hold incomingFinalMu so an explicit decline cannot
// race a 200 OK or a matching CANCEL.
func (c *callRuntime) rejectPendingLocked(code int, reason string) error {
	c.mu.Lock()
	req, responder, toTag := c.incoming, c.respond, c.incomingToTag
	c.mu.Unlock()
	if req == nil || responder == nil {
		return fmt.Errorf("imscore: no incoming reader call")
	}
	err := responder(newIncomingDialogResponse(req, code, reason, nil, toTag))
	c.finish("ended", err)
	return err
}

func (c *callRuntime) hangup(ctx context.Context) error {
	c.mu.Lock()
	state, peer, callID := c.state.State, c.state.Peer, c.state.CallID
	cseq := c.inviteCSeq
	switch state {
	case "idle", "ended", "failed", "cancelling":
		c.mu.Unlock()
		return nil
	case "outgoing", "early":
		// The flag belongs to the INVITE transaction and must be set while the
		// state lock is held. Otherwise a fast final response can race request
		// construction and be reported as a network rejection.
		c.cancelRequested = true
		c.state.State = "cancelling"
	default:
		c.cseq++
		cseq = c.cseq
	}
	c.mu.Unlock()
	method := sip.BYE
	if state == "outgoing" || state == "early" {
		method = sip.CANCEL
	}
	payload, err := c.buildRequest(method, peer, callID, cseq, nil)
	if err == nil {
		err = c.service.transportRuntime.enqueueWrite(ctx, payload)
	}
	if method == sip.CANCEL && err == nil {
		// Keep the INVITE response watcher alive until the server returns its
		// final 487 (or a raced 2xx). The final response still requires ACK.
		return nil
	}
	c.finish("ended", err)
	return err
}

func (c *callRuntime) finish(state string, err error) {
	c.mu.Lock()
	c.stopIncomingDecisionTimerLocked()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.media != nil {
		_ = c.media.Close()
		c.media = nil
	}
	if c.audioConn != nil {
		_ = c.audioConn.Close()
		c.audioConn = nil
	}
	c.incoming, c.respond, c.remoteRTP = nil, nil, nil
	c.incomingToTag = ""
	c.incomingAnswerSDP = nil
	c.incomingAnswerPreparing = false
	c.audioPeer = nil
	amr := c.amr
	c.amr = nil
	c.mediaOnce = sync.Once{}
	c.localTag, c.remoteTag, c.inviteBranch = "", "", ""
	c.inviteCSeq = 0
	c.non2xxACK, c.cancelRequested, c.lastRSeq, c.lastInviteReason = false, false, "", ""
	c.remoteTarget, c.routeSet, c.pracked = "", nil, nil
	c.dtmfPayload, c.dtmfReady, c.dtmfSending = 101, false, false
	c.state.State = state
	c.state.MediaReady = false
	c.state.EarlyMedia = false
	if err != nil {
		c.state.LastError = err.Error()
	}
	c.mu.Unlock()
	if amr != nil {
		amr.close()
	}
}

func (c *callRuntime) close() { c.finish("ended", nil) }

func (c *callRuntime) buildRequest(method sip.RequestMethod, peer, callID string, cseq uint32, body []byte) ([]byte, error) {
	phoneContext := strings.TrimSpace(c.service.cfg.CallPhoneContext)
	if phoneContext == "" {
		phoneContext = c.service.cfg.HomeDomain
	}
	target, err := normalizeCallTarget(peer, phoneContext, c.service.cfg.Realm)
	if err != nil {
		return nil, err
	}
	toTarget := target
	localPort := c.service.transportRuntime.policy.LocalPortC
	c.mu.Lock()
	if c.localTag == "" {
		c.localTag = sip.GenerateTagN(16)
	}
	wasNon2xxACK := method == sip.ACK && c.non2xxACK
	branch := sip.GenerateBranchN(16)
	if method == sip.INVITE {
		c.inviteBranch, c.inviteCSeq = branch, cseq
	} else if method == sip.CANCEL {
		branch, cseq = c.inviteBranch, c.inviteCSeq
	} else if method == sip.ACK {
		cseq = c.inviteCSeq
		if c.non2xxACK {
			branch = c.inviteBranch
			c.non2xxACK = false
		}
	}
	localTag, remoteTag, lastRSeq, inviteCSeq := c.localTag, c.remoteTag, c.lastRSeq, c.inviteCSeq
	remoteTarget := c.remoteTarget
	routeSet := append([]string(nil), c.routeSet...)
	dialogACK := method == sip.ACK && !wasNon2xxACK
	c.mu.Unlock()
	if (method == sip.PRACK || method == sip.BYE || method == sip.INFO || dialogACK) && remoteTarget != "" {
		target = remoteTarget
	}
	uri := sip.Uri{}
	if err := sip.ParseUri(target, &uri); err != nil {
		return nil, fmt.Errorf("imscore: invalid call target: %w", err)
	}
	request := sip.NewRequest(method, uri)
	request.AppendHeader(sip.NewHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s;rport", strings.ToUpper(registerTransportName(c.service.cfg, "")), formatRegisterViaHost(c.service.cfg.LocalIP, localPort), branch)))
	fromURI, preferredIdentity := c.originatingIdentities()
	request.AppendHeader(sip.NewHeader("From", "<"+fromURI+">;tag="+localTag))
	to := "<" + toTarget + ">"
	// CANCEL is part of the original INVITE transaction, not an in-dialog
	// request. Its To header must match the original INVITE and therefore must
	// not acquire the tag learned from a provisional response.
	if remoteTag != "" && method != sip.CANCEL {
		to += ";tag=" + remoteTag
	}
	request.AppendHeader(sip.NewHeader("To", to))
	request.AppendHeader(sip.NewHeader("Call-ID", callID))
	request.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d %s", cseq, method)))
	request.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	if (method == sip.PRACK || method == sip.BYE || method == sip.INFO || dialogACK) && len(routeSet) > 0 {
		for _, route := range routeSet {
			request.AppendHeader(sip.NewHeader("Route", route))
		}
	} else {
		request.AppendHeader(sip.NewHeader("Route", "<sip:"+effectiveRouteAddr(c.service.cfg)+";lr>"))
	}
	if method == sip.INVITE {
		contactState := registerState{sipInstance: strings.TrimSpace(c.service.cfg.SIPInstanceURN)}
		request.AppendHeader(sip.NewHeader("Contact", buildIMSCoreContact(c.service.cfg, contactState, c.service.transportRuntime.policy.LocalPortS)))
		request.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+preferredIdentity+">"))
		request.AppendHeader(sip.NewHeader("P-Preferred-Service", "urn:urn-7:3gpp-service.ims.icsi.mmtel"))
		// Carrier bundles may require an explicit early-media capability on the
		// originating INVITE. Emit only when the reviewed profile requests it;
		// unknown carriers retain the interoperable baseline without this
		// vendor-sensitive extension.
		if c.service.cfg.Template.SupportPEarlyMedia && c.service.cfg.Template.EarlyMediaNeedsHeader {
			request.AppendHeader(sip.NewHeader("P-Early-Media", "supported"))
		}
		request.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.icsi-ref=\""+encodedICSIRef(c.service.cfg.Template)+"\""))
		if templateIncludesCallPANI(c.service.cfg.Template) {
			request.AppendHeader(sip.NewHeader("P-Access-Network-Info", effectiveCallPANI(c.service.cfg.Template)))
		}
		request.AppendHeader(sip.NewHeader("Session-Expires", "1800;refresher=uac"))
		request.AppendHeader(sip.NewHeader("Min-SE", "90"))
		request.AppendHeader(sip.NewHeader("Accept", "application/sdp"))
	}
	request.AppendHeader(sip.NewHeader("Supported", "100rel,timer,replaces"))
	request.AppendHeader(sip.NewHeader("Allow", "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,INFO,OPTIONS,MESSAGE"))
	if userAgent := strings.TrimSpace(c.service.cfg.UserAgent); userAgent != "" {
		request.AppendHeader(sip.NewHeader("User-Agent", userAgent))
	}
	if method == sip.PRACK && lastRSeq != "" {
		request.AppendHeader(sip.NewHeader("RAck", fmt.Sprintf("%s %d INVITE", lastRSeq, inviteCSeq)))
	}
	if method != sip.INVITE && templateIncludesCallPANI(c.service.cfg.Template) {
		request.AppendHeader(sip.NewHeader("P-Access-Network-Info", effectiveCallPANI(c.service.cfg.Template)))
	}
	if c.service.verifyHeader != "" {
		request.AppendHeader(sip.NewHeader("Security-Verify", c.service.verifyHeader))
	}
	if len(body) > 0 {
		contentType := "application/sdp"
		if method == sip.INFO {
			contentType = "application/dtmf-relay"
		}
		request.AppendHeader(sip.NewHeader("Content-Type", contentType))
		request.SetBody(body)
	}
	request.SetDestination(effectiveTransportAddr(c.service.cfg))
	request.SetTransport(strings.ToUpper(registerTransportName(c.service.cfg, "")))
	ensureSIPStreamFraming(request)
	return []byte(request.String()), nil
}

// normalizeCallTarget converts a user dial string into an RFC 3966 target.
// E.164 numbers are globally scoped. National numbers and carrier service
// codes (for example CTExcel 888) are local numbers and must carry the home
// IMS domain as phone-context; a naked tel:888 is not a valid local tel URI.
func normalizeCallTarget(peer, homeDomain, realm string) (string, error) {
	target := strings.TrimSpace(peer)
	if target == "" {
		return "", fmt.Errorf("imscore: call target is required")
	}
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "tel:") {
		return target, nil
	}
	compact := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(target)
	if strings.HasPrefix(compact, "+") {
		return "tel:" + compact, nil
	}
	context := strings.TrimSpace(homeDomain)
	if context == "" {
		context = strings.TrimSpace(realm)
	}
	context = strings.TrimPrefix(strings.TrimPrefix(context, "sip:"), "SIP:")
	if context == "" {
		return "", fmt.Errorf("imscore: local call target %q requires phone-context", target)
	}
	return "tel:" + compact + ";phone-context=" + context, nil
}

func callRejectionError(response *sip.Response) error {
	return callRejectionErrorWithFallback(response, "")
}

func callRejectionErrorWithFallback(response *sip.Response, fallbackReason string) error {
	if response == nil {
		return fmt.Errorf("IMS 网络终止了呼叫")
	}
	if response.StatusCode == 487 {
		reasonValue := ""
		if reason := response.GetHeader("Reason"); reason != nil {
			reasonValue = strings.TrimSpace(reason.Value())
		}
		if reasonValue == "" {
			reasonValue = strings.TrimSpace(fallbackReason)
		}
		if reasonValue != "" {
			if cause, ok := q850Cause(reasonValue); ok {
				switch cause {
				case "1":
					return fmt.Errorf("运营商终止呼叫：SIP 487 / Q.850 1，号码不存在或未分配")
				case "20":
					return fmt.Errorf("运营商终止呼叫：SIP 487 / Q.850 20，被叫暂时不可达")
				case "127":
					return fmt.Errorf("运营商终止呼叫：SIP 487 / Q.850 127 互通失败")
				}
			}
			return fmt.Errorf("运营商终止呼叫：SIP 487 Request Terminated；Reason: %s", reasonValue)
		}
		return fmt.Errorf("运营商终止呼叫：SIP 487 Request Terminated")
	}
	return fmt.Errorf("IMS call rejected: SIP %d %s", response.StatusCode, response.Reason)
}

func q850Cause(value string) (string, bool) {
	parts := strings.Split(value, ";")
	if len(parts) < 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "q.850") {
		return "", false
	}
	for _, part := range parts[1:] {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) == 2 && strings.EqualFold(strings.TrimSpace(pair[0]), "cause") {
			cause := strings.Trim(strings.TrimSpace(pair[1]), `"`)
			if cause != "" {
				return cause, true
			}
		}
	}
	return "", false
}

func (c *callRuntime) updateDialogFromResponse(response *sip.Response) {
	c.updateDialogFromResponseForCall(response, "")
}

func (c *callRuntime) updateDialogFromResponseForCall(response *sip.Response, expectedCallID string) bool {
	if c == nil || response == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if expectedCallID != "" && c.state.CallID != expectedCallID {
		return false
	}
	if to := response.To(); to != nil {
		if tag, ok := to.Params.Get("tag"); ok {
			c.remoteTag = tag
		}
	}
	if contact := response.GetHeader("Contact"); contact != nil {
		if target := headerAddressURI(contact.Value()); target != "" {
			c.remoteTarget = target
		}
	}
	if headers := response.GetHeaders("Record-Route"); len(headers) > 0 {
		routes := make([]string, 0, len(headers))
		for i := len(headers) - 1; i >= 0; i-- {
			if value := strings.TrimSpace(headers[i].Value()); value != "" {
				routes = append(routes, value)
			}
		}
		c.routeSet = routes
	}
	return true
}

func headerAddressURI(value string) string {
	value = strings.TrimSpace(value)
	if left := strings.IndexByte(value, '<'); left >= 0 {
		if right := strings.IndexByte(value[left+1:], '>'); right >= 0 {
			return strings.TrimSpace(value[left+1 : left+1+right])
		}
	}
	if semicolon := strings.IndexByte(value, ';'); semicolon >= 0 {
		value = value[:semicolon]
	}
	return strings.TrimSpace(value)
}

// originatingIdentities follows the public identity that IMS associated with
// the registration.  Some TAS deployments accept an IMSI IMPU at REGISTER but
// reject an originating MMTEL INVITE unless From/P-Preferred-Identity use the
// assigned E.164 identity.
func (c *callRuntime) originatingIdentities() (fromURI, preferredIdentity string) {
	if c != nil && c.service != nil {
		number := strings.TrimSpace(c.service.registeredMSISDN)
		if strings.HasPrefix(number, "+") {
			domain := strings.TrimSpace(c.service.cfg.HomeDomain)
			if domain == "" {
				domain = strings.TrimSpace(c.service.cfg.Realm)
			}
			if domain != "" {
				return "sip:" + number + "@" + domain + ";user=phone", "tel:" + number
			}
		}
		fallback := strings.TrimSpace(c.service.cfg.PublicURI)
		return fallback, fallback
	}
	return "", ""
}

func headerContainsToken(header sip.Header, token string) bool {
	if header == nil {
		return false
	}
	for _, value := range strings.Split(header.Value(), ",") {
		if strings.EqualFold(strings.TrimSpace(value), token) {
			return true
		}
	}
	return false
}

func (c *callRuntime) localSDP(port int) []byte {
	ip := c.service.cfg.LocalIP.String()
	family := "IP4"
	if c.service.cfg.LocalIP.To4() == nil {
		family = "IP6"
	}
	var sessionID uint64
	_ = binary.Read(rand.Reader, binary.BigEndian, &sessionID)
	c.mu.Lock()
	direction, codec, payloadType, dtmfPayload, dtmfReady, amrOctetAligned := c.state.Direction, c.state.Codec, c.payloadType, c.dtmfPayload, c.dtmfReady, c.amrOctetAligned
	c.mu.Unlock()
	// PCMA remains the preferred codec. CTExcel/EE service numbers have been
	// observed to reject a PCMA-only offer with Q.850 cause 127, while accepting
	// AMR-NB mode 7. Advertise the implemented AMR fallback after PCMA instead
	// of making the carrier compatibility path the global default.
	if direction != "incoming" {
		if c.service.cfg.DisableAMR {
			return []byte(fmt.Sprintf("v=0\r\no=- %d 1 IN %s %s\r\ns=Proletarius\r\nc=IN %s %s\r\nt=0 0\r\nm=audio %d RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=maxptime:40\r\na=sendrecv\r\n", sessionID, family, ip, family, ip, port))
		}
		return []byte(fmt.Sprintf("v=0\r\no=- %d 1 IN %s %s\r\ns=Proletarius\r\nc=IN %s %s\r\nt=0 0\r\nm=audio %d RTP/AVP 8 97 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:97 AMR/8000\r\na=fmtp:97 octet-align=1;mode-set=7;max-red=0\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=maxptime:40\r\na=sendrecv\r\n", sessionID, family, ip, family, ip, port))
	}
	if payloadType == 0 {
		if codec == "AMR" {
			payloadType = 97
		} else {
			payloadType = 8
		}
	}
	payloads := strconv.Itoa(int(payloadType))
	attributes := fmt.Sprintf("a=rtpmap:%d PCMA/8000\r\n", payloadType)
	if codec == "AMR" {
		fmtp := "mode-set=7;max-red=0"
		if amrOctetAligned {
			fmtp = "octet-align=1;" + fmtp
		}
		attributes = fmt.Sprintf("a=rtpmap:%d AMR/8000\r\na=fmtp:%d %s\r\n", payloadType, payloadType, fmtp)
	}
	if dtmfReady {
		payloads += fmt.Sprintf(" %d", dtmfPayload)
		attributes += fmt.Sprintf("a=rtpmap:%d telephone-event/8000\r\na=fmtp:%d 0-15\r\n", dtmfPayload, dtmfPayload)
	}
	return []byte(fmt.Sprintf("v=0\r\no=- %d 1 IN %s %s\r\ns=Proletarius\r\nc=IN %s %s\r\nt=0 0\r\nm=audio %d RTP/AVP %s\r\n%sa=ptime:20\r\na=maxptime:20\r\na=sendrecv\r\n", sessionID, family, ip, family, ip, port, payloads, attributes))
}

func (c *callRuntime) applyRemoteSDP(body []byte, answer bool) error {
	if len(body) == 0 {
		c.mu.Lock()
		negotiated := answer && c.remoteRTP != nil && (c.state.Codec == "PCMA" || c.state.Codec == "AMR")
		c.mu.Unlock()
		if negotiated { // A final 200 may reuse the reliable early-media answer.
			return nil
		}
		return fmt.Errorf("imscore: remote SDP is missing; voice media was not negotiated")
	}
	var sessionIP, mediaIP net.IP
	port := 0
	payloadType := -1
	dtmfPayloadType := -1
	codec := ""
	amrOctetAligned := true
	mediaSection, audioSection, foundAudio := false, false, false
	var offeredPayloads []string
	rtpmap := make(map[string]string)
	fmtp := make(map[string]string)
	for _, raw := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "m=") {
			mediaSection, audioSection = true, false
			fields := strings.Fields(line)
			if !foundAudio && len(fields) > 3 && fields[0] == "m=audio" {
				parsedPort, err := strconv.Atoi(fields[1])
				if err != nil || parsedPort <= 0 || parsedPort > 65535 || fields[2] != "RTP/AVP" {
					continue
				}
				foundAudio, audioSection, port = true, true, parsedPort
				offeredPayloads = append([]string(nil), fields[3:]...)
			}
			continue
		}
		if strings.HasPrefix(line, "c=IN IP4 ") || strings.HasPrefix(line, "c=IN IP6 ") {
			parts := strings.Fields(line)
			if len(parts) == 3 {
				if !mediaSection {
					sessionIP = net.ParseIP(parts[2])
				} else if audioSection {
					mediaIP = net.ParseIP(parts[2])
					if mediaIP == nil {
						return fmt.Errorf("imscore: remote audio SDP has an invalid numeric address")
					}
				}
			}
		}
		if audioSection && strings.HasPrefix(strings.ToLower(line), "a=rtpmap:") {
			parts := strings.Fields(strings.TrimSpace(line[len("a=rtpmap:"):]))
			if len(parts) >= 2 {
				rtpmap[parts[0]] = strings.ToUpper(parts[1])
			}
		}
		if audioSection && strings.HasPrefix(strings.ToLower(line), "a=fmtp:") {
			parts := strings.SplitN(strings.TrimSpace(line[len("a=fmtp:"):]), " ", 2)
			if len(parts) == 2 {
				fmtp[parts[0]] = strings.ToLower(parts[1])
			}
		}
	}
	if mediaIP == nil {
		mediaIP = sessionIP
	}
	for _, payload := range offeredPayloads {
		parsed, err := strconv.Atoi(payload)
		if err != nil || parsed < 0 || parsed > 127 {
			continue
		}
		mapping := rtpmap[payload]
		pcma := mapping == "PCMA/8000" || mapping == "PCMA/8000/1"
		if (parsed == 8 && (mapping == "" || pcma)) || (!answer && parsed >= 96 && pcma) {
			payloadType = parsed
			codec = "PCMA"
			break
		}
	}
	if codec == "" && (c.service == nil || !c.service.cfg.DisableAMR) {
		for _, payload := range offeredPayloads {
			parsed, err := strconv.Atoi(payload)
			if err != nil || parsed < 96 || parsed > 127 || rtpmap[payload] != "AMR/8000" {
				continue
			}
			parameters := fmtp[payload]
			if !hasSDPMode(parameters, 7) {
				continue
			}
			payloadType, codec = parsed, "AMR"
			// RFC 4867 defaults to bandwidth-efficient mode when octet-align
			// is absent. O2/giffgaff uses exactly that form for incoming calls.
			amrOctetAligned = hasSDPParameter(parameters, "octet-align", "1")
			break
		}
	}
	for _, payload := range offeredPayloads {
		if rtpmap[payload] == "TELEPHONE-EVENT/8000" || rtpmap[payload] == "TELEPHONE-EVENT/8000/1" {
			// The peer's answer declares the payload number it receives.
			// RFC 3264 permits asymmetric mappings: do not require our offered 101.
			if parsed, parseErr := strconv.Atoi(payload); parseErr == nil && parsed >= 96 && parsed <= 127 && parsed != payloadType {
				dtmfPayloadType = parsed
				break
			}
		}
	}
	if mediaIP == nil || port <= 0 {
		return fmt.Errorf("imscore: remote SDP does not contain a numeric RTP endpoint")
	}
	if payloadType < 0 {
		return fmt.Errorf("imscore: 运营商未协商受支持的 PCMA 或 AMR-NB mode 7，无法建立语音")
	}
	c.mu.Lock()
	c.remoteRTP = &net.UDPAddr{IP: mediaIP, Port: port}
	c.state.Codec = codec
	c.state.MediaReady = true
	c.payloadType = byte(payloadType)
	c.amrOctetAligned = amrOctetAligned
	c.dtmfReady = dtmfPayloadType >= 0
	if c.dtmfReady {
		c.dtmfPayload = byte(dtmfPayloadType)
	}
	c.mu.Unlock()
	return nil
}

func hasSDPParameter(parameters, name, expected string) bool {
	for _, field := range strings.Split(parameters, ";") {
		pair := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(pair) == 2 && strings.EqualFold(strings.TrimSpace(pair[0]), name) && strings.TrimSpace(pair[1]) == expected {
			return true
		}
	}
	return false
}

func hasSDPMode(parameters string, wanted int) bool {
	for _, field := range strings.Split(parameters, ";") {
		pair := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(pair) != 2 || !strings.EqualFold(strings.TrimSpace(pair[0]), "mode-set") {
			continue
		}
		for _, mode := range strings.Split(pair[1], ",") {
			if parsed, err := strconv.Atoi(strings.TrimSpace(mode)); err == nil && parsed == wanted {
				return true
			}
		}
	}
	return false
}

const amrMode7SpeechBits = 244

// amrOctetAlignedToBandwidthEfficient converts one mode-7 AMR-NB frame from
// RFC 4867 octet-aligned form (CMR octet, ToC octet, 31 speech octets) to the
// bandwidth-efficient bit layout used by O2/giffgaff MT calls.
func amrOctetAlignedToBandwidthEfficient(payload []byte) ([]byte, error) {
	if len(payload) < 33 {
		return nil, fmt.Errorf("imscore: truncated octet-aligned AMR mode-7 payload")
	}
	toc := payload[1]
	if toc&0x80 != 0 || (toc>>3)&0x0f != 7 || toc&0x04 == 0 {
		return nil, fmt.Errorf("imscore: unsupported octet-aligned AMR frame")
	}
	out := make([]byte, (4+6+amrMode7SpeechBits+7)/8)
	writeBits(out, 0, uint64(payload[0]>>4), 4)
	writeBits(out, 4, 0, 1) // F=0, one frame per 20 ms packet.
	writeBits(out, 5, uint64((toc>>3)&0x0f), 4)
	writeBits(out, 9, uint64((toc>>2)&0x01), 1)
	for bit := 0; bit < amrMode7SpeechBits; bit++ {
		writeBits(out, 10+bit, uint64(readBit(payload[2:], bit)), 1)
	}
	return out, nil
}

func amrBandwidthEfficientToOctetAligned(payload []byte) ([]byte, error) {
	if len(payload)*8 < 4+6+amrMode7SpeechBits {
		return nil, fmt.Errorf("imscore: truncated bandwidth-efficient AMR mode-7 payload")
	}
	if readBit(payload, 4) != 0 {
		return nil, fmt.Errorf("imscore: multi-frame bandwidth-efficient AMR is not supported")
	}
	frameType := int(readBits(payload, 5, 4))
	quality := byte(readBits(payload, 9, 1))
	if frameType != 7 || quality == 0 {
		return nil, fmt.Errorf("imscore: unsupported bandwidth-efficient AMR frame type %d", frameType)
	}
	out := make([]byte, 33)
	out[0] = byte(readBits(payload, 0, 4)) << 4
	out[1] = byte(frameType<<3) | quality<<2
	for bit := 0; bit < amrMode7SpeechBits; bit++ {
		writeBits(out[2:], bit, uint64(readBit(payload, 10+bit)), 1)
	}
	return out, nil
}

func readBit(data []byte, bit int) byte {
	return (data[bit/8] >> (7 - uint(bit%8))) & 1
}

func readBits(data []byte, offset, count int) uint64 {
	var value uint64
	for index := 0; index < count; index++ {
		value = value<<1 | uint64(readBit(data, offset+index))
	}
	return value
}

func writeBits(data []byte, offset int, value uint64, count int) {
	for index := 0; index < count; index++ {
		bit := byte((value >> uint(count-1-index)) & 1)
		position := offset + index
		mask := byte(1 << (7 - uint(position%8)))
		if bit != 0 {
			data[position/8] |= mask
		} else {
			data[position/8] &^= mask
		}
	}
}

func (c *callRuntime) startMedia() {
	c.mu.Lock()
	codec, media, audio, remote := c.state.Codec, c.media, c.audioConn, c.remoteRTP
	if codec != "PCMA" && codec != "AMR" {
		c.state.MediaReady = false
		c.state.LastError = "运营商协商了不受支持的语音编码：" + codec
		c.mu.Unlock()
		return
	}
	if codec == "AMR" && c.amr == nil {
		amr, err := newAMRNBCodec()
		if err != nil {
			c.state.MediaReady = false
			c.state.LastError = err.Error()
			c.mu.Unlock()
			return
		}
		c.amr = amr
	}
	c.mu.Unlock()
	if media == nil || audio == nil || remote == nil {
		return
	}
	c.mediaOnce.Do(func() {
		var seed [10]byte
		_, _ = rand.Read(seed[:])
		c.rtpSeq = binary.BigEndian.Uint16(seed[:2])
		c.rtpTimestamp = binary.BigEndian.Uint32(seed[2:6])
		c.ssrc = binary.BigEndian.Uint32(seed[6:10])
		go c.runAudioUplink(audio, media, remote)
		go c.runRTPDownlink(media, audio)
	})
}

func (c *callRuntime) makeRTPPacket(payloadType byte, timestamp uint32, marker bool, payload []byte) []byte {
	packet := make([]byte, 12+len(payload))
	packet[0], packet[1] = 0x80, payloadType&0x7f
	if marker {
		packet[1] |= 0x80
	}
	binary.BigEndian.PutUint16(packet[2:4], c.rtpSeq)
	binary.BigEndian.PutUint32(packet[4:8], timestamp)
	binary.BigEndian.PutUint32(packet[8:12], c.ssrc)
	copy(packet[12:], payload)
	c.rtpSeq++
	return packet
}

func dtmfEvent(digit string) (byte, bool) {
	switch digit {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9":
		return digit[0] - '0', true
	case "*":
		return 10, true
	case "#":
		return 11, true
	default:
		return 0, false
	}
}

func (c *callRuntime) sendDTMF(ctx context.Context, digit string) error {
	event, err := c.resolveDTMFEvent(ctx, digit)
	if err != nil {
		return err
	}
	c.dtmfMu.Lock()
	defer c.dtmfMu.Unlock()
	c.mu.Lock()
	state, media, remote := c.state.State, c.media, c.remoteRTP
	payloadType, ready := c.dtmfPayload, c.dtmfReady
	c.mu.Unlock()
	if state != "active" || media == nil || remote == nil {
		return fmt.Errorf("imscore: DTMF requires an active call")
	}
	if !ready {
		return c.sendDTMFInfo(ctx, event)
	}
	// Serialize with speech RTP so event and audio packets share one monotonic
	// sequence space. Three identical end packets make the selection robust to
	// isolated packet loss without extending the perceived key press.
	c.mu.Lock()
	c.dtmfSending = true
	c.mu.Unlock()
	c.rtpMu.Lock()
	startTimestamp := c.rtpTimestamp
	c.rtpMu.Unlock()
	defer func() {
		c.mu.Lock()
		c.dtmfSending = false
		c.mu.Unlock()
	}()
	steps := []struct {
		duration uint16
		end      bool
	}{
		{160, false}, {320, false}, {480, false}, {640, false},
		{800, true}, {800, true}, {800, true},
	}
	for index, step := range steps {
		payload := []byte{event, 10, 0, 0}
		if step.end {
			payload[1] |= 0x80
		}
		binary.BigEndian.PutUint16(payload[2:4], step.duration)
		c.rtpMu.Lock()
		packet := c.makeRTPPacket(payloadType, startTimestamp, index == 0, payload)
		_, writeErr := media.WriteTo(packet, remote)
		c.rtpMu.Unlock()
		if writeErr != nil {
			return writeErr
		}
		if index+1 < len(steps) {
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	// Speech was intentionally paused while the event was emitted. Advance by
	// the elapsed 20 ms slots so the next audio timestamp remains continuous.
	c.rtpMu.Lock()
	c.rtpTimestamp = startTimestamp + uint32(len(steps)*160)
	c.rtpMu.Unlock()
	return nil
}

func (c *callRuntime) resolveDTMFEvent(ctx context.Context, digit string) (byte, error) {
	digit = strings.TrimSpace(digit)
	event, ok := dtmfEvent(digit)
	if c != nil && c.service != nil && c.service.cfg.DTMFEvent != nil {
		validator := c.service.cfg.DTMFEvent
		var err error
		event, err = validator(ctx, digit)
		if err != nil {
			return 0, fmt.Errorf("imscore: validate DTMF: %w", err)
		}
		ok = true
	}
	if !ok {
		return 0, fmt.Errorf("imscore: DTMF digit must be 0-9, * or #")
	}
	return event, nil
}

func (c *callRuntime) runAudioUplink(audio *net.UDPConn, media net.PacketConn, remote *net.UDPAddr) {
	buf := make([]byte, 2048)
	for {
		n, peer, err := audio.ReadFromUDP(buf)
		if err != nil {
			return
		}
		c.mu.Lock()
		token := c.state.AudioToken
		codec, pt, amr, dtmfSending, amrOctetAligned := c.state.Codec, c.payloadType, c.amr, c.dtmfSending, c.amrOctetAligned
		// The final answer or a re-INVITE may replace the early-media
		// destination. Do not keep sending microphone audio to the old port.
		remote = c.remoteRTP
		c.mu.Unlock()
		if remote == nil {
			continue
		}
		prefix := []byte(token + "\x00")
		if n <= len(prefix) || string(buf[:len(prefix)]) != string(prefix) {
			continue
		}
		c.mu.Lock()
		c.audioPeer = peer
		c.mu.Unlock()
		// Keep draining microphone datagrams while RFC 4733 is active so stale
		// speech is not burst-transmitted after the key event ends.
		if dtmfSending {
			continue
		}
		pcm := buf[len(prefix):n]
		if len(pcm) != 320 {
			continue
		}
		var payload []byte
		if codec == "AMR" {
			payload, err = amr.encode(pcm)
			if err != nil {
				c.setState("failed", err)
				return
			}
			if !amrOctetAligned {
				payload, err = amrOctetAlignedToBandwidthEfficient(payload)
				if err != nil {
					c.setState("failed", err)
					return
				}
			}
		} else {
			payload = encodeG711(pcm, true)
		}
		c.rtpMu.Lock()
		c.mu.Lock()
		dtmfSending = c.dtmfSending
		c.mu.Unlock()
		if dtmfSending {
			c.rtpMu.Unlock()
			continue
		}
		packet := c.makeRTPPacket(pt, c.rtpTimestamp, false, payload)
		_, sendErr := media.WriteTo(packet, remote)
		c.mu.Lock()
		if sendErr != nil {
			c.state.AudioTransportErrors++
		} else {
			c.state.RTPTransmitted++
		}
		c.mu.Unlock()
		c.rtpTimestamp += 160
		c.rtpMu.Unlock()
	}
}

func (c *callRuntime) runRTPDownlink(media net.PacketConn, audio *net.UDPConn) {
	buf := make([]byte, 2048)
	var lastSequence uint16
	var haveSequence bool
	var currentSSRC uint32
	var lastPCM []byte
	for {
		n, _, err := media.ReadFrom(buf)
		if err != nil {
			return
		}
		decoded, ok := parseRTPPacket(buf[:n])
		if !ok {
			continue
		}
		c.mu.Lock()
		expectedPT := c.payloadType
		c.mu.Unlock()
		if decoded.payloadType != expectedPT {
			continue
		}
		c.mu.Lock()
		c.state.RTPReceived++
		c.mu.Unlock()
		if !haveSequence || decoded.ssrc != currentSSRC {
			// A media gateway handover can legitimately replace the SSRC and
			// restart sequence numbering. Treat it as a new stream, not as a
			// flood of stale/out-of-order packets.
			haveSequence = false
			currentSSRC = decoded.ssrc
			lastPCM = lastPCM[:0]
		}
		missing := 0
		if haveSequence {
			delta := int16(decoded.sequence - lastSequence)
			if delta <= 0 {
				// Late and duplicated packets are more harmful than a concealed
				// frame: decoding them would replay stale speech as a loud click.
				continue
			}
			if delta > 1 {
				// Bound latency while still giving the local playback buffer a
				// smooth decay for ordinary and burst packet loss.
				missing = min(int(delta)-1, 3)
			}
		}
		lastSequence, haveSequence = decoded.sequence, true
		c.mu.Lock()
		peer, token, codec, amr, amrOctetAligned := c.audioPeer, c.state.AudioToken, c.state.Codec, c.amr, c.amrOctetAligned
		c.mu.Unlock()
		if peer == nil {
			continue
		}
		var pcm []byte
		if codec == "AMR" {
			amrPayload := decoded.payload
			if !amrOctetAligned {
				amrPayload, err = amrBandwidthEfficientToOctetAligned(amrPayload)
			}
			if err == nil {
				pcm, err = amr.decode(amrPayload)
			}
			if err != nil {
				c.mu.Lock()
				c.state.AudioDecodeErrors++
				c.mu.Unlock()
				for index := 0; index <= missing; index++ {
					concealed := concealPCMFrame(lastPCM, index+1)
					packet := append([]byte(token+"\x00"), concealed...)
					_, _ = audio.WriteToUDP(packet, peer)
				}
				continue
			}
		} else {
			pcm = decodeG711(decoded.payload, true)
		}
		for index := 0; index < missing; index++ {
			concealed := concealPCMFrame(lastPCM, index+1)
			packet := append([]byte(token+"\x00"), concealed...)
			_, _ = audio.WriteToUDP(packet, peer)
		}
		if missing > 0 {
			fadeInPCMFrame(pcm, 40)
		}
		// The native bridge consumes 20 ms frames. G.711 gateways can pack
		// several frames into one RTP packet (for example ptime=40/60).
		// Passing that packet through whole made the bridge discard all audio.
		for _, frame := range splitPCMFrames(pcm) {
			packet := append([]byte(token+"\x00"), frame...)
			_, _ = audio.WriteToUDP(packet, peer)
		}
		if len(pcm) >= 320 {
			lastPCM = append(lastPCM[:0], pcm[len(pcm)-320:]...)
		}
	}
}

func splitPCMFrames(pcm []byte) [][]byte {
	if len(pcm) == 0 || len(pcm)%320 != 0 {
		return nil
	}
	frames := make([][]byte, 0, len(pcm)/320)
	for offset := 0; offset < len(pcm); offset += 320 {
		frames = append(frames, pcm[offset:offset+320])
	}
	return frames
}

func concealPCMFrame(previous []byte, depth int) []byte {
	out := make([]byte, 320)
	if len(previous) < len(out) {
		return out
	}
	// Repeating a full speech frame creates a very audible 50 Hz buzz. Hold the
	// final sample instead and decay it continuously across at most three lost
	// frames. Adjacent envelopes meet at the same gain, avoiding a click at the
	// synthetic-frame boundaries.
	startGain := []float64{0.90, 0.30, 0.08}[min(max(depth-1, 0), 2)]
	endGain := []float64{0.30, 0.08, 0.00}[min(max(depth-1, 0), 2)]
	lastSample := int16(binary.LittleEndian.Uint16(previous[len(out)-2:]))
	for offset := 0; offset < len(out); offset += 2 {
		position := float64(offset/2) / 159
		weight := 0.5 - 0.5*math.Cos(math.Pi*position)
		gain := startGain + (endGain-startGain)*weight
		binary.LittleEndian.PutUint16(out[offset:], uint16(int16(float64(lastSample)*gain)))
	}
	return out
}

func fadeInPCMFrame(frame []byte, samples int) {
	count := min(len(frame)/2, samples)
	if count <= 0 {
		return
	}
	for index := 0; index < count; index++ {
		position := float64(index+1) / float64(count)
		gain := 0.5 - 0.5*math.Cos(math.Pi*position)
		offset := index * 2
		sample := int16(binary.LittleEndian.Uint16(frame[offset:]))
		binary.LittleEndian.PutUint16(frame[offset:], uint16(int16(float64(sample)*gain)))
	}
}

type parsedRTPPacket struct {
	payload     []byte
	payloadType byte
	sequence    uint16
	timestamp   uint32
	marker      bool
	ssrc        uint32
}

func parseRTPPacket(packet []byte) (parsedRTPPacket, bool) {
	if len(packet) < 12 || packet[0]>>6 != 2 {
		return parsedRTPPacket{}, false
	}
	offset := 12 + int(packet[0]&0x0f)*4
	if offset > len(packet) {
		return parsedRTPPacket{}, false
	}
	if packet[0]&0x10 != 0 {
		if offset+4 > len(packet) {
			return parsedRTPPacket{}, false
		}
		extensionWords := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4 + extensionWords*4
		if offset > len(packet) {
			return parsedRTPPacket{}, false
		}
	}
	end := len(packet)
	if packet[0]&0x20 != 0 {
		padding := int(packet[len(packet)-1])
		if padding == 0 || padding > end-offset {
			return parsedRTPPacket{}, false
		}
		end -= padding
	}
	if offset >= end {
		return parsedRTPPacket{}, false
	}
	return parsedRTPPacket{
		payload:     packet[offset:end],
		payloadType: packet[1] & 0x7f,
		sequence:    binary.BigEndian.Uint16(packet[2:4]),
		timestamp:   binary.BigEndian.Uint32(packet[4:8]),
		marker:      packet[1]&0x80 != 0,
		ssrc:        binary.BigEndian.Uint32(packet[8:12]),
	}, true
}

// rtpPayload validates the RTP v2 header and strips CSRC, extension and padding.
func rtpPayload(packet []byte) ([]byte, byte, bool) {
	parsed, ok := parseRTPPacket(packet)
	if !ok {
		return nil, 0, false
	}
	return parsed.payload, parsed.payloadType, true
}

func encodeG711(pcm []byte, alaw bool) []byte {
	out := make([]byte, len(pcm)/2)
	for i := range out {
		s := int16(binary.LittleEndian.Uint16(pcm[i*2:]))
		if alaw {
			out[i] = linearToALaw(s)
		} else {
			out[i] = linearToMuLaw(s)
		}
	}
	return out
}

func decodeG711(data []byte, alaw bool) []byte {
	out := make([]byte, len(data)*2)
	for i, b := range data {
		var s int16
		if alaw {
			s = aLawToLinear(b)
		} else {
			s = muLawToLinear(b)
		}
		binary.LittleEndian.PutUint16(out[i*2:], uint16(s))
	}
	return out
}

func linearToMuLaw(sample int16) byte {
	s := int(sample)
	sign := byte(0)
	if s < 0 {
		sign = 0x80
		s = -s
	}
	if s > 32635 {
		s = 32635
	}
	s += 132
	exp := 7
	for mask := 0x4000; exp > 0 && s&mask == 0; mask >>= 1 {
		exp--
	}
	mant := (s >> (exp + 3)) & 0x0f
	return ^(sign | byte(exp<<4) | byte(mant))
}
func muLawToLinear(v byte) int16 {
	v = ^v
	t := ((int(v) & 0x0f) << 3) + 132
	t <<= (v & 0x70) >> 4
	if v&0x80 != 0 {
		return int16(132 - t)
	}
	return int16(t - 132)
}
func linearToALaw(sample int16) byte {
	s := int(sample)
	sign := byte(0x80)
	if s < 0 {
		sign = 0
		s = -s - 1
	}
	if s > 32767 {
		s = 32767
	}
	var exp int
	if s >= 256 {
		for v := s >> 8; v > 1; v >>= 1 {
			exp++
		}
		exp++
		if exp > 7 {
			exp = 7
		}
	}
	mant := byte((s >> uint(exp+3)) & 0x0f)
	if exp == 0 {
		mant = byte((s >> 4) & 0x0f)
	}
	return (sign | byte(exp<<4) | mant) ^ 0x55
}
func aLawToLinear(v byte) int16 {
	v ^= 0x55
	t := int(v&0x0f) << 4
	exp := int((v & 0x70) >> 4)
	if exp == 0 {
		t += 8
	} else {
		t += 0x108
		t <<= uint(exp - 1)
	}
	if v&0x80 == 0 {
		return int16(-t)
	}
	return int16(t)
}

func sipCallIDFromRequest(req *sip.Request) string {
	if req == nil || req.GetHeader("Call-ID") == nil {
		return ""
	}
	return strings.TrimSpace(req.GetHeader("Call-ID").Value())
}

func sipRequestPeer(req *sip.Request) string {
	if req == nil || req.GetHeader("From") == nil {
		return ""
	}
	value := headerAddressURI(req.GetHeader("From").Value())
	value = strings.TrimPrefix(strings.TrimPrefix(value, "sip:"), "tel:")
	if at := strings.IndexByte(value, '@'); at >= 0 {
		value = value[:at]
	}
	if semicolon := strings.IndexByte(value, ';'); semicolon >= 0 {
		value = value[:semicolon]
	}
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return strings.TrimSpace(req.GetHeader("From").Value())
}

func isEmergencyNumber(value string) bool {
	n := strings.NewReplacer("+", "", " ", "", "-", "", "(", "", ")", "").Replace(value)
	switch n {
	case "112", "911", "1911", "999", "000", "110", "119", "120":
		return true
	}
	return false
}
