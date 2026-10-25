package imscore

import (
	"context"
	"fmt"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Legacy SIP INFO is a fallback, not permission to send an unnegotiated RTP
// payload. Await the matching final response; never retry an ambiguous digit.
func (c *callRuntime) sendDTMFInfo(ctx context.Context, event byte) error {
	if event > 15 {
		return fmt.Errorf("imscore: invalid DTMF event")
	}
	c.mu.Lock()
	if c.state.State != "active" || c.service == nil || c.service.transportRuntime == nil {
		c.mu.Unlock()
		return fmt.Errorf("imscore: DTMF requires an active IMS dialog")
	}
	peer, callID := c.state.Peer, c.state.CallID
	c.cseq++
	cseq := c.cseq
	c.mu.Unlock()
	body := []byte(fmt.Sprintf("Signal=%c\r\nDuration=160\r\n", "0123456789*#ABCD"[event]))
	payload, err := c.buildRequest(sip.INFO, peer, callID, cseq, body)
	if err != nil {
		return err
	}
	rt := c.service.transportRuntime
	responses, cancel, err := rt.subscribeResponses(callID)
	if err != nil {
		return err
	}
	defer cancel()
	bounded, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := rt.enqueueWrite(bounded, payload); err != nil {
		return err
	}
	for {
		select {
		case <-bounded.Done():
			return fmt.Errorf("imscore: 按键确认超时或已取消，未自动重发：%w", bounded.Err())
		case response := <-responses:
			if response == nil {
				return fmt.Errorf("imscore: 按键确认通道已关闭")
			}
			seq := response.CSeq()
			if seq == nil || seq.MethodName != sip.INFO || seq.SeqNo != cseq || response.StatusCode < 200 {
				continue
			}
			if response.StatusCode >= 300 {
				return fmt.Errorf("imscore: 运营商未协商 RTP 按键，且拒绝 SIP INFO 按键（SIP %d）", response.StatusCode)
			}
			return nil
		}
	}
}
