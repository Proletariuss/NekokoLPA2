//go:build !linux

package ipsec

type NetEvent struct {
	Type    NetEventType
	PMTU    uint32
	Reason  string
	OldPort int
	NewPort int
}

type NetEventType int

const (
	EventPathMTU NetEventType = iota
	EventNetworkDown
	EventNATPortChanged
)

// Darwin has no Linux MSG_ERRQUEUE. UDP transport errors are still reported
// by normal reads/writes and SWu's DPD/retransmission machinery.
func (s *SocketManager) startErrorListener() {}
