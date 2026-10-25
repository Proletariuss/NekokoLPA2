package ipsec3gpp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// PacketDataplane is the SWu CHILD_SA packet boundary used by the IMS
// userspace network stack. Packets are complete inner IPv4/IPv6 packets.
//
// The interface is intentionally identical to voiceclient.PacketDataplane,
// but is declared here to keep the IPsec transform independent of the SIP
// stack package.
type PacketDataplane interface {
	SendInnerPacket([]byte) error
	InnerPackets() <-chan []byte
}

// TransformingDataplaneStats reports transforms performed at the SWu/netstack
// boundary. A dropped inbound packet is one that claimed to be an IP packet
// but failed parsing, ESP authentication, anti-replay, or decryption.
type TransformingDataplaneStats struct {
	OutboundPackets uint64
	InboundPackets  uint64
	InboundDropped  uint64
}

// TransformingDataplane is the sole owner of an SWu PacketDataplane receive
// stream. Before Install it transparently forwards all packets, allowing the
// initial clear-text REGISTER exchange. Once an ipsec-3gpp Transport is
// installed it encrypts matching outbound TCP flows and decrypts inbound ESP
// packets before they reach the same userspace TCP stack.
//
// Installing a replacement transport is atomic at the packet boundary. This
// is needed when registrar failover negotiates a new Security-Server offer.
type TransformingDataplane struct {
	source   PacketDataplane
	sourceRX <-chan []byte
	inbound  chan []byte
	errors   chan error
	closed   chan struct{}
	done     chan struct{}

	transport atomic.Pointer[Transport]
	closeOnce sync.Once

	outboundPackets atomic.Uint64
	inboundPackets  atomic.Uint64
	inboundDropped  atomic.Uint64
}

// NewTransformingDataplane starts a single receive pump for source. Calling
// source.InnerPackets exactly once is deliberate: an SWu session exposes a
// queue, not a broadcast feed, so multiple consumers would steal packets from
// the IMS TCP stack.
func NewTransformingDataplane(source PacketDataplane) (*TransformingDataplane, error) {
	if source == nil {
		return nil, errors.New("ipsec3gpp: transforming dataplane requires source")
	}
	sourceRX := source.InnerPackets()
	if sourceRX == nil {
		return nil, errors.New("ipsec3gpp: transforming dataplane source has no receive channel")
	}
	dp := &TransformingDataplane{
		source:   source,
		sourceRX: sourceRX,
		inbound:  make(chan []byte, 512),
		errors:   make(chan error, 16),
		closed:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	go dp.receiveLoop()
	return dp, nil
}

// Install enables ipsec-3gpp packet transforms. The Transport contains the
// negotiated flow selectors, SAs, and replay state.
func (d *TransformingDataplane) Install(transport *Transport) error {
	if d == nil {
		return errors.New("ipsec3gpp: transforming dataplane is nil")
	}
	if transport == nil {
		return errors.New("ipsec3gpp: cannot install nil transport")
	}
	select {
	case <-d.closed:
		return net.ErrClosed
	default:
	}
	d.transport.Store(transport)
	return nil
}

// Clear disables packet transforms without replacing or closing the SWu
// session. It is primarily useful while abandoning a failed registrar and
// starting a new clear-text negotiation.
func (d *TransformingDataplane) Clear() {
	if d != nil {
		d.transport.Store(nil)
	}
}

// Installed reports whether a negotiated transform is active.
func (d *TransformingDataplane) Installed() bool {
	return d != nil && d.transport.Load() != nil
}

// SendInnerPacket transforms a matching outbound TCP packet and forwards the
// complete resulting IP packet to the SWu CHILD_SA.
func (d *TransformingDataplane) SendInnerPacket(packet []byte) error {
	if d == nil || d.source == nil {
		return net.ErrClosed
	}
	select {
	case <-d.closed:
		return net.ErrClosed
	default:
	}

	out := append([]byte(nil), packet...)
	// Preserve the established TCP packet/MSS path. UDP alone needs this
	// extra fragmentation after reassembly and ESP expansion.
	fragmentUDP := false
	if transport := d.transport.Load(); transport != nil {
		if parsed, parseErr := parseIPPacket(packet); parseErr == nil {
			fragmentUDP = parsed.nextHeader == ipProtoUDP
		}
		var err error
		out, err = transport.TransformOutbound(packet)
		if err != nil {
			d.reportError(err)
			return err
		}
	}
	if out == nil {
		return nil
	} // waiting for a complete fragmented datagram
	packets := [][]byte{out}
	if fragmentUDP {
		var err error
		packets, err = fragmentProtectedPacket(out)
		if err != nil {
			return err
		}
	}
	for _, packet := range packets {
		if err := d.source.SendInnerPacket(packet); err != nil {
			return err
		}
		d.outboundPackets.Add(1)
	}
	return nil
}

// InnerPackets returns the one transformed receive stream consumed by the
// userspace network stack.
func (d *TransformingDataplane) InnerPackets() <-chan []byte {
	if d == nil {
		return nil
	}
	return d.inbound
}

// Errors exposes best-effort asynchronous inbound transform failures. The
// channel is diagnostic only; malformed or unauthenticated ESP is always
// dropped instead of being injected into the TCP stack.
func (d *TransformingDataplane) Errors() <-chan error {
	if d == nil {
		return nil
	}
	return d.errors
}

func (d *TransformingDataplane) Stats() TransformingDataplaneStats {
	if d == nil {
		return TransformingDataplaneStats{}
	}
	return TransformingDataplaneStats{
		OutboundPackets: d.outboundPackets.Load(),
		InboundPackets:  d.inboundPackets.Load(),
		InboundDropped:  d.inboundDropped.Load(),
	}
}

// Close stops the receive pump. It intentionally does not close source,
// because the SWu session is owned by the reader tunnel lifecycle.
func (d *TransformingDataplane) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() { close(d.closed) })
	<-d.done
	return nil
}

func (d *TransformingDataplane) receiveLoop() {
	defer close(d.done)
	defer close(d.inbound)
	for {
		select {
		case <-d.closed:
			return
		case packet, ok := <-d.sourceRX:
			if !ok {
				return
			}
			if len(packet) == 0 {
				continue
			}

			in := append([]byte(nil), packet...)
			if transport := d.transport.Load(); transport != nil {
				var err error
				in, err = transport.TransformInbound(packet)
				if err != nil {
					d.inboundDropped.Add(1)
					d.reportError(err)
					continue
				}
			}

			if in == nil {
				continue
			} // reassembly is pending; never leak fragments
			select {
			case <-d.closed:
				return
			case d.inbound <- in:
				d.inboundPackets.Add(1)
			}
		}
	}
}

func (d *TransformingDataplane) reportError(err error) {
	if d == nil || err == nil {
		return
	}
	select {
	case <-d.closed:
	case d.errors <- err:
	default:
	}
}
