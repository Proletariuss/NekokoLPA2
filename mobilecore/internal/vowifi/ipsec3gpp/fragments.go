package ipsec3gpp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var nextESPFragmentID atomic.Uint32

// The userspace link has MTU 1280. Reassembly before ESP can produce a larger
// packet, so fragment the encrypted result (never its plaintext) before SWu.
func fragmentProtectedPacket(packet []byte) ([][]byte, error) {
	const mtu = 1280
	if len(packet) <= mtu {
		return [][]byte{packet}, nil
	}
	parsed, err := parseIPPacket(packet)
	if err != nil {
		return nil, err
	}
	if parsed.nextHeader != ipProtoESP {
		return [][]byte{packet}, nil
	}
	id := nextESPFragmentID.Add(1)
	headerLen := len(parsed.header)
	fragmentHeader := 0
	if packet[0]>>4 == 6 {
		fragmentHeader = 8
	}
	chunk := (mtu - headerLen - fragmentHeader) / 8 * 8
	var packets [][]byte
	for offset := 0; offset < len(parsed.transportPayload); offset += chunk {
		end := min(offset+chunk, len(parsed.transportPayload))
		more := end < len(parsed.transportPayload)
		header := append([]byte(nil), parsed.header...)
		if packet[0]>>4 == 4 {
			flags := uint16(offset / 8)
			if more {
				flags |= 0x2000
			}
			binary.BigEndian.PutUint16(header[4:6], uint16(id))
			binary.BigEndian.PutUint16(header[6:8], flags)
			binary.BigEndian.PutUint16(header[2:4], uint16(headerLen+end-offset))
			updateIPv4HeaderChecksum(header)
		} else {
			header[6] = 44
			binary.BigEndian.PutUint16(header[4:6], uint16(fragmentHeader+end-offset))
			fragment := make([]byte, 8)
			fragment[0] = ipProtoESP
			flags := uint16(offset)
			if more {
				flags |= 1
			}
			binary.BigEndian.PutUint16(fragment[2:4], flags)
			binary.BigEndian.PutUint32(fragment[4:8], id)
			header = append(header, fragment...)
		}
		packets = append(packets, append(header, parsed.transportPayload[offset:end]...))
	}
	return packets, nil
}

// Reassemble before selecting ports and applying ESP. Encrypting a first
// fragment and passing later fragments through would leak SIP plaintext.
// Bound both memory and lifetime, reject overlaps, and keep no timer workers.
type fragmentReassembler struct {
	mu   sync.Mutex
	sets map[string]*fragmentSet
}
type fragmentSet struct {
	header   []byte
	payload  []byte
	covered  []bool
	total    int
	count    int
	created  time.Time
	maxEnd   int
	metadata []byte
}

func (r *fragmentReassembler) process(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, fmt.Errorf("empty IP packet")
	}
	var header, payload []byte
	var key string
	var offset int
	var more bool
	var metadata []byte
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return nil, fmt.Errorf("truncated IPv4 fragment")
		}
		flags := binary.BigEndian.Uint16(packet[6:8])
		if flags&0x3fff == 0 {
			return packet, nil
		}
		hlen := int(packet[0]&15) * 4
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if hlen < 20 || total < hlen || total > len(packet) {
			return nil, fmt.Errorf("invalid IPv4 fragment length")
		}
		offset, more = int(flags&0x1fff)*8, flags&0x2000 != 0
		header = append([]byte(nil), packet[:hlen]...)
		binary.BigEndian.PutUint16(header[6:8], 0)
		payload = packet[hlen:total]
		key = fmt.Sprintf("4/%x/%x/%d/%d", packet[12:16], packet[16:20], packet[9], binary.BigEndian.Uint16(packet[4:6]))
	case 6:
		if len(packet) < 40 {
			return nil, fmt.Errorf("truncated IPv6 fragment")
		}
		total := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if total > len(packet) {
			return nil, fmt.Errorf("invalid IPv6 fragment length")
		}
		next, position, previous := packet[6], 40, 6
		for next != 44 {
			if !isIPv6ExtensionHeader(next) {
				return packet, nil
			}
			if position+2 > total {
				return nil, fmt.Errorf("truncated IPv6 extension")
			}
			length := (int(packet[position+1]) + 1) * 8
			if position+length > total {
				return nil, fmt.Errorf("invalid IPv6 extension length")
			}
			next, previous, position = packet[position], position, position+length
		}
		if position+8 > total {
			return nil, fmt.Errorf("truncated IPv6 fragment header")
		}
		flags := binary.BigEndian.Uint16(packet[position+2 : position+4])
		offset, more = int(flags&0xfff8), flags&1 != 0
		header = append([]byte(nil), packet[:position]...)
		header[previous] = packet[position]
		payload = packet[position+8 : total]
		// IPv6 reassembly identifies packets by source, destination and ID.
		// Different Next Header values are conflicting metadata, not separate
		// datagrams that may quietly coexist under the same fragment ID.
		key = fmt.Sprintf("6/%x/%x/%d", packet[8:24], packet[24:40], binary.BigEndian.Uint32(packet[position+4:position+8]))
		metadata = append([]byte(nil), header...)
		metadata[4], metadata[5], metadata[7] = 0, 0, 0 // length and hop limit vary
		metadata[1] &^= 0x30                            // ECN may be marked independently in transit
	default:
		return nil, fmt.Errorf("invalid IP fragment version")
	}
	end := offset + len(payload)
	if len(payload) == 0 || end > 65535-len(header) || (more && len(payload)%8 != 0) {
		return nil, fmt.Errorf("invalid IP fragment bounds")
	}
	// RFC 6946: an IPv6 atomic fragment is a complete packet; it must never
	// merge with, complete, or delete an existing fragmented packet's state.
	if packet[0]>>4 == 6 && offset == 0 && !more {
		out := append(header, payload...)
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
		if err := validateReassembledIPv6(out); err != nil {
			return nil, err
		}
		return out, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sets == nil {
		r.sets = make(map[string]*fragmentSet)
	}
	now := time.Now()
	for id, set := range r.sets {
		if now.Sub(set.created) > 30*time.Second {
			delete(r.sets, id)
		}
	}
	set := r.sets[key]
	if set == nil {
		if len(r.sets) >= 64 {
			return nil, fmt.Errorf("IP fragment reassembly limit")
		}
		set = &fragmentSet{payload: make([]byte, 65535), covered: make([]bool, 65535), total: -1, created: now, metadata: metadata}
		r.sets[key] = set
	}
	if !bytes.Equal(set.metadata, metadata) {
		delete(r.sets, key)
		return nil, fmt.Errorf("conflicting IP fragment metadata")
	}
	if !more && end < set.maxEnd {
		delete(r.sets, key)
		return nil, fmt.Errorf("final IP fragment truncates already received bytes")
	}
	if set.total >= 0 && (end > set.total || (!more && end != set.total)) {
		delete(r.sets, key)
		return nil, fmt.Errorf("conflicting final IP fragment")
	}
	for i := offset; i < end; i++ {
		if set.covered[i] {
			delete(r.sets, key)
			return nil, fmt.Errorf("overlapping IP fragments")
		}
	}
	if offset == 0 {
		set.header = header
	}
	copy(set.payload[offset:end], payload)
	for i := offset; i < end; i++ {
		set.covered[i] = true
	}
	set.count += len(payload)
	set.maxEnd = max(set.maxEnd, end)
	if !more {
		set.total = end
	}
	if set.total < 0 || set.count != set.total || set.header == nil {
		return nil, nil
	}
	if len(set.header)+set.total > 65535 {
		delete(r.sets, key)
		return nil, fmt.Errorf("reassembled IP packet exceeds supported length")
	}
	for _, covered := range set.covered[:set.total] {
		if !covered {
			return nil, nil
		}
	}
	delete(r.sets, key)
	out := append(set.header, set.payload[:set.total]...)
	if out[0]>>4 == 4 {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		updateIPv4HeaderChecksum(out[:len(set.header)])
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
		if err := validateReassembledIPv6(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func validateReassembledIPv6(packet []byte) error {
	next, remaining := packet[6], packet[40:]
	for isIPv6ExtensionHeader(next) {
		if next == 44 {
			return fmt.Errorf("nested IPv6 fragment header")
		}
		if len(remaining) < 2 {
			return fmt.Errorf("truncated reassembled IPv6 extension")
		}
		size := (int(remaining[1]) + 1) * 8
		if size > len(remaining) {
			return fmt.Errorf("invalid reassembled IPv6 extension length")
		}
		next, remaining = remaining[0], remaining[size:]
	}
	return nil
}
