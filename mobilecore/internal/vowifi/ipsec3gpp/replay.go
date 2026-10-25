package ipsec3gpp

import (
	"sync"
)

const defaultReplayWindowSize uint32 = 64

// ReplayWindow implements a fixed-size anti-replay check for ESP sequence numbers.
type ReplayWindow struct {
	mu          sync.Mutex
	size        uint32
	initialized bool
	highest     uint32
	bitmap      uint64
	stats       ReplayStats
}

// NewReplayWindow creates a replay window. Zero size defaults to 64 packets.
func NewReplayWindow(size uint32) *ReplayWindow {
	if size == 0 {
		size = defaultReplayWindowSize
	}
	if size > 64 {
		size = 64
	}
	return &ReplayWindow{size: size}
}

// Accept returns true when seq is new and inside the replay window.
// 注意：Accept 同时检查并标记序列号，仅应在包已验证后调用。
// 若需先检查后验证（ICV），请用 Check + Update 组合。
func (w *ReplayWindow) Accept(seq uint32) bool {
	if w == nil {
		return false // fail-closed：无窗口时拒绝
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	// seq=0 始终非法（RFC 4303 §3.3），必须先于初始化检查
	if seq == 0 {
		w.stats.TooOld++
		return false
	}

	if !w.initialized {
		w.initialized = true
		w.highest = seq
		w.bitmap = 1
		w.stats.Accepted++
		return true
	}

	if seq > w.highest {
		shift := seq - w.highest
		if shift >= w.size {
			w.bitmap = 1
		} else {
			w.bitmap <<= shift
			w.bitmap |= 1
		}
		w.highest = seq
		w.stats.Accepted++
		return true
	}

	delta := w.highest - seq
	if delta >= w.size {
		w.stats.TooOld++
		return false
	}
	mask := uint64(1) << delta
	if w.bitmap&mask != 0 {
		w.stats.Duplicate++
		return false
	}
	w.bitmap |= mask
	w.stats.Accepted++
	return true
}

// Check 仅检查序列号是否合法（不标记）。ICV 验证通过后再调用 Update。
func (w *ReplayWindow) Check(seq uint32) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq == 0 {
		w.stats.TooOld++
		return false
	}
	if !w.initialized {
		return true // 首个包总是可通过检查，由 Update 完成初始化
	}
	if seq > w.highest {
		return true
	}
	delta := w.highest - seq
	if delta >= w.size {
		w.stats.TooOld++
		return false
	}
	mask := uint64(1) << delta
	if w.bitmap&mask != 0 {
		w.stats.Duplicate++
		return false
	}
	return true
}

// Update 在 ICV 验证通过后标记序列号并推进窗口。
func (w *ReplayWindow) Update(seq uint32) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq == 0 {
		return
	}
	if !w.initialized {
		w.initialized = true
		w.highest = seq
		w.bitmap = 1
		w.stats.Accepted++
		return
	}
	if seq > w.highest {
		shift := seq - w.highest
		if shift >= w.size {
			w.bitmap = 1
		} else {
			w.bitmap <<= shift
			w.bitmap |= 1
		}
		w.highest = seq
		w.stats.Accepted++
		return
	}
	delta := w.highest - seq
	if delta < w.size {
		w.bitmap |= uint64(1) << delta
		w.stats.Accepted++
	}
}

// Snapshot returns a copy of replay statistics.
func (w *ReplayWindow) Snapshot() ReplayStats {
	if w == nil {
		return ReplayStats{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}
