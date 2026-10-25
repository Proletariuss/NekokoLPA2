//go:build darwin && arm64 && amrcodec && !ios

package imscore

/*
#cgo CFLAGS: -I${SRCDIR}/../../../third_party/opencore-amr/prebuilt/macos-arm64/include
#cgo LDFLAGS: ${SRCDIR}/../../../third_party/opencore-amr/prebuilt/macos-arm64/lib/libopencore-amrnb.a -lc++
#include <stdlib.h>
#include <opencore-amrnb/interf_enc.h>
#include <opencore-amrnb/interf_dec.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"
)

// amrNBCodec owns independent AMR-NB encoder and decoder states. Calls are
// serialized so shutdown cannot release native state while an RTP worker is
// using it.
type amrNBCodec struct {
	mu      sync.Mutex
	encoder unsafe.Pointer
	decoder unsafe.Pointer
}

func AMRNBAvailable() bool { return true }

func newAMRNBCodec() (*amrNBCodec, error) {
	codec := &amrNBCodec{
		encoder: C.Encoder_Interface_init(0),
		decoder: C.Decoder_Interface_init(),
	}
	if codec.encoder == nil || codec.decoder == nil {
		codec.close()
		return nil, fmt.Errorf("imscore: initialize AMR-NB codec")
	}
	return codec, nil
}

// encode converts one 20 ms, 8 kHz, mono PCM frame into one RFC 4867
// octet-aligned AMR-NB RTP payload. Mode 7 is AMR 12.2 kbit/s, the mode
// selected by the CTExcel/EE media gateway.
func (c *amrNBCodec) encode(pcm []byte) ([]byte, error) {
	if len(pcm) != 320 {
		return nil, fmt.Errorf("imscore: AMR-NB requires 160 PCM samples, got %d bytes", len(pcm))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.encoder == nil {
		return nil, fmt.Errorf("imscore: AMR-NB encoder is closed")
	}
	var samples [160]C.short
	for index := range samples {
		samples[index] = C.short(int16(binary.LittleEndian.Uint16(pcm[index*2:])))
	}
	var storage [64]C.uchar
	length := int(C.Encoder_Interface_Encode(c.encoder, C.MR122, &samples[0], &storage[0], 1))
	if length <= 1 || length > len(storage) {
		return nil, fmt.Errorf("imscore: AMR-NB encoder returned %d bytes", length)
	}
	// CMR=15 means no mode request. The storage-format frame header returned
	// by opencore-amr is also the single-frame octet-aligned RTP ToC byte.
	payload := make([]byte, length+1)
	payload[0] = 0xf0
	copy(payload[1:], C.GoBytes(unsafe.Pointer(&storage[0]), C.int(length)))
	return payload, nil
}

func (c *amrNBCodec) decode(payload []byte) ([]byte, error) {
	if len(payload) < 3 {
		return nil, fmt.Errorf("imscore: truncated AMR-NB RTP payload")
	}
	// Octet-aligned payload: one-byte CMR, followed by one or more ToC
	// entries. The current implementation intentionally accepts one mode-7
	// speech frame, matching the negotiated ptime=20/mode-set=7 profile.
	toc := payload[1]
	if toc&0x80 != 0 {
		return nil, fmt.Errorf("imscore: multi-frame AMR-NB RTP is not supported")
	}
	frameType := (toc >> 3) & 0x0f
	if frameType != 7 {
		return nil, fmt.Errorf("imscore: unsupported AMR-NB frame type %d", frameType)
	}
	if toc&0x04 == 0 {
		return nil, fmt.Errorf("imscore: damaged AMR-NB frame")
	}
	if len(payload) < 33 { // CMR + ToC + 31 speech bytes for MR122.
		return nil, fmt.Errorf("imscore: truncated AMR-NB mode-7 frame")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decoder == nil {
		return nil, fmt.Errorf("imscore: AMR-NB decoder is closed")
	}
	frame := C.CBytes(payload[1:33])
	defer C.free(frame)
	var samples [160]C.short
	C.Decoder_Interface_Decode(c.decoder, (*C.uchar)(frame), &samples[0], 0)
	pcm := make([]byte, 320)
	for index, sample := range samples {
		binary.LittleEndian.PutUint16(pcm[index*2:], uint16(int16(sample)))
	}
	return pcm, nil
}

func (c *amrNBCodec) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.encoder != nil {
		C.Encoder_Interface_exit(c.encoder)
		c.encoder = nil
	}
	if c.decoder != nil {
		C.Decoder_Interface_exit(c.decoder)
		c.decoder = nil
	}
}
