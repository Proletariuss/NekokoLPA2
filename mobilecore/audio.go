package mobilecore

import (
	"errors"
	"net"
	"proletarius.local/core/internal/vowifi/imscore"
	"time"
)

func (e *Engine) closeAudioLocked() {
	if e.audio != nil {
		_ = e.audio.Close()
	}
	e.audio = nil
	e.audioPort = 0
	e.audioToken = ""
}
func (e *Engine) syncAudio(call imscore.CallState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if call.AudioPort == 0 || call.AudioToken == "" {
		e.closeAudioLocked()
		return
	}
	if e.audioPort == call.AudioPort && e.audioToken == call.AudioToken && e.audio != nil {
		return
	}
	e.closeAudioLocked()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: call.AudioPort})
	if err != nil {
		return
	}
	e.audio, e.audioPort, e.audioToken = conn, call.AudioPort, call.AudioToken
	// Establish the return address even during receive-only early media.
	frame := append([]byte(call.AudioToken+"\x00"), make([]byte, 320)...)
	_, _ = conn.Write(frame)
}

// WritePCM accepts exactly one 20 ms little-endian signed16 mono 8 kHz frame.
func (e *Engine) WritePCM(pcm []byte) error {
	if len(pcm) != 320 {
		return errors.New("PCM frame must contain 160 signed16 samples")
	}
	e.mu.Lock()
	conn, token := e.audio, e.audioToken
	e.mu.Unlock()
	if conn == nil {
		return errors.New("call audio is not ready")
	}
	_, err := conn.Write(append([]byte(token+"\x00"), pcm...))
	return err
}

// ReadPCM returns one 320-byte PCM frame, or nil after 500 ms / teardown.
// The host calls this on a dedicated worker, never its audio callback.
func (e *Engine) ReadPCM() []byte {
	e.audioReadMu.Lock()
	defer e.audioReadMu.Unlock()
	e.mu.Lock()
	conn, token := e.audio, e.audioToken
	e.mu.Unlock()
	if conn == nil {
		time.Sleep(20 * time.Millisecond)
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil
	}
	prefix := token + "\x00"
	if n != len(prefix)+320 || string(buffer[:len(prefix)]) != prefix {
		return nil
	}
	return append([]byte(nil), buffer[len(prefix):n]...)
}
