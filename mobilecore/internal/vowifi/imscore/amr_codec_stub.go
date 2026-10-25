//go:build (!ios && (!darwin || !arm64 || !amrcodec)) || (ios && !arm64)

package imscore

import "fmt"

type amrNBCodec struct{}

func AMRNBAvailable() bool { return false }

func newAMRNBCodec() (*amrNBCodec, error) {
	return nil, fmt.Errorf("imscore: AMR-NB is available only in the macOS ARM64 build")
}

func (c *amrNBCodec) encode([]byte) ([]byte, error) {
	return nil, fmt.Errorf("imscore: AMR-NB encoder is unavailable")
}

func (c *amrNBCodec) decode([]byte) ([]byte, error) {
	return nil, fmt.Errorf("imscore: AMR-NB decoder is unavailable")
}

func (c *amrNBCodec) close() {}
