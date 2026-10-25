//go:build !linux

package sim

import (
	"fmt"
	"os"
)

func OpenSerial(string, int) (*os.File, error) {
	return nil, fmt.Errorf("direct serial SIM access is unavailable on this platform")
}
