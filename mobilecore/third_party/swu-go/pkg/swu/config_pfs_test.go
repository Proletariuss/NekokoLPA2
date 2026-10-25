package swu

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestConfiguredPFSReachesSessionTransportForEveryImplementedGroup(t *testing.T) {
	for _, group := range []int{0, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21} {
		t.Run(fmt.Sprint(group), func(t *testing.T) {
			reached := errors.New("test transport reached")
			cfg := &Config{RekeyPFS: group, SIM: &effectiveConfigSIM{}, TransportFactory: func(string, string) (Transport, error) {
				return nil, reached
			}}
			if err := cfg.validate(); err != nil {
				t.Fatal(err)
			}
			if err := NewSession(cfg, zap.NewNop()).Connect(context.Background()); !errors.Is(err, reached) {
				t.Fatalf("implemented PFS blocked before transport: %v", err)
			}
		})
	}
}

func TestConfiguredPFSRejectsUnknownGroupsBeforeSessionTransport(t *testing.T) {
	for _, group := range []int{-1, 1, 3, 4, 6, 13, 22, 65535, 65536, 65550} {
		t.Run(fmt.Sprint(group), func(t *testing.T) {
			cfg := &Config{RekeyPFS: group, SIM: &effectiveConfigSIM{}, TransportFactory: func(string, string) (Transport, error) {
				t.Fatal("unsupported PFS opened transport")
				return nil, nil
			}}
			if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "unsupported rekey_pfs") {
				t.Fatalf("invalid PFS accepted: %v", err)
			}
			if err := NewSession(cfg, zap.NewNop()).Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "unsupported rekey_pfs") {
				t.Fatalf("session failed to reject invalid PFS: %v", err)
			}
		})
	}
}
