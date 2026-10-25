package imscore

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
)

const maxInitialRegisterJitter = time.Second

// waitInitialRegisterJitter applies the author keepalive.go pre-register delay.
func waitInitialRegisterJitter(ctx context.Context, cfg Config) error {
	if maxInitialRegisterJitter <= 0 {
		return nil
	}
	// 使用 crypto/rand 代替 math/rand（IMSCORE-5 修复）
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxInitialRegisterJitter)))
	var delay time.Duration
	if err != nil {
		// fallback: 使用固定延迟
		delay = maxInitialRegisterJitter / 2
	} else {
		delay = time.Duration(n.Int64())
	}
	if delay <= 0 {
		return nil
	}
	logger.Info("初始注册随机延迟 (Jitter)",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.String("duration", delay.String()))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
