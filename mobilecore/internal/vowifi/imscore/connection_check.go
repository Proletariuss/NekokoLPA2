package imscore

import (
	"context"
	"fmt"
)

// CheckConnection validates the current authenticated path without replacing
// the runtime or any call dialog. A stale binding or disabled OPTIONS policy
// requires the normal REGISTER renewal; the engine serializes these with its
// scheduled renewals. A positive result is a renewed registration lifetime.
func (s *Service) CheckConnection(ctx context.Context, refresh bool) (int, error) {
	if refresh || s.cfg.OptionsPingIntervalSeconds <= 0 {
		return s.RefreshRegistration(ctx)
	}
	op, release, ok := s.acquireOperation(false)
	if !ok {
		return 0, fmt.Errorf("IMS transport unavailable for connection check")
	}
	defer release()
	if op.runtime == nil {
		return 0, fmt.Errorf("IMS connection check has no transport")
	}
	operationCtx, cancel := op.context(ctx)
	defer cancel()
	return 0, op.runtime.checkConnection(operationCtx)
}
