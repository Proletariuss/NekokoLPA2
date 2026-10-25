package mobilecore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"proletarius.local/core/internal/vowifi/imscore"
)

func classifyCycleFailure(owner context.Context, err error) error {
	if owner.Err() == nil && errors.Is(err, context.Canceled) {
		// Deliberately remove the child cancellation identity. The permanent
		// cancellation rule still applies to cancellation of the owner itself.
		return fmt.Errorf("VoWiFi transport session ended internally: %v", err)
	}
	return err
}

func connectionCheckNeedsRefresh(now, registeredUntil time.Time, optionsInterval int) bool {
	// Reserve enough binding lifetime for the entire bounded verification.
	return optionsInterval <= 0 || !now.Add(60*time.Second).Before(registeredUntil)
}

func registrationFreshUntil(now time.Time, expires int) time.Time {
	// Unknown/invalid grants are immediately stale. Cap huge untrusted grants
	// conservatively before converting seconds to a nanosecond duration.
	return now.Add(time.Duration(min(max(expires, 0), 24*60*60)) * time.Second)
}

func (e *Engine) finishConnectionCheck(run *runningSession, service *imscore.Service, revision uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.run != run || run.service != service || run.ctx.Err() != nil {
		return false
	}
	if run.checkRevision == revision {
		run.checking = false
		select {
		case <-run.checks:
		default:
		}
	}
	return run.checking
}

func (e *Engine) deferConnectionRecovery(run *runningSession, service *imscore.Service) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.run == run && run.service == service {
		run.checking, run.recoveryPending = false, true
		select {
		case <-run.checks:
		default:
		}
	}
}

func (e *Engine) requestConnectionCheck(generation *int64, reason string) (string, error) {
	if generation == nil {
		return "", errors.New("connection check requires reader generation")
	}
	if reason != "" && reason != "foreground" && reason != "network_changed" {
		return "", errors.New("invalid connection check reason")
	}
	e.mu.Lock()
	run := e.run
	if *generation != e.generation || (run != nil && *generation != run.config.Generation) {
		e.mu.Unlock()
		return "", errors.New("reader generation changed")
	}
	if run == nil || run.ctx.Err() != nil {
		e.mu.Unlock()
		return "", errors.New("VoWiFi is stopped; reconnect manually")
	}
	// Startup and controlled recovery already verify a fresh IMS binding.
	// Do not retain an event that could later target a different IMS cycle.
	if run.service != nil && run.checks != nil && !run.recoveryPending {
		run.checkRevision++
		if !run.checking {
			run.checking = true
			select {
			case run.checks <- struct{}{}:
			default:
			}
		}
	}
	e.mu.Unlock()
	return e.Status(), nil
}
