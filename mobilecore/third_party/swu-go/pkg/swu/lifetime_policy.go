package swu

import (
	"math/rand"
	"time"
)

// Preserve the proven refresh cadence unless an explicit carrier lifetime
// requires earlier renewal. A missing template lifetime must not silently
// replace it with the parser's legacy 80000-second fallback.
func (s *Session) rekeyIntervals() (time.Duration, time.Duration) {
	ike, child := time.Duration(ikeRekeyInterval)*time.Second, time.Duration(childRekeyInterval)*time.Second
	if s.cfg != nil {
		ike = earlierLifetime(ike, s.cfg.IKELifetimeSeconds)
		child = earlierLifetime(child, s.cfg.ChildLifetimeSeconds)
	}
	return ike, child
}

// RFC 4478 AUTH_LIFETIME requires reauthentication, not merely new SA keys.
// Keep the user's shorter reauthentication policy authoritative.
func (s *Session) reauthenticationInterval() time.Duration {
	var interval time.Duration
	if s.cfg != nil && s.cfg.ReauthInterval > 0 {
		interval = safeLifetimeSeconds(s.cfg.ReauthInterval)
	}
	if s.authLifetime > 0 {
		deadline := safeLifetimeSeconds(int(s.authLifetime)) * 4 / 5
		if interval == 0 || deadline < interval {
			interval = deadline
		}
	}
	return interval
}

func earlierLifetime(current time.Duration, seconds int) time.Duration {
	if seconds <= 0 {
		return current
	}
	limit := safeLifetimeSeconds(seconds) * 4 / 5
	if limit < current {
		return limit
	}
	return current
}

func safeLifetimeSeconds(seconds int) time.Duration {
	// The cap also protects multiplication by the safety-margin numerator.
	const maximum = 365 * 24 * 60 * 60
	if seconds > maximum {
		seconds = maximum
	}
	return time.Duration(seconds) * time.Second
}

func boundedRekeyJitter(interval, maximum time.Duration) time.Duration {
	if limit := interval / 4; maximum > limit {
		maximum = limit
	}
	if maximum <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(maximum)))
}
