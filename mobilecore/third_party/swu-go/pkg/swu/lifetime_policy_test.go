package swu

import (
	"testing"
	"time"
)

func TestCarrierLifetimesPreserveExistingCadence(t *testing.T) {
	s := &Session{cfg: &Config{}}
	ike, child := s.rekeyIntervals()
	if ike != 1500*time.Second || child != 1800*time.Second {
		t.Fatalf("default cadence changed: %s / %s", ike, child)
	}
	s.cfg.IKELifetimeSeconds, s.cfg.ChildLifetimeSeconds = 80000, 1000
	ike, child = s.rekeyIntervals()
	if ike != 1500*time.Second || child != 800*time.Second {
		t.Fatalf("explicit lifetime ignored/extended: %s / %s", ike, child)
	}
	s.authLifetime = 300
	if s.reauthenticationInterval() != 240*time.Second {
		t.Fatal("AUTH_LIFETIME must trigger full authentication")
	}
	s.cfg.ReauthInterval = 120
	if s.reauthenticationInterval() != 120*time.Second {
		t.Fatal("user's shorter reauthentication lost")
	}
	s.authLifetime = 0
	s.cfg.ReauthInterval = 7200
	if s.reauthenticationInterval() != 7200*time.Second {
		t.Fatal("3HK reauthentication policy changed")
	}
}

func TestLifetimeBoundsAndJitter(t *testing.T) {
	for _, seconds := range []int{1, 10, 100, 80000, int(^uint(0) >> 1)} {
		d := earlierLifetime(1500*time.Second, seconds)
		if d <= 0 || d > 1500*time.Second {
			t.Fatalf("unsafe lifetime %d: %s", seconds, d)
		}
		for range 100 {
			j := boundedRekeyJitter(d, 30*time.Second)
			if j < 0 || j >= d || d-j <= 0 {
				t.Fatalf("unsafe jitter %s for %s", j, d)
			}
		}
	}
	if boundedRekeyJitter(0, time.Second) != 0 {
		t.Fatal("zero jitter bound must not panic")
	}
}
