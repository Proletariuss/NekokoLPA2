package swu

import (
	"fmt"
	"strings"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

const (
	defaultIPStack            = "ipv4v6"
	defaultNATTKeepalive      = 20 * time.Second
	defaultDPDInterval        = 120 * time.Second
	defaultAKAChallengeMode   = "minimal"
	akaChallengeModeOmit      = "omit"
	akaChallengeModeCheckcode = "checkcode"
	akaChallengeModeRecompute = "recompute"
)

func (c *Config) validate() error {
	if c == nil {
		return fmt.Errorf("swu: config is nil")
	}
	if err := c.validateCertificatePolicy(); err != nil {
		return err
	}
	if _, err := c.normalizedIPStack(); err != nil {
		return err
	}
	if _, err := c.normalizedAKAChallengeMode(); err != nil {
		return err
	}
	if c.NATTKeepaliveSeconds < 0 {
		return fmt.Errorf("swu: natt_keepalive_seconds must be >= 0")
	}
	if c.DPDIntervalSeconds < 0 {
		return fmt.Errorf("swu: dpd_interval_seconds must be >= 0")
	}
	if c.ReauthInterval < 0 {
		return fmt.Errorf("swu: reauth_interval_seconds must be >= 0")
	}
	if c.CookiePayloadType != "" && c.CookiePayloadType != "sa" {
		return fmt.Errorf("swu: unsupported cookie_payload_type")
	}
	if c.RekeyPFS < 0 || c.RekeyPFS > 65535 {
		return fmt.Errorf("swu: unsupported rekey_pfs %d", c.RekeyPFS)
	}
	if c.RekeyPFS != 0 {
		// Validate the implementation's capability without generating keys.
		// Legacy groups are allowed only when explicitly configured.
		if _, err := crypto.NewDiffieHellman(uint16(c.RekeyPFS)); err != nil {
			return fmt.Errorf("swu: unsupported rekey_pfs %d: %w", c.RekeyPFS, err)
		}
	}
	if len(c.EAPIdentity) > 253 || strings.ContainsAny(c.EAPIdentity, "\r\n\x00") {
		return fmt.Errorf("swu: invalid EAP identity")
	}
	if _, err := ikev2.BuildIKEProposals(c.IKEProposals, nil); err != nil {
		return fmt.Errorf("swu: %w", err)
	}
	if _, err := ikev2.BuildESPProposals(c.ESPProposals, []byte{0, 0, 0, 1}); err != nil {
		return fmt.Errorf("swu: %w", err)
	}
	return nil
}

func (c *Config) normalizedIPStack() (string, error) {
	value := strings.ToLower(strings.TrimSpace(c.IPStack))
	if value == "" {
		value = defaultIPStack
	}
	switch value {
	case "ipv4", "ipv6", "ipv4v6":
		return value, nil
	default:
		return "", fmt.Errorf("swu: unsupported ip_stack %q (want ipv4, ipv6, or ipv4v6)", c.IPStack)
	}
}

func (c *Config) requestedAddressFamilies() (ipv4, ipv6 bool, err error) {
	stack, err := c.normalizedIPStack()
	if err != nil {
		return false, false, err
	}
	return stack == "ipv4" || stack == "ipv4v6", stack == "ipv6" || stack == "ipv4v6", nil
}

func (c *Config) normalizedAKAChallengeMode() (string, error) {
	value := strings.ToLower(strings.TrimSpace(c.AKAChallengeMode))
	if value == "" {
		value = defaultAKAChallengeMode
	}
	switch value {
	case defaultAKAChallengeMode, akaChallengeModeOmit:
		return value, nil
	case akaChallengeModeCheckcode, akaChallengeModeRecompute:
		return "", fmt.Errorf("swu: unsupported aka_challenge_mode %q: classic EAP-AKA AT_CHECKCODE is not implemented correctly; use minimal or omit", c.AKAChallengeMode)
	default:
		return "", fmt.Errorf("swu: unsupported aka_challenge_mode %q (want minimal or omit)", c.AKAChallengeMode)
	}
}

func (c *Config) effectiveNATTKeepaliveInterval() time.Duration {
	if c.NATTKeepaliveSeconds > 0 {
		return time.Duration(c.NATTKeepaliveSeconds) * time.Second
	}
	return defaultNATTKeepalive
}

func (c *Config) effectiveDPDInterval() time.Duration {
	if c.DPDIntervalSeconds > 0 {
		return time.Duration(c.DPDIntervalSeconds) * time.Second
	}
	return defaultDPDInterval
}

func (c *Config) deviceIdentityIsEnabled() bool {
	return c.DeviceIdentityEnabled == nil || *c.DeviceIdentityEnabled
}

func (s *Session) effectiveNATTKeepaliveInterval() time.Duration {
	return s.cfg.effectiveNATTKeepaliveInterval()
}
