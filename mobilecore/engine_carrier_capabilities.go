package mobilecore

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/1239t/swu-go/pkg/sim"
	"github.com/1239t/swu-go/pkg/swu"
)

// A single testable boundary ensures parsed carrier capabilities actually
// reach the protocol implementation; neither proxy nor identity policy is
// recomputed by the tunnel.
func readerSWUConfig(config engineConfig, effective *readerVoWiFiEffectiveConfig, provider sim.SIMProvider) *swu.Config {
	enabled := effective.DeviceIdentityEnabled
	ikeLocalID := effective.IKELocalIdentifier
	if strings.TrimSpace(ikeLocalID) == "" {
		ikeLocalID = effective.Profile.ExpandLocalIdentifier(config.IMSI)
	}
	remoteID := strings.TrimSpace(effective.RemoteCertificateHostname)
	if remoteID == "" {
		remoteID = effective.EPDG
	}
	cfg := &swu.Config{
		EpDGAddr: effective.EPDG, EpDGPort: uint16(effective.EPDGPort), APN: effective.APN,
		IPStack: effective.IPStack, LocalPort: uint16(effective.IKELocalPort), SIM: provider,
		EnableDriver: true, DataplaneMode: "netstack", MCC: config.MCC, MNC: config.MNC,
		DisableSwitchToNATTPort: effective.Profile.DisableSwitchToNATTPort,
		IKELocalIdentifier:      ikeLocalID, EAPIdentity: effective.EAPIdentity,
		ValidateRemoteCertificate: effective.ValidateRemoteCertificate, RemoteIdentifier: remoteID,
		RequireFullEAP:    effective.IMSRegisterTemplate.InitialAuthorization == "eap_direct",
		CookiePayloadType: effective.CookiePayloadType, CPInFinalAuth: effective.CPInFinalAuth,
		RekeyPFS: effective.RekeyPFS, NATTKeepaliveSeconds: effective.NATTKeepaliveSeconds,
		DPDIntervalSeconds: effective.DPDIntervalSeconds, DisableDPD: effective.DisableDPD,
		ReauthInterval:     effective.ReauthIntervalSeconds,
		IKELifetimeSeconds: effective.IKELifetimeSeconds, ChildLifetimeSeconds: effective.ChildLifetimeSeconds,
		IKEProposals: append([]string(nil), effective.IKEProposals...),
		ESPProposals: append([]string(nil), effective.ESPProposals...), AKAChallengeMode: effective.AKAChallengeMode,
		DeviceIdentityEnabled: &enabled,
	}
	applyReaderCertificateProfile(config, effective, cfg)
	if config.Proxy != "" {
		cfg.TransportFactory = newReaderSWUProxyTransportFactory(config.Proxy)
	}
	return cfg
}

func readerIMSTransport(effective *readerVoWiFiEffectiveConfig) string {
	if strings.EqualFold(strings.TrimSpace(effective.IMSTransport), "udp") {
		return "udp"
	}
	// Auto deliberately retains the proven TCP behavior; a network failure
	// never silently downgrades transport/security or bypasses a proxy.
	return "tcp"
}

func effectiveForEPDGCandidate(source *readerVoWiFiEffectiveConfig, index int) *readerVoWiFiEffectiveConfig {
	copy := *source
	if source.EPDGSource == "carrier-template" && index > 0 && index < len(source.EPDGCandidates) {
		copy.EPDG = source.EPDGCandidates[index]
	}
	return &copy
}

func canAdvanceEPDGCandidate(stage string, err error) bool {
	return err != nil && !permanentSessionFailure(err) && (stage == "transport" || stage == "ike_sa_init")
}

var errEPDGRedirectPolicy = errors.New("ePDG redirect rejected by destination policy")

func effectiveForAuthenticatedRedirect(source *readerVoWiFiEffectiveConfig, redirect *swu.RedirectError, count int) (*readerVoWiFiEffectiveConfig, error) {
	if redirect == nil || !redirect.Authenticated || count >= 3 || source.EPDGSource == "custom" || source.EPDGSource == "carrier-override" {
		return nil, errEPDGRedirectPolicy
	}
	address := strings.TrimSpace(redirect.NewAddr)
	if !validRedirectAddress(address) || strings.EqualFold(strings.TrimSuffix(address, "."), strings.TrimSuffix(source.EPDG, ".")) {
		return nil, fmt.Errorf("%w: invalid or repeated target", errEPDGRedirectPolicy)
	}
	copy := *source
	copy.EPDG, copy.EPDGCandidates = address, []string{address}
	// The routing hint is not a new trust anchor or new authorized identity.
	if copy.RemoteCertificateHostname == "" {
		copy.RemoteCertificateHostname = source.EPDG
	}
	return &copy, nil
}

func validRedirectAddress(address string) bool {
	if net.ParseIP(address) != nil {
		return true
	}
	name := strings.TrimSuffix(address, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
