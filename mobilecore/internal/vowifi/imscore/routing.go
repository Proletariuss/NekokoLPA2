package imscore

import (
	"net"
	"strings"
)

func effectiveTransportAddr(cfg Config) string {
	if v := strings.TrimSpace(cfg.TransportPCSCFAddr); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.PCSCFAddr)
}

// effectiveRouteAddr matches author imscore: when the logical registrar is the
// UE inner IPv6 but TCP targets the IKE gateway, Route uses the gateway.
func effectiveRouteAddr(cfg Config) string {
	transport := effectiveTransportAddr(cfg)
	registrar := strings.TrimSpace(cfg.PCSCFAddr)
	if transport != "" && registrar != "" && transport != registrar {
		return transport
	}
	return registrar
}

func effectiveIPSecGatewayAddr(cfg Config) string {
	// A real P-CSCF challenge binds the security agreement to that exact node.
	// Do not pick another candidate after receiving Security-Server from it.
	// Gateway substitution is only for the legacy hairpin representation where
	// the logical registrar is the UE's own inner address.
	if registrar := strings.TrimSpace(cfg.PCSCFAddr); registrar != "" && !registrarHostEqualsLocalIP(registrar, cfg.LocalIP) {
		return effectiveTransportAddr(cfg)
	}
	if gateway := pickIKEGatewayCandidate(registrarCandidates(cfg), cfg.LocalIP); gateway != "" {
		return gateway
	}
	return effectiveTransportAddr(cfg)
}

func effectiveIPSecRemoteIP(cfg Config) net.IP {
	addr := effectiveIPSecGatewayAddr(cfg)
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}
