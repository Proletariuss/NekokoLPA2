package ipsec3gpp

import (
	"errors"
	"fmt"
	"net"
)

// Flow describes one direction of a 3GPP ipsec-3gpp security association.
type Flow struct {
	OutboundSPI uint32
	InboundSPI  uint32
	LocalPort   int
	RemotePort  int
	AuthAlg     string
	EncAlg      string
	CK          []byte
	IK          []byte
}

// Policy captures the negotiated ipsec-3gpp parameters for SIP-over-TCP ESP.
type Policy struct {
	LocalIP     []byte
	RemoteIP    []byte
	LocalPortC  int
	LocalPortS  int
	RemotePortC int
	RemotePortS int
	FlowC       Flow
	FlowS       Flow
}

// ReplayStats tracks anti-replay decisions.
type ReplayStats struct {
	Accepted  uint64
	Duplicate uint64
	TooOld    uint64
}

// TransportStats aggregates userspace ESP transform counters.
type TransportStats struct {
	OutboundPackets     uint64
	InboundPackets      uint64
	PassthroughPackets  uint64
	TransformErrors     uint64
	Replay              ReplayStats
	LastSourcePort      int
	LastDestinationPort int
	LastSourceIP        string
	LastDestinationIP   string
}

// PolicyInput is the minimum set of inputs required to build a Policy.
type PolicyInput struct {
	LocalIP  net.IP
	RemoteIP net.IP
	Mech     SecurityMechanism
	// Local SPI/ports are the UE values advertised in Security-Client. Mech
	// contains the independently allocated P-CSCF values from Security-Server.
	LocalSPIC  uint32
	LocalSPIS  uint32
	LocalPortC int
	LocalPortS int
	CK         []byte
	IK         []byte
	AuthAlg    string
	EncAlg     string
}

// NewPolicy builds a Policy from negotiated Security-Server parameters and AKA keys.
func NewPolicy(in PolicyInput) (Policy, error) {
	localIP, err := normalizeIP(in.LocalIP)
	if err != nil {
		return Policy{}, fmt.Errorf("ipsec3gpp: local IP %w", err)
	}
	remoteIP, err := normalizeIP(in.RemoteIP)
	if err != nil {
		return Policy{}, fmt.Errorf("ipsec3gpp: remote IP %w", err)
	}
	if len(in.CK) == 0 || len(in.IK) == 0 {
		return Policy{}, errors.New("ipsec3gpp: CK and IK are required")
	}

	authAlg := canonicalAuthAlg(coalesce(in.AuthAlg, in.Mech.Alg))
	encAlg := canonicalEncAlg(coalesce(in.EncAlg, in.Mech.EAlg))
	if authAlg == "" || encAlg == "" {
		return Policy{}, errors.New("ipsec3gpp: authentication and encryption algorithms are required")
	}
	if in.Mech.SPIc == 0 || in.Mech.SPIs == 0 || in.LocalSPIC == 0 || in.LocalSPIS == 0 {
		return Policy{}, errors.New("ipsec3gpp: UE and P-CSCF spi-c/spi-s are required")
	}

	ports := fillPorts(in)
	ck := append([]byte(nil), in.CK...)
	ik := append([]byte(nil), in.IK...)

	flowC := Flow{
		OutboundSPI: in.Mech.SPIs,
		InboundSPI:  in.LocalSPIC,
		LocalPort:   ports.localC,
		RemotePort:  ports.remoteS,
		AuthAlg:     authAlg,
		EncAlg:      encAlg,
		CK:          ck,
		IK:          ik,
	}
	flowS := Flow{
		OutboundSPI: in.Mech.SPIc,
		InboundSPI:  in.LocalSPIS,
		LocalPort:   ports.localS,
		RemotePort:  ports.remoteC,
		AuthAlg:     authAlg,
		EncAlg:      encAlg,
		CK:          ck,
		IK:          ik,
	}

	return Policy{
		LocalIP:     localIP,
		RemoteIP:    remoteIP,
		LocalPortC:  ports.localC,
		LocalPortS:  ports.localS,
		RemotePortC: ports.remoteC,
		RemotePortS: ports.remoteS,
		FlowC:       flowC,
		FlowS:       flowS,
	}, nil
}

type portPair struct {
	localC, localS, remoteC, remoteS int
}

func fillPorts(in PolicyInput) portPair {
	localC, localS := in.LocalPortC, in.LocalPortS
	remoteC, remoteS := in.Mech.PortC, in.Mech.PortS
	if localC == 0 {
		localC = 5060
	}
	if localS == 0 {
		localS = localC
	}
	if remoteC == 0 {
		remoteC = 5060
	}
	if remoteS == 0 {
		remoteS = remoteC
	}
	return portPair{
		localC:  localC,
		localS:  localS,
		remoteC: remoteC,
		remoteS: remoteS,
	}
}

func normalizeIP(ip net.IP) ([]byte, error) {
	if ip == nil {
		return nil, errors.New("must not be nil")
	}
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...), nil
	}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		return append([]byte(nil), v6...), nil
	}
	return nil, fmt.Errorf("invalid address %q", ip.String())
}

func normalizeIPPair(a, b []byte) (local, remote []byte, err error) {
	if len(a) == 0 || len(b) == 0 {
		return nil, nil, errors.New("ipsec3gpp: local/remote IP must not be nil")
	}
	if (len(a) == 4) != (len(b) == 4) {
		return nil, nil, errors.New("ipsec3gpp: local/remote IP family mismatch")
	}
	return append([]byte(nil), a...), append([]byte(nil), b...), nil
}

func coalesce(values ...string) string {
	for _, v := range values {
		if s := trimToken(v); s != "" {
			return s
		}
	}
	return ""
}

func ipEqual(a, b []byte) bool {
	return net.IP(a).Equal(net.IP(b))
}
