package imscore

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"
	"proletarius.local/core/internal/vowifi/messaging"
	"proletarius.local/core/internal/vowifi/policy"
	"proletarius.local/core/internal/vowifi/sim"
	"proletarius.local/core/internal/vowifi/voiceclient"
)

// IMSConfig is the author v1.1.2 imscore service configuration surface.
type IMSConfig struct {
	Enabled                    bool
	DeviceID                   string
	PCSCF                      string
	Registrar                  string
	Domain                     string
	Realm                      string
	CallPhoneContext           string
	IMPI                       string
	IMPU                       string
	CarrierPresetID            string
	IMSRegisterTemplate        policy.IMSRegisterTemplate
	IMSRegisterPolicySource    string
	LocalAddr                  string
	LocalPort                  int
	Transport                  string
	UserAgent                  string
	PAccessNetworkInfo         string
	CellularNetworkInfo        string
	SIPInstance                string
	IcsiRef                    string
	TCPKeepaliveSeconds        int
	OptionsPingIntervalSeconds int
	EnableIPSec3GPP            *bool
}

// DialOptions carries TCP dial tuning for IMSNetwork.DialContext.
type DialOptions struct {
	Timeout   int64
	KeepAlive int64
	TCPMSS    int
}

// StartSessionInput carries runtimehost session context not present on IMSConfig.
type StartSessionInput struct {
	TraceID                  string
	LocalIP                  net.IP
	Dataplane                voiceclient.PacketDataplane
	RegistrarCandidates      []string
	AKA                      sim.AKAProvider
	EAPDirectAuth            *EAPDirectAuth
	DeliveryStore            messaging.DeliveryStore
	DecodeIncomingRPDU       func([]byte) (byte, string, []byte, error)
	DecodeIncomingSMS        func([]byte) (InboundSMS, bool, error)
	DTMFEvent                func(context.Context, string) (byte, error)
	ValidateRegisterResponse func(context.Context, []byte, string, uint32) error
	IncomingSMS              func(sender, content string, at time.Time) error
	IncomingSMSMessage       func(InboundSMS) error
	IncomingSIPRequest       func(*sip.Request)
	IncomingSIPHandler       func(*sip.Request, SIPResponder)
	IMSI                     string
	DisableAMR               bool
	MCC                      string
	MNC                      string
	CellID                   string
	RegisterExpirySeconds    int
}

// IMSConfigFromVoice builds the author-facing IMSConfig from runtimehost inputs.
func IMSConfigFromVoice(v voiceclient.Config, template policy.IMSRegisterTemplate, presetID string) IMSConfig {
	transport := strings.TrimSpace(v.Transport)
	if transport == "" {
		transport = "auto"
	}
	policySource := "default"
	if id := strings.TrimSpace(template.RegisterPolicy.ID); id != "" {
		policySource = id
	}
	cfg := IMSConfig{
		Enabled:                 true,
		DeviceID:                strings.TrimSpace(v.DeviceID),
		PCSCF:                   strings.TrimSpace(v.PCSCFAddr),
		Registrar:               strings.TrimSpace(v.PCSCFAddr),
		Domain:                  strings.TrimSpace(v.HomeDomain),
		Realm:                   strings.TrimSpace(v.Realm),
		IMPI:                    strings.TrimSpace(v.PrivateID),
		IMPU:                    strings.TrimSpace(v.PublicURI),
		CarrierPresetID:         strings.TrimSpace(presetID),
		IMSRegisterTemplate:     template,
		IMSRegisterPolicySource: policySource,
		LocalPort:               v.LocalPort,
		Transport:               transport,
		UserAgent:               strings.TrimSpace(v.RegisterProfile.UserAgent),
		SIPInstance:             strings.TrimSpace(v.SIPInstanceURN),
	}
	if v.LocalIP != nil {
		cfg.LocalAddr = v.LocalIP.String()
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "SimAdmin VoWiFi"
	}
	if strings.TrimSpace(cfg.CarrierPresetID) == "" {
		cfg.CarrierPresetID = "3gpp-default"
	}
	if strings.TrimSpace(cfg.IMSRegisterTemplate.ID) == "" {
		cfg.IMSRegisterTemplate = policy.DefaultIMSRegisterTemplate()
	}
	return cfg
}

func internalConfigFromIMS(ims IMSConfig, in StartSessionInput) Config {
	pcscf := strings.TrimSpace(ims.PCSCF)
	if pcscf == "" {
		pcscf = strings.TrimSpace(ims.Registrar)
	}
	template := ims.IMSRegisterTemplate
	transport := resolveIMSConfigTransport(ims.Transport, template.Transport)
	template.Transport = transport
	expires := in.RegisterExpirySeconds
	if expires <= 0 && template.Expires > 0 {
		expires = template.Expires
	}
	cfg := Config{
		DeviceID:                   strings.TrimSpace(ims.DeviceID),
		TraceID:                    strings.TrimSpace(in.TraceID),
		LocalIP:                    in.LocalIP,
		Dataplane:                  in.Dataplane,
		PCSCFAddr:                  pcscf,
		RegistrarCandidates:        append([]string(nil), in.RegistrarCandidates...),
		Realm:                      strings.TrimSpace(ims.Realm),
		CallPhoneContext:           strings.TrimSpace(ims.CallPhoneContext),
		PrivateID:                  strings.TrimSpace(ims.IMPI),
		PublicURI:                  strings.TrimSpace(ims.IMPU),
		HomeDomain:                 strings.TrimSpace(ims.Domain),
		IMSI:                       strings.TrimSpace(in.IMSI),
		DisableAMR:                 in.DisableAMR,
		AKA:                        in.AKA,
		EAPDirectAuth:              in.EAPDirectAuth.clone(),
		Template:                   template,
		MCC:                        strings.TrimSpace(in.MCC),
		MNC:                        strings.TrimSpace(in.MNC),
		CellID:                     strings.TrimSpace(in.CellID),
		SIPInstanceURN:             strings.TrimSpace(ims.SIPInstance),
		UserAgent:                  strings.TrimSpace(ims.UserAgent),
		LocalPort:                  ims.LocalPort,
		Transport:                  transport,
		TCPKeepaliveSeconds:        ims.TCPKeepaliveSeconds,
		OptionsPingIntervalSeconds: ims.OptionsPingIntervalSeconds,
		RegisterExpirySeconds:      expires,
		DeliveryStore:              in.DeliveryStore,
		DecodeIncomingRPDU:         in.DecodeIncomingRPDU,
		DecodeIncomingSMS:          in.DecodeIncomingSMS,
		DTMFEvent:                  in.DTMFEvent,
		ValidateRegisterResponse:   in.ValidateRegisterResponse,
		IncomingSMS:                in.IncomingSMS,
		IncomingSMSMessage:         in.IncomingSMSMessage,
		IncomingSIPRequest:         in.IncomingSIPRequest,
		IncomingSIPHandler:         in.IncomingSIPHandler,
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "SimAdmin VoWiFi"
	}
	if strings.TrimSpace(cfg.Template.ID) == "" {
		cfg.Template = policy.DefaultIMSRegisterTemplate()
	}
	return cfg
}

func resolveIMSConfigTransport(configured, template string) string {
	configured = strings.ToLower(strings.TrimSpace(configured))
	template = strings.ToLower(strings.TrimSpace(template))
	if configured != "" && configured != "auto" {
		return configured
	}
	if template != "" && template != "auto" {
		return template
	}
	return "tcp"
}

func registerPolicyID(t policy.IMSRegisterTemplate) string {
	if id := strings.TrimSpace(t.RegisterPolicy.ID); id != "" {
		return id
	}
	return "default"
}
