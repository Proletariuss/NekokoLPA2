package mobilecore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/1239t/swu-go/pkg/swu"
	"go.uber.org/zap"
	"proletarius.local/core/internal/vowifi"
	"proletarius.local/core/internal/vowifi/carrier"
)

func TestPublishedCapabilitiesReachEngineBoundary(t *testing.T) {
	p := &carrier.Profile{MCC: "234", MNC: "20", UseIPSec: true}
	e := &readerVoWiFiEffectiveConfig{Profile: p, EPDG: "first.example", EPDGPort: 4500,
		RemoteCertificateHostname: "auth.example", ValidateRemoteCertificate: true,
		IKELifetimeSeconds: 3600, ChildLifetimeSeconds: 1200, ReauthIntervalSeconds: 7200,
		IKEProposals: []string{"aes256gcm16-prfsha384-ecp384"}, ESPProposals: []string{"aes256gcm16"},
		RekeyPFS: 20, IMSTransport: "udp", DeviceIdentityEnabled: true}
	config := engineConfig{cardConfig: cardConfig{MCC: "234", MNC: "20", IMSI: "234201234567890"}, Proxy: "socks5://127.0.0.1:1080"}
	cfg := readerSWUConfig(config, e, nil)
	if !cfg.ValidateRemoteCertificate || cfg.RemoteIdentifier != "auth.example" || cfg.EpDGAddr != "first.example" || cfg.EpDGPort != 4500 || cfg.TransportFactory == nil || cfg.DataplaneMode != "netstack" {
		t.Fatalf("security/routing not applied: %+v", cfg)
	}
	if cfg.IKELifetimeSeconds != 3600 || cfg.ChildLifetimeSeconds != 1200 || cfg.ReauthInterval != 7200 || cfg.RekeyPFS != 20 || !reflect.DeepEqual(cfg.IKEProposals, e.IKEProposals) {
		t.Fatal("lifetime/proposals not applied")
	}
	// Mapping fields is insufficient: exercise the real session validation
	// boundary, but stop before opening a socket or contacting an operator.
	probe := errors.New("capability validation reached transport")
	reachedTransport := false
	cfg.TransportFactory = func(local, remote string) (swu.Transport, error) {
		reachedTransport = true
		return nil, probe
	}
	if err := swu.NewSession(cfg, zap.NewNop()).Connect(context.Background()); !reachedTransport || !errors.Is(err, probe) {
		t.Fatalf("published capabilities rejected at session entry: %v", err)
	}
	if readerIMSTransport(e) != "udp" {
		t.Fatal("UDP ignored")
	}
	for _, mode := range []string{"", "auto", "tcp"} {
		e.IMSTransport = mode
		if readerIMSTransport(e) != "tcp" {
			t.Fatal("TCP default changed")
		}
	}
	e.RemoteCertificateHostname = ""
	if readerSWUConfig(config, e, nil).RemoteIdentifier != e.EPDG {
		t.Fatal("expected peer identity lost")
	}
}

func TestThreeHKProductionBoundaryRegression(t *testing.T) {
	p, err := carrier.ResolveWithError(carrier.SIMIdentity{MCC: "454", MNC: "03"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := resolveReaderVoWiFiEffectiveConfig(p, nil, false, &vowifi.SIMInfo{IMSI: "454031234567890", MCC: "454", MNC: "03"}, "custom.example", 4500, makeDeviceIMEI())
	if err != nil {
		t.Fatal(err)
	}
	cfg := readerSWUConfig(engineConfig{cardConfig: cardConfig{IMSI: "454031234567890"}}, e, nil)
	if cfg.EpDGAddr != "custom.example" || cfg.EpDGPort != 4500 || cfg.RekeyPFS != 14 || cfg.ReauthInterval != 7200 || !cfg.RequireFullEAP || cfg.IPStack != "ipv4" || readerIMSTransport(e) != "tcp" {
		t.Fatalf("3HK policy regressed: %+v", cfg)
	}
}

func TestCandidateFailoverCannotBypassAuthenticationOrCustomAddress(t *testing.T) {
	e := &readerVoWiFiEffectiveConfig{EPDG: "one.example", EPDGSource: "carrier-template", EPDGCandidates: []string{"one.example", "two.example"}}
	if got := effectiveForEPDGCandidate(e, 1); got.EPDG != "two.example" || e.EPDG != "one.example" {
		t.Fatal("candidate mutation")
	}
	for _, source := range []string{"custom", "carrier-override"} {
		e.EPDGSource = source
		if effectiveForEPDGCandidate(e, 1).EPDG != "one.example" {
			t.Fatal("explicit destination bypassed")
		}
	}
	networkErr := errors.New("connection timed out")
	for _, stage := range []string{"transport", "ike_sa_init"} {
		if !canAdvanceEPDGCandidate(stage, networkErr) {
			t.Fatal("safe bounded failover disabled")
		}
	}
	for _, stage := range []string{"ike_auth", "eap_aka", "eap_response", "tunnel_setup", "ims"} {
		if canAdvanceEPDGCandidate(stage, networkErr) {
			t.Fatal("authentication replay across candidates")
		}
	}
	badCert := fmt.Errorf("certificate rejected: %w", swu.ErrPeerAuthentication)
	if canAdvanceEPDGCandidate("ike_sa_init", badCert) || !permanentSessionFailure(badCert) {
		t.Fatal("bad certificate retried")
	}
	if permanentSessionFailure(nil) {
		t.Fatal("nil failure")
	}
}

func TestRedirectRequiresAuthenticationPreservesTrustAndCustomPolicy(t *testing.T) {
	e := &readerVoWiFiEffectiveConfig{EPDG: "one.example", EPDGSource: "carrier-template", EPDGPort: 4500}
	r := &swu.RedirectError{NewAddr: "two.example", Authenticated: true}
	next, err := effectiveForAuthenticatedRedirect(e, r, 0)
	if err != nil || next.EPDG != "two.example" || next.EPDGPort != 4500 || next.RemoteCertificateHostname != "one.example" || e.EPDG != "one.example" {
		t.Fatalf("redirect changed trust/routing policy: %+v %v", next, err)
	}
	for _, bad := range []string{"", "https://two.example", "two.example:500", "bad..name", "-bad.example", "one.example"} {
		r.NewAddr = bad
		if _, err := effectiveForAuthenticatedRedirect(e, r, 0); !errors.Is(err, errEPDGRedirectPolicy) {
			t.Fatalf("unsafe redirect %q", bad)
		}
	}
	r.NewAddr = "two.example"
	for _, source := range []string{"custom", "carrier-override"} {
		e.EPDGSource = source
		if _, err := effectiveForAuthenticatedRedirect(e, r, 0); !permanentSessionFailure(err) {
			t.Fatal("explicit destination changed")
		}
	}
	e.EPDGSource = "carrier-template"
	if _, err := effectiveForAuthenticatedRedirect(e, r, 3); err == nil {
		t.Fatal("unbounded redirect")
	}
	r.Authenticated = false
	if _, err := effectiveForAuthenticatedRedirect(e, r, 0); err == nil {
		t.Fatal("unauthenticated redirect followed")
	}
}
