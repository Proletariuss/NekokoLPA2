package imscore

import (
	"net"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
	"proletarius.local/core/internal/vowifi/ipsec3gpp"
	"proletarius.local/core/internal/vowifi/policy"
)

func TestBuildTemplateSecurityClientPreservesCompleteOffer(t *testing.T) {
	got := buildTemplateSecurityClient(policy.DefaultGiffgaffTemplate(), 1, 2, 5064, 5063)
	if strings.Count(got, "ipsec-3gpp") != len(policy.DefaultSecurityClientMechanisms()) {
		t.Fatalf("expected complete mechanism list, got %q", got)
	}
	for _, want := range []string{
		"alg=hmac-sha-1-96",
		"ealg=aes-cbc",
		"prot=esp",
		"mod=trans",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("header %q missing %q", got, want)
		}
	}
}

func TestBuildRegisterRequestUsesConnectedLocalPortInContact(t *testing.T) {
	cfg := Config{
		LocalIP:    net.ParseIP("2001:db8::10"),
		HomeDomain: "ims.mnc033.mcc234.3gppnetwork.org",
		PrivateID:  "234330000000001@ims.mnc033.mcc234.3gppnetwork.org",
		PublicURI:  "sip:234330000000001@ims.mnc033.mcc234.3gppnetwork.org",
		IMSI:       "234330000000001",
		Template:   policy.OrangeUKTemplate(),
	}
	req, err := buildRegisterRequest(cfg, registerState{sipInstance: "urn:uuid:test"}, 25219, false, initialRegisterVariant{})
	if err != nil {
		t.Fatal(err)
	}
	contact := req.GetHeader("Contact")
	if contact == nil || !strings.Contains(contact.Value(), "]:25219;transport=tcp") {
		t.Fatalf("Contact=%v, want connected local port 25219", contact)
	}
}

func TestContactGrantedExpiryUsesShortestPositiveBinding(t *testing.T) {
	got := contactGrantedExpiry([]string{
		`<sip:current@[2001:db8::1]:5063>;expires=2400;audio,<sip:old@[2001:db8::2]:5063>;expires=0`,
		`<sip:other@[2001:db8::3]:5063>;Expires=3000`,
	})
	if got != 2400 {
		t.Fatalf("granted expiry = %d, want 2400", got)
	}
	if got := contactGrantedExpiry([]string{`<sip:old@example>;expires=0`}); got != 0 {
		t.Fatalf("zero-expiry stale binding = %d, want 0", got)
	}
}

func TestBuildGiffgaffRegisterOmitsUnconfiguredBusinessHeaders(t *testing.T) {
	tmpl := policy.DefaultGiffgaffTemplate()
	cfg := Config{
		LocalIP: net.ParseIP("2001:db8::10"), HomeDomain: "ims.mnc010.mcc234.3gppnetwork.org",
		Realm: "ims.mnc010.mcc234.3gppnetwork.org", PrivateID: "234100000000001@ims.mnc010.mcc234.3gppnetwork.org",
		PublicURI: "sip:234100000000001@ims.mnc010.mcc234.3gppnetwork.org", IMSI: "234100000000001",
		Template: tmpl, Transport: "tcp", UserAgent: "iOS/18.6.2 iPhone",
	}
	req, err := buildRegisterRequest(cfg, registerState{sipInstance: "urn:uuid:test"}, 5060, true, initialRegisterVariant{includePANI: true, includeCellular: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"P-Preferred-Identity", "P-Visited-Network-ID", "Cellular-Network-Info"} {
		if got := req.GetHeader(name); got != nil {
			t.Fatalf("giffgaff unexpectedly included %s: %v", name, got)
		}
	}
	if contact := req.GetHeader("Contact"); contact == nil || !strings.Contains(contact.Value(), "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel") {
		t.Fatalf("giffgaff GSMA Contact = %v", contact)
	}
}

func TestResolveStableSIPInstanceUsesConfig(t *testing.T) {
	cfg := Config{SIPInstanceURN: "urn:uuid:fixed-id"}
	if got := resolveStableSIPInstance(cfg); got != "urn:uuid:fixed-id" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildRegisterRequestUsesTemplateHeadersAndRequiredSecAgree(t *testing.T) {
	tmpl := policy.DefaultIMSRegisterTemplate()
	tmpl.Expires = 600000
	tmpl.SupportedHeader = "path,sec-agree,gruu,test-feature"
	tmpl.AllowHeader = "REGISTER,OPTIONS"
	tmpl.FixedPANI = "IEEE-802.11;country=US"
	tmpl.AccessType = "wlan1"
	tmpl.SecAgreeMode = "required"

	cfg := Config{
		LocalIP:    net.ParseIP("2001:db8::10"),
		HomeDomain: "ims.example.test",
		Realm:      "ims.example.test",
		PrivateID:  "310260123456789@ims.example.test",
		PublicURI:  "sip:310260123456789@ims.example.test",
		IMSI:       "310260123456789",
		Template:   tmpl,
		Transport:  "tcp",
		UserAgent:  "test-agent",
	}
	req, err := buildRegisterRequest(cfg, registerState{sipInstance: "urn:uuid:test"}, 5070, true, initialRegisterVariant{includePANI: true})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"Expires":               "600000",
		"Supported":             "path,sec-agree,gruu,test-feature",
		"Allow":                 "REGISTER,OPTIONS",
		"P-Access-Network-Info": "IEEE-802.11;country=US",
		"Require":               "sec-agree",
		"Proxy-Require":         "sec-agree",
	}
	for name, want := range checks {
		header := req.GetHeader(name)
		if header == nil || header.Value() != want {
			t.Fatalf("%s = %v, want %q", name, header, want)
		}
	}
	contact := req.GetHeader("Contact")
	if contact == nil || !strings.Contains(contact.Value(), `+g.3gpp.accesstype="wlan1"`) {
		t.Fatalf("Contact = %v", contact)
	}
}

func TestBuildRegisterRequestAdvertisesCompleteSecAgreeBundleInAutoMode(t *testing.T) {
	tmpl := policy.OrangeUKTemplate()
	cfg := Config{
		LocalIP: net.ParseIP("2001:db8::10"), HomeDomain: "ims.mnc033.mcc234.3gppnetwork.org",
		Realm: "ims.mnc033.mcc234.3gppnetwork.org", PrivateID: "234330000000001@ims.mnc033.mcc234.3gppnetwork.org",
		PublicURI: "sip:234330000000001@ims.mnc033.mcc234.3gppnetwork.org", IMSI: "234330000000001",
		Template: tmpl, Transport: "tcp", UserAgent: "test-agent",
	}
	req, err := buildRegisterRequest(cfg, registerState{sipInstance: "urn:uuid:test"}, 5070, true, initialRegisterVariant{initialAuth: tmpl.InitialAuthorization})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Security-Client", "Require", "Proxy-Require"} {
		if req.GetHeader(name) == nil {
			t.Fatalf("auto sec-agree REGISTER omitted %s", name)
		}
	}
	if auth := req.GetHeader("Authorization"); auth == nil || !strings.Contains(auth.Value(), "algorithm=AKAv1-MD5") {
		t.Fatalf("initial Authorization = %v", auth)
	}
}

func TestBuildInitialAuthorizationDigestEmpty(t *testing.T) {
	cfg := Config{HomeDomain: "ims.example.test", Realm: "ims.example.test", PrivateID: "user@ims.example.test"}
	auth := buildInitialAuthorization(cfg, "digest_empty")
	for _, want := range []string{`Digest uri="sip:ims.example.test"`, `username="user@ims.example.test"`, `response=""`, `nonce=""`} {
		if !strings.Contains(auth, want) {
			t.Fatalf("authorization = %q, missing %q", auth, want)
		}
	}
	if strings.Contains(auth, "algorithm=") {
		t.Fatalf("digest_empty must not preselect an algorithm: %q", auth)
	}
}

func TestAuthenticatedRegisterFailureDetailClassifiesSecurityMismatch(t *testing.T) {
	res := sip.NewResponse(403, "Forbidden")
	res.AppendHeader(sip.NewHeader("P-Debug-Info", "private-data; No Matched Security Item"))
	if got := authenticatedRegisterFailureDetail(res); got != "; carrier detail: no matched IMS security item" {
		t.Fatalf("detail = %q", got)
	}
}

func TestProtectedRegisterUsesNegotiatedPortsAndIntegrityMarker(t *testing.T) {
	tmpl := policy.OrangeUKTemplate()
	cfg := Config{
		LocalIP: net.ParseIP("2001:db8::10"), PCSCFAddr: "[2001:db8::20]:5060",
		HomeDomain: "ims.mnc033.mcc234.3gppnetwork.org", Realm: "ims.mnc030.mcc234.3gppnetwork.org",
		PrivateID: "234330000000001@ims.mnc033.mcc234.3gppnetwork.org",
		PublicURI: "sip:234330000000001@ims.mnc033.mcc234.3gppnetwork.org",
		IMSI:      "234330000000001", Template: tmpl, Transport: "tcp", UserAgent: "test-agent",
	}
	state := registerState{
		portC: 5064, portS: 5063, sipInstance: "urn:uuid:test", verifyHeader: "ipsec-3gpp;test=yes",
		ipsecPolicy: ipsec3gpp.Policy{LocalPortC: 5064, LocalPortS: 5063, RemotePortC: 6064, RemotePortS: 6063},
	}
	initial, err := buildRegisterRequest(cfg, state, 5060, true, initialRegisterVariant{initialAuth: "aka_empty"})
	if err != nil {
		t.Fatal(err)
	}
	initial.AppendHeader(sip.NewHeader("CSeq", "1 REGISTER"))
	protected, _, err := buildAuthenticatedRegisterWithHeader(cfg, state, initial, `Digest response="abc",algorithm=AKAv1-MD5`)
	if err != nil {
		t.Fatal(err)
	}
	if contact := protected.GetHeader("Contact"); contact == nil || !strings.Contains(contact.Value(), "]:5063;transport=tcp") {
		t.Fatalf("protected Contact = %v", contact)
	}
	if route := protected.GetHeader("Route"); route == nil || route.Value() != "<sip:[2001:db8::20]:6063;transport=tcp;lr>" {
		t.Fatalf("protected Route = %v", route)
	}
	if auth := protected.GetHeader("Authorization"); auth == nil || !strings.Contains(auth.Value(), "integrity-protected=yes") {
		t.Fatalf("protected Authorization = %v", auth)
	}
	if verify := protected.GetHeader("Security-Verify"); verify == nil || verify.Value() != state.verifyHeader {
		t.Fatalf("Security-Verify = %v", verify)
	}
}

func TestRegisterAttemptLocalPortUsesConfiguredPortOnlyInitially(t *testing.T) {
	cfg := Config{
		LocalPort: 5077,
		LocalIP:   net.ParseIP("2001:db8::10"),
		PCSCFAddr: "[2001:db8::20]:5060",
	}
	if got := registerAttemptLocalPort(cfg, 0); got != 5077 {
		t.Fatalf("first port = %d, want 5077", got)
	}
	if got := registerAttemptLocalPort(cfg, 1); got == 5077 || got < 10000 || got >= 60000 {
		t.Fatalf("retry port = %d, want a fresh ephemeral port", got)
	}
}
