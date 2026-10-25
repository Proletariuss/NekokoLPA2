package mobilecore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/1239t/swu-go/pkg/swu"
	"proletarius.local/core/internal/vowifi/carrier"
)

const authRequestFixture = `{"stage":"initial","message_id":1,"payload_types":[35,40,41,47],"notify_types":[16384,16417],"idi_types":[1],"idr_types":[2],"idi_anonymous":true,"idr_is_apn":true,"certreq_count":1,"certreq_encodings":[4],"certreq_ca_hash_count":0,"eap_codes":[],"eap_types":[],"certificate_required":true,"eap_only_offered":false,"fragmented":false,"packet_count":1,"send_state":"prepared"}`

func TestAuthRequestDiagnosticJSONOwnershipAndFailureRetention(t *testing.T) {
	e := NewEngine(&fakeHost{events: make(chan string, 8)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx}
	e.run, e.phase, e.attempt = run, "ike", 1
	var request swu.AuthRequestDiagnostic
	if err := json.Unmarshal([]byte(authRequestFixture), &request); err != nil {
		t.Fatal(err)
	}
	e.recordAuthDiagnostic(run, 1, swu.AuthDiagnostic{Stage: "initial", FailureCode: "missing_certificate_auth"})
	e.recordAuthRequestDiagnostic(run, 1, ctx, request)
	var status, expected map[string]any
	if err := json.Unmarshal([]byte(e.Status()), &status); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(authRequestFixture), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(status["ike_auth_request_diagnostic"], expected) {
		t.Fatalf("request schema changed: %#v", status["ike_auth_request_diagnostic"])
	}
	request.Stage, request.EAPCodes, request.EAPTypes = "eap", []int{2}, []int{23}
	e.recordAuthRequestDiagnostic(run, 1, ctx, request)
	// Every numeric list must own its callback and status-copy storage.
	for _, name := range []string{"PayloadTypes", "NotifyTypes", "IDiTypes", "IDrTypes", "CertReqEncodings", "EAPCodes", "EAPTypes"} {
		callback := reflect.ValueOf(&request).Elem().FieldByName(name)
		if callback.Len() == 0 {
			continue
		}
		original := callback.Index(0).Int()
		callback.Index(0).SetInt(99)
		stored := reflect.ValueOf(e.ikeAuthRequestDiagnostic).Elem().FieldByName(name)
		if stored.Index(0).Int() != original {
			t.Fatalf("callback aliases %s", name)
		}
		copy := cloneAuthRequestDiagnosticStatus(e.ikeAuthRequestDiagnostic)
		reflect.ValueOf(copy).Elem().FieldByName(name).Index(0).SetInt(123)
		if stored.Index(0).Int() != original {
			t.Fatalf("status copy aliases %s", name)
		}
	}
	e.phase, e.run = "failed", nil
	if status := e.Status(); !strings.Contains(status, "ike_auth_request_diagnostic") || !strings.Contains(status, "missing_certificate_auth") {
		t.Fatalf("terminal failure lost independent request/response snapshots: %s", status)
	}
}

func TestAuthRequestDiagnosticBoundsAndMalformedSecretInjection(t *testing.T) {
	host := &fakeHost{events: make(chan string, 8)}
	e := NewEngine(host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx}
	e.run, e.phase = run, "ike"
	var request swu.AuthRequestDiagnostic
	if err := json.Unmarshal([]byte(`{"stage":"eap","send_state":"prepared","payload_types":[-1,256],"notify_types":[-1,65536],"idi_types":[-1,256],"idr_types":[-1,256],"certreq_encodings":[-1,256],"eap_codes":[-1,256],"eap_types":[-1,256],"certreq_count":100,"certreq_ca_hash_count":-1,"packet_count":1000,"raw":"subscriber-secret","idi":"subscriber-secret","ca_hash":"subscriber-secret","failure_code":"subscriber-secret"}`), &request); err != nil {
		t.Fatal(err)
	}
	request.PayloadTypes = append(request.PayloadTypes, make([]int, 40)...)
	e.recordAuthRequestDiagnostic(run, 0, ctx, request)
	got := e.ikeAuthRequestDiagnostic
	if len(got.PayloadTypes) != 32 || got.PayloadTypes[0] != 0 || got.PayloadTypes[1] != 255 || got.NotifyTypes[1] != 65535 || got.CertReqCount != 32 || got.CertReqCAHashCount != 0 || got.PacketCount != 255 {
		t.Fatal(got)
	}
	if strings.Contains(e.Status(), "subscriber-secret") {
		t.Fatal("unlisted request data exported")
	}
	request.Stage = "subscriber-secret"
	e.recordAuthRequestDiagnostic(run, 0, ctx, request)
	request.Stage, request.SendState = "initial", "subscriber-secret"
	e.recordAuthRequestDiagnostic(run, 0, ctx, request)
	if len(host.events) != 1 || e.ikeAuthRequestDiagnostic != got {
		t.Fatal("untrusted request enum accepted")
	}
}

func TestAuthRequestDiagnosticRetryAndCancellationFences(t *testing.T) {
	host := &fakeHost{events: make(chan string, 8)}
	e := NewEngine(host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx}
	e.run, e.phase = run, "ike"
	request := swu.AuthRequestDiagnostic{Stage: "initial", SendState: "prepared"}
	e.recordAuthRequestDiagnostic(run, 0, ctx, request)
	e.recordAuthDiagnostic(run, 0, swu.AuthDiagnostic{Stage: "initial", FailureCode: "missing_certificate_auth"})
	if !e.beginConnectionAttempt(run, engineConfig{}, &readerVoWiFiEffectiveConfig{}) || e.attempt != 1 || e.ikeAuthRequestDiagnostic != nil || e.ikeAuthDiagnostic != nil {
		t.Fatal("retry retained previous request/response")
	}
	e.recordAuthRequestDiagnostic(run, 0, ctx, request)
	e.recordAuthRequestDiagnostic(&runningSession{ctx: ctx}, 1, ctx, request)
	cycleCtx, cancelCycle := context.WithCancel(ctx)
	cancelCycle()
	e.recordAuthRequestDiagnostic(run, 1, cycleCtx, request)
	e.phase = "failed"
	e.recordAuthRequestDiagnostic(run, 1, ctx, request)
	e.phase = "ike"
	cancel()
	e.recordAuthRequestDiagnostic(run, 1, ctx, request)
	if e.beginConnectionAttempt(run, engineConfig{}, &readerVoWiFiEffectiveConfig{}) || e.ikeAuthRequestDiagnostic != nil || len(host.events) != 2 {
		t.Fatal("stale/failed/cancelled request restored diagnostics")
	}
}

func TestAuthRequestDiagnosticConcurrentStatusAndStop(t *testing.T) {
	e := NewEngine(&fakeHost{events: make(chan string, 512)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	e.run, e.phase = run, "ike"
	go func() { <-ctx.Done(); close(run.done) }()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 256; i++ {
			e.recordAuthRequestDiagnostic(run, 0, ctx, swu.AuthRequestDiagnostic{Stage: "eap", MessageID: uint32(i), SendState: "prepared", EAPCodes: []int{2}, EAPTypes: []int{23}})
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 256; i++ {
			_ = e.Status()
		}
	}()
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if strings.Contains(e.Status(), "ike_auth_request_diagnostic") {
		t.Fatal("request callback restored stopped diagnostic")
	}
}

func TestAuthRequestDiagnosticConcurrentRetryAndRestart(t *testing.T) {
	e := NewEngine(&fakeHost{events: make(chan string, 1024)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	e.run, e.phase = run, "ike"
	go func() { <-ctx.Done(); close(run.done) }()
	request := swu.AuthRequestDiagnostic{Stage: "initial", SendState: "prepared", PayloadTypes: []int{35}}
	var callbacks sync.WaitGroup
	callbacks.Add(1)
	go func() {
		defer callbacks.Done()
		for i := 0; i < 256; i++ {
			e.recordAuthRequestDiagnostic(run, 0, ctx, request)
		}
	}()
	if !e.beginConnectionAttempt(run, engineConfig{}, &readerVoWiFiEffectiveConfig{}) {
		t.Fatal("retry failed")
	}
	callbacks.Wait()
	if e.ikeAuthRequestDiagnostic != nil {
		t.Fatal("old attempt callback restored request after retry")
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	// This artificial run has no serve defer; model its completed teardown.
	e.mu.Lock()
	e.run = nil
	e.mu.Unlock()
	if err := e.Start(`{"generation":2,"imsi":"invalid","usim_aid":"invalid","mcc":"x","mnc":"y"}`); err != nil {
		t.Fatal(err)
	}
	callbacks.Add(1)
	go func() {
		defer callbacks.Done()
		for i := 0; i < 256; i++ {
			e.recordAuthRequestDiagnostic(run, 1, ctx, request)
			_ = e.Status()
		}
	}()
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	callbacks.Wait()
	if strings.Contains(e.Status(), "ike_auth_request_diagnostic") {
		t.Fatal("previous run callback restored request after new Start/Stop")
	}
}

func TestAuthDiagnosticJSONOwnershipAndAttemptIsolation(t *testing.T) {
	host := &fakeHost{events: make(chan string, 32)}
	e := NewEngine(host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx, cancel: cancel}
	e.run, e.phase, e.attempt = run, "ike", 1
	diagnostic := swu.AuthDiagnostic{Stage: "initial", MessageID: 1, CertificateRequired: true, FailureCode: "missing_certificate_auth"}
	// Construct via JSON so this test also checks the callback's JSON schema.
	if err := json.Unmarshal([]byte(`{"stage":"initial","message_id":1,"payload_types":[35,48],"notify_types":[16384],"eap_codes":[1],"eap_types":[23],"auth_methods":[1],"idr_types":[2],"certificate_required":true,"failure_code":"missing_certificate_auth"}`), &diagnostic); err != nil {
		t.Fatal(err)
	}
	e.recordAuthDiagnostic(run, 1, diagnostic)
	diagnostic.PayloadTypes[0] = 99
	var status map[string]any
	if err := json.Unmarshal([]byte(e.Status()), &status); err != nil {
		t.Fatal(err)
	}
	exported := status["ike_auth_diagnostic"].(map[string]any)
	if got := exported["payload_types"].([]any)[0]; got != float64(35) {
		t.Fatalf("callback slice alias: %v", got)
	}
	for _, key := range []string{"payload_types", "notify_types", "eap_codes", "eap_types", "auth_methods", "idr_types"} {
		if _, ok := exported[key].([]any); !ok {
			t.Fatalf("%s is not a JSON numeric array: %#v", key, exported[key])
		}
	}
	copy := cloneAuthDiagnosticStatus(e.ikeAuthDiagnostic)
	copy.PayloadTypes[0] = 123
	if e.ikeAuthDiagnostic.PayloadTypes[0] != 35 {
		t.Fatal("status copy aliases engine")
	}
	initial := e.ikeAuthDiagnostic
	diagnostic.MessageID = 2
	e.recordAuthDiagnostic(&runningSession{ctx: ctx}, 1, diagnostic)
	e.recordAuthDiagnostic(run, 0, diagnostic)
	e.phase = "failed"
	e.recordAuthDiagnostic(run, 1, diagnostic)
	if e.ikeAuthDiagnostic != initial {
		t.Fatal("stale callback replaced final failure")
	}
	// The failed snapshot survives teardown for subsequent log export.
	e.run = nil
	if !strings.Contains(e.Status(), "missing_certificate_auth") {
		t.Fatal("lost failed diagnostic")
	}
	e.run, e.phase = run, "ike"
	cancel()
	e.recordAuthDiagnostic(run, 1, diagnostic)
	if e.ikeAuthDiagnostic != initial {
		t.Fatal("cancelled callback updated diagnostic")
	}
	if len(host.events) != 1 {
		t.Fatalf("unexpected diagnostic events: %d", len(host.events))
	}
}

func TestConnectionPolicyNeverExportsEndpointsOrIdentities(t *testing.T) {
	effective := &readerVoWiFiEffectiveConfig{
		EPDG: "secret.private.endpoint", EPDGSource: "custom", EPDGPort: 4500,
		RemoteCertificateHostname: "secret.cert.hostname", ValidateRemoteCertificate: true,
		IPStack: "ipv6", IMSTransport: "udp",
	}
	policy := connectionPolicyFor(engineConfig{Proxy: "user:password@secret.proxy:1080"}, effective)
	encoded := marshalJSON(policy)
	for _, forbidden := range []string{"secret", "password", "user:", "hostname\":\"secret"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("private policy data exported: %s", encoded)
		}
	}
	if policy.RegistryRevision != carrier.EmbeddedRegistryRevision || !policy.ProxyEnabled || policy.EPDGSource != "custom" || policy.EPDGPort != 4500 || policy.RemoteIdentitySource != "certificate-hostname" || policy.EAPOnlyOffered || !policy.CertificateRequired || policy.IMSTransport != "udp" {
		t.Fatal(policy)
	}
	if effective.EPDG != "secret.private.endpoint" || effective.RemoteCertificateHostname != "secret.cert.hostname" {
		t.Fatal("diagnostics changed policy")
	}
	if policy.CertificateProfile != "strict_ike" {
		t.Fatalf("custom policy compatibility profile = %q", policy.CertificateProfile)
	}
}

func TestConnectionPolicyCertificateProfile(t *testing.T) {
	const hostname = "epdg.epc.mnc020.mcc234.pub.3gppnetwork.org"
	effective := &readerVoWiFiEffectiveConfig{
		Profile: &carrier.Profile{ID: "apple_hutchison_uk", MCC: "234", MNC: "20", ValidateRemoteCertificate: true},
		EPDG:    hostname, EPDGSource: "carrier-template", EPDGPort: 500,
		RemoteCertificateHostname: hostname, ValidateRemoteCertificate: true,
	}
	config := engineConfig{cardConfig: cardConfig{MCC: "234", MNC: "20"}}
	if got := connectionPolicyFor(config, effective).CertificateProfile; got != "three_uk_server_auth" {
		t.Fatalf("3UK profile = %q", got)
	}
	effective.EPDGSource = "custom"
	if got := connectionPolicyFor(config, effective).CertificateProfile; got != "strict_ike" {
		t.Fatalf("custom profile = %q", got)
	}
}

func TestAuthDiagnosticBoundsAndUnknownText(t *testing.T) {
	host := &fakeHost{events: make(chan string, 8)}
	e := NewEngine(host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx}
	e.run, e.phase = run, "ike"
	var diagnostic swu.AuthDiagnostic
	if err := json.Unmarshal([]byte(`{"stage":"initial","payload_types":[35],"failure_code":"subscriber-secret","cert_count":1000}`), &diagnostic); err != nil {
		t.Fatal(err)
	}
	for len(diagnostic.PayloadTypes) < 100 {
		diagnostic.PayloadTypes = append(diagnostic.PayloadTypes, 35)
	}
	e.recordAuthDiagnostic(run, 0, diagnostic)
	if len(e.ikeAuthDiagnostic.PayloadTypes) != 32 || e.ikeAuthDiagnostic.CertCount != 32 || e.ikeAuthDiagnostic.FailureCode != "auth_response_invalid" {
		t.Fatal(e.ikeAuthDiagnostic)
	}
	if strings.Contains(e.Status(), "subscriber-secret") {
		t.Fatal("untrusted failure code exported")
	}
	diagnostic.Stage = "subscriber-secret"
	e.recordAuthDiagnostic(run, 0, diagnostic)
	if len(host.events) != 1 || e.ikeAuthDiagnostic.Stage != "initial" {
		t.Fatal("untrusted stage accepted")
	}
}

func TestCertificateDiagnosticJSONOwnershipAndLifecycle(t *testing.T) {
	e := NewEngine(&fakeHost{events: make(chan string, 8)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx}
	e.run, e.phase, e.attempt = run, "ike", 2
	fingerprint := strings.Repeat("0123456789abcdef", 4)
	var diagnostic swu.AuthDiagnostic
	fixture := `{"stage":"initial","message_id":1,"payload_types":[35,37,39,48],"eap_codes":[1],"eap_types":[1],"cert_count":1,"auth_methods":[1],"idr_types":[2],"certificate_required":true,"failure_code":"certificate_validation_failed","certificate_failure":"certificate_chain_incomplete","certificate_trust_stage":2,"certificate_trust_code":-25318,"certificate_leaf_sha256":"` + fingerprint + `","subject":"subscriber-secret","certificate":"subscriber-secret"}`
	if err := json.Unmarshal([]byte(fixture), &diagnostic); err != nil {
		t.Fatal(err)
	}
	e.recordAuthDiagnostic(run, 2, diagnostic)
	e.recordAuthRequestDiagnostic(run, 2, ctx, swu.AuthRequestDiagnostic{Stage: "initial", SendState: "prepared", CertReqCount: 1})
	copy := cloneAuthDiagnosticStatus(e.ikeAuthDiagnostic)
	copy.CertificateFailure, copy.CertificateLeafSHA256 = "certificate_revoked", ""
	copy.CertificateTrustCode, copy.CertificateTrustStage = -67820, 9
	diagnostic.CertificateFailure, diagnostic.CertificateLeafSHA256 = "subscriber-secret", "subscriber-secret"
	diagnostic.CertificateTrustCode, diagnostic.CertificateTrustStage = 99, 99
	e.phase, e.run = "failed", nil
	var status map[string]any
	if err := json.Unmarshal([]byte(e.Status()), &status); err != nil {
		t.Fatal(err)
	}
	got := status["ike_auth_diagnostic"].(map[string]any)
	for key, want := range map[string]any{
		"failure_code": "certificate_validation_failed", "certificate_failure": "certificate_chain_incomplete",
		"certificate_trust_stage": float64(2), "certificate_trust_code": float64(-25318), "certificate_leaf_sha256": fingerprint,
	} {
		if got[key] != want {
			t.Fatalf("%s = %#v, want %#v", key, got[key], want)
		}
	}
	request := status["ike_auth_request_diagnostic"].(map[string]any)
	if request["certreq_count"] != float64(1) || status["attempt"] != float64(2) || status["phase"] != "failed" {
		t.Fatalf("request/lifecycle fields changed: %s", e.Status())
	}
	if _, ok := request["certificate_failure"]; ok || strings.Contains(e.Status(), "subscriber-secret") {
		t.Fatal("response detail leaked into request or private data exported")
	}
}

func TestCertificateDiagnosticBoundsAndInjection(t *testing.T) {
	e := NewEngine(&fakeHost{events: make(chan string, 64)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx}
	e.run, e.phase = run, "ike"
	for _, tc := range []struct {
		stage, code, wantStage, wantCode int
	}{
		{0, 0, 0, 0}, {16, -2147483648, 16, -2147483648}, {16, 2147483647, 16, 2147483647},
		{-1, -2147483649, 0, -2147483648}, {17, 2147483648, 16, 2147483647},
	} {
		e.recordAuthDiagnostic(run, 0, swu.AuthDiagnostic{Stage: "initial", FailureCode: "certificate_validation_failed", CertificateFailure: "subscriber-secret", CertificateTrustStage: tc.stage, CertificateTrustCode: tc.code})
		got := e.ikeAuthDiagnostic
		if got.CertificateFailure != "certificate_trust_internal" || got.CertificateTrustStage != tc.wantStage || got.CertificateTrustCode != tc.wantCode || strings.Contains(e.Status(), "subscriber-secret") {
			t.Fatalf("certificate diagnostic not sanitized: %#v", got)
		}
	}
	for _, fingerprint := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 64) + "\n", "subscriber-secret"} {
		e.recordAuthDiagnostic(run, 0, swu.AuthDiagnostic{Stage: "initial", CertificateLeafSHA256: fingerprint})
		if e.ikeAuthDiagnostic.CertificateLeafSHA256 != "" || strings.Contains(e.Status(), "certificate_leaf_sha256") {
			t.Fatalf("invalid fingerprint exported: %q", fingerprint)
		}
	}
}

func TestDiagnosticStopClearsRetainedFailure(t *testing.T) {
	e := NewEngine(&fakeHost{})
	e.ikeAuthDiagnostic = &ikeAuthDiagnosticStatus{Stage: "final", FailureCode: "final_auth_mismatch"}
	e.ikeAuthRequestDiagnostic = &ikeAuthRequestDiagnosticStatus{Stage: "final", SendState: "prepared"}
	e.connectionPolicy = &connectionPolicyStatus{EPDGSource: "custom"}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.Status(), "ike_auth_diagnostic") || strings.Contains(e.Status(), "ike_auth_request_diagnostic") || strings.Contains(e.Status(), "connection_policy") {
		t.Fatal("stopped diagnostics retained")
	}
}

func TestNewSessionCannotExportPreviousAuthFailure(t *testing.T) {
	e := NewEngine(&fakeHost{events: make(chan string, 8)})
	e.ikeAuthDiagnostic = &ikeAuthDiagnosticStatus{Stage: "initial", FailureCode: "missing_certificate_auth"}
	e.ikeAuthRequestDiagnostic = &ikeAuthRequestDiagnosticStatus{Stage: "initial", SendState: "prepared"}
	e.connectionPolicy = &connectionPolicyStatus{EPDGSource: "custom"}
	// This configuration fails local SIM validation before any network work.
	if err := e.Start(`{"generation":1,"imsi":"invalid","usim_aid":"invalid","mcc":"x","mnc":"y"}`); err != nil {
		t.Fatal(err)
	}
	if status := e.Status(); strings.Contains(status, "ike_auth_diagnostic") || strings.Contains(status, "ike_auth_request_diagnostic") || strings.Contains(status, "connection_policy") {
		t.Fatalf("previous session diagnostic leaked: %s", status)
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthDiagnosticConcurrentStatusAndStop(t *testing.T) {
	e := NewEngine(&fakeHost{events: make(chan string, 512)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &runningSession{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	e.run, e.phase = run, "ike"
	go func() { <-ctx.Done(); close(run.done) }()
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 256; i++ {
			e.recordAuthDiagnostic(run, 0, swu.AuthDiagnostic{Stage: "eap", MessageID: uint32(i)})
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 256; i++ {
			_ = e.Status()
		}
	}()
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if strings.Contains(e.Status(), "ike_auth_diagnostic") {
		t.Fatal("callback restored diagnostics after Stop")
	}
}

func TestTerminalSessionErrorPreservesCauseAndReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		text string
	}{
		{fmt.Errorf("outer: %w", swu.ErrPeerAuthentication), "immediately after IKE authentication"},
		{errors.New("network timeout"), "startup failures exhausted retries"},
		{errEPDGRedirectPolicy, "non-retryable session"},
	} {
		got := terminalSessionError(tc.err)
		if !errors.Is(got, tc.err) || !strings.Contains(got.Error(), tc.text) {
			t.Fatalf("cause/reason lost: %v", got)
		}
		if permanentSessionFailure(got) != permanentSessionFailure(tc.err) {
			t.Fatalf("classification changed: %v", got)
		}
	}
}
