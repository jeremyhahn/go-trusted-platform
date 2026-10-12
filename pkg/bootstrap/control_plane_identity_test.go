// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// writeCPTemplate writes a control-plane template carrying the given
// webservices block and points the orchestrator's config at it.
func writeCPTemplate(t *testing.T, o *Orchestrator, webservices string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control-plane.yaml")
	if err := os.WriteFile(path, []byte(webservices), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	o.config.Templates = map[string]string{RoleControlPlane: path}
}

// newTLSNameTestOrchestrator is newTrustTestOrchestrator with a logger the
// test can read back, so the once-only log line can be asserted.
func newTLSNameTestOrchestrator() (*Orchestrator, *bytes.Buffer) {
	o := newTrustTestOrchestrator()
	var logs bytes.Buffer
	o.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return o, &logs
}

func TestControlPlaneTLSName_FromMergedConfigSubjectCN(t *testing.T) {
	o, logs := newTLSNameTestOrchestrator()
	writeCPTemplate(t, o, `
webservices:
  - name: internal
    tls-port: 9443
    certificate:
      subject:
        cn: cp.internal.test
  - name: public
    tls-port: 8443
    certificate:
      subject:
        cn: cp.from-template.test
      sans:
        dns:
          - cp.from-template.test
`)

	name, err := o.controlPlaneTLSName()
	if err != nil {
		t.Fatalf("controlPlaneTLSName: %v", err)
	}
	if name != "cp.from-template.test" {
		t.Fatalf("expected the 8443 webservice's subject CN, got %q", name)
	}
	if !strings.Contains(logs.String(), "webservices[1].certificate.subject.cn") {
		t.Errorf("the config key must be logged, got %q", logs.String())
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("a name found in the merged config must not warn: %q", logs.String())
	}
}

func TestControlPlaneTLSName_FromMergedConfigFirstDNSSAN(t *testing.T) {
	o, logs := newTLSNameTestOrchestrator()
	writeCPTemplate(t, o, `
webservices:
  - name: public
    tls-port: 8443
    certificate:
      sans:
        dns:
          - cp.san-only.test
          - www.cp.san-only.test
`)

	name, err := o.controlPlaneTLSName()
	if err != nil {
		t.Fatalf("controlPlaneTLSName: %v", err)
	}
	if name != "cp.san-only.test" {
		t.Fatalf("expected the first DNS SAN, got %q", name)
	}
	if !strings.Contains(logs.String(), "webservices[0].certificate.sans.dns[0]") {
		t.Errorf("the config key must be logged, got %q", logs.String())
	}
}

func TestControlPlaneTLSName_FallsBackToRoleAliasAtWarn(t *testing.T) {
	o, logs := newTLSNameTestOrchestrator()
	// A template that carries no webservice certificate identity.
	writeCPTemplate(t, o, "webservices:\n  - name: public\n    tls-port: 8443\n")

	name, err := o.controlPlaneTLSName()
	if err != nil {
		t.Fatalf("controlPlaneTLSName: %v", err)
	}
	if name != "cp.example.test" {
		t.Fatalf("expected cp.<platform domain>, got %q", name)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), controlPlaneTLSNameFallbackSource) {
		t.Errorf("the fallback must be logged at WARN naming its source, got %q", logs.String())
	}
}

func TestControlPlaneTLSName_NoTemplateFallsBackAtWarn(t *testing.T) {
	o, logs := newTLSNameTestOrchestrator()

	name, err := o.controlPlaneTLSName()
	if err != nil {
		t.Fatalf("controlPlaneTLSName: %v", err)
	}
	if name != "cp.example.test" {
		t.Fatalf("expected cp.<platform domain>, got %q", name)
	}
	if !strings.Contains(logs.String(), "merged control-plane config unavailable") {
		t.Errorf("the missing template must be the stated reason, got %q", logs.String())
	}
}

func TestControlPlaneTLSName_UnknownWithoutConfigOrDomain(t *testing.T) {
	o := newTrustTestOrchestrator()
	o.config = nil
	if _, err := o.controlPlaneTLSName(); !errors.As(err, &ControlPlaneTLSNameUnknownError{}) {
		t.Fatalf("expected ControlPlaneTLSNameUnknownError without config, got %v", err)
	}

	o = newTrustTestOrchestrator()
	o.config.Platform.Domain = "  "
	if _, err := o.controlPlaneTLSName(); !errors.As(err, &ControlPlaneTLSNameUnknownError{}) {
		t.Fatalf("expected ControlPlaneTLSNameUnknownError with a blank domain, got %v", err)
	}
	if msg := (ControlPlaneTLSNameUnknownError{}).Error(); !strings.Contains(msg, "platform.domain") {
		t.Errorf("unexpected message %q", msg)
	}
}

func TestControlPlaneTLSName_ResolvedOnceAndLoggedOnce(t *testing.T) {
	o, logs := newTLSNameTestOrchestrator()
	first, err := o.controlPlaneTLSName()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	// A config change after the first resolution must not change the
	// answer: every TLS client verifies against one name.
	o.config.Platform.Domain = "changed.test"
	second, err := o.controlPlaneTLSName()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != second {
		t.Fatalf("name must be resolved once, got %q then %q", first, second)
	}
	if got := strings.Count(logs.String(), "control-plane TLS name"); got != 2 {
		// One WARN for the missing template, one for the fallback name.
		t.Errorf("expected the two resolution log lines exactly once, got %d in %q", got, logs.String())
	}
}

func TestWebserviceTLSNameFromConfig(t *testing.T) {
	cases := map[string]struct {
		yaml       string
		wantName   string
		wantSource string
	}{
		"cn wins over san": {
			yaml:       "webservices:\n  - tls-port: 8443\n    certificate:\n      subject: {cn: a.test}\n      sans: {dns: [b.test]}\n",
			wantName:   "a.test",
			wantSource: "webservices[0].certificate.subject.cn",
		},
		"blank cn falls to san": {
			yaml:       "webservices:\n  - tls-port: 8443\n    certificate:\n      subject: {cn: '  '}\n      sans: {dns: ['', b.test]}\n",
			wantName:   "b.test",
			wantSource: "webservices[0].certificate.sans.dns[1]",
		},
		"other port ignored": {
			yaml: "webservices:\n  - tls-port: 9443\n    certificate:\n      subject: {cn: a.test}\n",
		},
		"singular webservice": {
			yaml:       "webservice:\n  tls-port: 8443\n  certificate:\n    sans: {dns: [c.test]}\n",
			wantName:   "c.test",
			wantSource: "webservice.certificate.sans.dns[0]",
		},
		"list wins over singular": {
			yaml:       "webservices:\n  - tls-port: 8443\n    certificate:\n      subject: {cn: a.test}\nwebservice:\n  tls-port: 8443\n  certificate:\n    subject: {cn: c.test}\n",
			wantName:   "a.test",
			wantSource: "webservices[0].certificate.subject.cn",
		},
		"singular on other port ignored": {
			yaml: "webservice:\n  tls-port: 9443\n  certificate:\n    subject: {cn: c.test}\n",
		},
		"no webservices": {yaml: "network: {}\n"},
	}
	for name, tc := range cases {
		gotName, gotSource, err := webserviceTLSNameFromConfig(tc.yaml, cpWebserviceTLSPort)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if gotName != tc.wantName || gotSource != tc.wantSource {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", name, gotName, gotSource, tc.wantName, tc.wantSource)
		}
	}
}

func TestWebserviceTLSNameFromConfig_UnparseableYAMLIsAnError(t *testing.T) {
	name, source, err := webserviceTLSNameFromConfig("webservices: [\n", cpWebserviceTLSPort)
	if err == nil {
		t.Fatal("a config that is not YAML must be reported, not read as carrying no name")
	}
	if name != "" || source != "" {
		t.Errorf("no name may be returned with an error, got (%q, %q)", name, source)
	}
}

func TestControlPlaneDialCandidates_OrderAndDedupe(t *testing.T) {
	o := newTrustTestOrchestrator()
	node := &o.discovered[0]
	node.Hostname = "cp-01"
	node.MACs = []string{"aa:bb:cc:dd:ee:01"}
	node.Interfaces = append(node.Interfaces, installer.InterfaceConfig{
		Name: "eth1", Type: installer.InterfaceTypeStatic, IPv4Address: "10.0.0.5/24",
	})
	// registration.json reports an address that is also declared static:
	// it leads, and is not repeated.
	o.config.Deployer = registrationSink(t, node, "10.0.0.5")

	got := o.controlPlaneDialCandidates(node)
	want := []string{"10.0.0.5", "127.0.0.1", "cp-01"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

func TestControlPlaneDialCandidates_NoRegistrationNoDeployer(t *testing.T) {
	o := newTrustTestOrchestrator()
	node := &o.discovered[0]
	got := o.controlPlaneDialCandidates(node)
	want := []string{"127.0.0.1", "cp-01"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}

	o.config = nil
	if got := o.controlPlaneDialCandidates(node); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("without config candidates = %v, want %v", got, want)
	}

	node.Interfaces = nil
	node.Hostname = ""
	if got := o.controlPlaneDialCandidates(node); len(got) != 0 {
		t.Fatalf("expected no candidates, got %v", got)
	}
}

func TestFetchControlPlaneCABundle_VerifiesByTLSNameNotAddress(t *testing.T) {
	pki := newTestCPPKI(t)
	startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	o := newTrustTestOrchestrator()
	// The leaf names only cp.example.test; the orchestrator dials
	// 127.0.0.1. Verification must be for the name.
	if _, err := o.fetchControlPlaneCABundle(context.Background()); err != nil {
		t.Fatalf("capture-then-verify must verify the served chain for the TLS name: %v", err)
	}

	// The same server, expected under a different name, is rejected
	// even though its chain is genuine.
	o = newTrustTestOrchestrator()
	o.config.Platform.Domain = "other.test"
	_, err := o.fetchControlPlaneCABundle(context.Background())
	var verifyErr ErrCABundleVerifyFailed
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected ErrCABundleVerifyFailed for a name mismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "cp.other.test") {
		t.Errorf("the expected name must be in the error, got %v", err)
	}
}

func TestFetchControlPlaneSPKIPin_DialsStaticIPOnly(t *testing.T) {
	pki := newTestCPPKI(t)
	startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	o := newTrustTestOrchestrator()
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	o.storeControlPlaneCAPool(pool)
	// registration.json points at a dead address; the pin capture must
	// not consult it and must succeed from the declared static IP.
	o.discovered[0].MACs = []string{"aa:bb:cc:dd:ee:01"}
	o.config.Deployer = registrationSink(t, &o.discovered[0], "127.0.0.2")

	pin, err := o.fetchControlPlaneSPKIPin(context.Background())
	if err != nil {
		t.Fatalf("fetchControlPlaneSPKIPin: %v", err)
	}
	if pin != pki.spkiPinB {
		t.Errorf("pin = %q, want %q", pin, pki.spkiPinB)
	}

	// Without a static IP the registration address is not a fallback.
	o.discovered[0].Interfaces = nil
	if _, err := o.fetchControlPlaneSPKIPin(context.Background()); !errors.As(err, &ControlPlaneStaticIPRequiredError{}) {
		t.Fatalf("expected ControlPlaneStaticIPRequiredError, got %v", err)
	}

	// With a static IP where nothing listens, the live registration and
	// hostname addresses are not consulted either: the capture fails.
	o.discovered[0].Interfaces = []installer.InterfaceConfig{{Name: "eth0", Type: installer.InterfaceTypeStatic, IPv4Address: "127.0.0.3"}}
	o.discovered[0].Hostname = "127.0.0.1"
	o.config.Deployer = registrationSink(t, &o.discovered[0], "127.0.0.1")
	_, err = o.fetchControlPlaneSPKIPin(context.Background())
	if err == nil || !strings.Contains(err.Error(), "127.0.0.3") {
		t.Fatalf("pin capture must fail on the static address, not fall back, got %v", err)
	}
}

func TestSeedTemplatesWithSeeder_RequiresCapturedPool(t *testing.T) {
	o := newTrustTestOrchestrator()
	o.discovered[0].Interfaces = nil
	// No pool cached and no declared address to capture it from: seeding
	// must refuse with the capture failure as its cause, never fall back
	// to the system pool.
	_, err := o.seedTemplatesWithSeeder(context.Background())
	var required ErrCABundleRequired
	if !errors.As(err, &required) {
		t.Fatalf("expected ErrCABundleRequired, got %T: %v", err, err)
	}
	if required.Operation != "template seeding" {
		t.Errorf("operation = %q", required.Operation)
	}
	if !errors.As(err, &ControlPlaneStaticIPRequiredError{}) {
		t.Errorf("the capture failure must be the cause, got %v", err)
	}
}

func TestControlPlaneTLSName_AndAddresses_Exported(t *testing.T) {
	o := newTrustTestOrchestrator()
	name, err := o.ControlPlaneTLSName()
	if err != nil || name != testCPTLSName {
		t.Fatalf("ControlPlaneTLSName = %q, %v", name, err)
	}
	if got := o.ControlPlaneAddresses(&o.discovered[0]); strings.Join(got, ",") != "127.0.0.1,cp-01" {
		t.Fatalf("ControlPlaneAddresses = %v", got)
	}
}

func TestSeeder_Seed_RefusesWithoutCAPool(t *testing.T) {
	s := NewSeeder(SeederParams{
		ControlPlaneAddr: "127.0.0.1:8443",
		Config:           minimalConfig(),
		Discovered:       []DiscoveredNode{},
		Logger:           orchTestLogger(),
	})
	err := s.Seed(context.Background())
	var required ErrCABundleRequired
	if !errors.As(err, &required) {
		t.Fatalf("expected ErrCABundleRequired, got %T: %v", err, err)
	}
	if required.Operation != "template seeding" {
		t.Errorf("operation = %q", required.Operation)
	}
}

// seederTLSTestServer serves the template and profile endpoints over TLS
// with the test control plane's DNS-only leaf.
func seederTLSTestServer(t *testing.T, pki *testCPPKI) string {
	t.Helper()
	srv := startTestCPServerHandler(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		body := `{"id":"tmpl-001"}`
		if strings.HasSuffix(r.URL.Path, "/create-profile") {
			body = `{"code":201,"success":true,"payload":{"id":"1"}}`
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	return srv.Listener.Addr().String()
}

func seederTLSTestConfig(t *testing.T) (*BootstrapConfig, []DiscoveredNode) {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "cp.yaml")
	if err := os.WriteFile(templatePath, []byte("hostname: placeholder\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	cfg := minimalConfig()
	cfg.Templates = map[string]string{RoleControlPlane: templatePath}
	discovered := []DiscoveredNode{{
		NodeConfig:     NodeConfig{Hostname: "cp1", Role: RoleControlPlane, MACs: []string{"aa:bb:cc:dd:ee:01"}},
		DiscoveredMACs: []string{"aa:bb:cc:dd:ee:01"},
	}}
	return cfg, discovered
}

func TestSeeder_Seed_VerifiesControlPlaneByServerName(t *testing.T) {
	pki := newTestCPPKI(t)
	addr := seederTLSTestServer(t, pki)
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	cfg, discovered := seederTLSTestConfig(t)

	s := NewSeeder(SeederParams{
		ControlPlaneAddr: addr,
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         pool,
		ServerName:       testCPTLSName,
	})
	if err := s.Seed(context.Background()); err != nil {
		t.Fatalf("the seeder must verify a DNS-only leaf by the control plane's TLS name: %v", err)
	}

	// Same pool, no expected name: the leaf does not name 127.0.0.1 and
	// the upload must fail TLS verification rather than proceed.
	s = NewSeeder(SeederParams{
		ControlPlaneAddr: addr,
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         pool,
	})
	err := s.Seed(context.Background())
	if err == nil {
		t.Fatal("expected TLS verification to fail without the expected server name")
	}
	if !strings.Contains(err.Error(), "IP SANs") {
		t.Errorf("expected the IP-SAN verification failure, got %v", err)
	}
}
