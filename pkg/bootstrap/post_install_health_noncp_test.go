package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gatewayTemplate declares the two listeners a gateway serves: the public one
// on 443, whose certificate a public ACME directory issues, and the internal
// platform listener on 9443, whose certificate the control-plane CA issues.
const gatewayTemplate = `
webservices:
  - name: public
    tls-port: 443
    certificate:
      subject:
        cn: www.example.com
  - name: internal
    tls-port: 9443
    certificate:
      subject:
        cn: gw.example.test
`

// workerTemplate is the singular webservice form the compute templates use,
// naming the listener by its first DNS SAN rather than a subject CN.
const workerTemplate = `
webservice:
  tls-port: 9443
  certificate:
    sans:
      dns:
        - w1.example.test
`

// issueTestNodeLeaf issues a server leaf from ca carrying dnsName as its only
// SAN — no IP SANs, like every identity certificate a platform node serves.
func issueTestNodeLeaf(t *testing.T, ca *testCPPKI, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.caCert.Raw}, PrivateKey: key}
}

// startTestNodeServer serves /api/v1/status with 200 over TLS 1.3 on
// 127.0.0.1:0, presenting cert. Unlike startTestCPServer it leaves
// cpWebservicePort alone, so a control plane and a node can run side by side.
func startTestNodeServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// writeRoleTemplate writes body as role's template and registers it.
func writeRoleTemplate(t *testing.T, o *Orchestrator, role, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), role+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	if o.config.Templates == nil {
		o.config.Templates = map[string]string{}
	}
	o.config.Templates[role] = path
}

// newNodeHealthTestOrchestrator starts a control plane that serves the CA
// bundle of cp at its declared static IP and a node that serves nodeCert, and
// returns an orchestrator whose own health checker probes the node.
func newNodeHealthTestOrchestrator(t *testing.T, cp *testCPPKI, nodeCert tls.Certificate, ticker interface {
	New(time.Duration) (<-chan time.Time, func())
}) *Orchestrator {
	t.Helper()
	startTestCPServer(t, cp, http.StatusOK, cp.caPEM)
	return newGateTestOrchestrator(t, startTestNodeServer(t, nodeCert), ticker)
}

func TestAwaitPostInstallHealth_NonControlPlane_PassesAgainstPlatformAnchorByName(t *testing.T) {
	cases := []struct {
		name     string
		role     string
		hostname string
		template string
		tlsName  string
	}{
		{name: "gateway", role: RoleGateway, hostname: "gw1", template: gatewayTemplate, tlsName: "gw.example.test"},
		{name: "worker", role: RoleWorker, hostname: "w1", template: workerTemplate, tlsName: "w1.example.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := newTestCPPKI(t)
			// A failed first round cancels the wait, so a probe that cannot
			// verify the leaf fails at once instead of polling to the deadline.
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ticker := newHookedHealthTicker(0, cancel)
			o := newNodeHealthTestOrchestrator(t, cp, issueTestNodeLeaf(t, cp, tc.tlsName), ticker)
			writeRoleTemplate(t, o, tc.role, tc.template)
			node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: tc.hostname, Role: tc.role}}

			err := o.awaitPostInstallHealth(ctx, node, []string{"127.0.0.1"}, "")
			if err != nil {
				t.Fatalf("a %s serving a platform-issued leaf must pass the health wait, got %v", tc.role, err)
			}
			if ticker.created.Load() {
				t.Error("a node that is already serving must pass on the first probe")
			}
		})
	}
}

func TestAwaitPostInstallHealth_NonControlPlane_LeafFromAnotherCAFails(t *testing.T) {
	cp := newTestCPPKI(t)
	// The node serves a leaf minted by its own local CA, which the deployer
	// has never seen: the probe must refuse it, not fall back to anything.
	nodeCA := newTestCPPKI(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	o := newNodeHealthTestOrchestrator(t, cp, issueTestNodeLeaf(t, nodeCA, "gw.example.test"), newHookedHealthTicker(0, cancel))
	writeRoleTemplate(t, o, RoleGateway, gatewayTemplate)
	node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}}

	err := o.awaitPostInstallHealth(ctx, node, []string{"127.0.0.1"}, "")
	if err == nil {
		t.Fatal("a leaf that does not chain to the platform anchor must fail the health wait")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the wait must end on its context, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("the chain failure must be reported, got %v", err)
	}
}

func TestAwaitPostInstallHealth_NonControlPlane_NotServingFailsAtTheDeadline(t *testing.T) {
	cp := newTestCPPKI(t)
	o := newNodeHealthTestOrchestrator(t, cp, issueTestNodeLeaf(t, cp, "gw.example.test"), newFakeHealthTicker(0))
	writeRoleTemplate(t, o, RoleGateway, gatewayTemplate)
	port, err := strconv.Atoi(closedTCPPort(t))
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	o.healthChk.(*httpHealthChecker).httpsPorts = []int{port}
	o.config.Platform.HealthTimeout = 50 * time.Millisecond
	node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}}

	err = o.awaitPostInstallHealth(t.Context(), node, []string{"127.0.0.1"}, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a node that never serves must fail at the health deadline, got %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the refused dial must be reported, got %v", err)
	}
}

func TestAwaitPostInstallHealth_NonControlPlane_UnknownTLSNameIsTerminal(t *testing.T) {
	cp := newTestCPPKI(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticker := newHookedHealthTicker(0, cancel)
	o := newNodeHealthTestOrchestrator(t, cp, issueTestNodeLeaf(t, cp, "gw.example.test"), ticker)
	// A template with no 9443 listener says nothing about the name the node
	// serves; probing anyway could only verify against the dialed address.
	writeRoleTemplate(t, o, RoleGateway, "webservices:\n  - name: public\n    tls-port: 443\n")
	node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}}

	err := o.awaitPostInstallHealth(ctx, node, []string{"127.0.0.1"}, "")
	var unknown NodeTLSNameUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected NodeTLSNameUnknownError, got %T: %v", err, err)
	}
	if unknown.Hostname != "gw1" || unknown.Role != RoleGateway || unknown.TLSPort != nodeWebserviceTLSPort {
		t.Errorf("the error must name the node, role and port, got %+v", unknown)
	}
	if ticker.created.Load() {
		t.Error("an unknown TLS name is a config error: the wait must not poll")
	}
}

func TestAwaitPostInstallHealth_NonControlPlane_MissingTemplateIsTerminal(t *testing.T) {
	cp := newTestCPPKI(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	o := newNodeHealthTestOrchestrator(t, cp, issueTestNodeLeaf(t, cp, "gw.example.test"), newHookedHealthTicker(0, cancel))
	node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}}

	err := o.awaitPostInstallHealth(ctx, node, []string{"127.0.0.1"}, "")
	if !errors.As(err, &NodeTLSNameUnknownError{}) {
		t.Fatalf("expected NodeTLSNameUnknownError, got %T: %v", err, err)
	}
	if !errors.As(err, &ErrTemplateNotFoundForRole{}) {
		t.Errorf("the missing template must be the cause, got %v", err)
	}
}

func TestWaitForHealthAny_TimeoutReportsEveryCandidate(t *testing.T) {
	cp := newTestCPPKI(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	o := newNodeHealthTestOrchestrator(t, cp, issueTestNodeLeaf(t, newTestCPPKI(t), "gw.example.test"), newHookedHealthTicker(0, cancel))
	writeRoleTemplate(t, o, RoleGateway, gatewayTemplate)
	node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway}}

	// 127.0.0.1 answers with a leaf from the wrong CA; nothing listens on
	// 127.0.0.2, the stale address probed last. The refused dial must not
	// hide the TLS failure on the address that was actually reachable.
	err := o.awaitPostInstallHealth(ctx, node, []string{"127.0.0.1", "127.0.0.2"}, "")
	if err == nil {
		t.Fatal("expected the wait to fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "health check failed for 127.0.0.1") || !strings.Contains(msg, "unknown authority") {
		t.Errorf("the reachable candidate's TLS failure must be reported, got %v", err)
	}
	if !strings.Contains(msg, "health check failed for 127.0.0.2") {
		t.Errorf("the stale candidate's failure must be reported as well, got %v", err)
	}
	var failures HealthProbeFailures
	if !errors.As(err, &failures) || len(failures) != 2 {
		t.Fatalf("expected one failure per candidate, got %v", err)
	}
}

func TestHTTPHealthChecker_RefusedPortDoesNotHideTLSFailure(t *testing.T) {
	cp := newTestCPPKI(t)
	o := newNodeHealthTestOrchestrator(t, cp, issueTestNodeLeaf(t, newTestCPPKI(t), "gw.example.test"), newFakeHealthTicker(0))
	hc := o.healthChk.(*httpHealthChecker)
	closed, err := strconv.Atoi(closedTCPPort(t))
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	// The serving port is probed first and fails verification; the closed
	// port probed after it must not replace that failure.
	hc.httpsPorts = append(hc.httpsPorts, closed)
	pool := x509.NewCertPool()
	pool.AddCert(cp.caCert)
	hc.WithCAPool(pool)

	err = hc.CheckServerName(t.Context(), "127.0.0.1", "gw.example.test")
	if err == nil {
		t.Fatal("expected the probe to fail")
	}
	if !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("the TLS failure on the reachable port must be reported, got %v", err)
	}
}

func TestHTTPHealthChecker_AllPortsRefusedReportsTheDial(t *testing.T) {
	o := newGateTestOrchestrator(t, nil, newFakeHealthTicker(0))
	hc := o.healthChk.(*httpHealthChecker)
	closed, err := strconv.Atoi(closedTCPPort(t))
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	hc.httpsPorts = []int{closed}

	err = hc.Check(t.Context(), "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("with nothing reachable the dial failure is the report, got %v", err)
	}
}

func TestProvisionRemainingNodes_EveryNodeFinishesAndEveryFailureIsReported(t *testing.T) {
	o := newTrustTestOrchestrator()
	o.discovered = append(o.discovered,
		DiscoveredNode{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway, BootMethod: "floppy"}},
		DiscoveredNode{NodeConfig: NodeConfig{Hostname: "w1", Role: RoleWorker, BootMethod: "floppy"}},
		DiscoveredNode{NodeConfig: NodeConfig{Hostname: "w2", Role: RoleWorker, SkipInstall: true}},
	)
	result := &BootstrapResult{}
	o.populateNodeResults(result)

	err := o.provisionRemainingNodes(t.Context(), result)
	var failed ErrNodesProvisionFailed
	if !errors.As(err, &failed) || len(failed.Failures) != 2 {
		t.Fatalf("expected both node failures, got %T: %v", err, err)
	}
	for _, hostname := range []string{"gw1", "w1"} {
		if !strings.Contains(err.Error(), hostname) {
			t.Errorf("the failure of %s must be reported, got %v", hostname, err)
		}
	}
	status := map[string]string{}
	for _, n := range result.Nodes {
		status[n.Hostname] = n.Status
	}
	if status["gw1"] != nodeStatusFailed || status["w1"] != nodeStatusFailed || status["w2"] != nodeStatusSkipped {
		t.Errorf("every node's outcome must be recorded before the phase returns, got %v", status)
	}
}

func TestProvisionRemainingNodes_SingleFailureIsReturnedAsIs(t *testing.T) {
	o := newTrustTestOrchestrator()
	o.discovered = append(o.discovered,
		DiscoveredNode{NodeConfig: NodeConfig{Hostname: "gw1", Role: RoleGateway, BootMethod: "floppy"}},
		DiscoveredNode{NodeConfig: NodeConfig{Hostname: "w2", Role: RoleWorker, SkipInstall: true}},
	)

	err := o.provisionRemainingNodes(t.Context(), &BootstrapResult{})
	var nodeErr ErrNodeProvisionFailed
	if !errors.As(err, &nodeErr) || nodeErr.Hostname != "gw1" {
		t.Fatalf("expected gw1's ErrNodeProvisionFailed, got %T: %v", err, err)
	}
	if errors.As(err, &ErrNodesProvisionFailed{}) {
		t.Errorf("one failure needs no aggregate, got %v", err)
	}
}

func TestErrNodesProvisionFailed_ErrorAndUnwrap(t *testing.T) {
	first := ErrNodeProvisionFailed{Hostname: "gw1", Role: RoleGateway, Cause: context.Canceled}
	second := ErrNodeProvisionFailed{Hostname: "w1", Role: RoleWorker, Cause: context.DeadlineExceeded}
	err := ErrNodesProvisionFailed{Failures: []error{first, second}}
	if !strings.Contains(err.Error(), "2 nodes failed") || !strings.Contains(err.Error(), "gw1") || !strings.Contains(err.Error(), "w1") {
		t.Errorf("unexpected message %q", err.Error())
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Error("every node failure must be reachable through Unwrap")
	}
}

func TestHealthProbeFailures_ErrorAndUnwrap(t *testing.T) {
	failures := HealthProbeFailures{
		ErrHealthCheckFailed{Address: "10.0.0.1", Cause: context.Canceled},
		ErrHealthCheckFailed{Address: "10.0.0.2"},
	}
	want := "bootstrap: health check failed for 10.0.0.1: context canceled; bootstrap: health check failed for 10.0.0.2"
	if failures.Error() != want {
		t.Errorf("Error() = %q, want %q", failures.Error(), want)
	}
	if !errors.Is(failures, context.Canceled) {
		t.Error("each candidate's failure must be reachable through Unwrap")
	}
	assertNoNilChildren(t, failures.Unwrap(), 2)
}

func TestNodeTLSNameUnknownError_ErrorAndUnwrap(t *testing.T) {
	err := NodeTLSNameUnknownError{Hostname: "gw1", Role: RoleGateway, TLSPort: 9443, Cause: context.Canceled}
	if !strings.Contains(err.Error(), "gw1") || !strings.Contains(err.Error(), "9443") || !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("unexpected message %q", err.Error())
	}
	if !errors.Is(err, context.Canceled) {
		t.Error("the cause must be reachable")
	}
	bare := NodeTLSNameUnknownError{Hostname: "gw1", Role: RoleGateway, TLSPort: 9443}
	if strings.Contains(bare.Error(), "<nil>") || bare.Unwrap() != nil {
		t.Errorf("a causeless error must not render or unwrap a nil cause: %q", bare.Error())
	}
}
