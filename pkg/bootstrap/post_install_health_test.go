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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// hookedHealthTicker is a pollTicker seam whose New runs onNew before
// handing out the queued ticks. A test uses onNew to act exactly at the
// moment a wait falls through to its ticker — cancel the context, or
// bring the server "up" — instead of racing a real clock.
type hookedHealthTicker struct {
	fakeHealthTicker
	onNew func()
}

func newHookedHealthTicker(queued int, onNew func()) *hookedHealthTicker {
	return &hookedHealthTicker{fakeHealthTicker: *newFakeHealthTicker(queued), onNew: onNew}
}

func (h *hookedHealthTicker) New(d time.Duration) (<-chan time.Time, func()) {
	if h.onNew != nil {
		h.onNew()
	}
	return h.fakeHealthTicker.New(d)
}

// closedTCPPort returns a loopback port that nothing listens on, so a
// dial to it is refused immediately — the shape of "the node is still
// booting" without waiting on a real boot.
func closedTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// newGateTestOrchestrator builds the trust-test orchestrator with the
// production httpHealthChecker (system pool, no pxeboot URL) pointed at
// the test server's ephemeral port, plus the given ticker seam.
func newGateTestOrchestrator(t *testing.T, srv *httptest.Server, ticker interface {
	New(time.Duration) (<-chan time.Time, func())
}) *Orchestrator {
	t.Helper()
	o := newTrustTestOrchestrator()
	hc := newHTTPHealthChecker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, o.config.HealthProbePorts())
	if srv != nil {
		pointControlPlaneAt(t, o, srv)
		hc.httpsPorts = []int{serverPort(t, srv)}
	}
	o.healthChk = hc
	o.pollTicker = ticker.New
	return o
}

func TestAwaitPostInstallHealth_ControlPlane_PassesAgainstSelfProvisionedCA(t *testing.T) {
	pki := newTestCPPKI(t)
	// Every path answers 200 with the bundle: /api/v1/acme/ca-bundle for
	// the capture and /api/v1/status for the probe.
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	ticker := newFakeHealthTicker(0)
	o := newGateTestOrchestrator(t, srv, ticker)

	err := o.awaitPostInstallHealth(t.Context(), &o.discovered[0], []string{"127.0.0.1"}, "")
	if err != nil {
		t.Fatalf("gate must pass once the CA bundle is captured before probing, got %v", err)
	}
	if o.cpCAPool == nil {
		t.Fatal("cpCAPool must be captured by the gate")
	}
	if ticker.created.Load() {
		t.Error("a control plane that is already serving must pass on the first capture and first probe")
	}
}

func TestAwaitPostInstallHealth_Worker_CapturesAnchor_NameMismatchFails(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// The worker's probe captures the platform anchor, so the leaf chains;
	// but the leaf names the control plane, not the worker's declared
	// listener, so verification still fails. The ticker hook ends the wait
	// right after that first failed probe.
	ticker := newHookedHealthTicker(0, cancel)
	o := newGateTestOrchestrator(t, srv, ticker)
	writeRoleTemplate(t, o, RoleWorker, workerTemplate)
	worker := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "w1", Role: RoleWorker}}

	err := o.awaitPostInstallHealth(ctx, worker, []string{"127.0.0.1"}, "")
	if err == nil {
		t.Fatal("a leaf issued for another name must fail verification")
	}
	if o.cachedControlPlaneCAPool() == nil {
		t.Error("a worker's health wait must capture the platform anchor it verifies against")
	}
	var hcErr ErrHealthCheckFailed
	if !errors.As(err, &hcErr) {
		t.Fatalf("expected ErrHealthCheckFailed, got %T: %v", err, err)
	}
	var timeout HealthWaitTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("expected HealthWaitTimeoutError in the chain, got %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the context error must remain reachable, got %v", err)
	}
	if !strings.Contains(err.Error(), "not w1.example.test") {
		t.Errorf("the name mismatch must be reported, not just the context error: %v", err)
	}
}

func TestAwaitPostInstallHealth_ControlPlane_MismatchedBundleFailsFast(t *testing.T) {
	serving := newTestCPPKI(t)
	other := newTestCPPKI(t)
	srv := startTestCPServer(t, serving, http.StatusOK, other.caPEM)
	ticker := newFakeHealthTicker(0)
	o := newGateTestOrchestrator(t, srv, ticker)

	err := o.awaitPostInstallHealth(t.Context(), &o.discovered[0], []string{"127.0.0.1"}, "")
	var verifyErr ErrCABundleVerifyFailed
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected ErrCABundleVerifyFailed, got %T: %v", err, err)
	}
	var hcErr ErrHealthCheckFailed
	if !errors.As(err, &hcErr) {
		t.Fatalf("expected the cause wrapped in ErrHealthCheckFailed, got %v", err)
	}
	if o.cpCAPool != nil {
		t.Error("a bundle that fails capture-then-verify must never be stored")
	}
	if ticker.created.Load() {
		t.Error("a rejected bundle is terminal: the gate must not retry it")
	}
}

func TestAwaitPostInstallHealth_ControlPlane_RetriesUntilTheNodeIsUp(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	livePort := serverPort(t, srv)
	// First capture attempt dials a port nothing listens on (connection
	// refused = still booting); the ticker hook then "boots" the node by
	// pointing the CP port back at the live server before the tick.
	var o *Orchestrator
	ticker := newHookedHealthTicker(1, func() { o.config.Platform.ControlPlanePort = livePort })
	o = newGateTestOrchestrator(t, srv, ticker)
	o.config.Platform.ControlPlanePort = closedTCPPort(t)

	err := o.awaitPostInstallHealth(t.Context(), &o.discovered[0], []string{"127.0.0.1"}, "")
	if err != nil {
		t.Fatalf("a refused connection must be retried, not reported: %v", err)
	}
	if !ticker.created.Load() {
		t.Error("the first refused capture must fall through to the ticker")
	}
	if o.cpCAPool == nil {
		t.Fatal("cpCAPool must be captured once the node answers")
	}
}

func TestAwaitPostInstallHealth_ControlPlane_DeadlineReportsLastCaptureError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticker := newHookedHealthTicker(0, cancel)
	o := newGateTestOrchestrator(t, nil, ticker)
	o.config.Platform.ControlPlanePort = closedTCPPort(t)

	err := o.awaitPostInstallHealth(ctx, &o.discovered[0], []string{"127.0.0.1"}, "")
	var unavailable CABundleUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected CABundleUnavailableError, got %T: %v", err, err)
	}
	if unavailable.Attempts != 1 {
		t.Errorf("expected exactly one capture attempt before cancellation, got %d", unavailable.Attempts)
	}
	// Every candidate address is tried per attempt (the static IP is
	// refused, the hostname does not resolve); whichever failed last is
	// what the operator must see, and it names the bundle endpoint.
	if unavailable.LastErr == nil || !strings.Contains(unavailable.LastErr.Error(), "/api/v1/acme/ca-bundle") {
		t.Errorf("the last capture error must be carried, got %v", unavailable.LastErr)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the context error must remain reachable, got %v", err)
	}
	if !strings.Contains(err.Error(), "/api/v1/acme/ca-bundle") {
		t.Errorf("the operator-facing message must name the last capture error: %v", err)
	}
}

func TestAwaitPostInstallHealth_ControlPlane_CachedPoolIsPropagatedWithoutFetch(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	ticker := newFakeHealthTicker(0)
	o := newGateTestOrchestrator(t, srv, ticker)
	// Prime the cache directly, bypassing the fetch and therefore its
	// propagateCAPool: the checker still holds the system pool, so the
	// probe can only pass if the gate propagates the cached pool itself.
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	o.storeControlPlaneCAPool(pool)
	// Point the bundle endpoint at a dead port: a capture would fail, so
	// passing also proves the cached pool was reused.
	o.config.Platform.ControlPlanePort = closedTCPPort(t)

	if err := o.awaitPostInstallHealth(t.Context(), &o.discovered[0], []string{"127.0.0.1"}, ""); err != nil {
		t.Fatalf("a cached pool must be propagated without refetching: %v", err)
	}
}

func TestAwaitPostInstallHealth_ControlPlane_CaptureAloneIsNotHealth(t *testing.T) {
	pki := newTestCPPKI(t)
	// The CA endpoint answers, so capture-then-verify succeeds, but the
	// daemon is not serving: the probe must still be required to pass.
	srv := startTestCPServerHandler(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/acme/ca-bundle" {
			if _, err := w.Write(pki.caPEM); err != nil {
				t.Errorf("write bundle: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ticker := newHookedHealthTicker(0, cancel)
	o := newGateTestOrchestrator(t, srv, ticker)

	err := o.awaitPostInstallHealth(ctx, &o.discovered[0], []string{"127.0.0.1"}, "")
	if err == nil {
		t.Fatal("a captured bundle must not count as a healthy daemon")
	}
	if o.cpCAPool == nil {
		t.Error("the bundle must have been captured before the probe ran")
	}
	var timeout HealthWaitTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("expected HealthWaitTimeoutError from the probe, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("the probe's HTTP status must be reported: %v", err)
	}
}

func TestAwaitControlPlaneCAPool_QueuedWaiterHonorsContextAndDoesNotFetch(t *testing.T) {
	pki := newTestCPPKI(t)
	var bundleFetches atomic.Int64
	srv := startTestCPServerHandler(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/acme/ca-bundle" {
			bundleFetches.Add(1)
		}
		if _, err := w.Write(pki.caPEM); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	o := newGateTestOrchestrator(t, srv, newFakeHealthTicker(0))
	// Hold the capture gate as a concurrent waiter would while its fetch
	// is in flight. The waiter under test must neither fetch around the
	// holder nor sit in the queue past its own deadline.
	release, err := o.acquireCAFetchGate(t.Context())
	if err != nil {
		t.Fatalf("acquire gate: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- o.awaitControlPlaneCAPool(ctx, "cp-02") }()
	cancel()
	waitErr := <-done
	release()

	var unavailable CABundleUnavailableError
	if !errors.As(waitErr, &unavailable) {
		t.Fatalf("expected CABundleUnavailableError from the queued waiter, got %T: %v", waitErr, waitErr)
	}
	if !errors.Is(waitErr, context.Canceled) {
		t.Errorf("the queued waiter's own context must end the wait, got %v", waitErr)
	}
	if got := bundleFetches.Load(); got != 0 {
		t.Errorf("a waiter must not fetch while another holds the gate, got %d fetches", got)
	}
	if o.cachedControlPlaneCAPool() != nil {
		t.Error("no pool may be stored by a waiter that never fetched")
	}
}

func TestAwaitControlPlaneCAPool_QueuedWaiterUsesPoolStoredByHolder(t *testing.T) {
	pki := newTestCPPKI(t)
	var bundleFetches atomic.Int64
	srv := startTestCPServerHandler(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/acme/ca-bundle" {
			bundleFetches.Add(1)
		}
		if _, err := w.Write(pki.caPEM); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	o := newGateTestOrchestrator(t, srv, newFakeHealthTicker(0))
	release, err := o.acquireCAFetchGate(t.Context())
	if err != nil {
		t.Fatalf("acquire gate: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- o.awaitControlPlaneCAPool(t.Context(), "cp-02") }()
	// The holder "finishes its fetch": store the pool, then release. The
	// queued waiter must find it cached and make no request of its own.
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	o.storeControlPlaneCAPool(pool)
	release()

	if waitErr := <-done; waitErr != nil {
		t.Fatalf("queued waiter must succeed on the holder's pool: %v", waitErr)
	}
	if got := bundleFetches.Load(); got != 0 {
		t.Errorf("a waiter that finds the pool cached must not fetch, got %d fetches", got)
	}
}

// The concurrent run below is a race-detector exercise over the shared
// pool and health-checker swap; the two gate tests above are what pin the
// serialization deterministically.
func TestAwaitPostInstallHealth_ConcurrentControlPlanes_CaptureOnce(t *testing.T) {
	pki := newTestCPPKI(t)
	var bundleFetches atomic.Int64
	srv := startTestCPServerHandler(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/acme/ca-bundle" {
			bundleFetches.Add(1)
		}
		if _, err := w.Write(pki.caPEM); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	ticker := newFakeHealthTicker(0)
	o := newGateTestOrchestrator(t, srv, ticker)
	// A second control-plane node sharing the first's static IP is
	// enough to exercise two concurrent waits over the same pool.
	o.discovered = append(o.discovered, o.discovered[0])
	o.discovered[1].Hostname = "cp-02"

	const waiters = 2
	errs := make(chan error, waiters)
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(node *DiscoveredNode) {
			defer wg.Done()
			errs <- o.awaitPostInstallHealth(t.Context(), node, []string{"127.0.0.1"}, "")
		}(&o.discovered[i])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent control-plane wait failed: %v", err)
		}
	}
	if got := bundleFetches.Load(); got != 1 {
		t.Errorf("expected exactly one bundle capture across concurrent waiters, got %d", got)
	}
	if o.cachedControlPlaneCAPool() == nil {
		t.Fatal("cpCAPool must be captured")
	}
}

func TestAwaitPostInstallHealth_InjectedCheckerOwnsItsTrust(t *testing.T) {
	// No server, no static-IP reachable; an injected checker reports
	// healthy on its own terms and the gate must not try to capture a
	// bundle on its behalf.
	o := newTrustTestOrchestrator()
	o.healthChk = &mockHealthChecker{}
	o.pollTicker = newFakeHealthTicker(0).New

	if err := o.awaitPostInstallHealth(t.Context(), &o.discovered[0], []string{"127.0.0.1"}, ""); err != nil {
		t.Fatalf("expected the injected checker's verdict, got %v", err)
	}
	if o.cpCAPool != nil {
		t.Error("no bundle must be captured for an injected checker")
	}
}

func TestAwaitControlPlaneCAPool_NoStaticIPIsTerminal(t *testing.T) {
	o := newTrustTestOrchestrator()
	// A hostname and a registration IP are not substitutes: the trust
	// anchor comes from the declared static address or not at all.
	o.discovered[0].Interfaces = nil
	o.discovered[0].MACs = []string{"aa:bb:cc:dd:ee:01"}
	o.config.Deployer = registrationSink(t, &o.discovered[0], "127.0.0.1")
	o.healthChk = newHTTPHealthChecker(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, o.config.HealthProbePorts())
	ticker := newFakeHealthTicker(0)
	o.pollTicker = ticker.New

	err := o.awaitControlPlaneCAPool(t.Context(), "cp-01")
	var noAddr ControlPlaneStaticIPRequiredError
	if !errors.As(err, &noAddr) {
		t.Fatalf("expected ControlPlaneStaticIPRequiredError, got %T: %v", err, err)
	}
	if ticker.created.Load() {
		t.Error("a missing static IP cannot be cured by waiting; the gate must not retry")
	}
}

func TestAwaitControlPlaneCAPool_UnknownTLSNameIsTerminal(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	ticker := newFakeHealthTicker(0)
	o := newGateTestOrchestrator(t, srv, ticker)
	o.config = nil

	err := o.awaitControlPlaneCAPool(t.Context(), "cp-01")
	var unknown ControlPlaneTLSNameUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected ControlPlaneTLSNameUnknownError, got %T: %v", err, err)
	}
	if ticker.created.Load() {
		t.Error("an unknown TLS name cannot be cured by waiting; the gate must not retry")
	}
}

// registrationSink serves registration.json for one node at the paths
// fetchRegistrationIP tries, reporting the given IP, and returns the
// DeployerConfig that points installLogBaseURL at it.
func registrationSink(t *testing.T, node *DiscoveredNode, ip string) DeployerConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/registration.json") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, err := w.Write([]byte(`{"hostname":"` + node.Hostname + `","ip":"` + ip + `"}`)); err != nil {
			t.Errorf("write registration: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split sink addr: %v", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse sink port: %v", err)
	}
	return DeployerConfig{Host: host, BootstrapHTTPPort: p}
}

// startRogueCPServer binds a second, attacker-controlled control plane
// on 127.0.0.2 at the same port as the genuine one, presenting a leaf
// for the same TLS name issued by its own CA and serving that CA as its
// bundle. It returns a counter of requests that completed a handshake.
func startRogueCPServer(t *testing.T, port int) (rogue *testCPPKI, hits *atomic.Int64) {
	t.Helper()
	rogue = newTestCPPKI(t)
	hits = &atomic.Int64{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if _, err := w.Write(rogue.caPEM); err != nil {
			t.Errorf("rogue write: %v", err)
		}
	}))
	if err := srv.Listener.Close(); err != nil {
		t.Fatalf("close default listener: %v", err)
	}
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("listen on 127.0.0.2:%d: %v", port, err)
	}
	srv.Listener = l
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{rogue.tlsCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return rogue, hits
}

// rogueRegistration stands up the genuine control plane on the node's
// static 127.0.0.1, a rogue one on 127.0.0.2, and a registration.json
// that points the node at the rogue.
func rogueRegistration(t *testing.T, o *Orchestrator) (genuine, rogue *testCPPKI, rogueHits *atomic.Int64) {
	t.Helper()
	genuine = newTestCPPKI(t)
	srv := startTestCPServer(t, genuine, http.StatusOK, genuine.caPEM)
	pointControlPlaneAt(t, o, srv)
	rogue, rogueHits = startRogueCPServer(t, o.config.Platform.ControlPlanePort)
	o.discovered[0].MACs = []string{"aa:bb:cc:dd:ee:01"}
	o.config.Deployer = registrationSink(t, &o.discovered[0], "127.0.0.2")
	return genuine, rogue, rogueHits
}

func TestFetchControlPlaneCABundle_NeverTrustsRegistrationForTheAnchor(t *testing.T) {
	o := newTrustTestOrchestrator()
	genuine, rogue, rogueHits := rogueRegistration(t, o)

	bundle, err := o.fetchControlPlaneCABundle(t.Context())
	if err != nil {
		t.Fatalf("capture from the declared static address must succeed: %v", err)
	}
	if bundle != string(genuine.caPEM) {
		t.Fatal("the captured bundle must be the genuine control plane's")
	}
	if rogueHits.Load() != 0 {
		t.Fatalf("the capture must never dial the registration-supplied address, rogue served %d requests", rogueHits.Load())
	}
	// The pinned pool trusts the genuine CA and nothing the rogue issued.
	pool := o.cachedControlPlaneCAPool()
	if _, err := rogue.caCert.Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("the rogue CA must not verify against the captured pool")
	}
	if _, err := genuine.caCert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("the genuine CA must verify against the captured pool: %v", err)
	}
}

func TestFetchControlPlaneCABundle_NoFallbackWhenStaticIsDown(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	o := newTrustTestOrchestrator()
	pointControlPlaneAt(t, o, srv)
	// The genuine control plane answers on 127.0.0.1 and both the
	// registration IP and the hostname would reach it; the declared
	// static address is where nothing listens. The capture must fail
	// rather than fall through to an address the config did not vouch
	// for.
	o.discovered[0].Interfaces = []installer.InterfaceConfig{{Name: "eth0", Type: installer.InterfaceTypeStatic, IPv4Address: "127.0.0.3"}}
	o.discovered[0].Hostname = "127.0.0.1"
	o.discovered[0].MACs = []string{"aa:bb:cc:dd:ee:01"}
	o.config.Deployer = registrationSink(t, &o.discovered[0], "127.0.0.1")

	_, err := o.fetchControlPlaneCABundle(t.Context())
	if err == nil {
		t.Fatal("capture must not fall back from the static address to registration or hostname")
	}
	if !strings.Contains(err.Error(), "127.0.0.3") {
		t.Errorf("the failure must be the static address's, got %v", err)
	}
	if o.cachedControlPlaneCAPool() != nil {
		t.Error("no pool may be stored")
	}
}

func TestAwaitPostInstallHealth_RedirectedRegistrationFailsVerificationAfterCapture(t *testing.T) {
	o := newGateTestOrchestrator(t, nil, newFakeHealthTicker(0))
	_, _, rogueHits := rogueRegistration(t, o)
	hc := o.healthChk.(*httpHealthChecker)
	hc.httpsPorts = []int{o.config.Platform.ControlPlanePort}

	// The gate captures from the static address, then probes the
	// registration address first: the rogue's certificate does not chain
	// to the pinned pool, so the probe fails closed and moves on.
	if err := o.awaitPostInstallHealth(t.Context(), &o.discovered[0], []string{"127.0.0.2", "127.0.0.1"}, ""); err != nil {
		t.Fatalf("gate must pass on the genuine address after the redirect fails verification: %v", err)
	}
	if rogueHits.Load() != 0 {
		t.Fatalf("no request may complete against the rogue, it served %d", rogueHits.Load())
	}
	probeErr := hc.CheckServerName(t.Context(), "127.0.0.2", testCPTLSName)
	if probeErr == nil || !strings.Contains(probeErr.Error(), "x509") {
		t.Fatalf("a probe redirected to the rogue must fail TLS verification, got %v", probeErr)
	}
}

func TestHTTPHealthChecker_ServerName_VerifiesDNSOnlyLeafByName(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	o := newGateTestOrchestrator(t, srv, newFakeHealthTicker(0))
	hc := o.healthChk.(*httpHealthChecker)
	hc.WithCAPool(pool)

	if err := hc.CheckServerName(t.Context(), "127.0.0.1", testCPTLSName); err != nil {
		t.Fatalf("a DNS-only leaf dialed by IP must verify when the expected name is given: %v", err)
	}
	err := hc.Check(t.Context(), "127.0.0.1")
	if err == nil {
		t.Fatal("the same leaf must not verify against the dialed IP")
	}
	if !strings.Contains(err.Error(), "IP SANs") {
		t.Errorf("expected the IP-SAN verification failure, got %v", err)
	}
}

func TestHTTPHealthChecker_ConcurrentNamedProbesAndPoolSwaps(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	o := newGateTestOrchestrator(t, srv, newFakeHealthTicker(0))
	hc := o.healthChk.(*httpHealthChecker)
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	hc.WithCAPool(pool)

	// Probes and pool swaps interleave freely; the race detector is the
	// assertion on the client cache, and every probe after a swap must
	// still verify because each swap installs the same trusted pool.
	const workers, rounds = 4, 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				errs <- hc.CheckServerName(t.Context(), "127.0.0.1", testCPTLSName)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				hc.WithCAPool(pool)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("named probe failed during concurrent pool swaps: %v", err)
		}
	}
}

func TestControlPlaneHealthGate_VerifiesDNSOnlyLeafByName(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	o := newGateTestOrchestrator(t, srv, newFakeHealthTicker(0))
	// The gate dials the node's candidates — here its static 127.0.0.1;
	// the hostname is deliberately unresolvable — and the test control
	// plane answers with a leaf that names only cp.example.test.
	o.discovered[0].Hostname = "cp-gate.invalid"
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	o.storeControlPlaneCAPool(pool)
	o.propagateCAPool()

	if err := o.controlPlaneHealthGate(t.Context()); err != nil {
		t.Fatalf("the gate must verify the control plane for its TLS name: %v", err)
	}

	// Without a resolvable TLS name the gate cannot verify anything and
	// says so, instead of probing by address and timing out.
	o.config = nil
	o.cpTLSNameOnce = sync.Once{}
	err := o.controlPlaneHealthGate(t.Context())
	var gateErr ErrControlPlaneHealthGateFailed
	if !errors.As(err, &gateErr) {
		t.Fatalf("expected ErrControlPlaneHealthGateFailed, got %T: %v", err, err)
	}
	if !errors.As(err, &ControlPlaneTLSNameUnknownError{}) {
		t.Errorf("the unknown TLS name must be the cause, got %v", err)
	}
}

func TestHTTPHealthChecker_WithCAPool_RebuildsNamedClients(t *testing.T) {
	pki := newTestCPPKI(t)
	srv := startTestCPServer(t, pki, http.StatusOK, pki.caPEM)
	o := newGateTestOrchestrator(t, srv, newFakeHealthTicker(0))
	hc := o.healthChk.(*httpHealthChecker)
	// A named client built before the pool arrives verifies against the
	// system pool and fails; the pool swap must not leave it cached.
	if err := hc.CheckServerName(t.Context(), "127.0.0.1", testCPTLSName); err == nil {
		t.Fatal("expected verification against the system pool to fail")
	}
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	hc.WithCAPool(pool)
	if err := hc.CheckServerName(t.Context(), "127.0.0.1", testCPTLSName); err != nil {
		t.Fatalf("named client must be rebuilt from the new pool: %v", err)
	}
}

func TestWaitForHealthAny_TimeoutCarriesLastProbeError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	o := newTrustTestOrchestrator()
	o.healthChk = &mockHealthChecker{err: errors.New("tls: bad certificate")}
	o.pollTicker = newHookedHealthTicker(0, cancel).New

	err := o.waitForHealthAny(ctx, []string{"127.0.0.1"}, "", "cp-01", nil, "")
	var timeout HealthWaitTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("expected HealthWaitTimeoutError, got %T: %v", err, err)
	}
	if timeout.LastProbe == nil || timeout.LastProbe.Error() != "tls: bad certificate" {
		t.Errorf("expected the last probe error to be carried, got %v", timeout.LastProbe)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected the context error to remain reachable, got %v", err)
	}
}

func TestWaitForHealthAny_NoAddresses(t *testing.T) {
	o := newTrustTestOrchestrator()
	o.healthChk = &mockHealthChecker{}
	if err := o.waitForHealthAny(t.Context(), nil, "", "cp-01", nil, ""); err == nil {
		t.Fatal("expected an error with no addresses and no registration URL")
	}
}

func TestCABundleUnavailableError_ErrorAndUnwrap(t *testing.T) {
	last := errors.New("dial tcp: connection refused")
	err := CABundleUnavailableError{Hostname: "cp-01", Attempts: 3, Cause: context.DeadlineExceeded, LastErr: last}
	msg := err.Error()
	for _, want := range []string{"cp-01", "3 attempts", "context deadline exceeded", "connection refused"} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected %q in %q", want, msg)
		}
	}
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, last) {
		t.Error("both the context error and the last capture error must unwrap")
	}

	bare := CABundleUnavailableError{Hostname: "cp-01", Cause: context.Canceled}
	if strings.Contains(bare.Error(), "last attempt") {
		t.Errorf("no last-attempt suffix without a LastErr: %q", bare.Error())
	}
	assertNoNilChildren(t, bare.Unwrap(), 1)
}

// assertNoNilChildren checks a multi-error Unwrap result has exactly want
// entries and none of them nil, as the errors package requires.
func assertNoNilChildren(t *testing.T, children []error, want int) {
	t.Helper()
	if len(children) != want {
		t.Fatalf("expected %d unwrapped errors, got %d", want, len(children))
	}
	for i, child := range children {
		if child == nil {
			t.Errorf("unwrapped child %d is nil", i)
		}
	}
}

func TestHealthWaitTimeoutError_ErrorAndUnwrap(t *testing.T) {
	probe := errors.New("x509: certificate signed by unknown authority")
	err := HealthWaitTimeoutError{Cause: context.DeadlineExceeded, LastProbe: probe}
	msg := err.Error()
	for _, want := range []string{"context deadline exceeded", "x509: certificate signed by unknown authority"} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected %q in %q", want, msg)
		}
	}
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, probe) {
		t.Error("both the context error and the last probe error must unwrap")
	}

	bare := HealthWaitTimeoutError{Cause: context.Canceled}
	if strings.Contains(bare.Error(), "last probe") {
		t.Errorf("no last-probe suffix without a LastProbe: %q", bare.Error())
	}
	assertNoNilChildren(t, bare.Unwrap(), 1)
}

func TestControlPlaneStaticIPRequiredError_Error(t *testing.T) {
	msg := ControlPlaneStaticIPRequiredError{Hostname: "cp-01"}.Error()
	if !strings.Contains(msg, "cp-01") || !strings.Contains(msg, "nodes[].interfaces") {
		t.Errorf("unexpected message %q", msg)
	}
}

func TestErrCABundleRequired_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("dial tcp: connection refused")
	err := ErrCABundleRequired{Operation: "template seeding", Cause: cause}
	if !strings.Contains(err.Error(), "template seeding") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("unexpected message %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Error("the cause must unwrap")
	}
	bare := ErrCABundleRequired{Operation: "SPKI pin capture"}
	if !strings.Contains(bare.Error(), "has not been fetched") {
		t.Errorf("unexpected bare message %q", bare.Error())
	}
}

func TestIsTerminalCABundleError(t *testing.T) {
	cases := map[string]struct {
		err      error
		terminal bool
	}{
		"verify failed":    {ErrCABundleVerifyFailed{URL: "u", Cause: errors.New("x")}, true},
		"invalid bundle":   {ErrCABundleInvalid{URL: "u"}, true},
		"no control plane": {ErrNoControlPlaneNode{}, true},
		"no address":       {ControlPlaneStaticIPRequiredError{Hostname: "h"}, true},
		"no tls name":      {ControlPlaneTLSNameUnknownError{}, true},
		"refused":          {errors.New("dial tcp: connection refused"), false},
		"http status":      {&MessageError{Msg: "GET u: status 503"}, false},
		"no peer certs":    {ErrNoPeerCertificates{Endpoint: "e"}, false},
	}
	for name, tc := range cases {
		if got := isTerminalCABundleError(tc.err); got != tc.terminal {
			t.Errorf("%s: terminal=%v, want %v", name, got, tc.terminal)
		}
	}
}
