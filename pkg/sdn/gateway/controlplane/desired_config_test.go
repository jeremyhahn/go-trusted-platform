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

package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
)

// mutableSource is the control plane's intent, changed by the test.
type mutableSource struct {
	mu  sync.Mutex
	doc *gwstate.DesiredConfig
}

func (m *mutableSource) DesiredConfig(id string) (*gwstate.DesiredConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc := *m.doc
	doc.GatewayID = id
	return &doc, nil
}

func (m *mutableSource) set(doc *gwstate.DesiredConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.doc = doc
}

// controlPlaneTLS is a CA with a server certificate for the control plane
// on loopback and a client certificate whose Common Name is the gateway's
// identity — the shape the control plane binds telemetry and desired
// config to.
type controlPlaneTLS struct {
	server tls.Certificate
	client tls.Certificate
	pool   *x509.CertPool
}

func newControlPlaneTLS(t *testing.T, gatewayID string) controlPlaneTLS {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "desired-config-test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, ips []net.IP) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: ips, DNSNames: []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return controlPlaneTLS{
		server: issue(2, "cp.test", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}),
		client: issue(3, gatewayID, x509.ExtKeyUsageClientAuth, nil),
		pool:   pool,
	}
}

type snapshotOf struct{ gw *gateway.Gateway }

func (s snapshotOf) Collect(context.Context) (*gwstate.Snapshot, error) { return s.gw.Snapshot(), nil }

// watchedStore signals every snapshot the control plane stores, so a test
// waits for the report it expects rather than for a wall-clock deadline. A
// deadline fails a run whose runner stalls the loops for longer than the
// deadline, though nothing is wrong with the loops.
type watchedStore struct {
	gwstate.Store
	stored chan struct{}
}

func newWatchedStore(store gwstate.Store) *watchedStore {
	return &watchedStore{Store: store, stored: make(chan struct{}, 1)}
}

func (s *watchedStore) Put(snap *gwstate.Snapshot) error {
	if err := s.Store.Put(snap); err != nil {
		return err
	}
	select {
	case s.stored <- struct{}{}:
	default:
		// A signal is already pending, and the waiter reads the latest
		// snapshot when it takes it.
	}
	return nil
}

// waitFor returns the stored snapshot of gatewayID once one satisfies pred.
// It wakes on each store, and only ctx ending stops it early; it then
// returns the last snapshot it read with the context's error.
func (s *watchedStore) waitFor(ctx context.Context, gatewayID string, pred func(*gwstate.Snapshot) bool) (*gwstate.Snapshot, error) {
	for {
		snap, err := s.Get(gatewayID)
		if err == nil && pred(snap) {
			return snap, nil
		}
		select {
		case <-s.stored:
		case <-ctx.Done():
			return snap, ctx.Err()
		}
	}
}

func TestWatchedStoreWaitsForTheMatchingReport(t *testing.T) {
	const gatewayID = "gw-watched"
	files, err := gwstate.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newWatchedStore(files)
	isRev2 := func(s *gwstate.Snapshot) bool { return s.DesiredConfig.Version == "rev-2" }

	type result struct {
		snap *gwstate.Snapshot
		err  error
	}
	waited := make(chan result, 1)
	go func() {
		snap, err := store.waitFor(t.Context(), gatewayID, isRev2)
		waited <- result{snap, err}
	}()

	// The waiter is woken by the rev-1 report, which does not satisfy it,
	// and returns only on the rev-2 report however late that arrives.
	for _, version := range []string{"rev-1", "rev-2"} {
		snap := &gwstate.Snapshot{GatewayID: gatewayID}
		snap.DesiredConfig.Version = version
		if err := store.Put(snap); err != nil {
			t.Fatalf("Put %s: %v", version, err)
		}
	}
	got := <-waited
	if got.err != nil || got.snap.DesiredConfig.Version != "rev-2" {
		t.Fatalf("waitFor = %+v, %v; want the rev-2 report", got.snap, got.err)
	}
}

func TestWatchedStoreWaitEndsWithItsContext(t *testing.T) {
	const gatewayID = "gw-watched"
	files, err := gwstate.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newWatchedStore(files)
	snap := &gwstate.Snapshot{GatewayID: gatewayID}
	snap.DesiredConfig.Version = "rev-1"
	if err := store.Put(snap); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	last, err := store.waitFor(ctx, gatewayID, func(s *gwstate.Snapshot) bool { return s.DesiredConfig.Version == "rev-2" })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitFor error = %v, want context.Canceled", err)
	}
	if last == nil || last.DesiredConfig.Version != "rev-1" {
		t.Fatalf("waitFor should return the last snapshot it read, got %+v", last)
	}
}

// observeBound caps one convergence wait in TestDesiredConfigReachesTheGateway.
// It is thousands of the loops' 20ms intervals, so a runner that stalls the
// telemetry path does not fail a correct run, yet a regression that never
// converges fails with the last stored snapshot and runs the test's cleanup
// instead of hanging until the test binary's own timeout.
const observeBound = 2 * time.Minute

// TestDesiredConfigReachesTheGateway drives the real control loop end to
// end (#555): the platform's control-plane router serves a typed desired
// config over mTLS on loopback, the gateway's reporter fetches it, the
// reconciler applies it through a real gateway node, and the gateway's
// telemetry snapshot — posted back over the same mTLS session and stored by
// the control plane — reports the version it converged on. A second
// document carrying a section this gateway does not run is observed as a
// typed apply failure on the control plane, with the previous version
// retained.
func TestDesiredConfigReachesTheGateway(t *testing.T) {
	const gatewayID = "gw-desired-config"
	const loopInterval = 20 * time.Millisecond
	tlsFix := newControlPlaneTLS(t, gatewayID)
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	files, err := gwstate.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newWatchedStore(files)
	source := &mutableSource{doc: &gwstate.DesiredConfig{Version: "rev-1"}}
	cp := restgateway.NewControlPlane(logger, store, source, response.NewResponseWriter(logger, nil))
	router := mux.NewRouter()
	cp.RegisterGatewayFacingRoutes(router.PathPrefix("/api/v1").Subrouter())

	srv := httptest.NewUnstartedServer(router)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsFix.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    tlsFix.pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	gw, err := gateway.NewGateway(&gateway.GatewayConfig{
		Enabled: true, ID: gatewayID,
		MinReputation: gateway.MinReputation, MinAgeDays: gateway.MinAgeDays, MinUptimePct: gateway.MinUptimePct,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	gw.SetNodeMetrics(0.95, time.Duration(gateway.MinAgeDays+30)*24*time.Hour, 99.0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("gateway Start: %v", err)
	}
	defer gw.Stop(context.Background())

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{tlsFix.client}, RootCAs: tlsFix.pool, MinVersion: tls.VersionTLS12,
	}}}
	reporter, err := NewReporter(ReporterConfig{
		CPBaseURL: srv.URL, GatewayID: gatewayID, Interval: loopInterval,
		HTTPClient: client, Collector: snapshotOf{gw},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	reconciler, err := NewReconciler(ReconcilerConfig{
		Fetcher: reporter, Applier: gw, Interval: loopInterval,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	var loops sync.WaitGroup
	loops.Add(2)
	go func() { defer loops.Done(); _ = reporter.Start(ctx) }()
	go func() { defer loops.Done(); _ = reconciler.Start(ctx) }()
	defer loops.Wait()
	defer cancel()

	observed := func(pred func(*gwstate.Snapshot) bool) *gwstate.Snapshot {
		t.Helper()
		waitCtx, stop := context.WithTimeout(ctx, observeBound)
		defer stop()
		snap, err := store.waitFor(waitCtx, gatewayID, pred)
		if err != nil {
			t.Fatalf("the control plane never observed the expected state: %v; last snapshot: %+v", err, snap)
		}
		return snap
	}

	first := observed(func(s *gwstate.Snapshot) bool { return s.DesiredConfig.Version == "rev-1" })
	if first.DesiredConfig.LastError != "" || first.DesiredConfig.AppliedAt.IsZero() {
		t.Fatalf("rev-1 should have applied cleanly: %+v", first.DesiredConfig)
	}

	// A change on the control plane the gateway cannot apply — a load
	// balancer section on a node with no load balancer — is observed as
	// a typed failure, and the last good version is retained.
	source.set(&gwstate.DesiredConfig{
		Version: "rev-2",
		LoadBalancer: &gwstate.DesiredLoadBalancer{VIPs: []gwstate.DesiredVIP{{
			Address: "10.0.200.10", Port: 443, Protocol: "tcp",
			Backends: []gwstate.DesiredBackend{{Address: "10.0.100.11", Port: 8443}},
		}}},
	})
	second := observed(func(s *gwstate.Snapshot) bool { return s.DesiredConfig.LastError != "" })
	if second.DesiredConfig.Version != "rev-1" {
		t.Fatalf("a failed apply must not advance the version: %+v", second.DesiredConfig)
	}
	if want := gwstate.SectionLoadBalancer; !strings.Contains(second.DesiredConfig.LastError, want) {
		t.Fatalf("LastError should name the failing section %q: %q", want, second.DesiredConfig.LastError)
	}

	// Withdrawing the section converges again on a new version.
	source.set(&gwstate.DesiredConfig{Version: "rev-3"})
	third := observed(func(s *gwstate.Snapshot) bool { return s.DesiredConfig.Version == "rev-3" })
	if third.DesiredConfig.LastError != "" {
		t.Fatalf("rev-3 should have applied cleanly: %+v", third.DesiredConfig)
	}
}
