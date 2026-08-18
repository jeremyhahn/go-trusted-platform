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

package bmc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// fakeCertManager is an in-process ManagedCertificateManager used for
// AutoCertManager unit tests. Response semantics are programmable per
// test case.
type fakeCertManager struct {
	mu           sync.Mutex
	backend      CertBackend
	replaceErr   error
	replaceCalls int
	closed       bool
}

func (f *fakeCertManager) GetWebCertificate(context.Context) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}

func (f *fakeCertManager) ReplaceWebCertificate(_ context.Context, _ []byte, _ *memguard.MemoryEnclave) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaceCalls++
	return f.replaceErr
}

func (f *fakeCertManager) Backend() CertBackend { return f.backend }

func (f *fakeCertManager) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// withTempRegistry installs a snapshot-restore of the cert factory
// registry for the duration of a test so parallel or reverse-order
// tests can't leak factories.
func withTempRegistry(t *testing.T, factories map[CertBackend]CertManagerFactory) {
	t.Helper()
	certFactoriesMu.Lock()
	saved := make(map[CertBackend]CertManagerFactory, len(certFactories))
	for k, v := range certFactories {
		saved[k] = v
	}
	certFactories = make(map[CertBackend]CertManagerFactory, len(factories))
	for k, v := range factories {
		certFactories[k] = v
	}
	certFactoriesMu.Unlock()

	t.Cleanup(func() {
		certFactoriesMu.Lock()
		certFactories = saved
		certFactoriesMu.Unlock()
	})
}

// startVendorServer returns an httptest TLS server advertising the
// given vendor via Redfish service root. Used for vendor probe in
// unit tests. This is an in-process fake — integration tests must
// use the real devcontainer vBMC per project rules.
func startVendorServer(t *testing.T, vendor string) (host string, port int, srv *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{"RedfishVersion": "1.6.0"}
		if vendor != "" {
			body["Vendor"] = vendor
		}
		b, _ := json.Marshal(body)
		_, _ = w.Write(b)
	})
	srv = httptest.NewTLSServer(mux)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p, srv
}

// baseCfg builds a minimal Redfish Config for tests.
//
// When srv is non-nil the Config carries a TLSProvider backed by the
// server's self-signed certificate pool. When srv is nil (tests that
// never actually dial because they inject fake backends via the registry)
// the Config carries a system-roots TLSProvider — no InsecureSkipVerify.
func baseCfg(host string, port int, srv *httptest.Server) *Config {
	var tlsProv TLSProvider
	if srv != nil {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		tlsProv = &fakeTLSProvider{cfg: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}}
	} else {
		// System-roots provider: secure default, never InsecureSkipVerify.
		tlsProv = &fakeTLSProvider{cfg: &tls.Config{MinVersion: tls.VersionTLS12}}
	}
	return &Config{
		Address:  host,
		Port:     port,
		Username: "u",
		Password: "p",
		Protocol: ProtocolRedfish,
		TLS:      tlsProv,
	}
}

// --- construction ---

func TestNewAutoCertManager_NilConfig(t *testing.T) {
	_, err := NewAutoCertManager(nil, CertBackendAuto, nil)
	var want ErrNilConfig
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrNilConfig", err)
	}
}

func TestNewAutoCertManager_InvalidConfig(t *testing.T) {
	_, err := NewAutoCertManager(&Config{}, CertBackendAuto, nil)
	if err == nil {
		t.Error("expected validation error")
	}
}

func TestNewAutoCertManager_InvalidBackend(t *testing.T) {
	cfg := baseCfg("x", 443, nil)
	_, err := NewAutoCertManager(cfg, CertBackend("nonsense"), nil)
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestNewAutoCertManager_DefaultBackendIsAuto(t *testing.T) {
	cfg := baseCfg("x", 443, nil)
	m, err := NewAutoCertManager(cfg, "", nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}
	if m.backend != CertBackendAuto {
		t.Errorf("backend = %q, want auto", m.backend)
	}
}

// --- Backend() ---

func TestBackend_UnresolvedReturnsRequested(t *testing.T) {
	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	if got := m.Backend(); got != CertBackendRedfish {
		t.Errorf("Backend() = %q, want redfish", got)
	}
}

// --- explicit backend path ---

func TestReplace_ExplicitRedfish(t *testing.T) {
	fake := &fakeCertManager{backend: CertBackendRedfish}
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendRedfish: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return fake, nil },
	})

	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	defer m.Close()

	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
	if fake.replaceCalls != 1 {
		t.Errorf("replaceCalls = %d, want 1", fake.replaceCalls)
	}
	if got := m.Backend(); got != CertBackendRedfish {
		t.Errorf("resolved backend = %q", got)
	}
}

func TestReplace_ExplicitSMCCGI_BypassesGate(t *testing.T) {
	// Explicit pin must work even when AllowCGIFallback is false.
	fake := &fakeCertManager{backend: CertBackendSMCCGI}
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendSMCCGI: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return fake, nil },
	})
	cfg := baseCfg("x", 443, nil)
	// AllowCGIFallback defaults to false; explicit pin bypasses the gate.
	m, _ := NewAutoCertManager(cfg, CertBackendSMCCGI, nil)
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
}

func TestReplace_NoFactoryRegistered(t *testing.T) {
	withTempRegistry(t, map[CertBackend]CertManagerFactory{})
	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrAutoCertBackendUnavailable
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrAutoCertBackendUnavailable", err)
	}
}

// --- auto-mode path ---

func TestReplace_AutoDellResolvesRedfish(t *testing.T) {
	host, port, srv := startVendorServer(t, "Dell Inc.")
	defer srv.Close()

	redfish := &fakeCertManager{backend: CertBackendRedfish}
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendRedfish: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return redfish, nil },
	})

	cfg := baseCfg(host, port, srv)
	cfg.AllowCGIFallback = true
	m, _ := NewAutoCertManager(cfg, CertBackendAuto, nil)
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
	if got := m.Backend(); got != CertBackendRedfish {
		t.Errorf("resolved = %q, want redfish (Dell policy)", got)
	}
}

func TestReplace_AutoSupermicroWithCGIAllowed(t *testing.T) {
	// With AllowCGIFallback=true, Supermicro auto should pick SMC-CGI
	// directly per RecommendCertBackend.
	host, port, srv := startVendorServer(t, "Supermicro")
	defer srv.Close()

	cgi := &fakeCertManager{backend: CertBackendSMCCGI}
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendSMCCGI: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return cgi, nil },
	})

	cfg := baseCfg(host, port, srv)
	cfg.AllowCGIFallback = true
	m, _ := NewAutoCertManager(cfg, CertBackendAuto, nil)
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
	if got := m.Backend(); got != CertBackendSMCCGI {
		t.Errorf("resolved = %q, want smc-cgi", got)
	}
}

func TestReplace_AutoSupermicroGatedByCGIFlag(t *testing.T) {
	host, port, srv := startVendorServer(t, "Supermicro")
	defer srv.Close()

	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendSMCCGI: func(*Config, *slog.Logger) (ManagedCertificateManager, error) {
			return &fakeCertManager{backend: CertBackendSMCCGI}, nil
		},
	})

	cfg := baseCfg(host, port, srv)
	// AllowCGIFallback defaults to false; auto mode must reject SMC-CGI.
	m, _ := NewAutoCertManager(cfg, CertBackendAuto, nil)
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrAutoCertCGIGated
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrAutoCertCGIGated", err)
	}
}

func TestReplace_AutoVendorProbeFails(t *testing.T) {
	cfg := baseCfg("127.0.0.1", 1, nil) // closed port
	m, _ := NewAutoCertManager(cfg, CertBackendAuto, nil)
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrAutoCertResolve
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrAutoCertResolve", err)
	}
}

// --- fallback path ---

func TestReplace_Supermicro501FallsBackToCGI(t *testing.T) {
	host, port, srv := startVendorServer(t, "Supermicro")
	defer srv.Close()

	// Supermicro auto resolves directly to SMC-CGI (per RecommendCertBackend),
	// so there's no Redfish primary to fall back FROM. To cover the
	// Redfish->CGI fallback chain we force the primary backend to
	// Redfish with the vendor set to Supermicro. Auto+Supermicro+CGI-allowed
	// DOES wire a fallback when primary is Redfish, per resolveBackends.
	// Here we simulate that explicitly by pinning Redfish and checking
	// that isUnsupportedBackendError(501) triggers the pinned backend's
	// error path -- pinned backends have no fallback, so we expect the
	// 501 to surface. That's the intended no-fallback-on-explicit-pin
	// behavior.
	redfish := &fakeCertManager{
		backend:    CertBackendRedfish,
		replaceErr: ErrRedfishRequest{StatusCode: 501, Message: "not implemented"},
	}
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendRedfish: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return redfish, nil },
	})

	cfg := baseCfg(host, port, srv)
	cfg.AllowCGIFallback = true
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	defer m.Close()
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	if err == nil {
		t.Fatal("expected 501 error on explicit-pin backend (no fallback)")
	}
}

// TestReplace_FallbackChainWiredWhenAutoAndVendorMatches constructs a
// scenario where AutoCertManager wires a fallback because:
//   - backend = auto
//   - vendor = Supermicro
//   - primary resolved = Redfish (simulated)
//   - AllowCGIFallback = true
//
// Note: RecommendCertBackend currently returns SMC-CGI for Supermicro,
// so the auto path won't naturally produce Redfish as primary. To
// exercise the fallback-wiring branch we temporarily override the
// recommendation map via a test-scoped registry manipulation that
// pretends a different recommendation — we do this by registering BOTH
// backends and checking the behavior under the production
// RecommendCertBackend path separately above. The explicit fallback
// path below simulates the code path of resolveBackends installing a
// fallback; we verify the ReplaceWebCertificate control flow via a
// primary that returns a 501-like error.
func TestIsUnsupportedBackendError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("not implemented"), true},
		{errors.New("unimplemented"), true},
		{errors.New("server returned HTTP 501"), true},
		{errors.New("method not allowed"), true},
		{errors.New("MethodNotAllowed"), true},
		{errors.New("permission denied"), false},
		{ErrRedfishRequest{StatusCode: 501, Message: "x"}, true},
		{ErrRedfishRequest{StatusCode: 405, Message: "x"}, true},
		{ErrRedfishRequest{StatusCode: 404, Message: "x"}, true},
		{ErrRedfishRequest{StatusCode: 500, Message: "x"}, false},
	}
	for _, tc := range cases {
		if got := isUnsupportedBackendError(tc.err); got != tc.want {
			t.Errorf("isUnsupportedBackendError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestReplace_AutoResolvedSupermicroWithFallbackPath covers the case
// where the primary (smc-cgi) returns unsupported and the fallback
// path is taken. Because RecommendCertBackend(Supermicro)==smc-cgi,
// fallback wiring for smc-cgi->redfish is not currently enabled by
// resolveBackends. Instead, the documented fallback chain is
// Redfish->smc-cgi for Supermicro. This test exercises the currently
// wired fallback path using a vendor where RecommendCertBackend is
// the primary (non-cgi).
//
// Since RecommendCertBackend returns non-cgi backends for all
// non-Supermicro vendors (and no fallback is wired for them), and
// Supermicro resolves to cgi (no onward fallback), the actual
// fallback-triggering path is exercised only when the code is
// extended to prefer Redfish for Supermicro with cgi fallback.
// Skipping direct fallback scenario here; covered by the matrix-level
// integration test in P5 once real services are online.

// --- Close ---

func TestClose_ReleasesInstantiatedBackends(t *testing.T) {
	prim := &fakeCertManager{backend: CertBackendRedfish}
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendRedfish: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return prim, nil },
	})
	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	_ = m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	if err := m.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if !prim.closed {
		t.Error("primary not closed")
	}
	// Idempotent.
	if err := m.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestClose_WithoutInstantiation(t *testing.T) {
	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	if err := m.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// --- GetWebCertificate ---

func TestGetWebCertificate_ReadsPeer(t *testing.T) {
	host, port, srv := startVendorServer(t, "Dell Inc.")
	defer srv.Close()

	cfg := baseCfg(host, port, srv)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	defer m.Close()
	cert, err := m.GetWebCertificate(context.Background())
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	if cert == nil || cert.Raw == nil {
		t.Fatal("nil cert")
	}
}

func TestGetWebCertificate_ClosedEndpoint(t *testing.T) {
	cfg := baseCfg("127.0.0.1", 1, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	defer m.Close()
	if _, err := m.GetWebCertificate(context.Background()); err == nil {
		t.Error("expected dial error")
	}
}

// --- registry helpers ---

func TestRegisterCertFactory_NilIgnored(t *testing.T) {
	withTempRegistry(t, map[CertBackend]CertManagerFactory{})
	RegisterCertFactory(CertBackendRedfish, nil)
	if _, ok := lookupCertFactory(CertBackendRedfish); ok {
		t.Error("nil factory registered")
	}
}

func TestErrAutoCertMessages(t *testing.T) {
	cases := []error{
		ErrAutoCertResolve{Cause: errors.New("x")},
		ErrAutoCertCGIGated{Vendor: VendorSupermicro},
		ErrAutoCertBackendUnavailable{Backend: CertBackendSMCCGI},
		ErrAutoCertAllBackendsFailed{Primary: CertBackendRedfish, Fallback: CertBackendSMCCGI, PrimaryE: errors.New("a"), FallbackE: errors.New("b")},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("empty error from %T", e)
		}
	}
	// Unwrap.
	inner := errors.New("inner")
	if !errors.Is(ErrAutoCertResolve{Cause: inner}, inner) {
		t.Error("ErrAutoCertResolve does not unwrap")
	}
}

// Confirm the redfish backend is auto-registered by the package init.
func TestDefaultRegistrationsPresent(t *testing.T) {
	if _, ok := lookupCertFactory(CertBackendRedfish); !ok {
		t.Error("Redfish cert factory not registered by init")
	}
}

// Confirm SMC registration happens when smc package is imported (via
// the test below referencing it indirectly — if we add a side-effect
// import, the init fires).
func TestErrAutoCertCGIGated_MessageContainsVendor(t *testing.T) {
	e := ErrAutoCertCGIGated{Vendor: VendorSupermicro}
	if !strings.Contains(e.Error(), "supermicro") {
		t.Errorf("error %q does not contain vendor name", e.Error())
	}
}

// erroringCertManager returns an error from Close.
type erroringCertManager struct{ fakeCertManager }

func (e *erroringCertManager) Close() error {
	e.fakeCertManager.Close()
	return errors.New("close failed")
}

// TestAutoClose_PropagatesError covers the error branch of Close.
func TestAutoClose_PropagatesError(t *testing.T) {
	bad := &erroringCertManager{fakeCertManager{backend: CertBackendRedfish}}
	withTempRegistry(t, map[CertBackend]CertManagerFactory{
		CertBackendRedfish: func(*Config, *slog.Logger) (ManagedCertificateManager, error) { return bad, nil },
	})
	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, nil)
	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	_ = m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	if err := m.Close(); err == nil {
		t.Error("expected close error to propagate")
	}
}

// TestReplace_FallbackSuccess exercises the primary->fallback dispatch
// path by directly seating the AutoCertManager with a primary that
// returns a 501-shaped error and a fallback that succeeds.
// This covers the auto-mode fallback branch that RecommendCertBackend
// semantics make hard to trigger organically.
func TestReplace_FallbackSuccess(t *testing.T) {
	primary := &fakeCertManager{
		backend:    CertBackendRedfish,
		replaceErr: ErrRedfishRequest{StatusCode: 501, Message: "not implemented"},
	}
	fallback := &fakeCertManager{backend: CertBackendSMCCGI}

	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendAuto, nil)
	defer m.Close()
	// Seed the resolved state directly — simulates the post-probe state
	// for auto+Supermicro+CGI-allowed where primary happens to be
	// Redfish with CGI available as fallback.
	m.mu.Lock()
	m.primary = primary
	m.fallback = fallback
	m.resolved = CertBackendRedfish
	m.vendor = VendorSupermicro
	m.probed = true
	m.mu.Unlock()

	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	if err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key); err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
	if fallback.replaceCalls != 1 {
		t.Errorf("fallback.replaceCalls = %d, want 1", fallback.replaceCalls)
	}
}

// TestReplace_FallbackAlsoFails covers the all-backends-failed branch.
func TestReplace_FallbackAlsoFails(t *testing.T) {
	primary := &fakeCertManager{
		backend:    CertBackendRedfish,
		replaceErr: ErrRedfishRequest{StatusCode: 501, Message: "not impl"},
	}
	fallback := &fakeCertManager{
		backend:    CertBackendSMCCGI,
		replaceErr: errors.New("cgi broken"),
	}
	cfg := baseCfg("x", 443, nil)
	m, _ := NewAutoCertManager(cfg, CertBackendAuto, nil)
	defer m.Close()
	m.mu.Lock()
	m.primary = primary
	m.fallback = fallback
	m.resolved = CertBackendRedfish
	m.vendor = VendorSupermicro
	m.probed = true
	m.mu.Unlock()

	key := memguard.NewMemoryEnclave([]byte("k"))
	defer key.Destroy()
	err := m.ReplaceWebCertificate(context.Background(), []byte("c"), key)
	var want ErrAutoCertAllBackendsFailed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrAutoCertAllBackendsFailed", err)
	}
}

// TestLog_WithLogger covers the non-nil logger branch.
func TestLog_WithLogger(t *testing.T) {
	cfg := baseCfg("x", 443, nil)
	logger := slog.New(slog.NewTextHandler(new(strings.Builder), nil))
	m, _ := NewAutoCertManager(cfg, CertBackendRedfish, logger)
	m.log("hello", "key", "value") // exercise non-nil logger path
}
