package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{}, Deps{Logger: testLogger()}); !errors.Is(err, ErrNoListeners) {
		t.Fatalf("New err = %v, want ErrNoListeners", err)
	}
}

func TestNewFailClosed(t *testing.T) {
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	authed := authConfig("http://10.0.0.1:8080")
	trustPool := publicConfig("https://10.0.0.1:8443")
	trustPool.Pools[0].TLS.TrustClass = "internal"
	tests := []struct {
		name    string
		cfg     Config
		deps    Deps
		wantErr error
	}{
		{"auth chain required", authed, Deps{ServerTLS: serverTLS}, ErrAuthChainRequired},
		{"tls required for auth", authed, Deps{Auth: &fakeAuth{}}, ErrTLSRequiredForAuth},
		{"trust resolver required", trustPool, Deps{}, ErrTrustResolverRequired},
		{"public without tls allowed", publicConfig("http://10.0.0.1:8080"), Deps{}, nil},
		{"authed fully composed", authed, Deps{Auth: &fakeAuth{}, ServerTLS: serverTLS}, nil},
		{"trust class composed", trustPool, Deps{Trust: &fakeTrust{cfg: &tls.Config{MinVersion: tls.VersionTLS13}}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.deps.Logger = testLogger()
			e, err := New(tt.cfg, tt.deps)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("New err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if e == nil {
				t.Fatal("New returned nil engine")
			}
		})
	}
}

func TestNewDefaultsAuditAndLogger(t *testing.T) {
	e, err := New(publicConfig("http://10.0.0.1:8080"), Deps{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.deps.Audit == nil {
		t.Error("nil Audit not defaulted to a no-op sink")
	}
	if e.deps.Logger == nil {
		t.Error("nil Logger not defaulted")
	}
}

func TestReloadSwapsRoutes(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	next := publicConfig(backend.URL)
	next.Routes[0].ID = "svc2"
	next.Routes[0].PathPrefix = "/v2"
	if err := e.Reload(next); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/v2/thing", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("new route status = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/other", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("old catch-all still routed: status = %d, want 404", rec.Code)
	}
	if got := e.Status().ReloadCount; got != 1 {
		t.Fatalf("ReloadCount = %d, want 1", got)
	}
}

func TestReloadInvalidConfigKeepsOldState(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	bad := publicConfig(backend.URL)
	bad.Routes[0].Auth.Mode = ""
	if err := e.Reload(bad); !errors.Is(err, ErrRouteAuthModeRequired) {
		t.Fatalf("Reload err = %v, want ErrRouteAuthModeRequired", err)
	}
	// Old state must be fully intact.
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status after failed reload = %d, want 200", rec.Code)
	}
	if got := e.Status().ReloadCount; got != 0 {
		t.Fatalf("ReloadCount = %d, want 0 after failed reload", got)
	}
}

func TestReloadFailClosed(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	// Engine was composed without an auth chain; a reload introducing a
	// non-public route must be rejected.
	authed := authConfig(backend.URL)
	if err := e.Reload(authed); !errors.Is(err, ErrAuthChainRequired) {
		t.Fatalf("Reload err = %v, want ErrAuthChainRequired", err)
	}
}

// TestReloadCarriesTransportConnections verifies transport reuse across
// Reload by counting backend TCP connections: an unchanged pool must keep
// its warm keep-alive connection, while a changed pool must dial a new one.
func TestReloadCarriesTransportConnections(t *testing.T) {
	var conns atomic.Int64
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Errorf("backend write: %v", err)
		}
	}))
	backend.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	backend.Start()
	t.Cleanup(backend.Close)

	e, _ := newPublicEngine(t, backend.URL)
	doGet := func() {
		t.Helper()
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	}
	doGet()
	if got := conns.Load(); got != 1 {
		t.Fatalf("connections after first request = %d, want 1", got)
	}
	// Reload with an identical pool config: transport (and its warm
	// connection) must carry over, so no new connection is dialed.
	if err := e.Reload(publicConfig(backend.URL)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	doGet()
	if got := conns.Load(); got != 1 {
		t.Fatalf("connections after unchanged reload = %d, want 1 (transport carried)", got)
	}
	// Reload with a changed pool config: a fresh transport must dial a new
	// connection and the old transport is retired.
	changed := publicConfig(backend.URL)
	changed.Pools[0].MaxIdleConnsPerHost = 4
	if err := e.Reload(changed); err != nil {
		t.Fatalf("Reload changed: %v", err)
	}
	doGet()
	if got := conns.Load(); got != 2 {
		t.Fatalf("connections after changed reload = %d, want 2 (new transport)", got)
	}
}

func TestStatusReportsCompiledState(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	status := e.Status()
	if status.Routes != 1 || status.Pools != 1 {
		t.Fatalf("Status = %+v, want 1 route 1 pool", status)
	}
	if len(status.Listeners) != 1 || status.Listeners[0].ID != "main" {
		t.Fatalf("Status.Listeners = %+v", status.Listeners)
	}
	if status.Listeners[0].BoundAddress != "" {
		t.Error("BoundAddress must be empty before Start")
	}
	if status.Listeners[0].TLS {
		t.Error("TLS must be false without ServerTLS")
	}
}

func TestMergeAuthDefaults(t *testing.T) {
	defaults := AuthDefaults{AttestationMaxAge: 5 * time.Minute, BackendZone: "default-zone"}
	tests := []struct {
		name     string
		in       AuthRequirements
		wantAge  time.Duration
		wantZone string
	}{
		{
			"fills unset fields",
			AuthRequirements{Mode: AuthModeMTLS, RequireAttestation: true},
			5 * time.Minute, "default-zone",
		},
		{
			"route values win",
			AuthRequirements{Mode: AuthModeMTLS, RequireAttestation: true, AttestationMaxAge: time.Minute, BackendZone: "z9"},
			time.Minute, "z9",
		},
		{
			"no attestation leaves age zero",
			AuthRequirements{Mode: AuthModeMTLS},
			0, "default-zone",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.in
			mergeAuthDefaults(&a, defaults)
			if a.AttestationMaxAge != tt.wantAge {
				t.Errorf("AttestationMaxAge = %v, want %v", a.AttestationMaxAge, tt.wantAge)
			}
			if a.BackendZone != tt.wantZone {
				t.Errorf("BackendZone = %q, want %q", a.BackendZone, tt.wantZone)
			}
		})
	}
}

func TestCompiledRouteCarriesMergedDefaults(t *testing.T) {
	backend := okBackend(t)
	cfg := authConfig(backend.URL)
	cfg.Routes[0].Auth.RequireAttestation = true
	cfg.Defaults = AuthDefaults{AttestationMaxAge: 2 * time.Minute, BackendZone: "z-default"}
	auth := &fakeAuth{decision: &AuthDecision{Allowed: true}}
	e, err := New(cfg, Deps{Auth: auth, Logger: testLogger(), ServerTLS: &tls.Config{MinVersion: tls.VersionTLS13}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	route := auth.routeSeen()
	if route == nil {
		t.Fatal("auth chain never invoked")
	}
	got := route.Config().Auth
	if got.AttestationMaxAge != 2*time.Minute || got.BackendZone != "z-default" {
		t.Fatalf("merged auth = %+v", got)
	}
}

func TestReloadCarriesRouteMetrics(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if err := e.Reload(publicConfig(backend.URL)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := e.Metrics().Routes["svc"].Requests; got != 1 {
		t.Fatalf("requests after reload = %d, want carried 1", got)
	}
}

// TestConcurrentRequestsDuringReload hammers the handler from multiple
// goroutines while Reload swaps configurations, verifying the lock-free
// route table swap under -race.
func TestConcurrentRequestsDuringReload(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	cfgA := publicConfig(backend.URL)
	cfgB := publicConfig(backend.URL)
	cfgB.Routes = append(cfgB.Routes, RouteConfig{
		ID:         "extra",
		PathPrefix: "/extra",
		PoolID:     "pool",
		Auth:       AuthRequirements{Mode: AuthModePublic},
	})
	var wg sync.WaitGroup
	const workers = 8
	const iterations = 200
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/stable", nil))
				if rec.Code != http.StatusOK {
					t.Errorf("status = %d, want 200", rec.Code)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cfg := cfgA
			if i%2 == 0 {
				cfg = cfgB
			}
			if err := e.Reload(cfg); err != nil {
				t.Errorf("Reload #%d: %v", i, err)
				return
			}
		}
	}()
	wg.Wait()
}
