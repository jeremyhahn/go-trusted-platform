// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Fakes
// =============================================================================

// fakeControlPlane implements ControlPlaneClient with programmable
// responses.
type fakeControlPlane struct {
	mu         sync.Mutex
	configResp *platformv1.GetProxyConfigResponse
	configErr  error
	matrixResp *platformv1.GetProxyZoneMatrixResponse
	matrixErr  error

	configCalls int
	matrixCalls int
	notify      chan struct{}
}

func (f *fakeControlPlane) Config(ctx context.Context) (*platformv1.GetProxyConfigResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configCalls++
	if f.notify != nil {
		select {
		case f.notify <- struct{}{}:
		default:
		}
	}
	return f.configResp, f.configErr
}

func (f *fakeControlPlane) ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.matrixCalls++
	return f.matrixResp, f.matrixErr
}

func (f *fakeControlPlane) setVersion(version uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configResp = &platformv1.GetProxyConfigResponse{Version: version}
}

func (f *fakeControlPlane) calls() (config, matrix int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.configCalls, f.matrixCalls
}

// fakeReloader records reloaded configurations and returns a programmable
// error.
type fakeReloader struct {
	mu      sync.Mutex
	configs []proxy.Config
	err     error
}

func (f *fakeReloader) Reload(cfg proxy.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.configs = append(f.configs, cfg)
	return nil
}

func (f *fakeReloader) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.configs)
}

func (f *fakeReloader) last(t *testing.T) proxy.Config {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.configs) == 0 {
		t.Fatal("no reloads recorded")
	}
	return f.configs[len(f.configs)-1]
}

// fakeTrustResolver implements trust.Resolver for adapter tests.
type fakeTrustResolver struct {
	lastClass    trust.Class
	lastEndpoint string
	tlsErr       error
}

func (f *fakeTrustResolver) TLSConfig(ctx context.Context, class trust.Class, endpoint string) (*tls.Config, error) {
	f.lastClass = class
	f.lastEndpoint = endpoint
	if f.tlsErr != nil {
		return nil, f.tlsErr
	}
	return &tls.Config{MinVersion: tls.VersionTLS13}, nil
}

func (f *fakeTrustResolver) CAPool(ctx context.Context, class trust.Class, endpoint string) (*x509.CertPool, error) {
	return nil, nil
}

func (f *fakeTrustResolver) CABundlePEM(ctx context.Context, class trust.Class) ([]byte, error) {
	return nil, nil
}

// =============================================================================
// LazyControlPlaneClient
// =============================================================================

func TestNewLazyControlPlaneClientNilDial(t *testing.T) {
	_, err := NewLazyControlPlaneClient(nil)
	var nilErr *ErrNilDialFunc
	if !errors.As(err, &nilErr) {
		t.Fatalf("err = %v, want *ErrNilDialFunc", err)
	}
}

func TestLazyControlPlaneClientDialFailure(t *testing.T) {
	dialErr := errors.New("socket missing")
	attempts := 0
	lazy, err := NewLazyControlPlaneClient(func(ctx context.Context) (ControlPlaneClient, error) {
		attempts++
		return nil, dialErr
	})
	if err != nil {
		t.Fatalf("NewLazyControlPlaneClient: %v", err)
	}
	_, err = lazy.Config(context.Background())
	var dial *ErrDialFailed
	if !errors.As(err, &dial) {
		t.Fatalf("Config err = %v, want *ErrDialFailed", err)
	}
	if !errors.Is(err, dialErr) {
		t.Fatalf("dial cause not wrapped: %v", err)
	}
	// A second call retries the dial.
	if _, err := lazy.ZoneMatrix(context.Background()); err == nil {
		t.Fatal("expected dial failure on retry")
	}
	if attempts != 2 {
		t.Fatalf("dial attempts = %d, want 2", attempts)
	}
}

func TestLazyControlPlaneClientCachesClient(t *testing.T) {
	fake := &fakeControlPlane{configResp: &platformv1.GetProxyConfigResponse{Version: 7}}
	dials := 0
	lazy, err := NewLazyControlPlaneClient(func(ctx context.Context) (ControlPlaneClient, error) {
		dials++
		return fake, nil
	})
	if err != nil {
		t.Fatalf("NewLazyControlPlaneClient: %v", err)
	}
	for i := 0; i < 3; i++ {
		resp, err := lazy.Config(context.Background())
		if err != nil {
			t.Fatalf("Config: %v", err)
		}
		if resp.GetVersion() != 7 {
			t.Fatalf("version = %d, want 7", resp.GetVersion())
		}
	}
	if _, err := lazy.ZoneMatrix(context.Background()); err != nil {
		t.Fatalf("ZoneMatrix: %v", err)
	}
	if dials != 1 {
		t.Fatalf("dials = %d, want 1", dials)
	}
}

// =============================================================================
// ZoneMatrixProvider
// =============================================================================

func TestZoneMatrixProviderDefaultsDenyAll(t *testing.T) {
	p := NewZoneMatrixProvider()
	if v := p.Matrix().Allowed("a", "b"); v.Allowed {
		t.Fatal("fresh provider must deny all traffic")
	}
}

func TestZoneMatrixProviderUpdate(t *testing.T) {
	p := NewZoneMatrixProvider()
	p.Update(&platformv1.GetProxyZoneMatrixResponse{
		Zones: []string{"control-plane", "services"},
		Pairs: []*platformv1.ProxyZonePair{
			{From: "control-plane", To: "services", Services: []string{"https"}},
			{From: "control-plane", To: "control-plane"},
		},
	})
	m := p.Matrix()
	if v := m.Allowed("control-plane", "services"); !v.Allowed || len(v.Services) != 1 || v.Services[0] != "https" {
		t.Fatalf("control-plane->services = %+v, want allowed with https", v)
	}
	if v := m.Allowed("control-plane", "control-plane"); !v.Allowed {
		t.Fatal("control-plane->control-plane must be allowed")
	}
	if v := m.Allowed("services", "control-plane"); v.Allowed {
		t.Fatal("services->control-plane must be denied (not in pairs)")
	}
	if v := m.Allowed("services", "services"); v.Allowed {
		t.Fatal("services->services must be denied: platformd pairs are authoritative")
	}
}

func TestZoneMatrixProviderUpdateNilKeepsMatrix(t *testing.T) {
	p := NewZoneMatrixProvider()
	p.Update(&platformv1.GetProxyZoneMatrixResponse{
		Zones: []string{"a"},
		Pairs: []*platformv1.ProxyZonePair{{From: "a", To: "a"}},
	})
	p.Update(nil)
	if v := p.Matrix().Allowed("a", "a"); !v.Allowed {
		t.Fatal("nil update must not clear the compiled matrix")
	}
}

func TestZoneMatrixProviderUpdatePairZoneMissingFromNames(t *testing.T) {
	p := NewZoneMatrixProvider()
	p.Update(&platformv1.GetProxyZoneMatrixResponse{
		Zones: []string{"services"},
		Pairs: []*platformv1.ProxyZonePair{{From: "edge", To: "services"}},
	})
	if v := p.Matrix().Allowed("edge", "services"); !v.Allowed {
		t.Fatal("pair with undeclared source zone must still compile")
	}
}

// =============================================================================
// TrustResolverAdapter
// =============================================================================

func TestNewTrustResolverAdapterNeedsATrustSource(t *testing.T) {
	_, err := NewTrustResolverAdapter(nil, nil)
	var nilErr *ErrNilResolver
	if !errors.As(err, &nilErr) {
		t.Fatalf("err = %v, want *ErrNilResolver", err)
	}
}

// TestTrustResolverAdapterBMCUsesTheResolver pins the bmc class to the trust
// resolver, with the backend endpoint passed through for endpoint pinning.
func TestTrustResolverAdapterBMCUsesTheResolver(t *testing.T) {
	fake := &fakeTrustResolver{}
	adapter, err := NewTrustResolverAdapter(fake, nil)
	if err != nil {
		t.Fatalf("NewTrustResolverAdapter: %v", err)
	}
	cfg, err := adapter.ClientTLSConfig(context.Background(), BackendTrustBMC, "bmc:443")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil tls config")
	}
	if fake.lastClass != trust.ClassBMC || fake.lastEndpoint != "bmc:443" {
		t.Fatalf("resolver saw (%q, %q), want (bmc, bmc:443)", fake.lastClass, fake.lastEndpoint)
	}
}

// TestTrustResolverAdapterPlatformUsesTheAnchor pins the platform class to
// the platform anchor: a backend the platform CA issued verifies, and the
// resolver is never consulted.
func TestTrustResolverAdapterPlatformUsesTheAnchor(t *testing.T) {
	root := platformTestRoot(t)
	anchor, err := trust.NewAnchor(trust.AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
		return []*x509.Certificate{root}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeTrustResolver{}
	adapter, err := NewTrustResolverAdapter(fake, anchor)
	if err != nil {
		t.Fatalf("NewTrustResolverAdapter: %v", err)
	}
	cfg, err := adapter.ClientTLSConfig(context.Background(), BackendTrustPlatform, "cp.example.internal:8443")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil || !cfg.RootCAs.Equal(mustPool(root)) {
		t.Fatal("the platform class must verify against the platform anchor")
	}
	if fake.lastClass != "" {
		t.Fatalf("the resolver must not be consulted for the platform class, saw %q", fake.lastClass)
	}
}

// TestTrustResolverAdapterMissingSource covers a class whose source this
// gateway was not configured with: a typed error naming the missing
// configuration, never another class's trust.
func TestTrustResolverAdapterMissingSource(t *testing.T) {
	root := platformTestRoot(t)
	anchor, err := trust.NewAnchor(trust.AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
		return []*x509.Certificate{root}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	anchorOnly, err := NewTrustResolverAdapter(nil, anchor)
	if err != nil {
		t.Fatal(err)
	}
	var missing *ErrTrustSourceMissing
	if _, err := anchorOnly.ClientTLSConfig(context.Background(), BackendTrustBMC, "bmc:443"); !errors.As(err, &missing) {
		t.Fatalf("bmc without a resolver: err = %v, want *ErrTrustSourceMissing", err)
	}

	resolverOnly, err := NewTrustResolverAdapter(&fakeTrustResolver{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolverOnly.ClientTLSConfig(context.Background(), BackendTrustPlatform, ""); !errors.As(err, &missing) {
		t.Fatalf("platform without an anchor: err = %v, want *ErrTrustSourceMissing", err)
	}
}

func TestTrustResolverAdapterUnknownClass(t *testing.T) {
	adapter, err := NewTrustResolverAdapter(&fakeTrustResolver{}, nil)
	if err != nil {
		t.Fatalf("NewTrustResolverAdapter: %v", err)
	}
	for _, class := range []string{"public-web", "internal", "default"} {
		_, err = adapter.ClientTLSConfig(context.Background(), class, "")
		var unknown *ErrUnknownTrustClass
		if !errors.As(err, &unknown) {
			t.Fatalf("%q: err = %v, want *ErrUnknownTrustClass", class, err)
		}
		if unknown.Class != class {
			t.Fatalf("Class = %q", unknown.Class)
		}
	}
}

func TestTrustResolverAdapterPropagatesResolverError(t *testing.T) {
	resolveErr := errors.New("no strategy succeeded")
	adapter, err := NewTrustResolverAdapter(&fakeTrustResolver{tlsErr: resolveErr}, nil)
	if err != nil {
		t.Fatalf("NewTrustResolverAdapter: %v", err)
	}
	if _, err := adapter.ClientTLSConfig(context.Background(), BackendTrustBMC, ""); !errors.Is(err, resolveErr) {
		t.Fatalf("err = %v, want resolver error", err)
	}
}

// platformTestRoot is a self-signed CA standing in for the platform CA.
func platformTestRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root-ca.platform.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// =============================================================================
// MergeConfig
// =============================================================================

func TestMergeConfigPlatformdWins(t *testing.T) {
	static := proxy.Config{
		Listeners: []proxy.ListenerConfig{{ID: "https", Address: ":8443"}},
		Routes: []proxy.RouteConfig{
			{ID: "app", PathPrefix: "/", PoolID: "static-pool", Auth: proxy.AuthRequirements{Mode: proxy.AuthModePublic}},
			{ID: "static-only", PathPrefix: "/static", PoolID: "static-pool", Auth: proxy.AuthRequirements{Mode: proxy.AuthModePublic}},
		},
		Pools: []proxy.BackendPoolConfig{
			{ID: "static-pool", Backends: []proxy.BackendConfig{{URL: "http://127.0.0.1:1"}}},
		},
	}
	runtimeRoutes := []proxy.RouteConfig{
		{ID: "app", PathPrefix: "/v2", PoolID: "runtime-pool", Auth: proxy.AuthRequirements{Mode: proxy.AuthModeMTLS}},
		{ID: "runtime-only", PathPrefix: "/rt", PoolID: "runtime-pool", Auth: proxy.AuthRequirements{Mode: proxy.AuthModePublic}},
	}
	runtimePools := []proxy.BackendPoolConfig{
		{ID: "runtime-pool", Backends: []proxy.BackendConfig{{URL: "http://127.0.0.1:2"}}},
		{ID: "static-pool", Backends: []proxy.BackendConfig{{URL: "http://127.0.0.1:3"}}},
	}

	merged := MergeConfig(static, runtimeRoutes, runtimePools)

	if len(merged.Listeners) != 1 || merged.Listeners[0].ID != "https" {
		t.Fatalf("listeners must come from static config: %+v", merged.Listeners)
	}
	if len(merged.Routes) != 3 {
		t.Fatalf("routes = %d, want 3", len(merged.Routes))
	}
	// Static ordering preserved, platformd override applied in place.
	if merged.Routes[0].ID != "app" || merged.Routes[0].PathPrefix != "/v2" || merged.Routes[0].Auth.Mode != proxy.AuthModeMTLS {
		t.Fatalf("route app not overridden: %+v", merged.Routes[0])
	}
	if merged.Routes[1].ID != "static-only" {
		t.Fatalf("static-only route lost: %+v", merged.Routes[1])
	}
	if merged.Routes[2].ID != "runtime-only" {
		t.Fatalf("runtime-only route not appended: %+v", merged.Routes[2])
	}
	if len(merged.Pools) != 2 {
		t.Fatalf("pools = %d, want 2", len(merged.Pools))
	}
	if merged.Pools[0].ID != "static-pool" || merged.Pools[0].Backends[0].URL != "http://127.0.0.1:3" {
		t.Fatalf("static-pool not overridden: %+v", merged.Pools[0])
	}
	if merged.Pools[1].ID != "runtime-pool" {
		t.Fatalf("runtime-pool not appended: %+v", merged.Pools[1])
	}
}

func TestMergeConfigEmptyRuntime(t *testing.T) {
	static := proxy.Config{
		Routes: []proxy.RouteConfig{{ID: "app"}},
		Pools:  []proxy.BackendPoolConfig{{ID: "backend"}},
	}
	merged := MergeConfig(static, nil, nil)
	if len(merged.Routes) != 1 || len(merged.Pools) != 1 {
		t.Fatalf("static config must survive empty runtime: %+v", merged)
	}
}

// =============================================================================
// ConfigSyncer
// =============================================================================

func TestNewConfigSyncerValidation(t *testing.T) {
	fake := &fakeControlPlane{}
	reloader := &fakeReloader{}

	_, err := NewConfigSyncer(SyncerConfig{Reloader: reloader})
	var nilClient *ErrNilClient
	if !errors.As(err, &nilClient) {
		t.Fatalf("err = %v, want *ErrNilClient", err)
	}

	_, err = NewConfigSyncer(SyncerConfig{Client: fake})
	var nilReloader *ErrNilReloader
	if !errors.As(err, &nilReloader) {
		t.Fatalf("err = %v, want *ErrNilReloader", err)
	}

	s, err := NewConfigSyncer(SyncerConfig{Client: fake, Reloader: reloader})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}
	if s.interval != DefaultSyncInterval {
		t.Fatalf("interval = %v, want default", s.interval)
	}
}

func TestConfigSyncerVersionGating(t *testing.T) {
	fake := &fakeControlPlane{}
	fake.setVersion(1)
	reloader := &fakeReloader{}
	s, err := NewConfigSyncer(SyncerConfig{Client: fake, Reloader: reloader})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}

	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if reloader.count() != 1 {
		t.Fatalf("reloads = %d, want 1", reloader.count())
	}

	// Same version: no reload.
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if reloader.count() != 1 {
		t.Fatalf("reloads after same version = %d, want 1", reloader.count())
	}

	// Version bump: reload.
	fake.setVersion(2)
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if reloader.count() != 2 {
		t.Fatalf("reloads after bump = %d, want 2", reloader.count())
	}

	st := s.Status()
	if !st.Synced || st.Version != 2 || st.LastError != "" {
		t.Fatalf("status = %+v", st)
	}
}

func TestConfigSyncerAppliesVersionZero(t *testing.T) {
	// A fresh platformd store is at version 0; the first sync must still
	// apply it (the merge may add runtime state later).
	fake := &fakeControlPlane{}
	fake.setVersion(0)
	reloader := &fakeReloader{}
	s, err := NewConfigSyncer(SyncerConfig{Client: fake, Reloader: reloader})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if reloader.count() != 1 {
		t.Fatalf("reloads = %d, want 1", reloader.count())
	}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if reloader.count() != 1 {
		t.Fatalf("version 0 must not re-apply: reloads = %d", reloader.count())
	}
}

func TestConfigSyncerMergesRuntimeOverStatic(t *testing.T) {
	static := proxy.Config{
		Listeners: []proxy.ListenerConfig{{ID: "https", Address: ":0"}},
		Routes: []proxy.RouteConfig{
			{ID: "app", PathPrefix: "/", PoolID: "backend", Auth: proxy.AuthRequirements{Mode: proxy.AuthModePublic}},
		},
		Pools: []proxy.BackendPoolConfig{
			{ID: "backend", Backends: []proxy.BackendConfig{{URL: "http://127.0.0.1:1"}}},
		},
	}
	fake := &fakeControlPlane{
		configResp: &platformv1.GetProxyConfigResponse{
			Version: 5,
			Routes: []*platformv1.ProxyRoute{{
				Id:         "runtime",
				PathPrefix: "/rt",
				PoolId:     "backend",
				Auth:       &platformv1.ProxyAuthRequirements{Mode: proxy.AuthModePublic},
			}},
		},
	}
	reloader := &fakeReloader{}
	s, err := NewConfigSyncer(SyncerConfig{Client: fake, Reloader: reloader, Static: static})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	merged := reloader.last(t)
	if len(merged.Routes) != 2 {
		t.Fatalf("merged routes = %d, want 2", len(merged.Routes))
	}
	if merged.Routes[0].ID != "app" || merged.Routes[1].ID != "runtime" {
		t.Fatalf("merged route order: %+v", merged.Routes)
	}
	if len(merged.Listeners) != 1 {
		t.Fatal("listeners must come from static config")
	}
}

func TestConfigSyncerFailedReloadKeepsVersion(t *testing.T) {
	fake := &fakeControlPlane{}
	fake.setVersion(3)
	reloadErr := errors.New("invalid config")
	reloader := &fakeReloader{err: reloadErr}
	s, err := NewConfigSyncer(SyncerConfig{Client: fake, Reloader: reloader})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}

	if err := s.SyncOnce(context.Background()); !errors.Is(err, reloadErr) {
		t.Fatalf("SyncOnce = %v, want reload error", err)
	}
	st := s.Status()
	if st.Synced || st.Version != 0 || st.LastError == "" {
		t.Fatalf("status after failed reload = %+v", st)
	}

	// Clearing the failure lets the same version apply on the next tick.
	reloader.mu.Lock()
	reloader.err = nil
	reloader.mu.Unlock()
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce retry: %v", err)
	}
	st = s.Status()
	if !st.Synced || st.Version != 3 || st.LastError != "" {
		t.Fatalf("status after retry = %+v", st)
	}
}

func TestConfigSyncerConfigErrorSurfaces(t *testing.T) {
	fetchErr := errors.New("unavailable")
	fake := &fakeControlPlane{configErr: fetchErr}
	reloader := &fakeReloader{}
	s, err := NewConfigSyncer(SyncerConfig{Client: fake, Reloader: reloader})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}
	if err := s.SyncOnce(context.Background()); !errors.Is(err, fetchErr) {
		t.Fatalf("SyncOnce = %v, want fetch error", err)
	}
	if s.Status().LastError == "" {
		t.Fatal("fetch error must surface in status")
	}
}

func TestConfigSyncerRefreshesMatrixEveryCycle(t *testing.T) {
	fake := &fakeControlPlane{
		matrixResp: &platformv1.GetProxyZoneMatrixResponse{
			Zones: []string{"a", "b"},
			Pairs: []*platformv1.ProxyZonePair{{From: "a", To: "b"}},
		},
	}
	fake.setVersion(1)
	matrix := NewZoneMatrixProvider()
	reloader := &fakeReloader{}
	s, err := NewConfigSyncer(SyncerConfig{Client: fake, Reloader: reloader, Matrix: matrix})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}

	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if v := matrix.Matrix().Allowed("a", "b"); !v.Allowed {
		t.Fatal("matrix not applied")
	}

	// Same config version, changed matrix: refresh must still land.
	fake.mu.Lock()
	fake.matrixResp = &platformv1.GetProxyZoneMatrixResponse{
		Zones: []string{"a", "b"},
		Pairs: []*platformv1.ProxyZonePair{{From: "b", To: "a"}},
	}
	fake.mu.Unlock()
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if v := matrix.Matrix().Allowed("b", "a"); !v.Allowed {
		t.Fatal("matrix not refreshed on unchanged config version")
	}
	if v := matrix.Matrix().Allowed("a", "b"); v.Allowed {
		t.Fatal("stale matrix entry survived refresh")
	}
}

func TestConfigSyncerMatrixErrorAborts(t *testing.T) {
	matrixErr := errors.New("matrix unavailable")
	fake := &fakeControlPlane{matrixErr: matrixErr}
	fake.setVersion(1)
	reloader := &fakeReloader{}
	s, err := NewConfigSyncer(SyncerConfig{
		Client:   fake,
		Reloader: reloader,
		Matrix:   NewZoneMatrixProvider(),
	})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}
	if err := s.SyncOnce(context.Background()); !errors.Is(err, matrixErr) {
		t.Fatalf("SyncOnce = %v, want matrix error", err)
	}
	if reloader.count() != 0 {
		t.Fatal("reload must not run when matrix refresh fails")
	}
}

func TestConfigSyncerRunStopsOnCancel(t *testing.T) {
	fake := &fakeControlPlane{notify: make(chan struct{}, 1)}
	fake.setVersion(1)
	fake.mu.Lock()
	fake.configResp.Version = 1
	fake.mu.Unlock()
	reloader := &fakeReloader{}
	s, err := NewConfigSyncer(SyncerConfig{
		Client:   fake,
		Reloader: reloader,
		Interval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewConfigSyncer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Wait for the immediate sync to land, then cancel and require exit.
	select {
	case <-fake.notify:
	case <-time.After(5 * time.Second):
		t.Fatal("sync loop never called the control plane")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit on context cancellation")
	}
	config, _ := fake.calls()
	if config == 0 {
		t.Fatal("no config fetches recorded")
	}
}
