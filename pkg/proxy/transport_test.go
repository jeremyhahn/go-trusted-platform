package proxy

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

func poolConfig(id, backendURL string) BackendPoolConfig {
	return BackendPoolConfig{ID: id, Backends: []BackendConfig{{URL: backendURL}}}
}

func TestBuildTransportDefaults(t *testing.T) {
	pc := poolConfig("p", "http://10.0.0.1:8080")
	backends, err := parseBackends(&pc)
	if err != nil {
		t.Fatalf("parseBackends: %v", err)
	}
	tr, err := buildTransport(&pc, backends, Deps{}.withDefaults())
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false, want true")
	}
	if tr.MaxIdleConnsPerHost != defaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != defaultIdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", tr.IdleConnTimeout, defaultIdleConnTimeout)
	}
	if tr.TLSClientConfig != nil {
		t.Error("TLSClientConfig set without a trust class")
	}
}

func TestBuildTransportOverrides(t *testing.T) {
	pc := poolConfig("p", "http://10.0.0.1:8080")
	pc.MaxIdleConnsPerHost = 7
	pc.IdleConnTimeout = 5 * time.Second
	backends, err := parseBackends(&pc)
	if err != nil {
		t.Fatalf("parseBackends: %v", err)
	}
	tr, err := buildTransport(&pc, backends, Deps{}.withDefaults())
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}
	if tr.MaxIdleConnsPerHost != 7 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 7", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 5*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 5s", tr.IdleConnTimeout)
	}
}

func TestBuildTransportTrustClass(t *testing.T) {
	want := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "resolved"}
	trust := &fakeTrust{cfg: want}
	pc := poolConfig("p", "https://backend.internal:8443")
	pc.TLS.TrustClass = "internal"
	backends, err := parseBackends(&pc)
	if err != nil {
		t.Fatalf("parseBackends: %v", err)
	}
	tr, err := buildTransport(&pc, backends, Deps{Trust: trust}.withDefaults())
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}
	if tr.TLSClientConfig != want {
		t.Error("TLSClientConfig not taken from TrustResolver")
	}
	if trust.trustClass != "internal" {
		t.Errorf("trustClass = %q, want internal", trust.trustClass)
	}
	if trust.endpoint != "backend.internal:8443" {
		t.Errorf("endpoint = %q, want backend.internal:8443", trust.endpoint)
	}
}

func TestBuildTransportTrustResolveError(t *testing.T) {
	resolveErr := errors.New("no such trust class")
	trust := &fakeTrust{err: resolveErr}
	pc := poolConfig("p", "https://backend.internal:8443")
	pc.TLS.TrustClass = "internal"
	backends, err := parseBackends(&pc)
	if err != nil {
		t.Fatalf("parseBackends: %v", err)
	}
	if _, err = buildTransport(&pc, backends, Deps{Trust: trust}.withDefaults()); !errors.Is(err, resolveErr) {
		t.Fatalf("buildTransport err = %v, want wrapped %v", err, resolveErr)
	}
	var terr *TrustResolveError
	if !errors.As(err, &terr) {
		t.Fatalf("error %T, want *TrustResolveError", err)
	}
	if terr.PoolID != "p" || terr.TrustClass != "internal" {
		t.Fatalf("TrustResolveError = %+v", terr)
	}
}

func TestParseBackendsInvalidURL(t *testing.T) {
	pc := BackendPoolConfig{ID: "p", Backends: []BackendConfig{{URL: "://bad"}}}
	if _, err := parseBackends(&pc); !errors.Is(err, ErrInvalidBackendURL) {
		t.Fatalf("parseBackends err = %v, want ErrInvalidBackendURL", err)
	}
}

func TestPoolConfigHash(t *testing.T) {
	a := poolConfig("p", "http://10.0.0.1:8080")
	b := poolConfig("p", "http://10.0.0.1:8080")
	if poolConfigHash(&a) != poolConfigHash(&b) {
		t.Error("identical configs must hash equal")
	}
	b.IdleConnTimeout = time.Minute
	if poolConfigHash(&a) == poolConfigHash(&b) {
		t.Error("different configs must hash differently")
	}
}

func TestCompilePoolsCarriesUnchangedTransport(t *testing.T) {
	cfg := &Config{Pools: []BackendPoolConfig{poolConfig("p", "http://10.0.0.1:8080")}}
	deps := Deps{}.withDefaults()
	first, retired, err := compilePools(cfg, deps, nil)
	if err != nil {
		t.Fatalf("compilePools: %v", err)
	}
	if len(retired) != 0 {
		t.Fatalf("retired = %d transports, want 0", len(retired))
	}
	second, retired, err := compilePools(cfg, deps, first)
	if err != nil {
		t.Fatalf("compilePools reload: %v", err)
	}
	if second["p"].transport != first["p"].transport {
		t.Error("unchanged pool must carry its transport")
	}
	if len(retired) != 0 {
		t.Fatalf("retired = %d transports for unchanged pool, want 0", len(retired))
	}
}

func TestCompilePoolsRetiresChangedTransport(t *testing.T) {
	cfg := &Config{Pools: []BackendPoolConfig{poolConfig("p", "http://10.0.0.1:8080")}}
	deps := Deps{}.withDefaults()
	first, _, err := compilePools(cfg, deps, nil)
	if err != nil {
		t.Fatalf("compilePools: %v", err)
	}
	changed := &Config{Pools: []BackendPoolConfig{poolConfig("p", "http://10.0.0.9:8080")}}
	second, retired, err := compilePools(changed, deps, first)
	if err != nil {
		t.Fatalf("compilePools reload: %v", err)
	}
	if second["p"].transport == first["p"].transport {
		t.Error("changed pool must get a new transport")
	}
	if len(retired) != 1 || retired[0] != first["p"].transport {
		t.Fatalf("retired = %v, want the old transport", retired)
	}
}

func TestCompilePoolsRetiresRemovedPool(t *testing.T) {
	cfg := &Config{Pools: []BackendPoolConfig{
		poolConfig("keep", "http://10.0.0.1:8080"),
		poolConfig("drop", "http://10.0.0.2:8080"),
	}}
	deps := Deps{}.withDefaults()
	first, _, err := compilePools(cfg, deps, nil)
	if err != nil {
		t.Fatalf("compilePools: %v", err)
	}
	shrunk := &Config{Pools: []BackendPoolConfig{poolConfig("keep", "http://10.0.0.1:8080")}}
	second, retired, err := compilePools(shrunk, deps, first)
	if err != nil {
		t.Fatalf("compilePools reload: %v", err)
	}
	if second["keep"].transport != first["keep"].transport {
		t.Error("kept pool must carry its transport")
	}
	if len(retired) != 1 || retired[0] != first["drop"].transport {
		t.Fatalf("retired = %v, want the dropped pool transport", retired)
	}
}

func TestCompilePoolsPropagatesErrors(t *testing.T) {
	deps := Deps{}.withDefaults()
	t.Run("invalid backend url", func(t *testing.T) {
		cfg := &Config{Pools: []BackendPoolConfig{{ID: "p", Backends: []BackendConfig{{URL: "://bad"}}}}}
		if _, _, err := compilePools(cfg, deps, nil); !errors.Is(err, ErrInvalidBackendURL) {
			t.Fatalf("err = %v, want ErrInvalidBackendURL", err)
		}
	})
	t.Run("unknown balancer", func(t *testing.T) {
		pc := poolConfig("p", "http://10.0.0.1:8080")
		pc.Balancer = "bogus"
		cfg := &Config{Pools: []BackendPoolConfig{pc}}
		if _, _, err := compilePools(cfg, deps, nil); !errors.Is(err, ErrUnknownBalancer) {
			t.Fatalf("err = %v, want ErrUnknownBalancer", err)
		}
	})
	t.Run("trust resolver failure", func(t *testing.T) {
		resolveErr := errors.New("boom")
		pc := poolConfig("p", "https://10.0.0.1:8443")
		pc.TLS.TrustClass = "internal"
		cfg := &Config{Pools: []BackendPoolConfig{pc}}
		d := Deps{Trust: &fakeTrust{err: resolveErr}}.withDefaults()
		if _, _, err := compilePools(cfg, d, nil); !errors.Is(err, resolveErr) {
			t.Fatalf("err = %v, want wrapped %v", err, resolveErr)
		}
	})
}
