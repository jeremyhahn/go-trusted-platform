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

package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// testLogger returns a quiet logger for assembly tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// writeTLSFixtures writes the test TLS bundle's server keypair and CA
// bundle as PEM files and returns their paths.
func writeTLSFixtures(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	dir := t.TempDir()

	var certPEM bytes.Buffer
	for _, der := range bundle.ServerCert.Certificate {
		if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatalf("encode cert: %v", err)
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(bundle.ServerCert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	certFile = filepath.Join(dir, "server.pem")
	keyFile = filepath.Join(dir, "server-key.pem")
	caFile = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certFile, certPEM.Bytes(), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(caFile, bundle.CACertPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return certFile, keyFile, caFile
}

// publicProxyConfig returns an enabled proxy configuration with one public
// route and no TLS.
func publicProxyConfig() *proxysvc.Config {
	return &proxysvc.Config{
		Enabled:   true,
		Listeners: []proxysvc.ListenerConfig{{ID: "web", Address: "127.0.0.1:0"}},
		Routes: []proxysvc.RouteConfig{{
			ID:         "app",
			PathPrefix: "/",
			Pool:       "backend",
			Auth:       proxysvc.AuthConfig{Mode: proxy.AuthModePublic},
		}},
		Pools: []proxysvc.PoolConfig{{
			ID:       "backend",
			Backends: []proxysvc.BackendConfig{{URL: "http://127.0.0.1:18080"}},
		}},
	}
}

func TestLoadServeConfig(t *testing.T) {
	yaml := []byte(`
gateway:
  enabled: true
  id: gw-test
proxy:
  enabled: true
  listeners:
    - id: web
      address: 127.0.0.1:0
  routes:
    - id: app
      path-prefix: /
      pool: backend
      auth:
        mode: public
  pools:
    - id: backend
      backends:
        - url: http://127.0.0.1:18080
  sync:
    enabled: true
    interval: 5s
  platformd:
    protocol: unix
    socket: /run/platformd.sock
`)
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(yaml)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	cfg, err := LoadServeConfig(v)
	if err != nil {
		t.Fatalf("LoadServeConfig: %v", err)
	}
	if cfg.Gateway == nil || cfg.Gateway.ID != "gw-test" || !cfg.Gateway.Enabled {
		t.Fatalf("gateway section: %+v", cfg.Gateway)
	}
	if cfg.Proxy == nil || !cfg.Proxy.Enabled {
		t.Fatalf("proxy section: %+v", cfg.Proxy)
	}
	if len(cfg.Proxy.Listeners) != 1 || cfg.Proxy.Listeners[0].ID != "web" {
		t.Fatalf("proxy listeners: %+v", cfg.Proxy.Listeners)
	}
	if cfg.Proxy.Routes[0].PathPrefix != "/" || cfg.Proxy.Routes[0].Pool != "backend" {
		t.Fatalf("proxy route: %+v", cfg.Proxy.Routes[0])
	}
	if cfg.Proxy.Sync.Interval != 5*time.Second {
		t.Fatalf("sync interval: %v", cfg.Proxy.Sync.Interval)
	}
	if cfg.Trust != nil {
		t.Fatal("absent trust section must stay nil")
	}
}

func TestLoadServeConfigAbsentSections(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader([]byte("debug: true\n"))); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	cfg, err := LoadServeConfig(v)
	if err != nil {
		t.Fatalf("LoadServeConfig: %v", err)
	}
	if cfg.Gateway != nil || cfg.Proxy != nil || cfg.Trust != nil {
		t.Fatalf("sections must be nil when absent: %+v", cfg)
	}
}

func TestBuildGatewayNilConfig(t *testing.T) {
	if _, err := BuildGateway(nil, testLogger()); !errors.Is(err, ErrConfigLoadFailed) {
		t.Fatalf("err = %v, want ErrConfigLoadFailed", err)
	}
}

func TestBuildGatewayNothingEnabled(t *testing.T) {
	cfg := &ServeConfig{Gateway: &gateway.GatewayConfig{Enabled: false}}
	if _, err := BuildGateway(cfg, testLogger()); !errors.Is(err, ErrNothingEnabled) {
		t.Fatalf("err = %v, want ErrNothingEnabled", err)
	}
}

func TestBuildGatewayGatewayDisabledWithProxy(t *testing.T) {
	cfg := &ServeConfig{
		Gateway: &gateway.GatewayConfig{Enabled: false},
		Proxy:   publicProxyConfig(),
	}
	if _, err := BuildGateway(cfg, testLogger()); !errors.Is(err, ErrGatewayDisabled) {
		t.Fatalf("err = %v, want ErrGatewayDisabled", err)
	}
}

func TestBuildGatewayDefaultsWithProxyLifecycle(t *testing.T) {
	cfg := &ServeConfig{Proxy: publicProxyConfig()}
	gw, err := BuildGateway(cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	if gw.GetConfig().ID != defaultGatewayID {
		t.Fatalf("ID = %q, want %q", gw.GetConfig().ID, defaultGatewayID)
	}

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !gw.HasService(gateway.ServiceProxy) {
		t.Fatal("proxy service not active after Start")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := gw.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestBuildGatewayWithoutProxy(t *testing.T) {
	cfg := &ServeConfig{Gateway: &gateway.GatewayConfig{Enabled: true, ID: "plain"}}
	gw, err := BuildGateway(cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	if gw.HasService(gateway.ServiceProxy) {
		t.Fatal("proxy must not be registered when disabled")
	}
}

func TestBuildProxyHandlerDisabled(t *testing.T) {
	var disabledErr *proxysvc.ErrProxyDisabled
	_, err := BuildProxyHandler(nil, nil, testLogger())
	if !errors.As(err, &disabledErr) {
		t.Fatalf("nil config err = %v, want *ErrProxyDisabled", err)
	}
	_, err = BuildProxyHandler(&proxysvc.Config{Enabled: false}, nil, testLogger())
	if !errors.As(err, &disabledErr) {
		t.Fatalf("disabled config err = %v, want *ErrProxyDisabled", err)
	}
}

func TestBuildProxyHandlerMTLSRequiresServerTLS(t *testing.T) {
	cfg := publicProxyConfig()
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLS
	_, err := BuildProxyHandler(cfg, nil, testLogger())
	var tlsErr *proxysvc.ErrServerTLSRequired
	if !errors.As(err, &tlsErr) {
		t.Fatalf("err = %v, want *ErrServerTLSRequired", err)
	}
}

func TestBuildProxyHandlerMTLSRequiresClientCA(t *testing.T) {
	certFile, keyFile, _ := writeTLSFixtures(t)
	cfg := publicProxyConfig()
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLS
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	_, err := BuildProxyHandler(cfg, nil, testLogger())
	var caErr *proxysvc.ErrClientCARequired
	if !errors.As(err, &caErr) {
		t.Fatalf("err = %v, want *ErrClientCARequired", err)
	}
}

func TestBuildProxyHandlerMTLSComplete(t *testing.T) {
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := publicProxyConfig()
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLS
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAFile = caFile

	handler, err := BuildProxyHandler(cfg, nil, testLogger())
	if err != nil {
		t.Fatalf("BuildProxyHandler: %v", err)
	}
	if handler.Name() != "proxy" {
		t.Fatalf("Name = %q", handler.Name())
	}
	snap := handler.HealthSnapshot()
	if snap.Engine == nil || snap.Engine.Routes != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.Sync != nil {
		t.Fatal("sync disabled must leave Sync nil")
	}
}

func TestBuildProxyHandlerZoneRoutesRequireSync(t *testing.T) {
	// Zone-enforcing routes need the zone matrix, which only the sync loop
	// supplies; without sync the chain lacks the zones capability and the
	// engine rejects the configuration fail-closed.
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := publicProxyConfig()
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLS
	cfg.Routes[0].Auth.AllowedZones = []string{"trusted"}
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAFile = caFile

	if _, err := BuildProxyHandler(cfg, nil, testLogger()); err == nil {
		t.Fatal("zone route without sync must fail fail-closed")
	}

	cfg.Sync.Enabled = true
	handler, err := BuildProxyHandler(cfg, nil, testLogger())
	if err != nil {
		t.Fatalf("BuildProxyHandler with sync: %v", err)
	}
	if snap := handler.HealthSnapshot(); snap.Sync == nil {
		t.Fatal("sync enabled must populate Sync snapshot")
	}
}

func TestBuildProxyHandlerBadCertFile(t *testing.T) {
	cfg := publicProxyConfig()
	cfg.TLS.CertFile = filepath.Join(t.TempDir(), "missing.pem")
	cfg.TLS.KeyFile = filepath.Join(t.TempDir(), "missing-key.pem")
	_, err := BuildProxyHandler(cfg, nil, testLogger())
	var loadErr *proxysvc.ErrCertificateLoadFailed
	if !errors.As(err, &loadErr) {
		t.Fatalf("err = %v, want *ErrCertificateLoadFailed", err)
	}
}

func TestBuildProxyHandlerBadClientCAFile(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	cfg := publicProxyConfig()
	cfg.TLS.ClientCAFile = garbage
	_, err := BuildProxyHandler(cfg, nil, testLogger())
	var caErr *proxysvc.ErrClientCALoadFailed
	if !errors.As(err, &caErr) {
		t.Fatalf("garbage bundle err = %v, want *ErrClientCALoadFailed", err)
	}

	cfg.TLS.ClientCAFile = filepath.Join(t.TempDir(), "missing.pem")
	_, err = BuildProxyHandler(cfg, nil, testLogger())
	if !errors.As(err, &caErr) {
		t.Fatalf("missing bundle err = %v, want *ErrClientCALoadFailed", err)
	}
}

func TestBuildProxyHandlerGRPCRequiresTrust(t *testing.T) {
	cfg := publicProxyConfig()
	cfg.Sync.Enabled = true
	cfg.Platformd.Protocol = proxysvc.PlatformdProtocolGRPC
	cfg.Platformd.GRPCAddr = "127.0.0.1:10443"
	if _, err := BuildProxyHandler(cfg, nil, testLogger()); !errors.Is(err, ErrTrustRequiredForGRPC) {
		t.Fatalf("err = %v, want ErrTrustRequiredForGRPC", err)
	}
}

func TestPlatformdDialUnknownProtocol(t *testing.T) {
	dial := platformdDial(proxysvc.PlatformdConfig{Protocol: "carrier-pigeon"}, nil)
	_, err := dial(context.Background())
	var cfgErr *proxysvc.ErrConfigInvalid
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err = %v, want *ErrConfigInvalid", err)
	}
}

func TestPlatformdDialUnixSocketMissing(t *testing.T) {
	dial := platformdDial(proxysvc.PlatformdConfig{
		Protocol: proxysvc.PlatformdProtocolUnix,
		Socket:   filepath.Join(t.TempDir(), "absent.sock"),
	}, nil)
	if _, err := dial(context.Background()); err == nil {
		t.Fatal("dial must fail when the platformd socket is absent")
	}
}

func TestPlatformdDialGRPCRequiresResolver(t *testing.T) {
	dial := platformdDial(proxysvc.PlatformdConfig{
		Protocol: proxysvc.PlatformdProtocolGRPC,
		GRPCAddr: "127.0.0.1:10443",
	}, nil)
	if _, err := dial(context.Background()); !errors.Is(err, ErrTrustRequiredForGRPC) {
		t.Fatalf("err = %v, want ErrTrustRequiredForGRPC", err)
	}
}

// fakeResolver implements trust.Resolver for assembly branch tests.
type fakeResolver struct {
	pool    *x509.CertPool
	poolErr error
	tlsErr  error
}

func (f *fakeResolver) TLSConfig(ctx context.Context, class trust.Class, endpoint string) (*tls.Config, error) {
	if f.tlsErr != nil {
		return nil, f.tlsErr
	}
	return &tls.Config{MinVersion: tls.VersionTLS13}, nil
}

func (f *fakeResolver) CAPool(ctx context.Context, class trust.Class, endpoint string) (*x509.CertPool, error) {
	if f.poolErr != nil {
		return nil, f.poolErr
	}
	return f.pool, nil
}

func (f *fakeResolver) CABundlePEM(ctx context.Context, class trust.Class) ([]byte, error) {
	return nil, nil
}

func TestLoadServeConfigDecodeError(t *testing.T) {
	tests := []struct {
		section string
		yaml    string
	}{
		{"gateway", "gateway:\n  - 1\n  - 2\n"},
		{"proxy", "proxy:\n  - 1\n  - 2\n"},
		{"trust", "trust:\n  - 1\n  - 2\n"},
	}
	for _, tc := range tests {
		t.Run(tc.section, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			if err := v.ReadConfig(bytes.NewReader([]byte(tc.yaml))); err != nil {
				t.Fatalf("ReadConfig: %v", err)
			}
			_, err := LoadServeConfig(v)
			var sectionErr *ErrConfigSection
			if !errors.As(err, &sectionErr) {
				t.Fatalf("err = %v, want *ErrConfigSection", err)
			}
			if sectionErr.Section != tc.section {
				t.Fatalf("Section = %q, want %q", sectionErr.Section, tc.section)
			}
			if sectionErr.Unwrap() == nil {
				t.Fatal("cause not wrapped")
			}
		})
	}
}

func TestBuildServeLogger(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		logFormat = format
		if logger := buildServeLogger(); logger == nil {
			t.Fatalf("nil logger for format %q", format)
		}
	}
	debugMode = true
	if logger := buildServeLogger(); logger == nil {
		t.Fatal("nil logger in debug mode")
	}
	debugMode = false
	logFormat = "json"
}

func TestLoadClientCAsFromResolver(t *testing.T) {
	pool := x509.NewCertPool()
	cfg := publicProxyConfig()

	t.Run("resolver pool used", func(t *testing.T) {
		got, err := loadClientCAs(cfg, &fakeResolver{pool: pool}, true)
		if err != nil {
			t.Fatalf("loadClientCAs: %v", err)
		}
		if got != pool {
			t.Fatal("resolver pool not returned")
		}
	})

	t.Run("resolver failure fatal when auth needed", func(t *testing.T) {
		resolveErr := errors.New("no strategy succeeded")
		if _, err := loadClientCAs(cfg, &fakeResolver{poolErr: resolveErr}, true); !errors.Is(err, resolveErr) {
			t.Fatalf("err = %v, want resolver error", err)
		}
	})

	t.Run("resolver failure tolerated without auth", func(t *testing.T) {
		got, err := loadClientCAs(cfg, &fakeResolver{poolErr: errors.New("offline")}, false)
		if err != nil || got != nil {
			t.Fatalf("got %v, %v; want nil, nil", got, err)
		}
	})

	t.Run("no resolver no file", func(t *testing.T) {
		got, err := loadClientCAs(cfg, nil, false)
		if err != nil || got != nil {
			t.Fatalf("got %v, %v; want nil, nil", got, err)
		}
	})
}

func TestBuildServerTLSWithClientCAs(t *testing.T) {
	certFile, keyFile, _ := writeTLSFixtures(t)
	cfg := publicProxyConfig()
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile

	pool := x509.NewCertPool()
	tlsCfg, err := buildServerTLS(cfg, pool)
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if tlsCfg.ClientCAs != pool || tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("client CA verification not configured: %+v", tlsCfg)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsCfg.MinVersion)
	}

	// No cert file: no server TLS.
	noTLS := publicProxyConfig()
	got, err := buildServerTLS(noTLS, nil)
	if err != nil || got != nil {
		t.Fatalf("got %v, %v; want nil, nil", got, err)
	}
}

func TestBuildTrustResolverInvalidConfig(t *testing.T) {
	if r, err := buildTrustResolver(nil, testLogger()); err != nil || r != nil {
		t.Fatalf("nil config must yield nil resolver: %v, %v", r, err)
	}
	bad := &trust.Config{
		Default: &trust.ScopeConfig{Strategies: []trust.Strategy{"not-a-strategy"}},
	}
	if _, err := buildTrustResolver(bad, testLogger()); err == nil {
		t.Fatal("invalid trust config must fail")
	}
}

func TestPlatformdDialGRPCWithResolver(t *testing.T) {
	t.Run("resolver tls error propagates", func(t *testing.T) {
		tlsErr := errors.New("resolve failed")
		dial := platformdDial(proxysvc.PlatformdConfig{
			Protocol: proxysvc.PlatformdProtocolGRPC,
			GRPCAddr: "127.0.0.1:1",
		}, &fakeResolver{tlsErr: tlsErr})
		if _, err := dial(context.Background()); !errors.Is(err, tlsErr) {
			t.Fatalf("err = %v, want resolver error", err)
		}
	})

	t.Run("grpc client constructed lazily", func(t *testing.T) {
		// gRPC connections are lazy: construction succeeds and connection
		// failures surface on the first RPC, where the sync loop's lazy
		// client retries them.
		dial := platformdDial(proxysvc.PlatformdConfig{
			Protocol: proxysvc.PlatformdProtocolGRPC,
			GRPCAddr: "127.0.0.1:1",
		}, &fakeResolver{})
		dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		client, err := dial(dialCtx)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if client == nil {
			t.Fatal("nil control-plane client")
		}
		if _, err := client.Config(dialCtx); err == nil {
			t.Fatal("RPC to unreachable platformd must fail")
		}
	})
}

// mtlsProxyConfig returns a complete mTLS proxy configuration with TLS
// fixtures applied.
func mtlsProxyConfig(t *testing.T) *proxysvc.Config {
	t.Helper()
	certFile, keyFile, caFile := writeTLSFixtures(t)
	cfg := publicProxyConfig()
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLS
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAFile = caFile
	return cfg
}

func TestBuildProxyHandlerAttestationRoutesRequireGate(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.Routes[0].Auth.RequireAttestation = true

	if _, err := BuildProxyHandler(cfg, nil, testLogger()); !errors.Is(err, proxy.ErrAttestationGateNotConfigured) {
		t.Fatalf("attestation route without gate = %v, want ErrAttestationGateNotConfigured", err)
	}

	cfg.Attestation.Enabled = true
	if _, err := BuildProxyHandler(cfg, nil, testLogger()); err != nil {
		t.Fatalf("BuildProxyHandler with attestation gate: %v", err)
	}
}

func TestBuildProxyHandlerTokenRoutesRequireAuthenticator(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLSOrToken

	if _, err := BuildProxyHandler(cfg, nil, testLogger()); !errors.Is(err, proxy.ErrTokenAuthNotConfigured) {
		t.Fatalf("token route without authenticator = %v, want ErrTokenAuthNotConfigured", err)
	}

	cfg.TokenAuth = proxysvc.TokenAuthConfig{
		Enabled:   true,
		Issuer:    "https://broker.example",
		JWKSURL:   "https://broker.example/jwks.json",
		AuthzMode: proxysvc.AuthzModeOffline,
	}
	if _, err := BuildProxyHandler(cfg, nil, testLogger()); err != nil {
		t.Fatalf("BuildProxyHandler with token auth: %v", err)
	}
}

func TestBuildProxyHandlerTokenAuthInvalidSection(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.TokenAuth = proxysvc.TokenAuthConfig{Enabled: true}
	var cfgErr *proxysvc.ErrTokenAuthConfig
	if _, err := BuildProxyHandler(cfg, nil, testLogger()); !errors.As(err, &cfgErr) {
		t.Fatalf("invalid token-auth section = %v, want *ErrTokenAuthConfig", err)
	}
}

func TestBuildProxyHandlerOPARoutesRequireEvaluator(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.Routes[0].Auth.OPAPolicy = "proxy_authz"

	if _, err := BuildProxyHandler(cfg, nil, testLogger()); !errors.Is(err, proxy.ErrOPANotConfigured) {
		t.Fatalf("opa route without evaluator = %v, want ErrOPANotConfigured", err)
	}

	cfg.OPA.Enabled = true
	if _, err := BuildProxyHandler(cfg, nil, testLogger()); err != nil {
		t.Fatalf("BuildProxyHandler with opa evaluator: %v", err)
	}
}

func TestPlatformdAttestationDialUnixSocketMissing(t *testing.T) {
	dial := platformdAttestationDial(proxysvc.PlatformdConfig{
		Protocol: proxysvc.PlatformdProtocolUnix,
		Socket:   filepath.Join(t.TempDir(), "missing.sock"),
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dial(ctx); err == nil {
		t.Fatal("expected dial failure for a missing platformd socket")
	}
}

func TestPlatformdAttestationDialGRPCRequiresResolver(t *testing.T) {
	dial := platformdAttestationDial(proxysvc.PlatformdConfig{
		Protocol: proxysvc.PlatformdProtocolGRPC,
		GRPCAddr: "127.0.0.1:1",
	}, nil)
	if _, err := dial(context.Background()); !errors.Is(err, ErrTrustRequiredForGRPC) {
		t.Fatalf("grpc dial without resolver = %v, want ErrTrustRequiredForGRPC", err)
	}
}
