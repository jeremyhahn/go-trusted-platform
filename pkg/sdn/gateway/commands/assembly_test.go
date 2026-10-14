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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
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
			PoolID:     "backend",
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
	if cfg.Proxy.Routes[0].PathPrefix != "/" || cfg.Proxy.Routes[0].PoolID != "backend" {
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
	if _, err := BuildGateway(context.Background(), nil, testLogger()); !errors.Is(err, ErrConfigLoadFailed) {
		t.Fatalf("err = %v, want ErrConfigLoadFailed", err)
	}
}

func TestVPNRevocationJournal(t *testing.T) {
	dataDir := t.TempDir()
	got := vpnRevocationJournal(dataDir)
	want := gateway.NewRevocationJournal(filepath.Join(dataDir, "vpn", "pending-revocations.json"))
	if got == nil || *got != *want {
		t.Fatalf("journal = %+v, want %+v under --data-dir", got, want)
	}
	if journal := vpnRevocationJournal(""); journal != nil {
		t.Fatalf("journal = %+v without a data directory, want nil so the VPN refuses to build", journal)
	}
}

func TestBuildGatewayNothingEnabled(t *testing.T) {
	cfg := &ServeConfig{Gateway: &gateway.GatewayConfig{Enabled: false}}
	if _, err := BuildGateway(context.Background(), cfg, testLogger()); !errors.Is(err, ErrNothingEnabled) {
		t.Fatalf("err = %v, want ErrNothingEnabled", err)
	}
}

func TestBuildGatewayGatewayDisabledWithProxy(t *testing.T) {
	cfg := &ServeConfig{
		Gateway: &gateway.GatewayConfig{Enabled: false},
		Proxy:   publicProxyConfig(),
	}
	if _, err := BuildGateway(context.Background(), cfg, testLogger()); !errors.Is(err, ErrGatewayDisabled) {
		t.Fatalf("err = %v, want ErrGatewayDisabled", err)
	}
}

func TestBuildGatewayDefaultsWithProxyLifecycle(t *testing.T) {
	cfg := &ServeConfig{Proxy: publicProxyConfig()}
	gw, err := BuildGateway(context.Background(), cfg, testLogger())
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
	gw, err := BuildGateway(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	if gw.HasService(gateway.ServiceProxy) {
		t.Fatal("proxy must not be registered when disabled")
	}
}

func TestBuildGatewayProxyHostedElsewhere(t *testing.T) {
	cfg := &ServeConfig{
		Gateway: &gateway.GatewayConfig{
			Enabled:        true,
			ID:             "routing-child",
			HostedServices: []string{gateway.ServiceTransit},
		},
		Proxy: publicProxyConfig(),
	}
	gw, err := BuildGateway(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	for _, report := range gw.ServiceReports() {
		if report.Name == gateway.ServiceProxy {
			t.Fatal("a child that does not host the proxy must not register it")
		}
	}
}

func TestBuildGatewayRelaysASupervisedProxy(t *testing.T) {
	proxyCfg := publicProxyConfig()
	// mTLS without server TLS fails BuildProxyHandler, so the build only
	// succeeds if this process relays the proxy instead of building it.
	proxyCfg.Routes[0].Auth.Mode = proxy.AuthModeMTLS
	cfg := &ServeConfig{
		Gateway: &gateway.GatewayConfig{Enabled: true, ID: "supervising-parent"},
		Proxy:   proxyCfg,
		Process: supervisorSettings(t),
		DataDir: t.TempDir(),
	}
	if _, err := BuildSupervisor(cfg, process.Inherited{ConfigFile: "/etc/gatewayd/config.yaml"}, testLogger()); err != nil {
		t.Fatalf("BuildSupervisor: %v", err)
	}

	gw, err := BuildGateway(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway must relay the proxy, not build it: %v", err)
	}
	found := false
	for _, report := range gw.ServiceReports() {
		found = found || report.Name == gateway.ServiceProxy
	}
	if !found {
		t.Fatal("the supervising parent must register the proxy relay")
	}
	entries, err := os.ReadDir(cfg.DataDir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("the parent opened proxy state it no longer owns: %v", entries)
	}
}

func TestBuildGatewaySupervisorDoesNotRelayADisabledProxy(t *testing.T) {
	proxyCfg := publicProxyConfig()
	proxyCfg.Enabled = false
	cfg := &ServeConfig{
		Gateway: &gateway.GatewayConfig{Enabled: true, ID: "supervising-parent"},
		Proxy:   proxyCfg,
		Process: supervisorSettings(t),
	}
	if _, err := BuildSupervisor(cfg, process.Inherited{ConfigFile: "/etc/gatewayd/config.yaml"}, testLogger()); err != nil {
		t.Fatalf("BuildSupervisor: %v", err)
	}

	gw, err := BuildGateway(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	for _, report := range gw.ServiceReports() {
		if report.Name == gateway.ServiceProxy {
			t.Fatal("a disabled proxy must not be relayed to a child")
		}
	}
}

func TestEnabledServices(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ServeConfig
		want []string
	}{
		{
			name: "the gateway sections, then the proxy",
			cfg: &ServeConfig{
				Gateway: &gateway.GatewayConfig{Enabled: true, Transit: &gateway.TransitServiceConfig{Enabled: true}},
				Proxy:   publicProxyConfig(),
			},
			want: []string{gateway.ServiceTransit, gateway.ServiceProxy},
		},
		{
			name: "the proxy alone, with no gateway section",
			cfg:  &ServeConfig{Proxy: publicProxyConfig()},
			want: []string{gateway.ServiceProxy},
		},
		{
			name: "a disabled proxy is not a service",
			cfg: &ServeConfig{
				Gateway: &gateway.GatewayConfig{Enabled: true, Transit: &gateway.TransitServiceConfig{Enabled: true}},
				Proxy:   &proxysvc.Config{Enabled: false},
			},
			want: []string{gateway.ServiceTransit},
		},
		{
			name: "nothing configured",
			cfg:  &ServeConfig{},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := enabledServices(tc.cfg)
			if len(got) != len(tc.want) {
				t.Fatalf("enabledServices = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("enabledServices = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestBuildProxyHandlerDisabled(t *testing.T) {
	var disabledErr *proxysvc.ErrProxyDisabled
	_, err := BuildProxyHandler(nil, nil, nil, testLogger())
	if !errors.As(err, &disabledErr) {
		t.Fatalf("nil config err = %v, want *ErrProxyDisabled", err)
	}
	_, err = BuildProxyHandler(&proxysvc.Config{Enabled: false}, nil, nil, testLogger())
	if !errors.As(err, &disabledErr) {
		t.Fatalf("disabled config err = %v, want *ErrProxyDisabled", err)
	}
}

func TestBuildProxyHandlerMTLSRequiresServerTLS(t *testing.T) {
	cfg := publicProxyConfig()
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLS
	_, err := BuildProxyHandler(cfg, nil, nil, testLogger())
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
	_, err := BuildProxyHandler(cfg, nil, nil, testLogger())
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

	handler, err := BuildProxyHandler(cfg, nil, nil, testLogger())
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
	cfg.Routes[0].Auth.AllowedZones = []string{"control-plane"}
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.ClientCAFile = caFile

	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); err == nil {
		t.Fatal("zone route without sync must fail fail-closed")
	}

	cfg.Sync.Enabled = true
	handler, err := BuildProxyHandler(cfg, nil, nil, testLogger())
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
	_, err := BuildProxyHandler(cfg, nil, nil, testLogger())
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
	_, err := BuildProxyHandler(cfg, nil, nil, testLogger())
	var caErr *proxysvc.ErrClientCALoadFailed
	if !errors.As(err, &caErr) {
		t.Fatalf("garbage bundle err = %v, want *ErrClientCALoadFailed", err)
	}

	cfg.TLS.ClientCAFile = filepath.Join(t.TempDir(), "missing.pem")
	_, err = BuildProxyHandler(cfg, nil, nil, testLogger())
	if !errors.As(err, &caErr) {
		t.Fatalf("missing bundle err = %v, want *ErrClientCALoadFailed", err)
	}
}

func TestBuildProxyHandlerGRPCRequiresTrust(t *testing.T) {
	cfg := publicProxyConfig()
	cfg.Sync.Enabled = true
	cfg.Platformd.Protocol = proxysvc.PlatformdProtocolGRPC
	cfg.Platformd.GRPCAddr = "127.0.0.1:10443"
	cfg.Platformd.TokenFile = filepath.Join(t.TempDir(), "platformd.token")
	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); !errors.Is(err, ErrPlatformAnchorRequiredForGRPC) {
		t.Fatalf("err = %v, want ErrPlatformAnchorRequiredForGRPC", err)
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
	if _, err := dial(context.Background()); !errors.Is(err, ErrPlatformAnchorRequiredForGRPC) {
		t.Fatalf("err = %v, want ErrPlatformAnchorRequiredForGRPC", err)
	}
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

func TestLoadClientCAsFromPlatformAnchor(t *testing.T) {
	cfg := publicProxyConfig()

	t.Run("anchor pool used", func(t *testing.T) {
		bundle := testutil.GenerateTestTLSBundle(t)
		got, err := loadClientCAs(cfg, fileAnchor(t, bundle.CACertPEM), true)
		if err != nil {
			t.Fatalf("loadClientCAs: %v", err)
		}
		if got == nil || !got.Equal(poolOf(t, bundle.CACertPEM)) {
			t.Fatal("the platform anchor's pool must verify the proxy's callers")
		}
	})

	t.Run("anchor failure fatal when auth needed", func(t *testing.T) {
		missing := trust.NewFileAnchorSource(filepath.Join(t.TempDir(), "absent.pem"))
		anchor, _ := trust.NewAnchor(missing)
		var unavailable *trust.ErrAnchorUnavailable
		if _, err := loadClientCAs(cfg, anchor, true); !errors.As(err, &unavailable) {
			t.Fatalf("err = %v, want *trust.ErrAnchorUnavailable", err)
		}
	})

	t.Run("anchor failure tolerated without auth", func(t *testing.T) {
		anchor, _ := trust.NewAnchor(trust.NewFileAnchorSource(filepath.Join(t.TempDir(), "absent.pem")))
		got, err := loadClientCAs(cfg, anchor, false)
		if err != nil || got != nil {
			t.Fatalf("got %v, %v; want nil, nil", got, err)
		}
	})

	t.Run("no anchor no file", func(t *testing.T) {
		got, err := loadClientCAs(cfg, nil, false)
		if err != nil || got != nil {
			t.Fatalf("got %v, %v; want nil, nil", got, err)
		}
	})
}

// fileAnchor writes caPEM to a file and returns the platform anchor reading
// it, the way gatewayd's `platform-ca-file:` is served.
func fileAnchor(t *testing.T, caPEM []byte) *trust.Anchor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cp-ca.pem")
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	anchor, err := trust.NewAnchor(trust.NewFileAnchorSource(path))
	if err != nil {
		t.Fatal(err)
	}
	return anchor
}

func poolOf(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no certificates in the test CA PEM")
	}
	return pool
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
	if r, err := buildTrustResolver(nil, t.TempDir(), testLogger()); err != nil || r != nil {
		t.Fatalf("nil config must yield nil resolver: %v, %v", r, err)
	}
	bad := &trust.Config{
		Bootstrap: &trust.ScopeConfig{Strategies: []trust.Strategy{"not-a-strategy"}},
	}
	if _, err := buildTrustResolver(bad, t.TempDir(), testLogger()); err == nil {
		t.Fatal("invalid trust config must fail")
	}
}

func TestPlatformdDialGRPCWithPlatformAnchor(t *testing.T) {
	t.Run("anchor failure propagates", func(t *testing.T) {
		anchor, _ := trust.NewAnchor(trust.NewFileAnchorSource(filepath.Join(t.TempDir(), "absent.pem")))
		dial := platformdDial(proxysvc.PlatformdConfig{
			Protocol: proxysvc.PlatformdProtocolGRPC,
			GRPCAddr: "127.0.0.1:1",
		}, anchor)
		var unavailable *trust.ErrAnchorUnavailable
		if _, err := dial(context.Background()); !errors.As(err, &unavailable) {
			t.Fatalf("err = %v, want *trust.ErrAnchorUnavailable", err)
		}
	})

	t.Run("grpc client constructed lazily", func(t *testing.T) {
		// gRPC connections are lazy: construction succeeds and connection
		// failures surface on the first RPC, where the sync loop's lazy
		// client retries them.
		certFile, keyFile, _ := writeTLSFixtures(t)
		dial := platformdDial(proxysvc.PlatformdConfig{
			Protocol: proxysvc.PlatformdProtocolGRPC,
			GRPCAddr: "127.0.0.1:1",
			CertFile: certFile,
			KeyFile:  keyFile,
		}, fileAnchor(t, testutil.GenerateTestTLSBundle(t).CACertPEM))
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

// TestPlatformdGRPCPresentsAClientIdentity pins that every gRPC connection
// gatewayd opens to platformd authenticates: platformd's gRPC listener
// requires an mTLS client certificate or a bearer token, so a connection
// carrying only the platform anchor's server roots is refused at assembly
// rather than failing every RPC with Unauthenticated.
func TestPlatformdGRPCPresentsAClientIdentity(t *testing.T) {
	anchor := fileAnchor(t, testutil.GenerateTestTLSBundle(t).CACertPEM)
	grpcConfig := func() proxysvc.PlatformdConfig {
		return proxysvc.PlatformdConfig{Protocol: proxysvc.PlatformdProtocolGRPC, GRPCAddr: "127.0.0.1:1"}
	}

	t.Run("no identity refused", func(t *testing.T) {
		var cfgErr *proxysvc.ErrConfigInvalid
		if _, err := platformdOptions(context.Background(), grpcConfig(), anchor); !errors.As(err, &cfgErr) {
			t.Fatalf("err = %v, want *proxysvc.ErrConfigInvalid", err)
		}
	})

	t.Run("client certificate presented", func(t *testing.T) {
		certFile, keyFile, _ := writeTLSFixtures(t)
		pcfg := grpcConfig()
		pcfg.CertFile, pcfg.KeyFile = certFile, keyFile
		opts, err := platformdOptions(context.Background(), pcfg, anchor)
		if err != nil {
			t.Fatalf("platformdOptions: %v", err)
		}
		if opts.TLSConfig == nil || len(opts.TLSConfig.Certificates) != 1 {
			t.Fatal("the connection must present the configured client certificate")
		}
		if opts.TLSConfig.RootCAs == nil {
			t.Fatal("the connection must still verify platformd against the platform anchor")
		}
	})

	t.Run("bearer token presented", func(t *testing.T) {
		pcfg := grpcConfig()
		pcfg.TokenFile = filepath.Join(t.TempDir(), "platformd.token")
		if err := os.WriteFile(pcfg.TokenFile, []byte("platform-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		opts, err := platformdOptions(context.Background(), pcfg, anchor)
		if err != nil {
			t.Fatalf("platformdOptions: %v", err)
		}
		if opts.BearerToken != "platform-token" {
			t.Fatalf("BearerToken = %q, want the token file's trimmed content", opts.BearerToken)
		}
	})

	t.Run("unreadable certificate refused", func(t *testing.T) {
		pcfg := grpcConfig()
		pcfg.CertFile = filepath.Join(t.TempDir(), "absent.pem")
		pcfg.KeyFile = filepath.Join(t.TempDir(), "absent.key")
		var loadErr *proxysvc.ErrPlatformdIdentityLoadFailed
		if _, err := platformdOptions(context.Background(), pcfg, anchor); !errors.As(err, &loadErr) {
			t.Fatalf("err = %v, want *proxysvc.ErrPlatformdIdentityLoadFailed", err)
		}
	})

	t.Run("empty token refused", func(t *testing.T) {
		pcfg := grpcConfig()
		pcfg.TokenFile = filepath.Join(t.TempDir(), "platformd.token")
		if err := os.WriteFile(pcfg.TokenFile, []byte(" \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var loadErr *proxysvc.ErrPlatformdIdentityLoadFailed
		if _, err := platformdOptions(context.Background(), pcfg, anchor); !errors.As(err, &loadErr) {
			t.Fatalf("err = %v, want *proxysvc.ErrPlatformdIdentityLoadFailed", err)
		}
	})

	t.Run("overlay dial refused without identity", func(t *testing.T) {
		cfg := &ServeConfig{
			Proxy:   &proxysvc.Config{Platformd: grpcConfig()},
			Gateway: &gateway.GatewayConfig{Overlay: &gateway.OverlayServiceConfig{Enabled: true}},
		}
		var cfgErr *proxysvc.ErrConfigInvalid
		if err := wireOverlayRuntime(context.Background(), cfg, anchor, &gateway.GatewayRuntime{}); !errors.As(err, &cfgErr) {
			t.Fatalf("err = %v, want *proxysvc.ErrConfigInvalid", err)
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

	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); !errors.Is(err, proxy.ErrAttestationGateNotConfigured) {
		t.Fatalf("attestation route without gate = %v, want ErrAttestationGateNotConfigured", err)
	}

	cfg.Attestation.Enabled = true
	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); err != nil {
		t.Fatalf("BuildProxyHandler with attestation gate: %v", err)
	}
}

func TestBuildProxyHandlerTokenRoutesRequireAuthenticator(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.Routes[0].Auth.Mode = proxy.AuthModeMTLSOrToken

	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); !errors.Is(err, proxy.ErrTokenAuthNotConfigured) {
		t.Fatalf("token route without authenticator = %v, want ErrTokenAuthNotConfigured", err)
	}

	cfg.TokenAuth = proxysvc.TokenAuthConfig{
		Enabled:   true,
		Issuer:    "https://broker.example",
		JWKSURL:   "https://broker.example/jwks.json",
		AuthzMode: proxysvc.AuthzModeOffline,
	}
	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); err != nil {
		t.Fatalf("BuildProxyHandler with token auth: %v", err)
	}
}

func TestBuildProxyHandlerTokenAuthInvalidSection(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.TokenAuth = proxysvc.TokenAuthConfig{Enabled: true}
	var cfgErr *proxysvc.ErrTokenAuthConfig
	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); !errors.As(err, &cfgErr) {
		t.Fatalf("invalid token-auth section = %v, want *ErrTokenAuthConfig", err)
	}
}

func TestBuildProxyHandlerOPARoutesRequireEvaluator(t *testing.T) {
	cfg := mtlsProxyConfig(t)
	cfg.Routes[0].Auth.OPAPolicy = "proxy_authz"

	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); !errors.Is(err, proxy.ErrOPANotConfigured) {
		t.Fatalf("opa route without evaluator = %v, want ErrOPANotConfigured", err)
	}

	cfg.OPA.Enabled = true
	if _, err := BuildProxyHandler(cfg, nil, nil, testLogger()); err != nil {
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
	if _, err := dial(context.Background()); !errors.Is(err, ErrPlatformAnchorRequiredForGRPC) {
		t.Fatalf("grpc dial without resolver = %v, want ErrPlatformAnchorRequiredForGRPC", err)
	}
}

func TestLoadServeConfigSDNAndControlPlane(t *testing.T) {
	yaml := []byte(`
gateway:
  enabled: true
  id: gw-edge
sdn:
  enabled: true
  ovs:
    socket: /var/run/openvswitch/db.sock
    bridge: br-fabric
  environment:
    id: 4
    base: 10.0.0.0/8
    overrides:
      - zone: fabric
        subnet: 10.4.100.0/22
control-plane:
  enabled: true
  base-url: https://cp.example.com:8443
  interval: 15s
  cert-file: /etc/gatewayd/idevid.pem
  key-file: /etc/gatewayd/idevid-key.pem
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
	if cfg.SDN == nil || !cfg.SDN.Enabled || cfg.SDN.OVS == nil {
		t.Fatalf("sdn section: %+v", cfg.SDN)
	}
	if cfg.SDN.OVS.Bridge != "br-fabric" || cfg.SDN.OVS.Socket != "/var/run/openvswitch/db.sock" {
		t.Fatalf("ovs subsection: %+v", cfg.SDN.OVS)
	}
	env := cfg.SDN.Environment
	if env == nil || env.ID != 4 || len(env.Overrides) != 1 {
		t.Fatalf("environment: %+v", env)
	}
	// netip.Prefix decodes only through the TextUnmarshaler decode hook;
	// a regression here means prefix-bearing configs fail startup.
	if env.Base.String() != "10.0.0.0/8" || env.Overrides[0].Subnet.String() != "10.4.100.0/22" {
		t.Fatalf("environment prefixes: base %v override %v", env.Base, env.Overrides[0].Subnet)
	}
	if cfg.ControlPlane == nil || !cfg.ControlPlane.Enabled {
		t.Fatalf("control-plane section: %+v", cfg.ControlPlane)
	}
	if cfg.ControlPlane.BaseURL != "https://cp.example.com:8443" ||
		cfg.ControlPlane.Interval != 15*time.Second {
		t.Fatalf("control-plane values: %+v", cfg.ControlPlane)
	}
}

func TestLoadServeConfigInvalidControlPlane(t *testing.T) {
	yaml := []byte(`
control-plane:
  enabled: true
`)
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(yaml)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	var sectionErr *ErrConfigSection
	if _, err := LoadServeConfig(v); !errors.As(err, &sectionErr) || sectionErr.Section != "control-plane" {
		t.Fatalf("err = %v, want *ErrConfigSection{control-plane}", err)
	}
}

func TestBuildHostRuntimeFromProxyListeners(t *testing.T) {
	cfg := &ServeConfig{Proxy: &proxysvc.Config{
		Enabled: true,
		Listeners: []proxysvc.ListenerConfig{
			{ID: "edge", Address: ":8443"},
			{ID: "admin", Address: "127.0.0.1:9443"},
			{ID: "ephemeral", Address: "127.0.0.1:0"},
		},
	}}
	logger := testLogger()
	host, err := buildHostRuntime(cfg, nil, logger)
	if err != nil {
		t.Fatalf("buildHostRuntime: %v", err)
	}
	if host.Logger != logger {
		t.Fatal("host runtime must carry the daemon logger")
	}
	inventory := host.Listeners.(hostfw.StaticInventory)
	if len(inventory) != 2 {
		t.Fatalf("inventory = %+v, want the two fixed-port listeners", inventory)
	}
	ports := map[uint16]bool{}
	for _, l := range inventory {
		ports[l.Port] = true
	}
	if !ports[8443] || !ports[9443] {
		t.Fatalf("inventory ports = %v, want 8443 and 9443", ports)
	}
}

func TestBuildHostRuntimeRejectsBadListenerAddress(t *testing.T) {
	cfg := &ServeConfig{Proxy: &proxysvc.Config{
		Enabled:   true,
		Listeners: []proxysvc.ListenerConfig{{ID: "edge", Address: "no-port"}},
	}}
	_, err := buildHostRuntime(cfg, nil, testLogger())
	var sectionErr *ErrConfigSection
	if !errors.As(err, &sectionErr) {
		t.Fatalf("err = %v, want *ErrConfigSection", err)
	}
	if sectionErr.Section != "proxy.listeners" {
		t.Fatalf("Section = %q, want proxy.listeners", sectionErr.Section)
	}
	var inventoryErr *gateway.ErrListenerInventory
	if !errors.As(err, &inventoryErr) || inventoryErr.Listener != "edge" {
		t.Fatalf("err = %v, want *gateway.ErrListenerInventory for edge", err)
	}
}

func TestBuildHostRuntimeWithoutProxy(t *testing.T) {
	for name, cfg := range map[string]*ServeConfig{
		"nil proxy":      {},
		"disabled proxy": {Proxy: &proxysvc.Config{Enabled: false, Listeners: []proxysvc.ListenerConfig{{ID: "x", Address: "bad"}}}},
		"no listeners":   {Proxy: &proxysvc.Config{Enabled: true}},
	} {
		t.Run(name, func(t *testing.T) {
			host, err := buildHostRuntime(cfg, nil, testLogger())
			if err != nil {
				t.Fatalf("buildHostRuntime: %v", err)
			}
			if host.Listeners != nil {
				t.Fatalf("Listeners = %v, want nil so hostfw falls back to its static default", host.Listeners)
			}
			if host.Logger == nil {
				t.Fatal("Logger must be set")
			}
		})
	}
}

func TestLoadServeConfigSecretStore(t *testing.T) {
	yaml := []byte(`
secret-store:
  quicbaas-addr: 10.4.6.10:9443
  quicbaas-transport: grpc
  timeout: 3s
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
	if cfg.Secrets == nil {
		t.Fatal("secret-store section must decode")
	}
	if cfg.Secrets.QuicBaaSAddr != "10.4.6.10:9443" || cfg.Secrets.QuicBaaSTransport != "grpc" {
		t.Fatalf("secret store: %+v", cfg.Secrets)
	}
	if cfg.Secrets.Timeout != 3*time.Second {
		t.Fatalf("timeout = %v, want 3s", cfg.Secrets.Timeout)
	}
}

func TestLoadServeConfigSecretStoreInvalid(t *testing.T) {
	yaml := []byte(`
secret-store:
  quicbaas-transport: smoke-signal
`)
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(yaml)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	_, err := LoadServeConfig(v)
	var sectionErr *ErrConfigSection
	if !errors.As(err, &sectionErr) || sectionErr.Section != "secret-store" {
		t.Fatalf("err = %v, want *ErrConfigSection for secret-store", err)
	}
}

func TestLoadServeConfigPlatformSecretsSectionIsNotTheStore(t *testing.T) {
	// platformd's own `secrets:` switchboard shares the file; gatewayd
	// must not read it as its store address.
	yaml := []byte(`
secrets:
  enabled: true
  local-kms: true
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
	if cfg.Secrets != nil {
		t.Fatalf("platformd's secrets section decoded as the store: %+v", cfg.Secrets)
	}
}

func TestBuildHostRuntimeWithoutSecretStoreHasNoResolver(t *testing.T) {
	host, err := buildHostRuntime(&ServeConfig{}, nil, testLogger())
	if err != nil {
		t.Fatalf("buildHostRuntime: %v", err)
	}
	if host.SecretResolver != nil {
		t.Fatal("no secret-store section must leave every reference failing closed")
	}
}

func TestBuildHostRuntimeSecretStoreNeedsTrust(t *testing.T) {
	cfg := &ServeConfig{Secrets: &secrets.Config{QuicBaaSAddr: "127.0.0.1:9443"}}
	_, err := buildHostRuntime(cfg, nil, testLogger())
	var sectionErr *ErrConfigSection
	if !errors.As(err, &sectionErr) || sectionErr.Section != "secret-store" {
		t.Fatalf("err = %v, want *ErrConfigSection for secret-store", err)
	}
	var trustErr *secrets.ErrTrustRequired
	if !errors.As(err, &trustErr) {
		t.Fatalf("err = %v, want secrets.ErrTrustRequired", err)
	}
}

func TestBuildHostRuntimeBuildsTheSecretResolver(t *testing.T) {
	// The anchor is the shipped shape — the platform CA bundle provisioning
	// projects onto the node, read through `platform-ca-file:` — so the
	// anchor handed in here is the one a real gateway would carry.
	cfg := &ServeConfig{
		Secrets:        &secrets.Config{QuicBaaSAddr: "127.0.0.1:9443"},
		PlatformCAFile: filepath.Join(t.TempDir(), "cp-ca.pem"),
	}
	if err := os.WriteFile(cfg.PlatformCAFile, testutil.GenerateTestTLSBundle(t).CACertPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		t.Fatalf("buildPlatformAnchor: %v", err)
	}
	host, err := buildHostRuntime(cfg, anchor, testLogger())
	if err != nil {
		t.Fatalf("buildHostRuntime: %v", err)
	}
	if host.SecretResolver == nil {
		t.Fatal("a secret-store section must produce a resolver")
	}
	// The store is reached lazily: resolving a reference is what dials, so
	// an unreachable store surfaces at start, not at assembly.
	if _, err := host.SecretResolver(context.Background(), "not-a-reference"); err == nil {
		t.Fatal("a bare value must not resolve")
	}
}
