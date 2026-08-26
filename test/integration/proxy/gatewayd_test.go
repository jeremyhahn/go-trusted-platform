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

//go:build integration

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	gwcommands "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/commands"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gatewaydFixture is one running in-process gatewayd proxy handler.
//
// The suite assembles gatewayd through gwcommands.BuildProxyHandler — the
// exact function the gatewayd serve command runs — rather than launching
// the binary: the devcontainer harness only manages platformd, and the
// in-process handler exposes HealthSnapshot for deterministic (ticker-
// bounded, sleep-free) sync assertions the binary cannot offer.
type gatewaydFixture struct {
	handler   *proxysvc.Handler
	baseURL   string
	clientCA  *tls.Config // client with platform mTLS cert
	anonymous *tls.Config // client without a certificate
}

// startGatewayd assembles and starts the proxy handler with static mtls
// routes fronting the echo backend and the platformd sync loop enabled
// over the Unix socket.
func startGatewayd(t *testing.T, echoURL string) *gatewaydFixture {
	t.Helper()
	endpoints := GetServiceEndpoints()
	gwTLS := GenerateGatewayTLS(t)

	cfg := &proxysvc.Config{
		Enabled: true,
		TLS: proxysvc.TLSConfig{
			CertFile:     gwTLS.CertFile,
			KeyFile:      gwTLS.KeyFile,
			ClientCAFile: os.Getenv(EnvCACert),
		},
		Listeners: []proxysvc.ListenerConfig{{ID: "test", Address: "127.0.0.1:0"}},
		Routes: []proxysvc.RouteConfig{
			{
				ID:         "echo-mtls",
				PathPrefix: "/echo",
				Pool:       "echo",
				Auth:       proxysvc.AuthConfig{Mode: "mtls"},
			},
			{
				ID:         "echo-zoned",
				PathPrefix: "/zoned",
				Pool:       "echo",
				Auth: proxysvc.AuthConfig{
					Mode:         "mtls",
					AllowedZones: []string{"trusted"},
				},
			},
		},
		Pools: []proxysvc.PoolConfig{{
			ID:       "echo",
			Backends: []proxysvc.BackendConfig{{URL: echoURL}},
		}},
		Sync: proxysvc.SyncConfig{
			Enabled:  true,
			Interval: time.Second,
		},
		Platformd: proxysvc.PlatformdConfig{
			Protocol: proxysvc.PlatformdProtocolUnix,
			Socket:   endpoints.PlatformUnix,
		},
	}

	handler, err := gwcommands.BuildProxyHandler(cfg, nil, nil)
	if err != nil {
		t.Fatalf("BuildProxyHandler: %v", err)
	}
	if err := handler.Start(context.Background()); err != nil {
		t.Fatalf("start proxy handler: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := handler.Stop(stopCtx); err != nil {
			t.Errorf("stop proxy handler: %v", err)
		}
	})

	snap := handler.HealthSnapshot()
	if len(snap.Engine.Listeners) != 1 || snap.Engine.Listeners[0].BoundAddress == "" {
		t.Fatalf("no bound listener: %+v", snap.Engine)
	}
	baseURL := "https://" + snap.Engine.Listeners[0].BoundAddress

	// Client with the platform mTLS certificate, trusting the gatewayd
	// listener through the ephemeral CA.
	withCert := PlatformClientTLS(t)
	withCert.RootCAs = gwTLS.CAPool

	anonymous := &tls.Config{
		RootCAs:    gwTLS.CAPool,
		MinVersion: tls.VersionTLS13,
	}

	return &gatewaydFixture{
		handler:   handler,
		baseURL:   baseURL,
		clientCA:  withCert,
		anonymous: anonymous,
	}
}

// httpClient builds a client for one TLS identity.
func httpClient(tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// TestGatewaydProxyTraffic runs the end-to-end data-plane scenarios: the
// legacy echo app protected behind mTLS, zone fail-closed denial,
// header-spoofing defense, and platformd-driven hot reload.
func TestGatewaydProxyTraffic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	echo := StartEchoBackend(t)
	fixture := startGatewayd(t, echo.URL)

	t.Run("MTLSClientReachesBackend", func(t *testing.T) {
		client := httpClient(fixture.clientCA)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fixture.baseURL+"/echo/hello", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		// Spoofed identity headers must never survive the proxy hop.
		req.Header.Set("X-TP-Client-ID", "spoofed-identity")
		req.Header.Set("X-TP-Client-Zone", "spoofed-zone")
		req.Header.Set("X-TP-Attested", "true")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /echo/hello: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		echoed := DecodeEcho(t, resp)
		if echoed.Path != "/echo/hello" {
			t.Fatalf("backend path = %q", echoed.Path)
		}
		// The proxy authenticated the caller and injected real identity.
		if got := echoed.Headers.Get("X-TP-Auth-Method"); got != "mtls" {
			t.Fatalf("X-TP-Auth-Method = %q, want mtls", got)
		}
		if got := echoed.Headers.Get("X-TP-Client-ID"); got == "" || got == "spoofed-identity" {
			t.Fatalf("X-TP-Client-ID = %q: spoofed inbound value survived or identity missing", got)
		}
		if got := echoed.Headers.Get("X-TP-Client-Zone"); got == "spoofed-zone" {
			t.Fatal("spoofed X-TP-Client-Zone survived the proxy hop")
		}
		if got := echoed.Headers.Get("X-TP-Attested"); got == "true" {
			t.Fatal("spoofed X-TP-Attested survived the proxy hop")
		}
		if got := echoed.Headers.Get("X-TP-Cert-Fingerprint"); got == "" {
			t.Fatal("X-TP-Cert-Fingerprint missing")
		}
	})

	t.Run("NoCertificateDenied", func(t *testing.T) {
		client := httpClient(fixture.anonymous)
		resp, err := client.Get(fixture.baseURL + "/echo/hello")
		if err != nil {
			t.Fatalf("GET without cert: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("ZoneRouteFailClosed", func(t *testing.T) {
		// The harness client certificate carries no platform network-zone
		// extension, so a zone-scoped route must deny it fail-closed even
		// though the certificate chain is valid.
		client := httpClient(fixture.clientCA)
		resp, err := client.Get(fixture.baseURL + "/zoned/secret")
		if err != nil {
			t.Fatalf("GET /zoned: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (zone fail-closed)", resp.StatusCode)
		}
	})

	t.Run("UnmatchedPathNotFound", func(t *testing.T) {
		client := httpClient(fixture.clientCA)
		resp, err := client.Get(fixture.baseURL + "/nowhere")
		if err != nil {
			t.Fatalf("GET /nowhere: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("HotReloadFromPlatformd", func(t *testing.T) {
		testHotReload(t, ctx, fixture, echo.URL)
	})
}

// testHotReload provisions a runtime route via platformctl, waits (ticker-
// bounded) for the gatewayd sync loop to apply it, verifies live routing,
// then updates the route and verifies the change is picked up.
func testHotReload(t *testing.T, ctx context.Context, fixture *gatewaydFixture, echoURL string) {
	t.Helper()

	cli := NewCLIAdapter()
	if err := cli.Setup(ctx); err != nil {
		t.Fatalf("CLI setup: %v", err)
	}
	t.Cleanup(func() { cli.Teardown() })

	poolID := UniqueID("gw-echo")
	routeID := UniqueID("gw-runtime")

	callCtx, cancel := ShortContext(ctx)
	defer cancel()
	if _, _, err := cli.CreatePool(callCtx, &platformv1.ProxyPool{
		Id:       poolID,
		Backends: []*platformv1.ProxyBackend{{Url: echoURL}},
	}); err != nil {
		t.Fatalf("CreatePool: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cli.DeleteRoute(cleanupCtx, routeID)
		cli.DeletePool(cleanupCtx, poolID)
	})

	_, createVersion, err := cli.CreateRoute(callCtx, &platformv1.ProxyRoute{
		Id:         routeID,
		PathPrefix: "/runtime",
		PoolId:     poolID,
		Auth:       &platformv1.ProxyAuthRequirements{Mode: "public"},
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	// Wait for the sync loop to apply the new version.
	WaitFor(t, 30*time.Second, 250*time.Millisecond,
		fmt.Sprintf("gatewayd sync to reach version %d", createVersion),
		func() bool {
			snap := fixture.handler.HealthSnapshot()
			return snap.Sync != nil && snap.Sync.Synced && snap.Sync.Version >= createVersion
		})

	// The runtime route serves live traffic (public route, no client cert).
	client := httpClient(fixture.anonymous)
	resp, err := client.Get(fixture.baseURL + "/runtime/ping")
	if err != nil {
		t.Fatalf("GET /runtime/ping: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("runtime route status = %d, want 200", resp.StatusCode)
	}
	echoed := DecodeEcho(t, resp)
	if echoed.Path != "/runtime/ping" {
		t.Fatalf("backend path = %q", echoed.Path)
	}

	// Update the route path and verify the change goes live.
	_, updateVersion, err := cli.UpdateRoute(callCtx, &platformv1.ProxyRoute{
		Id:         routeID,
		PathPrefix: "/runtime-v2",
		PoolId:     poolID,
		Auth:       &platformv1.ProxyAuthRequirements{Mode: "public"},
	})
	if err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	WaitFor(t, 30*time.Second, 250*time.Millisecond,
		fmt.Sprintf("gatewayd sync to reach version %d", updateVersion),
		func() bool {
			snap := fixture.handler.HealthSnapshot()
			return snap.Sync != nil && snap.Sync.Version >= updateVersion
		})

	resp, err = client.Get(fixture.baseURL + "/runtime-v2/ping")
	if err != nil {
		t.Fatalf("GET /runtime-v2/ping: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("updated route status = %d, want 200", resp.StatusCode)
	}
	resp, err = client.Get(fixture.baseURL + "/runtime/ping")
	if err != nil {
		t.Fatalf("GET old path: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("old path status = %d, want 404 after reload", resp.StatusCode)
	}
}

// TestGatewaydAssemblyLifecycle proves the full BuildGateway assembly
// (gateway node + registered proxy handler) starts and stops cleanly with
// the platformd sync loop attached — the exact serve-command code path.
func TestGatewaydAssemblyLifecycle(t *testing.T) {
	echo := StartEchoBackend(t)
	endpoints := GetServiceEndpoints()
	gwTLS := GenerateGatewayTLS(t)

	cfg := &gwcommands.ServeConfig{
		Proxy: &proxysvc.Config{
			Enabled: true,
			TLS: proxysvc.TLSConfig{
				CertFile:     gwTLS.CertFile,
				KeyFile:      gwTLS.KeyFile,
				ClientCAFile: os.Getenv(EnvCACert),
			},
			Listeners: []proxysvc.ListenerConfig{{ID: "test", Address: "127.0.0.1:0"}},
			Routes: []proxysvc.RouteConfig{{
				ID:         "echo",
				PathPrefix: "/",
				Pool:       "echo",
				Auth:       proxysvc.AuthConfig{Mode: "mtls"},
			}},
			Pools: []proxysvc.PoolConfig{{
				ID:       "echo",
				Backends: []proxysvc.BackendConfig{{URL: echo.URL}},
			}},
			Sync: proxysvc.SyncConfig{Enabled: true, Interval: time.Second},
			Platformd: proxysvc.PlatformdConfig{
				Protocol: proxysvc.PlatformdProtocolUnix,
				Socket:   endpoints.PlatformUnix,
			},
		},
	}

	gw, err := gwcommands.BuildGateway(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("BuildGateway: %v", err)
	}
	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("gateway Start: %v", err)
	}
	if !gw.HasService("proxy") {
		t.Fatal("proxy service not active")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := gw.Stop(stopCtx); err != nil {
		t.Fatalf("gateway Stop: %v", err)
	}
}
