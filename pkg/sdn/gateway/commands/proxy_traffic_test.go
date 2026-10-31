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

package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// echoed is what the echo backend saw of a proxied request.
type echoed struct {
	Path    string      `json:"path"`
	Headers http.Header `json:"headers"`
}

// startEchoBackend serves every request back as its path and headers, so a
// test sees exactly what the proxy forwarded.
func startEchoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(echoed{Path: r.URL.Path, Headers: r.Header}); err != nil {
			t.Errorf("echo encode: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// mtlsProxyFixture is a started proxy handler on a loopback listener, with
// one client presenting a certificate from the trusted client CA and one
// presenting none.
type mtlsProxyFixture struct {
	baseURL   string
	withCert  *http.Client
	anonymous *http.Client
}

// startMTLSProxy builds the proxy exactly as gatewayd does, from a proxy
// section with an mTLS route and a zone-scoped mTLS route, and starts it.
// Sync is enabled because zone routes need the zone matrix; the platformd
// socket does not exist, so the matrix stays deny-all.
func startMTLSProxy(t *testing.T, backendURL string) *mtlsProxyFixture {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	certFile, keyFile, caFile := writeKeypairFixtures(t, bundle, bundle.ServerCert, "server")

	cfg := &proxysvc.Config{
		Enabled: true,
		TLS: proxysvc.TLSConfig{
			CertFile:     certFile,
			KeyFile:      keyFile,
			ClientCAFile: caFile,
		},
		Listeners: []proxysvc.ListenerConfig{{ID: "test", Address: "127.0.0.1:0"}},
		Routes: []proxysvc.RouteConfig{
			{
				ID:         "echo-mtls",
				PathPrefix: "/echo",
				PoolID:     "echo",
				Auth:       proxysvc.AuthConfig{Mode: proxy.AuthModeMTLS},
			},
			{
				ID:         "echo-zoned",
				PathPrefix: "/zoned",
				PoolID:     "echo",
				Auth: proxysvc.AuthConfig{
					Mode:         proxy.AuthModeMTLS,
					AllowedZones: []string{"control-plane"},
				},
			},
		},
		Pools: []proxysvc.PoolConfig{{
			ID:       "echo",
			Backends: []proxysvc.BackendConfig{{URL: backendURL}},
		}},
		Sync: proxysvc.SyncConfig{Enabled: true, Interval: time.Hour},
		Platformd: proxysvc.PlatformdConfig{
			Protocol: proxysvc.PlatformdProtocolUnix,
			Socket:   filepath.Join(t.TempDir(), "platformd.sock"),
		},
	}

	handler, err := BuildProxyHandler(cfg, nil, nil, testLogger())
	if err != nil {
		t.Fatalf("BuildProxyHandler: %v", err)
	}
	if err := handler.Start(context.Background()); err != nil {
		t.Fatalf("start proxy handler: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := handler.Stop(stopCtx); err != nil {
			t.Errorf("stop proxy handler: %v", err)
		}
	})

	snap := handler.HealthSnapshot()
	if len(snap.Engine.Listeners) != 1 || snap.Engine.Listeners[0].BoundAddress == "" {
		t.Fatalf("no bound listener: %+v", snap.Engine)
	}

	client := func(certs []tls.Certificate) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      bundle.CAPool,
			Certificates: certs,
			MinVersion:   tls.VersionTLS13,
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Timeout: 5 * time.Second, Transport: transport}
	}
	return &mtlsProxyFixture{
		baseURL:   "https://" + snap.Engine.Listeners[0].BoundAddress,
		withCert:  client([]tls.Certificate{bundle.ClientCert}),
		anonymous: client(nil),
	}
}

func (f *mtlsProxyFixture) status(t *testing.T, client *http.Client, path string) int {
	t.Helper()
	resp, err := client.Get(f.baseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	return resp.StatusCode
}

// TestBuildProxyHandler_ServesMTLSTrafficOverARealHandshake drives the proxy
// gatewayd assembles over a real TLS listener: the identity the backend
// sees is derived from the verified client certificate, never from inbound
// headers, and a missing certificate, a zone route without a zone, and an
// unknown path are each refused.
func TestBuildProxyHandler_ServesMTLSTrafficOverARealHandshake(t *testing.T) {
	backend := startEchoBackend(t)
	fixture := startMTLSProxy(t, backend.URL)

	t.Run("MTLSClientReachesBackend", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fixture.baseURL+"/echo/hello", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		// Spoofed identity headers must never survive the proxy hop.
		req.Header.Set("X-TP-Client-ID", "spoofed-identity")
		req.Header.Set("X-TP-Client-Zone", "spoofed-zone")
		req.Header.Set("X-TP-Attested", "true")

		resp, err := fixture.withCert.Do(req)
		if err != nil {
			t.Fatalf("GET /echo/hello: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got echoed
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode echo: %v", err)
		}
		if got.Path != "/echo/hello" {
			t.Fatalf("backend path = %q", got.Path)
		}
		// The proxy authenticated the caller and injected real identity.
		if v := got.Headers.Get("X-TP-Auth-Method"); v != "mtls" {
			t.Fatalf("X-TP-Auth-Method = %q, want mtls", v)
		}
		if v := got.Headers.Get("X-TP-Client-ID"); v == "" || v == "spoofed-identity" {
			t.Fatalf("X-TP-Client-ID = %q: spoofed inbound value survived or identity missing", v)
		}
		if got.Headers.Get("X-TP-Client-Zone") == "spoofed-zone" {
			t.Fatal("spoofed X-TP-Client-Zone survived the proxy hop")
		}
		if got.Headers.Get("X-TP-Attested") == "true" {
			t.Fatal("spoofed X-TP-Attested survived the proxy hop")
		}
		if got.Headers.Get("X-TP-Cert-Fingerprint") == "" {
			t.Fatal("X-TP-Cert-Fingerprint missing")
		}
	})

	t.Run("NoCertificateDenied", func(t *testing.T) {
		if code := fixture.status(t, fixture.anonymous, "/echo/hello"); code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", code)
		}
	})

	t.Run("ZoneRouteFailClosed", func(t *testing.T) {
		// The client certificate carries no platform network-zone extension,
		// so a zone-scoped route must deny it fail-closed even though the
		// certificate chain is valid.
		if code := fixture.status(t, fixture.withCert, "/zoned/secret"); code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (zone fail-closed)", code)
		}
	})

	t.Run("UnmatchedPathNotFound", func(t *testing.T) {
		if code := fixture.status(t, fixture.withCert, "/nowhere"); code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", code)
		}
	})
}
