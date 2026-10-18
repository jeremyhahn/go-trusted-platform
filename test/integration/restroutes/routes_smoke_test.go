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

//go:build integration

// Package restroutes exercises every REST endpoint that the WebUI consumes
// to confirm platformd registers them at runtime.
//
// The intent is a smoke test, not a full functional sweep: each endpoint
// must respond with anything other than the platformd "the requested API
// endpoint does not exist" envelope, which signals the route is mounted
// and a handler ran (even when the underlying service returns an error).
package restroutes

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	envEndpoint = "PLATFORM_REST_ENDPOINT"
	envCAFile   = "PLATFORM_CA_CERT"
	envCertFile = "PLATFORM_CLIENT_CERT"
	envKeyFile  = "PLATFORM_CLIENT_KEY"

	notFoundMessage = "the requested API endpoint does not exist"
)

// route describes one expected REST endpoint.
type route struct {
	method string
	path   string
	body   string // optional JSON body for POST/PUT/PATCH
}

// allRoutes enumerates every REST endpoint the WebUI calls.
// Routes that depend on path-derived IDs use a placeholder that the
// handler will reject with 4xx after the route matches; that still
// proves the route is registered (no 404 envelope).
func allRoutes() []route {
	return []route{
		// Compute
		{http.MethodGet, "/api/v1/compute/vms", ""},
		{http.MethodGet, "/api/v1/compute/vms/test-id", ""},
		{http.MethodGet, "/api/v1/compute/vms/test-id/metrics", ""},
		{http.MethodGet, "/api/v1/compute/vms/test-id/snapshots", ""},
		{http.MethodGet, "/api/v1/compute/containers", ""},
		{http.MethodGet, "/api/v1/compute/containers/test-id", ""},
		{http.MethodGet, "/api/v1/compute/containers/test-id/metrics", ""},

		// TPM
		{http.MethodGet, "/api/v1/tpm/info", ""},
		{http.MethodGet, "/api/v1/tpm/ek", ""},
		{http.MethodGet, "/api/v1/tpm/ek/certificate", ""},
		{http.MethodGet, "/api/v1/tpm/srk", ""},
		{http.MethodGet, "/api/v1/tpm/ak", ""},
		{http.MethodGet, "/api/v1/tpm/eventlog", ""},
		{http.MethodGet, "/api/v1/tpm/pcrs", ""},
		{http.MethodGet, "/api/v1/tpm/nvram/0x1c00002", ""},

		// IDevID
		{http.MethodGet, "/api/v1/idevid", ""},
		{http.MethodGet, "/api/v1/idevid/exists", ""},
		{http.MethodGet, "/api/v1/idevid/certificate", ""},
		{http.MethodGet, "/api/v1/idevid/iak", ""},
		{http.MethodGet, "/api/v1/idevid/iak/exists", ""},
		{http.MethodGet, "/api/v1/idevid/iak/certificate", ""},
		{http.MethodGet, "/api/v1/idevid/attributes", ""},

		// Attestation (server router)
		{http.MethodGet, "/api/v1/attestation/manifests", ""},

		// Tenants
		{http.MethodGet, "/api/v1/tenants", ""},
		{http.MethodGet, "/api/v1/tenants/by-name/test", ""},
		{http.MethodGet, "/api/v1/tenants/test-tenant-id", ""},
		{http.MethodGet, "/api/v1/tenants/test-tenant-id/quotas", ""},
		{http.MethodGet, "/api/v1/tenants/test-tenant-id/usage", ""},
		{http.MethodGet, "/api/v1/tenants/test-tenant-id/bridge", ""},
		{http.MethodGet, "/api/v1/tenants/test-tenant-id/dek", ""},
		{http.MethodGet, "/api/v1/tenants/test-tenant-id/barrier", ""},

		// Invitations
		{http.MethodGet, "/api/v1/invitations", ""},
		{http.MethodGet, "/api/v1/invitations/123", ""},
		{http.MethodGet, "/api/v1/invitations/token/test-token", ""},

		// EAB
		{http.MethodGet, "/api/v1/eab/credentials", ""},
		{http.MethodGet, "/api/v1/eab/credentials/123", ""},
		{http.MethodGet, "/api/v1/eab/credentials/key/test-key", ""},
		{http.MethodGet, "/api/v1/eab/credentials/123/qrcode", ""},
		{http.MethodGet, "/api/v1/eab/credentials/123/url", ""},

		// Gateway
		{http.MethodGet, "/api/v1/gateway/status", ""},
		{http.MethodGet, "/api/v1/gateway/bgp/status", ""},
		{http.MethodGet, "/api/v1/gateway/bgp/peers", ""},
		{http.MethodGet, "/api/v1/gateway/bgp/prefixes", ""},
		{http.MethodGet, "/api/v1/gateway/ipam/pools", ""},
		{http.MethodGet, "/api/v1/gateway/ipam/allocations", ""},

		// Overlay
		{http.MethodGet, "/api/v1/overlay/status", ""},
		{http.MethodGet, "/api/v1/overlay/vteps", ""},
		{http.MethodGet, "/api/v1/overlay/vteps/test-node", ""},
		{http.MethodGet, "/api/v1/overlay/vnis", ""},
		{http.MethodGet, "/api/v1/overlay/tunnels", ""},
		{http.MethodGet, "/api/v1/overlay/macs", ""},

		// PXE
		{http.MethodGet, "/api/v1/pxe/status", ""},
		{http.MethodGet, "/api/v1/pxe/devices", ""},
		{http.MethodGet, "/api/v1/pxe/devices/test-device", ""},
		{http.MethodGet, "/api/v1/pxe/devices/mac/00:00:00:00:00:00", ""},
		{http.MethodGet, "/api/v1/pxe/devices/test-device/events", ""},

		// Pre-existing routes that must still resolve (regression guards)
		{http.MethodGet, "/api/v1/iam/tenants", ""},
		{http.MethodGet, "/api/v1/kms/keys", ""},
		{http.MethodGet, "/api/v1/sdn/bridges", ""},
		{http.MethodGet, "/api/v1/dns/zones", ""},
		{http.MethodGet, "/api/v1/vtpm/instances", ""},
		{http.MethodGet, "/api/v1/platform/health", ""},
		{http.MethodGet, "/api/v1/devices", ""},
		{http.MethodGet, "/api/v1/ca/info", ""},

		// Trust bootstrap at the canonical host-root path — what the go-xkms
		// trust fetcher (and `xkey trust import-platform`) requests. It is
		// mounted on the ROOT router, outside /api/v1, so it is exactly the
		// kind of route the /api/v1 enumeration above would never catch.
		{http.MethodGet, "/v1/ca/bootstrap", ""},
	}
}

// newClient constructs an mTLS-aware HTTP client using env vars exposed by
// the integration runner (PLATFORM_CA_CERT, PLATFORM_CLIENT_CERT,
// PLATFORM_CLIENT_KEY). Falls back to system roots when only the CA env is
// set.
func newClient(t *testing.T) *http.Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile := os.Getenv(envCAFile); caFile != "" {
		caBytes, err := os.ReadFile(caFile)
		require.NoError(t, err, "read PLATFORM_CA_CERT")
		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(caBytes), "parse CA cert")
		tlsCfg.RootCAs = pool
	}
	certFile := os.Getenv(envCertFile)
	keyFile := os.Getenv(envKeyFile)
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		require.NoError(t, err, "load mTLS client cert/key")
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// TestRESTRoutes_AllRegistered verifies every WebUI-consumed REST endpoint
// is mounted on the running platformd. A 404 with the well-known
// "endpoint does not exist" message indicates the route is not registered;
// any other response (including 5xx from a downstream service) proves the
// route exists.
func TestRESTRoutes_AllRegistered(t *testing.T) {
	endpoint := os.Getenv(envEndpoint)
	if endpoint == "" {
		t.Fatalf("%s not set; run via run-integration-tests.sh, which exports it for the running platformd", envEndpoint)
	}
	client := newClient(t)
	for _, r := range allRoutes() {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			var body io.Reader
			if r.body != "" {
				body = strings.NewReader(r.body)
			}
			req, err := http.NewRequest(r.method, endpoint+r.path, body)
			require.NoError(t, err)
			req.Header.Set("Accept", "application/json")
			if r.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := client.Do(req)
			require.NoError(t, err, "request %s %s", r.method, r.path)
			defer resp.Body.Close()
			payload, _ := io.ReadAll(resp.Body)
			assertRouteRegistered(t, resp.StatusCode, payload)
		})
	}
}

func assertRouteRegistered(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != http.StatusNotFound {
		return
	}
	// 404 with the platform's "endpoint does not exist" envelope means the
	// route was not mounted; any other 404 (e.g. resource id missing) is a
	// legitimate downstream response.
	var env struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &env); err == nil {
		assert.NotEqual(t, notFoundMessage, env.Message,
			fmt.Sprintf("route appears unregistered: status=404 body=%s", string(body)))
	}
}

// TestRESTRoutes_NoRouteInventory pins the removal of GET /endpoints (#551).
// The route walked the mux and handed any caller every registered template,
// gated paths included, with no credential. A live daemon must not answer it
// with a route list; the debug flag's debugRoutes() logs the inventory for
// operators instead of serving it.
func TestRESTRoutes_NoRouteInventory(t *testing.T) {
	endpoint := os.Getenv(envEndpoint)
	require.NotEmpty(t, endpoint, "%s must point at the running platformd", envEndpoint)
	client := newClient(t)

	req, err := http.NewRequest(http.MethodGet, endpoint+"/endpoints", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)

	// The status is not the signal: with the console deployed the SPA
	// catch-all answers 200 with index.html for any unknown path, and
	// without it the answer is 404. What must never come back is the old
	// payload — a JSON list of route templates.
	assert.False(t, looksLikeRouteInventory(payload),
		"the route inventory oracle is back (status %d): %s", resp.StatusCode, string(payload))
}

// looksLikeRouteInventory reports whether body is a JSON list of route
// templates: the removed handler wrote []string through the response
// writer, which encodes it as a bare array.
func looksLikeRouteInventory(body []byte) bool {
	var templates []string
	if err := json.Unmarshal(body, &templates); err != nil {
		return false
	}
	for _, tmpl := range templates {
		if strings.HasPrefix(tmpl, "/") {
			return true
		}
	}
	return false
}
