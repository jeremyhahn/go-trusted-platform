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

package webservice

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

func newPlaintextTestServer(cfg *v1.Config) *WebServerV1 {
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	return &WebServerV1{
		logger:      newTestLogger(),
		config:      cfg,
		router:      router,
		routerMutex: &sync.Mutex{},
	}
}

// TestPlaintextHandler_RedirectsWhenTLSIsConfigured pins #535: with a TLS
// port configured the plaintext port carries nothing but a redirect to it —
// no API, no console, so no credential is ever asked for in the clear.
func TestPlaintextHandler_RedirectsWhenTLSIsConfigured(t *testing.T) {
	server := newPlaintextTestServer(&v1.Config{
		Port: 9080, TLSPort: 9443,
		Certificate: v1.Identity{SANS: &ca.CASubjectAlternativeNames{
			DNS: []string{"cp.example.internal"},
			IPs: []string{"fd00::10"},
		}},
	})
	handler, err := server.plaintextHandler()
	require.NoError(t, err)

	cases := map[string]struct {
		method   string
		target   string
		wantCode int
		wantLoc  string
	}{
		"api route":             {http.MethodGet, "http://cp.example.internal:9080/api/v1/devices?page=2", http.StatusMovedPermanently, "https://cp.example.internal:9443/api/v1/devices?page=2"},
		"console":               {http.MethodGet, "http://cp.example.internal:9080/", http.StatusMovedPermanently, "https://cp.example.internal:9443/"},
		"head":                  {http.MethodHead, "http://cp.example.internal:9080/login", http.StatusMovedPermanently, "https://cp.example.internal:9443/login"},
		"post keeps its method": {http.MethodPost, "http://cp.example.internal:9080/api/v1/auth/login", http.StatusPermanentRedirect, "https://cp.example.internal:9443/api/v1/auth/login"},
		"ipv6 host":             {http.MethodGet, "http://[fd00::10]:9080/x", http.StatusMovedPermanently, "https://[fd00::10]:9443/x"},
		"bare host":             {http.MethodGet, "http://cp.example.internal/x", http.StatusMovedPermanently, "https://cp.example.internal:9443/x"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, c.wantCode, rec.Code)
			assert.Equal(t, c.wantLoc, rec.Header().Get("Location"))
			assert.NotContains(t, rec.Body.String(), "<html", "the console must not be served in the clear")
		})
	}
}

func TestPlaintextHandler_RedirectOmitsThePortFor443(t *testing.T) {
	server := newPlaintextTestServer(&v1.Config{Port: 80, TLSPort: 443,
		Certificate: v1.Identity{Subject: ca.CASubject{CommonName: "gw.example.com"}}})
	handler, err := server.plaintextHandler()
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "http://gw.example.com/acme/directory", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, "https://gw.example.com/acme/directory", rec.Header().Get("Location"))
}

// TestPlaintextHandler_LoopbackOnlyMayServeTheRouter: without a TLS port the
// plaintext listener is the only listener, and it may carry the router only
// when it cannot leave the host.
func TestPlaintextHandler_LoopbackOnlyMayServeTheRouter(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "127.0.0.9"} {
		t.Run(host, func(t *testing.T) {
			server := newPlaintextTestServer(&v1.Config{Port: 9080, BindHost: host})
			handler, err := server.plaintextHandler()
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodGet, "http://localhost:9080/api/v1/devices", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "the router itself should answer")
		})
	}
}

func TestPlaintextHandler_RefusesAnExposedPlaintextOnlyListener(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::", "10.4.2.140", "cp.example.internal"} {
		t.Run("bind-host="+host, func(t *testing.T) {
			server := newPlaintextTestServer(&v1.Config{Name: "internal", Port: 9080, BindHost: host})
			_, err := server.plaintextHandler()
			var want *ErrPlaintextExposure
			require.True(t, errors.As(err, &want), "got %v", err)
			assert.Equal(t, "internal", want.Name)
			assert.Equal(t, 9080, want.Port)
			assert.Contains(t, err.Error(), "internal")
		})
	}
}

func TestPlaintextHandler_NoPlaintextPortMeansNoHandler(t *testing.T) {
	server := newPlaintextTestServer(&v1.Config{TLSPort: 9443})
	handler, err := server.plaintextHandler()
	require.NoError(t, err)
	assert.Nil(t, handler)
}

func TestIsLoopbackHost(t *testing.T) {
	assert.True(t, isLoopbackHost("127.0.0.1"))
	assert.True(t, isLoopbackHost("127.255.255.254"))
	assert.True(t, isLoopbackHost("::1"))
	assert.True(t, isLoopbackHost("localhost"))
	assert.False(t, isLoopbackHost(""))
	assert.False(t, isLoopbackHost("0.0.0.0"))
	assert.False(t, isLoopbackHost("::"))
	assert.False(t, isLoopbackHost("10.0.0.1"))
	assert.False(t, isLoopbackHost("cp.example.internal"))
}

// TestRedirectToTLS_RefusesAnUnknownHost pins the open-redirect fix gosec
// G710 asked for: the Location host comes from configuration, never from
// the request, and a Host the webservice is not configured to answer for
// is a 421, not a redirect to wherever the attacker named.
func TestRedirectToTLS_RefusesAnUnknownHost(t *testing.T) {
	server := newPlaintextTestServer(&v1.Config{Port: 9080, TLSPort: 9443,
		Certificate: v1.Identity{Subject: ca.CASubject{CommonName: "cp.example.internal"}}})
	handler, err := server.plaintextHandler()
	require.NoError(t, err)

	for _, host := range []string{"evil.example.org:9080", "cp.example.internal.evil.example.org", "203.0.113.9"} {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+host+"/login", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusMisdirectedRequest, rec.Code)
			assert.Empty(t, rec.Header().Get("Location"))
		})
	}

	// The configured spelling wins over the request's casing.
	req := httptest.NewRequest(http.MethodGet, "http://CP.EXAMPLE.INTERNAL:9080/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
	assert.Equal(t, "https://cp.example.internal:9443/login", rec.Header().Get("Location"))
}

func TestServedHosts_CollectsEveryConfiguredName(t *testing.T) {
	vhosts := []v1.VirtualHost{{Hosts: []string{"app.example.com", "*.apps.example.com"}}}
	server := newPlaintextTestServer(&v1.Config{
		BindHost: "10.4.2.140",
		Certificate: v1.Identity{
			Subject: ca.CASubject{CommonName: "cp.example.com"},
			SANS:    &ca.CASubjectAlternativeNames{DNS: []string{"cp", "cp.example.internal"}, IPs: []string{"10.4.200.10"}},
		},
		VirtualHosts: &vhosts,
		WebAuthn:     &v1.WebAuthn{RPID: "example.com", RPOrigins: []string{"https://console.example.com:8443"}},
		CORS:         &v1.CORSConfig{AllowedOrigins: []string{"https://ui.example.com", "not a url"}},
	})
	hosts := server.servedHosts()
	for _, want := range []string{"localhost", "127.0.0.1", "::1", "10.4.2.140", "cp.example.com", "cp",
		"cp.example.internal", "10.4.200.10", "app.example.com", "*.apps.example.com", "example.com",
		"console.example.com", "ui.example.com"} {
		assert.Contains(t, hosts, want)
	}
	assert.NotContains(t, hosts, "not a url")
	assert.NotContains(t, hosts, "")

	empty := newPlaintextTestServer(&v1.Config{}).servedHosts()
	assert.Len(t, empty, 3, "loopback only when nothing is configured")
}

func TestMatchServedHost_WildcardVirtualHosts(t *testing.T) {
	served := map[string]string{"cp.example.com": "cp.example.com", "*.apps.example.com": "*.apps.Example.com"}
	host, ok := matchServedHost(served, "cp.example.com")
	require.True(t, ok)
	assert.Equal(t, "cp.example.com", host)

	host, ok = matchServedHost(served, "foo.apps.example.com")
	require.True(t, ok)
	assert.Equal(t, "foo.apps.Example.com", host, "the configured suffix spelling wins")

	for _, bad := range []string{"foo.bar.apps.example.com", "apps.example.com", "example.com", ".apps.example.com", "evil.example.org"} {
		_, ok := matchServedHost(served, bad)
		assert.False(t, ok, bad)
	}
}

// TestShutdown_DrainsThePlaintextServer pins the review finding on #564: the
// plaintext listener is its own http.Server and Shutdown must reach it.
func TestShutdown_DrainsThePlaintextServer(t *testing.T) {
	server := newPlaintextTestServer(&v1.Config{Port: 0, TLSPort: 9443})
	server.closeChan = make(chan bool, 1)
	server.httpServer = &http.Server{Handler: server.router}
	server.plainServer = &http.Server{Handler: http.NotFoundHandler()}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- server.plainServer.Serve(ln) }()

	server.Shutdown()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(10 * time.Second):
		t.Fatal("the plaintext server was not drained by Shutdown")
	}
}
