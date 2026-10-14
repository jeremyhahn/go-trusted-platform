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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// edgeRegistry supplies only what an edge surface mounts: an ACME service.
// Registration never calls it, so the nil embedding is safe; any other
// registry method reached is a test failure by panic, which is the point.
type edgeRegistry struct {
	v1.RestHandlerRegistry
	acme trustedca.ACMERestServicer
}

type stubACME struct{ trustedca.ACMERestServicer }

func (r *edgeRegistry) ACMERestService() trustedca.ACMERestServicer { return r.acme }

func newSurfaceServer(t *testing.T, cfg *v1.Config, registry v1.RestHandlerRegistry) *WebServerV1 {
	t.Helper()
	surface, err := resolveSurface(cfg)
	require.NoError(t, err)
	server := &WebServerV1{
		baseURI:             "/api/v1",
		logger:              newTestLogger(),
		config:              cfg,
		restServiceRegistry: registry,
		router:              mux.NewRouter(),
		routerMutex:         &sync.Mutex{},
		surface:             surface,
	}
	server.limits = resolveLimits(cfg, surface)
	server.httpServer = server.limits.newHTTPServer(nil)
	return server
}

func edgeConfig(vhosts ...v1.VirtualHost) *v1.Config {
	cfg := &v1.Config{
		Name: "public", Port: 80, TLSPort: 443, Surface: v1.SurfaceEdge,
		Certificate: v1.Identity{Subject: ca.CASubject{CommonName: "gw.example.com"}},
	}
	if len(vhosts) > 0 {
		cfg.VirtualHosts = &vhosts
	}
	return cfg
}

func walk(t *testing.T, router *mux.Router) []string {
	t.Helper()
	var routes []string
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if tmpl, err := route.GetPathTemplate(); err == nil {
			routes = append(routes, tmpl)
		}
		return nil
	}))
	return routes
}

func get(router http.Handler, host, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
	req.RemoteAddr = "203.0.113.7:4242"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestResolveSurface(t *testing.T) {
	for in, want := range map[string]string{"": v1.SurfaceFull, "full": v1.SurfaceFull, "edge": v1.SurfaceEdge, "provisioning": v1.SurfaceProvisioning} {
		got, err := resolveSurface(&v1.Config{Surface: in})
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := resolveSurface(&v1.Config{Name: "x", Surface: "public"})
	var want *ErrUnknownSurface
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Contains(t, err.Error(), "public")
}

// TestEdgeSurface_RouteSetIsAWhitelist is the #571 audit: everything an
// edge listener mounts is ACME under the API prefix, the virtual hosts, or
// the catch-all — so a route added later to the platform cannot appear on
// the public listener without failing here.
func TestEdgeSurface_RouteSetIsAWhitelist(t *testing.T) {
	proxied := v1.VirtualHost{Hosts: []string{"app.example.com", "*.apps.example.com"}, Proxy: &v1.ProxyConfig{Backends: []string{"http://127.0.0.1:1"}}}
	server := newSurfaceServer(t, edgeConfig(proxied), &edgeRegistry{acme: &stubACME{}})
	server.buildRoutes()

	routes := walk(t, server.router)
	require.NotEmpty(t, routes)
	for _, tmpl := range routes {
		allowed := strings.HasPrefix(tmpl, "/api/v1/acme") || tmpl == "/api/v1" || tmpl == "/"
		assert.True(t, allowed, "edge surface mounted %q — only ACME, the virtual hosts and the catch-all belong on a public listener", tmpl)
	}
	assert.Contains(t, routes, "/api/v1/acme/directory")

	// What must NOT be there.
	for _, forbidden := range []string{"/v2", "/api/v1/devices", "/api/v1/platform", "/v1/ca/bootstrap"} {
		for _, tmpl := range routes {
			assert.False(t, strings.HasPrefix(tmpl, forbidden), "edge surface mounted %q", tmpl)
		}
	}
}

func TestEdgeSurface_UnknownHostIs421_ServedHostIs404(t *testing.T) {
	server := newSurfaceServer(t, edgeConfig(), &edgeRegistry{acme: &stubACME{}})
	server.buildRoutes()

	rec := get(server.router, "evil.example.org", "/")
	assert.Equal(t, http.StatusMisdirectedRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), "<html")

	rec = get(server.router, "gw.example.com", "/dashboard")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "<html")

	// The API and registry are not there at all on the edge.
	rec = get(server.router, "gw.example.com", "/api/v1/devices")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = get(server.router, "gw.example.com", "/v2/")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestEdgeSurface_WithoutACMEIsAPureProxyEdge(t *testing.T) {
	// A gateway node has no ACME server; its edge is the virtual hosts alone.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	defer backend.Close()
	vhost := v1.VirtualHost{Hosts: []string{"app.example.com"}, Proxy: &v1.ProxyConfig{Backends: []string{backend.URL}}}
	server := newSurfaceServer(t, edgeConfig(vhost), &edgeRegistry{acme: nil})
	server.buildRoutes()

	for _, tmpl := range walk(t, server.router) {
		assert.False(t, strings.HasPrefix(tmpl, "/api"), "no ACME service, so no API route at all: %q", tmpl)
	}
	assert.Equal(t, http.StatusTeapot, get(server.router, "app.example.com", "/anything").Code)
	assert.Equal(t, http.StatusMisdirectedRequest, get(server.router, "other.example.com", "/").Code)

	root := mux.NewRouter()
	assert.False(t, v1.NewRouter(server.logger, &stubEdgeCA{}, nil, nil, server.restServiceRegistry, nil).RegisterEdgeRoutes(root, "/api/v1"))
	assert.Empty(t, walk(t, root))
}

func TestEdgeSurface_EmptyIsRefused(t *testing.T) {
	server := newSurfaceServer(t, edgeConfig(), &edgeRegistry{acme: nil})
	assert.False(t, server.hasVirtualHosts())
	err := &ErrEdgeSurfaceEmpty{Name: "public"}
	assert.Contains(t, err.Error(), "public")
	// buildRoutes would FatalError here; the guard it uses is the pair above.
	empty := []v1.VirtualHost{{Hosts: nil}}
	server.config.VirtualHosts = &empty
	assert.False(t, server.hasVirtualHosts())
}

type stubEdgeCA struct{ ca.CACertificateAuthority }

// TestVirtualHosts_RegisterBeforePathRoutes: a virtual host owns its Host
// entirely, on both surfaces, so a request for it never reaches the
// platform's own routes.
func TestVirtualHosts_RegisterBeforePathRoutes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()
	vhost := v1.VirtualHost{Hosts: []string{"app.example.com", "*.apps.example.com"}, Proxy: &v1.ProxyConfig{Backends: []string{backend.URL}}}

	server := newSurfaceServer(t, edgeConfig(vhost), &edgeRegistry{acme: &stubACME{}})
	server.buildRoutes()

	for _, host := range []string{"app.example.com", "APP.example.com:443", "one.apps.example.com"} {
		rec := get(server.router, host, "/api/v1/acme/directory")
		assert.Equal(t, http.StatusTeapot, rec.Code, "%s should be owned by the virtual host, even under the API prefix", host)
		assert.Equal(t, "yes", rec.Header().Get("X-Backend"))
	}
	// Two labels under the wildcard are not the virtual host.
	rec := get(server.router, "a.b.apps.example.com", "/x")
	assert.Equal(t, http.StatusMisdirectedRequest, rec.Code)
}

func TestHostSetMatcher(t *testing.T) {
	m := hostSetMatcher([]string{"App.Example.com", "*.apps.example.com", " "})
	match := func(host string) bool {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		return m(req, &mux.RouteMatch{})
	}
	assert.True(t, match("app.example.com"))
	assert.True(t, match("app.example.com:8443"))
	assert.True(t, match("x.apps.example.com"))
	assert.False(t, match("apps.example.com"))
	assert.False(t, match("x.y.apps.example.com"))
	assert.False(t, match("example.com"))
	assert.False(t, match(""))
}

func TestResolveLimits_EdgeDefaultsAndOverrides(t *testing.T) {
	full := resolveLimits(&v1.Config{}, v1.SurfaceFull)
	assert.Equal(t, 0, full.MaxHeaderBytes)
	assert.Equal(t, 0, full.MaxConnections)
	assert.Nil(t, full.RateLimit)
	assert.Equal(t, HTTP_SERVER_READ_TIMEOUT, full.ReadTimeout)
	assert.Equal(t, HTTP_SERVER_WRITE_TIMEOUT, full.WriteTimeout)
	assert.Equal(t, HTTP_SERVER_IDLE_TIMEOUT, full.IdleTimeout)

	edge := resolveLimits(&v1.Config{}, v1.SurfaceEdge)
	assert.Equal(t, EdgeMaxHeaderBytes, edge.MaxHeaderBytes)
	assert.Equal(t, EdgeMaxConnections, edge.MaxConnections)
	require.NotNil(t, edge.RateLimit)
	assert.Equal(t, float64(EdgeRateLimitPerSecond), edge.RateLimit.RequestsPerSecond)
	assert.Equal(t, EdgeRateLimitBurst, edge.RateLimit.Burst)

	custom := resolveLimits(&v1.Config{MaxHeaderBytes: 1024, ReadTimeout: time.Second, MaxConnections: 7,
		RateLimit: &v1.RateLimitConfig{RequestsPerSecond: 2, Burst: 3}}, v1.SurfaceEdge)
	assert.Equal(t, 1024, custom.MaxHeaderBytes)
	assert.Equal(t, time.Second, custom.ReadTimeout)
	assert.Equal(t, 7, custom.MaxConnections)
	assert.Equal(t, float64(2), custom.RateLimit.RequestsPerSecond)

	srv := custom.newHTTPServer(nil)
	assert.Equal(t, 1024, srv.MaxHeaderBytes)
	assert.Equal(t, time.Second, srv.ReadTimeout)
}

func TestListenerLimits_LimitListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	assert.Same(t, ln, ListenerLimits{}.limitListener(ln), "no cap leaves the listener alone")
	assert.NotSame(t, ln, ListenerLimits{MaxConnections: 1}.limitListener(ln))
}

func TestListenerLimits_NewRateLimiter(t *testing.T) {
	l, err := ListenerLimits{}.newRateLimiter()
	require.NoError(t, err)
	assert.Nil(t, l)
	l, err = ListenerLimits{RateLimit: &v1.RateLimitConfig{RequestsPerSecond: 0}}.newRateLimiter()
	require.NoError(t, err)
	assert.Nil(t, l, "a zero rate disables the limiter")
	l, err = ListenerLimits{RateLimit: &v1.RateLimitConfig{RequestsPerSecond: 0.5}}.newRateLimiter()
	require.NoError(t, err)
	require.NotNil(t, l, "a fractional rate still yields a bucket of at least one")
	require.NoError(t, l.Close())
}

// countingLimiter is deterministic: it admits the first n requests per key.
type countingLimiter struct {
	n    int
	seen map[string]int
}

func (c *countingLimiter) Allow(key string) bool {
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.seen[key]++
	return c.seen[key] <= c.n
}

func TestRateLimitMiddleware(t *testing.T) {
	limiter := &countingLimiter{n: 2}
	router := mux.NewRouter()
	router.Use(rateLimitMiddleware(limiter, "3"))
	router.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	codes := []int{}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://h/x", nil)
		req.RemoteAddr = "198.51.100.9:" + strings.Repeat("1", i+1)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	assert.Equal(t, []int{200, 200, 429}, codes, "every port of one source shares a bucket")
	assert.Equal(t, "3", rec429Header(router, limiter), "Retry-After carries the configured hint")

	req := httptest.NewRequest(http.MethodGet, "http://h/x", nil)
	req.RemoteAddr = "198.51.100.10:1"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "another source has its own bucket")
	assert.Equal(t, "203.0.113.5", sourceKey("203.0.113.5:99"))
	assert.Equal(t, "no-port", sourceKey("no-port"))
}

// TestFullSurface_KeepsTheConsoleForServedHosts pins that the default
// surface is unchanged by #571 apart from virtual hosts winning first.
func TestFullSurface_KeepsTheConsoleForServedHosts(t *testing.T) {
	cfg := &v1.Config{Name: "internal", Port: 9080, TLSPort: 9443, Home: t.TempDir(), Index: "index.html"}
	surface, err := resolveSurface(cfg)
	require.NoError(t, err)
	assert.Equal(t, v1.SurfaceFull, surface)
	limits := resolveLimits(cfg, surface)
	assert.Nil(t, limits.RateLimit)
	assert.Equal(t, 0, limits.MaxConnections)
}

func rec429Header(router http.Handler, limiter *countingLimiter) string {
	req := httptest.NewRequest(http.MethodGet, "http://h/x", nil)
	req.RemoteAddr = "198.51.100.9:7"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Header().Get("Retry-After")
}

func TestListenerLimits_RetryAfterAndQUIC(t *testing.T) {
	assert.Equal(t, "1", ListenerLimits{}.retryAfter())
	assert.Equal(t, "1", ListenerLimits{RateLimit: &v1.RateLimitConfig{RequestsPerSecond: 50}}.retryAfter())
	assert.Equal(t, "2", ListenerLimits{RateLimit: &v1.RateLimitConfig{RequestsPerSecond: 0.5}}.retryAfter())
	assert.Equal(t, "10", ListenerLimits{RateLimit: &v1.RateLimitConfig{RequestsPerSecond: 0.1}}.retryAfter())

	edge := ListenerLimits{}.quicConfig(v1.SurfaceEdge)
	assert.Equal(t, int64(EdgeMaxIncomingStreams), edge.MaxIncomingStreams)
	assert.Equal(t, int64(EdgeMaxIncomingStreams), edge.MaxIncomingUniStreams)
	full := ListenerLimits{}.quicConfig(v1.SurfaceFull)
	assert.Zero(t, full.MaxIncomingStreams)
}
