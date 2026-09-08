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
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/netutil"

	"github.com/jeremyhahn/go-trusted-platform/pkg/security/ratelimit"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// Edge-surface defaults (#571). A full surface keeps Go's defaults and no
// caps unless configured; a public edge listener gets these unless the
// operator overrides them.
const (
	// EdgeMaxHeaderBytes bounds request headers on an edge listener.
	EdgeMaxHeaderBytes = 64 << 10
	// EdgeMaxConnections caps concurrent TCP connections per edge listener.
	EdgeMaxConnections = 4096
	// EdgeRateLimitPerSecond is the sustained per-source request rate on an
	// edge listener.
	EdgeRateLimitPerSecond = 50
	// EdgeRateLimitBurst is the per-source burst on an edge listener.
	EdgeRateLimitBurst = 100
	// edgeRateLimitIdle is how long an idle source keeps its bucket.
	edgeRateLimitIdle = 5 * time.Minute
)

// ListenerLimits are the resolved per-listener limits a webservice runs
// with: the configured value where set, the surface's default otherwise.
type ListenerLimits struct {
	MaxHeaderBytes int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxConnections int
	RateLimit      *v1.RateLimitConfig
}

// resolveSurface validates the configured surface, returning the effective
// value ("" reads as full).
func resolveSurface(cfg *v1.Config) (string, error) {
	switch cfg.Surface {
	case "", v1.SurfaceFull:
		return v1.SurfaceFull, nil
	case v1.SurfaceEdge:
		return v1.SurfaceEdge, nil
	default:
		return "", &ErrUnknownSurface{Name: cfg.Name, Surface: cfg.Surface}
	}
}

// resolveLimits fills the listener limits from the config, taking the edge
// defaults for zero fields on an edge surface and the historical server
// timeouts on a full one.
func resolveLimits(cfg *v1.Config, surface string) ListenerLimits {
	l := ListenerLimits{
		MaxHeaderBytes: cfg.MaxHeaderBytes,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		IdleTimeout:    cfg.IdleTimeout,
		MaxConnections: cfg.MaxConnections,
		RateLimit:      cfg.RateLimit,
	}
	if l.ReadTimeout <= 0 {
		l.ReadTimeout = HTTP_SERVER_READ_TIMEOUT
	}
	if l.WriteTimeout <= 0 {
		l.WriteTimeout = HTTP_SERVER_WRITE_TIMEOUT
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = HTTP_SERVER_IDLE_TIMEOUT
	}
	if surface == v1.SurfaceEdge {
		if l.MaxHeaderBytes <= 0 {
			l.MaxHeaderBytes = EdgeMaxHeaderBytes
		}
		if l.MaxConnections <= 0 {
			l.MaxConnections = EdgeMaxConnections
		}
		if l.RateLimit == nil {
			l.RateLimit = &v1.RateLimitConfig{RequestsPerSecond: EdgeRateLimitPerSecond, Burst: EdgeRateLimitBurst}
		}
	}
	return l
}

// newHTTPServer builds an http.Server carrying the resolved limits.
func (l ListenerLimits) newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:        handler,
		MaxHeaderBytes: l.MaxHeaderBytes,
		ReadTimeout:    l.ReadTimeout,
		WriteTimeout:   l.WriteTimeout,
		IdleTimeout:    l.IdleTimeout,
	}
}

// limitListener caps concurrent connections on ln when MaxConnections is
// set; otherwise it returns ln unchanged.
func (l ListenerLimits) limitListener(ln net.Listener) net.Listener {
	if l.MaxConnections <= 0 {
		return ln
	}
	return netutil.LimitListener(ln, l.MaxConnections)
}

// newRateLimiter builds the per-source token bucket the limits ask for, or
// nil when they ask for none.
func (l ListenerLimits) newRateLimiter() (*ratelimit.TokenBucketLimiter, error) {
	if l.RateLimit == nil || l.RateLimit.RequestsPerSecond <= 0 {
		return nil, nil
	}
	burst := l.RateLimit.Burst
	if burst <= 0 {
		burst = int(l.RateLimit.RequestsPerSecond)
		if burst < 1 {
			burst = 1
		}
	}
	return ratelimit.NewTokenBucketLimiter(ratelimit.LimitConfig{
		Rate:            l.RateLimit.RequestsPerSecond,
		Burst:           burst,
		CleanupInterval: time.Minute,
		MaxIdleTime:     edgeRateLimitIdle,
	})
}

// sourceLimiter is the subset of the token bucket the middleware needs; a
// test substitutes a deterministic one.
type sourceLimiter interface {
	Allow(key string) bool
}

// rateLimitMiddleware answers 429 to a source that has exhausted its
// bucket. The key is the remote address without its port; a client behind
// the platform's own proxy is keyed by the proxy, which is the honest
// answer until the proxy is the thing terminating the edge.
func rateLimitMiddleware(limiter sourceLimiter, retryAfter string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow(sourceKey(r.RemoteAddr)) {
				w.Header().Set("Retry-After", retryAfter)
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// retryAfter is the Retry-After hint for a refused source: the seconds one
// token takes to replenish at the configured rate, at least one.
func (l ListenerLimits) retryAfter() string {
	if l.RateLimit == nil || l.RateLimit.RequestsPerSecond <= 0 {
		return "1"
	}
	secs := int(math.Ceil(1 / l.RateLimit.RequestsPerSecond))
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// EdgeMaxIncomingStreams bounds the streams one HTTP/3 connection may open on
// an edge listener. netutil.LimitListener caps TCP connections only; QUIC
// connections over UDP are not counted, so this is the per-connection bound
// that keeps one client from holding unbounded stream state. A connection
// cap for QUIC itself is not something quic-go's server exposes; the
// residual risk is documented in docs/web/architecture.md.
const EdgeMaxIncomingStreams = 100

// quicConfig returns the QUIC settings for the HTTP/3 listener: the stream
// bound above on an edge surface, defaults otherwise.
func (l ListenerLimits) quicConfig(surface string) *quic.Config {
	cfg := &quic.Config{}
	if surface == v1.SurfaceEdge {
		cfg.MaxIncomingStreams = EdgeMaxIncomingStreams
		cfg.MaxIncomingUniStreams = EdgeMaxIncomingStreams
	}
	return cfg
}

// sourceKey reduces a remote address to its host so every port a source
// opens shares one bucket.
func sourceKey(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// hostSetMatcher matches a request whose Host is one of hosts, exactly or
// under a `*.suffix` wildcard by exactly one label. It is the virtual-host
// matcher: mux's own Host matcher is a template, not an allowlist.
func hostSetMatcher(hosts []string) mux.MatcherFunc {
	served := make(map[string]string, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h != "" {
			served[strings.ToLower(h)] = h
		}
	}
	return func(r *http.Request, _ *mux.RouteMatch) bool {
		_, ok := matchServedHost(served, requestHost(r))
		return ok
	}
}

// requestHost is the lower-cased request host without port or brackets.
func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

// misdirectedUnlessServed is the edge surface's catch-all: a request for a
// host this webservice serves but a path it does not mount is 404, and a
// request for any other host is 421 — never the SPA, never a route list.
func (server *WebServerV1) misdirectedUnlessServed() http.HandlerFunc {
	served := server.servedHosts()
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := matchServedHost(served, requestHost(r)); !ok {
			http.Error(w, "misdirected request: unknown host", http.StatusMisdirectedRequest)
			return
		}
		http.NotFound(w, r)
	}
}

// ErrUnknownSurface is the startup refusal for a surface value the web
// server does not know. Serving a full surface by accident on what the
// operator meant to be an edge is the failure this prevents.
type ErrUnknownSurface struct {
	Name    string
	Surface string
}

// Error implements the error interface.
func (e *ErrUnknownSurface) Error() string {
	return fmt.Sprintf("webservice %q: unknown surface %q (want %q or %q)",
		e.Name, e.Surface, v1.SurfaceFull, v1.SurfaceEdge)
}

// ErrEdgeSurfaceEmpty is the startup refusal for an edge surface with no
// ACME service and no virtual host: it would mount nothing.
type ErrEdgeSurfaceEmpty struct {
	Name string
}

// Error implements the error interface.
func (e *ErrEdgeSurfaceEmpty) Error() string {
	return fmt.Sprintf("webservice %q: an edge surface with no ACME service and no virtual host mounts nothing", e.Name)
}
