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

// @title Trusted Platform
// @version 0.0.6-alpha.1
// @description The Trusted Platform RESTful Web Services API
// @termsOfService https://letstrust.org/terms

// @contact.name API Support
// @contact.url https://letstrust.org/support
// @contact.email support@letstrust.org

// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.txt

// @license.name Commercial
// @license.url https://letstrust.org/licenses/commercial.txt

// @BasePath /api/v1
// schemes: [http, https, ws, wss]
// @securityDefinitions.apikey JWT
// @in header
// @name Authorization

package webservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/ratelimit"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webserver/embed"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restca "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/ca"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

const (
	HTTP_CLIENT_TIMEOUT       = 10 * time.Second
	HTTP_SERVER_READ_TIMEOUT  = 5 * time.Second
	HTTP_SERVER_WRITE_TIMEOUT = 30 * time.Second
	HTTP_SERVER_IDLE_TIMEOUT  = 120 * time.Second

	defaultIndexTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to {{.VirtualHost}}</h1>
</body>
</html>`
)

var (
	ErrLoadTlsCerts = errors.New("webserver: unable to load TLS certificates")
	ErrBindPort     = errors.New("webserver: unable to bind to web service port")
)

// apiPathPrefixes lists the URL path namespaces the API routers own. An
// unclaimed path under one of these prefixes is a missing endpoint, not a
// console route: it gets a JSON 404 so the client sees the route it asked
// for rather than an HTML page that only fails further downstream.
//
//   - /api/          the platform REST surface (/api/v1/...)
//   - /v1/           canonical root-anchored contracts (trust bootstrap:
//     /v1/ca/bootstrap, go-xkms trust/fetcher DefaultBundlePath)
//   - /v2/           the OCI Distribution surface, which the spec anchors
//     at the host root
//   - /.well-known/  RFC 8615 discovery documents (OIDC metadata, JWKS)
var apiPathPrefixes = []string{
	"/api/",
	"/v1/",
	"/v2/",
	"/.well-known/",
}

// staticAssetPathPrefixes lists URL path namespaces that hold build output.
// A miss there is a missing asset, so it gets a plain 404 rather than the
// SPA shell — serving index.html for a missing script yields a syntax error
// in the browser instead of a 404 in the network tab.
var staticAssetPathPrefixes = []string{
	"/_next/",
	"/static/",
}

// isNonSPAPath reports whether path should never be handled by the SPA
// fallback. This prevents the embedded Next.js frontend from intercepting
// REST API requests and returning HTML instead of JSON.
func isNonSPAPath(path string) bool {
	if isAPIPath(path) {
		return true
	}
	return hasAnyPrefix(path, staticAssetPathPrefixes)
}

// isAPIPath reports whether path belongs to an API namespace.
func isAPIPath(path string) bool {
	return hasAnyPrefix(path, apiPathPrefixes)
}

// hasAnyPrefix reports whether path starts with any of the given prefixes.
func hasAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// writeJSONNotFound writes a JSON-formatted 404 response for API paths.
// Non-API paths receive the standard plain-text http.NotFound response.
func writeJSONNotFound(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "not found",
			"path":    r.URL.Path,
			"message": "the requested API endpoint does not exist",
		})
		return
	}
	http.NotFound(w, r)
}

type WebServerV1 struct {
	ctx          context.Context
	baseURI      string
	ca           trustedca.CACertificateAuthority
	caConfig     *trustedca.CAConfig
	closeChan    chan bool
	certReloader atomic.Pointer[bootstrap.CertReloader]
	config       *v1.Config
	debug        bool
	eventType    string
	httpServer   *http.Server
	// plainServer serves the plaintext port (the TLS redirect, or the
	// router on loopback); it is separate from httpServer so a runtime
	// route rebuild on the TLS side cannot leak into it, and Shutdown
	// drains both (#535).
	plainServer *http.Server
	// h3 is the HTTP/3 listener startHTTPS opens; stored atomically
	// because startHTTPS runs on its own goroutine, and Shutdown closes
	// and joins it.
	h3 atomic.Pointer[h3Listener]
	// surface and limits are resolved once from config (#571); limiter is
	// the per-source token bucket both listeners share, nil when none.
	surface             string
	limits              ListenerLimits
	limiter             *ratelimit.TokenBucketLimiter
	logger              *logging.Logger
	middleware          middleware.JsonWebTokenMiddleware
	restServiceRegistry v1.RestHandlerRegistry
	router              *mux.Router
	routerMutex         *sync.Mutex
	keyAttributes       *xkmssdk.KeyAttributes
}

// h3Listener is the HTTP/3 server, the UDP socket it serves, and done,
// closed once its Serve goroutine has returned.
type h3Listener struct {
	server *http3.Server
	conn   net.PacketConn
	done   chan struct{}
}

// ErrHTTP3Shutdown is a step of the HTTP/3 shutdown that failed: drain
// (the graceful Shutdown did not finish within the shutdown context), close
// (the Close fallback failed) or socket (the UDP socket did not close).
type ErrHTTP3Shutdown struct {
	Step  string
	Cause error
}

func (e *ErrHTTP3Shutdown) Error() string {
	return fmt.Sprintf("webserver: HTTP/3 shutdown %s: %v", e.Step, e.Cause)
}

func (e *ErrHTTP3Shutdown) Unwrap() error { return e.Cause }

// isServerClosed reports whether err is the clean exit an HTTP/3 Serve
// returns after Close or Shutdown.
func isServerClosed(err error) bool {
	return errors.Is(err, http.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed)
}

func NewWebServerV1(
	ctx context.Context,
	debug bool,
	logger *logging.Logger,
	_ca trustedca.CACertificateAuthority,
	caConfig *trustedca.CAConfig,
	config *v1.Config,
	restServiceRegistry v1.RestHandlerRegistry,
	keyAttributes *xkmssdk.KeyAttributes) *WebServerV1 {

	if _ca == nil {
		logger.FatalError(trustedca.CAErrNotInitialized)
	}

	webserver := &WebServerV1{
		ctx:                 ctx,
		baseURI:             "/api/v1",
		ca:                  _ca,
		caConfig:            caConfig,
		closeChan:           make(chan bool, 1),
		config:              config,
		debug:               debug,
		eventType:           "WebServer",
		logger:              logger,
		middleware:          restServiceRegistry.JSONWebTokenHandler(),
		restServiceRegistry: restServiceRegistry,
		router:              mux.NewRouter().StrictSlash(true),
		routerMutex:         &sync.Mutex{},
		keyAttributes:       keyAttributes,
	}

	// The surface and the listener limits are settled here, before any
	// listener exists: an unknown surface and an unbuildable limiter are
	// startup defects (#571).
	surface, err := resolveSurface(config)
	if err != nil {
		logger.FatalError(err)
	}
	webserver.surface = surface
	webserver.limits = resolveLimits(config, surface)
	limiter, err := webserver.limits.newRateLimiter()
	if err != nil {
		logger.FatalError(err)
	}
	webserver.limiter = limiter
	webserver.httpServer = webserver.limits.newHTTPServer(webserver.router)
	webserver.plainServer = webserver.limits.newHTTPServer(nil)
	// A plaintext-only listener that can leave the host is a startup
	// defect, not a degraded node (#535); refuse before anything binds.
	if _, err := webserver.plaintextHandler(); err != nil {
		logger.FatalError(err)
	}
	return webserver
}

// Shutdown the web server
func (server *WebServerV1) Shutdown() {
	server.logger.Info("webserver: shutting down")
	server.closeChan <- true
	close(server.closeChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if server.plainServer != nil {
		if err := server.plainServer.Shutdown(ctx); err != nil {
			server.logger.Warn("webserver: plaintext listener did not drain", slog.String("error", err.Error()))
		}
	}
	if err := server.httpServer.Shutdown(ctx); err != nil {
		server.logger.Warn("webserver: TLS listener did not drain", slog.String("error", err.Error()))
	}
	if err := server.shutdownHTTP3(ctx); err != nil {
		server.logger.Warn("webserver: HTTP/3 listener did not drain", slog.String("error", err.Error()))
	}
	if server.limiter != nil {
		if err := server.limiter.Close(); err != nil {
			server.logger.Warn("webserver: rate limiter did not close", slog.String("error", err.Error()))
		}
	}
}

// shutdownHTTP3 drains the HTTP/3 server startHTTPS opened within ctx,
// closes it when the drain fails or ctx expires, waits for its Serve
// goroutine to return, then releases the UDP socket. It does nothing when
// startHTTPS never ran.
func (server *WebServerV1) shutdownHTTP3(ctx context.Context) error {
	h3 := server.h3.Load()
	if h3 == nil {
		return nil
	}
	var errs []error
	// Shutdown sends GOAWAY and waits, within ctx, for the in-flight
	// requests to complete; Close is the fallback that aborts them.
	if err := h3.server.Shutdown(ctx); err != nil {
		errs = append(errs, &ErrHTTP3Shutdown{Step: "drain", Cause: err})
		if err := h3.server.Close(); err != nil {
			errs = append(errs, &ErrHTTP3Shutdown{Step: "close", Cause: err})
		}
	}
	// Shutdown and Close both close the listener Serve accepts from, so
	// Serve returns and closes done.
	<-h3.done
	if err := h3.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		errs = append(errs, &ErrHTTP3Shutdown{Step: "socket", Cause: err})
	}
	return errors.Join(errs...)
}

// Starts the web server
func (server *WebServerV1) Run() {
	server.buildRoutes()

	// Start HTTP / HTTPS servers
	if server.config.TLSPort > 0 {
		go server.startHTTPS()
	}
	plaintext, err := server.plaintextHandler()
	if err != nil {
		server.logger.FatalError(err)
	}
	if plaintext != nil {
		go server.startHTTP(plaintext)
	}

	<-server.closeChan
}

// plaintextHandler decides what the plaintext port carries (#535).
//
// With a TLS port configured it carries a redirect to that port and
// nothing else: no API, no console, so a client is never invited to send a
// credential in the clear. Without a TLS port the plaintext listener is
// the only listener and may carry the router only when bound to loopback,
// where it cannot leave the host; anything else is ErrPlaintextExposure.
// No plaintext port at all yields a nil handler.
func (server *WebServerV1) plaintextHandler() (http.Handler, error) {
	if server.config.Port <= 0 {
		return nil, nil
	}
	if server.config.TLSPort > 0 {
		return redirectToTLS(server.config.TLSPort, server.servedHosts()), nil
	}
	if isLoopbackHost(server.config.BindHost) {
		return server.routerHandler(), nil
	}
	return nil, &ErrPlaintextExposure{
		Name:     server.config.Name,
		BindHost: server.config.BindHost,
		Port:     server.config.Port,
	}
}

// routerHandler returns the live router under the router mutex, so a
// loopback plaintext listener follows runtime route rebuilds exactly as
// the TLS listener does.
func (server *WebServerV1) routerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.routerMutex.Lock()
		router := server.router
		server.routerMutex.Unlock()
		router.ServeHTTP(w, r)
	})
}

// servedHosts is the set of host names this webservice is configured to
// answer for, keyed by lower-cased name with the configured spelling as
// the value: the certificate subject and its DNS and IP SANs, every
// virtual host, the WebAuthn relying-party id and origins, the CORS
// origins, the bind host when it is an address, and loopback. It is what
// the plaintext redirect trusts instead of the request's Host header.
func (server *WebServerV1) servedHosts() map[string]string {
	hosts := map[string]string{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if h, _, err := net.SplitHostPort(name); err == nil {
			name = h
		}
		name = strings.Trim(name, "[]")
		if name != "" {
			hosts[strings.ToLower(name)] = name
		}
	}
	addOrigin := func(origin string) {
		if u, err := url.Parse(origin); err == nil && u.Host != "" {
			add(u.Host)
		}
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	cfg := server.config
	add(cfg.BindHost)
	add(cfg.Certificate.Subject.CommonName)
	if cfg.Certificate.SANS != nil {
		for _, n := range cfg.Certificate.SANS.DNS {
			add(n)
		}
		for _, n := range cfg.Certificate.SANS.IPs {
			add(n)
		}
	}
	if cfg.VirtualHosts != nil {
		for _, vh := range *cfg.VirtualHosts {
			for _, n := range vh.Hosts {
				add(n)
			}
		}
	}
	if cfg.WebAuthn != nil {
		add(cfg.WebAuthn.RPID)
		for _, o := range cfg.WebAuthn.RPOrigins {
			addOrigin(o)
		}
	}
	if cfg.CORS != nil {
		for _, o := range cfg.CORS.AllowedOrigins {
			addOrigin(o)
		}
	}
	return hosts
}

// matchServedHost resolves a lower-cased requested host against the served
// set: an exact entry wins and yields the configured spelling; otherwise a
// wildcard virtual host `*.suffix` matches exactly one extra label, and the
// result is that label joined to the configured suffix — so a wildcard
// still bounds the Location to a configured domain.
func matchServedHost(served map[string]string, requested string) (string, bool) {
	if host, ok := served[requested]; ok {
		return host, true
	}
	label, rest, found := strings.Cut(requested, ".")
	if !found || label == "" || strings.ContainsAny(label, "/\\@:?#") {
		return "", false
	}
	if suffix, ok := served["*."+rest]; ok {
		return label + strings.TrimPrefix(suffix, "*"), true
	}
	return "", false
}

// redirectToTLS answers every request for a served host with a permanent
// redirect to the same path and query on the TLS port. The host in the
// Location header is the configured spelling looked up from served, never
// the request's Host header, so a forged Host cannot turn the redirect
// into an open redirect; an unknown host is answered 421 Misdirected
// Request. GET and HEAD take 301; other methods take 308 so a client that
// retries keeps its method and body rather than degrading to a GET.
func redirectToTLS(tlsPort int, served map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := r.Host
		if h, _, err := net.SplitHostPort(requested); err == nil {
			requested = h
		}
		host, ok := matchServedHost(served, strings.ToLower(strings.Trim(requested, "[]")))
		if !ok {
			http.Error(w, "misdirected request: unknown host", http.StatusMisdirectedRequest)
			return
		}
		authority := net.JoinHostPort(host, strconv.Itoa(tlsPort))
		if tlsPort == 443 {
			authority = host
			if strings.Contains(host, ":") {
				authority = "[" + host + "]"
			}
		}
		// Only the path and query travel from the request; the scheme and
		// authority are fixed above and url.URL re-encodes the path, so a
		// caller cannot smuggle a second authority into the Location.
		target := (&url.URL{
			Scheme:   "https",
			Host:     authority,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}).String()
		code := http.StatusPermanentRedirect
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			code = http.StatusMovedPermanently
		}
		// #nosec G710 -- the host is the configured spelling from servedHosts, never the request's; only the path and query are the caller's, re-encoded by url.URL
		http.Redirect(w, r, target, code)
	})
}

// isLoopbackHost reports whether host names the loopback interface: an
// IPv4 127/8 or IPv6 ::1 literal, or the name "localhost". The empty host
// (every interface), the unspecified addresses and any other name are not
// loopback — a hostname that happens to resolve to loopback today is not
// a property this check can rely on.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ErrPlaintextExposure is the startup refusal for a webservice whose only
// listener is plaintext and reachable beyond the host (#535). Credentials
// and every API response would cross the network unencrypted.
type ErrPlaintextExposure struct {
	Name     string
	BindHost string
	Port     int
}

// Error implements the error interface.
func (e *ErrPlaintextExposure) Error() string {
	host := e.BindHost
	if host == "" {
		host = "every interface"
	}
	return fmt.Sprintf("webservice %q: plaintext port %d on %s with no tls-port is refused; "+
		"configure tls-port, or bind-host a loopback address for a host-local listener",
		e.Name, e.Port, host)
}

// Serve static files from the provided directory with optional rewrite rules.
// If the web frontend is embedded (built with platform_web tag), serves from
// the embedded filesystem. Otherwise, serves from the filesystem.
func (server *WebServerV1) serveStaticFiles(rootDir, index string, rewriteRules []*v1.RewriteRule) http.HandlerFunc {
	// Check if we should use embedded filesystem
	if embed.IsEmbedded() && embed.WebFS != nil {
		server.logger.Info("Serving web frontend from embedded filesystem")
		return server.serveEmbeddedFiles(index, rewriteRules)
	}

	server.logger.Info("Serving web frontend from filesystem",
		slog.String("rootDir", rootDir),
	)
	return server.serveFilesystemFiles(rootDir, index, rewriteRules)
}

// serveEmbeddedFiles serves static files from the embedded filesystem
func (server *WebServerV1) serveEmbeddedFiles(index string, rewriteRules []*v1.RewriteRule) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestPath := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
		server.logger.Debug("Incoming request (embedded)",
			slog.String("remoteAddr", r.RemoteAddr),
			slog.String("method", r.Method),
			slog.String("requestPath", requestPath),
		)

		// Apply rewrite rules
		for _, rule := range rewriteRules {
			matched, err := regexp.MatchString(rule.Pattern, "/"+requestPath)
			if err != nil {
				server.logger.Error(errors.New("invalid rewrite pattern"),
					slog.String("pattern", rule.Pattern),
					slog.Any("error", err),
				)
				continue
			}
			if matched {
				server.logger.Debug("Rewrite applied",
					slog.String("originalPath", requestPath),
					slog.String("rewrittenPath", rule.Target),
					slog.String("pattern", rule.Pattern),
				)
				requestPath = strings.TrimPrefix(rule.Target, "/")
				break
			}
		}

		// Try to serve the requested file from embedded FS
		if requestPath == "" {
			requestPath = index
		}

		f, err := embed.WebFS.Open(requestPath)
		if err == nil {
			defer f.Close()
			stat, statErr := f.Stat()
			if statErr == nil {
				if stat.IsDir() {
					// Try index file in directory
					indexPath := requestPath + "/" + index
					if indexPath[0] == '/' {
						indexPath = indexPath[1:]
					}
					server.serveEmbeddedFile(w, r, indexPath)
					return
				}
				server.logger.Debug("Serving embedded file",
					slog.String("filePath", requestPath),
				)
				http.ServeFileFS(w, r, embed.WebFS, requestPath)
				return
			}
		}

		// Never fall back to SPA index for API routes or static asset paths.
		// API paths get a JSON 404; static asset paths get a plain 404.
		if isNonSPAPath("/" + requestPath) {
			server.logger.Warn("Non-SPA resource not found (embedded)",
				slog.String("requestPath", requestPath),
			)
			writeJSONNotFound(w, r)
			return
		}

		// Next.js static export of a dynamic route ([id], [zone], …) only
		// pre-renders a single `__placeholder__` segment. When a real ID is
		// requested at runtime there is no matching directory on disk, so
		// without help Next would fall through to its built-in 404 → /auth
		// redirect. Walk the path from right to left looking for a sibling
		// `__placeholder__` directory and serve its index.html instead so
		// the SPA can hydrate and read the actual ID from the URL.
		if placeholderPath := findPlaceholderFallback(requestPath, index); placeholderPath != "" {
			server.logger.Debug("Serving Next dynamic-route placeholder (embedded)",
				slog.String("requestPath", requestPath),
				slog.String("placeholder", placeholderPath),
			)
			server.serveEmbeddedFile(w, r, placeholderPath)
			return
		}

		// Fallback to SPA index
		server.logger.Debug("Fallback to SPA index file (embedded)",
			slog.String("requestedPath", requestPath),
		)
		server.serveEmbeddedFile(w, r, index)
	}
}

// findPlaceholderFallback returns the embedded path of a Next.js
// `__placeholder__` index that should be served for `requestPath`, or
// an empty string when no candidate exists. The function walks the URL
// from the deepest segment up; for each prefix it tries replacing the
// next segment with `__placeholder__` and checks whether that sibling
// directory contains the static `index` file.
func findPlaceholderFallback(requestPath, index string) string {
	if requestPath == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		candidateParts := append([]string{}, parts[:i]...)
		candidateParts = append(candidateParts, "__placeholder__")
		candidate := strings.Join(candidateParts, "/") + "/" + index
		if f, err := embed.WebFS.Open(candidate); err == nil {
			f.Close()
			return candidate
		}
	}
	return ""
}

// findPlaceholderFallbackFS is the on-disk counterpart to
// findPlaceholderFallback. It returns the absolute filesystem path to a
// Next.js `__placeholder__` index that should be served for
// `requestPath`, or an empty string when no candidate exists. Same
// walk-from-deepest-segment-up strategy as the embedded variant.
//
// This is the path the deployed CP exercises — `public_html` is
// installed to /var/lib/trusted-platform/public_html during ISO
// install, and the server reads from it instead of the embedded FS.
// Without this fallback, clicks on detail rows (e.g.
// /devices/5168606593679365) miss the disk file, isn't a non-SPA
// path, and end up served `/index.html` (the dashboard) — which the
// browser interprets as a navigation back to dashboard.
func findPlaceholderFallbackFS(rootDir, requestPath, index string) string {
	if requestPath == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		candidateParts := append([]string{}, parts[:i]...)
		candidateParts = append(candidateParts, "__placeholder__", index)
		candidate := filepath.Join(append([]string{rootDir}, candidateParts...)...)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// serveEmbeddedFile serves a single file from the embedded filesystem
func (server *WebServerV1) serveEmbeddedFile(w http.ResponseWriter, r *http.Request, path string) {
	f, err := embed.WebFS.Open(path)
	if err != nil {
		server.logger.Warn("Embedded file not found",
			slog.String("path", path),
			slog.Any("error", err),
		)
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		server.logger.Error(errors.New("failed to stat embedded file"),
			slog.String("path", path),
			slog.Any("error", err),
		)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Use http.ServeContent for proper content-type and range support
	seeker, ok := f.(interface {
		fs.File
		Seek(offset int64, whence int) (int64, error)
	})
	if !ok {
		// Fall back to ServeFileFS which handles this case
		http.ServeFileFS(w, r, embed.WebFS, path)
		return
	}

	server.logger.Debug("Serving embedded file",
		slog.String("filePath", path),
	)
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), seeker)
}

// serveFilesystemFiles serves static files from the local filesystem
func (server *WebServerV1) serveFilesystemFiles(rootDir, index string, rewriteRules []*v1.RewriteRule) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestPath := filepath.Clean(r.URL.Path)
		server.logger.Debug("Incoming request",
			slog.String("remoteAddr", r.RemoteAddr),
			slog.String("method", r.Method),
			slog.String("requestPath", requestPath),
		)

		// Apply rewrite rules
		for _, rule := range rewriteRules {
			matched, err := regexp.MatchString(rule.Pattern, requestPath)
			if err != nil {
				server.logger.Error(errors.New("invalid rewrite pattern"),
					slog.String("pattern", rule.Pattern),
					slog.Any("error", err),
				)
				continue
			}
			if matched {
				server.logger.Debug("Rewrite applied",
					slog.String("originalPath", requestPath),
					slog.String("rewrittenPath", rule.Target),
					slog.String("pattern", rule.Pattern),
				)
				requestPath = rule.Target
				break
			}
		}

		// Resolve static file path
		staticPath := filepath.Join(rootDir, requestPath)
		server.logger.Debug("Resolved static path",
			slog.String("staticPath", staticPath),
		)

		info, err := os.Stat(staticPath)
		if err == nil {
			// Serve file directly if it exists
			if !info.IsDir() {
				server.logger.Debug("Serving static file",
					slog.String("filePath", staticPath),
				)
				http.ServeFile(w, r, staticPath)
				return
			}
			// Serve the index file if the request points to a directory
			staticPath = filepath.Join(staticPath, index)
			if _, err := os.Stat(staticPath); err == nil {
				server.logger.Debug("Serving directory index file",
					slog.String("filePath", staticPath),
				)
				http.ServeFile(w, r, staticPath)
				return
			}
		}

		// Never fall back to SPA index for API routes or static asset paths.
		// API paths get a JSON 404; static asset paths get a plain 404.
		if isNonSPAPath(requestPath) {
			server.logger.Warn("Non-SPA resource not found",
				slog.String("requestPath", requestPath),
			)
			writeJSONNotFound(w, r)
			return
		}

		// Next.js static export of a dynamic route ([id], [zone], …) only
		// pre-renders a single `__placeholder__` segment. When a real ID
		// is requested at runtime there is no matching directory on disk,
		// so without help we fall through to `/index.html` (the dashboard
		// root) and the user lands back on the dashboard instead of the
		// detail page. Walk the path from right to left looking for a
		// sibling `__placeholder__` directory and serve its index.html
		// instead so the client component can hydrate from the URL.
		if placeholderPath := findPlaceholderFallbackFS(rootDir, requestPath, index); placeholderPath != "" {
			server.logger.Debug("Serving Next dynamic-route placeholder",
				slog.String("requestPath", requestPath),
				slog.String("placeholder", placeholderPath),
			)
			http.ServeFile(w, r, placeholderPath)
			return
		}

		// Fallback to SPA index
		fallbackPath := filepath.Join(rootDir, index)
		server.logger.Debug("Fallback to SPA index file",
			slog.String("fallbackPath", fallbackPath),
			slog.String("requestedPath", requestPath),
		)

		if _, err := os.Stat(fallbackPath); err == nil {
			server.logger.Debug("Serving SPA index file",
				slog.String("filePath", fallbackPath),
			)
			http.ServeFile(w, r, fallbackPath)
			return
		}

		// File not found
		server.logger.Warn("File not found",
			slog.String("staticPath", staticPath),
			slog.String("requestedPath", requestPath),
		)
		http.NotFound(w, r)
	}
}

// Ensures the provided directory exists and creates it with the specified index file
// if it doesn't exist.
func (server *WebServerV1) ensureDirectoryExists(vhostDir, virtualHost, index string) error {

	// Create directory if it does not exist
	if err := os.MkdirAll(vhostDir, 0755); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to create directory %s", vhostDir), Err: err}
	}

	// Create default index file
	if err := server.createDefaultIndexFile(vhostDir, virtualHost, index); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to create default index file in directory %s", vhostDir), Err: err}
	}

	return nil
}

// Creates a default index file in the provided directory if it doesn't exist.
func (server *WebServerV1) createDefaultIndexFile(directory, virtualHost, index string) error {
	indexFilePath := filepath.Join(directory, index)

	// Skip creation if file already exists
	if _, err := os.Stat(indexFilePath); err == nil {
		server.logger.Warn("Index file already exists",
			slog.String("index", indexFilePath))
		return nil
	} else if !os.IsNotExist(err) {
		return &WrappedError{Msg: "failed to check index file", Err: err}
	}

	// Create and write default index file
	tmpl, err := template.New("index").Parse(defaultIndexTemplate)
	if err != nil {
		return &WrappedError{Msg: "failed to parse default index template", Err: err}
	}

	file, err := os.Create(indexFilePath)
	if err != nil {
		return &WrappedError{Msg: "failed to create index file", Err: err}
	}
	defer file.Close()

	// Fill template data and write file
	data := struct{ VirtualHost string }{VirtualHost: virtualHost}
	if err := tmpl.Execute(file, data); err != nil {
		return &WrappedError{Msg: "failed to write to index file", Err: err}
	}

	server.logger.Info(
		"Created default index file",
		slog.String("virtualhost", virtualHost),
		slog.String("index", indexFilePath))
	return nil
}

// Validates the provided host header to prevent injection attacks.
// Handler for reverse proxying requests to a list of backend servers
func (server *WebServerV1) reverseProxyHandler(backends []string, lbFunc LoadBalancerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(backends) == 0 {
			http.Error(w, "No backend servers configured", http.StatusInternalServerError)
			return
		}

		// Select a backend using the load balancer
		backend := lbFunc(backends)
		backendURL, err := url.Parse(backend)
		if err != nil {
			server.logger.Errorf("Invalid backend URL: %s, error: %v", backend, err)
			http.Error(w, "Invalid backend URL", http.StatusInternalServerError)
			return
		}

		// Proxy the request to the selected backend
		proxy := httputil.NewSingleHostReverseProxy(backendURL)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
			server.logger.Errorf("Proxy error: %v", e)
			http.Error(w, "Proxy error", http.StatusBadGateway)
		}
		server.logger.Debug("Proxying request to backend",
			slog.String("backend", backendURL.String()),
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method),
			slog.String("remote-addr", r.RemoteAddr),
			slog.String("host", r.Host),
		)
		proxy.ServeHTTP(w, r)
	}
}

// listener is one of this webservice's bind points: the configured
// bind-host joined with port, and the network family that host implies.
// An empty bind-host is the unspecified address on every family — the
// plaintext listener used to pin itself to tcp4 while the TLS listener did
// not; both now follow the one configured host (#552).
func (server *WebServerV1) listener(port int) tpconfig.Listener {
	return tpconfig.Listener{BindHost: server.config.BindHost, Port: port}
}

// Start the plaintext HTTP server with the handler plaintextHandler
// chose: the TLS redirect, or — loopback only — the router itself.
func (server *WebServerV1) startHTTP(handler http.Handler) {

	web := server.listener(server.config.Port)
	sWebAddr := web.Address()
	httpListener, err := net.Listen(web.Network("tcp"), sWebAddr)
	if err != nil {
		server.logger.Fatalf("Failed to start HTTP server: %v", err)
	}
	httpListener = server.limits.limitListener(httpListener)

	server.logger.Info(
		"Listening for incoming HTTP (HTTP/1.1, HTTP/2) connections",
		slog.String("tcp", sWebAddr),
		slog.Bool("redirect_only", server.config.TLSPort > 0))

	if server.plainServer == nil {
		server.plainServer = server.limits.newHTTPServer(nil)
	}
	server.plainServer.Handler = handler
	err = server.plainServer.Serve(httpListener)
	if err != nil && err != http.ErrServerClosed {
		server.logger.Fatalf("webserver: unable to start web services: %v", err)
	}
}

// Start the HTTPS server (HTTP/1.1, HTTP/2, and HTTP/3)
func (server *WebServerV1) startHTTPS() {

	tlsListenerCfg := server.listener(server.config.TLSPort)
	sTlsAddr := tlsListenerCfg.Address()

	server.logger.Info("starting secure TLS web services",
		slog.String("address", sTlsAddr))

	// Configure TLS for HTTP/1.1, HTTP/2, and HTTP/3
	tlsconf, err := server.buildTLSConfig(server.ctx)
	if err != nil {
		server.logger.FatalError(err)
	}
	tlsconf.NextProtos = []string{"h3", "h2", "http/1.1"}

	// Set up certificate hot-reload for seamless certificate rotation
	var initialCert *tls.Certificate
	if len(tlsconf.Certificates) > 0 {
		initialCert = &tlsconf.Certificates[0]
	} else if tlsconf.GetCertificate != nil {
		initialCert, err = tlsconf.GetCertificate(nil)
		if err != nil {
			server.logger.FatalError(err)
		}
	}
	if initialCert != nil {
		reloader, rErr := bootstrap.NewCertReloader(initialCert)
		if rErr != nil {
			server.logger.FatalError(rErr)
		}
		// Stored atomically: Run() writes it on the serving goroutine while the
		// certificate-renewal sweep reads it from the scheduler's.
		server.certReloader.Store(reloader)
		tlsconf.GetCertificate = reloader.GetCertificateFunc()
	}
	server.httpServer.TLSConfig = tlsconf

	// Start HTTP/3 Server
	h3Server := &http3.Server{
		TLSConfig:  tlsconf,
		Handler:    server.httpServer.Handler, // Reuse the same HTTP handler
		QUICConfig: server.limits.quicConfig(server.surface),
	}

	// Listen for UDP traffic for HTTP/3
	udpConn, err := net.ListenPacket(tlsListenerCfg.Network("udp"), sTlsAddr)
	if err != nil {
		server.logger.Fatalf("Failed to start HTTP/3 server: %v", err)
	}

	h3 := &h3Listener{server: h3Server, conn: udpConn, done: make(chan struct{})}
	server.h3.Store(h3)

	go func() {
		defer close(h3.done)
		server.logger.Info(
			"Listening for incoming HTTP/3 connections",
			slog.String("udp", udpConn.LocalAddr().String()))

		if err := h3Server.Serve(udpConn); err != nil && !isServerClosed(err) {
			server.logger.Fatalf("HTTP/3 server error: %v", err)
		}
	}()

	// Start HTTPS server for HTTP/1.1 and HTTP/2
	tlsListener, err := tls.Listen(tlsListenerCfg.Network("tcp"), sTlsAddr, tlsconf)
	if err != nil {
		server.logger.Fatalf("Failed to start HTTPS server: %v", err)
	}
	tlsListener = server.limits.limitListener(tlsListener)

	server.logger.Info(
		"Listening for incoming HTTPS (HTTP/1.1, HTTP/2) connections",
		slog.String("tcp", sTlsAddr))

	if err := server.httpServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		server.logger.Fatalf("HTTPS server error: %v", err)
	}
}

// CertReloader returns the certificate hot-reloader for this web server.
// It may be nil if the server was not started with HTTPS.
func (server *WebServerV1) CertReloader() *bootstrap.CertReloader {
	return server.certReloader.Load()
}

// buildTLSConfig constructs the certificate-bearing TLS configuration for this
// webservice.
//
// Shared by startHTTPS and ReloadCertificate ON PURPOSE. When the two built the
// config separately, only startHTTPS honoured Certificate.ACME.CrossSign: the
// first renewal then replaced a cross-signed chain with an ordinary one and
// broke every client that depended on the configured cross-sign trust path --
// silently, and only after the first rotation.
func (server *WebServerV1) buildTLSConfig(ctx context.Context) (*tls.Config, error) {
	if server.config.Certificate.ACME != nil && server.config.Certificate.ACME.CrossSign != nil {
		// Validate the configured cross-signer URL to surface misconfigurations
		// early, matching the legacy wrapper's behavior.
		if _, err := util.ParseFQDN(server.config.Certificate.ACME.CrossSign.DirectoryURL); err != nil {
			return nil, err
		}
		// Native pkg/ca.TLSConfigWithXSigner uses its xsigner argument as a
		// non-nil toggle that opts the returned tls.Config into the
		// cross-signed trust augmentation. The CA itself implements
		// crypto.Signer, so passing server.ca preserves the cross-signed
		// behavior the wrapper provided with only a CN hint.
		tlsConfig, err := server.ca.TLSConfigWithXSigner(ctx, server.keyAttributes, server.ca)
		if err != nil {
			return nil, err
		}
		return requestOptionalClientCert(tlsConfig), nil
	}
	// ServerTLSConfig (not bare TLSConfig) makes the server intent explicit.
	// Bare TLSConfig defaults IsServer:false and triggers "TLS: ServerName not
	// specified for client connection - SNI may fail" on every startup; the
	// resulting config still works as a server (Go's TLS server ignores
	// client-only fields) but the WARN is misleading and clutters platformd logs.
	tlsConfig, err := server.ca.ServerTLSConfig(ctx, server.keyAttributes, false)
	if err != nil {
		return nil, err
	}
	return server.trustCallerAnchors(requestOptionalClientCert(tlsConfig)), nil
}

// trustCallerAnchors adds the attestation caller-admission anchors to the
// listener's ClientCAs.
//
// The CA hands back ClientCAs holding only this node's own root and
// intermediate. On a worker that is a CA the control plane never issued
// from, so the reporting server's client certificate — issued by the
// platform CA that enrolled this node — fails the handshake before any
// handler runs (measured on the fleet: HTTP 000 on every node, 200 on the
// control plane). The caller policy already knows which anchors a
// reporting server must chain to; the listener has to request certificates
// from the same anchors or the policy can never be consulted.
//
// ClientAuth stays VerifyClientCertIfGiven: a browser with no certificate
// completes the handshake as before, and the policy re-verifies the chain
// itself before admitting anyone, so widening ClientCAs widens nothing but
// the set of certificates that reach the policy.
func (server *WebServerV1) trustCallerAnchors(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig == nil || server.restServiceRegistry == nil {
		return tlsConfig
	}
	rep := server.restServiceRegistry.AttestationReporting()
	if rep == nil || rep.Policy == nil {
		return tlsConfig
	}
	anchors := rep.Policy.Anchors()
	if len(anchors) == 0 {
		return tlsConfig
	}
	if tlsConfig.ClientCAs == nil {
		tlsConfig.ClientCAs = x509.NewCertPool()
	} else {
		tlsConfig.ClientCAs = tlsConfig.ClientCAs.Clone()
	}
	for _, cert := range anchors {
		tlsConfig.ClientCAs.AddCert(cert)
	}
	if tlsConfig.ClientAuth == tls.NoClientCert {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tlsConfig
}

// requestOptionalClientCert makes the listener ASK for a client
// certificate without requiring one.
//
// The CA hands back a server config that populates ClientCAs but leaves
// ClientAuth at tls.NoClientCert, so the listener never sent a
// CertificateRequest and r.TLS.PeerCertificates was empty on every
// request it served. That silently disabled every mTLS-gated surface on
// this listener: the device-enrollment routes wrap MTLSMiddleware, which
// fails closed on an absent peer certificate, so they could only ever
// answer 401 — and the gateway control plane had no certificate identity
// to bind reported telemetry to.
//
// tls.VerifyClientCertIfGiven rather than RequireAndVerifyClientCert
// because the WebUI and the JWT-authenticated API share this listener: a
// browser holding no client certificate completes the handshake exactly
// as before, while a certificate that IS presented must chain to
// ClientCAs or the handshake fails. Handlers therefore read peer
// identity from VerifiedChains, which is populated only after that
// verification, never from PeerCertificates. This mirrors gatewayd's own
// front door (buildServerTLS, pkg/sdn/gateway/commands/assembly.go).
//
// With no ClientCAs there is nothing to verify against, so the config is
// left alone and the cert-bound handlers fail closed on their own.
func requestOptionalClientCert(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig == nil || tlsConfig.ClientCAs == nil {
		return tlsConfig
	}
	if tlsConfig.ClientAuth == tls.NoClientCert {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tlsConfig
}

// ReloadCertificate makes the running listener serve the certificate currently
// held by the CA, without dropping connections or restarting the server.
//
// This is what turns certificate RENEWAL into certificate ROTATION. The TLS
// config the listener starts with is a static snapshot
// (ca.ServerTLSConfig returns Certificates: []tls.Certificate{...}), so issuing
// a replacement into the CA changes nothing that clients see. Before this
// existed, the renewal sweep re-issued a fresh certificate every single day --
// the live endpoint still served the old one, so the sweep read the same
// near-expiry certificate on the next run and issued again -- while the served
// certificate marched to expiry and TLS eventually broke. CertReloader was
// present and wired into GetCertificate, but nothing ever called Reload.
func (server *WebServerV1) ReloadCertificate(ctx context.Context) error {
	reloader := server.certReloader.Load()
	if reloader == nil {
		return ErrCertReloaderUnavailable{Webservice: server.config.Name}
	}

	tlsconf, err := server.buildTLSConfig(ctx)
	if err != nil {
		return ErrCertReloadFailed{Webservice: server.config.Name, Cause: err}
	}

	var next *tls.Certificate
	if len(tlsconf.Certificates) > 0 {
		next = &tlsconf.Certificates[0]
	} else if tlsconf.GetCertificate != nil {
		if next, err = tlsconf.GetCertificate(nil); err != nil {
			return ErrCertReloadFailed{Webservice: server.config.Name, Cause: err}
		}
	}
	if next == nil {
		return ErrCertReloadFailed{
			Webservice: server.config.Name,
			Cause:      errors.New("CA returned no certificate"),
		}
	}
	if err := reloader.Reload(next); err != nil {
		return ErrCertReloadFailed{Webservice: server.config.Name, Cause: err}
	}
	server.logger.Info("webservice TLS certificate reloaded on the live listener",
		"webservice", server.config.Name)
	return nil
}

// addAltSvcHeader advertises the HTTP/3 listener on every response. HTTP/3
// listens on UDP at the TLS port number, so that port is what Alt-Svc names.
func addAltSvcHeader(next http.Handler, tlsPort int) http.Handler {
	if tlsPort <= 0 {
		// No TLS listener means no HTTP/3 listener: advertise nothing.
		return next
	}
	altSvc := fmt.Sprintf(`h3=":%d"; ma=86400`, tlsPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", altSvc)
		next.ServeHTTP(w, r)
	})
}

// Build the routes for the web server. This is a thread safe operation that
// can be used to dynamically update the web server routes at runtime.
func (server *WebServerV1) buildRoutes() {

	responseWriter := response.NewResponseWriter(server.logger, nil)

	muxRouter := mux.NewRouter().StrictSlash(true)

	// The per-source rate limiter runs before anything else so a flooding
	// source is refused before it reaches a handler (#571).
	if server.limiter != nil {
		muxRouter.Use(rateLimitMiddleware(server.limiter, server.limits.retryAfter()))
	}

	// Apply CORS middleware if configured
	if server.config.CORS != nil {
		muxRouter.Use(middleware.CORSMiddleware(middleware.CORSOptions{
			AllowedOrigins:   server.config.CORS.AllowedOrigins,
			AllowedMethods:   server.config.CORS.AllowedMethods,
			AllowedHeaders:   server.config.CORS.AllowedHeaders,
			AllowCredentials: server.config.CORS.AllowCredentials,
		}))
	}

	// Virtual hosts register BEFORE every path route: mux matches in
	// registration order, and a virtual host owns its Host entirely — a
	// request for it never falls through to this server's own API or
	// console (#571). Their matcher is an allowlist of configured names
	// with one-label wildcards, not a template. The provisioning listener
	// carries none: it serves one route to the provisioning zone (#177).
	if server.surface != v1.SurfaceProvisioning {
		server.registerVirtualHosts(muxRouter)
	}

	// There is deliberately no route inventory at the root. /endpoints used
	// to walk the mux and hand any caller every registered template,
	// gated paths included, with no credential — an oracle that amplified
	// every other exposure (#551). The debug flag's debugRoutes() logs the
	// same inventory locally for operators who need it.

	v1Router := v1.NewRouter(
		server.logger,
		server.ca,
		server.caConfig,
		server.keyAttributes,
		server.restServiceRegistry,
		responseWriter)

	switch server.surface {
	case v1.SurfaceEdge:
		// A public edge listener carries the ACME routes, the virtual hosts
		// above and the TLS redirect (plaintextHandler) — no console, no
		// /api/v1, no /v2, no canonical root routes. A path it does not
		// mount is 404 on a served host and 421 on any other.
		acme := v1Router.RegisterEdgeRoutes(muxRouter, server.baseURI)
		if !acme && !server.hasVirtualHosts() {
			// A public listener that would answer nothing but 404 and 421
			// is a misconfiguration, not a quiet edge.
			server.logger.FatalError(&ErrEdgeSurfaceEmpty{Name: server.config.Name})
		}
		muxRouter.PathPrefix("/").HandlerFunc(server.misdirectedUnlessServed())
	case v1.SurfaceProvisioning:
		// The provisioning listener carries the unauthenticated boot-time
		// GET /api/v1/devices/config and nothing else (#177). Every other
		// path is the same 404 an unknown route gets on any listener, and
		// no other surface mounts the route, so a general listener answers
		// it with that 404 too.
		if !v1Router.RegisterProvisioningRoutes(muxRouter, server.baseURI) {
			server.logger.FatalError(&ErrProvisioningSurfaceEmpty{Name: server.config.Name})
		}
		muxRouter.PathPrefix("/").HandlerFunc(writeJSONNotFound)
	default:
		// The OCI Distribution-spec surface lives at /v2 on the ROOT router —
		// the spec mandates "/v2/" at the host root; under /api/v1 `crane pull
		// cp.example.com/foo:1` would fail. The v1 router mounts it behind the
		// same caller gate and admin chain as its attestation quote routes
		// (#549); a refused mount is a startup defect, not a degraded node.
		if err := v1Router.RegisterRootRoutes(muxRouter); err != nil {
			server.logger.FatalError(err)
		}

		server.registerCanonicalRoutes(muxRouter, responseWriter)

		apiRouter := muxRouter.PathPrefix(server.baseURI).Subrouter()

		v1Router.RegisterRoutes(apiRouter)

		// Default handler for unmatched routes: the console.
		muxRouter.PathPrefix("/").HandlerFunc(
			server.serveStaticFiles(server.config.Home, server.config.Index, server.config.RewriteRules),
		)
	}

	server.routerMutex.Lock()
	server.router = muxRouter
	server.httpServer.Handler = addAltSvcHeader(server.router, server.config.TLSPort)
	server.routerMutex.Unlock()

	if server.debug {
		server.debugRoutes()
	}
}

// hasVirtualHosts reports whether at least one virtual host names a host.
func (server *WebServerV1) hasVirtualHosts() bool {
	if server.config.VirtualHosts == nil {
		return false
	}
	for _, vhost := range *server.config.VirtualHosts {
		if len(vhost.Hosts) > 0 {
			return true
		}
	}
	return false
}

// registerVirtualHosts mounts each configured virtual host on root, as a
// reverse proxy when it names backends and as a static site otherwise.
func (server *WebServerV1) registerVirtualHosts(root *mux.Router) {
	if server.config.VirtualHosts == nil {
		return
	}
	for _, vhost := range *server.config.VirtualHosts {
		if len(vhost.Hosts) == 0 {
			server.logger.Warn("virtual host with no hosts skipped")
			continue
		}
		// Create the virtual host directory
		vhostDir := filepath.Join(server.config.Home, vhost.Home)

		// Use the virtual host's custom index or fallback to the global index
		indexFile := vhost.Index
		if indexFile == "" {
			indexFile = server.config.Index
		}

		proxied := vhost.Proxy != nil && len(vhost.Proxy.Backends) > 0
		if !proxied {
			// Ensure the directory exists
			if err := server.ensureDirectoryExists(vhostDir, vhost.Hosts[0], indexFile); err != nil {
				server.logger.Errorf("Failed to set up directory for virtual host %s: %v", vhost.Hosts[0], err)
				continue
			}
		}

		subRouter := root.MatcherFunc(hostSetMatcher(vhost.Hosts)).Subrouter()
		if vhost.CORS != nil {
			subRouter.Use(middleware.CORSMiddleware(middleware.CORSOptions{
				AllowedOrigins:   vhost.CORS.AllowedOrigins,
				AllowedMethods:   vhost.CORS.AllowedMethods,
				AllowedHeaders:   vhost.CORS.AllowedHeaders,
				AllowCredentials: vhost.CORS.AllowCredentials,
			}))
		}

		if proxied {
			subRouter.PathPrefix("/").HandlerFunc(
				server.reverseProxyHandler(vhost.Proxy.Backends, RoundRobinBalancer()),
			)
			server.logger.Infof("Virtual hosts %v configured as reverse proxy", vhost.Hosts)
		} else {
			subRouter.PathPrefix("/").HandlerFunc(
				server.serveStaticFiles(vhostDir, indexFile, vhost.RewriteRules),
			)
			server.logger.Infof("Virtual hosts %v mapped to directory %s with index %s", vhost.Hosts, vhostDir, indexFile)
		}
	}
}

// registerCanonicalRoutes mounts the unauthenticated trust-bootstrap bundle
// at its canonical root-relative path, in addition to the /api/v1-prefixed
// route the v1 router registers. The canonical path is defined by the go-xkms
// trust fetcher (its DefaultBundlePath) and is what
// `xkey trust import-platform <host:port>` fetches; a client making first
// contact has no credential and no way to discover this platform's API
// prefix. It goes on the ROOT router, alongside the OCI /v2 surface, because
// both are contracts anchored at the host root.
func (server *WebServerV1) registerCanonicalRoutes(
	router *mux.Router, responseWriter response.HttpWriter) {

	restca.NewCARouter(
		server.logger,
		server.ca,
		responseWriter).RegisterCanonicalRoutes(router)
}

// DebugRoutes prints the routes to the log
func (server *WebServerV1) debugRoutes() {
	err := server.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetPathTemplate()
		if err == nil {
			server.logger.Debug("route", "path", pathTemplate)
		}
		pathRegexp, err := route.GetPathRegexp()
		if err == nil {
			server.logger.Debug("route", "pathRegexp", pathRegexp)
		}
		queriesTemplates, err := route.GetQueriesTemplates()
		if err == nil {
			server.logger.Debug("route", "queriesTemplates", strings.Join(queriesTemplates, ","))
		}
		queriesRegexps, err := route.GetQueriesRegexp()
		if err == nil {
			server.logger.Debug("route", "queriesRegexps", strings.Join(queriesRegexps, ","))
		}
		methods, err := route.GetMethods()
		if err == nil {
			server.logger.Debug("route", "methods", strings.Join(methods, ","))
		}
		server.logger.Debug("route", "separator", "---")
		return nil
	})
	if err != nil {
		server.logger.Errorf("[WebServer.WalkRoutes] Error: %v", err)
	}
}
