package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
)

// headerForwardedClientCert is stripped from every inbound request before
// forwarding so callers cannot spoof mTLS identity.
const headerForwardedClientCert = "X-Forwarded-Client-Cert"

// identityHeaderPrefix marks the platform identity headers stripped from
// every inbound request; Phase 2 re-injects trusted values after auth.
const identityHeaderPrefix = "X-TP-"

// errorResponse is the JSON body written for engine-generated errors.
type errorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
}

// ServeHTTP implements http.Handler. It is the single shared handler for all
// listeners: match route, authenticate (fail closed), strip inbound identity
// headers, and forward through the route's shared reverse proxy.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := e.state.Load()
	stripIdentityHeaders(r.Header)
	route := st.table.match(r.Host, r.URL.Path)
	if route == nil {
		e.notFound.Add(1)
		e.deps.Audit.Record(r.Context(), auditEvent(r, "", DecisionNoRoute, "no matching route", nil))
		writeJSONError(w, e.deps.Logger, http.StatusNotFound, "no route", "")
		return
	}
	route.metrics.requests.Add(1)
	var identity *ClientIdentity
	if route.cfg.Auth.Mode != AuthModePublic {
		decision, err := e.deps.Auth.Authenticate(r.Context(), r, route)
		if err != nil {
			route.metrics.errors.Add(1)
			e.deps.Audit.Record(r.Context(), auditEvent(r, route.cfg.ID, DecisionError, err.Error(), nil))
			writeJSONError(w, e.deps.Logger, http.StatusInternalServerError, "authentication error", "")
			return
		}
		if decision == nil || !decision.Allowed {
			route.metrics.denied.Add(1)
			reason := "denied"
			if decision != nil {
				if decision.Reason != "" {
					reason = decision.Reason
				}
				identity = decision.Identity
			}
			e.deps.Audit.Record(r.Context(), auditEvent(r, route.cfg.ID, DecisionDeny, reason, identity))
			writeJSONError(w, e.deps.Logger, http.StatusForbidden, "forbidden", reason)
			return
		}
		identity = decision.Identity
		e.deps.Audit.Record(r.Context(), auditEvent(r, route.cfg.ID, DecisionAllow, "", identity))
		// Authenticated routes never forward the caller's inbound
		// Authorization value: on the mTLS path it is untrusted baggage, and
		// on the token path the proxy terminated that credential — forwarding
		// the caller's platform token would let backends replay it. Backends
		// authenticate the proxy through its mTLS platform identity and read
		// the caller's identity from the trusted X-TP-* headers.
		r.Header.Del(headerAuthorization)
		if identity != nil {
			injectIdentity(r.Header, identity)
		}
	}
	cw := &countingResponseWriter{ResponseWriter: w, bytes: &route.metrics.bytesOut}
	route.rp.ServeHTTP(cw, r)
}

// newReverseProxy builds the shared httputil.ReverseProxy for one compiled
// route using the modern Rewrite API. rcfg must point at the CompiledRoute's
// own config copy so the closure stays valid for the route's lifetime.
func newReverseProxy(rcfg *RouteConfig, pool *compiledPool, m *routeMetrics, deps Deps) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: pool.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			b := pool.balancer.Next(pool.backends)
			if rcfg.StripPrefix {
				stripRequestPrefix(pr.Out.URL, rcfg.PathPrefix)
			}
			pr.SetURL(b.url)
			pr.SetXForwarded()
			if rcfg.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			m.errors.Add(1)
			deps.Audit.Record(r.Context(), auditEvent(r, rcfg.ID, DecisionError, err.Error(), nil))
			deps.Logger.Error("proxy: backend error", "route", rcfg.ID, "error", err)
			writeJSONError(w, deps.Logger, http.StatusBadGateway, "bad gateway", "")
		},
		ErrorLog: slog.NewLogLogger(deps.Logger.Handler(), slog.LevelError),
	}
}

// stripIdentityHeaders removes X-Forwarded-Client-Cert and every X-TP-*
// header (case-insensitive) from the inbound request so clients cannot spoof
// platform identity, regardless of the auth outcome path.
func stripIdentityHeaders(h http.Header) {
	for k := range h {
		if isIdentityHeader(k) {
			delete(h, k)
		}
	}
}

func isIdentityHeader(k string) bool {
	if strings.EqualFold(k, headerForwardedClientCert) {
		return true
	}
	return len(k) >= len(identityHeaderPrefix) &&
		strings.EqualFold(k[:len(identityHeaderPrefix)], identityHeaderPrefix)
}

// stripRequestPrefix removes the route path prefix from the outgoing URL,
// preserving a leading slash. RawPath is stripped in lockstep when present
// and cleared when it diverges.
func stripRequestPrefix(u *url.URL, prefix string) {
	if prefix == "" || prefix == "/" {
		return
	}
	if strings.HasPrefix(u.Path, prefix) {
		u.Path = ensureLeadingSlash(u.Path[len(prefix):])
	}
	if u.RawPath != "" {
		if strings.HasPrefix(u.RawPath, prefix) {
			u.RawPath = ensureLeadingSlash(u.RawPath[len(prefix):])
		} else {
			u.RawPath = ""
		}
	}
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		return "/" + p
	}
	return p
}

// writeJSONError writes a JSON error body with the given status. Encoding
// failures (e.g. a disconnected client) are logged, never ignored.
func writeJSONError(w http.ResponseWriter, logger *slog.Logger, status int, message, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(errorResponse{Error: message, Reason: reason}); err != nil {
		logger.Debug("proxy: failed to write error response", "error", err)
	}
}

// countingResponseWriter counts response bytes into a route's bytesOut
// counter. Unwrap lets http.ResponseController reach Flush/Hijack on the
// underlying writer.
type countingResponseWriter struct {
	http.ResponseWriter
	bytes *atomic.Uint64
}

// Write implements io.Writer, counting bytes written.
func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes.Add(uint64(n))
	return n, err
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController.
func (w *countingResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

var _ http.Handler = (*Engine)(nil)
