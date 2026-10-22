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

package rest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// PeerAuthenticator turns a verified mTLS client chain into the caller's
// authorized context. The daemon admits a verified certificate as the
// operator principal (docs/daemon/api.md).
type PeerAuthenticator interface {
	AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error)
}

// ErrRouteUnauthenticated is returned when a request carries no credential
// the guard can verify.
type ErrRouteUnauthenticated struct {
	Reason string
}

// Error implements the error interface.
func (e ErrRouteUnauthenticated) Error() string {
	return "authentication required: " + e.Reason
}

// ErrRouteForbidden is returned when the caller is authenticated but does
// not hold the route's scope, or when no guard is configured.
type ErrRouteForbidden struct {
	Scope  string
	Reason string
}

// Error implements the error interface.
func (e ErrRouteForbidden) Error() string {
	return "scope " + e.Scope + " required: " + e.Reason
}

// ScopeGuard enforces a per-route scope on the daemon REST listener, the
// same scope the gRPC method catalog requires for the RPC behind the route.
// A bearer platform token is preferred; without one the verified mTLS
// client certificate is the credential. A nil guard denies every request.
type ScopeGuard struct {
	tokens TokenAuthorizer
	peers  PeerAuthenticator
	logger *slog.Logger
}

// NewScopeGuard creates a guard. Either authenticator may be nil, which
// refuses the credentials it would have verified.
func NewScopeGuard(tokens TokenAuthorizer, peers PeerAuthenticator, logger *slog.Logger) *ScopeGuard {
	if logger == nil {
		logger = slog.Default()
	}
	return &ScopeGuard{tokens: tokens, peers: peers, logger: logger}
}

// Require wraps next so it runs only for a caller holding scope: 401 when
// the caller is not authenticated, 403 when it lacks the scope.
func (g *ScopeGuard) Require(scope string, next http.HandlerFunc) http.HandlerFunc {
	return g.RequireCaller(scope, func(w http.ResponseWriter, r *http.Request, _ *platformtoken.AuthorizedContext) {
		next(w, r)
	})
}

// CallerHandlerFunc is a handler that also receives the caller its
// ScopeGuard authenticated, for a route whose decision depends on who is
// calling (the tenant routes' own-tenant rule).
type CallerHandlerFunc func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext)

// RequireCaller is Require for a handler that needs the authenticated
// caller: next runs only for a caller holding scope, and receives it.
func (g *ScopeGuard) RequireCaller(scope string, next CallerHandlerFunc) http.HandlerFunc {
	return g.require(scope, false, next)
}

// RequireToken is Require for a route that a platform bearer token alone may
// reach: a verified client certificate is refused with 401, so the route
// never rides on mTLS authentication (ca:sign-csr, docs/ca/api.md).
func (g *ScopeGuard) RequireToken(scope string, next http.HandlerFunc) http.HandlerFunc {
	return g.require(scope, true, func(w http.ResponseWriter, r *http.Request, _ *platformtoken.AuthorizedContext) {
		next(w, r)
	})
}

// require serves next only to a caller holding scope; tokenOnly refuses a
// caller without a bearer token.
func (g *ScopeGuard) require(scope string, tokenOnly bool, next CallerHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, statusCode, err := g.authorize(r, scope, tokenOnly)
		if err != nil {
			writeGuardError(w, g.loggerOrDefault(), statusCode, err)
			return
		}
		next(w, r, caller)
	}
}

// authorize authenticates r and checks scope, returning the caller, or the
// HTTP status to answer with when it fails. tokenOnly accepts only a bearer
// platform token.
func (g *ScopeGuard) authorize(r *http.Request, scope string, tokenOnly bool) (*platformtoken.AuthorizedContext, int, error) {
	if g == nil {
		return nil, http.StatusForbidden, ErrRouteForbidden{Scope: scope, Reason: "no authorization is configured for this route"}
	}
	if tokenOnly && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return nil, http.StatusUnauthorized, ErrRouteUnauthenticated{Reason: "this route requires a platform bearer token granting " + scope}
	}
	authCtx, err := g.authenticate(r)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	if authCtx == nil {
		return nil, http.StatusUnauthorized, ErrRouteUnauthenticated{Reason: "the credential authorized no caller"}
	}
	if err := authCtx.RequireScope(scope); err != nil {
		return nil, http.StatusForbidden, ErrRouteForbidden{Scope: scope, Reason: err.Error()}
	}
	return authCtx, http.StatusOK, nil
}

// authenticate resolves the caller from its bearer token, or else from its
// verified client certificate.
func (g *ScopeGuard) authenticate(r *http.Request) (*platformtoken.AuthorizedContext, error) {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		if g.tokens == nil {
			return nil, ErrRouteUnauthenticated{Reason: "bearer tokens are not accepted on this listener"}
		}
		authCtx, err := g.tokens.AuthorizeToken(r.Context(), strings.TrimSpace(token), "", r.Header.Get("DPoP"), r.Method, requestURL(r))
		if err != nil {
			return nil, ErrRouteUnauthenticated{Reason: err.Error()}
		}
		return authCtx, nil
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil, ErrRouteUnauthenticated{Reason: "no bearer token or verified client certificate"}
	}
	if g.peers == nil {
		return nil, ErrRouteUnauthenticated{Reason: "client certificates are not accepted on this listener"}
	}
	authCtx, err := g.peers.AuthenticatePeer(r.Context(), r.TLS.VerifiedChains[0])
	if err != nil {
		return nil, ErrRouteUnauthenticated{Reason: err.Error()}
	}
	return authCtx, nil
}

func (g *ScopeGuard) loggerOrDefault() *slog.Logger {
	if g == nil {
		return slog.Default()
	}
	return g.logger
}

// callerContextKey keys the principal a front end serving a daemon route in
// the same process has already authenticated.
type callerContextKey struct{}

// WithCaller returns a copy of ctx carrying caller: the principal the
// webservice authenticated by its own session before it replays a daemon
// route in-process. A context value cannot cross the wire, so only code in
// this process can set it.
func WithCaller(ctx context.Context, caller *platformtoken.AuthorizedContext) context.Context {
	return context.WithValue(ctx, callerContextKey{}, caller)
}

// caller returns the principal r acts as: the one a replaying front end put
// in the context, else the one the bearer token or verified client
// certificate authenticates on this listener.
func (g *ScopeGuard) caller(r *http.Request) (*platformtoken.AuthorizedContext, error) {
	if caller, ok := r.Context().Value(callerContextKey{}).(*platformtoken.AuthorizedContext); ok && caller != nil {
		return caller, nil
	}
	return g.authenticate(r)
}

// writeGuardError writes the standard REST error envelope for a refusal.
func writeGuardError(w http.ResponseWriter, logger *slog.Logger, statusCode int, err error) {
	logger.Warn("REST request refused", "error", err, "http_status", statusCode)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	body := ErrorResponse{
		Error:     err.Error(),
		Code:      statusCode,
		Timestamp: time.Now().UTC(),
	}
	if encodeErr := json.NewEncoder(w).Encode(body); encodeErr != nil {
		logger.Error("Failed to write REST error response", "error", encodeErr)
	}
}
