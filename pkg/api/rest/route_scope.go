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
// authorized context. The certificate names the principal; what it may do
// is decided per route by the guard's PeerAuthorizationChecker.
type PeerAuthenticator interface {
	AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error)
}

// PeerAuthorizationChecker decides whether a caller authenticated by its
// client certificate may perform action on resource (the IAM PEP behind
// the daemon). It has the signature of quic.PeerAuthorizationChecker.
type PeerAuthorizationChecker interface {
	CheckPeerPermission(ctx context.Context, authCtx *platformtoken.AuthorizedContext, resource, action string) (bool, error)
}

// ScopeGuardOption configures a ScopeGuard.
type ScopeGuardOption func(*ScopeGuard)

// WithPeerAuthorizationChecker sets the checker that decides certificate
// callers. Without one every certificate caller is refused 403.
func WithPeerAuthorizationChecker(checker PeerAuthorizationChecker) ScopeGuardOption {
	return func(g *ScopeGuard) {
		g.peerChecker = checker
	}
}

// certificateCallerKey marks a request context whose caller the guard
// authenticated by its client certificate.
type certificateCallerKey struct{}

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
// client certificate is the credential, and the guard's peer checker
// decides what a certificate caller may do. A nil guard denies every
// request.
type ScopeGuard struct {
	tokens      TokenAuthorizer
	peers       PeerAuthenticator
	peerChecker PeerAuthorizationChecker
	logger      *slog.Logger
}

// NewScopeGuard creates a guard. Either authenticator may be nil, which
// refuses the credentials it would have verified; without a
// WithPeerAuthorizationChecker option certificate callers are refused 403.
func NewScopeGuard(tokens TokenAuthorizer, peers PeerAuthenticator, logger *slog.Logger, opts ...ScopeGuardOption) *ScopeGuard {
	if logger == nil {
		logger = slog.Default()
	}
	guard := &ScopeGuard{tokens: tokens, peers: peers, logger: logger}
	for _, opt := range opts {
		if opt != nil {
			opt(guard)
		}
	}
	return guard
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
	authCtx, certificate, err := g.identify(r)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	if err := g.decide(r.Context(), authCtx, certificate, scope); err != nil {
		return nil, http.StatusForbidden, err
	}
	return authCtx, http.StatusOK, nil
}

// decide checks that caller may use scope. A caller authenticated by its
// client certificate is decided by the peer checker for the scope's
// resource and action (refused when none is wired, it errors or it says
// no); any other caller must hold the scope.
func (g *ScopeGuard) decide(ctx context.Context, caller *platformtoken.AuthorizedContext, certificate bool, scope string) error {
	if !certificate {
		if err := caller.RequireScope(scope); err != nil {
			return ErrRouteForbidden{Scope: scope, Reason: err.Error()}
		}
		return nil
	}
	resource, action, ok := strings.Cut(scope, ":")
	if !ok || resource == "" || action == "" {
		return ErrRouteForbidden{Scope: scope, Reason: "the scope names no resource and action"}
	}
	if g.peerChecker == nil {
		return ErrRouteForbidden{Scope: scope, Reason: "no authorization checker is configured for client certificates"}
	}
	allowed, err := g.peerChecker.CheckPeerPermission(ctx, caller, resource, action)
	if err != nil {
		return ErrRouteForbidden{Scope: scope, Reason: "the certificate principal's permission could not be checked: " + err.Error()}
	}
	if !allowed {
		return ErrRouteForbidden{Scope: scope, Reason: "the certificate principal is not granted the permission"}
	}
	return nil
}

// AuthorizeCaller makes the guard's decision for a caller that Authenticate
// handed to a router deciding its own per-route scope: a certificate caller
// is decided by the peer checker, any other caller must hold scope. It
// returns ErrRouteForbidden when the caller may not use scope.
func (g *ScopeGuard) AuthorizeCaller(r *http.Request, caller *platformtoken.AuthorizedContext, scope string) error {
	if g == nil {
		return ErrRouteForbidden{Scope: scope, Reason: "no authorization is configured for this route"}
	}
	if caller == nil {
		return ErrRouteForbidden{Scope: scope, Reason: "no authenticated caller"}
	}
	certificate, _ := r.Context().Value(certificateCallerKey{}).(bool)
	return g.decide(r.Context(), caller, certificate, scope)
}

// Authenticate serves next to any authenticated caller, without a scope
// check, and hands it the caller. It is for a router that makes its own
// per-route scope decision on the caller through AuthorizeCaller (the
// daemon's IAM REST plane). A nil guard answers 403 and a missing or
// invalid credential 401, as Require does.
func (g *ScopeGuard) Authenticate(next CallerHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g == nil {
			writeGuardError(w, g.loggerOrDefault(), http.StatusForbidden, ErrRouteForbidden{Reason: "no authorization is configured for this route"})
			return
		}
		caller, certificate, err := g.identify(r)
		if err != nil {
			writeGuardError(w, g.loggerOrDefault(), http.StatusUnauthorized, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), certificateCallerKey{}, certificate)), caller)
	}
}

// identify authenticates r and returns the caller its credential names and
// whether that credential was the client certificate.
func (g *ScopeGuard) identify(r *http.Request) (*platformtoken.AuthorizedContext, bool, error) {
	authCtx, certificate, err := g.authenticate(r)
	if err != nil {
		return nil, false, err
	}
	if authCtx == nil {
		return nil, false, ErrRouteUnauthenticated{Reason: "the credential authorized no caller"}
	}
	return authCtx, certificate, nil
}

// authenticate resolves the caller from its bearer token, or else from its
// verified client certificate; certificate reports the latter.
func (g *ScopeGuard) authenticate(r *http.Request) (authCtx *platformtoken.AuthorizedContext, certificate bool, err error) {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		if g.tokens == nil {
			return nil, false, ErrRouteUnauthenticated{Reason: "bearer tokens are not accepted on this listener"}
		}
		authCtx, err := g.tokens.AuthorizeToken(r.Context(), strings.TrimSpace(token), "", r.Header.Get("DPoP"), r.Method, requestURL(r))
		if err != nil {
			return nil, false, ErrRouteUnauthenticated{Reason: err.Error()}
		}
		return authCtx, false, nil
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil, false, ErrRouteUnauthenticated{Reason: "no bearer token or verified client certificate"}
	}
	if g.peers == nil {
		return nil, false, ErrRouteUnauthenticated{Reason: "client certificates are not accepted on this listener"}
	}
	authCtx, err = g.peers.AuthenticatePeer(r.Context(), r.TLS.VerifiedChains[0])
	if err != nil {
		return nil, false, ErrRouteUnauthenticated{Reason: err.Error()}
	}
	return authCtx, true, nil
}

func (g *ScopeGuard) loggerOrDefault() *slog.Logger {
	if g == nil {
		return slog.Default()
	}
	return g.logger
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
