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

package iam

import (
	"context"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-quicbaas/pkg/iam/dpop"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// DPoPHeader is the RFC 9449 HTTP header carrying the DPoP proof JWT.
const DPoPHeader = "DPoP"

// platformTokenValidator is the subset of the QuicBaaS platformtoken.Validator
// the middleware depends on. Defining it as an interface keeps the middleware
// unit-testable without standing up a JWKS HTTP source while still binding to
// the real validator in production.
type platformTokenValidator interface {
	ValidatePlatformToken(ctx context.Context, token string) (*platformtoken.Claims, error)
	ValidateWithDPoP(ctx context.Context, token, dpopProof, htm, htu string, replayCache dpop.ReplayCache) (*platformtoken.Claims, error)
}

// PlatformTokenConfig configures the inbound platform-token middleware. It is
// the middleware-layer projection of the YAML webservice JWT.PlatformToken
// block, resolved into the concrete validator inputs.
type PlatformTokenConfig struct {
	// AllowBearer accepts a non-sender-constrained bearer token when the
	// request carries no DPoP header. When false, every request must present
	// a DPoP proof bound to the token's cnf.jkt.
	AllowBearer bool
}

// PlatformTokenMiddleware validates inbound QuicBaaS broker platform tokens as a
// pure consumer: it verifies the token signature against the broker JWKS (by
// kid), checks iss/aud/exp via the platformtoken.Validator, optionally binds a
// presented DPoP proof to the token's cnf.jkt (RFC 9449), and projects the
// validated claims into an AuthorizedContext (scp -> RBAC, tenant_id -> RLS)
// that downstream handlers and the AuthzMiddleware consume.
//
// It satisfies middleware.AuthMiddleware (Verify + RefreshToken) so it can be
// installed at the same router seam as the legacy JWT handler.
type PlatformTokenMiddleware struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	validator      platformTokenValidator
	config         PlatformTokenConfig
	replayCache    dpop.ReplayCache
}

// NewPlatformTokenMiddleware constructs a PlatformTokenMiddleware from a fully
// constructed validator. The validator is built from PlatformTokenConfig in the
// handler registry (which owns the broker issuer / JWKS URL / audience), so this
// constructor stays free of network and key-source concerns.
func NewPlatformTokenMiddleware(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	validator platformTokenValidator,
	config PlatformTokenConfig,
) (*PlatformTokenMiddleware, error) {

	if logger == nil {
		return nil, ErrInvalidConfig{Field: "logger", Reason: "logger is required"}
	}
	if responseWriter == nil {
		return nil, ErrInvalidConfig{Field: "responseWriter", Reason: "response writer is required"}
	}
	if validator == nil {
		return nil, ErrInvalidConfig{Field: "validator", Reason: "platform-token validator is required"}
	}

	return &PlatformTokenMiddleware{
		logger:         logger,
		responseWriter: responseWriter,
		validator:      validator,
		config:         config,
		replayCache:    dpop.NewMemoryReplayCache(dpop.SystemClock{}),
	}, nil
}

// Handler returns an http.Handler middleware that validates platform tokens.
func (m *PlatformTokenMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Verify(w, r, next.ServeHTTP)
	})
}

// Verify validates the inbound platform token (and, when present or required,
// its DPoP proof), stores the resulting AuthorizedContext and an IAMSession in
// the request context, and calls next on success. On any validation failure it
// writes a 401 and does not call next.
func (m *PlatformTokenMiddleware) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	authCtx, err := m.authorize(r)
	if err != nil {
		m.logger.Debugf("platform-token: validation failed: %v", err)
		m.responseWriter.Error401(w, r, err)
		return
	}

	ctx := SetAuthorizedContext(r.Context(), authCtx)
	ctx = SetSessionInContext(ctx, sessionFromAuthorizedContext(authCtx))
	next(w, r.WithContext(ctx))
}

// authorize extracts and validates the bearer token and (where applicable) the
// DPoP proof, returning the projected AuthorizedContext. All branches return a
// typed error the caller maps to 401.
func (m *PlatformTokenMiddleware) authorize(r *http.Request) (*platformtoken.AuthorizedContext, error) {
	token, err := extractBearer(r)
	if err != nil {
		return nil, err
	}

	dpopProof := strings.TrimSpace(r.Header.Get(DPoPHeader))

	var claims *platformtoken.Claims
	if dpopProof != "" {
		claims, err = m.validator.ValidateWithDPoP(
			r.Context(), token, dpopProof, r.Method, requestURL(r), m.replayCache)
	} else {
		if !m.config.AllowBearer {
			return nil, ErrTokenInvalid{Reason: "DPoP proof required"}
		}
		claims, err = m.validator.ValidatePlatformToken(r.Context(), token)
	}
	if err != nil {
		return nil, err
	}

	return platformtoken.Authorize(claims), nil
}

// RefreshToken is not supported on the pure-validator path: the platform does
// not mint broker tokens, it only validates them. Refresh is the broker's
// responsibility. It always returns 401 so the contract is explicit.
func (m *PlatformTokenMiddleware) RefreshToken(w http.ResponseWriter, r *http.Request) {
	m.responseWriter.Error401(w, r, ErrTokenInvalid{
		Reason: "token refresh is performed by the broker, not the platform",
	})
}

// RequireScope returns a route guard that enforces the validated context was
// granted scope, writing 403 when it was not. It is the scp -> RBAC enforcement
// helper for protected routes.
func (m *PlatformTokenMiddleware) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, ok := AuthorizedContextFromRequest(r)
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "no authorized context"})
				return
			}
			if err := authCtx.RequireScope(scope); err != nil {
				m.logger.Debugf("platform-token: scope denied: %v", err)
				m.responseWriter.Error403(w, r, ErrForbidden{Reason: err.Error()}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyScope returns a route guard that enforces at least one of scopes was
// granted, writing 403 otherwise.
func (m *PlatformTokenMiddleware) RequireAnyScope(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, ok := AuthorizedContextFromRequest(r)
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "no authorized context"})
				return
			}
			if err := authCtx.RequireAnyScope(scopes...); err != nil {
				m.logger.Debugf("platform-token: scope denied: %v", err)
				m.responseWriter.Error403(w, r, ErrForbidden{Reason: err.Error()}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns a route guard that enforces the validated context carries
// role in its supplemental roles claim, writing 403 otherwise.
func (m *PlatformTokenMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, ok := AuthorizedContextFromRequest(r)
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "no authorized context"})
				return
			}
			if !authCtx.HasRole(role) {
				m.logger.Debugf("platform-token: role %q not granted", role)
				m.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "required role not granted: " + role,
				}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractBearer pulls the bearer token from the Authorization header.
func extractBearer(r *http.Request) (string, error) {
	authHeader := r.Header.Get(AuthorizationHeader)
	if authHeader == "" {
		return "", ErrMissingToken{}
	}
	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return "", ErrTokenInvalid{Reason: "invalid authorization header format"}
	}
	token := strings.TrimPrefix(authHeader, BearerPrefix)
	if token == "" {
		return "", ErrMissingToken{}
	}
	return token, nil
}

// requestURL reconstructs the absolute request URL (htu) used for DPoP htu
// matching. The DPoP htu excludes query and fragment per RFC 9449 §4.3.
func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
			scheme = forwarded
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return scheme + "://" + host + r.URL.Path
}

// sessionFromAuthorizedContext builds an IAMSession from a validated
// AuthorizedContext so the existing session-aware handlers and AuthzMiddleware
// (which reads the session for tenant + roles) continue to work unchanged on the
// platform-token path. Scopes are surfaced as roles for the session's RBAC view
// in addition to the supplemental roles claim.
func sessionFromAuthorizedContext(authCtx *platformtoken.AuthorizedContext) IAMSession {
	roles := make([]string, 0, len(authCtx.Roles)+len(authCtx.Scopes))
	roles = append(roles, authCtx.Roles...)
	roles = append(roles, authCtx.Scopes...)

	user := &iamsdk.User{
		ID:       authCtx.Subject,
		TenantID: authCtx.TenantID,
		Username: authCtx.Subject,
		Roles:    roles,
	}
	return NewIAMSession(user)
}

// authorizedContextKeyType is the context key for the AuthorizedContext.
type authorizedContextKeyType struct{}

var authorizedContextKey = authorizedContextKeyType{}

// SetAuthorizedContext stores the validated AuthorizedContext in ctx.
func SetAuthorizedContext(ctx context.Context, authCtx *platformtoken.AuthorizedContext) context.Context {
	return context.WithValue(ctx, authorizedContextKey, authCtx)
}

// AuthorizedContextFromContext retrieves the validated AuthorizedContext.
func AuthorizedContextFromContext(ctx context.Context) (*platformtoken.AuthorizedContext, bool) {
	authCtx, ok := ctx.Value(authorizedContextKey).(*platformtoken.AuthorizedContext)
	return authCtx, ok
}

// AuthorizedContextFromRequest retrieves the validated AuthorizedContext from
// the request context.
func AuthorizedContextFromRequest(r *http.Request) (*platformtoken.AuthorizedContext, bool) {
	return AuthorizedContextFromContext(r.Context())
}
