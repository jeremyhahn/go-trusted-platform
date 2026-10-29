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

package quic

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrAuthValidatorNotConfigured is returned when no token validator is available.
type ErrAuthValidatorNotConfigured struct{}

func (e ErrAuthValidatorNotConfigured) Error() string {
	return "OIDC token validator not configured"
}

// ErrMissingToken is returned when no token is present in the request.
type ErrMissingToken struct{}

func (e ErrMissingToken) Error() string {
	return "missing authentication token"
}

// ErrTokenValidationFailed is returned when token validation fails.
type ErrTokenValidationFailed struct {
	Cause error
}

func (e ErrTokenValidationFailed) Error() string {
	if e.Cause != nil {
		return "token validation failed: " + e.Cause.Error()
	}
	return "token validation failed"
}

func (e ErrTokenValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrPermissionDenied is returned when the user lacks permission.
type ErrPermissionDenied struct {
	Resource string
	Action   string
}

func (e ErrPermissionDenied) Error() string {
	return "permission denied: " + e.Action + " on " + e.Resource
}

// =============================================================================
// Token Validator Interface
// =============================================================================

// TokenValidator validates authentication tokens.
// This interface allows for different token validation implementations
// (e.g., QuicBaaS OIDC provider, local JWT validation, etc.).
type TokenValidator interface {
	// ValidateToken validates a token and returns whether it's valid.
	ValidateToken(ctx context.Context, token string) (bool, error)
}

// AuthorizationChecker checks if an authenticated user has permission for an action.
type AuthorizationChecker interface {
	// CheckPermission checks if the subject has permission for the given resource and action.
	CheckPermission(ctx context.Context, subject, resource, action string) (bool, error)
}

// =============================================================================
// Token Context Key
// =============================================================================

// tokenContextKey is the context key for the validated token.
type tokenContextKey struct{}

// ContextWithToken adds a validated token to the context.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

// TokenFromContext extracts the validated token from the context.
func TokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(tokenContextKey{}).(string)
	return token, ok
}

// =============================================================================
// Auth Middleware
// =============================================================================

// AuthMiddleware provides authentication and authorization for QUIC handlers.
//
// GuardRequest is the single entry point the dispatcher calls for every
// request: it resolves the operation's permission from the catalog
// (opcode_permissions.go), authenticates the caller and enforces the
// permission. Unclassified operations are refused.
type AuthMiddleware struct {
	tokenValidator    TokenValidator
	peerAuthenticator PeerAuthenticator
	authzChecker      AuthorizationChecker
	requireAuth       bool
	peerAuthenticated bool
}

// AuthMiddlewareOption configures the auth middleware.
type AuthMiddlewareOption func(*AuthMiddleware)

// WithQUICTokenValidator sets the token validator.
func WithQUICTokenValidator(v TokenValidator) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.tokenValidator = v
	}
}

// WithQUICAuthorizationChecker sets the authorization checker.
func WithQUICAuthorizationChecker(c AuthorizationChecker) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.authzChecker = c
	}
}

// WithQUICRequireAuth sets whether authentication is required.
func WithQUICRequireAuth(require bool) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.requireAuth = require
	}
}

// WithQUICPeerAuthenticated marks the transport as having authenticated the
// peer itself (mutual TLS: the listener rejects any client certificate the
// client CA pool does not verify). A request without a token is then
// authenticated by its certificate, the same as the gRPC mTLS listener. A
// request that does present a token is still validated, and its scopes are
// still enforced, when a token validator is configured.
func WithQUICPeerAuthenticated() AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.peerAuthenticated = true
	}
}

// NewAuthMiddleware creates a new auth middleware.
func NewAuthMiddleware(opts ...AuthMiddlewareOption) *AuthMiddleware {
	m := &AuthMiddleware{
		requireAuth: true, // Default to requiring auth
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// GuardRequest authenticates and authorizes a request before it is
// dispatched. It returns the context to dispatch with (carrying the
// validated token and AuthorizedContext), or a non-nil response that must be
// sent instead of dispatching.
//
// Order matters: pre-auth operations pass untouched; every other request is
// authenticated first, so an anonymous caller learns nothing about which
// operations exist; then an unclassified operation is refused and a
// classified one must carry its permission.
func (m *AuthMiddleware) GuardRequest(ctx context.Context, req *quicwire.Request) (context.Context, *quicwire.Response) {
	perm, preAuth, lookupErr := LookupOperationPermission(req.Opcode, req.Payload)
	if preAuth {
		return ctx, nil
	}

	byPeer := m.authenticatesByPeer(req)
	ctx, resp := m.AuthenticateRequest(ctx, req)
	if resp != nil {
		return ctx, resp
	}

	if lookupErr != nil {
		var missing ErrSubOpcodeMissing
		if errors.As(lookupErr, &missing) {
			return ctx, &quicwire.Response{Status: quicwire.StatusInvalidRequest, Payload: []byte(lookupErr.Error())}
		}
		return ctx, &quicwire.Response{Status: quicwire.StatusPermissionDenied, Payload: []byte(lookupErr.Error())}
	}

	if resp := m.AuthorizeRequest(ctx, perm.Resource, perm.Action); resp != nil {
		// A certificate-authenticated caller outside its scopes may still
		// call the methods its authenticator admits, as on gRPC.
		if byPeer && m.peerAdmitsOperation(req) {
			return ctx, nil
		}
		return ctx, resp
	}
	return ctx, nil
}

// AuthenticateRequest validates the token in a request.
// Returns the validated token, or an error response if authentication fails.
func (m *AuthMiddleware) AuthenticateRequest(ctx context.Context, req *quicwire.Request) (context.Context, *quicwire.Response) {
	// Under mTLS the connection's verified client certificate is the
	// credential of a request without a token, and of every request when no
	// token validator is configured. A presented token is still validated.
	if m.authenticatesByPeer(req) {
		return m.authenticatePeer(ctx)
	}

	// The transport verified the peer certificate; a request without a token
	// is authenticated by it.
	if m.peerAuthenticated && req.Token == "" {
		return ctx, nil
	}

	// If no validator configured, handle based on requireAuth setting
	if m.tokenValidator == nil {
		if m.requireAuth && !m.peerAuthenticated {
			return ctx, &quicwire.Response{
				Status:  quicwire.StatusUnavailable,
				Payload: []byte(ErrAuthValidatorNotConfigured{}.Error()),
			}
		}
		return ctx, nil
	}

	// Check for token
	if req.Token == "" {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte(ErrMissingToken{}.Error()),
		}
	}

	// Prefer the platform-token (claims) path when the validator supports it:
	// validate the framed bearer token, project scp -> RBAC / tenant_id -> RLS,
	// and stash the AuthorizedContext for AuthorizeRequest and downstream
	// handlers. QUIC has no DPoP frame, so this is always a bearer validation.
	//
	// requiredPerm="" routes through the validator's scope-free path: the
	// operation's required scope is enforced afterwards in AuthorizeRequest
	// against the stored AuthorizedContext, so a valid token lacking the
	// scope is answered PermissionDenied rather than Unauthorized. Online
	// liveness/revocation is still enforced here on every request. QUIC has
	// no DPoP frame, so the proof / htm / htu inputs are empty.
	if cv, ok := m.tokenValidator.(ClaimsTokenValidator); ok {
		authCtx, err := cv.AuthorizeToken(ctx, req.Token, "", "", "", "")
		if err != nil {
			return ctx, &quicwire.Response{
				Status:  quicwire.StatusUnauthorized,
				Payload: []byte(ErrTokenValidationFailed{Cause: err}.Error()),
			}
		}
		ctx = ContextWithAuthorizedContext(ctx, authCtx)
		return ContextWithToken(ctx, req.Token), nil
	}

	// Validate token (legacy bool-only path)
	valid, err := m.tokenValidator.ValidateToken(ctx, req.Token)
	if err != nil {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte(ErrTokenValidationFailed{Cause: err}.Error()),
		}
	}
	if !valid {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte("invalid token"),
		}
	}

	// Add validated token to context
	return ContextWithToken(ctx, req.Token), nil
}

// AuthorizeRequest checks if the authenticated user has permission for the operation.
// This should be called after AuthenticateRequest.
func (m *AuthMiddleware) AuthorizeRequest(ctx context.Context, resource, action string) *quicwire.Response {
	// When the request was validated via the platform-token (claims) path, an
	// AuthorizedContext is present: enforce scp -> RBAC against it directly
	// (the resource/action pair projects to the "resource:action" scope). This
	// is the canonical authorization path for broker-issued tokens.
	if authCtx, ok := AuthorizedContextFromContext(ctx); ok {
		scope := scopeForOperation(resource, action)
		if scope == "" {
			return nil
		}
		if err := authCtx.RequireScope(scope); err != nil {
			return &quicwire.Response{
				Status:  quicwire.StatusPermissionDenied,
				Payload: []byte(ErrPermissionDenied{Resource: resource, Action: action}.Error()),
			}
		}
		return nil
	}

	// No claims and no authorization checker: the caller was authenticated
	// by a scope-less credential (a peer certificate, or a validator without
	// claims), which authorizes every classified operation, as on gRPC.
	if m.authzChecker == nil {
		return nil
	}

	// Get token from context
	token, ok := TokenFromContext(ctx)
	if !ok {
		return &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte("no authenticated session"),
		}
	}

	// Check permission
	allowed, err := m.authzChecker.CheckPermission(ctx, token, resource, action)
	if err != nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInternalError,
			Payload: []byte("authorization check failed: " + err.Error()),
		}
	}
	if !allowed {
		return &quicwire.Response{
			Status:  quicwire.StatusPermissionDenied,
			Payload: []byte(ErrPermissionDenied{Resource: resource, Action: action}.Error()),
		}
	}

	return nil
}
