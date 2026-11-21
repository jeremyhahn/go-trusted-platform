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

package mcp

import (
	"context"
	"errors"
	"strings"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
)

// AuthorizationChecker validates tool authorization.
type AuthorizationChecker struct {
	authService AuthorizationService
	authManager AuthManager

	// peerAuthenticator turns the verified client certificate of a
	// tokenless request into its principal; nil disables that path.
	peerAuthenticator PeerAuthenticator

	// toolPermissions maps tool names to required permissions
	toolPermissions map[string]string

	// pep decides a tool permission when the token carried no scope grant.
	pep iam.PEPClient
}

// NewAuthorizationChecker creates a new authorization checker.
func NewAuthorizationChecker(authService AuthorizationService, authManager AuthManager, opts ...AuthorizationCheckerOption) *AuthorizationChecker {
	c := &AuthorizationChecker{
		authService:     authService,
		authManager:     authManager,
		toolPermissions: declaredToolPermissions(PlatformTools{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// declaredToolPermissions reads a module's MCP tool declaration into the
// checker's table. A nil module declares nothing, so every tool is denied.
func declaredToolPermissions(module quicbaas.ModuleMCPToolPermissions) map[string]string {
	permissions := make(map[string]string)
	if module == nil {
		return permissions
	}
	for name, permission := range module.MCPToolPermissions() {
		permissions[name] = permission.String()
	}
	return permissions
}

// WithToolPermissions makes the checker enforce the given module's declared
// MCP tool permissions in place of the platform module's (SPEC row 116).
func WithToolPermissions(module quicbaas.ModuleMCPToolPermissions) AuthorizationCheckerOption {
	return func(c *AuthorizationChecker) {
		c.toolPermissions = declaredToolPermissions(module)
	}
}

// permissionResourceAction splits a declared Permission into the resource and
// action the PEP decides. The SDK's Permission is "resource:action"; the
// pinned go-quicbaas SDK re-exports no accessor for the two halves (go-qrdb's
// permission.Resource/Action are behind the layer guard), so the split is
// done here, on the first colon.
func permissionResourceAction(permission quicbaas.Permission) (resource, action string, ok bool) {
	resource, action, ok = strings.Cut(permission.String(), ":")
	return resource, action, ok && resource != "" && action != ""
}

// CheckToolAuthorization checks if the given token has permission to execute the
// tool. It is the context-less form retained for callers that do not need the
// projected AuthorizedContext; it delegates to AuthorizeTool and discards the
// returned context.
func (c *AuthorizationChecker) CheckToolAuthorization(ctx context.Context, toolName string, token string) *AuthorizationError {
	_, authErr := c.AuthorizeTool(ctx, toolName, token)
	return authErr
}

// AuthorizeTool validates the token and authorizes the tool, returning a context
// enriched with the validated AuthorizedContext (scp -> RBAC, tenant_id -> RLS)
// when the configured AuthManager supports the claims path. The returned context
// is the input context unchanged on the legacy / unauthenticated paths.
func (c *AuthorizationChecker) AuthorizeTool(ctx context.Context, toolName string, token string) (context.Context, *AuthorizationError) {
	// Get required permission for tool
	// A tool with no entry is DENIED. The map is a permission grant, not an
	// optional annotation.
	//
	// This previously returned nil — allow — with a comment saying the tool
	// registry would handle the error. It does not: a registered tool with no
	// map entry reached its handler unauthorized, and 357 of 428 registered
	// tools had no entry, including BMC power control and virtual-media
	// mounting (#300). The gap between what that comment described and what
	// the code did is why it survived review.
	//
	// A tool that legitimately needs no permission says so with an explicit
	// empty string, which is handled just below.
	permission, exists := c.toolPermissions[toolName]
	if !exists {
		return ctx, &AuthorizationError{
			Type:    AuthErrorToolNotClassified,
			Message: "tool '" + toolName + "' has no permission mapping and cannot be authorized",
		}
	}

	// If no permission required, allow
	if permission == "" {
		return ctx, nil
	}

	// An identity-gated tool needs an authenticated caller and nothing
	// more: its handler decides, so the PEP is not asked.
	if quicbaas.Permission(permission) == quicbaas.PermissionIdentityGated {
		authCtx, outcome, authErr := c.authenticate(ctx, token, "")
		if authErr != nil {
			return ctx, authErr
		}
		if outcome == authUnverified {
			return ctx, &AuthorizationError{
				Type:    AuthErrorMissingToken,
				Message: "Authentication required for this operation",
			}
		}
		return authCtx, nil
	}

	// A malformed declaration ("bmc", "bmc:") has no scope, and an empty
	// scope passes authenticate for any claims or mTLS caller: refuse it
	// before authenticating, not after (#2011 Codex r2).
	resource, action, ok := permissionResourceAction(quicbaas.Permission(permission))
	if !ok {
		return ctx, &AuthorizationError{
			Type:    AuthErrorPermissionDenied,
			Message: "Invalid permission configuration",
		}
	}

	authCtx, outcome, authErr := c.authenticate(ctx, token, scopeForToolPermission(permission))
	if authErr != nil {
		return ctx, authErr
	}
	if outcome == authScoped {
		return authCtx, nil
	}

	// The token was validated without a scope (legacy path) or not verified
	// at all (authService only): the IAM PEP decides the tool's permission
	// for the caller (SPEC row 116, #1995). No PEP, no caller or a PEP
	// failure is a denial.
	denied := &AuthorizationError{
		Type:    AuthErrorPermissionDenied,
		Message: "Permission denied: insufficient privileges",
	}
	if c.pep == nil || c.authManager == nil {
		return ctx, denied
	}
	claims, err := c.authManager.GetTokenClaims(ctx, token)
	if err != nil {
		return ctx, denied
	}
	subject := pepSubjectFromClaims(claims)
	// The legacy ValidateToken path fills the user and roles but no tenant;
	// the old QuicBaaSAuthAdapter refused a blank tenant before deciding, so
	// a tenantless caller never reaches the PEP (#2011 Codex).
	if subject.ID == "" || strings.TrimSpace(subject.TenantID) == "" {
		return ctx, denied
	}
	resp, err := c.pep.Check(ctx, &iam.CheckRequest{
		Subject:  subject,
		TenantID: subject.TenantID,
		Resource: resource,
		Action:   action,
	})
	if err != nil || resp == nil || !resp.Allowed {
		return ctx, denied
	}
	return ctx, nil
}

// pepSubjectFromClaims builds the PEP subject from a token's claims.
func pepSubjectFromClaims(claims map[string]interface{}) iam.CheckSubject {
	var s iam.CheckSubject
	s.ID, _ = claims["sub"].(string)
	s.TenantID, _ = claims["tenant_id"].(string)
	s.Roles = claimStrings(claims["roles"])
	s.Groups = claimStrings(claims["groups"])
	return s
}

// claimStrings reads a claim that is a []string or a JSON-decoded []interface{}.
func claimStrings(v interface{}) []string {
	switch vals := v.(type) {
	case []string:
		return vals
	case []interface{}:
		out := make([]string, 0, len(vals))
		for _, x := range vals {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// WithPEPClient sets the IAM policy enforcement point that decides a tool
// permission on the unscoped path.
func WithPEPClient(pep iam.PEPClient) AuthorizationCheckerOption {
	return func(c *AuthorizationChecker) {
		c.pep = pep
	}
}

// Authenticate establishes that the caller is a principal, with the same
// authentication branches as AuthorizeTool but no tool permission lookup
// and no scope check. Listing methods (tools/list, resources/list) call it
// so an anonymous client cannot enumerate the catalogue, as the REST stack
// answers the equivalent with 401 (#414).
//
// A tokenless request under mTLS authenticates with its verified client
// certificate. With no authorization backend nothing can establish a
// principal, so the request is refused (#440). A token is validated by the
// claims path (empty requiredPerm: liveness kept, scope skipped) or the
// legacy ValidateToken. With only an authService configured no backend
// verifies a presented token (that service checks permissions, not
// identity), so the token is refused as invalid: an arbitrary string is
// not a principal (#1879).
func (c *AuthorizationChecker) Authenticate(ctx context.Context, token string) *AuthorizationError {
	_, outcome, authErr := c.authenticate(ctx, token, "")
	if authErr != nil {
		return authErr
	}
	if outcome == authUnverified {
		return &AuthorizationError{
			Type:    AuthErrorInvalidToken,
			Message: "Invalid or expired token: no authentication backend can verify it",
		}
	}
	return nil
}

// authOutcome says how far authenticate established the caller.
type authOutcome int

const (
	// authScoped: the caller is a verified principal and the requested
	// scope (if any) was enforced; the returned context carries the
	// AuthorizedContext.
	authScoped authOutcome = iota
	// authValidated: the legacy AuthManager validated the token, but no
	// scope was enforced.
	authValidated
	// authUnverified: a token was presented but no backend verified it
	// (only an authService is configured).
	authUnverified
)

// authenticate holds the authentication branches shared by AuthorizeTool and
// Authenticate. scope is the required scope enforced on the peer and claims
// paths; empty skips the scope check.
//
// Under mTLS the verified client certificate authenticates a tokenless
// request, as on REST, gRPC and QUIC. A presented token never takes that
// path: it is validated by the token backend.
//
// With no authorization backend there is nothing that can grant a
// permission or establish a principal, so the request is refused (#440).
// This used to allow everything "for test mode and standalone deployments",
// which served every tool to any caller whenever the IAM wiring failed at
// startup; a default that allows when the deciding component is absent is
// the shape #300 closed one layer up.
func (c *AuthorizationChecker) authenticate(ctx context.Context, token, scope string) (context.Context, authOutcome, *AuthorizationError) {
	if token == "" && c.peerAuthenticator != nil {
		state, _, _ := channelbind.ConnectionTLS(ctx)
		if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			return ctx, authUnverified, &AuthorizationError{
				Type:    AuthErrorMissingToken,
				Message: "Authentication required for this operation: no bearer token and no verified client certificate",
			}
		}
		authCtx, err := c.peerAuthenticator.AuthenticatePeer(ctx, state.VerifiedChains[0])
		if err != nil || authCtx == nil {
			return ctx, authUnverified, &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid client certificate",
			}
		}
		if scope != "" {
			if err := authCtx.RequireScope(scope); err != nil {
				return ctx, authUnverified, &AuthorizationError{
					Type:    AuthErrorPermissionDenied,
					Message: "Permission denied: insufficient privileges",
				}
			}
		}
		return ContextWithAuthorizedContext(ctx, authCtx), authScoped, nil
	}

	if c.authService == nil && c.authManager == nil {
		return ctx, authUnverified, &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation: no authorization backend is configured",
		}
	}

	if token == "" {
		return ctx, authUnverified, &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation",
		}
	}

	// Prefer the platform-token (claims) path when the AuthManager supports
	// it: the scope is enforced INSIDE the validator so the offline scope
	// check and online liveness run in one pipeline. A scope denial surfaces
	// as a *platformtoken.ScopeDeniedError; every other failure (auth,
	// liveness) is an invalid/expired token.
	if cv, ok := c.authManager.(ClaimsAuthManager); ok && cv != nil {
		authCtx, err := cv.AuthorizeToken(ctx, token, scope, "", "", "")
		if err != nil {
			var scopeErr *platformtoken.ScopeDeniedError
			if errors.As(err, &scopeErr) {
				return ctx, authUnverified, &AuthorizationError{
					Type:    AuthErrorPermissionDenied,
					Message: "Permission denied: insufficient privileges",
				}
			}
			return ctx, authUnverified, &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid or expired token",
			}
		}
		// The token goes on ctx with its grant, whether it came in the
		// params or the request: a tool that accepts only a token's grant,
		// never a peer certificate's, tells the two apart by it.
		return ContextWithAuthorizedContext(ContextWithToken(ctx, token), authCtx), authScoped, nil
	}

	// Legacy bool-only path.
	if c.authManager != nil {
		valid, err := c.authManager.ValidateToken(ctx, token)
		if err != nil || !valid {
			return ctx, authUnverified, &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid or expired token",
			}
		}
		return ctx, authValidated, nil
	}

	return ctx, authUnverified, nil
}

// IsEnabled returns true if authorization checking is enabled.
func (c *AuthorizationChecker) IsEnabled() bool {
	return c.authService != nil || c.authManager != nil
}
