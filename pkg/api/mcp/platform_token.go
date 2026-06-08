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
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// ClaimsAuthManager is the richer optional interface an AuthManager may
// implement to project a validated platform token into an AuthorizedContext
// (scp -> RBAC, tenant_id -> RLS). The AuthorizationChecker type-asserts the
// configured AuthManager for it: when present, CheckToolAuthorization validates
// the token, stashes the AuthorizedContext, and enforces the tool's required
// scope against it. When absent, it falls back to the legacy
// AuthManager.ValidateToken + AuthorizationService.CheckPermission path.
//
// MCP carries the bearer token over its transport (HTTP Authorization header
// for the HTTP transport); DPoP binding follows the HTTP path's optional rule
// and is supplied via dpopProof when available.
type ClaimsAuthManager interface {
	// AuthorizeToken validates the bearer token (binding the DPoP proof when a
	// non-empty proof is supplied) and returns the projected AuthorizedContext,
	// or a typed error.
	AuthorizeToken(ctx context.Context, token, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error)
}

// authorizedContextKeyType is the context key for the validated AuthorizedContext.
type authorizedContextKeyType struct{}

var authorizedContextKey = authorizedContextKeyType{}

// ContextWithAuthorizedContext stores the validated AuthorizedContext in ctx so
// MCP tool handlers enforce scp -> RBAC and tenant_id -> RLS uniformly with the
// other transports.
func ContextWithAuthorizedContext(ctx context.Context, authCtx *platformtoken.AuthorizedContext) context.Context {
	return context.WithValue(ctx, authorizedContextKey, authCtx)
}

// AuthorizedContextFromContext retrieves the validated AuthorizedContext.
func AuthorizedContextFromContext(ctx context.Context) (*platformtoken.AuthorizedContext, bool) {
	authCtx, ok := ctx.Value(authorizedContextKey).(*platformtoken.AuthorizedContext)
	return authCtx, ok
}

// scopeForToolPermission maps an MCP tool-permission string ("<svc>:<verb>",
// e.g. "dns:write") to the platform token scope convention "<svc>.<verb>"
// (e.g. "dns.write"). An empty permission means no scope is required.
func scopeForToolPermission(permission string) string {
	if permission == "" {
		return ""
	}
	parts := strings.SplitN(permission, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "." + parts[1]
}
