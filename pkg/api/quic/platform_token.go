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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// ClaimsTokenValidator is the richer optional interface a TokenValidator may
// implement to project a validated platform token into an AuthorizedContext
// (scp -> RBAC, tenant_id -> RLS). The QUIC auth middleware type-asserts for
// it: when present, AuthenticateRequest validates via this path and stashes the
// AuthorizedContext in the request context, and AuthorizeRequest enforces the
// required scope against it. When absent, the middleware falls back to the
// bool-only ValidateToken + AuthorizationChecker path.
//
// QUIC carries the access token in a framed protocol field (req.Token), not an
// HTTP header, and has no DPoP frame, so QUIC validation is always bearer: the
// proof / htm / htu inputs to the validator are empty.
type ClaimsTokenValidator interface {
	// AuthorizeToken runs the full validator pipeline and returns the projected
	// AuthorizedContext. When requiredPerm is empty the offline scope check is
	// skipped but the per-tenant online liveness/revocation check is still
	// enforced. QUIC authenticates with requiredPerm="" (the opcode's required
	// scope is not known until AuthorizeRequest, which then enforces it against
	// the stored AuthorizedContext), so liveness runs on every request path.
	AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error)
}

// authorizedContextKeyType is the context key for the validated AuthorizedContext.
type authorizedContextKeyType struct{}

var authorizedContextKey = authorizedContextKeyType{}

// ContextWithAuthorizedContext stores the validated AuthorizedContext in ctx so
// QUIC handlers enforce scp -> RBAC and tenant_id -> RLS uniformly with the
// other transports.
func ContextWithAuthorizedContext(ctx context.Context, authCtx *platformtoken.AuthorizedContext) context.Context {
	return context.WithValue(ctx, authorizedContextKey, authCtx)
}

// AuthorizedContextFromContext retrieves the validated AuthorizedContext.
func AuthorizedContextFromContext(ctx context.Context) (*platformtoken.AuthorizedContext, bool) {
	authCtx, ok := ctx.Value(authorizedContextKey).(*platformtoken.AuthorizedContext)
	return authCtx, ok
}

// scopeForOperation maps a QUIC resource/action permission pair to the platform
// token scope convention: the qrdb-canonical colon "resource:action" (e.g.
// "dns:write"). This is the QUIC projection of DefaultOpcodePermissions onto
// the platform scope catalog, which matches the scp claim the broker mints from
// a subject's qrdb-resolved permissions.
func scopeForOperation(resource, action string) string {
	if resource == "" || action == "" {
		return ""
	}
	return resource + ":" + action
}
