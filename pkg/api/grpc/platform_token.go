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

package grpc

import (
	"context"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc/metadata"
)

// DPoPMetadataKey is the lowercase gRPC metadata key carrying an RFC 9449 DPoP
// proof JWT. gRPC normalizes metadata keys to lowercase, so callers send the
// proof under "dpop".
const DPoPMetadataKey = "dpop"

// ClaimsTokenValidator is the richer optional interface a TokenValidator may
// implement to project a validated platform token into an AuthorizedContext
// (scp -> RBAC, tenant_id -> RLS). The OIDC interceptors type-assert for it:
// when present, they validate via this path and stash the AuthorizedContext in
// the request context; when absent, they fall back to the bool-only
// ValidateToken path (the legacy QuicBaaS / platform-JWT adapter). This keeps
// the cutover additive — existing validators continue to work unchanged.
type ClaimsTokenValidator interface {
	// AuthorizeToken validates the bearer token (binding the DPoP proof when a
	// non-empty proof is supplied), returning the projected AuthorizedContext on
	// success or a typed error the interceptor maps to Unauthenticated.
	AuthorizeToken(ctx context.Context, token, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error)
}

// authorizedContextKeyType is the context key for the validated AuthorizedContext.
type authorizedContextKeyType struct{}

var authorizedContextKey = authorizedContextKeyType{}

// ContextWithAuthorizedContext stores the validated AuthorizedContext in ctx so
// downstream handlers enforce scp -> RBAC and tenant_id -> RLS uniformly with
// the HTTP path.
func ContextWithAuthorizedContext(ctx context.Context, authCtx *platformtoken.AuthorizedContext) context.Context {
	return context.WithValue(ctx, authorizedContextKey, authCtx)
}

// AuthorizedContextFromContext retrieves the validated AuthorizedContext.
func AuthorizedContextFromContext(ctx context.Context) (*platformtoken.AuthorizedContext, bool) {
	authCtx, ok := ctx.Value(authorizedContextKey).(*platformtoken.AuthorizedContext)
	return authCtx, ok
}

// dpopProofFromContext extracts a DPoP proof from incoming gRPC metadata, if
// present. gRPC has no HTTP request line, so DPoP htm/htu cannot be bound to a
// real method/URL; the proof is best-effort and only used when the validator
// supports it (mirroring the HTTP path's optional DPoP behavior).
func dpopProofFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get(DPoPMetadataKey)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
