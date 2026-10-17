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
	"crypto/x509"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// PeerAuthenticator authenticates a caller by the client certificate chain
// its TLS connection presented (mTLS) and returns the principal the request
// acts as. chain is the TLS stack's first verified chain, leaf first. It is
// the contract the QUIC and REST transports use for the same purpose.
type PeerAuthenticator interface {
	AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error)
}

// AuthorizationCheckerOption configures an AuthorizationChecker.
type AuthorizationCheckerOption func(*AuthorizationChecker)

// WithPeerAuthenticator authenticates a request that carries no bearer token
// by the verified client certificate of its connection. A nil authenticator
// leaves the certificate path disabled.
func WithPeerAuthenticator(a PeerAuthenticator) AuthorizationCheckerOption {
	return func(c *AuthorizationChecker) {
		c.peerAuthenticator = a
	}
}

// tokenOnlyTools are the tools a client certificate alone never authorizes,
// whatever scopes its principal holds: each requires a platform token, as on
// every other transport. ca_sign_csr certifies a KMS key for code signing
// (docs/ca/api.md, "Sign CSR needs ca:sign-csr").
var tokenOnlyTools = map[string]struct{}{
	"ca_sign_csr": {},
}

// authorizePeer authenticates a tokenless request by its connection's
// verified client certificate, then enforces the tool's scope against the
// principal the certificate authenticates. Only VerifiedChains is read:
// PeerCertificates is whatever the client sent.
func (c *AuthorizationChecker) authorizePeer(ctx context.Context, toolName, permission string) (context.Context, *AuthorizationError) {
	// A token-only tool is refused before the certificate is even read: the
	// operator's certificate carries scopes a token would grant, so its
	// scope check alone would let it through.
	if _, tokenOnly := tokenOnlyTools[toolName]; tokenOnly {
		return ctx, &AuthorizationError{
			Type:    AuthErrorPermissionDenied,
			Message: "Permission denied: tool '" + toolName + "' requires a platform token; a client certificate alone does not authorize it",
		}
	}
	state, _, _ := channelbind.ConnectionTLS(ctx)
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ctx, &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation: no bearer token and no verified client certificate",
		}
	}
	authCtx, err := c.peerAuthenticator.AuthenticatePeer(ctx, state.VerifiedChains[0])
	if err != nil || authCtx == nil {
		return ctx, &AuthorizationError{
			Type:    AuthErrorInvalidToken,
			Message: "Invalid client certificate",
		}
	}
	if err := authCtx.RequireScope(scopeForToolPermission(permission)); err != nil {
		return ctx, &AuthorizationError{
			Type:    AuthErrorPermissionDenied,
			Message: "Permission denied: insufficient privileges",
		}
	}
	// The mark travels with the context into the services a tool calls, so
	// a token-only check there refuses this principal too.
	ctx = peercred.ContextWithCertificatePrincipal(ctx)
	return ContextWithAuthorizedContext(ctx, authCtx), nil
}
