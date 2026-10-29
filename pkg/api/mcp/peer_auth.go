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

// PeerMethodAdmitter is implemented by a PeerAuthenticator that lets a
// certificate call a fixed set of RPCs its granted scopes do not cover: the
// installer certificate completing its own install. Methods are gRPC full
// method names, so every transport asks the same list.
type PeerMethodAdmitter interface {
	AdmitsMethod(method string) bool
}

// PeerInstallerAuthenticator is implemented by a PeerAuthenticator whose
// AuthenticatePeer refuses the installer certificate, which carries no
// tenant. It is asked only for a tool PeerMethodAdmitter admits, and only
// after AuthenticatePeer refused the chain.
type PeerInstallerAuthenticator interface {
	AuthenticateInstallerPeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error)
}

// peerAdmitsTool reports whether the peer authenticator admits the gRPC
// method toolName serves to a certificate whose scopes do not cover it.
func (c *AuthorizationChecker) peerAdmitsTool(toolName string) bool {
	admitter, ok := c.peerAuthenticator.(PeerMethodAdmitter)
	if !ok {
		return false
	}
	tool, ok := pxeTools[toolName]
	return ok && admitter.AdmitsMethod(tool.method)
}

// authorizePeer authenticates a tokenless request by its connection's
// verified client certificate, then enforces the tool's scope against the
// principal the certificate authenticates, unless the authenticator admits
// the tool's method outside those scopes. Only VerifiedChains is read:
// PeerCertificates is whatever the client sent.
func (c *AuthorizationChecker) authorizePeer(ctx context.Context, toolName, permission string) (context.Context, *AuthorizationError) {
	state, _, _ := channelbind.ConnectionTLS(ctx)
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ctx, &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation: no bearer token and no verified client certificate",
		}
	}
	authCtx, err := c.peerAuthenticator.AuthenticatePeer(ctx, state.VerifiedChains[0])
	if installer, ok := c.peerAuthenticator.(PeerInstallerAuthenticator); ok && err != nil && c.peerAdmitsTool(toolName) {
		authCtx, err = installer.AuthenticateInstallerPeer(ctx, state.VerifiedChains[0])
	}
	if err != nil || authCtx == nil {
		return ctx, &AuthorizationError{
			Type:    AuthErrorInvalidToken,
			Message: "Invalid client certificate",
		}
	}
	if err := authCtx.RequireScope(scopeForToolPermission(permission)); err != nil && !c.peerAdmitsTool(toolName) {
		return ctx, &AuthorizationError{
			Type:    AuthErrorPermissionDenied,
			Message: "Permission denied: insufficient privileges",
		}
	}
	return ContextWithAuthorizedContext(ctx, authCtx), nil
}
