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

// PeerAuthorizationChecker decides whether the principal a verified client
// certificate authenticated holds a tool permission. The daemon wires the
// IAM PEP; the certificate principal carries no scopes to decide by. It is
// the contract the REST scope guard uses for the same purpose.
type PeerAuthorizationChecker interface {
	CheckPeerPermission(ctx context.Context, authCtx *platformtoken.AuthorizedContext, resource, action string) (bool, error)
}

// WithPeerAuthorizationChecker decides a certificate caller's tool
// permission. Without one (nil), every certificate caller is refused a tool
// that needs a permission.
func WithPeerAuthorizationChecker(checker PeerAuthorizationChecker) AuthorizationCheckerOption {
	return func(c *AuthorizationChecker) {
		c.peerChecker = checker
	}
}

// authorizePeer authenticates a tokenless request by its connection's
// verified client certificate, then enforces the tool's scope against the
// principal the certificate authenticates. Only VerifiedChains is read:
// PeerCertificates is whatever the client sent.
