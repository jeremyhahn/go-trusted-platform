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
	"crypto/x509"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// ErrMissingClientCertificate is returned when a peer-authenticated request
// arrives on a connection that presented no verified client certificate.
type ErrMissingClientCertificate struct{}

func (e ErrMissingClientCertificate) Error() string {
	return "missing verified client certificate"
}

// ErrPeerAuthenticationFailed is returned when the client certificate does
// not authenticate a principal.
type ErrPeerAuthenticationFailed struct {
	Cause error
}

func (e ErrPeerAuthenticationFailed) Error() string {
	if e.Cause != nil {
		return "client certificate authentication failed: " + e.Cause.Error()
	}
	return "client certificate authentication failed"
}

func (e ErrPeerAuthenticationFailed) Unwrap() error {
	return e.Cause
}

// PeerAuthenticator authenticates a caller by the client certificate chain
// its connection presented (mTLS) and returns the principal the request acts
// as. chain is the TLS stack's first verified chain, leaf first.
type PeerAuthenticator interface {
	AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error)
}

// WithQUICPeerAuthenticator authenticates requests by the connection's
// verified client certificate instead of a framed bearer token.
func WithQUICPeerAuthenticator(a PeerAuthenticator) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.peerAuthenticator = a
	}
}

// authenticatePeer authenticates the request by the connection's verified
// client certificate and stores the resulting AuthorizedContext in ctx. Only
// VerifiedChains is read: PeerCertificates is whatever the client sent.
func (m *AuthMiddleware) authenticatePeer(ctx context.Context) (context.Context, *quicwire.Response) {
	state := ConnectionTLS(ctx)
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte(ErrMissingClientCertificate{}.Error()),
		}
	}
	authCtx, err := m.peerAuthenticator.AuthenticatePeer(ctx, state.VerifiedChains[0])
	if err != nil {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte(ErrPeerAuthenticationFailed{Cause: err}.Error()),
		}
	}
	// The principal holds operator scopes but no platform token; the mark
	// keeps it out of token-only operations such as SignCSR.
	ctx = peercred.ContextWithCertificatePrincipal(ctx)
	return ContextWithAuthorizedContext(ctx, authCtx), nil
}
