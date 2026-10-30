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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

// PeerMethodAdmitter is implemented by a PeerAuthenticator that lets a
// certificate call a fixed set of RPCs its granted scopes do not cover: the
// installer certificate completing its own install. Methods are gRPC full
// method names, so every transport asks the same list.
type PeerMethodAdmitter interface {
	AdmitsMethod(method string) bool
}

// PeerInstallerAuthenticator is implemented by a PeerAuthenticator whose
// AuthenticatePeer refuses the installer certificate, which carries no
// tenant. It is asked only for an operation PeerMethodAdmitter admits, and
// only after AuthenticatePeer refused the chain.
type PeerInstallerAuthenticator interface {
	AuthenticateInstallerPeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error)
}

// operationMethods names the gRPC method a QUIC operation serves, for the
// operations a PeerMethodAdmitter may admit, keyed by opcode then sub-opcode.
var operationMethods = map[byte]map[byte]string{
	quicwire.OpProvisioningCategory: {
		quicwire.PXESubWebhookComplete: platformv1.PXEService_WebhookComplete_FullMethodName,
	},
}

// authenticatesByPeer reports whether req is authenticated by the
// connection's verified client certificate: it carries no token, or no
// token validator is configured.
func (m *AuthMiddleware) authenticatesByPeer(req *quicwire.Request) bool {
	return m.peerAuthenticator != nil && (req.Token == "" || m.tokenValidator == nil)
}

// peerAdmitsOperation reports whether the peer authenticator admits req's
// operation to a certificate whose scopes do not cover it.
func (m *AuthMiddleware) peerAdmitsOperation(req *quicwire.Request) bool {
	admitter, ok := m.peerAuthenticator.(PeerMethodAdmitter)
	if !ok || len(req.Payload) == 0 {
		return false
	}
	method, ok := operationMethods[req.Opcode][req.Payload[0]]
	return ok && admitter.AdmitsMethod(method)
}

// authenticatePeer authenticates the request by the connection's verified
// client certificate and stores the resulting AuthorizedContext in ctx. Only
// VerifiedChains is read: PeerCertificates is whatever the client sent.
func (m *AuthMiddleware) authenticatePeer(ctx context.Context, req *quicwire.Request) (context.Context, *quicwire.Response) {
	state := ConnectionTLS(ctx)
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte(ErrMissingClientCertificate{}.Error()),
		}
	}
	authCtx, err := m.peerAuthenticator.AuthenticatePeer(ctx, state.VerifiedChains[0])
	if installer, ok := m.peerAuthenticator.(PeerInstallerAuthenticator); ok && err != nil && m.peerAdmitsOperation(req) {
		authCtx, err = installer.AuthenticateInstallerPeer(ctx, state.VerifiedChains[0])
	}
	if err != nil {
		return ctx, &quicwire.Response{
			Status:  quicwire.StatusUnauthorized,
			Payload: []byte(ErrPeerAuthenticationFailed{Cause: err}.Error()),
		}
	}
	return ContextWithAuthorizedContext(ctx, authCtx), nil
}
