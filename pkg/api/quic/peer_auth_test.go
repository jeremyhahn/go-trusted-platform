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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// peerAuthenticatorStub is a PeerAuthenticator test double.
type peerAuthenticatorStub struct {
	authCtx  *platformtoken.AuthorizedContext
	err      error
	gotChain []*x509.Certificate
	calls    int
}

func (s *peerAuthenticatorStub) AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	s.calls++
	s.gotChain = chain
	if s.err != nil {
		return nil, s.err
	}
	return s.authCtx, nil
}

func peerContext(state *tls.ConnectionState) context.Context {
	return WithConnectionTLS(context.Background(), state)
}

func TestAuthenticateRequest_PeerAuthenticator_AttachesPrincipal(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	want := &platformtoken.AuthorizedContext{Subject: "admin", Scopes: []string{"*:*"}}
	stub := &peerAuthenticatorStub{authCtx: want}
	mw := NewAuthMiddleware(WithQUICPeerAuthenticator(stub), WithQUICRequireAuth(true))

	ctx, resp := mw.AuthenticateRequest(peerContext(&tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}), &quicwire.Request{Opcode: quicwire.OpPIVCategory})
	if resp != nil {
		t.Fatalf("authenticate failed: status=%d payload=%s", resp.Status, resp.Payload)
	}
	if stub.calls != 1 || len(stub.gotChain) != 1 || stub.gotChain[0] != leaf {
		t.Fatalf("authenticator not given the verified chain; calls=%d chain=%v", stub.calls, stub.gotChain)
	}
	got, ok := AuthorizedContextFromContext(ctx)
	if !ok || got != want {
		t.Fatal("AuthorizedContext not stashed in context")
	}
	if resp := AuthorizeSubOpcode(ctx, PIVSubOpcodePermissions, quicwire.PIVSubGenerate); resp != nil {
		t.Errorf("authenticated operator refused: status=%d payload=%s", resp.Status, resp.Payload)
	}
}

// Only the chain the TLS stack verified is a credential: certificates the
// client merely presented, or no TLS state at all, authenticate nobody.
func TestAuthenticateRequest_PeerAuthenticator_NoVerifiedChainIsUnauthorized(t *testing.T) {
	presented := &x509.Certificate{Raw: []byte("unverified")}
	cases := map[string]context.Context{
		"no connection state":  context.Background(),
		"nil connection state": peerContext(nil),
		"unverified peer cert": peerContext(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{presented}}),
		"empty verified chain": peerContext(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			stub := &peerAuthenticatorStub{authCtx: &platformtoken.AuthorizedContext{Scopes: []string{"*:*"}}}
			mw := NewAuthMiddleware(WithQUICPeerAuthenticator(stub), WithQUICRequireAuth(true))

			out, resp := mw.AuthenticateRequest(ctx, &quicwire.Request{Opcode: quicwire.OpPIVCategory})
			if resp == nil || resp.Status != quicwire.StatusUnauthorized {
				t.Fatalf("resp = %+v, want Unauthorized", resp)
			}
			if string(resp.Payload) != (ErrMissingClientCertificate{}).Error() {
				t.Errorf("payload = %q", resp.Payload)
			}
			if stub.calls != 0 {
				t.Error("the authenticator ran without a verified chain")
			}
			if _, ok := AuthorizedContextFromContext(out); ok {
				t.Error("a principal was attached without a verified chain")
			}
		})
	}
}

func TestAuthenticateRequest_PeerAuthenticator_RejectionIsUnauthorized(t *testing.T) {
	stub := &peerAuthenticatorStub{err: errors.New("revoked")}
	mw := NewAuthMiddleware(WithQUICPeerAuthenticator(stub), WithQUICRequireAuth(true))

	ctx, resp := mw.AuthenticateRequest(peerContext(&tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{{Raw: []byte("leaf")}}},
	}), &quicwire.Request{Opcode: quicwire.OpPIVCategory})
	if resp == nil || resp.Status != quicwire.StatusUnauthorized {
		t.Fatalf("resp = %+v, want Unauthorized", resp)
	}
	if !strings.Contains(string(resp.Payload), "client certificate authentication failed: revoked") {
		t.Errorf("payload = %q", resp.Payload)
	}
	if _, ok := AuthorizedContextFromContext(ctx); ok {
		t.Error("a principal was attached for a rejected certificate")
	}
}

func TestErrPeerAuthenticationFailed_UnwrapsCause(t *testing.T) {
	cause := errors.New("expired")
	err := error(ErrPeerAuthenticationFailed{Cause: cause})
	if !errors.Is(err, cause) {
		t.Error("cause not reachable through errors.Is")
	}
	if got := (ErrPeerAuthenticationFailed{}).Error(); got != "client certificate authentication failed" {
		t.Errorf("Error() without cause = %q", got)
	}
}
