package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// peerAuthenticatorStub authenticates every chain as the configured
// principal and counts the calls, so a test can prove a certificate was
// never read.
type peerAuthenticatorStub struct {
	authCtx *platformtoken.AuthorizedContext
	err     error
	calls   int
}

func (s *peerAuthenticatorStub) AuthenticatePeer(ctx context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.authCtx, nil
}

// errPeerRejected is the failure the stub authenticator returns for an
// unknown certificate.
type errPeerRejected struct{}

func (errPeerRejected) Error() string { return "certificate maps to no principal" }

// operatorScopes is what an operator certificate's principal holds.
var operatorScopes = []string{"*:*"}

// mtlsContext carries a connection whose client certificate the TLS layer
// verified, as the MCP HTTP transport attaches it.
func mtlsContext() context.Context {
	state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
	return channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, state)
}

func newPeerChecker(mgr AuthManager, peers *peerAuthenticatorStub) *AuthorizationChecker {
	return NewAuthorizationChecker(nil, mgr, WithPeerAuthenticator(peers))
}

// docs/ca/api.md: a client certificate alone never authorizes sign-csr, on
// any transport, whatever scopes its principal holds.
func TestAuthorizeTool_CertificateAloneNeverSignsCSR(t *testing.T) {
	peers := &peerAuthenticatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "operator", Scopes: operatorScopes}}
	checker := newPeerChecker(nil, peers)

	ctx, authErr := checker.AuthorizeTool(mtlsContext(), "ca_sign_csr", "")
	require.NotNil(t, authErr, "an operator certificate alone must not authorize ca_sign_csr")
	assert.Equal(t, AuthErrorPermissionDenied, authErr.Type)
	assert.Contains(t, authErr.Message, "requires a platform token")
	assert.Zero(t, peers.calls, "the certificate must not be read for a token-only tool")
	_, attached := AuthorizedContextFromContext(ctx)
	assert.False(t, attached, "a refused request carries no principal")
}

func TestAuthorizeTool_TokenWithSignCSRScopeSignsUnderMTLS(t *testing.T) {
	peers := &peerAuthenticatorStub{authCtx: &platformtoken.AuthorizedContext{Subject: "operator", Scopes: operatorScopes}}
	token := &platformtoken.AuthorizedContext{Subject: "signer", Scopes: []string{"ca:sign-csr"}}
	mgr := &claimsAuthManagerStub{authCtx: token}
	checker := newPeerChecker(mgr, peers)

	ctx, authErr := checker.AuthorizeTool(mtlsContext(), "ca_sign_csr", "tok")
	require.Nil(t, authErr, "a platform token with ca:sign-csr must authorize ca_sign_csr")
	assert.Equal(t, 1, mgr.calls)
	assert.Zero(t, peers.calls, "a presented token is validated by the token backend, not the certificate")
	got, ok := AuthorizedContextFromContext(ctx)
	require.True(t, ok)
	assert.Same(t, token, got)
	assert.False(t, peercred.IsCertificatePrincipal(ctx), "a token principal is not marked certificate-only")
}

func TestAuthorizeTool_CertificateAloneAuthorizesOtherTools(t *testing.T) {
	operator := &platformtoken.AuthorizedContext{Subject: "operator", Scopes: operatorScopes}
	peers := &peerAuthenticatorStub{authCtx: operator}
	checker := newPeerChecker(nil, peers)

	ctx, authErr := checker.AuthorizeTool(mtlsContext(), "ca_info", "")
	require.Nil(t, authErr, "an operator certificate must still authorize a tool its scopes grant")
	assert.Equal(t, 1, peers.calls)
	got, ok := AuthorizedContextFromContext(ctx)
	require.True(t, ok)
	assert.Same(t, operator, got)
	assert.True(t, peercred.IsCertificatePrincipal(ctx),
		"the request is tagged so a token-only check in the service the tool calls refuses it")
}

func TestAuthorizeTool_CertificateAloneRefusals(t *testing.T) {
	cases := []struct {
		name     string
		ctx      context.Context
		peers    *peerAuthenticatorStub
		wantType AuthErrorType
	}{
		{
			name:     "no verified chain",
			ctx:      context.Background(),
			peers:    &peerAuthenticatorStub{authCtx: &platformtoken.AuthorizedContext{Scopes: operatorScopes}},
			wantType: AuthErrorMissingToken,
		},
		{
			name:     "certificate maps to no principal",
			ctx:      mtlsContext(),
			peers:    &peerAuthenticatorStub{err: errPeerRejected{}},
			wantType: AuthErrorInvalidToken,
		},
		{
			name:     "principal lacks the scope",
			ctx:      mtlsContext(),
			peers:    &peerAuthenticatorStub{authCtx: &platformtoken.AuthorizedContext{Scopes: []string{"dns:read"}}},
			wantType: AuthErrorPermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checker := newPeerChecker(nil, tc.peers)

			ctx, authErr := checker.AuthorizeTool(tc.ctx, "ca_info", "")
			require.NotNil(t, authErr)
			assert.Equal(t, tc.wantType, authErr.Type)
			assert.False(t, peercred.IsCertificatePrincipal(ctx), "a refused request is not tagged")
		})
	}
}
