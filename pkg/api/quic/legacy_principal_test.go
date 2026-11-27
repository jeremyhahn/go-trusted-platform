package quic

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// principalQUICTokenValidator is a legacy (bool-only) validator that also
// names the token's principal, as the daemon's local-JWT validator does.
type principalQUICTokenValidator struct {
	principal *platformtoken.AuthorizedContext
	err       error
}

func (v *principalQUICTokenValidator) ValidateToken(context.Context, string) (bool, error) {
	return true, nil
}

func (v *principalQUICTokenValidator) TokenPrincipal(context.Context, string) (*platformtoken.AuthorizedContext, error) {
	return v.principal, v.err
}

// plainQUICTokenValidator validates tokens but names no principal.
type plainQUICTokenValidator struct{}

func (plainQUICTokenValidator) ValidateToken(context.Context, string) (bool, error) {
	return true, nil
}

func TestAuthenticateRequest_LegacyPrincipalBound(t *testing.T) {
	m := NewAuthMiddleware(WithQUICTokenValidator(&principalQUICTokenValidator{
		principal: &platformtoken.AuthorizedContext{TenantID: "tenant-a"},
	}))

	ctx, resp := m.AuthenticateRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpHealth, Token: "local-jwt"})
	if resp != nil {
		t.Fatalf("a valid local JWT must authenticate, got %+v", resp)
	}
	p, ok := LegacyPrincipalFromContext(ctx)
	if !ok || p.TenantID != "tenant-a" {
		t.Fatalf("legacy principal = %+v, %v; want tenant-a", p, ok)
	}
	if _, ok := AuthorizedContextFromContext(ctx); ok {
		t.Fatal("a legacy principal must not be stored as a platform-token AuthorizedContext")
	}
	if tok, _ := TokenFromContext(ctx); tok != "local-jwt" {
		t.Fatalf("token = %q, want local-jwt", tok)
	}
}

func TestAuthenticateRequest_LegacyWithoutPrincipalStaysUnbound(t *testing.T) {
	m := NewAuthMiddleware(WithQUICTokenValidator(plainQUICTokenValidator{}))

	ctx, resp := m.AuthenticateRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpHealth, Token: "local-jwt"})
	if resp != nil {
		t.Fatalf("a valid token must authenticate, got %+v", resp)
	}
	if _, ok := LegacyPrincipalFromContext(ctx); ok {
		t.Fatal("a validator without TokenPrincipal must store no principal")
	}
}

func TestAuthenticateRequest_LegacyPrincipalErrorUnauthorized(t *testing.T) {
	m := NewAuthMiddleware(WithQUICTokenValidator(&principalQUICTokenValidator{err: errors.New("no subject")}))

	_, resp := m.AuthenticateRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpHealth, Token: "local-jwt"})
	if resp == nil || resp.Status != quicwire.StatusUnauthorized {
		t.Fatalf("a TokenPrincipal error must be Unauthorized, got %+v", resp)
	}
}

func TestLegacyPrincipalFromContext_NilIsUnbound(t *testing.T) {
	ctx := ContextWithLegacyPrincipal(context.Background(), nil)
	if _, ok := LegacyPrincipalFromContext(ctx); ok {
		t.Fatal("a nil legacy principal must read as unbound")
	}
}
