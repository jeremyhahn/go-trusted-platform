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
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// claimsValidatorStub is a ClaimsTokenValidator test double for the QUIC path.
type claimsValidatorStub struct {
	authCtx      *platformtoken.AuthorizedContext
	err          error
	gotToken     string
	gotPerm      string
	gotDPoPProof string
	calls        int
}

func (s *claimsValidatorStub) ValidateToken(ctx context.Context, token string) (bool, error) {
	return s.err == nil, s.err
}

func (s *claimsValidatorStub) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	s.calls++
	s.gotToken = token
	s.gotPerm = requiredPerm
	s.gotDPoPProof = dpopProof
	if s.err != nil {
		return nil, s.err
	}
	if requiredPerm != "" {
		if err := s.authCtx.RequireScope(requiredPerm); err != nil {
			return nil, err
		}
	}
	return s.authCtx, nil
}

func TestQUICAuthenticateRequest_ClaimsPath_StashesAuthorizedContext(t *testing.T) {
	want := &platformtoken.AuthorizedContext{Subject: "u", TenantID: "t", Scopes: []string{"dns:write"}}
	stub := &claimsValidatorStub{authCtx: want}
	mw := NewAuthMiddleware(WithQUICTokenValidator(stub), WithQUICRequireAuth(true))

	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: "tok-1"}
	ctx, resp := mw.AuthenticateRequest(context.Background(), req)
	if resp != nil {
		t.Fatalf("authenticate failed: status=%d payload=%s", resp.Status, resp.Payload)
	}
	if stub.calls != 1 || stub.gotToken != "tok-1" {
		t.Fatalf("validator not called with framed token; calls=%d token=%q", stub.calls, stub.gotToken)
	}
	// QUIC carries no DPoP frame: proof must be empty (bearer validation).
	if stub.gotDPoPProof != "" {
		t.Errorf("dpop proof = %q, want empty (QUIC bearer)", stub.gotDPoPProof)
	}
	// Authentication routes through the scope-free Validate path: the opcode's
	// required scope is enforced later in AuthorizeRequest, so requiredPerm is
	// empty here while online liveness still runs on every request.
	if stub.gotPerm != "" {
		t.Errorf("requiredPerm at authenticate = %q, want empty (scope deferred to AuthorizeRequest)", stub.gotPerm)
	}
	ac, ok := AuthorizedContextFromContext(ctx)
	if !ok || ac != want {
		t.Fatal("AuthorizedContext not stashed in context")
	}
}

func TestQUICAuthorizeRequest_ClaimsPath_EnforcesScope(t *testing.T) {
	mw := NewAuthMiddleware(WithQUICTokenValidator(
		&claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Scopes: []string{"dns:write"}}}),
		WithQUICRequireAuth(true))

	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: "tok"}
	ctx, resp := mw.AuthenticateRequest(context.Background(), req)
	if resp != nil {
		t.Fatalf("authenticate failed: %s", resp.Payload)
	}

	// Granted scope -> allowed.
	if resp := mw.AuthorizeRequest(ctx, "dns", "write"); resp != nil {
		t.Fatalf("authorize denied a granted scope: status=%d", resp.Status)
	}
	// Missing scope -> permission denied.
	resp = mw.AuthorizeRequest(ctx, "dns", "delete")
	if resp == nil {
		t.Fatal("expected permission denied for ungranted scope")
	}
	if resp.Status != quicwire.StatusPermissionDenied {
		t.Errorf("status = %d, want StatusPermissionDenied", resp.Status)
	}
}

func TestQUICAuthenticateRequest_ClaimsPath_InvalidTokenRejected(t *testing.T) {
	stub := &claimsValidatorStub{err: &platformtoken.ExpiredTokenError{}}
	mw := NewAuthMiddleware(WithQUICTokenValidator(stub), WithQUICRequireAuth(true))

	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: "expired"}
	_, resp := mw.AuthenticateRequest(context.Background(), req)
	if resp == nil {
		t.Fatal("expected an error response for invalid token")
	}
	if resp.Status != quicwire.StatusUnauthorized {
		t.Errorf("status = %d, want StatusUnauthorized", resp.Status)
	}
}

func TestQUICAuthenticateRequest_MissingToken(t *testing.T) {
	stub := &claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{}}
	mw := NewAuthMiddleware(WithQUICTokenValidator(stub), WithQUICRequireAuth(true))

	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: ""}
	_, resp := mw.AuthenticateRequest(context.Background(), req)
	if resp == nil || resp.Status != quicwire.StatusUnauthorized {
		t.Fatalf("expected unauthorized for missing token, got %+v", resp)
	}
	if stub.calls != 0 {
		t.Error("validator must not be called when token is empty")
	}
}

// legacyValidator is a bool-only TokenValidator (no claims interface).
type legacyValidator struct{ valid bool }

func (l *legacyValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return l.valid, nil
}

// legacyChecker is a bool-only AuthorizationChecker for the legacy path.
type legacyChecker struct {
	allowed   bool
	gotResrc  string
	gotAction string
}

func (c *legacyChecker) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error) {
	c.gotResrc = resource
	c.gotAction = action
	return c.allowed, nil
}

func TestQUICAuthorize_LegacyFallback(t *testing.T) {
	// No claims interface -> AuthenticateRequest stashes only the token and
	// AuthorizeRequest delegates to the AuthorizationChecker.
	checker := &legacyChecker{allowed: true}
	mw := NewAuthMiddleware(
		WithQUICTokenValidator(&legacyValidator{valid: true}),
		WithQUICAuthorizationChecker(checker),
		WithQUICRequireAuth(true),
	)

	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: "tok"}
	ctx, resp := mw.AuthenticateRequest(context.Background(), req)
	if resp != nil {
		t.Fatalf("legacy authenticate failed: %s", resp.Payload)
	}
	if _, ok := AuthorizedContextFromContext(ctx); ok {
		t.Error("legacy path must not stash AuthorizedContext")
	}
	if resp := mw.AuthorizeRequest(ctx, "dns", "write"); resp != nil {
		t.Fatalf("legacy authorize denied: status=%d", resp.Status)
	}
	if checker.gotResrc != "dns" || checker.gotAction != "write" {
		t.Errorf("checker got %s/%s, want dns/write", checker.gotResrc, checker.gotAction)
	}
}

func TestScopeForOperation(t *testing.T) {
	if got := scopeForOperation("dns", "write"); got != "dns:write" {
		t.Errorf("got %q, want dns:write", got)
	}
	if got := scopeForOperation("", "write"); got != "" {
		t.Errorf("empty resource should yield empty scope, got %q", got)
	}
	if got := scopeForOperation("dns", ""); got != "" {
		t.Errorf("empty action should yield empty scope, got %q", got)
	}
}

func TestQUICGuardRequest_HealthNeedsNoToken(t *testing.T) {
	stub := &claimsValidatorStub{}
	mw := NewAuthMiddleware(WithQUICTokenValidator(stub), WithQUICRequireAuth(true))

	if _, resp := mw.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpHealth}); resp != nil {
		t.Fatalf("health opcode must not require a token, got status=%d", resp.Status)
	}
	if stub.calls != 0 {
		t.Fatal("a pre-auth operation must not reach the token validator")
	}
}

func TestQUICGuardRequest_ClaimsPath_EnforcesCatalogScope(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"exact scope", []string{"proxy:delete"}, true},
		{"resource wildcard", []string{"proxy:*"}, true},
		{"other action", []string{"proxy:read"}, false},
		{"other resource", []string{"sdn:delete"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := NewAuthMiddleware(WithQUICTokenValidator(
				&claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{Scopes: tc.scopes}}))
			req := &quicwire.Request{Opcode: quicwire.OpGatewayCategory, Token: "tok", Payload: []byte{quicwire.ProxySubRouteDelete}}

			_, resp := mw.GuardRequest(context.Background(), req)

			if tc.want && resp != nil {
				t.Fatalf("scopes %v refused: status=%d payload=%s", tc.scopes, resp.Status, resp.Payload)
			}
			if !tc.want && (resp == nil || resp.Status != quicwire.StatusPermissionDenied) {
				t.Fatalf("scopes %v: expected PermissionDenied, got %+v", tc.scopes, resp)
			}
		})
	}
}

func TestQUICAuthenticateRequest_NoValidator(t *testing.T) {
	// requireAuth=true with no validator -> Unavailable.
	mw := NewAuthMiddleware(WithQUICRequireAuth(true))
	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: "tok"}
	_, resp := mw.AuthenticateRequest(context.Background(), req)
	if resp == nil || resp.Status != quicwire.StatusUnavailable {
		t.Fatalf("expected Unavailable, got %+v", resp)
	}

	// requireAuth=false with no validator -> allowed.
	mw2 := NewAuthMiddleware(WithQUICRequireAuth(false))
	if _, resp := mw2.AuthenticateRequest(context.Background(), req); resp != nil {
		t.Fatalf("requireAuth=false should allow, got status=%d", resp.Status)
	}
}

func TestQUICAuthorizeRequest_NoChecker_LegacyAllows(t *testing.T) {
	// Legacy path with no AuthorizationChecker and no AuthorizedContext: allow.
	mw := NewAuthMiddleware(WithQUICTokenValidator(&legacyValidator{valid: true}), WithQUICRequireAuth(true))
	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: "tok"}
	ctx, resp := mw.AuthenticateRequest(context.Background(), req)
	if resp != nil {
		t.Fatalf("authenticate failed: %s", resp.Payload)
	}
	if resp := mw.AuthorizeRequest(ctx, "dns", "write"); resp != nil {
		t.Fatalf("no checker should allow, got status=%d", resp.Status)
	}
}

func TestQUICAuthorizeRequest_ClaimsPath_EmptyScopeAllows(t *testing.T) {
	mw := NewAuthMiddleware(WithQUICTokenValidator(
		&claimsValidatorStub{authCtx: &platformtoken.AuthorizedContext{}}), WithQUICRequireAuth(true))
	req := &quicwire.Request{Opcode: quicwire.OpDNSAddRecord, Token: "tok"}
	ctx, _ := mw.AuthenticateRequest(context.Background(), req)
	// Empty resource/action -> no scope required -> allowed.
	if resp := mw.AuthorizeRequest(ctx, "", ""); resp != nil {
		t.Fatalf("empty resource/action should allow, got status=%d", resp.Status)
	}
}
