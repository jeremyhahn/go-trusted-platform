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
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// claimsAuthManagerStub implements both AuthManager and ClaimsAuthManager so the
// AuthorizationChecker takes the platform-token claims path.
type claimsAuthManagerStub struct {
	authCtx  *platformtoken.AuthorizedContext
	err      error
	gotToken string
	calls    int
}

func (s *claimsAuthManagerStub) ValidateToken(ctx context.Context, token string) (bool, error) {
	return s.err == nil, s.err
}

func (s *claimsAuthManagerStub) GetTokenClaims(ctx context.Context, token string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (s *claimsAuthManagerStub) AuthorizeToken(ctx context.Context, token, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	s.calls++
	s.gotToken = token
	if s.err != nil {
		return nil, s.err
	}
	return s.authCtx, nil
}

func TestAuthorizeTool_ClaimsPath_AllowsGrantedScope(t *testing.T) {
	want := &platformtoken.AuthorizedContext{
		Subject:  "u",
		TenantID: "t",
		Scopes:   []string{"dns:write"},
	}
	mgr := &claimsAuthManagerStub{authCtx: want}
	checker := NewAuthorizationChecker(nil, mgr)

	ctx, authErr := checker.AuthorizeTool(context.Background(), "dns_add_record", "tok-1")
	if authErr != nil {
		t.Fatalf("AuthorizeTool denied a granted scope: %v", authErr)
	}
	if mgr.calls != 1 || mgr.gotToken != "tok-1" {
		t.Fatalf("validator not called as expected; calls=%d token=%q", mgr.calls, mgr.gotToken)
	}
	ac, ok := AuthorizedContextFromContext(ctx)
	if !ok || ac != want {
		t.Fatal("AuthorizedContext not stashed in returned context")
	}
}

func TestAuthorizeTool_ClaimsPath_DeniesMissingScope(t *testing.T) {
	mgr := &claimsAuthManagerStub{authCtx: &platformtoken.AuthorizedContext{Scopes: []string{"dns:read"}}}
	checker := NewAuthorizationChecker(nil, mgr)

	_, authErr := checker.AuthorizeTool(context.Background(), "dns_add_record", "tok")
	if authErr == nil {
		t.Fatal("expected permission denied for ungranted scope")
	}
	if authErr.Type != AuthErrorPermissionDenied {
		t.Errorf("error type = %v, want AuthErrorPermissionDenied", authErr.Type)
	}
}

func TestAuthorizeTool_ClaimsPath_InvalidTokenRejected(t *testing.T) {
	mgr := &claimsAuthManagerStub{err: &platformtoken.InvalidTokenError{Detail: "bad"}}
	checker := NewAuthorizationChecker(nil, mgr)

	_, authErr := checker.AuthorizeTool(context.Background(), "dns_add_record", "bad")
	if authErr == nil {
		t.Fatal("expected invalid-token error")
	}
	if authErr.Type != AuthErrorInvalidToken {
		t.Errorf("error type = %v, want AuthErrorInvalidToken", authErr.Type)
	}
}

func TestAuthorizeTool_ClaimsPath_MissingTokenForProtectedTool(t *testing.T) {
	mgr := &claimsAuthManagerStub{authCtx: &platformtoken.AuthorizedContext{}}
	checker := NewAuthorizationChecker(nil, mgr)

	_, authErr := checker.AuthorizeTool(context.Background(), "dns_add_record", "")
	if authErr == nil || authErr.Type != AuthErrorMissingToken {
		t.Fatalf("expected missing-token error, got %+v", authErr)
	}
	if mgr.calls != 0 {
		t.Error("validator must not be called when token is empty")
	}
}

func TestAuthorizeTool_ClaimsPath_NoAuthTool(t *testing.T) {
	// A tool that requires no permission must pass without calling the validator.
	mgr := &claimsAuthManagerStub{authCtx: &platformtoken.AuthorizedContext{}}
	checker := NewAuthorizationChecker(nil, mgr)

	_, authErr := checker.AuthorizeTool(context.Background(), "platform_health", "")
	if authErr != nil {
		t.Fatalf("health tool should require no auth: %v", authErr)
	}
}

func TestAuthorizeTool_LegacyFallback(t *testing.T) {
	// A bool-only AuthManager + AuthorizationService keeps the legacy path: the
	// returned context carries no AuthorizedContext.
	mgr := &mockAuthManager{validateFunc: func(ctx context.Context, token string) (bool, error) {
		return true, nil
	}}
	svc := &mockAuthorizationService{checkFunc: func(ctx context.Context, subject, resource, action string) (bool, error) {
		return true, nil
	}}
	checker := NewAuthorizationChecker(svc, mgr)

	ctx, authErr := checker.AuthorizeTool(context.Background(), "dns_add_record", "tok")
	if authErr != nil {
		t.Fatalf("legacy authorize denied: %v", authErr)
	}
	if !mgr.validateCalled || !svc.checkCalled {
		t.Error("legacy path must call ValidateToken and CheckPermission")
	}
	if svc.lastResource != "dns" || svc.lastAction != "write" {
		t.Errorf("legacy checker got %s/%s, want dns/write", svc.lastResource, svc.lastAction)
	}
	if _, ok := AuthorizedContextFromContext(ctx); ok {
		t.Error("legacy path must not stash AuthorizedContext")
	}
}

func TestCheckToolAuthorization_DelegatesToAuthorizeTool(t *testing.T) {
	mgr := &claimsAuthManagerStub{authCtx: &platformtoken.AuthorizedContext{Scopes: []string{"dns:write"}}}
	checker := NewAuthorizationChecker(nil, mgr)

	if authErr := checker.CheckToolAuthorization(context.Background(), "dns_add_record", "tok"); authErr != nil {
		t.Fatalf("CheckToolAuthorization denied a granted scope: %v", authErr)
	}
}

func TestScopeForToolPermission(t *testing.T) {
	cases := map[string]string{
		"dns:write": "dns:write",
		"vtpm:read": "vtpm:read",
		"":          "",
		"bad":       "",
		"a:":        "",
		":b":        "",
	}
	for in, want := range cases {
		if got := scopeForToolPermission(in); got != want {
			t.Errorf("scopeForToolPermission(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMCPContextWithAuthorizedContext_Roundtrip(t *testing.T) {
	ac := &platformtoken.AuthorizedContext{Subject: "x"}
	ctx := ContextWithAuthorizedContext(context.Background(), ac)
	got, ok := AuthorizedContextFromContext(ctx)
	if !ok || got != ac {
		t.Fatal("roundtrip failed")
	}
	if _, ok := AuthorizedContextFromContext(context.Background()); ok {
		t.Error("empty context should not yield an AuthorizedContext")
	}
}
