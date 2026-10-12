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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrAuthValidatorNotConfigured_Error(t *testing.T) {
	err := ErrAuthValidatorNotConfigured{}
	expected := "OIDC token validator not configured"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrMissingToken_Error(t *testing.T) {
	err := ErrMissingToken{}
	expected := "missing authentication token"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrTokenValidationFailed_Auth_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrTokenValidationFailed
		expected string
	}{
		{
			name:     "with cause",
			err:      ErrTokenValidationFailed{Cause: errors.New("token expired")},
			expected: "token validation failed: token expired",
		},
		{
			name:     "without cause",
			err:      ErrTokenValidationFailed{Cause: nil},
			expected: "token validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrTokenValidationFailed_Auth_Unwrap(t *testing.T) {
	cause := errors.New("token expired")
	err := ErrTokenValidationFailed{Cause: cause}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrPermissionDenied_Error(t *testing.T) {
	err := ErrPermissionDenied{Resource: "vtpm", Action: "write"}
	expected := "permission denied: write on vtpm"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

// =============================================================================
// Mock Implementations
// =============================================================================

type mockQUICTokenValidator struct {
	valid bool
	err   error
}

func (m *mockQUICTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return m.valid, m.err
}

type mockQUICAuthorizationChecker struct {
	allowed      bool
	err          error
	lastResource string
	lastAction   string
}

func (m *mockQUICAuthorizationChecker) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error) {
	m.lastResource = resource
	m.lastAction = action
	return m.allowed, m.err
}

// =============================================================================
// Token Context Tests
// =============================================================================

func TestContextWithToken_Auth(t *testing.T) {
	ctx := context.Background()
	token := "test-bearer-token"

	newCtx := ContextWithToken(ctx, token)

	retrieved, ok := TokenFromContext(newCtx)
	if !ok {
		t.Fatal("expected token to be found in context")
	}

	if retrieved != token {
		t.Errorf("TokenFromContext() = %q, want %q", retrieved, token)
	}
}

func TestTokenFromContext_Auth_NotFound(t *testing.T) {
	ctx := context.Background()

	_, ok := TokenFromContext(ctx)
	if ok {
		t.Error("expected token to not be found in empty context")
	}
}

// =============================================================================
// AuthMiddleware Option Tests
// =============================================================================

func TestAuthMiddlewareOptions(t *testing.T) {
	validator := &mockQUICTokenValidator{}
	checker := &mockQUICAuthorizationChecker{}

	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
		WithQUICAuthorizationChecker(checker),
		WithQUICRequireAuth(false),
		WithQUICPeerAuthenticated(),
	)

	if m.tokenValidator != validator {
		t.Error("WithQUICTokenValidator did not set token validator")
	}

	if m.authzChecker != checker {
		t.Error("WithQUICAuthorizationChecker did not set authorization checker")
	}

	if m.requireAuth {
		t.Error("WithQUICRequireAuth(false) did not set requireAuth to false")
	}

	if !m.peerAuthenticated {
		t.Error("WithQUICPeerAuthenticated did not mark the peer authenticated")
	}
}

func TestNewAuthMiddleware_Defaults(t *testing.T) {
	m := NewAuthMiddleware()

	if !m.requireAuth {
		t.Error("default requireAuth should be true")
	}

	if m.peerAuthenticated {
		t.Error("the peer must not be treated as authenticated by default")
	}
}

// =============================================================================
// AuthenticateRequest Tests
// =============================================================================

func TestAuthMiddleware_AuthenticateRequest_HealthIsNotExempt(t *testing.T) {
	// Pre-auth exemptions live in the catalog and are applied by
	// GuardRequest; AuthenticateRequest itself exempts nothing.
	m := NewAuthMiddleware(WithQUICTokenValidator(&mockQUICTokenValidator{valid: true}))

	_, resp := m.AuthenticateRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpHealth})

	if resp == nil || resp.Status != quicwire.StatusUnauthorized {
		t.Fatalf("expected Unauthorized for a tokenless request, got %+v", resp)
	}
}

func TestAuthMiddleware_AuthenticateRequest_PeerAuthenticatedWithoutToken(t *testing.T) {
	m := NewAuthMiddleware(WithQUICPeerAuthenticated())

	ctx, resp := m.AuthenticateRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey})

	if resp != nil {
		t.Fatalf("expected a certificate-authenticated peer to pass, got %+v", resp)
	}
	if _, ok := TokenFromContext(ctx); ok {
		t.Fatal("no token was presented, none may be placed in the context")
	}
}

func TestAuthMiddleware_AuthenticateRequest_PeerAuthenticatedStillValidatesTokens(t *testing.T) {
	m := NewAuthMiddleware(
		WithQUICPeerAuthenticated(),
		WithQUICTokenValidator(&mockQUICTokenValidator{valid: false}),
	)

	_, resp := m.AuthenticateRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey, Token: "forged"})

	if resp == nil || resp.Status != quicwire.StatusUnauthorized {
		t.Fatalf("expected a presented invalid token to be refused, got %+v", resp)
	}
}

func TestAuthMiddleware_AuthenticateRequest_PeerAuthenticatedWithoutValidator(t *testing.T) {
	m := NewAuthMiddleware(WithQUICPeerAuthenticated())

	_, resp := m.AuthenticateRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey, Token: "opaque"})

	if resp != nil {
		t.Fatalf("expected the peer certificate to authenticate the request, got %+v", resp)
	}
}

func TestAuthMiddleware_AuthenticateRequest_NoValidator_RequireAuth(t *testing.T) {
	m := NewAuthMiddleware(
		WithQUICRequireAuth(true),
	)

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: "test-token"}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response when no validator configured and auth required")
	}

	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusUnavailable)
	}
}

func TestAuthMiddleware_AuthenticateRequest_NoValidator_AuthNotRequired(t *testing.T) {
	m := NewAuthMiddleware(
		WithQUICRequireAuth(false),
	)

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: "test-token"}
	ctx, resp := m.AuthenticateRequest(context.Background(), req)

	if resp != nil {
		t.Errorf("expected nil response when auth not required, got %+v", resp)
	}

	if ctx == nil {
		t.Error("expected non-nil context")
	}
}

func TestAuthMiddleware_AuthenticateRequest_MissingToken(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: true}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: ""}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for missing token")
	}

	if resp.Status != quicwire.StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthenticateRequest_ValidationFails(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: false, err: errors.New("token expired")}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: "expired-token"}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for validation failure")
	}

	if resp.Status != quicwire.StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthenticateRequest_InvalidToken(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: false, err: nil}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: "invalid-token"}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for invalid token")
	}

	if resp.Status != quicwire.StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthenticateRequest_ValidToken(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: true}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: "valid-token"}
	ctx, resp := m.AuthenticateRequest(context.Background(), req)

	if resp != nil {
		t.Errorf("expected nil response for valid token, got %+v", resp)
	}

	// Verify token was added to context
	token, ok := TokenFromContext(ctx)
	if !ok {
		t.Error("expected token in context after successful validation")
	}

	if token != "valid-token" {
		t.Errorf("token in context = %q, want %q", token, "valid-token")
	}
}

// =============================================================================
// AuthorizeRequest Tests
// =============================================================================

func TestAuthMiddleware_AuthorizeRequest_NoChecker(t *testing.T) {
	m := NewAuthMiddleware()

	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, "vtpm", "write")

	if resp != nil {
		t.Errorf("expected nil response when no checker configured, got %+v", resp)
	}
}

func TestAuthMiddleware_AuthorizeRequest_NoTokenInContext(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: true}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	resp := m.AuthorizeRequest(context.Background(), "vtpm", "write")

	if resp == nil {
		t.Fatal("expected error response when no token in context")
	}

	if resp.Status != quicwire.StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthorizeRequest_CheckFails(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: false, err: errors.New("database error")}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, "vtpm", "write")

	if resp == nil {
		t.Fatal("expected error response for check failure")
	}

	if resp.Status != quicwire.StatusInternalError {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusInternalError)
	}
}

func TestAuthMiddleware_AuthorizeRequest_NotAllowed(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: false, err: nil}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, "vtpm", "write")

	if resp == nil {
		t.Fatal("expected error response when not allowed")
	}

	if resp.Status != quicwire.StatusPermissionDenied {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusPermissionDenied)
	}
}

func TestAuthMiddleware_AuthorizeRequest_Allowed(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: true, err: nil}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, "vtpm", "write")

	if resp != nil {
		t.Errorf("expected nil response when allowed, got %+v", resp)
	}
}

// =============================================================================
// GuardRequest Tests
// =============================================================================

func TestAuthMiddleware_GuardRequest_PreAuthNeedsNoCredentials(t *testing.T) {
	m := NewAuthMiddleware(WithQUICTokenValidator(&mockQUICTokenValidator{valid: false}))

	for _, opcode := range []byte{quicwire.OpHealth, quicwire.OpLiveness, quicwire.OpReadiness, quicwire.OpIAMAuthenticate} {
		if _, resp := m.GuardRequest(context.Background(), &quicwire.Request{Opcode: opcode}); resp != nil {
			t.Errorf("pre-auth opcode 0x%02X refused: %+v", opcode, resp)
		}
	}
}

func TestAuthMiddleware_GuardRequest_ChecksTheCatalogPermission(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: true}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(&mockQUICTokenValidator{valid: true}),
		WithQUICAuthorizationChecker(checker),
	)

	req := &quicwire.Request{Opcode: quicwire.OpGatewayCategory, Token: "valid-token", Payload: []byte{quicwire.ProxySubRouteDelete}}
	ctx, resp := m.GuardRequest(context.Background(), req)

	if resp != nil {
		t.Fatalf("expected an allowed request to pass, got %+v", resp)
	}
	if checker.lastResource != "proxy" || checker.lastAction != "delete" {
		t.Fatalf("checked %s:%s, want proxy:delete", checker.lastResource, checker.lastAction)
	}
	if token, ok := TokenFromContext(ctx); !ok || token != "valid-token" {
		t.Fatal("the dispatch context must carry the validated token")
	}
}

func TestAuthMiddleware_GuardRequest_DeniedPermission(t *testing.T) {
	m := NewAuthMiddleware(
		WithQUICTokenValidator(&mockQUICTokenValidator{valid: true}),
		WithQUICAuthorizationChecker(&mockQUICAuthorizationChecker{allowed: false}),
	)

	_, resp := m.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpVTPMDelete, Token: "valid-token"})

	if resp == nil || resp.Status != quicwire.StatusPermissionDenied {
		t.Fatalf("expected PermissionDenied, got %+v", resp)
	}
}

func TestAuthMiddleware_GuardRequest_UnclassifiedIsDenied(t *testing.T) {
	// A certificate-authenticated peer is authorized for every classified
	// operation; an unclassified one is still refused.
	m := NewAuthMiddleware(WithQUICPeerAuthenticated())

	_, resp := m.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpGatewayCategory, Payload: []byte{0x7F}})

	if resp == nil || resp.Status != quicwire.StatusPermissionDenied {
		t.Fatalf("expected PermissionDenied, got %+v", resp)
	}
	want := ErrOperationNotClassified{Opcode: quicwire.OpGatewayCategory, Sub: 0x7F, HasSub: true}.Error()
	if string(resp.Payload) != want {
		t.Fatalf("payload = %q, want %q", resp.Payload, want)
	}
}

func TestAuthMiddleware_GuardRequest_AuthenticatesBeforeClassifying(t *testing.T) {
	m := NewAuthMiddleware(WithQUICTokenValidator(&mockQUICTokenValidator{valid: true}))

	_, resp := m.GuardRequest(context.Background(), &quicwire.Request{Opcode: 0x90})

	if resp == nil || resp.Status != quicwire.StatusUnauthorized {
		t.Fatalf("an anonymous caller must be refused as Unauthorized, got %+v", resp)
	}
}

func TestAuthMiddleware_GuardRequest_CategoryWithoutSubOpcode(t *testing.T) {
	m := NewAuthMiddleware(WithQUICPeerAuthenticated())

	_, resp := m.GuardRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpNTPCategory})

	if resp == nil || resp.Status != quicwire.StatusInvalidRequest {
		t.Fatalf("expected InvalidRequest, got %+v", resp)
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestAuthMiddleware_EmptyToken_IsNotSkipped(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: true}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	// Non-health opcode with empty token should fail
	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: ""}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for empty token on protected opcode")
	}

	if resp.Status != quicwire.StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusUnauthorized)
	}
}
