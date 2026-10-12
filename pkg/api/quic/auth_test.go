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
	allowed bool
	err     error
}

func (m *mockQUICAuthorizationChecker) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error) {
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
		WithQUICSkipOpcodes(0xF0, 0xF1),
		WithQUICRequireAuth(false),
	)

	if m.tokenValidator != validator {
		t.Error("WithQUICTokenValidator did not set token validator")
	}

	if m.authzChecker != checker {
		t.Error("WithQUICAuthorizationChecker did not set authorization checker")
	}

	if !m.skipOpcodes[0xF0] || !m.skipOpcodes[0xF1] {
		t.Error("WithQUICSkipOpcodes did not set skip opcodes")
	}

	if m.requireAuth {
		t.Error("WithQUICRequireAuth(false) did not set requireAuth to false")
	}
}

func TestNewAuthMiddleware_Defaults(t *testing.T) {
	m := NewAuthMiddleware()

	// Default should require auth
	if !m.requireAuth {
		t.Error("default requireAuth should be true")
	}

	// Default should skip health opcodes
	if !m.skipOpcodes[quicwire.OpHealth] {
		t.Error("OpHealth should be skipped by default")
	}

	if !m.skipOpcodes[quicwire.OpLiveness] {
		t.Error("OpLiveness should be skipped by default")
	}

	if !m.skipOpcodes[quicwire.OpReadiness] {
		t.Error("OpReadiness should be skipped by default")
	}
}

// =============================================================================
// AuthenticateRequest Tests
// =============================================================================

func TestAuthMiddleware_AuthenticateRequest_SkipOpcode(t *testing.T) {
	m := NewAuthMiddleware()

	req := &quicwire.Request{Opcode: quicwire.OpHealth}
	ctx, resp := m.AuthenticateRequest(context.Background(), req)

	if resp != nil {
		t.Errorf("expected nil response for skipped opcode, got %+v", resp)
	}

	if ctx == nil {
		t.Error("expected non-nil context")
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

func TestAuthMiddleware_AuthorizeRequest_SkipOpcode(t *testing.T) {
	m := NewAuthMiddleware()

	req := &quicwire.Request{Opcode: quicwire.OpHealth}
	resp := m.AuthorizeRequest(context.Background(), req, "health", "read")

	if resp != nil {
		t.Errorf("expected nil response for skipped opcode, got %+v", resp)
	}
}

func TestAuthMiddleware_AuthorizeRequest_NoChecker(t *testing.T) {
	m := NewAuthMiddleware()

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: "test-token"}
	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, req, "vtpm", "write")

	if resp != nil {
		t.Errorf("expected nil response when no checker configured, got %+v", resp)
	}
}

func TestAuthMiddleware_AuthorizeRequest_NoTokenInContext(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: true}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate}
	resp := m.AuthorizeRequest(context.Background(), req, "vtpm", "write")

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

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate}
	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, req, "vtpm", "write")

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

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate}
	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, req, "vtpm", "write")

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

	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate}
	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, req, "vtpm", "write")

	if resp != nil {
		t.Errorf("expected nil response when allowed, got %+v", resp)
	}
}

// =============================================================================
// OpcodePermission Tests
// =============================================================================

func TestOpcodePermission_Fields(t *testing.T) {
	perm := OpcodePermission{Resource: "vtpm", Action: "write"}

	if perm.Resource != "vtpm" {
		t.Errorf("Resource = %q, want %q", perm.Resource, "vtpm")
	}

	if perm.Action != "write" {
		t.Errorf("Action = %q, want %q", perm.Action, "write")
	}
}

// =============================================================================
// DefaultOpcodePermissions Tests
// =============================================================================

func TestDefaultOpcodePermissions(t *testing.T) {
	perms := DefaultOpcodePermissions()

	// Test that health opcodes have no permission requirement
	healthOpcodes := []byte{quicwire.OpHealth, quicwire.OpLiveness, quicwire.OpReadiness}
	for _, op := range healthOpcodes {
		if perm := perms[op]; perm != nil {
			t.Errorf("expected nil permission for health opcode 0x%02X, got %+v", op, perm)
		}
	}

	// Test VTPM operations
	tests := []struct {
		opcode   byte
		resource string
		action   string
	}{
		{quicwire.OpVTPMCreate, "vtpm", "write"},
		{quicwire.OpVTPMDelete, "vtpm", "delete"},
		{quicwire.OpVTPMStart, "vtpm", "write"},
		{quicwire.OpVTPMStop, "vtpm", "write"},
		{quicwire.OpVTPMGetState, "vtpm", "read"},
		{quicwire.OpVTPMList, "vtpm", "read"},
		{quicwire.OpVTPMGetEK, "vtpm", "read"},
		{quicwire.OpVTPMGetAK, "vtpm", "read"},
		{quicwire.OpVTPMCreateAK, "vtpm", "write"},
		{quicwire.OpVTPMQuote, "vtpm", "read"},
		{quicwire.OpVTPMExtendPCR, "vtpm", "write"},
		{quicwire.OpVTPMReadPCR, "vtpm", "read"},
		{quicwire.OpVTPMSeal, "vtpm", "write"},
		{quicwire.OpVTPMUnseal, "vtpm", "read"},
		// DNS operations
		{quicwire.OpDNSAddRecord, "dns", "write"},
		{quicwire.OpDNSDeleteRecord, "dns", "delete"},
		{quicwire.OpDNSUpdateRecord, "dns", "write"},
		{quicwire.OpDNSGetRecord, "dns", "read"},
		{quicwire.OpDNSListRecords, "dns", "read"},
		{quicwire.OpDNSAddZone, "dns", "write"},
		{quicwire.OpDNSDeleteZone, "dns", "delete"},
		{quicwire.OpDNSGetZone, "dns", "read"},
		{quicwire.OpDNSListZones, "dns", "read"},
		{quicwire.OpDNSResolve, "dns", "read"},
		// Device operations
		{quicwire.OpDeviceRegister, "device", "write"},
		{quicwire.OpDeviceUnregister, "device", "delete"},
		{quicwire.OpDeviceGet, "device", "read"},
		{quicwire.OpDeviceList, "device", "read"},
		{quicwire.OpDeviceUpdate, "device", "write"},
		{quicwire.OpDeviceAttest, "device", "read"},
		// SDN operations
		{quicwire.OpSDNGetPortState, "sdn", "read"},
		{quicwire.OpSDNSetPortState, "sdn", "write"},
		{quicwire.OpSDNListPorts, "sdn", "read"},
		{quicwire.OpSDNApplyPolicy, "sdn", "write"},
		{quicwire.OpSDNGetPolicy, "sdn", "read"},
		{quicwire.OpSDNListPolicies, "sdn", "read"},
		{quicwire.OpSDNListBridges, "sdn", "read"},
		{quicwire.OpSDNCreateBridge, "sdn", "write"},
		{quicwire.OpSDNDeleteBridge, "sdn", "delete"},
		{quicwire.OpSDNCreatePort, "sdn", "write"},
		{quicwire.OpSDNDeletePort, "sdn", "delete"},
		{quicwire.OpSDNDeletePolicy, "sdn", "delete"},
		// KMS operations
		{quicwire.OpKMSGenerateKey, "kms", "write"},
		{quicwire.OpKMSImportKey, "kms", "write"},
		{quicwire.OpKMSGetKey, "kms", "read"},
		{quicwire.OpKMSListKeys, "kms", "read"},
		{quicwire.OpKMSDeleteKey, "kms", "delete"},
		{quicwire.OpKMSRotateKey, "kms", "write"},
		{quicwire.OpKMSEncrypt, "kms", "write"},
		{quicwire.OpKMSDecrypt, "kms", "read"},
		{quicwire.OpKMSSign, "kms", "write"},
		{quicwire.OpKMSVerify, "kms", "read"},
		// IAM operations
		{quicwire.OpIAMUserCreate, "iam", "write"},
		{quicwire.OpIAMUserDelete, "iam", "delete"},
		{quicwire.OpIAMUserGet, "iam", "read"},
		{quicwire.OpIAMUserList, "iam", "read"},
		{quicwire.OpIAMUserUpdate, "iam", "write"},
		{quicwire.OpIAMRoleCreate, "iam", "write"},
		{quicwire.OpIAMRoleDelete, "iam", "delete"},
		{quicwire.OpIAMRoleGet, "iam", "read"},
		{quicwire.OpIAMRoleList, "iam", "read"},
		// CA operations
		{quicwire.OpCAInfo, "ca", "read"},
		{quicwire.OpCAIssue, "ca", "write"},
		{quicwire.OpCARevoke, "ca", "write"},
		{quicwire.OpCARenew, "ca", "write"},
		{quicwire.OpCAGet, "ca", "read"},
		{quicwire.OpCAList, "ca", "read"},
	}

	for _, tt := range tests {
		t.Run(quicwire.OpcodeToString(tt.opcode), func(t *testing.T) {
			perm := perms[tt.opcode]
			if perm == nil {
				t.Fatalf("expected permission for opcode 0x%02X, got nil", tt.opcode)
			}

			if perm.Resource != tt.resource {
				t.Errorf("resource = %q, want %q", perm.Resource, tt.resource)
			}

			if perm.Action != tt.action {
				t.Errorf("action = %q, want %q", perm.Action, tt.action)
			}
		})
	}
}

// =============================================================================
// Integration Test: AuthenticateRequest + AuthorizeRequest
// =============================================================================

func TestAuthMiddleware_FullFlow(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: true}
	checker := &mockQUICAuthorizationChecker{allowed: true}

	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
		WithQUICAuthorizationChecker(checker),
	)

	// Create request
	req := &quicwire.Request{Opcode: quicwire.OpVTPMCreate, Token: "valid-token"}

	// Authenticate
	ctx, resp := m.AuthenticateRequest(context.Background(), req)
	if resp != nil {
		t.Fatalf("authentication failed: %+v", resp)
	}

	// Get permission for opcode
	perms := DefaultOpcodePermissions()
	perm := perms[req.Opcode]
	if perm == nil {
		t.Fatal("expected permission for OpVTPMCreate")
	}

	// Authorize
	resp = m.AuthorizeRequest(ctx, req, perm.Resource, perm.Action)
	if resp != nil {
		t.Fatalf("authorization failed: %+v", resp)
	}
}

func TestAuthMiddleware_FullFlow_Unauthorized(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: true}
	checker := &mockQUICAuthorizationChecker{allowed: false}

	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
		WithQUICAuthorizationChecker(checker),
	)

	// Create request
	req := &quicwire.Request{Opcode: quicwire.OpVTPMDelete, Token: "valid-token"}

	// Authenticate
	ctx, resp := m.AuthenticateRequest(context.Background(), req)
	if resp != nil {
		t.Fatalf("authentication failed: %+v", resp)
	}

	// Get permission for opcode
	perms := DefaultOpcodePermissions()
	perm := perms[req.Opcode]
	if perm == nil {
		t.Fatal("expected permission for OpVTPMDelete")
	}

	// Authorize
	resp = m.AuthorizeRequest(ctx, req, perm.Resource, perm.Action)
	if resp == nil {
		t.Fatal("expected authorization to fail")
	}

	if resp.Status != quicwire.StatusPermissionDenied {
		t.Errorf("status = %v, want %v", resp.Status, quicwire.StatusPermissionDenied)
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestAuthMiddleware_CustomSkipOpcodes(t *testing.T) {
	// Create middleware with custom skip opcode
	customOpcode := byte(0xFF)
	m := NewAuthMiddleware(
		WithQUICSkipOpcodes(customOpcode),
	)

	req := &quicwire.Request{Opcode: customOpcode}
	ctx, resp := m.AuthenticateRequest(context.Background(), req)

	if resp != nil {
		t.Errorf("expected nil response for custom skip opcode, got %+v", resp)
	}

	if ctx == nil {
		t.Error("expected non-nil context")
	}
}

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
