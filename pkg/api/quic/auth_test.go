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
	if !m.skipOpcodes[OpHealth] {
		t.Error("OpHealth should be skipped by default")
	}

	if !m.skipOpcodes[OpLiveness] {
		t.Error("OpLiveness should be skipped by default")
	}

	if !m.skipOpcodes[OpReadiness] {
		t.Error("OpReadiness should be skipped by default")
	}
}

// =============================================================================
// AuthenticateRequest Tests
// =============================================================================

func TestAuthMiddleware_AuthenticateRequest_SkipOpcode(t *testing.T) {
	m := NewAuthMiddleware()

	req := &Request{Opcode: OpHealth}
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

	req := &Request{Opcode: OpVTPMCreate, Token: "test-token"}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response when no validator configured and auth required")
	}

	if resp.Status != StatusUnavailable {
		t.Errorf("status = %v, want %v", resp.Status, StatusUnavailable)
	}
}

func TestAuthMiddleware_AuthenticateRequest_NoValidator_AuthNotRequired(t *testing.T) {
	m := NewAuthMiddleware(
		WithQUICRequireAuth(false),
	)

	req := &Request{Opcode: OpVTPMCreate, Token: "test-token"}
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

	req := &Request{Opcode: OpVTPMCreate, Token: ""}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for missing token")
	}

	if resp.Status != StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthenticateRequest_ValidationFails(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: false, err: errors.New("token expired")}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	req := &Request{Opcode: OpVTPMCreate, Token: "expired-token"}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for validation failure")
	}

	if resp.Status != StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthenticateRequest_InvalidToken(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: false, err: nil}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	req := &Request{Opcode: OpVTPMCreate, Token: "invalid-token"}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for invalid token")
	}

	if resp.Status != StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthenticateRequest_ValidToken(t *testing.T) {
	validator := &mockQUICTokenValidator{valid: true}
	m := NewAuthMiddleware(
		WithQUICTokenValidator(validator),
	)

	req := &Request{Opcode: OpVTPMCreate, Token: "valid-token"}
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

	req := &Request{Opcode: OpHealth}
	resp := m.AuthorizeRequest(context.Background(), req, "health", "read")

	if resp != nil {
		t.Errorf("expected nil response for skipped opcode, got %+v", resp)
	}
}

func TestAuthMiddleware_AuthorizeRequest_NoChecker(t *testing.T) {
	m := NewAuthMiddleware()

	req := &Request{Opcode: OpVTPMCreate, Token: "test-token"}
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

	req := &Request{Opcode: OpVTPMCreate}
	resp := m.AuthorizeRequest(context.Background(), req, "vtpm", "write")

	if resp == nil {
		t.Fatal("expected error response when no token in context")
	}

	if resp.Status != StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthorizeRequest_CheckFails(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: false, err: errors.New("database error")}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	req := &Request{Opcode: OpVTPMCreate}
	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, req, "vtpm", "write")

	if resp == nil {
		t.Fatal("expected error response for check failure")
	}

	if resp.Status != StatusInternalError {
		t.Errorf("status = %v, want %v", resp.Status, StatusInternalError)
	}
}

func TestAuthMiddleware_AuthorizeRequest_NotAllowed(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: false, err: nil}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	req := &Request{Opcode: OpVTPMCreate}
	ctx := ContextWithToken(context.Background(), "test-token")
	resp := m.AuthorizeRequest(ctx, req, "vtpm", "write")

	if resp == nil {
		t.Fatal("expected error response when not allowed")
	}

	if resp.Status != StatusPermissionDenied {
		t.Errorf("status = %v, want %v", resp.Status, StatusPermissionDenied)
	}
}

func TestAuthMiddleware_AuthorizeRequest_Allowed(t *testing.T) {
	checker := &mockQUICAuthorizationChecker{allowed: true, err: nil}
	m := NewAuthMiddleware(
		WithQUICAuthorizationChecker(checker),
	)

	req := &Request{Opcode: OpVTPMCreate}
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
	healthOpcodes := []byte{OpHealth, OpLiveness, OpReadiness}
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
		{OpVTPMCreate, "vtpm", "write"},
		{OpVTPMDelete, "vtpm", "delete"},
		{OpVTPMStart, "vtpm", "write"},
		{OpVTPMStop, "vtpm", "write"},
		{OpVTPMGetState, "vtpm", "read"},
		{OpVTPMList, "vtpm", "read"},
		{OpVTPMGetEK, "vtpm", "read"},
		{OpVTPMGetAK, "vtpm", "read"},
		{OpVTPMCreateAK, "vtpm", "write"},
		{OpVTPMQuote, "vtpm", "read"},
		{OpVTPMExtendPCR, "vtpm", "write"},
		{OpVTPMReadPCR, "vtpm", "read"},
		{OpVTPMSeal, "vtpm", "write"},
		{OpVTPMUnseal, "vtpm", "read"},
		// DNS operations
		{OpDNSAddRecord, "dns", "write"},
		{OpDNSDeleteRecord, "dns", "delete"},
		{OpDNSUpdateRecord, "dns", "write"},
		{OpDNSGetRecord, "dns", "read"},
		{OpDNSListRecords, "dns", "read"},
		{OpDNSAddZone, "dns", "write"},
		{OpDNSDeleteZone, "dns", "delete"},
		{OpDNSGetZone, "dns", "read"},
		{OpDNSListZones, "dns", "read"},
		{OpDNSResolve, "dns", "read"},
		// Device operations
		{OpDeviceRegister, "device", "write"},
		{OpDeviceUnregister, "device", "delete"},
		{OpDeviceGet, "device", "read"},
		{OpDeviceList, "device", "read"},
		{OpDeviceUpdate, "device", "write"},
		{OpDeviceAttest, "device", "read"},
		// SDN operations
		{OpSDNGetPortState, "sdn", "read"},
		{OpSDNSetPortState, "sdn", "write"},
		{OpSDNListPorts, "sdn", "read"},
		{OpSDNApplyPolicy, "sdn", "write"},
		{OpSDNGetPolicy, "sdn", "read"},
		{OpSDNListPolicies, "sdn", "read"},
		{OpSDNListBridges, "sdn", "read"},
		{OpSDNCreateBridge, "sdn", "write"},
		{OpSDNDeleteBridge, "sdn", "delete"},
		{OpSDNCreatePort, "sdn", "write"},
		{OpSDNDeletePort, "sdn", "delete"},
		{OpSDNDeletePolicy, "sdn", "delete"},
		// KMS operations
		{OpKMSGenerateKey, "kms", "write"},
		{OpKMSImportKey, "kms", "write"},
		{OpKMSGetKey, "kms", "read"},
		{OpKMSListKeys, "kms", "read"},
		{OpKMSDeleteKey, "kms", "delete"},
		{OpKMSRotateKey, "kms", "write"},
		{OpKMSEncrypt, "kms", "write"},
		{OpKMSDecrypt, "kms", "read"},
		{OpKMSSign, "kms", "write"},
		{OpKMSVerify, "kms", "read"},
		// IAM operations
		{OpIAMUserCreate, "iam", "write"},
		{OpIAMUserDelete, "iam", "delete"},
		{OpIAMUserGet, "iam", "read"},
		{OpIAMUserList, "iam", "read"},
		{OpIAMUserUpdate, "iam", "write"},
		{OpIAMRoleCreate, "iam", "write"},
		{OpIAMRoleDelete, "iam", "delete"},
		{OpIAMRoleGet, "iam", "read"},
		{OpIAMRoleList, "iam", "read"},
		// CA operations
		{OpCAInfo, "ca", "read"},
		{OpCAIssue, "ca", "write"},
		{OpCARevoke, "ca", "write"},
		{OpCARenew, "ca", "write"},
		{OpCAGet, "ca", "read"},
		{OpCAList, "ca", "read"},
	}

	for _, tt := range tests {
		t.Run(OpcodeToString(tt.opcode), func(t *testing.T) {
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
	req := &Request{Opcode: OpVTPMCreate, Token: "valid-token"}

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
	req := &Request{Opcode: OpVTPMDelete, Token: "valid-token"}

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

	if resp.Status != StatusPermissionDenied {
		t.Errorf("status = %v, want %v", resp.Status, StatusPermissionDenied)
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

	req := &Request{Opcode: customOpcode}
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
	req := &Request{Opcode: OpVTPMCreate, Token: ""}
	_, resp := m.AuthenticateRequest(context.Background(), req)

	if resp == nil {
		t.Fatal("expected error response for empty token on protected opcode")
	}

	if resp.Status != StatusUnauthorized {
		t.Errorf("status = %v, want %v", resp.Status, StatusUnauthorized)
	}
}
