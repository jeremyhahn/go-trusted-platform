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
	"errors"
	"strings"
	"testing"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"google.golang.org/grpc"
)

// mockTokenValidator implements TokenValidator for testing.
type mockTokenValidator struct {
	result *TokenValidationResult
	err    error
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, token string) (*TokenValidationResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// mockPEPClient implements iampb.PEPServiceClient for testing.
type mockPEPClient struct {
	checkResp *iampb.CheckResponse
	checkErr  error
}

func (m *mockPEPClient) Check(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
	if m.checkErr != nil {
		return nil, m.checkErr
	}
	return m.checkResp, nil
}

func (m *mockPEPClient) CheckBatch(ctx context.Context, in *iampb.CheckBatchRequest, opts ...grpc.CallOption) (*iampb.CheckBatchResponse, error) {
	return nil, nil
}

func (m *mockPEPClient) Subscribe(ctx context.Context, in *iampb.SubscribeRequest, opts ...grpc.CallOption) (iampb.PEPService_SubscribeClient, error) {
	return nil, nil
}

func TestNewQuicBaaSAuthAdapter(t *testing.T) {
	t.Run("with nil config", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)

		if adapter == nil {
			t.Fatal("expected adapter to be created")
		}
		if adapter.cachedClaims == nil {
			t.Error("cachedClaims should be initialized")
		}
	})

	t.Run("with config", func(t *testing.T) {
		validator := &mockTokenValidator{}
		pepClient := &mockPEPClient{}

		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator:  validator,
			PEPClient:       pepClient,
			DefaultTenantID: "default-tenant",
		})

		if adapter.tokenValidator != validator {
			t.Error("token validator not set")
		}
		if adapter.pepClient != pepClient {
			t.Error("PEP client not set")
		}
		if adapter.defaultTenantID != "default-tenant" {
			t.Errorf("defaultTenantID = %s, want default-tenant", adapter.defaultTenantID)
		}
	})
}

func TestQuicBaaSAuthAdapter_ValidateToken(t *testing.T) {
	t.Run("returns error when validator not configured", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)

		valid, err := adapter.ValidateToken(context.Background(), "test-token")

		if err == nil {
			t.Error("expected error for nil validator")
		}
		if valid {
			t.Error("expected valid to be false")
		}

		authErr, ok := err.(*QuicBaaSAuthError)
		if !ok {
			t.Fatalf("expected *QuicBaaSAuthError, got %T", err)
		}
		if authErr.Code != QuicBaaSAuthErrorServiceUnavailable {
			t.Errorf("error code = %d, want %d", authErr.Code, QuicBaaSAuthErrorServiceUnavailable)
		}
	})

	t.Run("returns false for empty token", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{},
		})

		valid, err := adapter.ValidateToken(context.Background(), "")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if valid {
			t.Error("expected valid to be false for empty token")
		}
	})

	t.Run("returns validation result", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid:    true,
				UserID:   "user-123",
				TenantID: "tenant-456",
			},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
		})

		valid, err := adapter.ValidateToken(context.Background(), "test-token")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !valid {
			t.Error("expected valid to be true")
		}

		// Check that result is cached
		if _, ok := adapter.cachedClaims["test-token"]; !ok {
			t.Error("expected token to be cached")
		}
	})

	t.Run("returns error on validator failure", func(t *testing.T) {
		validator := &mockTokenValidator{
			err: errors.New("validation failed"),
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
		})

		valid, err := adapter.ValidateToken(context.Background(), "test-token")

		if err == nil {
			t.Error("expected error")
		}
		if valid {
			t.Error("expected valid to be false")
		}
	})
}

func TestQuicBaaSAuthAdapter_GetTokenClaims(t *testing.T) {
	t.Run("returns error when validator not configured", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)

		claims, err := adapter.GetTokenClaims(context.Background(), "test-token")

		if err == nil {
			t.Error("expected error for nil validator")
		}
		if claims != nil {
			t.Error("expected claims to be nil")
		}
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{},
		})

		claims, err := adapter.GetTokenClaims(context.Background(), "")

		if err == nil {
			t.Error("expected error for empty token")
		}
		if claims != nil {
			t.Error("expected claims to be nil")
		}
	})

	t.Run("returns claims from cache", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{
				err: errors.New("should not be called"),
			},
		})

		// Pre-populate cache
		adapter.cachedClaims["test-token"] = &TokenValidationResult{
			Valid:    true,
			UserID:   "cached-user",
			TenantID: "cached-tenant",
		}

		claims, err := adapter.GetTokenClaims(context.Background(), "test-token")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims["sub"] != "cached-user" {
			t.Errorf("sub = %v, want cached-user", claims["sub"])
		}
	})

	t.Run("validates and returns claims", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid:     true,
				UserID:    "user-123",
				TenantID:  "tenant-456",
				Roles:     []string{"admin", "user"},
				Groups:    []string{"group-1"},
				ExpiresAt: 1234567890,
				Scope:     "mcp:tools",
			},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
		})

		claims, err := adapter.GetTokenClaims(context.Background(), "test-token")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims["sub"] != "user-123" {
			t.Errorf("sub = %v, want user-123", claims["sub"])
		}
		if claims["tenant_id"] != "tenant-456" {
			t.Errorf("tenant_id = %v, want tenant-456", claims["tenant_id"])
		}
		if claims["scope"] != "mcp:tools" {
			t.Errorf("scope = %v, want mcp:tools", claims["scope"])
		}

		// Check roles
		roles, ok := claims["roles"].([]string)
		if !ok || len(roles) != 2 {
			t.Errorf("roles = %v, want [admin user]", claims["roles"])
		}
	})

	t.Run("returns error for invalid token", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid: false,
			},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
		})

		claims, err := adapter.GetTokenClaims(context.Background(), "invalid-token")

		if err == nil {
			t.Error("expected error for invalid token")
		}
		if claims != nil {
			t.Error("expected claims to be nil")
		}
	})

	t.Run("returns error when validator fails", func(t *testing.T) {
		validator := &mockTokenValidator{
			err: errors.New("validation failed"),
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
		})

		claims, err := adapter.GetTokenClaims(context.Background(), "test-token")

		if err == nil {
			t.Error("expected error from validator failure")
		}
		if claims != nil {
			t.Error("expected claims to be nil")
		}
	})

	t.Run("skips invalid cached result and revalidates", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid:    true,
				UserID:   "fresh-user",
				TenantID: "fresh-tenant",
			},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
		})

		// Pre-populate cache with invalid result
		adapter.cachedClaims["test-token"] = &TokenValidationResult{
			Valid:    false, // Invalid cached result should be skipped
			UserID:   "cached-user",
			TenantID: "cached-tenant",
		}

		claims, err := adapter.GetTokenClaims(context.Background(), "test-token")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Should get fresh result, not cached invalid result
		if claims["sub"] != "fresh-user" {
			t.Errorf("sub = %v, want fresh-user (should have revalidated)", claims["sub"])
		}
	})
}

func TestQuicBaaSAuthAdapter_CheckPermission(t *testing.T) {
	t.Run("returns error when PEP not configured", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{},
		})

		allowed, err := adapter.CheckPermission(context.Background(), "token", "vtpm", "read")

		if err == nil {
			t.Error("expected error for nil PEP client")
		}
		if allowed {
			t.Error("expected allowed to be false")
		}
	})

	t.Run("uses cached claims", func(t *testing.T) {
		pepClient := &mockPEPClient{
			checkResp: &iampb.CheckResponse{Allowed: true},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{
				err: errors.New("should not be called"),
			},
			PEPClient: pepClient,
		})

		// Pre-populate cache
		adapter.cachedClaims["test-token"] = &TokenValidationResult{
			Valid:    true,
			UserID:   "user-123",
			TenantID: "tenant-456",
			Roles:    []string{"admin"},
		}

		allowed, err := adapter.CheckPermission(context.Background(), "test-token", "vtpm", "read")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected allowed to be true")
		}
	})

	t.Run("validates token and checks permission", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid:    true,
				UserID:   "user-123",
				TenantID: "tenant-456",
			},
		}
		pepClient := &mockPEPClient{
			checkResp: &iampb.CheckResponse{Allowed: true},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
			PEPClient:      pepClient,
		})

		allowed, err := adapter.CheckPermission(context.Background(), "test-token", "vtpm", "read")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected allowed to be true")
		}
	})

	t.Run("returns false when not allowed", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid:    true,
				UserID:   "user-123",
				TenantID: "tenant-456",
			},
		}
		pepClient := &mockPEPClient{
			checkResp: &iampb.CheckResponse{Allowed: false},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
			PEPClient:      pepClient,
		})

		allowed, err := adapter.CheckPermission(context.Background(), "test-token", "vtpm", "admin")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if allowed {
			t.Error("expected allowed to be false")
		}
	})

	t.Run("returns error on PEP failure", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid:    true,
				UserID:   "user-123",
				TenantID: "tenant-456",
			},
		}
		pepClient := &mockPEPClient{
			checkErr: errors.New("PEP unavailable"),
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
			PEPClient:      pepClient,
		})

		allowed, err := adapter.CheckPermission(context.Background(), "test-token", "vtpm", "read")

		if err == nil {
			t.Error("expected error on PEP failure")
		}
		if allowed {
			t.Error("expected allowed to be false")
		}
	})

	t.Run("uses default tenant when not in token", func(t *testing.T) {
		validator := &mockTokenValidator{
			result: &TokenValidationResult{
				Valid:  true,
				UserID: "user-123",
				// No TenantID
			},
		}
		pepClient := &mockPEPClient{
			checkResp: &iampb.CheckResponse{Allowed: true},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator:  validator,
			PEPClient:       pepClient,
			DefaultTenantID: "default-tenant",
		})

		allowed, err := adapter.CheckPermission(context.Background(), "test-token", "vtpm", "read")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected allowed to be true")
		}
	})

	t.Run("returns error when token validation fails", func(t *testing.T) {
		validator := &mockTokenValidator{
			err: errors.New("token validation failed"),
		}
		pepClient := &mockPEPClient{
			checkResp: &iampb.CheckResponse{Allowed: true},
		}
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: validator,
			PEPClient:      pepClient,
		})

		allowed, err := adapter.CheckPermission(context.Background(), "bad-token", "vtpm", "read")

		if err == nil {
			t.Error("expected error when token validation fails")
		}
		if allowed {
			t.Error("expected allowed to be false")
		}
	})
}

func TestQuicBaaSAuthAdapter_HelperMethods(t *testing.T) {
	t.Run("IsConfigured returns false when nothing configured", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)

		if adapter.IsConfigured() {
			t.Error("expected IsConfigured to return false")
		}
	})

	t.Run("IsConfigured returns false when only validator configured", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{},
		})

		if adapter.IsConfigured() {
			t.Error("expected IsConfigured to return false")
		}
	})

	t.Run("IsConfigured returns true when fully configured", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{},
			PEPClient:      &mockPEPClient{},
		})

		if !adapter.IsConfigured() {
			t.Error("expected IsConfigured to return true")
		}
	})

	t.Run("HasTokenValidator", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)
		if adapter.HasTokenValidator() {
			t.Error("expected HasTokenValidator to return false")
		}

		adapter = NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			TokenValidator: &mockTokenValidator{},
		})
		if !adapter.HasTokenValidator() {
			t.Error("expected HasTokenValidator to return true")
		}
	})

	t.Run("HasPEPClient", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)
		if adapter.HasPEPClient() {
			t.Error("expected HasPEPClient to return false")
		}

		adapter = NewQuicBaaSAuthAdapter(&QuicBaaSAuthConfig{
			PEPClient: &mockPEPClient{},
		})
		if !adapter.HasPEPClient() {
			t.Error("expected HasPEPClient to return true")
		}
	})

	t.Run("SetDefaultTenantID", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)
		adapter.SetDefaultTenantID("new-tenant")

		if adapter.defaultTenantID != "new-tenant" {
			t.Errorf("defaultTenantID = %s, want new-tenant", adapter.defaultTenantID)
		}
	})

	t.Run("ClearCache", func(t *testing.T) {
		adapter := NewQuicBaaSAuthAdapter(nil)
		adapter.cachedClaims["token1"] = &TokenValidationResult{}
		adapter.cachedClaims["token2"] = &TokenValidationResult{}

		adapter.ClearCache()

		if len(adapter.cachedClaims) != 0 {
			t.Errorf("cache should be empty, got %d entries", len(adapter.cachedClaims))
		}
	})
}

func TestQuicBaaSAuthError(t *testing.T) {
	err := &QuicBaaSAuthError{
		Code:    QuicBaaSAuthErrorTokenValidation,
		Message: "token validation failed",
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "quicbaas auth error") {
		t.Errorf("error string should contain prefix: %s", errStr)
	}
	if !strings.Contains(errStr, "token validation failed") {
		t.Errorf("error string should contain message: %s", errStr)
	}
}

func TestParseToolPermission(t *testing.T) {
	t.Run("parses valid permission", func(t *testing.T) {
		perm, err := ParseToolPermission("vtpm:read")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if perm.Resource != "vtpm" {
			t.Errorf("resource = %s, want vtpm", perm.Resource)
		}
		if perm.Action != "read" {
			t.Errorf("action = %s, want read", perm.Action)
		}
	})

	t.Run("returns nil for empty permission", func(t *testing.T) {
		perm, err := ParseToolPermission("")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if perm != nil {
			t.Error("expected nil for empty permission")
		}
	})

	t.Run("returns error for invalid format", func(t *testing.T) {
		perm, err := ParseToolPermission("invalid")

		if err == nil {
			t.Error("expected error for invalid format")
		}
		if perm != nil {
			t.Error("expected perm to be nil")
		}
	})

	t.Run("handles complex resource names", func(t *testing.T) {
		perm, err := ParseToolPermission("container:runtime:start")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if perm.Resource != "container" {
			t.Errorf("resource = %s, want container", perm.Resource)
		}
		if perm.Action != "runtime:start" {
			t.Errorf("action = %s, want runtime:start", perm.Action)
		}
	})
}

func TestTokenValidationResult(t *testing.T) {
	result := &TokenValidationResult{
		Valid:     true,
		UserID:    "user-123",
		TenantID:  "tenant-456",
		Roles:     []string{"admin", "user"},
		Groups:    []string{"group-1", "group-2"},
		ExpiresAt: 1234567890,
		Scope:     "mcp:tools mcp:resources",
	}

	if !result.Valid {
		t.Error("expected Valid to be true")
	}
	if result.UserID != "user-123" {
		t.Errorf("UserID = %s, want user-123", result.UserID)
	}
	if result.TenantID != "tenant-456" {
		t.Errorf("TenantID = %s, want tenant-456", result.TenantID)
	}
	if len(result.Roles) != 2 {
		t.Errorf("Roles count = %d, want 2", len(result.Roles))
	}
	if len(result.Groups) != 2 {
		t.Errorf("Groups count = %d, want 2", len(result.Groups))
	}
}

// =============================================================================
// QuicBaaSTokenValidator Tests
// =============================================================================

// mockQuicBaaSService implements QuicBaaSService for testing.
type mockQuicBaaSService struct {
	resp *ValidateTokenResponse
	err  error
}

func (m *mockQuicBaaSService) ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func TestNewQuicBaaSTokenValidator(t *testing.T) {
	svc := &mockQuicBaaSService{}
	validator := NewQuicBaaSTokenValidator(svc)

	if validator == nil {
		t.Fatal("expected validator to be created")
	}
	if validator.service != svc {
		t.Error("expected service to be set")
	}
}

func TestQuicBaaSTokenValidator_ValidateToken(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when service is nil", func(t *testing.T) {
		validator := &QuicBaaSTokenValidator{service: nil}

		_, err := validator.ValidateToken(ctx, "token")
		if err == nil {
			t.Error("expected error for nil service")
		}
		authErr, ok := err.(*QuicBaaSAuthError)
		if !ok {
			t.Fatalf("expected QuicBaaSAuthError, got %T", err)
		}
		if authErr.Code != QuicBaaSAuthErrorServiceUnavailable {
			t.Errorf("error code = %d, want %d", authErr.Code, QuicBaaSAuthErrorServiceUnavailable)
		}
	})

	t.Run("returns error on service failure", func(t *testing.T) {
		svc := &mockQuicBaaSService{
			err: errors.New("service error"),
		}
		validator := NewQuicBaaSTokenValidator(svc)

		_, err := validator.ValidateToken(ctx, "token")
		if err == nil {
			t.Error("expected error on service failure")
		}
		authErr, ok := err.(*QuicBaaSAuthError)
		if !ok {
			t.Fatalf("expected QuicBaaSAuthError, got %T", err)
		}
		if authErr.Code != QuicBaaSAuthErrorTokenValidation {
			t.Errorf("error code = %d, want %d", authErr.Code, QuicBaaSAuthErrorTokenValidation)
		}
	})

	t.Run("returns validation result on success", func(t *testing.T) {
		svc := &mockQuicBaaSService{
			resp: &ValidateTokenResponse{
				Valid:     true,
				UserID:    "user-123",
				Username:  "testuser",
				Roles:     []string{"admin", "user"},
				ExpiresAt: 1234567890,
			},
		}
		validator := NewQuicBaaSTokenValidator(svc)

		result, err := validator.ValidateToken(ctx, "valid-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Valid {
			t.Error("expected Valid to be true")
		}
		if result.UserID != "user-123" {
			t.Errorf("UserID = %s, want user-123", result.UserID)
		}
		if len(result.Roles) != 2 {
			t.Errorf("Roles count = %d, want 2", len(result.Roles))
		}
		if result.ExpiresAt != 1234567890 {
			t.Errorf("ExpiresAt = %d, want 1234567890", result.ExpiresAt)
		}
	})

	t.Run("returns invalid result for invalid token", func(t *testing.T) {
		svc := &mockQuicBaaSService{
			resp: &ValidateTokenResponse{
				Valid: false,
			},
		}
		validator := NewQuicBaaSTokenValidator(svc)

		result, err := validator.ValidateToken(ctx, "invalid-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Valid {
			t.Error("expected Valid to be false")
		}
	})
}

// =============================================================================
// Factory Function Tests
// =============================================================================

func TestNewQuicBaaSAuthAdapterFromService(t *testing.T) {
	t.Run("creates adapter with service and PEP client", func(t *testing.T) {
		svc := &mockQuicBaaSService{}
		pep := &mockPEPClient{}

		adapter := NewQuicBaaSAuthAdapterFromService(svc, pep, "tenant-123")

		if adapter == nil {
			t.Fatal("expected adapter to be created")
		}
		if !adapter.HasTokenValidator() {
			t.Error("expected token validator to be set")
		}
		if !adapter.HasPEPClient() {
			t.Error("expected PEP client to be set")
		}
		if !adapter.IsConfigured() {
			t.Error("expected adapter to be fully configured")
		}
	})

	t.Run("creates adapter with nil service", func(t *testing.T) {
		pep := &mockPEPClient{}

		adapter := NewQuicBaaSAuthAdapterFromService(nil, pep, "tenant-123")

		if adapter == nil {
			t.Fatal("expected adapter to be created")
		}
		if adapter.HasTokenValidator() {
			t.Error("expected token validator to be nil")
		}
		if !adapter.HasPEPClient() {
			t.Error("expected PEP client to be set")
		}
	})

	t.Run("creates adapter with nil PEP client", func(t *testing.T) {
		svc := &mockQuicBaaSService{}

		adapter := NewQuicBaaSAuthAdapterFromService(svc, nil, "tenant-123")

		if adapter == nil {
			t.Fatal("expected adapter to be created")
		}
		if !adapter.HasTokenValidator() {
			t.Error("expected token validator to be set")
		}
		if adapter.HasPEPClient() {
			t.Error("expected PEP client to be nil")
		}
	})

	t.Run("creates adapter with empty tenant ID", func(t *testing.T) {
		svc := &mockQuicBaaSService{}
		pep := &mockPEPClient{}

		adapter := NewQuicBaaSAuthAdapterFromService(svc, pep, "")

		if adapter == nil {
			t.Fatal("expected adapter to be created")
		}
		// Adapter should still be created even with empty tenant ID
		if !adapter.IsConfigured() {
			t.Error("expected adapter to be configured")
		}
	})
}

// =============================================================================
// LocalPEPAdapter Tests
// =============================================================================

// mockPolicyEvaluator implements PolicyEvaluator for testing.
type mockPolicyEvaluator struct {
	resp *PolicyCheckResponse
	err  error
}

func (m *mockPolicyEvaluator) Evaluate(ctx context.Context, req *PolicyCheckRequest) (*PolicyCheckResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func TestNewLocalPEPAdapter(t *testing.T) {
	evaluator := &mockPolicyEvaluator{}
	adapter := NewLocalPEPAdapter(evaluator)

	if adapter == nil {
		t.Fatal("expected adapter to be created")
	}
	if adapter.evaluator != evaluator {
		t.Error("expected evaluator to be set")
	}
}

func TestLocalPEPAdapter_Check(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when evaluator is nil", func(t *testing.T) {
		adapter := &LocalPEPAdapter{evaluator: nil}

		_, err := adapter.Check(ctx, &iampb.CheckRequest{
			Subject:  &iampb.Subject{Id: "user-123"},
			Action:   "read",
			Resource: "vtpm",
		})

		if err == nil {
			t.Error("expected error for nil evaluator")
		}
		authErr, ok := err.(*QuicBaaSAuthError)
		if !ok {
			t.Fatalf("expected QuicBaaSAuthError, got %T", err)
		}
		if authErr.Code != QuicBaaSAuthErrorServiceUnavailable {
			t.Errorf("error code = %d, want %d", authErr.Code, QuicBaaSAuthErrorServiceUnavailable)
		}
	})

	t.Run("returns error on evaluator failure", func(t *testing.T) {
		evaluator := &mockPolicyEvaluator{
			err: errors.New("evaluation error"),
		}
		adapter := NewLocalPEPAdapter(evaluator)

		_, err := adapter.Check(ctx, &iampb.CheckRequest{
			Subject:  &iampb.Subject{Id: "user-123"},
			Action:   "read",
			Resource: "vtpm",
		})

		if err == nil {
			t.Error("expected error on evaluation failure")
		}
		authErr, ok := err.(*QuicBaaSAuthError)
		if !ok {
			t.Fatalf("expected QuicBaaSAuthError, got %T", err)
		}
		if authErr.Code != QuicBaaSAuthErrorPermissionCheck {
			t.Errorf("error code = %d, want %d", authErr.Code, QuicBaaSAuthErrorPermissionCheck)
		}
	})

	t.Run("returns allowed on success", func(t *testing.T) {
		evaluator := &mockPolicyEvaluator{
			resp: &PolicyCheckResponse{
				Allowed:       true,
				MatchedPolicy: "vtpm-access-policy",
				MatchedRule:   "allow-read",
			},
		}
		adapter := NewLocalPEPAdapter(evaluator)

		resp, err := adapter.Check(ctx, &iampb.CheckRequest{
			Subject: &iampb.Subject{
				Id:       "user-123",
				TenantId: "tenant-456",
				Roles:    []string{"admin"},
				Groups:   []string{"developers"},
			},
			Action:   "read",
			Resource: "vtpm",
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Allowed {
			t.Error("expected Allowed to be true")
		}
	})

	t.Run("returns not allowed on denial", func(t *testing.T) {
		evaluator := &mockPolicyEvaluator{
			resp: &PolicyCheckResponse{
				Allowed: false,
				Reason:  "access denied",
			},
		}
		adapter := NewLocalPEPAdapter(evaluator)

		resp, err := adapter.Check(ctx, &iampb.CheckRequest{
			Subject:  &iampb.Subject{Id: "user-123"},
			Action:   "delete",
			Resource: "vtpm",
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Allowed {
			t.Error("expected Allowed to be false")
		}
	})

	t.Run("passes subject fields correctly", func(t *testing.T) {
		var capturedReq *PolicyCheckRequest
		evaluator := &mockPolicyEvaluator{
			resp: &PolicyCheckResponse{Allowed: true},
		}
		// Override Evaluate to capture the request
		originalEvaluate := evaluator.Evaluate
		_ = originalEvaluate // prevent unused warning
		captureAdapter := &capturingPolicyEvaluator{
			resp:     &PolicyCheckResponse{Allowed: true},
			captured: &capturedReq,
		}
		adapter := NewLocalPEPAdapter(captureAdapter)

		_, err := adapter.Check(ctx, &iampb.CheckRequest{
			Subject: &iampb.Subject{
				Id:       "user-123",
				TenantId: "tenant-456",
				Roles:    []string{"admin", "user"},
				Groups:   []string{"devs"},
			},
			Action:   "write",
			Resource: "device",
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedReq == nil {
			t.Fatal("expected request to be captured")
		}
		if capturedReq.Subject.ID != "user-123" {
			t.Errorf("Subject.ID = %s, want user-123", capturedReq.Subject.ID)
		}
		if capturedReq.Subject.TenantID != "tenant-456" {
			t.Errorf("Subject.TenantID = %s, want tenant-456", capturedReq.Subject.TenantID)
		}
		if len(capturedReq.Subject.Roles) != 2 {
			t.Errorf("Subject.Roles count = %d, want 2", len(capturedReq.Subject.Roles))
		}
		if capturedReq.Action != "write" {
			t.Errorf("Action = %s, want write", capturedReq.Action)
		}
		if capturedReq.Resource != "device" {
			t.Errorf("Resource = %s, want device", capturedReq.Resource)
		}
	})
}

// capturingPolicyEvaluator captures the request for inspection.
type capturingPolicyEvaluator struct {
	resp     *PolicyCheckResponse
	captured **PolicyCheckRequest
}

func (e *capturingPolicyEvaluator) Evaluate(ctx context.Context, req *PolicyCheckRequest) (*PolicyCheckResponse, error) {
	*e.captured = req
	return e.resp, nil
}
