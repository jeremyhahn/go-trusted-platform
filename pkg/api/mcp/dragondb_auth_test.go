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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
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

// mockPEPClient implements iam.PEPClient for testing.
type mockPEPClient struct {
	checkResp *iam.CheckResponse
	checkErr  error
}

func (m *mockPEPClient) Check(ctx context.Context, req *iam.CheckRequest) (*iam.CheckResponse, error) {
	if m.checkErr != nil {
		return nil, m.checkErr
	}
	return m.checkResp, nil
}

func (m *mockPEPClient) CheckBatch(ctx context.Context, req *iam.CheckBatchRequest) (*iam.CheckBatchResponse, error) {
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
			checkResp: &iam.CheckResponse{Allowed: true},
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
			checkResp: &iam.CheckResponse{Allowed: true},
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
			checkResp: &iam.CheckResponse{Allowed: false},
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
			checkResp: &iam.CheckResponse{Allowed: true},
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
			checkResp: &iam.CheckResponse{Allowed: true},
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
