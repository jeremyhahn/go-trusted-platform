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
	"testing"
)

// mockAuthManager is a mock implementation of AuthManager.
type mockAuthManager struct {
	validateFunc   func(ctx context.Context, token string) (bool, error)
	getClaimsFunc  func(ctx context.Context, token string) (map[string]interface{}, error)
	validateCalled bool
	lastToken      string
}

func (m *mockAuthManager) ValidateToken(ctx context.Context, token string) (bool, error) {
	m.validateCalled = true
	m.lastToken = token
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return true, nil
}

func (m *mockAuthManager) GetTokenClaims(ctx context.Context, token string) (map[string]interface{}, error) {
	if m.getClaimsFunc != nil {
		return m.getClaimsFunc(ctx, token)
	}
	return map[string]interface{}{}, nil
}

// mockAuthorizationService is a mock implementation of AuthorizationService.
type mockAuthorizationService struct {
	checkFunc    func(ctx context.Context, subject, resource, action string) (bool, error)
	checkCalled  bool
	lastSubject  string
	lastResource string
	lastAction   string
}

func (m *mockAuthorizationService) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error) {
	m.checkCalled = true
	m.lastSubject = subject
	m.lastResource = resource
	m.lastAction = action
	if m.checkFunc != nil {
		return m.checkFunc(ctx, subject, resource, action)
	}
	return true, nil
}

func TestNewAuthorizationChecker(t *testing.T) {
	t.Run("creates checker with nil services", func(t *testing.T) {
		checker := NewAuthorizationChecker(nil, nil)
		if checker == nil {
			t.Fatal("NewAuthorizationChecker returned nil")
		}
		if checker.authService != nil {
			t.Error("authService should be nil")
		}
		if checker.authManager != nil {
			t.Error("authManager should be nil")
		}
	})

	t.Run("creates checker with services", func(t *testing.T) {
		authSvc := &mockAuthorizationService{}
		authMgr := &mockAuthManager{}

		checker := NewAuthorizationChecker(authSvc, authMgr)
		if checker == nil {
			t.Fatal("NewAuthorizationChecker returned nil")
		}
		if checker.authService == nil {
			t.Error("authService should not be nil")
		}
		if checker.authManager == nil {
			t.Error("authManager should not be nil")
		}
	})

	t.Run("initializes tool permissions", func(t *testing.T) {
		checker := NewAuthorizationChecker(nil, nil)
		if len(checker.toolPermissions) == 0 {
			t.Error("toolPermissions should not be empty")
		}
	})
}

func TestToolPermissionCatalog(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	tests := []struct {
		toolName           string
		expectedPermission string
	}{
		// vTPM tools
		{"vtpm_create", "vtpm:write"},
		{"vtpm_delete", "vtpm:delete"},
		{"vtpm_list", "vtpm:read"},
		{"vtpm_start", "vtpm:write"},
		{"vtpm_stop", "vtpm:write"},
		{"vtpm_quote", "vtpm:read"},
		{"vtpm_seal", "vtpm:write"},
		{"vtpm_unseal", "vtpm:read"},
		{"vtpm_extend_pcr", "vtpm:write"},
		{"vtpm_read_pcr", "vtpm:read"},

		// DNS tools
		{"dns_add_record", "dns:write"},
		{"dns_delete_record", "dns:delete"},
		{"dns_get_record", "dns:read"},
		{"dns_list_records", "dns:read"},
		{"dns_resolve", "dns:read"},
		{"dns_create_zone", "dns:write"},
		{"dns_delete_zone", "dns:delete"},
		{"dns_list_zones", "dns:read"},

		// Device tools
		{"device_register", "device:write"},
		{"device_get", "device:read"},
		{"device_disable", "device:write"},
		{"device_enable", "device:write"},
		{"device_list", "device:read"},
		{"device_delete", "device:delete"},
		{"device_update", "device:write"},
		{"device_attest", "device:write"},
		{"device_record_attest_cert", "device:write"},
		{"device_provision", "device:write"},

		// SDN tools
		{"sdn_get_port_state", "sdn:read"},
		{"sdn_set_port_state", "sdn:write"},
		{"sdn_list_bridges", "sdn:read"},
		{"sdn_create_bridge", "sdn:write"},
		{"sdn_delete_bridge", "sdn:delete"},
		{"sdn_add_port", "sdn:write"},
		{"sdn_delete_port", "sdn:delete"},
		{"sdn_apply_policy", "sdn:write"},
		{"sdn_get_policy", "sdn:read"},
		{"sdn_list_policies", "sdn:read"},

		// Health tools (no auth required)
		{"platform_health", ""},
		{"platform_liveness", ""},
		{"platform_readiness", ""},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			permission, exists := checker.toolPermissions[tt.toolName]
			if !exists {
				t.Errorf("permission for %s not found", tt.toolName)
				return
			}
			if permission != tt.expectedPermission {
				t.Errorf("permission for %s = %s, want %s", tt.toolName, permission, tt.expectedPermission)
			}
		})
	}
}

func TestAuthorizationChecker_CheckToolAuthorization(t *testing.T) {
	ctx := context.Background()

	t.Run("refuses unknown tool", func(t *testing.T) {
		checker := NewAuthorizationChecker(nil, nil)
		err := checker.CheckToolAuthorization(ctx, "unknown_tool", "token")
		if err == nil || err.Type != AuthErrorToolNotClassified {
			t.Errorf("expected AuthErrorToolNotClassified for an unmapped tool, got %v", err)
		}
	})

	t.Run("allows tool with no permission required", func(t *testing.T) {
		checker := NewAuthorizationChecker(nil, nil)
		err := checker.CheckToolAuthorization(ctx, "platform_health", "")
		if err != nil {
			t.Errorf("expected nil error for health tool, got %v", err)
		}
	})

	// Until #440 both of these expected nil: "when no auth backend is
	// configured, all tools should be allowed (open mode for test/standalone
	// deployments)". That default served every protected tool to any caller
	// whenever the daemon's IAM wiring failed. A protected tool with no
	// backend is now refused, token or not, because nothing can validate it.
	t.Run("refuses protected tool when no auth services configured", func(t *testing.T) {
		checker := NewAuthorizationChecker(nil, nil)
		err := checker.CheckToolAuthorization(ctx, "vtpm_create", "")
		if err == nil || err.Type != AuthErrorMissingToken {
			t.Errorf("expected AuthErrorMissingToken without a backend, got %v", err)
		}
	})

	t.Run("refuses protected tool with a token when no auth configured", func(t *testing.T) {
		checker := NewAuthorizationChecker(nil, nil)
		err := checker.CheckToolAuthorization(ctx, "vtpm_delete", "some-token")
		if err == nil || err.Type != AuthErrorMissingToken {
			t.Errorf("expected AuthErrorMissingToken without a backend, got %v", err)
		}
	})

	t.Run("requires token for protected tool when auth configured", func(t *testing.T) {
		authMgr := &mockAuthManager{}
		checker := NewAuthorizationChecker(nil, authMgr)

		err := checker.CheckToolAuthorization(ctx, "vtpm_create", "")
		if err == nil {
			t.Fatal("expected error for missing token")
		}
		if err.Type != AuthErrorMissingToken {
			t.Errorf("error type = %v, want AuthErrorMissingToken", err.Type)
		}
	})

	t.Run("validates token with auth manager", func(t *testing.T) {
		authMgr := &mockAuthManager{
			validateFunc: func(ctx context.Context, token string) (bool, error) {
				return true, nil
			},
		}
		checker := NewAuthorizationChecker(nil, authMgr)

		err := checker.CheckToolAuthorization(ctx, "vtpm_create", "valid-token")
		if err != nil {
			t.Errorf("expected nil error for valid token, got %v", err)
		}
		if !authMgr.validateCalled {
			t.Error("ValidateToken was not called")
		}
		if authMgr.lastToken != "valid-token" {
			t.Errorf("lastToken = %s, want valid-token", authMgr.lastToken)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		authMgr := &mockAuthManager{
			validateFunc: func(ctx context.Context, token string) (bool, error) {
				return false, nil
			},
		}
		checker := NewAuthorizationChecker(nil, authMgr)

		err := checker.CheckToolAuthorization(ctx, "vtpm_create", "invalid-token")
		if err == nil {
			t.Fatal("expected error for invalid token")
		}
		if err.Type != AuthErrorInvalidToken {
			t.Errorf("error type = %v, want AuthErrorInvalidToken", err.Type)
		}
	})

	t.Run("rejects on token validation error", func(t *testing.T) {
		authMgr := &mockAuthManager{
			validateFunc: func(ctx context.Context, token string) (bool, error) {
				return false, errors.New("validation failed")
			},
		}
		checker := NewAuthorizationChecker(nil, authMgr)

		err := checker.CheckToolAuthorization(ctx, "vtpm_create", "some-token")
		if err == nil {
			t.Fatal("expected error for validation failure")
		}
		if err.Type != AuthErrorInvalidToken {
			t.Errorf("error type = %v, want AuthErrorInvalidToken", err.Type)
		}
	})

	t.Run("checks permission with authorization service", func(t *testing.T) {
		authSvc := &mockAuthorizationService{
			checkFunc: func(ctx context.Context, subject, resource, action string) (bool, error) {
				return true, nil
			},
		}
		checker := NewAuthorizationChecker(authSvc, nil)

		err := checker.CheckToolAuthorization(ctx, "vtpm_create", "token")
		if err != nil {
			t.Errorf("expected nil error for allowed permission, got %v", err)
		}
		if !authSvc.checkCalled {
			t.Error("CheckPermission was not called")
		}
		if authSvc.lastSubject != "token" {
			t.Errorf("lastSubject = %s, want token", authSvc.lastSubject)
		}
		if authSvc.lastResource != "vtpm" {
			t.Errorf("lastResource = %s, want vtpm", authSvc.lastResource)
		}
		if authSvc.lastAction != "write" {
			t.Errorf("lastAction = %s, want write", authSvc.lastAction)
		}
	})

	t.Run("denies permission when not allowed", func(t *testing.T) {
		authSvc := &mockAuthorizationService{
			checkFunc: func(ctx context.Context, subject, resource, action string) (bool, error) {
				return false, nil
			},
		}
		checker := NewAuthorizationChecker(authSvc, nil)

		err := checker.CheckToolAuthorization(ctx, "vtpm_delete", "token")
		if err == nil {
			t.Fatal("expected error for denied permission")
		}
		if err.Type != AuthErrorPermissionDenied {
			t.Errorf("error type = %v, want AuthErrorPermissionDenied", err.Type)
		}
	})

	t.Run("denies permission on check error", func(t *testing.T) {
		authSvc := &mockAuthorizationService{
			checkFunc: func(ctx context.Context, subject, resource, action string) (bool, error) {
				return false, errors.New("permission check failed")
			},
		}
		checker := NewAuthorizationChecker(authSvc, nil)

		err := checker.CheckToolAuthorization(ctx, "dns_add_record", "token")
		if err == nil {
			t.Fatal("expected error for check failure")
		}
		if err.Type != AuthErrorPermissionDenied {
			t.Errorf("error type = %v, want AuthErrorPermissionDenied", err.Type)
		}
	})

	t.Run("validates token before checking permission", func(t *testing.T) {
		callOrder := []string{}
		authMgr := &mockAuthManager{
			validateFunc: func(ctx context.Context, token string) (bool, error) {
				callOrder = append(callOrder, "validate")
				return true, nil
			},
		}
		authSvc := &mockAuthorizationService{
			checkFunc: func(ctx context.Context, subject, resource, action string) (bool, error) {
				callOrder = append(callOrder, "check")
				return true, nil
			},
		}
		checker := NewAuthorizationChecker(authSvc, authMgr)

		err := checker.CheckToolAuthorization(ctx, "vtpm_list", "token")
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
		if len(callOrder) != 2 || callOrder[0] != "validate" || callOrder[1] != "check" {
			t.Errorf("call order = %v, want [validate, check]", callOrder)
		}
	})
}

func TestAuthorizationChecker_IsEnabled(t *testing.T) {
	t.Run("returns false when no services", func(t *testing.T) {
		checker := NewAuthorizationChecker(nil, nil)
		if checker.IsEnabled() {
			t.Error("IsEnabled() = true, want false")
		}
	})

	t.Run("returns true when auth service configured", func(t *testing.T) {
		authSvc := &mockAuthorizationService{}
		checker := NewAuthorizationChecker(authSvc, nil)
		if !checker.IsEnabled() {
			t.Error("IsEnabled() = false, want true")
		}
	})

	t.Run("returns true when auth manager configured", func(t *testing.T) {
		authMgr := &mockAuthManager{}
		checker := NewAuthorizationChecker(nil, authMgr)
		if !checker.IsEnabled() {
			t.Error("IsEnabled() = false, want true")
		}
	})

	t.Run("returns true when both services configured", func(t *testing.T) {
		authSvc := &mockAuthorizationService{}
		authMgr := &mockAuthManager{}
		checker := NewAuthorizationChecker(authSvc, authMgr)
		if !checker.IsEnabled() {
			t.Error("IsEnabled() = false, want true")
		}
	})
}

func TestAuthorizationChecker_InvalidPermissionConfig(t *testing.T) {
	t.Run("returns error for malformed permission string", func(t *testing.T) {
		authSvc := &mockAuthorizationService{}
		checker := NewAuthorizationChecker(authSvc, nil)

		// Override toolPermissions with malformed permission (no colon)
		checker.toolPermissions["malformed_tool"] = "invalid_permission_no_colon"

		ctx := context.Background()
		err := checker.CheckToolAuthorization(ctx, "malformed_tool", "valid-token")

		if err == nil {
			t.Fatal("expected error for malformed permission configuration")
		}
		if err.Type != AuthErrorPermissionDenied {
			t.Errorf("error type = %v, want AuthErrorPermissionDenied", err.Type)
		}
	})
}

func TestAuthorizationChecker_PermissionParsing(t *testing.T) {
	t.Run("correctly parses resource and action from permission", func(t *testing.T) {
		authSvc := &mockAuthorizationService{}
		checker := NewAuthorizationChecker(authSvc, nil)

		tests := []struct {
			tool             string
			expectedResource string
			expectedAction   string
		}{
			{"vtpm_create", "vtpm", "write"},
			{"vtpm_delete", "vtpm", "delete"},
			{"vtpm_list", "vtpm", "read"},
			{"dns_add_record", "dns", "write"},
			{"dns_delete_record", "dns", "delete"},
			{"dns_get_record", "dns", "read"},
			{"device_register", "device", "write"},
			{"device_delete", "device", "delete"},
			{"device_get", "device", "read"},
			{"device_disable", "device", "write"},
			{"device_enable", "device", "write"},
			{"sdn_create_bridge", "sdn", "write"},
			{"sdn_delete_bridge", "sdn", "delete"},
			{"sdn_list_bridges", "sdn", "read"},
		}

		ctx := context.Background()
		for _, tt := range tests {
			t.Run(tt.tool, func(t *testing.T) {
				authSvc.checkCalled = false
				authSvc.lastResource = ""
				authSvc.lastAction = ""

				_ = checker.CheckToolAuthorization(ctx, tt.tool, "token")

				if authSvc.lastResource != tt.expectedResource {
					t.Errorf("resource = %s, want %s", authSvc.lastResource, tt.expectedResource)
				}
				if authSvc.lastAction != tt.expectedAction {
					t.Errorf("action = %s, want %s", authSvc.lastAction, tt.expectedAction)
				}
			})
		}
	})
}
