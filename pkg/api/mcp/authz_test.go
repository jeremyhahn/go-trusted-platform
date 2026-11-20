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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
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
		{"sdn_delete_policy", "sdn:delete"},

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
		authMgr := legacyCaller()
		checker := NewAuthorizationChecker(nil, authMgr, WithPEPClient(&recordingPEP{allowed: true}))

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
		checker := pepChecker(authSvc, nil)

		err := checker.CheckToolAuthorization(ctx, "vtpm_create", "token")
		if err != nil {
			t.Errorf("expected nil error for allowed permission, got %v", err)
		}
		if !authSvc.checkCalled {
			t.Error("CheckPermission was not called")
		}
		if authSvc.lastSubject != "user-1" {
			t.Errorf("lastSubject = %s, want the caller user-1", authSvc.lastSubject)
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
		checker := pepChecker(authSvc, nil)

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
		checker := pepChecker(authSvc, nil)

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
			getClaimsFunc: legacyCaller().getClaimsFunc,
		}
		authSvc := &mockAuthorizationService{
			checkFunc: func(ctx context.Context, subject, resource, action string) (bool, error) {
				callOrder = append(callOrder, "check")
				return true, nil
			},
		}
		checker := pepChecker(authSvc, authMgr)

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
		checker := pepChecker(authSvc, nil)

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
		checker := pepChecker(authSvc, nil)

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

// recordingPEP is an iam.PEPClient fake that records the last check request.
type recordingPEP struct {
	allowed bool
	err     error
	calls   int
	last    *iam.CheckRequest
}

func (p *recordingPEP) Check(_ context.Context, req *iam.CheckRequest) (*iam.CheckResponse, error) {
	p.calls++
	p.last = req
	if p.err != nil {
		return nil, p.err
	}
	return &iam.CheckResponse{Allowed: p.allowed}, nil
}

func (p *recordingPEP) CheckBatch(context.Context, *iam.CheckBatchRequest) (*iam.CheckBatchResponse, error) {
	return nil, errors.New("not used")
}

// legacyCaller is a bool-only AuthManager whose token carries a subject,
// a tenant and roles, so an unscoped tool call reaches the PEP fallback.
func legacyCaller() *mockAuthManager {
	return &mockAuthManager{
		validateFunc: func(context.Context, string) (bool, error) { return true, nil },
		getClaimsFunc: func(context.Context, string) (map[string]interface{}, error) {
			return map[string]interface{}{
				"sub":       "user-1",
				"tenant_id": "tenant-1",
				"roles":     []string{"operator"},
			}, nil
		},
	}
}

// TestAuthorizeTool_UnscopedPathDecidedByPEP pins SPEC row 116 (#1995): an
// unscoped tool call is decided by the IAM PEP for the caller and the
// tool's permission, never by a split of the permission string.
func TestAuthorizeTool_UnscopedPathDecidedByPEP(t *testing.T) {
	const tool = "pep_probe_tool"

	newChecker := func(pep iam.PEPClient) *AuthorizationChecker {
		var opts []AuthorizationCheckerOption
		if pep != nil {
			opts = append(opts, WithPEPClient(pep))
		}
		c := NewAuthorizationChecker(nil, legacyCaller(), opts...)
		c.toolPermissions[tool] = "device:power:write"
		return c
	}

	t.Run("allow", func(t *testing.T) {
		pep := &recordingPEP{allowed: true}
		if _, err := newChecker(pep).AuthorizeTool(context.Background(), tool, "tok"); err != nil {
			t.Fatalf("PEP allow: want nil error, got %v", err)
		}
		if pep.calls != 1 || pep.last == nil {
			t.Fatalf("PEP calls = %d, want 1", pep.calls)
		}
		if pep.last.Subject.ID != "user-1" || pep.last.Subject.TenantID != "tenant-1" {
			t.Errorf("subject = %+v, want user-1 in tenant-1", pep.last.Subject)
		}
		if len(pep.last.Subject.Roles) != 1 || pep.last.Subject.Roles[0] != "operator" {
			t.Errorf("roles = %v, want [operator]", pep.last.Subject.Roles)
		}
		if pep.last.Resource != "device" || pep.last.Action != "power:write" {
			t.Errorf("resource/action = %q/%q, want device/power:write", pep.last.Resource, pep.last.Action)
		}
	})

	t.Run("deny", func(t *testing.T) {
		_, err := newChecker(&recordingPEP{allowed: false}).AuthorizeTool(context.Background(), tool, "tok")
		if err == nil || err.Type != AuthErrorPermissionDenied {
			t.Fatalf("PEP deny: want permission denied, got %v", err)
		}
	})

	t.Run("error", func(t *testing.T) {
		_, err := newChecker(&recordingPEP{err: errors.New("pep down")}).AuthorizeTool(context.Background(), tool, "tok")
		if err == nil || err.Type != AuthErrorPermissionDenied {
			t.Fatalf("PEP error: want permission denied, got %v", err)
		}
	})

	t.Run("nil PEP", func(t *testing.T) {
		_, err := newChecker(nil).AuthorizeTool(context.Background(), tool, "tok")
		if err == nil || err.Type != AuthErrorPermissionDenied {
			t.Fatalf("nil PEP: want permission denied, got %v", err)
		}
	})
}

// A token the legacy ValidateToken path accepts carries a user and roles but
// may carry no tenant. The old QuicBaaSAuthAdapter refused a blank tenant
// before deciding; the PEP fallback must too, before asking the PEP
// (#2011 Codex).
func TestAuthorizeTool_BlankTenantRefusedBeforePEP(t *testing.T) {
	const tool = "pep_probe_tool"

	for name, tenant := range map[string]interface{}{
		"empty":      "",
		"whitespace": " \t ",
		"missing":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]interface{}{
				"sub":   "user-1",
				"roles": []string{"operator"},
			}
			if tenant != nil {
				claims["tenant_id"] = tenant
			}
			mgr := &mockAuthManager{
				validateFunc: func(context.Context, string) (bool, error) { return true, nil },
				getClaimsFunc: func(context.Context, string) (map[string]interface{}, error) {
					return claims, nil
				},
			}
			pep := &recordingPEP{allowed: true}
			c := NewAuthorizationChecker(nil, mgr, WithPEPClient(pep))
			c.toolPermissions[tool] = "device:power:write"

			_, err := c.AuthorizeTool(context.Background(), tool, "tok")
			if err == nil || err.Type != AuthErrorPermissionDenied {
				t.Fatalf("blank tenant: want permission denied, got %v", err)
			}
			if pep.calls != 0 {
				t.Errorf("PEP calls = %d, want 0: a tenantless caller must not reach the PEP", pep.calls)
			}
		})
	}
}

// declaredTools is a module declaring its MCP tool permissions through the
// SDK's ModuleMCPToolPermissions extension.
type declaredTools map[string]quicbaas.Permission

func (d declaredTools) MCPToolPermissions() map[string]quicbaas.Permission { return d }

var _ quicbaas.ModuleMCPToolPermissions = declaredTools(nil)

// TestAuthorizeTool_ModuleDeclaredPermissions pins SPEC row 116 (#1995): the
// tool's permission is the one its module declares, and the IAM PEP decides it.
func TestAuthorizeTool_ModuleDeclaredPermissions(t *testing.T) {
	module := declaredTools{
		"module_power_tool": quicbaas.Permission("bmc:power"),
		"module_gated_tool": quicbaas.PermissionIdentityGated,
	}
	newChecker := func(pep iam.PEPClient, manager AuthManager) *AuthorizationChecker {
		return NewAuthorizationChecker(nil, manager, WithPEPClient(pep), WithToolPermissions(module))
	}

	t.Run("declared permission goes to the PEP", func(t *testing.T) {
		pep := &recordingPEP{allowed: true}
		if _, err := newChecker(pep, legacyCaller()).AuthorizeTool(context.Background(), "module_power_tool", "tok"); err != nil {
			t.Fatalf("declared tool: want nil error, got %v", err)
		}
		if pep.calls != 1 || pep.last == nil {
			t.Fatalf("PEP calls = %d, want 1", pep.calls)
		}
		if pep.last.Resource != "bmc" || pep.last.Action != "power" {
			t.Errorf("resource/action = %q/%q, want bmc/power", pep.last.Resource, pep.last.Action)
		}
	})

	t.Run("undeclared tool is denied", func(t *testing.T) {
		pep := &recordingPEP{allowed: true}
		_, err := newChecker(pep, legacyCaller()).AuthorizeTool(context.Background(), "vtpm_list", "tok")
		if err == nil || err.Type != AuthErrorToolNotClassified {
			t.Fatalf("undeclared tool: want tool-not-classified, got %v", err)
		}
		if pep.calls != 0 {
			t.Errorf("PEP calls = %d, want 0", pep.calls)
		}
	})

	t.Run("identity-gated skips the PEP", func(t *testing.T) {
		pep := &recordingPEP{allowed: false}
		if _, err := newChecker(pep, legacyCaller()).AuthorizeTool(context.Background(), "module_gated_tool", "tok"); err != nil {
			t.Fatalf("identity-gated with a valid token: want nil error, got %v", err)
		}
		if pep.calls != 0 {
			t.Errorf("PEP calls = %d, want 0", pep.calls)
		}
	})

	t.Run("identity-gated needs an identity", func(t *testing.T) {
		_, err := newChecker(&recordingPEP{allowed: true}, legacyCaller()).AuthorizeTool(context.Background(), "module_gated_tool", "")
		if err == nil || err.Type != AuthErrorMissingToken {
			t.Fatalf("identity-gated without a token: want missing token, got %v", err)
		}
	})

	t.Run("scopes_supported comes from the declaration", func(t *testing.T) {
		got := advertisedScopes(newChecker(nil, nil).toolPermissions)
		if len(got) != 1 || got[0] != scopeForToolPermission("bmc:power") {
			t.Errorf("advertised scopes = %v, want only the scope of bmc:power", got)
		}
	})
}

// fixedPeer is a PeerAuthenticator that admits every verified chain as one
// principal.
type fixedPeer struct {
	authCtx *platformtoken.AuthorizedContext
	calls   int
}

func (p *fixedPeer) AuthenticatePeer(context.Context, []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	p.calls++
	return p.authCtx, nil
}

// TestAuthorizeTool_MalformedDeclarationRefusedBeforeAuth pins #2011 Codex
// r2: a module declaring "bmc" or "bmc:" has no scope, and an empty scope
// passes authentication for any claims or mTLS caller. The declaration is
// refused before the caller is authenticated, and the PEP is never asked.
func TestAuthorizeTool_MalformedDeclarationRefusedBeforeAuth(t *testing.T) {
	module := declaredTools{
		"t1": quicbaas.Permission("bmc"),
		"t2": quicbaas.Permission("bmc:"),
	}
	grant := &platformtoken.AuthorizedContext{
		Subject:  "u",
		TenantID: "t",
		Scopes:   []string{"*", "bmc", "bmc:", "bmc:power", "bmc:read", "bmc:write"},
	}

	for _, tool := range []string{"t1", "t2"} {
		t.Run(tool+" claims token", func(t *testing.T) {
			pep := &recordingPEP{allowed: true}
			mgr := &claimsAuthManagerStub{authCtx: grant}
			c := NewAuthorizationChecker(nil, mgr, WithPEPClient(pep), WithToolPermissions(module))
			_, err := c.AuthorizeTool(context.Background(), tool, "tok")
			if err == nil || err.Type != AuthErrorPermissionDenied {
				t.Fatalf("malformed declaration with a claims token: want permission denied, got %v", err)
			}
			if mgr.calls != 0 {
				t.Errorf("token validator calls = %d, want 0", mgr.calls)
			}
			if pep.calls != 0 {
				t.Errorf("PEP calls = %d, want 0", pep.calls)
			}
		})

		t.Run(tool+" mTLS peer", func(t *testing.T) {
			pep := &recordingPEP{allowed: true}
			peer := &fixedPeer{authCtx: grant}
			c := NewAuthorizationChecker(nil, legacyCaller(), WithPEPClient(pep), WithToolPermissions(module), WithPeerAuthenticator(peer))
			state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{&x509.Certificate{}}}}
			ctx := channelbind.WithConnectionTLS(context.Background(), "mcp", state)
			_, err := c.AuthorizeTool(ctx, tool, "")
			if err == nil || err.Type != AuthErrorPermissionDenied {
				t.Fatalf("malformed declaration with an mTLS peer: want permission denied, got %v", err)
			}
			if peer.calls != 0 {
				t.Errorf("peer authenticator calls = %d, want 0", peer.calls)
			}
			if pep.calls != 0 {
				t.Errorf("PEP calls = %d, want 0", pep.calls)
			}
		})
	}
}
