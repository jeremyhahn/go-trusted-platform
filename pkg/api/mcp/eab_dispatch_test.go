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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Test fixtures
// =============================================================================

// eabStubProvider is a minimal EABProvider that records the last invoked
// method and the arguments seen so tests can assert dispatch & arg-marshal.
type eabStubProvider struct {
	lastCall string
	// Captured args for the last Create/Validate/List/Revoke calls — used
	// to verify that the dispatcher correctly threaded arguments through.
	lastProfileID    uint64
	lastTenantID     string
	lastExpiresIn    int64
	lastHMACKeyLen   int
	lastCredentialID uint64
	lastKeyID        string
	lastHMACKey      string
	lastActiveOnly   bool
	lastStatus       string
	lastPage         uint32
	lastPageSize     uint32
	lastRevokerID    uint64
	lastSize         int
	lastPath         string
}

func (s *eabStubProvider) EABCreateCredential(_ context.Context, profileID uint64, tenantID string, expiresInSeconds int64, hmacKeyLength int) (interface{}, error) {
	s.lastCall = "create"
	s.lastProfileID = profileID
	s.lastTenantID = tenantID
	s.lastExpiresIn = expiresInSeconds
	s.lastHMACKeyLen = hmacKeyLength
	return map[string]interface{}{"id": uint64(42), "key_id": "abc"}, nil
}

func (s *eabStubProvider) EABGetCredential(_ context.Context, credentialID uint64) (interface{}, error) {
	s.lastCall = "get"
	s.lastCredentialID = credentialID
	return map[string]interface{}{"id": credentialID}, nil
}

func (s *eabStubProvider) EABGetCredentialByKeyID(_ context.Context, keyID string) (interface{}, error) {
	s.lastCall = "get_by_key_id"
	s.lastKeyID = keyID
	return map[string]interface{}{"key_id": keyID}, nil
}

func (s *eabStubProvider) EABListCredentials(_ context.Context, params EABListParams) (interface{}, error) {
	s.lastCall = "list"
	s.lastTenantID = params.TenantID
	s.lastProfileID = params.ProfileID
	s.lastActiveOnly = params.ActiveOnly
	s.lastStatus = params.Status
	s.lastPage = params.Page
	s.lastPageSize = params.PageSize
	return map[string]interface{}{"tenant_id": params.TenantID, "credentials": []map[string]interface{}{}}, nil
}

func (s *eabStubProvider) EABRevokeCredential(_ context.Context, credentialID uint64, revokerID uint64) (interface{}, error) {
	s.lastCall = "revoke"
	s.lastCredentialID = credentialID
	s.lastRevokerID = revokerID
	return map[string]interface{}{"credential_id": credentialID, "status": "revoked"}, nil
}

func (s *eabStubProvider) EABValidateCredential(_ context.Context, keyID string, hmacKey string) (interface{}, error) {
	s.lastCall = "validate"
	s.lastKeyID = keyID
	s.lastHMACKey = hmacKey
	return map[string]interface{}{"valid": true}, nil
}

func (s *eabStubProvider) EABDeleteCredential(_ context.Context, credentialID uint64) (interface{}, error) {
	s.lastCall = "delete"
	s.lastCredentialID = credentialID
	return map[string]interface{}{"credential_id": credentialID, "status": "deleted"}, nil
}

func (s *eabStubProvider) EABMarkCredentialUsed(_ context.Context, credentialID uint64) (interface{}, error) {
	s.lastCall = "mark_used"
	s.lastCredentialID = credentialID
	return map[string]interface{}{"credential_id": credentialID, "status": "used"}, nil
}

func (s *eabStubProvider) EABCleanupExpiredCredentials(_ context.Context, tenantID string) (interface{}, error) {
	s.lastCall = "cleanup"
	s.lastTenantID = tenantID
	return map[string]interface{}{"deleted_count": 0, "tenant_id": tenantID}, nil
}

func (s *eabStubProvider) EABGetCredentialQRCode(_ context.Context, credentialID uint64, size int) (interface{}, error) {
	s.lastCall = "qr"
	s.lastCredentialID = credentialID
	s.lastSize = size
	return map[string]interface{}{"credential_id": credentialID, "qr_code": "<base64>"}, nil
}

func (s *eabStubProvider) EABGetEnrollmentURL(_ context.Context, credentialID uint64, path string) (interface{}, error) {
	s.lastCall = "url"
	s.lastCredentialID = credentialID
	s.lastPath = path
	return map[string]interface{}{"credential_id": credentialID, "url": "https://x"}, nil
}

// eabCombinedProvider satisfies both ServiceProvider (via mockServiceProvider)
// and EABProvider (via eabStubProvider). The two types contribute disjoint
// method sets so embedding is collision-free.
type eabCombinedProvider struct {
	*mockServiceProvider
	*eabStubProvider
}

// Compile-time assertions: combined provider satisfies both interfaces.
var (
	_ ServiceProvider = (*eabCombinedProvider)(nil)
	_ EABProvider     = (*eabCombinedProvider)(nil)
)

// =============================================================================
// Tests
// =============================================================================

// TestToolRegistry_ExecuteTool_EAB_RoutesToProvider verifies that the
// ExecuteTool dispatcher routes platform_eab_* tools through the
// optional EABProvider interface and threads arguments correctly.
func TestToolRegistry_ExecuteTool_EAB_RoutesToProvider(t *testing.T) {
	stub := &eabStubProvider{}
	svc := &eabCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		eabStubProvider:     stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name     string
		args     map[string]interface{}
		wantCall string
		// wantArgs, when set, reports whether the arguments the provider
		// received are the ones the tool was called with.
		wantArgs func(s *eabStubProvider) bool
	}{
		{
			name:     "platform_eab_create_credential",
			args:     map[string]interface{}{"profile_id": 7, "tenant_id": "tenant-1", "expires_in_seconds": 3600, "hmac_key_length": 32},
			wantCall: "create",
		},
		{
			name:     "platform_eab_get_credential",
			args:     map[string]interface{}{"credential_id": 42},
			wantCall: "get",
		},
		{
			name:     "platform_eab_get_credential_by_key_id",
			args:     map[string]interface{}{"key_id": "k-abc"},
			wantCall: "get_by_key_id",
			wantArgs: func(s *eabStubProvider) bool { return s.lastKeyID == "k-abc" },
		},
		{
			name:     "platform_eab_list_credentials",
			args:     map[string]interface{}{"tenant_id": "tenant-1", "profile_id": 7, "active_only": true, "status": "active", "page": 2, "page_size": 10},
			wantCall: "list",
			wantArgs: func(s *eabStubProvider) bool {
				return s.lastTenantID == "tenant-1" && s.lastProfileID == 7 && s.lastActiveOnly &&
					s.lastStatus == "active" && s.lastPage == 2 && s.lastPageSize == 10
			},
		},
		{
			name:     "platform_eab_revoke_credential",
			args:     map[string]interface{}{"credential_id": 42, "revoker_id": 99},
			wantCall: "revoke",
			wantArgs: func(s *eabStubProvider) bool { return s.lastCredentialID == 42 && s.lastRevokerID == 99 },
		},
		{
			name:     "platform_eab_validate_credential",
			args:     map[string]interface{}{"key_id": "k-abc", "hmac_key": "AAECAwQF"},
			wantCall: "validate",
			wantArgs: func(s *eabStubProvider) bool { return s.lastKeyID == "k-abc" && s.lastHMACKey == "AAECAwQF" },
		},
		{
			name:     "platform_eab_delete_credential",
			args:     map[string]interface{}{"credential_id": 42},
			wantCall: "delete",
		},
		{
			name:     "platform_eab_mark_credential_used",
			args:     map[string]interface{}{"credential_id": 42},
			wantCall: "mark_used",
		},
		{
			name:     "platform_eab_cleanup_expired_credentials",
			args:     map[string]interface{}{"tenant_id": "tenant-1"},
			wantCall: "cleanup",
		},
		{
			name:     "platform_eab_get_credential_qr_code",
			args:     map[string]interface{}{"credential_id": 42, "size": 256},
			wantCall: "qr",
			wantArgs: func(s *eabStubProvider) bool { return s.lastCredentialID == 42 && s.lastSize == 256 },
		},
		{
			name:     "platform_eab_get_enrollment_url",
			args:     map[string]interface{}{"credential_id": 42, "path": "/enroll"},
			wantCall: "url",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if result == nil {
				t.Errorf("%s: result should not be nil", tc.name)
			}
			if stub.lastCall != tc.wantCall {
				t.Errorf("%s: lastCall = %q, want %q", tc.name, stub.lastCall, tc.wantCall)
			}
			if tc.wantArgs != nil && !tc.wantArgs(stub) {
				t.Errorf("%s: provider received the wrong arguments: %+v", tc.name, stub)
			}
		})
	}

	// Spot-check argument threading for a few representative tools.
	if stub.lastCredentialID != 42 || stub.lastPath != "/enroll" {
		t.Errorf("get_enrollment_url did not thread args: id=%d path=%q", stub.lastCredentialID, stub.lastPath)
	}

	// Re-invoke create explicitly so we can assert all create-specific args.
	if _, err := registry.ExecuteTool(ctx, "platform_eab_create_credential",
		map[string]interface{}{"profile_id": 7, "tenant_id": "tenant-1", "expires_in_seconds": 3600, "hmac_key_length": 64}); err != nil {
		t.Fatalf("create re-invoke failed: %v", err)
	}
	if stub.lastProfileID != 7 || stub.lastTenantID != "tenant-1" || stub.lastExpiresIn != 3600 || stub.lastHMACKeyLen != 64 {
		t.Errorf("create args not threaded correctly: %+v", stub)
	}
}

// TestToolRegistry_ExecuteTool_EAB_NoProvider verifies that EAB tools
// return ErrEABNotConfigured when the ServiceProvider does not also
// satisfy EABProvider.
func TestToolRegistry_ExecuteTool_EAB_NoProvider(t *testing.T) {
	// Plain mockServiceProvider does NOT satisfy EABProvider.
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	eabTools := []string{
		"platform_eab_create_credential",
		"platform_eab_get_credential",
		"platform_eab_get_credential_by_key_id",
		"platform_eab_list_credentials",
		"platform_eab_revoke_credential",
		"platform_eab_validate_credential",
		"platform_eab_delete_credential",
		"platform_eab_mark_credential_used",
		"platform_eab_cleanup_expired_credentials",
		"platform_eab_get_credential_qr_code",
		"platform_eab_get_enrollment_url",
	}
	for _, name := range eabTools {
		t.Run(name, func(t *testing.T) {
			args := map[string]interface{}{
				"credential_id": 1,
				"profile_id":    1,
				"tenant_id":     "t",
				"key_id":        "k",
				"hmac_key":      "AAECAwQF",
			}
			_, err := registry.ExecuteTool(ctx, name, args)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", name)
			}
			if !errors.Is(err, ErrEABNotConfigured) {
				t.Errorf("%s: expected ErrEABNotConfigured, got %v", name, err)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_EAB_ArgValidation verifies that EAB tools
// reject missing required arguments with typed errors.
func TestToolRegistry_ExecuteTool_EAB_ArgValidation(t *testing.T) {
	stub := &eabStubProvider{}
	svc := &eabCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		eabStubProvider:     stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	t.Run("create requires profile_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_create_credential",
			map[string]interface{}{"tenant_id": "t"})
		if !errors.Is(err, ErrEABProfileIDRequired) {
			t.Errorf("expected ErrEABProfileIDRequired, got %v", err)
		}
	})

	t.Run("create requires tenant_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_create_credential",
			map[string]interface{}{"profile_id": 1})
		if !errors.Is(err, ErrEABTenantIDRequired) {
			t.Errorf("expected ErrEABTenantIDRequired, got %v", err)
		}
	})

	t.Run("get requires credential_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_get_credential",
			map[string]interface{}{})
		if !errors.Is(err, ErrEABCredentialIDRequired) {
			t.Errorf("expected ErrEABCredentialIDRequired, got %v", err)
		}
	})

	t.Run("get_by_key_id requires key_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_get_credential_by_key_id",
			map[string]interface{}{})
		if !errors.Is(err, ErrEABKeyIDRequired) {
			t.Errorf("expected ErrEABKeyIDRequired, got %v", err)
		}
	})

	t.Run("list accepts empty tenant_id", func(t *testing.T) {
		// tenant_id is optional for list (empty = all tenants), matching
		// the gRPC ListCredentials filter cascade.
		if _, err := registry.ExecuteTool(ctx, "platform_eab_list_credentials",
			map[string]interface{}{}); err != nil {
			t.Errorf("list with empty tenant_id should succeed, got %v", err)
		}
	})

	t.Run("list threads status and pagination", func(t *testing.T) {
		if _, err := registry.ExecuteTool(ctx, "platform_eab_list_credentials",
			map[string]interface{}{"status": "revoked", "page": 3, "page_size": 25}); err != nil {
			t.Fatalf("list failed: %v", err)
		}
		if stub.lastStatus != "revoked" || stub.lastPage != 3 || stub.lastPageSize != 25 {
			t.Errorf("list params not threaded: status=%q page=%d page_size=%d",
				stub.lastStatus, stub.lastPage, stub.lastPageSize)
		}
	})

	t.Run("uint64 arguments accepted as decimal strings", func(t *testing.T) {
		// The repo-wide uint64-on-the-wire convention sends large IDs as
		// decimal strings; getInt64 must parse them.
		if _, err := registry.ExecuteTool(ctx, "platform_eab_get_credential",
			map[string]interface{}{"credential_id": "18446744073709551615"}); err != nil {
			t.Fatalf("string credential_id rejected: %v", err)
		}
		if stub.lastCredentialID != 18446744073709551615 {
			t.Errorf("string credential_id not parsed: got %d", stub.lastCredentialID)
		}
	})

	t.Run("revoke requires credential_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_revoke_credential",
			map[string]interface{}{})
		if !errors.Is(err, ErrEABCredentialIDRequired) {
			t.Errorf("expected ErrEABCredentialIDRequired, got %v", err)
		}
	})

	t.Run("validate requires key_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_validate_credential",
			map[string]interface{}{"hmac_key": "AAECAwQF"})
		if !errors.Is(err, ErrEABKeyIDRequired) {
			t.Errorf("expected ErrEABKeyIDRequired, got %v", err)
		}
	})

	t.Run("validate requires hmac_key", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_validate_credential",
			map[string]interface{}{"key_id": "k"})
		if !errors.Is(err, ErrEABHMACKeyRequired) {
			t.Errorf("expected ErrEABHMACKeyRequired, got %v", err)
		}
	})

	t.Run("delete requires credential_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_delete_credential",
			map[string]interface{}{})
		if !errors.Is(err, ErrEABCredentialIDRequired) {
			t.Errorf("expected ErrEABCredentialIDRequired, got %v", err)
		}
	})

	t.Run("mark_used requires credential_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_mark_credential_used",
			map[string]interface{}{})
		if !errors.Is(err, ErrEABCredentialIDRequired) {
			t.Errorf("expected ErrEABCredentialIDRequired, got %v", err)
		}
	})

	t.Run("qr requires credential_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_get_credential_qr_code",
			map[string]interface{}{})
		if !errors.Is(err, ErrEABCredentialIDRequired) {
			t.Errorf("expected ErrEABCredentialIDRequired, got %v", err)
		}
	})

	t.Run("url requires credential_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "platform_eab_get_enrollment_url",
			map[string]interface{}{})
		if !errors.Is(err, ErrEABCredentialIDRequired) {
			t.Errorf("expected ErrEABCredentialIDRequired, got %v", err)
		}
	})

	t.Run("cleanup accepts empty tenant_id", func(t *testing.T) {
		// tenant_id is optional for cleanup; ensure no validation error.
		_, err := registry.ExecuteTool(ctx, "platform_eab_cleanup_expired_credentials",
			map[string]interface{}{})
		if err != nil {
			t.Errorf("cleanup with empty tenant_id should succeed, got %v", err)
		}
	})
}

// TestToolRegistry_EABToolsRegistered verifies all platform_eab_* tool
// definitions are registered and listable.
func TestToolRegistry_EABToolsRegistered(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	expected := []string{
		"platform_eab_create_credential",
		"platform_eab_get_credential",
		"platform_eab_get_credential_by_key_id",
		"platform_eab_list_credentials",
		"platform_eab_revoke_credential",
		"platform_eab_validate_credential",
		"platform_eab_delete_credential",
		"platform_eab_mark_credential_used",
		"platform_eab_cleanup_expired_credentials",
		"platform_eab_get_credential_qr_code",
		"platform_eab_get_enrollment_url",
	}
	tools := registry.ListTools()
	got := make(map[string]mcpwire.ToolDefinition, len(tools))
	for _, td := range tools {
		got[td.Name] = td
	}
	for _, name := range expected {
		td, ok := got[name]
		if !ok {
			t.Errorf("missing registered tool: %s", name)
			continue
		}
		if td.Description == "" {
			t.Errorf("%s: empty description", name)
		}
		if td.InputSchema == nil {
			t.Errorf("%s: nil input schema", name)
		}
	}
}

// TestEABProviderHelper_eabProvider verifies the type-assertion helper.
func TestEABProviderHelper_eabProvider(t *testing.T) {
	// Without provider satisfaction, eabProvider() returns nil.
	plain := newMockServiceProvider()
	registry := NewToolRegistry(plain, logging.DefaultLogger())
	if got := registry.eabProvider(); got != nil {
		t.Errorf("expected nil EABProvider, got %v", got)
	}

	// With provider satisfaction, eabProvider() returns the provider.
	combined := &eabCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		eabStubProvider:     &eabStubProvider{},
	}
	registry2 := NewToolRegistry(combined, logging.DefaultLogger())
	if got := registry2.eabProvider(); got == nil {
		t.Error("expected non-nil EABProvider")
	}
}

// TestEABDispatchUnknown verifies dispatchEABTool returns handled=false for
// names that don't belong to the EAB namespace.
func TestEABDispatchUnknown(t *testing.T) {
	stub := &eabStubProvider{}
	svc := &eabCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		eabStubProvider:     stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	result, handled, err := registry.dispatchEABTool(context.Background(), "platform_bmc_power_on", map[string]interface{}{})
	if handled {
		t.Errorf("expected handled=false for non-EAB tool, got handled=true")
	}
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
	if err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
}
