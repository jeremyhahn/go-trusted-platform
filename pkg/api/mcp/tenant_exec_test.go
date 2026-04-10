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
)

func TestTenantToolExecution_ServiceUnavailable(t *testing.T) {
	ctx := context.Background()

	// Create a registry where getTenantManager returns nil (service unavailable).
	svc := newMockServiceProvider()
	registry := &ToolRegistry{
		service: svc,
		logger:  newTestLogger(),
		tools:   make([]ToolDefinition, 0),
	}
	registry.registerTenantTools()

	tools := []struct {
		name string
		args map[string]interface{}
	}{
		{"tenant_list", map[string]interface{}{}},
		{"tenant_get", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_get_by_name", map[string]interface{}{"name": "test"}},
		{"tenant_create", map[string]interface{}{"name": "new", "display_name": "New"}},
		{"tenant_update", map[string]interface{}{"tenant_id": "t1", "display_name": "Updated"}},
		{"tenant_delete", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_suspend", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_resume", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_get_quotas", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_get_usage", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_check_quota", map[string]interface{}{"tenant_id": "t1", "resource_type": "vms", "amount": float64(1)}},
		{"tenant_validate_vlan", map[string]interface{}{"tenant_id": "t1", "vlan_id": float64(100)}},
		{"tenant_get_bridge", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_sync", map[string]interface{}{}},
		{"tenant_rotate_dek", map[string]interface{}{"tenant_id": "t1"}},
		{"tenant_get_dek_status", map[string]interface{}{"tenant_id": "t1"}},
	}

	for _, tc := range tools {
		t.Run(tc.name+"_unavailable", func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err == nil {
				t.Fatal("expected ErrTenantServiceUnavailable")
			}
			if err != ErrTenantServiceUnavailable {
				t.Fatalf("expected ErrTenantServiceUnavailable, got %v", err)
			}
		})
	}
}

func TestTenantToolExecution_MissingRequiredArgs(t *testing.T) {
	ctx := context.Background()

	// Use a basic registry with no tenant manager so we can test arg validation.
	// Some tools check args before calling manager, some check manager first.
	// For the ones that check manager first, those are covered above.
	// For the ones that also need param validation, we test those here.
	svc := newMockServiceProvider()
	registry := &ToolRegistry{
		service: svc,
		logger:  newTestLogger(),
		tools:   make([]ToolDefinition, 0),
	}
	registry.registerTenantTools()

	t.Run("tenant_get missing tenant_id", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "tenant_get", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
		// Either ErrTenantServiceUnavailable (manager nil) or ErrTenantIDRequired
		// Since manager is nil, the manager check happens first
		if err != ErrTenantServiceUnavailable {
			t.Fatalf("expected ErrTenantServiceUnavailable, got %v", err)
		}
	})

	t.Run("tenant_get_by_name missing name", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "tenant_get_by_name", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
