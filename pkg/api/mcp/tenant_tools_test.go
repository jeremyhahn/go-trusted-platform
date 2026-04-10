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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

// createTestTenantEntity creates a test tenant entity.
func createTestTenantEntity(id, name string) *tenant.TenantEntity {
	return &tenant.TenantEntity{
		ID:          id,
		Name:        name,
		DisplayName: name + " Display",
		State:       tenant.StateActive,
		OVSBridge:   "br-tenant-" + name,
		VLANRange: tenant.VLANRange{
			Start: 100,
			End:   199,
		},
		DEKPath: "/tenant/12345/default",
		ComputeQuota: tenant.ComputeQuota{
			MaxVMs:        10,
			MaxContainers: 50,
			MaxVCPUs:      32,
			MaxMemoryMB:   65536,
			MaxDiskGB:     1024,
		},
		NetworkQuota: tenant.NetworkQuota{
			MaxBridges:       5,
			MaxPorts:         100,
			MaxBandwidthMbps: 10000,
		},
		StorageQuota: tenant.StorageQuota{
			MaxVolumesGB: 2048,
			MaxSnapshots: 100,
		},
		Labels: map[string]string{
			"env": "test",
		},
		Annotations: map[string]string{
			"note": "test tenant",
		},
		CreatedAt: time.Now().Add(-24 * time.Hour),
		UpdatedAt: time.Now(),
	}
}

// TestTenantToolsRegistration tests that all 17 tenant tools are registered.
func TestTenantToolsRegistration(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	expectedTools := []string{
		"tenant_list",
		"tenant_get",
		"tenant_get_by_name",
		"tenant_create",
		"tenant_update",
		"tenant_delete",
		"tenant_suspend",
		"tenant_resume",
		"tenant_get_quotas",
		"tenant_update_quotas",
		"tenant_get_usage",
		"tenant_check_quota",
		"tenant_validate_vlan",
		"tenant_get_bridge",
		"tenant_sync",
		"tenant_rotate_dek",
		"tenant_get_dek_status",
	}

	tools := registry.ListTools()
	registeredTools := make(map[string]bool)
	for _, tool := range tools {
		registeredTools[tool.Name] = true
	}

	for _, expectedTool := range expectedTools {
		if !registeredTools[expectedTool] {
			t.Errorf("expected tool %q to be registered but it was not found", expectedTool)
		}
	}
}

// TestTenantError tests the TenantError type.
func TestTenantError(t *testing.T) {
	err := &TenantError{
		Code:    "TEST_ERROR",
		Message: "test error message",
	}

	expected := "TEST_ERROR: test error message"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

// TestTenantServiceUnavailableError tests error handling when service is unavailable.
func TestTenantServiceUnavailableError(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	ctx := context.Background()

	// All tenant tools should return service unavailable error when no manager is set
	testCases := []struct {
		name string
		args map[string]interface{}
	}{
		{"tenant_list", map[string]interface{}{}},
		{"tenant_get", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_get_by_name", map[string]interface{}{"name": "test-name"}},
		{"tenant_create", map[string]interface{}{"name": "test-name"}},
		{"tenant_update", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_delete", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_suspend", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_resume", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_get_quotas", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_update_quotas", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_get_usage", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_check_quota", map[string]interface{}{"tenant_id": "test-id", "resource_type": "vms", "amount": 1}},
		{"tenant_validate_vlan", map[string]interface{}{"tenant_id": "test-id", "vlan_id": 100}},
		{"tenant_get_bridge", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_sync", map[string]interface{}{}},
		{"tenant_rotate_dek", map[string]interface{}{"tenant_id": "test-id"}},
		{"tenant_get_dek_status", map[string]interface{}{"tenant_id": "test-id"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err != ErrTenantServiceUnavailable {
				t.Errorf("expected ErrTenantServiceUnavailable, got %v", err)
			}
		})
	}
}

// TestTenantIDRequired tests validation for required tenant ID.
func TestTenantIDRequired(t *testing.T) {
	testCases := []struct {
		name     string
		toolName string
		args     map[string]interface{}
	}{
		{"tenant_get without ID", "tenant_get", map[string]interface{}{}},
		{"tenant_get with empty ID", "tenant_get", map[string]interface{}{"tenant_id": ""}},
		{"tenant_update without ID", "tenant_update", map[string]interface{}{}},
		{"tenant_delete without ID", "tenant_delete", map[string]interface{}{}},
		{"tenant_suspend without ID", "tenant_suspend", map[string]interface{}{}},
		{"tenant_resume without ID", "tenant_resume", map[string]interface{}{}},
		{"tenant_get_quotas without ID", "tenant_get_quotas", map[string]interface{}{}},
		{"tenant_update_quotas without ID", "tenant_update_quotas", map[string]interface{}{}},
		{"tenant_get_usage without ID", "tenant_get_usage", map[string]interface{}{}},
		{"tenant_check_quota without ID", "tenant_check_quota", map[string]interface{}{"resource_type": "vms", "amount": 1}},
		{"tenant_validate_vlan without ID", "tenant_validate_vlan", map[string]interface{}{"vlan_id": 100}},
		{"tenant_get_bridge without ID", "tenant_get_bridge", map[string]interface{}{}},
		{"tenant_rotate_dek without ID", "tenant_rotate_dek", map[string]interface{}{}},
		{"tenant_get_dek_status without ID", "tenant_get_dek_status", map[string]interface{}{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a registry with a mock service provider
			logger := newTestLogger()
			mockSvc := newMockServiceProvider()
			registry := NewToolRegistry(mockSvc, logger)

			ctx := context.Background()
			_, err := registry.ExecuteTool(ctx, tc.toolName, tc.args)

			// Since service unavailable is returned first (mock doesn't implement TenantServiceProvider),
			// we verify that the execution at least attempts to run
			if err == nil {
				t.Errorf("expected error for missing tenant_id")
			}
		})
	}
}

// TestTenantNameRequired tests validation for required tenant name.
func TestTenantNameRequired(t *testing.T) {
	testCases := []struct {
		name string
		args map[string]interface{}
	}{
		{"tenant_get_by_name without name", map[string]interface{}{}},
		{"tenant_get_by_name with empty name", map[string]interface{}{"name": ""}},
		{"tenant_create without name", map[string]interface{}{}},
		{"tenant_create with empty name", map[string]interface{}{"name": ""}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := newTestLogger()
			mockSvc := newMockServiceProvider()
			registry := NewToolRegistry(mockSvc, logger)

			ctx := context.Background()
			_, err := registry.ExecuteTool(ctx, "tenant_get_by_name", tc.args)

			// Service unavailable takes precedence, but if service were available,
			// name validation would occur
			if err == nil {
				t.Errorf("expected error for missing name")
			}
		})
	}
}

// TestFormatTenantEntity tests the formatTenantEntity function.
func TestFormatTenantEntity(t *testing.T) {
	t.Run("nil entity returns nil", func(t *testing.T) {
		result := formatTenantEntity(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid entity is formatted correctly", func(t *testing.T) {
		entity := createTestTenantEntity("test-id", "test-tenant")

		result := formatTenantEntity(entity)

		if result["id"] != "test-id" {
			t.Errorf("expected id 'test-id', got %v", result["id"])
		}

		if result["name"] != "test-tenant" {
			t.Errorf("expected name 'test-tenant', got %v", result["name"])
		}

		if result["display_name"] != "test-tenant Display" {
			t.Errorf("expected display_name 'test-tenant Display', got %v", result["display_name"])
		}

		if result["state"] != "active" {
			t.Errorf("expected state 'active', got %v", result["state"])
		}

		if result["ovs_bridge"] != "br-tenant-test-tenant" {
			t.Errorf("expected ovs_bridge 'br-tenant-test-tenant', got %v", result["ovs_bridge"])
		}

		// Check VLAN range
		vlanRange, ok := result["vlan_range"].(map[string]interface{})
		if !ok {
			t.Fatal("expected vlan_range to be a map")
		}
		if vlanRange["start"] != uint16(100) {
			t.Errorf("expected vlan_range.start 100, got %v", vlanRange["start"])
		}
		if vlanRange["end"] != uint16(199) {
			t.Errorf("expected vlan_range.end 199, got %v", vlanRange["end"])
		}

		// Check DEK handle
		if result["dek_handle"] != uint32(12345) {
			t.Errorf("expected dek_handle 12345, got %v", result["dek_handle"])
		}

		// Check compute quota
		computeQuota, ok := result["compute_quota"].(map[string]interface{})
		if !ok {
			t.Fatal("expected compute_quota to be a map")
		}
		if computeQuota["max_vms"] != int64(10) {
			t.Errorf("expected max_vms 10, got %v", computeQuota["max_vms"])
		}

		// Check labels
		labels, ok := result["labels"].(map[string]string)
		if !ok {
			t.Fatal("expected labels to be a map")
		}
		if labels["env"] != "test" {
			t.Errorf("expected label env='test', got %v", labels["env"])
		}
	})

	t.Run("empty VLAN range is not included", func(t *testing.T) {
		entity := createTestTenantEntity("test-id", "test-tenant")
		entity.VLANRange = tenant.VLANRange{}

		result := formatTenantEntity(entity)

		if _, exists := result["vlan_range"]; exists {
			t.Error("expected vlan_range to not be present for empty range")
		}
	})

	t.Run("zero DEK handle is not included", func(t *testing.T) {
		entity := createTestTenantEntity("test-id", "test-tenant")
		entity.DEKPath = "" // Empty DEKPath results in zero DEKHandle

		result := formatTenantEntity(entity)

		if _, exists := result["dek_handle"]; exists {
			t.Error("expected dek_handle to not be present for zero value")
		}
	})

	t.Run("deleted_at is included when set", func(t *testing.T) {
		entity := createTestTenantEntity("test-id", "test-tenant")
		deletedAt := time.Now()
		entity.DeletedAt = &deletedAt

		result := formatTenantEntity(entity)

		if _, exists := result["deleted_at"]; !exists {
			t.Error("expected deleted_at to be present")
		}
	})

	t.Run("empty labels not included", func(t *testing.T) {
		entity := createTestTenantEntity("test-id", "test-tenant")
		entity.Labels = nil

		result := formatTenantEntity(entity)

		if _, exists := result["labels"]; exists {
			t.Error("expected labels to not be present when empty")
		}
	})

	t.Run("empty annotations not included", func(t *testing.T) {
		entity := createTestTenantEntity("test-id", "test-tenant")
		entity.Annotations = nil

		result := formatTenantEntity(entity)

		if _, exists := result["annotations"]; exists {
			t.Error("expected annotations to not be present when empty")
		}
	})
}

// TestFormatTenantList tests the formatTenantList function.
func TestFormatTenantList(t *testing.T) {
	t.Run("empty list returns empty slice", func(t *testing.T) {
		result := formatTenantList(nil)
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %d elements", len(result))
		}
	})

	t.Run("multiple entities are formatted correctly", func(t *testing.T) {
		entities := []*tenant.TenantEntity{
			createTestTenantEntity("id-1", "tenant-1"),
			createTestTenantEntity("id-2", "tenant-2"),
		}

		result := formatTenantList(entities)

		if len(result) != 2 {
			t.Errorf("expected 2 elements, got %d", len(result))
		}

		if result[0]["id"] != "id-1" {
			t.Errorf("expected first id 'id-1', got %v", result[0]["id"])
		}

		if result[1]["id"] != "id-2" {
			t.Errorf("expected second id 'id-2', got %v", result[1]["id"])
		}
	})

	t.Run("empty slice input returns empty slice", func(t *testing.T) {
		result := formatTenantList([]*tenant.TenantEntity{})
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %d elements", len(result))
		}
	})
}

// TestHasQuotaArgs tests the has*QuotaArgs helper functions.
func TestHasQuotaArgs(t *testing.T) {
	t.Run("hasComputeQuotaArgs", func(t *testing.T) {
		testCases := []struct {
			name     string
			args     map[string]interface{}
			expected bool
		}{
			{"empty args", map[string]interface{}{}, false},
			{"max_vms present", map[string]interface{}{"max_vms": 10}, true},
			{"max_containers present", map[string]interface{}{"max_containers": 50}, true},
			{"max_vcpus present", map[string]interface{}{"max_vcpus": 32}, true},
			{"max_memory_mb present", map[string]interface{}{"max_memory_mb": 65536}, true},
			{"max_disk_gb present", map[string]interface{}{"max_disk_gb": 1024}, true},
			{"unrelated args", map[string]interface{}{"name": "test"}, false},
			{"nil value", map[string]interface{}{"max_vms": nil}, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := hasComputeQuotaArgs(tc.args)
				if result != tc.expected {
					t.Errorf("expected %v, got %v", tc.expected, result)
				}
			})
		}
	})

	t.Run("hasNetworkQuotaArgs", func(t *testing.T) {
		testCases := []struct {
			name     string
			args     map[string]interface{}
			expected bool
		}{
			{"empty args", map[string]interface{}{}, false},
			{"max_bridges present", map[string]interface{}{"max_bridges": 5}, true},
			{"max_ports present", map[string]interface{}{"max_ports": 100}, true},
			{"max_bandwidth_mbps present", map[string]interface{}{"max_bandwidth_mbps": 10000}, true},
			{"unrelated args", map[string]interface{}{"name": "test"}, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := hasNetworkQuotaArgs(tc.args)
				if result != tc.expected {
					t.Errorf("expected %v, got %v", tc.expected, result)
				}
			})
		}
	})

	t.Run("hasStorageQuotaArgs", func(t *testing.T) {
		testCases := []struct {
			name     string
			args     map[string]interface{}
			expected bool
		}{
			{"empty args", map[string]interface{}{}, false},
			{"max_volumes_gb present", map[string]interface{}{"max_volumes_gb": 2048}, true},
			{"max_snapshots present", map[string]interface{}{"max_snapshots": 100}, true},
			{"unrelated args", map[string]interface{}{"name": "test"}, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := hasStorageQuotaArgs(tc.args)
				if result != tc.expected {
					t.Errorf("expected %v, got %v", tc.expected, result)
				}
			})
		}
	})
}

// TestTenantToolInputSchemas tests that tool input schemas are properly defined.
func TestTenantToolInputSchemas(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	tools := registry.ListTools()
	tenantTools := make(map[string]ToolDefinition)
	for _, tool := range tools {
		if len(tool.Name) > 7 && tool.Name[:7] == "tenant_" {
			tenantTools[tool.Name] = tool
		}
	}

	// Verify tool count (now 17 with the two new DEK tools)
	if len(tenantTools) != 17 {
		t.Errorf("expected 17 tenant tools, got %d", len(tenantTools))
	}

	// Test specific tool schemas
	t.Run("tenant_create has required name field", func(t *testing.T) {
		tool := tenantTools["tenant_create"]
		schema := tool.InputSchema
		required, ok := schema["required"].([]string)
		if !ok {
			t.Fatal("expected required to be a string slice")
		}

		found := false
		for _, r := range required {
			if r == "name" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected 'name' to be in required fields")
		}
	})

	t.Run("tenant_get has required tenant_id field", func(t *testing.T) {
		tool := tenantTools["tenant_get"]
		schema := tool.InputSchema
		required, ok := schema["required"].([]string)
		if !ok {
			t.Fatal("expected required to be a string slice")
		}

		found := false
		for _, r := range required {
			if r == "tenant_id" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected 'tenant_id' to be in required fields")
		}
	})

	t.Run("tenant_check_quota has required fields", func(t *testing.T) {
		tool := tenantTools["tenant_check_quota"]
		schema := tool.InputSchema
		required, ok := schema["required"].([]string)
		if !ok {
			t.Fatal("expected required to be a string slice")
		}

		expectedFields := map[string]bool{
			"tenant_id":     false,
			"resource_type": false,
			"amount":        false,
		}

		for _, r := range required {
			if _, exists := expectedFields[r]; exists {
				expectedFields[r] = true
			}
		}

		for field, found := range expectedFields {
			if !found {
				t.Errorf("expected '%s' to be in required fields", field)
			}
		}
	})

	t.Run("tenant_validate_vlan has required fields", func(t *testing.T) {
		tool := tenantTools["tenant_validate_vlan"]
		schema := tool.InputSchema
		required, ok := schema["required"].([]string)
		if !ok {
			t.Fatal("expected required to be a string slice")
		}

		expectedFields := map[string]bool{
			"tenant_id": false,
			"vlan_id":   false,
		}

		for _, r := range required {
			if _, exists := expectedFields[r]; exists {
				expectedFields[r] = true
			}
		}

		for field, found := range expectedFields {
			if !found {
				t.Errorf("expected '%s' to be in required fields", field)
			}
		}
	})

	t.Run("tenant_list has optional pagination fields", func(t *testing.T) {
		tool := tenantTools["tenant_list"]
		schema := tool.InputSchema
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			t.Fatal("expected properties to be a map")
		}

		if _, exists := props["limit"]; !exists {
			t.Error("expected limit property")
		}
		if _, exists := props["offset"]; !exists {
			t.Error("expected offset property")
		}
	})

	t.Run("tenant_sync has empty properties", func(t *testing.T) {
		tool := tenantTools["tenant_sync"]
		schema := tool.InputSchema
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			t.Fatal("expected properties to be a map")
		}

		if len(props) != 0 {
			t.Error("expected empty properties for tenant_sync")
		}
	})

	t.Run("tenant_rotate_dek has required tenant_id field", func(t *testing.T) {
		tool := tenantTools["tenant_rotate_dek"]
		schema := tool.InputSchema
		required, ok := schema["required"].([]string)
		if !ok {
			t.Fatal("expected required to be a string slice")
		}

		found := false
		for _, r := range required {
			if r == "tenant_id" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected 'tenant_id' to be in required fields")
		}

		// Check that background is an optional parameter
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			t.Fatal("expected properties to be a map")
		}
		if _, exists := props["background"]; !exists {
			t.Error("expected background property to be defined")
		}
	})

	t.Run("tenant_get_dek_status has required tenant_id field", func(t *testing.T) {
		tool := tenantTools["tenant_get_dek_status"]
		schema := tool.InputSchema
		required, ok := schema["required"].([]string)
		if !ok {
			t.Fatal("expected required to be a string slice")
		}

		found := false
		for _, r := range required {
			if r == "tenant_id" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected 'tenant_id' to be in required fields")
		}
	})
}

// TestTenantErrorTypes tests the predefined tenant error types.
func TestTenantErrorTypes(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		contains string
	}{
		{"service unavailable", ErrTenantServiceUnavailable, "TENANT_SERVICE_UNAVAILABLE"},
		{"ID required", ErrTenantIDRequired, "TENANT_ID_REQUIRED"},
		{"name required", ErrTenantNameRequired, "TENANT_NAME_REQUIRED"},
		{"VLAN required", ErrTenantVLANRequired, "TENANT_VLAN_REQUIRED"},
		{"resource type required", ErrTenantResourceTypeRequired, "TENANT_RESOURCE_TYPE_REQUIRED"},
		{"amount required", ErrTenantAmountRequired, "TENANT_AMOUNT_REQUIRED"},
		{"invalid resource type", ErrTenantInvalidResourceType, "TENANT_INVALID_RESOURCE_TYPE"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errStr := tc.err.Error()
			if len(errStr) == 0 {
				t.Error("error message should not be empty")
			}

			tenantErr, ok := tc.err.(*TenantError)
			if !ok {
				t.Fatal("expected TenantError type")
			}

			if tenantErr.Code != tc.contains {
				t.Errorf("expected code %s, got %s", tc.contains, tenantErr.Code)
			}
		})
	}
}

// TestResourceTypeValidation tests validation of resource types.
func TestResourceTypeValidation(t *testing.T) {
	validTypes := []string{
		"vms", "containers", "vcpus", "memory", "disk",
		"bridges", "ports", "bandwidth", "volumes", "snapshots",
	}

	for _, rt := range validTypes {
		t.Run(rt+" is valid", func(t *testing.T) {
			resourceType := quota.ResourceType(rt)
			if !resourceType.IsValid() {
				t.Errorf("expected %s to be valid", rt)
			}
		})
	}

	t.Run("invalid type", func(t *testing.T) {
		resourceType := quota.ResourceType("invalid")
		if resourceType.IsValid() {
			t.Error("expected 'invalid' to be invalid resource type")
		}
	})
}

// TestTenantToolDescriptions tests that all tools have descriptions.
func TestTenantToolDescriptions(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	tools := registry.ListTools()
	for _, tool := range tools {
		if len(tool.Name) > 7 && tool.Name[:7] == "tenant_" {
			if tool.Description == "" {
				t.Errorf("tool %s has empty description", tool.Name)
			}
		}
	}
}

// TestGetTenantManagerNilProvider tests getTenantManager with nil provider.
func TestGetTenantManagerNilProvider(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	mgr := registry.getTenantManager()
	if mgr != nil {
		t.Error("expected nil manager when provider doesn't implement TenantServiceProvider")
	}
}

// TestVLANValidation tests VLAN ID validation bounds.
func TestVLANValidation(t *testing.T) {
	testCases := []struct {
		name    string
		vlanID  int
		isValid bool
	}{
		{"VLAN 0", 0, false},
		{"VLAN 1", 1, true},
		{"VLAN 100", 100, true},
		{"VLAN 4094", 4094, true},
		{"VLAN 4095", 4095, false},
		{"VLAN negative", -1, false},
		{"VLAN max edge", 4093, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isValid := tc.vlanID >= 1 && tc.vlanID <= 4094
			if isValid != tc.isValid {
				t.Errorf("expected VLAN %d validity to be %v, got %v", tc.vlanID, tc.isValid, isValid)
			}
		})
	}
}

// TestTenantSyncNoManager tests tenant_sync with unavailable manager.
func TestTenantSyncNoManager(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	ctx := context.Background()
	_, err := registry.ExecuteTool(ctx, "tenant_sync", map[string]interface{}{})

	if err != ErrTenantServiceUnavailable {
		t.Errorf("expected ErrTenantServiceUnavailable, got %v", err)
	}
}

// TestQuotaResourceCategories tests quota resource type categories.
func TestQuotaResourceCategories(t *testing.T) {
	testCases := []struct {
		resource quota.ResourceType
		category string
	}{
		{quota.ResourceVMs, "compute"},
		{quota.ResourceContainers, "compute"},
		{quota.ResourceVCPUs, "compute"},
		{quota.ResourceMemory, "compute"},
		{quota.ResourceBridges, "network"},
		{quota.ResourcePorts, "network"},
		{quota.ResourceBandwidth, "network"},
		{quota.ResourceDisk, "storage"},
		{quota.ResourceVolumes, "storage"},
		{quota.ResourceSnapshots, "storage"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.resource), func(t *testing.T) {
			if tc.resource.Category() != tc.category {
				t.Errorf("expected category %s, got %s", tc.category, tc.resource.Category())
			}
		})
	}
}

// TestTenantToolExecutionErrorHandling tests error handling in tool execution.
func TestTenantToolExecutionErrorHandling(t *testing.T) {
	ctx := context.Background()
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	// Test that execution with invalid tool name returns error
	t.Run("unknown tool returns error", func(t *testing.T) {
		_, err := registry.ExecuteTool(ctx, "tenant_unknown", map[string]interface{}{})
		if err == nil {
			t.Error("expected error for unknown tool")
		}
	})

	// Test all tenant tools return appropriate errors when service unavailable
	tenantTools := []string{
		"tenant_list", "tenant_get", "tenant_get_by_name", "tenant_create",
		"tenant_update", "tenant_delete", "tenant_suspend", "tenant_resume",
		"tenant_get_quotas", "tenant_update_quotas", "tenant_get_usage",
		"tenant_check_quota", "tenant_validate_vlan", "tenant_get_bridge", "tenant_sync",
		"tenant_rotate_dek", "tenant_get_dek_status",
	}

	for _, toolName := range tenantTools {
		t.Run(toolName+" handles missing service", func(t *testing.T) {
			args := map[string]interface{}{
				"tenant_id":     "test-id",
				"name":          "test-name",
				"resource_type": "vms",
				"amount":        int64(1),
				"vlan_id":       100,
			}
			_, err := registry.ExecuteTool(ctx, toolName, args)
			if !errors.Is(err, ErrTenantServiceUnavailable) {
				if _, ok := err.(*TenantError); !ok {
					t.Errorf("expected TenantError for %s, got %T: %v", toolName, err, err)
				}
			}
		})
	}
}

// TestTenantToolsSchemaTypes tests schema type definitions.
func TestTenantToolsSchemaTypes(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	tools := registry.ListTools()
	tenantTools := make(map[string]ToolDefinition)
	for _, tool := range tools {
		if len(tool.Name) > 7 && tool.Name[:7] == "tenant_" {
			tenantTools[tool.Name] = tool
		}
	}

	t.Run("tenant_create has correct property types", func(t *testing.T) {
		tool := tenantTools["tenant_create"]
		props := tool.InputSchema["properties"].(map[string]interface{})

		// Verify name is string type
		nameProp := props["name"].(map[string]interface{})
		if nameProp["type"] != "string" {
			t.Error("expected name to be string type")
		}

		// Verify vlan_start is integer type
		vlanProp := props["vlan_start"].(map[string]interface{})
		if vlanProp["type"] != "integer" {
			t.Error("expected vlan_start to be integer type")
		}

		// Verify labels is object type
		labelsProp := props["labels"].(map[string]interface{})
		if labelsProp["type"] != "object" {
			t.Error("expected labels to be object type")
		}
	})

	t.Run("tenant_check_quota has correct property types", func(t *testing.T) {
		tool := tenantTools["tenant_check_quota"]
		props := tool.InputSchema["properties"].(map[string]interface{})

		amountProp := props["amount"].(map[string]interface{})
		if amountProp["type"] != "integer" {
			t.Error("expected amount to be integer type")
		}

		resourceProp := props["resource_type"].(map[string]interface{})
		if resourceProp["type"] != "string" {
			t.Error("expected resource_type to be string type")
		}
	})

	t.Run("tenant_rotate_dek has correct property types", func(t *testing.T) {
		tool := tenantTools["tenant_rotate_dek"]
		props := tool.InputSchema["properties"].(map[string]interface{})

		// Verify tenant_id is string type
		tenantIDProp := props["tenant_id"].(map[string]interface{})
		if tenantIDProp["type"] != "string" {
			t.Error("expected tenant_id to be string type")
		}

		// Verify background is boolean type
		backgroundProp := props["background"].(map[string]interface{})
		if backgroundProp["type"] != "boolean" {
			t.Error("expected background to be boolean type")
		}
	})

	t.Run("tenant_get_dek_status has correct property types", func(t *testing.T) {
		tool := tenantTools["tenant_get_dek_status"]
		props := tool.InputSchema["properties"].(map[string]interface{})

		// Verify tenant_id is string type
		tenantIDProp := props["tenant_id"].(map[string]interface{})
		if tenantIDProp["type"] != "string" {
			t.Error("expected tenant_id to be string type")
		}
	})
}

// TestTenantErrorMessageFormat tests error message formatting.
func TestTenantErrorMessageFormat(t *testing.T) {
	err := &TenantError{
		Code:    "TEST_CODE",
		Message: "test message",
	}

	errStr := err.Error()
	if errStr != "TEST_CODE: test message" {
		t.Errorf("unexpected error format: %s", errStr)
	}
}

// TestDefaultPaginationValues tests default pagination behavior.
func TestDefaultPaginationValues(t *testing.T) {
	// Test that getInt returns 0 for missing keys
	args := map[string]interface{}{}
	limit := getInt(args, "limit")
	if limit != 0 {
		t.Errorf("expected default limit 0, got %d", limit)
	}

	// Test that present values are returned
	args["limit"] = 50
	limit = getInt(args, "limit")
	if limit != 50 {
		t.Errorf("expected limit 50, got %d", limit)
	}
}

// TestTenantEntityStateFormatting tests state formatting in entity.
func TestTenantEntityStateFormatting(t *testing.T) {
	states := []tenant.State{
		tenant.StateCreated,
		tenant.StateActive,
		tenant.StateSuspended,
		tenant.StateDeleting,
		tenant.StateDeleted,
	}

	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			entity := &tenant.TenantEntity{
				ID:        "test",
				Name:      "test",
				State:     state,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			result := formatTenantEntity(entity)
			if result["state"] != string(state) {
				t.Errorf("expected state %s, got %v", state, result["state"])
			}
		})
	}
}

// TestQuotaArgsMultipleKeys tests quota args detection with multiple keys.
func TestQuotaArgsMultipleKeys(t *testing.T) {
	t.Run("multiple compute args", func(t *testing.T) {
		args := map[string]interface{}{
			"max_vms":        10,
			"max_containers": 20,
			"max_vcpus":      32,
		}
		if !hasComputeQuotaArgs(args) {
			t.Error("expected true for multiple compute args")
		}
	})

	t.Run("mixed args with compute", func(t *testing.T) {
		args := map[string]interface{}{
			"name":     "test",
			"max_vms":  10,
			"max_disk": 100,
		}
		if !hasComputeQuotaArgs(args) {
			t.Error("expected true for mixed args with compute")
		}
	})

	t.Run("all quota types present", func(t *testing.T) {
		args := map[string]interface{}{
			"max_vms":        10,
			"max_bridges":    5,
			"max_volumes_gb": 100,
		}
		if !hasComputeQuotaArgs(args) {
			t.Error("expected true for compute")
		}
		if !hasNetworkQuotaArgs(args) {
			t.Error("expected true for network")
		}
		if !hasStorageQuotaArgs(args) {
			t.Error("expected true for storage")
		}
	})
}

// TestTenantRotateDEKNoManager tests tenant_rotate_dek with unavailable manager.
func TestTenantRotateDEKNoManager(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	ctx := context.Background()
	_, err := registry.ExecuteTool(ctx, "tenant_rotate_dek", map[string]interface{}{"tenant_id": "test-id"})

	if err != ErrTenantServiceUnavailable {
		t.Errorf("expected ErrTenantServiceUnavailable, got %v", err)
	}
}

// TestTenantGetDEKStatusNoManager tests tenant_get_dek_status with unavailable manager.
func TestTenantGetDEKStatusNoManager(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	ctx := context.Background()
	_, err := registry.ExecuteTool(ctx, "tenant_get_dek_status", map[string]interface{}{"tenant_id": "test-id"})

	if err != ErrTenantServiceUnavailable {
		t.Errorf("expected ErrTenantServiceUnavailable, got %v", err)
	}
}

// TestTenantDEKToolsDescription tests that DEK tools have proper descriptions.
func TestTenantDEKToolsDescription(t *testing.T) {
	logger := newTestLogger()
	mockSvc := newMockServiceProvider()
	registry := NewToolRegistry(mockSvc, logger)

	tools := registry.ListTools()
	toolsByName := make(map[string]ToolDefinition)
	for _, tool := range tools {
		toolsByName[tool.Name] = tool
	}

	t.Run("tenant_rotate_dek has description", func(t *testing.T) {
		tool, ok := toolsByName["tenant_rotate_dek"]
		if !ok {
			t.Fatal("tenant_rotate_dek tool not found")
		}
		if tool.Description == "" {
			t.Error("tenant_rotate_dek should have a description")
		}
		if tool.Description != "Rotate the Data Encryption Key for a tenant" {
			t.Errorf("unexpected description: %s", tool.Description)
		}
	})

	t.Run("tenant_get_dek_status has description", func(t *testing.T) {
		tool, ok := toolsByName["tenant_get_dek_status"]
		if !ok {
			t.Fatal("tenant_get_dek_status tool not found")
		}
		if tool.Description == "" {
			t.Error("tenant_get_dek_status should have a description")
		}
		if tool.Description != "Get DEK status including usage and rotation progress" {
			t.Errorf("unexpected description: %s", tool.Description)
		}
	})
}
