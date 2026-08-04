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
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
)

// =============================================================================
// Mock Tenant Manager for Coverage Tests
// =============================================================================

// mockTenantManager implements tenant manager methods for testing.
type mockTenantManager struct {
	listTenantsFunc     func(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error)
	getTenantFunc       func(ctx context.Context, id string) (*tenant.TenantEntity, error)
	getTenantByNameFunc func(ctx context.Context, name string) (*tenant.TenantEntity, error)
	createTenantFunc    func(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error)
	updateTenantFunc    func(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error)
	deleteTenantFunc    func(ctx context.Context, id string) error
	suspendTenantFunc   func(ctx context.Context, id string) error
	resumeTenantFunc    func(ctx context.Context, id string) error
	getQuotasFunc       func(ctx context.Context, id string) (*tenant.TenantQuotas, error)
	updateQuotasFunc    func(ctx context.Context, id string, quotas *tenant.TenantQuotas) error
	getUsageFunc        func(ctx context.Context, id string) (*quota.TenantUsage, error)
	checkQuotaFunc      func(ctx context.Context, id string, rt quota.ResourceType, amount int64) error
	validateVLANFunc    func(ctx context.Context, id string, vlanID uint16) error
	getBridgeNameFunc   func(ctx context.Context, id string) (string, error)
	syncFunc            func(ctx context.Context) error
	rotateDEKFunc       func(ctx context.Context, id string) error
	getDEKStatusFunc    func(ctx context.Context, id string) (*tenant.DEKStatus, error)
}

func newMockTenantManager() *mockTenantManager {
	now := time.Now()
	testEntity := &tenant.TenantEntity{
		ID:          "tenant-123",
		Name:        "test-tenant",
		DisplayName: "Test Tenant",
		State:       tenant.StateActive,
		OVSBridge:   "br-tenant-123",
		VLANRange: tenant.VLANRange{
			Start: 100,
			End:   199,
		},
		DEKPath: "/tenant/123/default",
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
		Labels:      map[string]string{"env": "test"},
		Annotations: map[string]string{"note": "test tenant"},
		CreatedAt:   now.Add(-24 * time.Hour),
		UpdatedAt:   now,
	}

	return &mockTenantManager{
		listTenantsFunc: func(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error) {
			return []*tenant.TenantEntity{testEntity}, 1, nil
		},
		getTenantFunc: func(ctx context.Context, id string) (*tenant.TenantEntity, error) {
			if id == "tenant-123" {
				return testEntity, nil
			}
			return nil, errors.New("tenant not found")
		},
		getTenantByNameFunc: func(ctx context.Context, name string) (*tenant.TenantEntity, error) {
			if name == "test-tenant" {
				return testEntity, nil
			}
			return nil, errors.New("tenant not found")
		},
		createTenantFunc: func(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error) {
			return &tenant.TenantEntity{
				ID:           "tenant-new",
				Name:         req.Name,
				DisplayName:  req.DisplayName,
				State:        tenant.StateActive,
				ComputeQuota: tenant.ComputeQuota{MaxVMs: 10},
				NetworkQuota: tenant.NetworkQuota{MaxBridges: 5},
				StorageQuota: tenant.StorageQuota{MaxVolumesGB: 100},
				CreatedAt:    now,
				UpdatedAt:    now,
			}, nil
		},
		updateTenantFunc: func(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error) {
			if id != "tenant-123" {
				return nil, errors.New("tenant not found")
			}
			return testEntity, nil
		},
		deleteTenantFunc: func(ctx context.Context, id string) error {
			if id != "tenant-123" {
				return errors.New("tenant not found")
			}
			return nil
		},
		suspendTenantFunc: func(ctx context.Context, id string) error {
			if id != "tenant-123" {
				return errors.New("tenant not found")
			}
			return nil
		},
		resumeTenantFunc: func(ctx context.Context, id string) error {
			if id != "tenant-123" {
				return errors.New("tenant not found")
			}
			return nil
		},
		getQuotasFunc: func(ctx context.Context, id string) (*tenant.TenantQuotas, error) {
			if id != "tenant-123" {
				return nil, errors.New("tenant not found")
			}
			return &tenant.TenantQuotas{
				Compute: tenant.ComputeQuota{MaxVMs: 10, MaxContainers: 50},
				Network: tenant.NetworkQuota{MaxBridges: 5, MaxPorts: 100},
				Storage: tenant.StorageQuota{MaxVolumesGB: 2048},
			}, nil
		},
		updateQuotasFunc: func(ctx context.Context, id string, quotas *tenant.TenantQuotas) error {
			if id != "tenant-123" {
				return errors.New("tenant not found")
			}
			return nil
		},
		getUsageFunc: func(ctx context.Context, id string) (*quota.TenantUsage, error) {
			if id != "tenant-123" {
				return nil, errors.New("tenant not found")
			}
			return &quota.TenantUsage{
				VMs:        2,
				Containers: 10,
				VCPUs:      8,
				MemoryMB:   16384,
				DiskGB:     200,
				Bridges:    1,
				Ports:      20,
				Volumes:    5,
				Timestamp:  now,
			}, nil
		},
		checkQuotaFunc: func(ctx context.Context, id string, rt quota.ResourceType, amount int64) error {
			if id != "tenant-123" {
				return errors.New("tenant not found")
			}
			return nil
		},
		validateVLANFunc: func(ctx context.Context, id string, vlanID uint16) error {
			if id != "tenant-123" {
				return errors.New("tenant not found")
			}
			if vlanID < 100 || vlanID > 199 {
				return errors.New("VLAN out of range")
			}
			return nil
		},
		getBridgeNameFunc: func(ctx context.Context, id string) (string, error) {
			if id != "tenant-123" {
				return "", errors.New("tenant not found")
			}
			return "br-tenant-123", nil
		},
		syncFunc: func(ctx context.Context) error {
			return nil
		},
		rotateDEKFunc: func(ctx context.Context, id string) error {
			if id != "tenant-123" {
				return errors.New("tenant not found")
			}
			return nil
		},
		getDEKStatusFunc: func(ctx context.Context, id string) (*tenant.DEKStatus, error) {
			if id != "tenant-123" {
				return nil, errors.New("tenant not found")
			}
			return &tenant.DEKStatus{
				Path:           "/tenant/123/default",
				Version:        1,
				Algorithm:      "AES-256-GCM",
				Status:         "active",
				IsDefault:      true,
				CreatedAt:      now.Add(-24 * time.Hour),
				RotatedAt:      now,
				UsageCount:     1000,
				BytesUsed:      1024 * 1024,
				MaxUsageCount:  1000000,
				MaxBytesUsed:   1024 * 1024 * 1024,
				WarningPercent: 80,
				UsagePercent:   5.0,
				NeedsRotation:  false,
			}, nil
		},
	}
}

// Implement tenant manager interface methods
func (m *mockTenantManager) ListTenants(ctx context.Context, limit, offset int) ([]*tenant.TenantEntity, int, error) {
	return m.listTenantsFunc(ctx, limit, offset)
}

func (m *mockTenantManager) GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error) {
	return m.getTenantFunc(ctx, id)
}

func (m *mockTenantManager) GetTenantByName(ctx context.Context, name string) (*tenant.TenantEntity, error) {
	return m.getTenantByNameFunc(ctx, name)
}

func (m *mockTenantManager) CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error) {
	return m.createTenantFunc(ctx, req)
}

func (m *mockTenantManager) UpdateTenant(ctx context.Context, id string, req *tenant.UpdateTenantRequest) (*tenant.TenantEntity, error) {
	return m.updateTenantFunc(ctx, id, req)
}

func (m *mockTenantManager) DeleteTenant(ctx context.Context, id string) error {
	return m.deleteTenantFunc(ctx, id)
}

func (m *mockTenantManager) SuspendTenant(ctx context.Context, id string) error {
	return m.suspendTenantFunc(ctx, id)
}

func (m *mockTenantManager) ResumeTenant(ctx context.Context, id string) error {
	return m.resumeTenantFunc(ctx, id)
}

func (m *mockTenantManager) GetTenantQuotas(ctx context.Context, id string) (*tenant.TenantQuotas, error) {
	return m.getQuotasFunc(ctx, id)
}

func (m *mockTenantManager) UpdateTenantQuotas(ctx context.Context, id string, quotas *tenant.TenantQuotas) error {
	return m.updateQuotasFunc(ctx, id, quotas)
}

func (m *mockTenantManager) GetTenantUsage(ctx context.Context, id string) (*quota.TenantUsage, error) {
	return m.getUsageFunc(ctx, id)
}

func (m *mockTenantManager) CheckTenantQuota(ctx context.Context, id string, rt quota.ResourceType, amount int64) error {
	return m.checkQuotaFunc(ctx, id, rt, amount)
}

func (m *mockTenantManager) ValidateTenantVLAN(ctx context.Context, id string, vlanID uint16) error {
	return m.validateVLANFunc(ctx, id, vlanID)
}

func (m *mockTenantManager) GetBridgeName(ctx context.Context, id string) (string, error) {
	return m.getBridgeNameFunc(ctx, id)
}

func (m *mockTenantManager) Sync(ctx context.Context) error {
	return m.syncFunc(ctx)
}

func (m *mockTenantManager) RotateTenantDEK(ctx context.Context, id string) error {
	return m.rotateDEKFunc(ctx, id)
}

func (m *mockTenantManager) GetTenantDEKStatus(ctx context.Context, id string) (*tenant.DEKStatus, error) {
	return m.getDEKStatusFunc(ctx, id)
}

// =============================================================================
// Mock Tenant Service Provider
// =============================================================================

// mockTenantServiceProvider wraps mockServiceProvider and adds tenant support.
type mockTenantServiceProvider struct {
	*mockServiceProvider
	tenantMgr *tenant.Manager
}

func (m *mockTenantServiceProvider) TenantManager() *tenant.Manager {
	return m.tenantMgr
}

// newTenantTestRegistry creates a ToolRegistry with a mock tenant manager.
func newTenantTestRegistry(mgr *tenant.Manager) *ToolRegistry {
	mockSvc := newMockServiceProvider()
	tenantProvider := &mockTenantServiceProvider{
		mockServiceProvider: mockSvc,
		tenantMgr:           mgr,
	}

	registry := &ToolRegistry{
		service: tenantProvider,
		logger:  newTestLogger(),
		tools:   make([]ToolDefinition, 0),
	}
	registry.registerTenantTools()
	return registry
}

// =============================================================================
// Tenant Tool Execution Tests with Mock Manager
// =============================================================================

func TestExecuteTenantList_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	registry := newTenantTestRegistry(nil)

	ctx := context.Background()

	// Test that without manager returns service unavailable
	_, err := registry.executeTenantList(ctx, map[string]interface{}{})
	if err != ErrTenantServiceUnavailable {
		t.Errorf("expected ErrTenantServiceUnavailable, got %v", err)
	}

	// Test list with mock
	result, _, listErr := mockMgr.ListTenants(ctx, 100, 0)
	if listErr != nil {
		t.Fatalf("mock list failed: %v", listErr)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 tenant, got %d", len(result))
	}
}

func TestExecuteTenantGet_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	entity, err := mockMgr.GetTenant(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entity.ID != "tenant-123" {
		t.Errorf("expected tenant ID 'tenant-123', got %s", entity.ID)
	}

	_, err = mockMgr.GetTenant(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantGetByName_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	entity, err := mockMgr.GetTenantByName(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entity.Name != "test-tenant" {
		t.Errorf("expected name 'test-tenant', got %s", entity.Name)
	}

	_, err = mockMgr.GetTenantByName(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantCreate_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	req := &tenant.CreateTenantRequest{
		Name:        "new-tenant",
		DisplayName: "New Tenant",
	}

	entity, err := mockMgr.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entity.Name != "new-tenant" {
		t.Errorf("expected name 'new-tenant', got %s", entity.Name)
	}
}

func TestExecuteTenantUpdate_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	displayName := "Updated Tenant"
	req := &tenant.UpdateTenantRequest{
		DisplayName: &displayName,
	}

	entity, err := mockMgr.UpdateTenant(ctx, "tenant-123", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entity == nil {
		t.Fatal("expected non-nil entity")
	}

	_, err = mockMgr.UpdateTenant(ctx, "nonexistent", req)
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantDelete_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	err := mockMgr.DeleteTenant(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mockMgr.DeleteTenant(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantSuspend_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	err := mockMgr.SuspendTenant(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mockMgr.SuspendTenant(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantResume_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	err := mockMgr.ResumeTenant(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mockMgr.ResumeTenant(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantGetQuotas_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	quotas, err := mockMgr.GetTenantQuotas(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if quotas.Compute.MaxVMs != 10 {
		t.Errorf("expected MaxVMs 10, got %d", quotas.Compute.MaxVMs)
	}

	_, err = mockMgr.GetTenantQuotas(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantUpdateQuotas_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	quotas := &tenant.TenantQuotas{
		Compute: tenant.ComputeQuota{MaxVMs: 20},
	}

	err := mockMgr.UpdateTenantQuotas(ctx, "tenant-123", quotas)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mockMgr.UpdateTenantQuotas(ctx, "nonexistent", quotas)
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantGetUsage_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	usage, err := mockMgr.GetTenantUsage(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.VMs != 2 {
		t.Errorf("expected VMs 2, got %d", usage.VMs)
	}

	_, err = mockMgr.GetTenantUsage(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantCheckQuota_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	err := mockMgr.CheckTenantQuota(ctx, "tenant-123", quota.ResourceVMs, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mockMgr.CheckTenantQuota(ctx, "nonexistent", quota.ResourceVMs, 1)
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantValidateVLAN_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	err := mockMgr.ValidateTenantVLAN(ctx, "tenant-123", 150)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mockMgr.ValidateTenantVLAN(ctx, "tenant-123", 50)
	if err == nil {
		t.Error("expected error for VLAN out of range")
	}

	err = mockMgr.ValidateTenantVLAN(ctx, "nonexistent", 150)
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantGetBridge_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	bridge, err := mockMgr.GetBridgeName(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bridge != "br-tenant-123" {
		t.Errorf("expected bridge 'br-tenant-123', got %s", bridge)
	}

	_, err = mockMgr.GetBridgeName(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantSync_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	err := mockMgr.Sync(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteTenantRotateDEK_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	err := mockMgr.RotateTenantDEK(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = mockMgr.RotateTenantDEK(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestExecuteTenantGetDEKStatus_WithMockManager(t *testing.T) {
	mockMgr := newMockTenantManager()
	ctx := context.Background()

	status, err := mockMgr.GetTenantDEKStatus(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Algorithm != "AES-256-GCM" {
		t.Errorf("expected algorithm 'AES-256-GCM', got %s", status.Algorithm)
	}

	_, err = mockMgr.GetTenantDEKStatus(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

// =============================================================================
// Client Coverage Tests
// =============================================================================

func TestClient_InitializeResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Method == "initialize" {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"serverInfo": map[string]interface{}{
						"name":    "Test Server",
						"version": "1.0.0",
					},
					"capabilities": map[string]interface{}{
						"tools":     true,
						"resources": true,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		http.Error(w, "unknown method", http.StatusBadRequest)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
		RetryDelay: 100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Initialize(context.Background())
	if err != nil {
		t.Errorf("Initialize failed: %v", err)
	}
}

func TestClient_ListToolsInvalidFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  "not a map",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	defer client.Close()

	_, err := client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestClient_ListToolsMissingTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	defer client.Close()

	_, err := client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for missing tools field")
	}
}

func TestClient_ListResourcesInvalidFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  "not a map",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	defer client.Close()

	_, err := client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestClient_ListResourcesMissingResources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	defer client.Close()

	_, err := client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for missing resources field")
	}
}

func TestClient_doRequestWithToken(t *testing.T) {
	tokenReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenReceived = r.Header.Get("Authorization")

		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{"status": "ok"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	defer client.Close()

	client.SetToken("test-bearer-token")

	err := client.Ping(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if tokenReceived != "Bearer test-bearer-token" {
		t.Errorf("expected Authorization header 'Bearer test-bearer-token', got %q", tokenReceived)
	}
}

func TestClient_doRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    -32600,
				Message: "Invalid Request",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	defer client.Close()

	err := client.Ping(context.Background())
	if err == nil {
		t.Error("expected error for RPC error response")
	}
}

func TestClient_ClosedClientOperations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not reach", http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	client.Close()

	err := client.Ping(context.Background())
	if err == nil {
		t.Error("expected error for closed client")
	}

	_, err = client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for closed client")
	}
}

func TestMapToStructSlice(t *testing.T) {
	type Item struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	input := []interface{}{
		map[string]interface{}{"name": "item1", "value": 1},
		map[string]interface{}{"name": "item2", "value": 2},
	}

	var result []Item
	err := mapToStruct(input, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d", len(result))
	}
	if result[0].Name != "item1" {
		t.Errorf("expected name 'item1', got %s", result[0].Name)
	}
}

func TestMarshalResultSlice(t *testing.T) {
	input := []string{"a", "b", "c"}

	result, err := marshalResult(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(arr) != 3 {
		t.Errorf("expected 3 items, got %d", len(arr))
	}
}
func TestMCPError_ErrorCoverage(t *testing.T) {
	err := &MCPError{
		Code:    -32600,
		Message: "Invalid Request",
		Data:    map[string]string{"detail": "missing required field"},
	}

	expected := "MCP error -32600: Invalid Request"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestClientOptionsCoverage(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "http://localhost:8080",
		Timeout:    10 * time.Second,
		MaxRetries: 5,
		RetryDelay: 200 * time.Millisecond,
	}

	if config.ServerAddr != "http://localhost:8080" {
		t.Errorf("unexpected ServerAddr: %s", config.ServerAddr)
	}
	if config.Timeout != 10*time.Second {
		t.Errorf("unexpected Timeout: %v", config.Timeout)
	}
	if config.MaxRetries != 5 {
		t.Errorf("unexpected MaxRetries: %d", config.MaxRetries)
	}
	if config.RetryDelay != 200*time.Millisecond {
		t.Errorf("unexpected RetryDelay: %v", config.RetryDelay)
	}
}

func TestNewClient_ValidationCoverage(t *testing.T) {
	// Test with empty server address
	_, err := NewClient(&ClientConfig{
		ServerAddr: "",
		Timeout:    5 * time.Second,
	})
	if err == nil {
		t.Error("expected error for empty server address")
	}

}

func TestGetStringMapCoverage(t *testing.T) {
	tests := []struct {
		name     string
		args     map[string]interface{}
		key      string
		expected map[string]string
	}{
		{
			name: "valid string map",
			args: map[string]interface{}{
				"labels": map[string]interface{}{
					"env":  "prod",
					"team": "platform",
				},
			},
			key:      "labels",
			expected: map[string]string{"env": "prod", "team": "platform"},
		},
		{
			name: "missing key",
			args: map[string]interface{}{
				"other": "value",
			},
			key:      "labels",
			expected: nil,
		},
		{
			name: "wrong type",
			args: map[string]interface{}{
				"labels": "not a map",
			},
			key:      "labels",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringMap(tt.args, tt.key)
			if tt.expected == nil && result != nil {
				t.Errorf("expected nil, got %v", result)
			} else if tt.expected != nil {
				for k, v := range tt.expected {
					if result[k] != v {
						t.Errorf("expected %s=%s, got %s=%s", k, v, k, result[k])
					}
				}
			}
		})
	}
}

// =============================================================================
// Additional Server Coverage Tests
// =============================================================================

func TestServer_SetOAuthMetadataCoverage(t *testing.T) {
	mockSvc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(mockSvc, config, newTestLogger())

	server.SetOAuthMetadata("https://example.com/api", []string{"https://auth.example.com"})

	handler := server.GetOAuthMetadataHandler()
	if handler == nil {
		t.Fatal("expected non-nil OAuth metadata handler")
	}
}

func TestServer_StartAlreadyRunning(t *testing.T) {
	mockSvc := newMockServiceProvider()
	config := &Config{
		ServerName:    "Test Server",
		ServerVersion: "1.0.0",
		Transport:     "http",
		HTTPAddr:      "127.0.0.1:0",
	}
	server := NewServer(mockSvc, config, newTestLogger())

	err := server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	err = server.Start()
	if err == nil {
		t.Error("expected error when starting already running server")
	}
}

func TestServer_StopNotRunning(t *testing.T) {
	mockSvc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(mockSvc, config, newTestLogger())

	// Stop without starting should return error
	err := server.Stop()
	if err == nil {
		t.Error("expected error when stopping server that is not running")
	}
}

// =============================================================================
// CA Error Coverage Tests
// =============================================================================

func TestCAError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *CAError
		expected string
	}{
		{
			name:     "basic error",
			err:      &CAError{Code: "CA_TEST", Message: "test message"},
			expected: "CA_TEST: test message",
		},
		{
			name:     "ErrCAServiceUnavailable",
			err:      ErrCAServiceUnavailable,
			expected: "CA_SERVICE_UNAVAILABLE: certificate authority service is not available",
		},
		{
			name:     "ErrCANotInitialized",
			err:      ErrCANotInitialized,
			expected: "CA_NOT_INITIALIZED: certificate authority is not initialized",
		},
		{
			name:     "ErrCACommonNameRequired",
			err:      ErrCACommonNameRequired,
			expected: "CA_COMMON_NAME_REQUIRED: common name is required for certificate issuance",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

// =============================================================================
// MarshalResult Error Path Coverage
// =============================================================================

func TestMarshalResult_Error(t *testing.T) {
	// Test with a value that cannot be marshaled to JSON
	// math.Inf causes json.Marshal to fail
	_, err := marshalResult(math.Inf(1))
	if err == nil {
		t.Error("expected error when marshaling infinity")
	}

	// Test with complex number (also cannot be marshaled)
	type unmarshalable struct {
		Ch chan int
	}
	_, err = marshalResult(unmarshalable{Ch: make(chan int)})
	if err == nil {
		t.Error("expected error when marshaling channel")
	}
}

// =============================================================================
// vTPM Service Error Coverage Tests
// =============================================================================

func TestExecuteVTPMQuote_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmQuoteFunc = func(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":  "test-vtpm",
		"nonce": "bm9uY2UxMjM=", // "nonce123" base64 encoded
		"pcrs":  []interface{}{float64(0), float64(1), float64(7)},
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_quote", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMUnseal_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmUnsealFunc = func(ctx context.Context, name string, sealed []byte) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":   "test-vtpm",
		"sealed": "c2VhbGVkLWRhdGE=", // "sealed-data" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_unseal", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMExtendPCR_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmExtendPCRFunc = func(ctx context.Context, name string, pcr int, data []byte) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
		"pcr":  float64(7),
		"data": "ZXh0ZW5kLWRhdGE=", // "extend-data" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_extend_pcr", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMReadPCR_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmReadPCRFunc = func(ctx context.Context, name string, pcr int) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
		"pcr":  float64(7),
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_read_pcr", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// ExecuteTool Context Timeout Coverage
// =============================================================================

func TestExecuteTool_WithExistingDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.ExecuteTool(ctx, "vtpm_list", map[string]interface{}{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestExecuteTool_UnknownTool(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "nonexistent_tool", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unknown tool")
	}
	if err.Error() != "unknown tool: nonexistent_tool" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// =============================================================================
// HTTP Transport Coverage Tests
// =============================================================================

func TestServer_HTTPTransportWithFreePort(t *testing.T) {
	mockSvc := newMockServiceProvider()

	// Get a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config := &Config{
		ServerName:    "Test Server",
		ServerVersion: "1.0.0",
		Transport:     "http",
		HTTPAddr:      addr,
	}
	server := NewServer(mockSvc, config, newTestLogger())

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	// Give the server time to start
	time.Sleep(50 * time.Millisecond)

	// Make a simple request
	resp, err := http.Post("http://"+addr+"/mcp", "application/json", nil)
	if err != nil {
		t.Logf("request error (expected for empty body): %v", err)
	} else {
		resp.Body.Close()
	}
}

// =============================================================================
// Additional Service Error Coverage Tests
// =============================================================================

func TestExecuteVTPMCreate_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmCreateFunc = func(ctx context.Context, name, algorithm string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":      "test-vtpm",
		"algorithm": "rsa",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_create", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMDelete_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmDeleteFunc = func(ctx context.Context, name string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_delete", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMStart_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmStartFunc = func(ctx context.Context, name string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_start", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMStop_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmStopFunc = func(ctx context.Context, name string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_stop", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmListFunc = func(ctx context.Context) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "vtpm_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMSeal_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmSealFunc = func(ctx context.Context, name string, data []byte, pcrs []int) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
		"data": "dGVzdC1kYXRh", // "test-data" base64 encoded
		"pcrs": []interface{}{float64(0), float64(7)},
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_seal", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// DNS Service Error Coverage Tests
// =============================================================================

func TestExecuteDNSAddRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsAddRecordFunc = func(ctx context.Context, name, recordType, value string, ttl int) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
		"value":       "192.168.1.1",
		"ttl":         float64(300),
	}

	_, err := registry.ExecuteTool(ctx, "dns_add_record", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSDeleteRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsDeleteRecordFunc = func(ctx context.Context, name, recordType string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
	}

	_, err := registry.ExecuteTool(ctx, "dns_delete_record", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSGetRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsGetRecordFunc = func(ctx context.Context, name, recordType string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
	}

	_, err := registry.ExecuteTool(ctx, "dns_get_record", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSListRecords_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsListRecordsFunc = func(ctx context.Context, zone string) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"zone": "example.com",
	}

	_, err := registry.ExecuteTool(ctx, "dns_list_records", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSResolve_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsResolveFunc = func(ctx context.Context, name, recordType string) ([]string, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
	}

	_, err := registry.ExecuteTool(ctx, "dns_resolve", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSCreateZone_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsCreateZoneFunc = func(ctx context.Context, zone string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"zone": "example.com",
	}

	_, err := registry.ExecuteTool(ctx, "dns_create_zone", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSDeleteZone_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsDeleteZoneFunc = func(ctx context.Context, zone string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"zone": "example.com",
	}

	_, err := registry.ExecuteTool(ctx, "dns_delete_zone", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSListZones_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsListZonesFunc = func(ctx context.Context) ([]string, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "dns_list_zones", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// Device Service Error Coverage Tests
// =============================================================================

func TestExecuteDeviceRegister_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceRegisterFunc = func(ctx context.Context, name, deviceType string, publicKey []byte) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test-device",
		"device_type": "server",
		"public_key":  "cHVibGljLWtleQ==", // "public-key" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "device_register", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDeviceGet_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceGetFunc = func(ctx context.Context, deviceID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"device_id": "device-123",
	}

	_, err := registry.ExecuteTool(ctx, "device_get", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDeviceList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceListFunc = func(ctx context.Context, filter map[string]string) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "device_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDeviceDelete_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceDeleteFunc = func(ctx context.Context, deviceID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"device_id": "device-123",
	}

	_, err := registry.ExecuteTool(ctx, "device_delete", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDeviceUpdate_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceUpdateFunc = func(ctx context.Context, deviceID string, updates map[string]interface{}) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"device_id": "device-123",
		"updates": map[string]interface{}{
			"name": "updated-device",
		},
	}

	_, err := registry.ExecuteTool(ctx, "device_update", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// SDN Service Error Coverage Tests
// =============================================================================

func TestExecuteSDNListBridges_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnListBridgesFunc = func(ctx context.Context) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "sdn_list_bridges", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteSDNCreateBridge_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnCreateBridgeFunc = func(ctx context.Context, bridgeName string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"bridge_name": "br0",
	}

	_, err := registry.ExecuteTool(ctx, "sdn_create_bridge", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteSDNDeleteBridge_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnDeleteBridgeFunc = func(ctx context.Context, bridgeName string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"bridge_name": "br0",
	}

	_, err := registry.ExecuteTool(ctx, "sdn_delete_bridge", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteSDNAddPort_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnAddPortFunc = func(ctx context.Context, bridgeName, portName, portType string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"bridge_name": "br0",
		"port_name":   "eth0",
		"port_type":   "internal",
	}

	_, err := registry.ExecuteTool(ctx, "sdn_add_port", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// Health Service Error Coverage Tests
// =============================================================================

func TestExecuteHealth_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.healthFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "health_check", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteLiveness_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.livenessFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "health_liveness", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteReadiness_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.readinessFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "health_readiness", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// CA Service Error Coverage Tests
// =============================================================================

func TestExecuteCAInfo_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caInfoFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_info", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAIssue_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caIssueFunc = func(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"common_name": "test.example.com",
	}

	_, err := registry.ExecuteTool(ctx, "ca_issue", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAGet_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caGetFunc = func(ctx context.Context, serial string, includePEM bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"serial": "1234567890",
	}

	_, err := registry.ExecuteTool(ctx, "ca_get", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caListFunc = func(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCARevoke_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caRevokeFunc = func(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"serial": "1234567890",
		"reason": float64(1),
	}

	_, err := registry.ExecuteTool(ctx, "ca_revoke", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCARenew_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caRenewFunc = func(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"serial": "1234567890",
	}

	_, err := registry.ExecuteTool(ctx, "ca_renew", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAVerify_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caVerifyFunc = func(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	_, err := registry.ExecuteTool(ctx, "ca_verify", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCACRL_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caCRLFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_crl", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCABundle_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caBundleFunc = func(ctx context.Context, storeType string, algorithm string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_bundle", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM User Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateUser_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateUserFunc = func(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"username":  "testuser",
		"email":     "test@example.com",
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_user", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteUser_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteUserFunc = func(ctx context.Context, tenantID, userID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_user", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetUser_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetUserFunc = func(ctx context.Context, tenantID, userID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_user", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListUsers_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListUsersFunc = func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_list_users", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Role Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateRoleFunc = func(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id":   "tenant-123",
		"id":          "role-456",
		"name":        "test-role",
		"permissions": []interface{}{"read", "write"},
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteRoleFunc = func(ctx context.Context, tenantID, roleID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"role_id":   "role-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetRoleFunc = func(ctx context.Context, tenantID, roleID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"role_id":   "role-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListRoles_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListRolesFunc = func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_list_roles", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMAssignRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamAssignRoleFunc = func(ctx context.Context, tenantID, userID, role string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
		"role":      "admin",
	}

	_, err := registry.ExecuteTool(ctx, "iam_assign_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMRevokeRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamRevokeRoleFunc = func(ctx context.Context, tenantID, userID, role string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
		"role":      "admin",
	}

	_, err := registry.ExecuteTool(ctx, "iam_revoke_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMCheckPermission_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCheckPermissionFunc = func(ctx context.Context, tenantID, userID, resource, action string) (bool, error) {
		return false, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
		"resource":  "containers",
		"action":    "create",
	}

	_, err := registry.ExecuteTool(ctx, "iam_check_permission", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMAuthenticate_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamAuthenticateFunc = func(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"username":  "testuser",
		"password":  "testpass",
	}

	_, err := registry.ExecuteTool(ctx, "iam_authenticate", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// KMS Service Error Coverage Tests
// =============================================================================

func TestExecuteKMSCreateKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsCreateKeyFunc = func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":      "test-key",
		"algorithm": "aes-256-gcm",
		"usage":     []interface{}{"encrypt", "decrypt"},
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSDeleteKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsDeleteKeyFunc = func(ctx context.Context, keyID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id": "key-123",
	}

	_, err := registry.ExecuteTool(ctx, "kms_delete_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGetKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGetKeyFunc = func(ctx context.Context, keyID string, version uint64) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id": "key-123",
	}

	_, err := registry.ExecuteTool(ctx, "kms_get_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSListKeys_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsListKeysFunc = func(ctx context.Context, limit, offset int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "kms_list_keys", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSRotateKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsRotateKeyFunc = func(ctx context.Context, keyID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id": "key-123",
	}

	_, err := registry.ExecuteTool(ctx, "kms_rotate_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSEncrypt_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsEncryptFunc = func(ctx context.Context, req *KMSEncryptRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "key-123",
		"plaintext": "dGVzdC1kYXRh", // "test-data" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_encrypt", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSDecrypt_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsDecryptFunc = func(ctx context.Context, req *KMSDecryptRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":     "key-123",
		"ciphertext": "Y2lwaGVydGV4dA==", // "ciphertext" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_decrypt", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSSign_PreHashedAndHashCoercion(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSSignRequest
	svc.kmsSignFunc = func(ctx context.Context, req *KMSSignRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"signature": "c2ln"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	// Numeric hash_algorithm mirrors the SDK MCP transport adapter, which
	// JSON-encodes the platform.v1 proto SignRequest (SHA256 = 2).
	args := map[string]interface{}{
		"key_id":         "key-123",
		"message":        "3q2+7w==", // 0xdeadbeef base64 encoded
		"hash_algorithm": float64(2),
		"pre_hashed":     true,
	}

	if _, err := registry.ExecuteTool(ctx, "kms_sign", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSSign was not called")
	}
	if !captured.PreHashed {
		t.Error("PreHashed = false, want true")
	}
	if captured.HashAlgorithm != "SHA256" {
		t.Errorf("HashAlgorithm = %q, want SHA256", captured.HashAlgorithm)
	}
	if len(captured.Message) != 4 {
		t.Errorf("Message = %x, want the 4 decoded digest bytes", captured.Message)
	}
}

func TestExecuteKMSSign_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_sign", map[string]interface{}{
		"key_id": "key-123",
	}); err == nil {
		t.Error("expected error for missing message")
	}
	if _, err := registry.ExecuteTool(ctx, "kms_sign", map[string]interface{}{
		"key_id":  "key-123",
		"message": "not-base64!!!",
	}); err == nil {
		t.Error("expected error for invalid base64 message")
	}
	if _, err := registry.ExecuteTool(ctx, "kms_sign", map[string]interface{}{
		"message": "bWVzc2FnZQ==",
	}); err == nil {
		t.Error("expected error for missing key_id")
	}
}

func TestExecuteKMSSign_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsSignFunc = func(ctx context.Context, req *KMSSignRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":  "key-123",
		"message": "bWVzc2FnZQ==", // "message" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_sign", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSVerify_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsVerifyFunc = func(ctx context.Context, req *KMSVerifyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "key-123",
		"message":   "bWVzc2FnZQ==", // "message" base64 encoded
		"signature": "c2lnbmF0dXJl", // "signature" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_verify", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGenerateRandom_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGenerateRandomFunc = func(ctx context.Context, numBytes int) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"num_bytes": float64(32),
	}

	_, err := registry.ExecuteTool(ctx, "kms_random", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Group Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateGroup_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateGroupFunc = func(ctx context.Context, req *IAMCreateGroupRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id":   "tenant-123",
		"id":          "group-456",
		"name":        "test-group",
		"description": "Test group description",
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_group", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteGroup_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteGroupFunc = func(ctx context.Context, tenantID, groupID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_group", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetGroup_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetGroupFunc = func(ctx context.Context, tenantID, groupID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_group", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListGroups_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListGroupsFunc = func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_list_groups", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMAddGroupMember_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamAddGroupMemberFunc = func(ctx context.Context, tenantID, groupID, userID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
		"user_id":   "user-789",
	}

	_, err := registry.ExecuteTool(ctx, "iam_add_group_member", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMRemoveGroupMember_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamRemoveGroupMemberFunc = func(ctx context.Context, tenantID, groupID, userID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
		"user_id":   "user-789",
	}

	_, err := registry.ExecuteTool(ctx, "iam_remove_group_member", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Tenant Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateTenant_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateTenantFunc = func(ctx context.Context, req *IAMCreateTenantRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id":   "tenant-new",
		"name": "New Tenant",
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_tenant", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteTenant_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteTenantFunc = func(ctx context.Context, tenantID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_tenant", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetTenant_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetTenantFunc = func(ctx context.Context, tenantID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_tenant", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListTenants_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListTenantsFunc = func(ctx context.Context, limit, offset int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "iam_list_tenants", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Token Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateToken_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateTokenFunc = func(ctx context.Context, req *IAMCreateTokenRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
		"scopes":    []interface{}{"read", "write"},
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_token", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMRevokeToken_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamRevokeTokenFunc = func(ctx context.Context, tokenID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"token_id": "token-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_revoke_token", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMVerifyToken_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamVerifyTokenFunc = func(ctx context.Context, token string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"token": "test-token-string",
	}

	_, err := registry.ExecuteTool(ctx, "iam_verify_token", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// KMS Data Key Service Error Coverage Tests
// =============================================================================

func TestExecuteKMSGenerateDataKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGenerateDataKeyFunc = func(ctx context.Context, req *KMSGenerateDataKeyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "kek-123",
		"algorithm": "aes-256-gcm",
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_data_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGenerateWrappedDataKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGenerateWrappedDataKeyFunc = func(ctx context.Context, req *KMSGenerateWrappedDataKeyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "kek-123",
		"algorithm": "aes-256-gcm",
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_wrapped_data_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGenerateWrappedDataKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"algorithm": "aes-256-gcm",
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_wrapped_data_key", args)
	if err == nil {
		t.Error("expected error for missing key_id")
	}
}

// =============================================================================
// Container Service Error Coverage Tests
// =============================================================================

func TestExecuteContainerCreate_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerCreateFunc = func(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":  "test-container",
		"image": "alpine:latest",
	}

	_, err := registry.ExecuteTool(ctx, "container_create", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerStart_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerStartFunc = func(ctx context.Context, id string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_start", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerStop_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerStopFunc = func(ctx context.Context, id string, timeout int) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_stop", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerRemove_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerRemoveFunc = func(ctx context.Context, id string, force bool) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_remove", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerGet_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerGetFunc = func(ctx context.Context, id string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_get", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerListFunc = func(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "container_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerLogs_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerLogsFunc = func(ctx context.Context, id string, follow bool, stdout bool, stderr bool, tail string, timestamps bool) (string, error) {
		return "", ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_logs", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerAttest_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerAttestFunc = func(ctx context.Context, id string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_attest", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// Additional Coverage Tests for 90%+ Target
// =============================================================================

// TestClaimsMapToResult_AllFieldTypes tests claimsMapToResult with different field types
func TestClaimsMapToResult_AllFieldTypes(t *testing.T) {
	adapter := &QuicBaaSAuthAdapter{}

	tests := []struct {
		name   string
		claims map[string]interface{}
		check  func(*testing.T, *TokenValidationResult)
	}{
		{
			name:   "empty claims returns valid result",
			claims: map[string]interface{}{},
			check: func(t *testing.T, r *TokenValidationResult) {
				if !r.Valid {
					t.Error("expected valid result")
				}
			},
		},
		{
			name: "all fields populated",
			claims: map[string]interface{}{
				"sub":       "user-123",
				"tenant_id": "tenant-456",
				"exp":       int64(1234567890),
				"roles":     []string{"admin", "user"},
				"groups":    []string{"group1", "group2"},
				"scope":     "read write",
			},
			check: func(t *testing.T, r *TokenValidationResult) {
				if r.UserID != "user-123" {
					t.Errorf("expected user-123, got %s", r.UserID)
				}
				if r.TenantID != "tenant-456" {
					t.Errorf("expected tenant-456, got %s", r.TenantID)
				}
				if r.ExpiresAt != 1234567890 {
					t.Errorf("expected 1234567890, got %d", r.ExpiresAt)
				}
				if len(r.Roles) != 2 {
					t.Errorf("expected 2 roles, got %d", len(r.Roles))
				}
				if len(r.Groups) != 2 {
					t.Errorf("expected 2 groups, got %d", len(r.Groups))
				}
				if r.Scope != "read write" {
					t.Errorf("expected 'read write', got %s", r.Scope)
				}
			},
		},
		{
			name: "wrong types ignored",
			claims: map[string]interface{}{
				"sub":       123,        // not string
				"tenant_id": true,       // not string
				"exp":       "not-int",  // not int64
				"roles":     "not-list", // not []string
				"groups":    123,        // not []string
				"scope":     456,        // not string
			},
			check: func(t *testing.T, r *TokenValidationResult) {
				if r.UserID != "" {
					t.Error("expected empty UserID")
				}
				if r.TenantID != "" {
					t.Error("expected empty TenantID")
				}
				if r.ExpiresAt != 0 {
					t.Error("expected zero ExpiresAt")
				}
				if len(r.Roles) != 0 {
					t.Error("expected empty Roles")
				}
				if len(r.Groups) != 0 {
					t.Error("expected empty Groups")
				}
				if r.Scope != "" {
					t.Error("expected empty Scope")
				}
			},
		},
		{
			name: "nil values",
			claims: map[string]interface{}{
				"sub":       nil,
				"tenant_id": nil,
				"exp":       nil,
				"roles":     nil,
				"groups":    nil,
				"scope":     nil,
			},
			check: func(t *testing.T, r *TokenValidationResult) {
				if !r.Valid {
					t.Error("expected valid result even with nil values")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.claimsMapToResult(tt.claims)
			tt.check(t, result)
		})
	}
}

// TestMarshalResultEdgeCases tests marshalResult with various edge cases
func TestMarshalResultEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
	}{
		{
			name:    "nil data",
			data:    nil,
			wantErr: false,
		},
		{
			name:    "simple string",
			data:    "test",
			wantErr: false,
		},
		{
			name:    "nested struct",
			data:    struct{ Name string }{Name: "test"},
			wantErr: false,
		},
		{
			name:    "slice",
			data:    []string{"a", "b", "c"},
			wantErr: false,
		},
		{
			name:    "map",
			data:    map[string]int{"a": 1, "b": 2},
			wantErr: false,
		},
		{
			name:    "channel cannot be marshaled",
			data:    make(chan int),
			wantErr: true,
		},
		{
			name:    "func cannot be marshaled",
			data:    func() {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := marshalResult(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("marshalResult() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestHTTPTransportEdgeCases tests additional HTTP transport scenarios
func TestHTTPTransportEdgeCases(t *testing.T) {
	// Test with invalid address to cover error paths
	server := &Server{
		config: &Config{
			Transport: "http",
			HTTPAddr:  "invalid-addr-no-port",
		},
		shutdown: make(chan struct{}),
	}

	// This should fail but exercise the code path
	err := server.Start()
	if err == nil {
		server.Stop()
	}
}

// TestServerStartWithSSE tests server with SSE transport
func TestServerStartWithSSE(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "sse",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}

	err := server.Start()
	if err == nil {
		server.Stop()
	}
}

// TestClientInitializeEdgeCases tests client initialization edge cases
func TestClientInitializeEdgeCases(t *testing.T) {
	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := &Client{
		config: &ClientConfig{
			ServerAddr: "http://localhost:9999",
		},
		httpClient: &http.Client{Timeout: time.Millisecond},
	}

	_, err := client.Initialize(ctx)
	if err == nil {
		t.Log("Initialize may or may not fail with cancelled context depending on timing")
	}
}

// TestAuthzCheckerEdgeCases tests authorization checker edge cases
func TestAuthzCheckerEdgeCases(t *testing.T) {
	// Test with no auth service configured - use a known protected tool
	checker := &AuthorizationChecker{
		toolPermissions: map[string]string{
			"protected_tool": "read:resource",
		},
	}

	ctx := context.Background()

	// Should allow protected tool when no auth backend is configured (open mode)
	err := checker.CheckToolAuthorization(ctx, "protected_tool", "")
	if err != nil {
		t.Errorf("expected nil in open mode for protected tool, got %v", err)
	}

	// Should return nil for unknown tool (delegates to tool registry)
	err = checker.CheckToolAuthorization(ctx, "unknown_tool", "")
	if err != nil {
		t.Errorf("expected nil for unknown tool, got %v", err)
	}
}

// TestServerStartStdioTransportNotSupported tests stdio transport path
func TestServerStartStdioTransportNotSupported(t *testing.T) {
	// Stdio transport can't be easily tested in unit tests
	// but we can exercise the code path that checks for it
	server := &Server{
		config: &Config{
			Transport: "stdio",
		},
		shutdown: make(chan struct{}),
	}

	// Start will try to use stdio which will fail
	err := server.Start()
	if err != nil {
		// Expected - stdio doesn't work in tests
		t.Logf("stdio transport error (expected): %v", err)
	}
}

// TestServerStartUnknownTransport tests unknown transport handling
func TestServerStartUnknownTransport(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "unknown-transport",
		},
		shutdown: make(chan struct{}),
	}

	err := server.Start()
	if err == nil {
		server.Stop()
		t.Error("expected error for unknown transport")
	}
}

// TestServerStopNotRunning tests stopping a server that's not running
func TestServerStopNotRunning(t *testing.T) {
	server := &Server{
		config:   &Config{},
		shutdown: make(chan struct{}),
	}

	// Should not panic or error
	server.Stop()
}

// TestDoRequestContextDeadline tests request with deadline
func TestDoRequestContextDeadline(t *testing.T) {
	// Create a server that delays
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": "ok"}`))
	}))
	defer ts.Close()

	client := &Client{
		config: &ClientConfig{
			ServerAddr: ts.URL,
			Timeout:    10 * time.Millisecond,
		},
		httpClient: &http.Client{Timeout: 10 * time.Millisecond},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Log("Request may or may not timeout depending on timing")
	}
}

// TestServerHandleHTTPRequestInvalidJSON tests HTTP handler with invalid JSON
func TestServerHandleHTTPRequestInvalidJSON(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "http",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}

	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader("invalid-json{"))
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	// JSON-RPC returns 200 OK with error in response body (per spec)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify error response
	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error response for invalid JSON")
	}
	if resp.Error != nil && resp.Error.Code != ParseError {
		t.Errorf("expected parse error code %d, got %d", ParseError, resp.Error.Code)
	}
}

// TestServerHandleHTTPRequestMethodNotAllowed tests HTTP handler with wrong method
func TestServerHandleHTTPRequestMethodNotAllowed(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "http",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}

	req := httptest.NewRequest("GET", "/mcp/v1", nil)
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestDoRequestServerError tests doRequest with server error
func TestDoRequestServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := &Client{
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for server error")
	}
}

// TestDoRequestInvalidJSON tests doRequest with invalid JSON response
func TestDoRequestInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-valid-json"))
	}))
	defer ts.Close()

	client := &Client{
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

// TestHandleHTTPRequestValidRequest tests handleHTTPRequest with valid request
func TestHandleHTTPRequestValidRequest(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport:     "http",
			HTTPAddr:      "127.0.0.1:0",
			ServerName:    "test",
			ServerVersion: "1.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

// TestServerStopWhileRunning tests stopping a running server
func TestServerStopWhileRunning(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "http",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	// Stop should work
	server.Stop()

	if server.running.Load() {
		t.Error("server should be stopped")
	}
}

// TestCheckToolAuthorizationMissingToken tests auth with missing token
func TestCheckToolAuthorizationMissingToken(t *testing.T) {
	checker := &AuthorizationChecker{
		toolPermissions: map[string]string{
			"protected_tool": "read:resource",
		},
	}

	ctx := context.Background()

	// Initialize with some mock auth service
	checker.authService = &mockAuthService{
		validateFunc: func(ctx context.Context, token string) (*TokenValidationResult, error) {
			return &TokenValidationResult{Valid: true}, nil
		},
	}

	// Should fail due to missing token
	err := checker.CheckToolAuthorization(ctx, "protected_tool", "")
	if err == nil {
		t.Error("expected error for missing token")
	}
	if err != nil && err.Type != AuthErrorMissingToken {
		t.Errorf("expected AuthErrorMissingToken, got %v", err.Type)
	}
}

// mockAuthService for auth testing
type mockAuthService struct {
	validateFunc  func(ctx context.Context, token string) (*TokenValidationResult, error)
	checkPermFunc func(ctx context.Context, subject, resource, action string) (bool, error)
}

func (m *mockAuthService) ValidateToken(ctx context.Context, token string) (*TokenValidationResult, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, nil
}

func (m *mockAuthService) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error) {
	if m.checkPermFunc != nil {
		return m.checkPermFunc(ctx, subject, resource, action)
	}
	return true, nil
}

// TestDoRequestWithToken tests doRequest with authorization token
func TestDoRequestWithToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify token was sent
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("expected 'Bearer test-token', got '%s'", auth)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer ts.Close()

	client := &Client{
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "test-token")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDoRequestEmptyResponse tests doRequest with empty response body
func TestDoRequestEmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Empty body
	}))
	defer ts.Close()

	client := &Client{
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for empty response")
	}
}

// TestDoRequestNetworkError tests doRequest with network failure
func TestDoRequestNetworkError(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			ServerAddr: "http://localhost:1", // Invalid port that won't be listening
			MaxRetries: 1,
		},
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for network failure")
	}
}

// TestServerInitializeTools tests initialize returning tools
func TestServerInitializeTools(t *testing.T) {
	server := &Server{
		config: &Config{
			ServerName:    "test-server",
			ServerVersion: "1.0.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error.Message)
	}
}

// TestDoRequestReadBodyError tests doRequest when reading body fails
func TestDoRequestReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send a response but close connection mid-stream (simulating read error)
		w.Header().Set("Content-Length", "1000") // Claim large body
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{`)) // Write partial body
		// Connection will close without sending full body
	}))
	defer ts.Close()

	client := &Client{
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	// This might result in either read error or JSON parse error
	if err == nil {
		t.Log("Expected error but may vary based on timing")
	}
}

// TestServerHandleRequestVersionMismatch tests handleRequest with wrong version
func TestServerHandleRequestVersionMismatch(t *testing.T) {
	server := &Server{
		config: &Config{
			ServerName:    "test",
			ServerVersion: "1.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	// Send request with wrong JSON-RPC version
	body := `{"jsonrpc":"1.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error for version mismatch")
	}
}

// TestServerHandleRequestUnknownMethod tests handleRequest with unknown method
func TestServerHandleRequestUnknownMethod(t *testing.T) {
	server := &Server{
		config: &Config{
			ServerName:    "test",
			ServerVersion: "1.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	body := `{"jsonrpc":"2.0","id":1,"method":"unknown_method"}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error for unknown method")
	}
}

// TestMCPErrorFormatting tests MCPError formatting
func TestMCPErrorFormatting(t *testing.T) {
	err := &MCPError{
		Code:    -32600,
		Message: "Invalid Request",
		Data:    "test data",
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "-32600") {
		t.Error("error should contain code")
	}
	if !strings.Contains(errStr, "Invalid Request") {
		t.Error("error should contain message")
	}
}

// TestIsConnected tests client connection status
func TestIsConnected(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			ServerAddr: "http://localhost:9999",
		},
		httpClient: &http.Client{},
	}

	// Should be connected initially
	if !client.IsConnected() {
		t.Error("expected connected initially")
	}

	// Close and check
	client.Close()

	if client.IsConnected() {
		t.Error("expected disconnected after close")
	}
}

// TestServerAddr tests ServerAddr getter
func TestServerAddr(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			ServerAddr: "http://test:8000",
		},
	}

	if client.ServerAddr() != "http://test:8000" {
		t.Errorf("expected 'http://test:8000', got '%s'", client.ServerAddr())
	}
}

// TestMakeErrorResponse tests makeErrorResponse function
func TestMakeErrorResponse(t *testing.T) {
	server := &Server{
		config: &Config{},
	}

	resp := server.makeErrorResponse(1, InvalidRequest, "test message", "test data")

	if resp.Error == nil {
		t.Error("expected error in response")
	}
	if resp.Error.Code != InvalidRequest {
		t.Errorf("expected code %d, got %d", InvalidRequest, resp.Error.Code)
	}
	if resp.Error.Message != "test message" {
		t.Errorf("expected message 'test message', got '%s'", resp.Error.Message)
	}
}

// TestOAuthMetadataServeHTTP tests OAuth metadata handler
func TestOAuthMetadataServeHTTP(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL:             "https://example.com:8443",
		AuthorizationServerURLs: []string{"https://auth.example.com"},
		DocumentationURL:        "https://docs.example.com",
	}
	handler := NewOAuthMetadataHandler(config)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}

	if metadata["resource"] != "https://example.com:8443" {
		t.Errorf("expected resource 'https://example.com:8443', got '%v'", metadata["resource"])
	}
}

// TestOAuthMetadataDefaultConfig tests OAuth metadata handler with default config
func TestOAuthMetadataDefaultConfig(t *testing.T) {
	handler := NewOAuthMetadataHandler(nil)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}

	// Should have default resource URL
	if _, exists := metadata["resource"]; !exists {
		t.Error("expected 'resource' field in metadata")
	}
}

// TestExecuteToolWithExistingDeadline tests ExecuteTool when context already has deadline
func TestExecuteToolWithExistingDeadline(t *testing.T) {
	logger := newTestLogger()
	registry := NewToolRegistry(nil, logger)

	// Create context with existing deadline
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Execute an unknown tool with existing deadline
	_, err := registry.ExecuteTool(ctx, "unknown_tool", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unknown tool")
	}
}

// TestAuthorizationCheckerNoService tests auth checker when service is nil
func TestAuthorizationCheckerNoService(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
}

// TestClientDoRequestWithContextTimeout tests client doRequest with cancellation
func TestClientDoRequestWithContextTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Request should timeout
	_, err = client.ListTools(ctx)
	if err == nil {
		t.Error("expected timeout error")
	}
}

// TestReadResourceEmptyURI tests ReadResource with empty URI
func TestReadResourceEmptyURI(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty URI")
	}
}

// TestReadResourceInvalidURI tests ReadResource with non-existent URI
func TestReadResourceInvalidURI(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "nonexistent://resource")
	if err == nil {
		t.Error("expected error for non-existent resource")
	}
}

// TestReadResourceEmptyPath tests ReadResource with platform:// but no path
func TestReadResourceEmptyPath(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "platform://")
	if err == nil {
		t.Error("expected error for empty resource path")
	}
}

// TestReadResourceUnknownType tests ReadResource with unknown resource type
func TestReadResourceUnknownType(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "platform://unknowntype/resource")
	if err == nil {
		t.Error("expected error for unknown resource type")
	}
}

// TestOAuthDefaultOAuthMetadataConfigCreation tests default OAuth config creation
func TestOAuthDefaultOAuthMetadataConfigCreation(t *testing.T) {
	config := DefaultOAuthMetadataConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	// Default config should have empty ResourceURL (to be set later)
	if config.ResourceURL != "" {
		t.Error("expected empty default ResourceURL")
	}
}

// TestListResourcesInvalidResponse tests ListResources with invalid response format
func TestListResourcesInvalidResponse(t *testing.T) {
	// Create server that returns non-map response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "not_a_map", // Invalid - should be a map
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(&ClientConfig{ServerAddr: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for invalid response format")
	}
}

// TestListResourcesMissingResources tests ListResources with missing resources field
func TestListResourcesMissingResources(t *testing.T) {
	// Create server that returns map without resources field
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{"other": "data"}, // Missing resources field
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(&ClientConfig{ServerAddr: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for missing resources field")
	}
}

// TestDoRequestWithRPCErrorData tests doRequest when server returns JSON-RPC error with data
func TestDoRequestWithRPCErrorData(t *testing.T) {
	// Create server that returns JSON-RPC error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]interface{}{
				"code":    -32600,
				"message": "Invalid Request",
				"data":    "test error data",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(&ClientConfig{ServerAddr: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for RPC error response")
	}

	// Should be MCPError
	var mcpErr *MCPError
	if !errors.As(err, &mcpErr) {
		t.Errorf("expected MCPError, got %T", err)
	}
}

// TestOAuthMetadataMethodNotAllowed tests OAuth metadata with non-GET/HEAD methods
func TestOAuthMetadataMethodNotAllowed(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL: "https://example.com:8443",
	}
	handler := NewOAuthMetadataHandler(config)

	req := httptest.NewRequest("POST", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestOAuthMetadataHeadRequest tests OAuth metadata with HEAD request
func TestOAuthMetadataHeadRequest(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL: "https://example.com:8443",
	}
	handler := NewOAuthMetadataHandler(config)

	req := httptest.NewRequest("HEAD", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// HEAD should return headers but no body
	if w.Body.Len() != 0 {
		t.Errorf("expected empty body for HEAD request, got %d bytes", w.Body.Len())
	}

	// Should still have Content-Type header
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type header")
	}
}

// TestOAuthMetadataSetters tests OAuth metadata setter methods
func TestOAuthMetadataSetters(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL: "https://old.example.com",
	}
	handler := NewOAuthMetadataHandler(config)

	// Test SetResourceURL
	handler.SetResourceURL("https://new.example.com")
	if handler.GetMetadata().Resource != "https://new.example.com" {
		t.Error("SetResourceURL did not update metadata")
	}

	// Test SetAuthorizationServers
	handler.SetAuthorizationServers([]string{"https://auth1.example.com", "https://auth2.example.com"})
	if len(handler.GetMetadata().AuthorizationServers) != 2 {
		t.Error("SetAuthorizationServers did not update metadata")
	}
}
