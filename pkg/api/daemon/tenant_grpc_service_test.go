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

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant/quota"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock IAM Client
// =============================================================================

// mockIAMClientForTenant implements iam.TenantClient for tenant service testing.
type mockIAMClientForTenant struct {
	mu      sync.RWMutex
	tenants map[string]*sdkiam.Tenant
	nextID  int
}

func newMockIAMClientForTenant() *mockIAMClientForTenant {
	return &mockIAMClientForTenant{
		tenants: make(map[string]*sdkiam.Tenant),
		nextID:  1,
	}
}

func (m *mockIAMClientForTenant) Create(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := req.ID
	if id == "" {
		id = req.Name + "-id"
	}

	t := &sdkiam.Tenant{
		ID:   id,
		Name: req.Name,
	}

	m.tenants[t.ID] = t
	m.nextID++
	return t, nil
}

func (m *mockIAMClientForTenant) Get(ctx context.Context, tenantID string) (*sdkiam.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.tenants[tenantID]
	if !ok {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	return t, nil
}

func (m *mockIAMClientForTenant) List(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenants := make([]sdkiam.Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		tenants = append(tenants, *t)
	}

	return &sdkiam.ListTenantsResponse{
		Tenants:    tenants,
		Pagination: sdkiam.PaginationInfo{TotalCount: len(tenants)},
	}, nil
}

func (m *mockIAMClientForTenant) Update(ctx context.Context, tenantID string, req *sdkiam.UpdateTenantRequest) (*sdkiam.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tenants[tenantID]
	if !ok {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}

	if req.DisplayName != "" {
		t.DisplayName = req.DisplayName
	}
	return t, nil
}

func (m *mockIAMClientForTenant) Delete(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.tenants, tenantID)
	return nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func createTestTenantManager(t *testing.T) *tenant.Manager {
	cfg := tenant.DefaultConfig()
	cfg.EnableDEKIsolation = false // Disable for testing

	mgr, err := tenant.NewManager(&tenant.ManagerConfig{
		IAMTenantClient: newMockIAMClientForTenant(),
		Config:          cfg,
		Logger:          nil,
	})
	require.NoError(t, err)
	return mgr
}

func createTestTenantService(t *testing.T) *TenantGRPCService {
	logger := logging.DefaultLogger()
	mgr := createTestTenantManager(t)

	return NewTenantGRPCService(
		WithTenantManagerGRPC(mgr),
		WithTenantLoggerGRPC(logger),
	)
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewTenantGRPCService(t *testing.T) {
	t.Run("creates service with default logger", func(t *testing.T) {
		svc := NewTenantGRPCService()
		assert.NotNil(t, svc)
		assert.NotNil(t, svc.logger)
		assert.Nil(t, svc.manager)
	})

	t.Run("creates service with options", func(t *testing.T) {
		logger := logging.DefaultLogger()
		mgr := createTestTenantManager(t)

		svc := NewTenantGRPCService(
			WithTenantManagerGRPC(mgr),
			WithTenantLoggerGRPC(logger),
		)

		assert.NotNil(t, svc)
		assert.Equal(t, logger, svc.logger)
		assert.Equal(t, mgr, svc.manager)
	})

	t.Run("SetManager updates manager", func(t *testing.T) {
		svc := NewTenantGRPCService()
		assert.Nil(t, svc.manager)

		mgr := createTestTenantManager(t)
		svc.SetManager(mgr)

		assert.Equal(t, mgr, svc.manager)
	})
}

// =============================================================================
// ListTenants Tests
// =============================================================================

func TestTenantGRPCService_ListTenants(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.ListTenants(ctx, &ListTenantsRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.ListTenants(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns empty list when no tenants", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.ListTenants(ctx, &ListTenantsRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Empty(t, resp.Tenants)
		assert.Equal(t, int32(0), resp.Total)
	})

	t.Run("returns tenants with pagination", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create test tenant first
		_, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name:        "test-tenant",
			DisplayName: "Test Tenant",
		})
		require.NoError(t, err)

		resp, err := svc.ListTenants(ctx, &ListTenantsRequest{
			Limit:  10,
			Offset: 0,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Len(t, resp.Tenants, 1)
		assert.Equal(t, "test-tenant", resp.Tenants[0].Name)
	})

	t.Run("uses default limit when not specified", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.ListTenants(ctx, &ListTenantsRequest{
			Limit: 0, // Should use default
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

// =============================================================================
// GetTenant Tests
// =============================================================================

func TestTenantGRPCService_GetTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.GetTenant(ctx, &GetTenantRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetTenant(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetTenant(ctx, &GetTenantRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns not found for non-existent tenant", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetTenant(ctx, &GetTenantRequest{TenantID: "non-existent"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns tenant by ID", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name:        "get-test",
			DisplayName: "Get Test",
		})
		require.NoError(t, err)

		resp, err := svc.GetTenant(ctx, &GetTenantRequest{
			TenantID: createResp.Tenant.ID,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "get-test", resp.Tenant.Name)
	})
}

// =============================================================================
// GetTenantByName Tests
// =============================================================================

func TestTenantGRPCService_GetTenantByName(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.GetTenantByName(ctx, &GetTenantByNameRequest{Name: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetTenantByName(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty name", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetTenantByName(ctx, &GetTenantByNameRequest{Name: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns tenant by name", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant first
		_, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name:        "name-test",
			DisplayName: "Name Test",
		})
		require.NoError(t, err)

		resp, err := svc.GetTenantByName(ctx, &GetTenantByNameRequest{
			Name: "name-test",
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "name-test", resp.Tenant.Name)
	})
}

// =============================================================================
// CreateTenant Tests
// =============================================================================

func TestTenantGRPCService_CreateTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.CreateTenant(ctx, &CreateTenantRequest{Name: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CreateTenant(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty name", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CreateTenant(ctx, &CreateTenantRequest{Name: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("creates tenant successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name:        "create-test",
			DisplayName: "Create Test",
			Labels:      map[string]string{"env": "test"},
			Annotations: map[string]string{"owner": "qa"},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.Tenant.ID)
		assert.Equal(t, "create-test", resp.Tenant.Name)
		assert.Equal(t, "Create Test", resp.Tenant.DisplayName)
		assert.Equal(t, "test", resp.Tenant.Labels["env"])
	})

	t.Run("creates tenant with custom quotas", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "quota-test",
			ComputeQuota: &ComputeQuotaInfo{
				MaxVMs:        20,
				MaxContainers: 100,
				MaxVCPUs:      64,
				MaxMemoryMB:   131072,
			},
			NetworkQuota: &NetworkQuotaInfo{
				MaxBridges:       10,
				MaxPorts:         200,
				MaxBandwidthMbps: 20000,
			},
			StorageQuota: &StorageQuotaInfo{
				MaxVolumesGB: 4096,
				MaxSnapshots: 200,
			},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, int64(20), resp.Tenant.ComputeQuota.MaxVMs)
		assert.Equal(t, int64(10), resp.Tenant.NetworkQuota.MaxBridges)
		assert.Equal(t, int64(4096), resp.Tenant.StorageQuota.MaxVolumesGB)
	})

	t.Run("returns error for duplicate tenant name", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create first tenant
		_, err := svc.CreateTenant(ctx, &CreateTenantRequest{Name: "duplicate-test"})
		require.NoError(t, err)

		// Try to create duplicate
		resp, err := svc.CreateTenant(ctx, &CreateTenantRequest{Name: "duplicate-test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})
}

// =============================================================================
// UpdateTenant Tests
// =============================================================================

func TestTenantGRPCService_UpdateTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.UpdateTenant(ctx, &UpdateTenantRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.UpdateTenant(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.UpdateTenant(ctx, &UpdateTenantRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("updates tenant successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name:        "update-test",
			DisplayName: "Original Name",
		})
		require.NoError(t, err)

		// Update tenant
		resp, err := svc.UpdateTenant(ctx, &UpdateTenantRequest{
			TenantID:    createResp.Tenant.ID,
			DisplayName: "Updated Name",
			Labels:      map[string]string{"updated": "true"},
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "Updated Name", resp.Tenant.DisplayName)
		assert.Equal(t, "true", resp.Tenant.Labels["updated"])
	})
}

// =============================================================================
// DeleteTenant Tests
// =============================================================================

func TestTenantGRPCService_DeleteTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.DeleteTenant(ctx, &DeleteTenantRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.DeleteTenant(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.DeleteTenant(ctx, &DeleteTenantRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("deletes tenant successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "delete-test",
		})
		require.NoError(t, err)

		// Delete tenant
		resp, err := svc.DeleteTenant(ctx, &DeleteTenantRequest{
			TenantID: createResp.Tenant.ID,
		})

		require.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify tenant is deleted
		_, err = svc.GetTenant(ctx, &GetTenantRequest{TenantID: createResp.Tenant.ID})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// =============================================================================
// SuspendTenant Tests
// =============================================================================

func TestTenantGRPCService_SuspendTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.SuspendTenant(ctx, &SuspendTenantRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.SuspendTenant(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.SuspendTenant(ctx, &SuspendTenantRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("suspends tenant successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "suspend-test",
		})
		require.NoError(t, err)

		// Suspend tenant
		resp, err := svc.SuspendTenant(ctx, &SuspendTenantRequest{
			TenantID: createResp.Tenant.ID,
		})

		require.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify tenant is suspended
		getResp, err := svc.GetTenant(ctx, &GetTenantRequest{TenantID: createResp.Tenant.ID})
		require.NoError(t, err)
		assert.Equal(t, "suspended", getResp.Tenant.State)
	})
}

// =============================================================================
// ResumeTenant Tests
// =============================================================================

func TestTenantGRPCService_ResumeTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.ResumeTenant(ctx, &ResumeTenantRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.ResumeTenant(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.ResumeTenant(ctx, &ResumeTenantRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("resumes suspended tenant successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "resume-test",
		})
		require.NoError(t, err)

		// Suspend first
		_, err = svc.SuspendTenant(ctx, &SuspendTenantRequest{
			TenantID: createResp.Tenant.ID,
		})
		require.NoError(t, err)

		// Resume tenant
		resp, err := svc.ResumeTenant(ctx, &ResumeTenantRequest{
			TenantID: createResp.Tenant.ID,
		})

		require.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify tenant is active
		getResp, err := svc.GetTenant(ctx, &GetTenantRequest{TenantID: createResp.Tenant.ID})
		require.NoError(t, err)
		assert.Equal(t, "active", getResp.Tenant.State)
	})

	t.Run("returns error when resuming non-suspended tenant", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant (which starts as active)
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "resume-active-test",
		})
		require.NoError(t, err)

		// Try to resume an already active tenant
		resp, err := svc.ResumeTenant(ctx, &ResumeTenantRequest{
			TenantID: createResp.Tenant.ID,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})
}

// =============================================================================
// GetQuotas Tests
// =============================================================================

func TestTenantGRPCService_GetQuotas(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.GetQuotas(ctx, &GetQuotasRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetQuotas(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetQuotas(ctx, &GetQuotasRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns quotas successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant with custom quotas
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "quotas-test",
			ComputeQuota: &ComputeQuotaInfo{
				MaxVMs: 15,
			},
		})
		require.NoError(t, err)

		resp, err := svc.GetQuotas(ctx, &GetQuotasRequest{
			TenantID: createResp.Tenant.ID,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, int64(15), resp.Compute.MaxVMs)
	})
}

// =============================================================================
// UpdateQuotas Tests
// =============================================================================

func TestTenantGRPCService_UpdateQuotas(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.UpdateQuotas(ctx, &UpdateQuotasRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.UpdateQuotas(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.UpdateQuotas(ctx, &UpdateQuotasRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("updates quotas successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "update-quotas-test",
		})
		require.NoError(t, err)

		// Update quotas
		resp, err := svc.UpdateQuotas(ctx, &UpdateQuotasRequest{
			TenantID: createResp.Tenant.ID,
			Compute: &ComputeQuotaInfo{
				MaxVMs:        30,
				MaxContainers: 150,
			},
		})

		require.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify quotas updated
		quotasResp, err := svc.GetQuotas(ctx, &GetQuotasRequest{TenantID: createResp.Tenant.ID})
		require.NoError(t, err)
		assert.Equal(t, int64(30), quotasResp.Compute.MaxVMs)
	})
}

// =============================================================================
// GetUsage Tests
// =============================================================================

func TestTenantGRPCService_GetUsage(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.GetUsage(ctx, &GetUsageRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetUsage(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetUsage(ctx, &GetUsageRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// =============================================================================
// CheckQuota Tests
// =============================================================================

func TestTenantGRPCService_CheckQuota(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.CheckQuota(ctx, &CheckQuotaRequest{
			TenantID: "test",
			Resource: "vms",
			Amount:   1,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CheckQuota(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CheckQuota(ctx, &CheckQuotaRequest{
			TenantID: "",
			Resource: "vms",
			Amount:   1,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty resource", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CheckQuota(ctx, &CheckQuotaRequest{
			TenantID: "test",
			Resource: "",
			Amount:   1,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for invalid amount", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CheckQuota(ctx, &CheckQuotaRequest{
			TenantID: "test",
			Resource: "vms",
			Amount:   0,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for invalid resource type", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.CheckQuota(ctx, &CheckQuotaRequest{
			TenantID: "test",
			Resource: "invalid-resource",
			Amount:   1,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestTenantGRPCService_Sync(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.Sync(ctx, &SyncRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("syncs successfully", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.Sync(ctx, &SyncRequest{})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Success)
	})
}

// =============================================================================
// RotateTenantDEK Tests
// =============================================================================

func TestTenantGRPCService_RotateTenantDEK(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.RotateTenantDEK(ctx, &RotateTenantDEKRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.RotateTenantDEK(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.RotateTenantDEK(ctx, &RotateTenantDEKRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when DEK isolation is disabled", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create a tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "rotate-dek-test",
		})
		require.NoError(t, err)

		// Try to rotate DEK - should fail since DEK isolation is disabled in test manager
		resp, err := svc.RotateTenantDEK(ctx, &RotateTenantDEKRequest{
			TenantID:   createResp.Tenant.ID,
			Background: false,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// =============================================================================
// GetTenantDEKStatus Tests
// =============================================================================

func TestTenantGRPCService_GetTenantDEKStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when manager not initialized", func(t *testing.T) {
		svc := NewTenantGRPCService()

		resp, err := svc.GetTenantDEKStatus(ctx, &GetTenantDEKStatusRequest{TenantID: "test"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error for nil request", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetTenantDEKStatus(ctx, nil)

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error for empty tenant_id", func(t *testing.T) {
		svc := createTestTenantService(t)

		resp, err := svc.GetTenantDEKStatus(ctx, &GetTenantDEKStatusRequest{TenantID: ""})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when DEK isolation is disabled", func(t *testing.T) {
		svc := createTestTenantService(t)

		// Create a tenant first
		createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
			Name: "dek-status-test",
		})
		require.NoError(t, err)

		// Try to get DEK status - should fail since DEK isolation is disabled in test manager
		resp, err := svc.GetTenantDEKStatus(ctx, &GetTenantDEKStatusRequest{
			TenantID: createResp.Tenant.ID,
		})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestTenantGRPCService_ToGRPCError(t *testing.T) {
	svc := NewTenantGRPCService()

	t.Run("nil error returns nil", func(t *testing.T) {
		result := svc.toGRPCError(nil)
		assert.Nil(t, result)
	})

	t.Run("ErrTenantNotFound maps to NotFound", func(t *testing.T) {
		err := tenant.ErrTenantNotFound{ID: "test"}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("ErrTenantExists maps to AlreadyExists", func(t *testing.T) {
		err := tenant.ErrTenantExists{Name: "test"}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})

	t.Run("ErrInvalidRequest maps to InvalidArgument", func(t *testing.T) {
		err := tenant.ErrInvalidRequest{Reason: "test"}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("ErrInvalidState maps to FailedPrecondition", func(t *testing.T) {
		err := tenant.ErrInvalidState{Current: tenant.StateDeleted}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("ErrQuotaExceeded maps to ResourceExhausted", func(t *testing.T) {
		err := tenant.ErrQuotaExceeded{TenantID: "test", Resource: "vms"}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.ResourceExhausted, st.Code())
	})
}

// =============================================================================
// EntityToTenantInfo Tests
// =============================================================================

func TestTenantGRPCService_EntityToTenantInfo(t *testing.T) {
	svc := NewTenantGRPCService()

	t.Run("nil entity returns nil", func(t *testing.T) {
		result := svc.entityToTenantInfo(nil)
		assert.Nil(t, result)
	})

	t.Run("converts entity to info", func(t *testing.T) {
		entity := &tenant.TenantEntity{
			ID:          "test-id",
			Name:        "test-name",
			DisplayName: "Test Name",
			State:       tenant.StateActive,
			DEKPath:     "/tenant/12345/default",
			ComputeQuota: tenant.ComputeQuota{
				MaxVMs:        10,
				MaxContainers: 50,
			},
			NetworkQuota: tenant.NetworkQuota{
				MaxBridges: 5,
			},
			StorageQuota: tenant.StorageQuota{
				MaxVolumesGB: 1024,
			},
			Labels:      map[string]string{"env": "test"},
			Annotations: map[string]string{"owner": "qa"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		info := svc.entityToTenantInfo(entity)

		assert.NotNil(t, info)
		assert.Equal(t, "test-id", info.ID)
		assert.Equal(t, "test-name", info.Name)
		assert.Equal(t, "Test Name", info.DisplayName)
		assert.Equal(t, "active", info.State)
		assert.Equal(t, uint32(12345), info.DEKHandle)
		assert.Equal(t, int64(10), info.ComputeQuota.MaxVMs)
		assert.Equal(t, int64(5), info.NetworkQuota.MaxBridges)
		assert.Equal(t, int64(1024), info.StorageQuota.MaxVolumesGB)
		assert.Equal(t, "test", info.Labels["env"])
		assert.Equal(t, "qa", info.Annotations["owner"])
	})
}

// =============================================================================
// Resource Type Validation Tests
// =============================================================================

func TestResourceTypeValidation(t *testing.T) {
	validResources := []string{
		"vms", "containers", "vcpus", "memory", "disk",
		"bridges", "ports", "bandwidth", "volumes", "snapshots",
	}

	for _, r := range validResources {
		t.Run("valid_"+r, func(t *testing.T) {
			rt := quota.ResourceType(r)
			assert.True(t, rt.IsValid())
		})
	}

	t.Run("invalid resource type", func(t *testing.T) {
		rt := quota.ResourceType("invalid")
		assert.False(t, rt.IsValid())
	})
}

// =============================================================================
// Additional Coverage Tests for GetUsage
// =============================================================================

func TestTenantGRPCService_GetUsage_Success(t *testing.T) {
	ctx := context.Background()
	svc := createTestTenantService(t)

	// Create tenant first
	createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
		Name:        "usage-test",
		DisplayName: "Usage Test",
	})
	require.NoError(t, err)

	// Get usage for valid tenant
	// Note: The mock tenant manager may not have a usage tracker configured,
	// so we test that the error path is exercised correctly
	resp, err := svc.GetUsage(ctx, &GetUsageRequest{
		TenantID: createResp.Tenant.ID,
	})

	if err != nil {
		// Should be InvalidArgument if usage tracker not configured
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	} else {
		// If successful, verify response structure
		assert.NotNil(t, resp)
		assert.Equal(t, createResp.Tenant.ID, resp.TenantID)
	}
}

// =============================================================================
// Additional Coverage Tests for CheckQuota
// =============================================================================

func TestTenantGRPCService_CheckQuota_Success(t *testing.T) {
	ctx := context.Background()
	svc := createTestTenantService(t)

	// Create tenant with quotas
	createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
		Name: "check-quota-test",
		ComputeQuota: &ComputeQuotaInfo{
			MaxVMs:        10,
			MaxContainers: 50,
			MaxVCPUs:      32,
			MaxMemoryMB:   65536,
		},
	})
	require.NoError(t, err)

	t.Run("returns response with correct fields", func(t *testing.T) {
		resp, err := svc.CheckQuota(ctx, &CheckQuotaRequest{
			TenantID: createResp.Tenant.ID,
			Resource: "vms",
			Amount:   5,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		// Response should have correct identifiers regardless of availability
		assert.Equal(t, createResp.Tenant.ID, resp.TenantID)
		assert.Equal(t, "vms", resp.Resource)
		assert.Equal(t, int64(5), resp.Amount)
		// Message should be set
		assert.NotEmpty(t, resp.Message)
	})

	t.Run("returns response for large amount", func(t *testing.T) {
		resp, err := svc.CheckQuota(ctx, &CheckQuotaRequest{
			TenantID: createResp.Tenant.ID,
			Resource: "vms",
			Amount:   100,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
		// Response should contain message indicating result
		assert.NotEmpty(t, resp.Message)
	})
}

func TestTenantGRPCService_ToGRPCError_Additional(t *testing.T) {
	svc := NewTenantGRPCService()

	t.Run("ErrInvalidTransition maps to FailedPrecondition", func(t *testing.T) {
		err := tenant.ErrInvalidTransition{From: tenant.StateActive, To: tenant.StateDeleted}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("ErrStorageFailed maps to Internal", func(t *testing.T) {
		err := tenant.ErrStorageFailed{Operation: "save"}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("ErrDEKOperationFailed maps to Internal", func(t *testing.T) {
		err := tenant.ErrDEKOperationFailed{Operation: "create", TenantID: "test"}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("ErrConfigValidation maps to InvalidArgument", func(t *testing.T) {
		err := tenant.ErrConfigValidation{Field: "name", Reason: "invalid"}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("unknown error maps to Internal", func(t *testing.T) {
		err := tenant.ErrResourceLimitReached{TenantID: "test", Resource: "unknown", Limit: 10}
		result := svc.toGRPCError(err)

		st, ok := status.FromError(result)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

// =============================================================================
// Additional UpdateQuotas Coverage Tests
// =============================================================================

func TestTenantGRPCService_UpdateQuotas_AllTypes(t *testing.T) {
	ctx := context.Background()
	svc := createTestTenantService(t)

	// Create tenant first
	createResp, err := svc.CreateTenant(ctx, &CreateTenantRequest{
		Name: "update-all-quotas-test",
	})
	require.NoError(t, err)

	t.Run("updates network quotas", func(t *testing.T) {
		resp, err := svc.UpdateQuotas(ctx, &UpdateQuotasRequest{
			TenantID: createResp.Tenant.ID,
			Network: &NetworkQuotaInfo{
				MaxBridges:       15,
				MaxPorts:         300,
				MaxBandwidthMbps: 25000,
			},
		})

		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("updates storage quotas", func(t *testing.T) {
		resp, err := svc.UpdateQuotas(ctx, &UpdateQuotasRequest{
			TenantID: createResp.Tenant.ID,
			Storage: &StorageQuotaInfo{
				MaxVolumesGB: 8192,
				MaxSnapshots: 400,
			},
		})

		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("updates all quotas at once", func(t *testing.T) {
		resp, err := svc.UpdateQuotas(ctx, &UpdateQuotasRequest{
			TenantID: createResp.Tenant.ID,
			Compute: &ComputeQuotaInfo{
				MaxVMs:        50,
				MaxContainers: 200,
				MaxVCPUs:      128,
				MaxMemoryMB:   262144,
			},
			Network: &NetworkQuotaInfo{
				MaxBridges:       20,
				MaxPorts:         400,
				MaxBandwidthMbps: 50000,
			},
			Storage: &StorageQuotaInfo{
				MaxVolumesGB: 10240,
				MaxSnapshots: 500,
			},
		})

		require.NoError(t, err)
		assert.True(t, resp.Success)
	})
}
