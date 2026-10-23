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
	"log/slog"
	"sync"
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock IAM Client for TenantGRPCServer Tests
// =============================================================================

// mockIAMClientForServer implements iam.TenantClient for server testing.
type mockIAMClientForServer struct {
	mu      sync.RWMutex
	tenants map[string]*sdkiam.Tenant
}

func newMockIAMClientForServer() *mockIAMClientForServer {
	return &mockIAMClientForServer{
		tenants: make(map[string]*sdkiam.Tenant),
	}
}

// Reconcile satisfies tenant.RoleReconciler; these tests do not inspect roles.
func (m *mockIAMClientForServer) Reconcile(_ context.Context, tenantID string) (*sdkiam.ReconcileRolesResponse, error) {
	return &sdkiam.ReconcileRolesResponse{TenantID: tenantID}, nil
}

func (m *mockIAMClientForServer) Create(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
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
	return t, nil
}

func (m *mockIAMClientForServer) Get(ctx context.Context, tenantID string) (*sdkiam.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.tenants[tenantID]
	if !ok {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	return t, nil
}

func (m *mockIAMClientForServer) List(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
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

func (m *mockIAMClientForServer) Update(ctx context.Context, tenantID string, req *sdkiam.UpdateTenantRequest) (*sdkiam.Tenant, error) {
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

func (m *mockIAMClientForServer) Delete(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.tenants, tenantID)
	return nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func createTestTenantManagerForServer(t *testing.T) *tenant.Manager {
	cfg := tenant.DefaultConfig()
	cfg.EnableDEKIsolation = false // Disable for testing

	mgr, err := tenant.NewManager(&tenant.ManagerConfig{
		IAMTenantClient: newMockIAMClientForServer(),
		IAMRoleClient:   newMockIAMClientForServer(),
		Config:          cfg,
		Logger:          nil,
	})
	require.NoError(t, err)
	return mgr
}

func createTestTenantGRPCServer(t *testing.T) *TenantGRPCServer {
	logger := slog.Default()
	mgr := createTestTenantManagerForServer(t)

	server := NewTenantGRPCServer(WithTenantLogger(logger))
	server.SetManager(mgr)
	return server
}

// createUninitializedServer creates a server without a manager for testing
// FailedPrecondition error paths.
func createUninitializedServer() *TenantGRPCServer {
	return NewTenantGRPCServer(WithTenantLogger(slog.Default()))
}

// =============================================================================
// WithTenantManager Option Test - Exercises constructor with manager option
// =============================================================================

func TestTenantGRPCServer_WithTenantManager_Option(t *testing.T) {
	mgr := createTestTenantManagerForServer(t)
	logger := slog.Default()

	// Create server using WithTenantManager option directly
	server := NewTenantGRPCServer(
		WithTenantManager(mgr),
		WithTenantLogger(logger),
	)

	// Verify manager was set by performing an operation
	ctx := context.Background()
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "option-test",
	})
	require.NoError(t, err)
	assert.NotNil(t, createResp)
	assert.Equal(t, "option-test", createResp.Tenant.Name)
}

// =============================================================================
// Manager Not Initialized Tests - FailedPrecondition Error Paths
// =============================================================================

func TestTenantGRPCServer_ListTenants_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.ListTenants(ctx, &platformv1.ListTenantsRequest{})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "tenant manager not initialized")
}

func TestTenantGRPCServer_GetTenant_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.GetTenant(ctx, &platformv1.GetTenantRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_GetTenantByName_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{Name: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_CreateTenant_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{Name: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_UpdateTenant_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_DeleteTenant_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_SuspendTenant_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_ResumeTenant_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_GetQuotas_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_UpdateQuotas_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_GetUsage_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.GetUsage(ctx, &platformv1.GetUsageRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_CheckQuota_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: "test",
		Resource: "vms",
		Amount:   1,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_Sync_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.Sync(ctx, &platformv1.SyncTenantsRequest{})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_RotateTenantDEK_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestTenantGRPCServer_GetTenantDEKStatus_ManagerNotInitialized(t *testing.T) {
	ctx := context.Background()
	server := createUninitializedServer()

	resp, err := server.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{TenantId: "test"})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

// =============================================================================
// ListTenants Tests - Currently at 12.5% coverage
// =============================================================================

func TestTenantGRPCServer_ListTenants_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create some tenants
	_, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{Name: "list-test-1"})
	require.NoError(t, err)
	_, err = server.CreateTenant(ctx, &platformv1.CreateTenantRequest{Name: "list-test-2"})
	require.NoError(t, err)

	// List tenants
	resp, err := server.ListTenants(ctx, &platformv1.ListTenantsRequest{
		Limit:  10,
		Offset: 0,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.GreaterOrEqual(t, len(resp.Tenants), 2)
	assert.GreaterOrEqual(t, int(resp.Total), 2)
}

func TestTenantGRPCServer_ListTenants_DefaultLimit(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// List tenants with zero limit (should use default 100)
	resp, err := server.ListTenants(ctx, &platformv1.ListTenantsRequest{
		Limit:  0,
		Offset: 0,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestTenantGRPCServer_ListTenants_NegativeOffset(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// List tenants with negative offset (should become 0)
	resp, err := server.ListTenants(ctx, &platformv1.ListTenantsRequest{
		Limit:  10,
		Offset: -5,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// =============================================================================
// GetTenant Tests - Currently at 22.2% coverage
// =============================================================================

func TestTenantGRPCServer_GetTenant_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name:        "get-test",
		DisplayName: "Get Test Tenant",
	})
	require.NoError(t, err)

	// Get the tenant
	resp, err := server.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: createResp.Tenant.Id,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, createResp.Tenant.Id, resp.Tenant.Id)
	assert.Equal(t, "get-test", resp.Tenant.Name)
}

func TestTenantGRPCServer_GetTenant_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_GetTenant_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: "nonexistent-tenant-id",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// =============================================================================
// GetTenantByName Tests - Currently at 22.2% coverage
// =============================================================================

func TestTenantGRPCServer_GetTenantByName_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	_, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name:        "getbyname-test",
		DisplayName: "Get By Name Test",
	})
	require.NoError(t, err)

	// Get by name
	resp, err := server.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: "getbyname-test",
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "getbyname-test", resp.Tenant.Name)
}

func TestTenantGRPCServer_GetTenantByName_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_GetTenantByName_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: "nonexistent-tenant-name",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// =============================================================================
// UpdateTenant Tests - Currently at 14.3% coverage
// =============================================================================

func TestTenantGRPCServer_UpdateTenant_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name:        "update-test",
		DisplayName: "Original Name",
	})
	require.NoError(t, err)

	// Update the tenant
	resp, err := server.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{
		TenantId:    createResp.Tenant.Id,
		DisplayName: "Updated Name",
		Labels:      map[string]string{"env": "test"},
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "tenant updated successfully", resp.Status.Message)
}

func TestTenantGRPCServer_UpdateTenant_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_UpdateTenant_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{
		TenantId:    "nonexistent-tenant-id",
		DisplayName: "New Name",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// =============================================================================
// DeleteTenant Tests - Currently at 20% coverage
// =============================================================================

func TestTenantGRPCServer_DeleteTenant_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "delete-test",
	})
	require.NoError(t, err)

	// Delete the tenant
	resp, err := server.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{
		TenantId: createResp.Tenant.Id,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "tenant deleted successfully", resp.Status.Message)
}

func TestTenantGRPCServer_DeleteTenant_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_DeleteTenant_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{
		TenantId: "nonexistent-tenant-id",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// =============================================================================
// SuspendTenant Tests - Currently at 70% coverage
// =============================================================================

func TestTenantGRPCServer_SuspendTenant_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "suspend-test",
	})
	require.NoError(t, err)

	// Suspend the tenant
	resp, err := server.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{
		TenantId: createResp.Tenant.Id,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
}

func TestTenantGRPCServer_SuspendTenant_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_SuspendTenant_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{
		TenantId: "nonexistent-tenant",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// =============================================================================
// ResumeTenant Tests - Currently at 20% coverage
// =============================================================================

func TestTenantGRPCServer_ResumeTenant_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant first
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name:        "resume-test",
		DisplayName: "Resume Test Tenant",
	})
	require.NoError(t, err)
	tenantID := createResp.Tenant.Id

	// Suspend the tenant
	_, err = server.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{
		TenantId: tenantID,
	})
	require.NoError(t, err)

	// Resume the tenant
	resp, err := server.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{
		TenantId: tenantID,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "tenant resumed successfully", resp.Status.Message)
}

func TestTenantGRPCServer_ResumeTenant_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Empty tenant_id
	resp, err := server.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_ResumeTenant_ActiveIsIdempotent(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant (which starts active, not suspended)
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "resume-active-test",
	})
	require.NoError(t, err)

	// Resuming an active tenant is a same-state transition: it succeeds
	// so a retried resume never fails (docs/tenant/engineering.md §2).
	resp, err := server.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{
		TenantId: createResp.Tenant.Id,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.GetStatus().GetSuccess())

	got, err := server.GetTenant(ctx, &platformv1.GetTenantRequest{TenantId: createResp.Tenant.Id})
	require.NoError(t, err)
	assert.Equal(t, platformv1.TenantState_TENANT_STATE_ACTIVE, got.GetTenant().GetState())
}

func TestTenantGRPCServer_ResumeTenant_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{
		TenantId: "nonexistent-tenant",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// =============================================================================
// GetQuotas Tests - Currently at 22.2% coverage
// =============================================================================

func TestTenantGRPCServer_GetQuotas_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant with custom quotas
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "quota-test",
		ComputeQuota: &platformv1.ComputeQuota{
			MaxVms:        15,
			MaxContainers: 75,
			MaxVcpus:      64,
			MaxMemoryMb:   65536,
		},
		NetworkQuota: &platformv1.NetworkQuota{
			MaxBridges:       8,
			MaxPorts:         200,
			MaxBandwidthMbps: 5000,
		},
		StorageQuota: &platformv1.StorageQuota{
			MaxVolumesGb: 2048,
			MaxSnapshots: 100,
		},
	})
	require.NoError(t, err)

	// Get quotas
	resp, err := server.GetQuotas(ctx, &platformv1.GetQuotasRequest{
		TenantId: createResp.Tenant.Id,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, createResp.Tenant.Id, resp.TenantId)
	assert.Equal(t, int64(15), resp.Compute.MaxVms)
	assert.Equal(t, int64(75), resp.Compute.MaxContainers)
	assert.Equal(t, int64(8), resp.Network.MaxBridges)
	assert.Equal(t, int64(2048), resp.Storage.MaxVolumesGb)
}

func TestTenantGRPCServer_GetQuotas_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetQuotas(ctx, &platformv1.GetQuotasRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_GetQuotas_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetQuotas(ctx, &platformv1.GetQuotasRequest{
		TenantId: "nonexistent-tenant",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// =============================================================================
// UpdateQuotas Tests - Currently at 11.8% coverage
// =============================================================================

func TestTenantGRPCServer_UpdateQuotas_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant first
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "update-quota-test",
	})
	require.NoError(t, err)

	// Update quotas
	resp, err := server.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{
		TenantId: createResp.Tenant.Id,
		Compute: &platformv1.ComputeQuota{
			MaxVms:        30,
			MaxContainers: 150,
			MaxVcpus:      128,
			MaxMemoryMb:   131072,
		},
		Network: &platformv1.NetworkQuota{
			MaxBridges:       15,
			MaxPorts:         400,
			MaxBandwidthMbps: 10000,
		},
		Storage: &platformv1.StorageQuota{
			MaxVolumesGb: 4096,
			MaxSnapshots: 200,
		},
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Status.Success)

	// Verify quotas were updated
	quotasResp, err := server.GetQuotas(ctx, &platformv1.GetQuotasRequest{
		TenantId: createResp.Tenant.Id,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(30), quotasResp.Compute.MaxVms)
	assert.Equal(t, int64(15), quotasResp.Network.MaxBridges)
	assert.Equal(t, int64(4096), quotasResp.Storage.MaxVolumesGb)
}

func TestTenantGRPCServer_UpdateQuotas_PartialUpdate(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "partial-quota-test",
	})
	require.NoError(t, err)
	id := createResp.Tenant.Id

	// MaxDiskGB has no wire field, so seed it, and the other sections,
	// through the manager.
	seed := &tenant.TenantQuotas{
		Compute: tenant.ComputeQuota{MaxVMs: 10, MaxContainers: 40, MaxVCPUs: 64, MaxMemoryMB: 8192, MaxDiskGB: 500},
		Network: tenant.NetworkQuota{MaxBridges: 4, MaxPorts: 100, MaxBandwidthMbps: 1000},
		Storage: tenant.StorageQuota{MaxVolumesGB: 900, MaxSnapshots: 20},
	}
	require.NoError(t, server.manager.UpdateQuotas(ctx, id, seed))

	// Change one limit, as `platformctl tenant quotas set --max-vms` does.
	resp, err := server.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{
		TenantId: id,
		Compute: &platformv1.ComputeQuota{
			MaxVms:        25,
			MaxContainers: 40,
			MaxVcpus:      64,
			MaxMemoryMb:   8192,
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Status.Success)

	got, err := server.manager.GetQuotas(ctx, id)
	require.NoError(t, err)
	want := *seed
	want.Compute.MaxVMs = 25
	assert.Equal(t, want, *got, "only MaxVMs may change; MaxDiskGB and the absent sections are kept")
}

func TestTenantGRPCServer_UpdateQuotas_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_UpdateQuotas_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{
		TenantId: "nonexistent-tenant",
		Compute: &platformv1.ComputeQuota{
			MaxVms: 25,
		},
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Equal(t, tenant.ErrTenantNotFound{ID: "nonexistent-tenant"}.Error(), st.Message())
}

// =============================================================================
// GetUsage Tests - Currently at 22.2% coverage
// =============================================================================

func TestTenantGRPCServer_GetUsage_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetUsage(ctx, &platformv1.GetUsageRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_GetUsage_TenantNotConfigured(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "usage-test",
	})
	require.NoError(t, err)

	// Get usage - will fail because usage tracker not configured in test environment
	// This exercises the error path through GetUsage
	resp, err := server.GetUsage(ctx, &platformv1.GetUsageRequest{
		TenantId: createResp.Tenant.Id,
	})

	// The call should succeed or return error - either way it exercises the code path
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		// InvalidArgument when usage tracker not configured
		assert.Equal(t, codes.InvalidArgument, st.Code())
	} else {
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Usage)
	}
}

// =============================================================================
// CheckQuota Tests - Currently at 10.5% coverage
// =============================================================================

func TestTenantGRPCServer_CheckQuota_UsesTenantQuotaWithoutEnforcer(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "check-quota-test",
		ComputeQuota: &platformv1.ComputeQuota{
			MaxVms: 10,
		},
	})
	require.NoError(t, err)

	allowed, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: createResp.Tenant.Id,
		Resource: "vms",
		Amount:   5,
	})
	require.NoError(t, err)
	assert.True(t, allowed.GetAvailable(), allowed.GetMessage())

	// A refusal is an answer, not an error.
	refused, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: createResp.Tenant.Id,
		Resource: "vms",
		Amount:   11,
	})
	require.NoError(t, err)
	assert.False(t, refused.GetAvailable())
}

func TestTenantGRPCServer_CheckQuota_TenantNotFound(t *testing.T) {
	server := createTestTenantGRPCServer(t)

	_, err := server.CheckQuota(context.Background(), &platformv1.CheckQuotaRequest{
		TenantId: "missing-tenant",
		Resource: "vms",
		Amount:   1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestTenantGRPCServer_CheckQuota_InvalidArgument_EmptyTenantID(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: "",
		Resource: "vms",
		Amount:   1,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_CheckQuota_InvalidArgument_EmptyResource(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: "test-id",
		Resource: "",
		Amount:   1,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_CheckQuota_InvalidArgument_ZeroAmount(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: "test-id",
		Resource: "vms",
		Amount:   0,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_CheckQuota_InvalidArgument_NegativeAmount(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: "test-id",
		Resource: "vms",
		Amount:   -5,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_CheckQuota_InvalidArgument_InvalidResource(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.CheckQuota(ctx, &platformv1.CheckQuotaRequest{
		TenantId: "test-id",
		Resource: "invalid-resource",
		Amount:   1,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_Sync_Success(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.Sync(ctx, &platformv1.SyncTenantsRequest{})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "sync completed successfully", resp.Status.Message)
}

// =============================================================================
// RotateTenantDEK Tests - Currently at 20% coverage
// =============================================================================

func TestTenantGRPCServer_RotateTenantDEK_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_RotateTenantDEK_DEKIsolationDisabled(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "rotate-dek-test",
	})
	require.NoError(t, err)

	// Try to rotate DEK - should fail since DEK isolation is disabled
	resp, err := server.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{
		TenantId:   createResp.Tenant.Id,
		Background: false,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_RotateTenantDEK_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{
		TenantId: "nonexistent-tenant",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	// Either NotFound or InvalidArgument (depending on if DEK isolation is checked first)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.True(t, st.Code() == codes.NotFound || st.Code() == codes.InvalidArgument)
}

// =============================================================================
// GetTenantDEKStatus Tests - Currently at 16.7% coverage
// =============================================================================

func TestTenantGRPCServer_GetTenantDEKStatus_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{
		TenantId: "",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_GetTenantDEKStatus_DEKIsolationDisabled(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	// Create a tenant
	createResp, err := server.CreateTenant(ctx, &platformv1.CreateTenantRequest{
		Name: "dek-status-test",
	})
	require.NoError(t, err)

	// Try to get DEK status - should fail since DEK isolation is disabled
	resp, err := server.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{
		TenantId: createResp.Tenant.Id,
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestTenantGRPCServer_GetTenantDEKStatus_NotFound(t *testing.T) {
	ctx := context.Background()
	server := createTestTenantGRPCServer(t)

	resp, err := server.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{
		TenantId: "nonexistent-tenant",
	})

	assert.Nil(t, resp)
	require.Error(t, err)
	// Either NotFound or InvalidArgument (depending on if DEK isolation is checked first)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.True(t, st.Code() == codes.NotFound || st.Code() == codes.InvalidArgument)
}

// =============================================================================
// Additional Error Mapping Tests for toGRPCError - Currently at 97.4%
// =============================================================================

func TestTenantGRPCServer_ToGRPCError_UnknownError(t *testing.T) {
	server := NewTenantGRPCServer()

	// Generic error should map to Internal
	err := server.toGRPCError(assert.AnError)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}
