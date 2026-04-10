//go:build integration

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

package tenant

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// TestHarnessGRPC tests the tenant service using the embedded test harness.
// This test starts an embedded QuicBaaS with IAM and a gRPC tenant service.
func TestHarnessGRPC(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create and start test harness
	harness, err := NewTestHarness(nil)
	require.NoError(t, err, "Failed to create test harness")

	err = harness.Start(ctx)
	require.NoError(t, err, "Failed to start test harness")
	defer func() {
		stopErr := harness.Stop(context.Background())
		if stopErr != nil {
			t.Logf("Warning: failed to stop test harness: %v", stopErr)
		}
	}()

	// Create gRPC client connected to the test harness
	client, conn, err := harness.NewGRPCClient(ctx)
	require.NoError(t, err, "Failed to create gRPC client")
	defer conn.Close()

	// Run tenant tests
	t.Run("CreateTenant", func(t *testing.T) {
		testHarnessCreateTenant(t, ctx, client)
	})

	t.Run("GetTenant", func(t *testing.T) {
		testHarnessGetTenant(t, ctx, client)
	})

	t.Run("GetTenantByName", func(t *testing.T) {
		testHarnessGetTenantByName(t, ctx, client)
	})

	t.Run("UpdateTenant", func(t *testing.T) {
		testHarnessUpdateTenant(t, ctx, client)
	})

	t.Run("ListTenants", func(t *testing.T) {
		testHarnessListTenants(t, ctx, client)
	})

	t.Run("DeleteTenant", func(t *testing.T) {
		testHarnessDeleteTenant(t, ctx, client)
	})
}

func testHarnessCreateTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	testCases := []struct {
		name        string
		req         *platformv1.CreateTenantRequest
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name: "valid tenant",
			req: &platformv1.CreateTenantRequest{
				Name:        fmt.Sprintf("test-tenant-%d", time.Now().UnixNano()),
				DisplayName: "Test Tenant",
				Labels: map[string]string{
					"env": "test",
				},
			},
			expectError: false,
		},
		{
			name: "empty name",
			req: &platformv1.CreateTenantRequest{
				Name:        "",
				DisplayName: "Invalid Tenant",
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.CreateTenant(ctx, tc.req)
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Tenant)
			assert.NotEmpty(t, resp.Tenant.Id)
			assert.Equal(t, tc.req.Name, resp.Tenant.Name)
			assert.Equal(t, tc.req.DisplayName, resp.Tenant.DisplayName)
		})
	}
}

func testHarnessGetTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	// Create a tenant to get
	createReq := &platformv1.CreateTenantRequest{
		Name:        fmt.Sprintf("get-test-%d", time.Now().UnixNano()),
		DisplayName: "Get Test Tenant",
	}
	createResp, err := client.CreateTenant(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, createResp.Tenant)

	tenantID := createResp.Tenant.Id

	// Test getting the tenant
	getResp, err := client.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: tenantID,
	})
	require.NoError(t, err)
	require.NotNil(t, getResp.Tenant)
	assert.Equal(t, tenantID, getResp.Tenant.Id)
	assert.Equal(t, createReq.Name, getResp.Tenant.Name)

	// Test getting non-existent tenant
	_, err = client.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: "non-existent-id",
	})
	assert.Error(t, err)
}

func testHarnessGetTenantByName(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	tenantName := fmt.Sprintf("name-test-%d", time.Now().UnixNano())

	// Create a tenant
	createReq := &platformv1.CreateTenantRequest{
		Name:        tenantName,
		DisplayName: "Name Test Tenant",
	}
	createResp, err := client.CreateTenant(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, createResp.Tenant)

	// Get by name
	getResp, err := client.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: tenantName,
	})
	require.NoError(t, err)
	require.NotNil(t, getResp.Tenant)
	assert.Equal(t, tenantName, getResp.Tenant.Name)
	assert.Equal(t, createResp.Tenant.Id, getResp.Tenant.Id)

	// Test getting non-existent tenant by name
	_, err = client.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: "non-existent-name",
	})
	assert.Error(t, err)
}

func testHarnessUpdateTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	// Create a tenant to update
	createReq := &platformv1.CreateTenantRequest{
		Name:        fmt.Sprintf("update-test-%d", time.Now().UnixNano()),
		DisplayName: "Original Display Name",
	}
	createResp, err := client.CreateTenant(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, createResp.Tenant)

	tenantID := createResp.Tenant.Id

	// Update the tenant
	updateResp, err := client.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{
		TenantId:    tenantID,
		DisplayName: "Updated Display Name",
		Labels: map[string]string{
			"updated": "true",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, updateResp.Tenant)
	assert.Equal(t, "Updated Display Name", updateResp.Tenant.DisplayName)
	assert.Equal(t, "true", updateResp.Tenant.Labels["updated"])
}

func testHarnessListTenants(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	// Create a few tenants
	prefix := fmt.Sprintf("list-test-%d", time.Now().UnixNano())
	for i := 0; i < 3; i++ {
		_, err := client.CreateTenant(ctx, &platformv1.CreateTenantRequest{
			Name:        fmt.Sprintf("%s-%d", prefix, i),
			DisplayName: fmt.Sprintf("List Test Tenant %d", i),
		})
		require.NoError(t, err)
	}

	// List tenants
	listResp, err := client.ListTenants(ctx, &platformv1.ListTenantsRequest{
		Limit: 100,
	})
	require.NoError(t, err)
	require.NotNil(t, listResp)
	assert.GreaterOrEqual(t, len(listResp.Tenants), 3)
}

func testHarnessDeleteTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	// Create a tenant to delete
	createReq := &platformv1.CreateTenantRequest{
		Name:        fmt.Sprintf("delete-test-%d", time.Now().UnixNano()),
		DisplayName: "Delete Test Tenant",
	}
	createResp, err := client.CreateTenant(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, createResp.Tenant)

	tenantID := createResp.Tenant.Id

	// Delete the tenant
	_, err = client.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{
		TenantId: tenantID,
	})
	require.NoError(t, err)

	// Verify it's deleted
	_, err = client.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: tenantID,
	})
	assert.Error(t, err)
}

// TestHarnessTenantManager tests the tenant manager directly via the test harness.
func TestHarnessTenantManager(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create and start test harness
	harness, err := NewTestHarness(nil)
	require.NoError(t, err, "Failed to create test harness")

	err = harness.Start(ctx)
	require.NoError(t, err, "Failed to start test harness")
	defer func() {
		stopErr := harness.Stop(context.Background())
		if stopErr != nil {
			t.Logf("Warning: failed to stop test harness: %v", stopErr)
		}
	}()

	// Get tenant manager
	mgr := harness.TenantManager()
	require.NotNil(t, mgr, "Tenant manager should not be nil")

	// Run tests via manager directly
	t.Run("DirectCreate", func(t *testing.T) {
		testManagerCreateTenant(t, ctx, mgr)
	})
}

func testManagerCreateTenant(t *testing.T, ctx context.Context, mgr interface{}) {
	t.Helper()

	// Type assert to tenant.Manager
	tenantMgr, ok := mgr.(TenantManager)
	if !ok {
		t.Skip("Manager does not implement TenantManager interface")
		return
	}

	// Create tenant
	tenant, err := tenantMgr.CreateTenant(ctx, TenantCreateRequest{
		Name:        fmt.Sprintf("direct-test-%d", time.Now().UnixNano()),
		DisplayName: "Direct Test Tenant",
	})
	require.NoError(t, err)
	require.NotNil(t, tenant)
	assert.NotEmpty(t, tenant.ID)
}

// TenantManager interface for direct tenant manager testing
type TenantManager interface {
	CreateTenant(ctx context.Context, req TenantCreateRequest) (*TenantResult, error)
}

// TenantCreateRequest for manager testing
type TenantCreateRequest struct {
	Name        string
	DisplayName string
}

// TenantResult for manager testing
type TenantResult struct {
	ID   string
	Name string
}
