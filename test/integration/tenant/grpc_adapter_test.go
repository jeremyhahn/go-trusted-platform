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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestTenantGRPCService exercises the TenantService protobuf contract
// directly against the runner's platformd. It dials the daemon the runner
// started, through the same endpoint and mTLS trio as the gRPC adapter, and
// never starts a QuicBaaS of its own (#541): a second node in the container
// collides with the daemon's ports and tests nothing the daemon serves.
func TestTenantGRPCService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	require.NoError(t, adapter.Setup(ctx), "Failed to connect to the runner's platformd")
	t.Cleanup(func() {
		if err := adapter.Teardown(context.Background()); err != nil {
			t.Errorf("close gRPC connection: %v", err)
		}
	})
	client := adapter.client

	t.Run("CreateTenant", func(t *testing.T) {
		testGRPCServiceCreateTenant(t, ctx, client)
	})

	t.Run("GetTenant", func(t *testing.T) {
		testGRPCServiceGetTenant(t, ctx, client)
	})

	t.Run("GetTenantByName", func(t *testing.T) {
		testGRPCServiceGetTenantByName(t, ctx, client)
	})

	t.Run("UpdateTenant", func(t *testing.T) {
		testGRPCServiceUpdateTenant(t, ctx, client)
	})

	t.Run("ListTenants", func(t *testing.T) {
		testGRPCServiceListTenants(t, ctx, client)
	})

	t.Run("DeleteTenant", func(t *testing.T) {
		testGRPCServiceDeleteTenant(t, ctx, client)
	})
}

// createGRPCServiceTenant creates a tenant on the runner's platformd and
// deletes it when the test ends, so the shared daemon is left as it was
// found. A tenant the test already deleted is not an error.
func createGRPCServiceTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient, req *platformv1.CreateTenantRequest) *platformv1.Tenant {
	t.Helper()

	resp, err := client.CreateTenant(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Tenant)

	tenantID := resp.Tenant.Id
	t.Cleanup(func() {
		_, deleteErr := client.DeleteTenant(context.Background(), &platformv1.DeleteTenantRequest{
			TenantId: tenantID,
		})
		if deleteErr != nil && status.Code(deleteErr) != codes.NotFound {
			t.Errorf("delete tenant %s: %v", tenantID, deleteErr)
		}
	})
	return resp.Tenant
}

func testGRPCServiceCreateTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	t.Run("valid tenant", func(t *testing.T) {
		req := &platformv1.CreateTenantRequest{
			Name:        GenerateTestTenantName("grpc-create"),
			DisplayName: "Test Tenant",
			Labels: map[string]string{
				"env": "test",
			},
		}
		created := createGRPCServiceTenant(t, ctx, client, req)
		assert.NotEmpty(t, created.Id)
		assert.Equal(t, req.Name, created.Name)
		assert.Equal(t, req.DisplayName, created.DisplayName)
	})

	t.Run("empty name", func(t *testing.T) {
		_, err := client.CreateTenant(ctx, &platformv1.CreateTenantRequest{
			Name:        "",
			DisplayName: "Invalid Tenant",
		})
		assert.Error(t, err)
	})
}

func testGRPCServiceGetTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	req := &platformv1.CreateTenantRequest{
		Name:        GenerateTestTenantName("grpc-get"),
		DisplayName: "Get Test Tenant",
	}
	created := createGRPCServiceTenant(t, ctx, client, req)

	getResp, err := client.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: created.Id,
	})
	require.NoError(t, err)
	require.NotNil(t, getResp.Tenant)
	assert.Equal(t, created.Id, getResp.Tenant.Id)
	assert.Equal(t, req.Name, getResp.Tenant.Name)

	_, err = client.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: "non-existent-id",
	})
	assert.Error(t, err)
}

func testGRPCServiceGetTenantByName(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	req := &platformv1.CreateTenantRequest{
		Name:        GenerateTestTenantName("grpc-name"),
		DisplayName: "Name Test Tenant",
	}
	created := createGRPCServiceTenant(t, ctx, client, req)

	getResp, err := client.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: req.Name,
	})
	require.NoError(t, err)
	require.NotNil(t, getResp.Tenant)
	assert.Equal(t, req.Name, getResp.Tenant.Name)
	assert.Equal(t, created.Id, getResp.Tenant.Id)

	_, err = client.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{
		Name: "non-existent-name",
	})
	assert.Error(t, err)
}

func testGRPCServiceUpdateTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	created := createGRPCServiceTenant(t, ctx, client, &platformv1.CreateTenantRequest{
		Name:        GenerateTestTenantName("grpc-update"),
		DisplayName: "Original Display Name",
	})

	updateResp, err := client.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{
		TenantId:    created.Id,
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

func testGRPCServiceListTenants(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	for i := 0; i < 3; i++ {
		createGRPCServiceTenant(t, ctx, client, &platformv1.CreateTenantRequest{
			Name:        GenerateTestTenantName("grpc-list"),
			DisplayName: fmt.Sprintf("List Test Tenant %d", i),
		})
	}

	listResp, err := client.ListTenants(ctx, &platformv1.ListTenantsRequest{
		Limit: 100,
	})
	require.NoError(t, err)
	require.NotNil(t, listResp)
	assert.GreaterOrEqual(t, len(listResp.Tenants), 3)
}

func testGRPCServiceDeleteTenant(t *testing.T, ctx context.Context, client platformv1.TenantServiceClient) {
	t.Helper()

	created := createGRPCServiceTenant(t, ctx, client, &platformv1.CreateTenantRequest{
		Name:        GenerateTestTenantName("grpc-delete"),
		DisplayName: "Delete Test Tenant",
	})

	_, err := client.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{
		TenantId: created.Id,
	})
	require.NoError(t, err)

	_, err = client.GetTenant(ctx, &platformv1.GetTenantRequest{
		TenantId: created.Id,
	})
	assert.Error(t, err)
}
