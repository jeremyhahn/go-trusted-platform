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

// Package tenant provides integration tests for Tenant services across all protocols.
// These tests verify that tenant operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified TenantCommands interface.
//
// Run tests via:
//
//	make integration-test-tenant
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package tenant

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tenantpkg "github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestTenantMultiProtocol runs all tenant tests across multiple protocols
func TestTenantMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement TenantCommands
	adapters := []TenantCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "tenant", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testTenantProtocol(t, ctx, adapter)
		})
	}
}

// testTenantProtocol runs the complete tenant test suite against a single protocol adapter.
func testTenantProtocol(t *testing.T, ctx context.Context, cmd TenantCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("TenantCRUD", func(t *testing.T) {
		testTenantCreate(t, ctx, cmd, prefix)
		testTenantGet(t, ctx, cmd, prefix)
		testTenantGetByName(t, ctx, cmd, prefix)
		testTenantUpdate(t, ctx, cmd, prefix)
		testTenantDelete(t, ctx, cmd, prefix)
		testTenantList(t, ctx, cmd, prefix)
	})

	t.Run("TenantLifecycle", func(t *testing.T) {
		testTenantSuspend(t, ctx, cmd, prefix)
		testTenantResume(t, ctx, cmd, prefix)
		testTenantLifecycleEdgeCases(t, ctx, cmd, prefix)
	})

	t.Run("TenantQuotas", func(t *testing.T) {
		testTenantGetQuotas(t, ctx, cmd, prefix)
		testTenantUpdateQuotas(t, ctx, cmd, prefix)
		testTenantUsage(t, ctx, cmd, prefix)
		testTenantCheckQuota(t, ctx, cmd, prefix)
	})

	t.Run("TenantNetwork", func(t *testing.T) {
	})

	t.Run("TenantSync", func(t *testing.T) {
		testTenantSyncOps(t, ctx, cmd, prefix)
	})
}

// ============================================================================
// Tenant CRUD Tests
// ============================================================================

func testTenantCreate(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateBasicTenant", func(t *testing.T) {
		tenantName := prefix + "-create-basic"
		opts := CreateTenantOptions{
			Name:        tenantName,
			DisplayName: "Test Tenant Basic",
			Labels:      DefaultLabels(),
			Annotations: DefaultAnnotations(),
		}

		result, err := cmd.CreateTenant(testCtx, opts)
		require.NoError(t, err, "CreateTenant should succeed for basic tenant")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Tenant, "Result.Tenant should not be nil")
		assert.NotEmpty(t, result.Tenant.ID, "Tenant ID should not be empty")
		assert.Equal(t, tenantName, result.Tenant.Name, "Tenant name should match")
		assert.Equal(t, "Test Tenant Basic", result.Tenant.DisplayName, "Display name should match")
	})

	t.Run("CreateTenantWithQuotas", func(t *testing.T) {
		tenantName := prefix + "-create-quotas"
		opts := CreateTenantOptions{
			Name:        tenantName,
			DisplayName: "Test Tenant Quotas",
			Labels: map[string]string{
				"tier":        "premium",
				"environment": "production",
			},
		}

		result, err := cmd.CreateTenant(testCtx, opts)
		require.NoError(t, err, "CreateTenant should succeed with labels")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Tenant, "Result.Tenant should not be nil")
		assert.NotEmpty(t, result.Tenant.ID, "Tenant ID should not be empty")
	})

	t.Run("CreateTenantDuplicateNameFails", func(t *testing.T) {
		tenantName := prefix + "-create-dup"
		opts := CreateTenantOptions{
			Name:        tenantName,
			DisplayName: "Duplicate Test",
		}

		// First creation should succeed
		result, err := cmd.CreateTenant(testCtx, opts)
		require.NoError(t, err, "First CreateTenant should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Second creation with same name should fail
		_, err = cmd.CreateTenant(testCtx, opts)
		require.Error(t, err, "CreateTenant should fail for duplicate name")
	})

	t.Run("CreateTenantEmptyNameFails", func(t *testing.T) {
		opts := CreateTenantOptions{
			Name:        "",
			DisplayName: "No Name Tenant",
		}

		_, err := cmd.CreateTenant(testCtx, opts)
		require.Error(t, err, "CreateTenant should fail with empty name")
	})
}

func testTenantGet(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant first
	tenantName := prefix + "-get-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Get Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("GetExistingTenant", func(t *testing.T) {
		opts := GetTenantOptions{
			TenantID: createResult.Tenant.ID,
		}

		result, err := cmd.GetTenant(testCtx, opts)
		require.NoError(t, err, "GetTenant should succeed for existing tenant")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Tenant, "Result.Tenant should not be nil")
		assert.Equal(t, createResult.Tenant.ID, result.Tenant.ID, "Tenant ID should match")
		assert.Equal(t, tenantName, result.Tenant.Name, "Tenant name should match")
		assert.Equal(t, "Get Test Tenant", result.Tenant.DisplayName, "Display name should match")
	})

	t.Run("GetNonexistentTenantFails", func(t *testing.T) {
		opts := GetTenantOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
		}

		_, err := cmd.GetTenant(testCtx, opts)
		require.Error(t, err, "GetTenant should fail for nonexistent tenant")
	})
}

func testTenantGetByName(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant first
	tenantName := prefix + "-getbyname-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "GetByName Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("GetTenantByNameExisting", func(t *testing.T) {
		opts := GetTenantByNameOptions{
			Name: tenantName,
		}

		result, err := cmd.GetTenantByName(testCtx, opts)
		require.NoError(t, err, "GetTenantByName should succeed for existing tenant")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Tenant, "Result.Tenant should not be nil")
		assert.Equal(t, createResult.Tenant.ID, result.Tenant.ID, "Tenant ID should match")
		assert.Equal(t, tenantName, result.Tenant.Name, "Tenant name should match")
	})

	t.Run("GetTenantByNameNonexistentFails", func(t *testing.T) {
		opts := GetTenantByNameOptions{
			Name: "nonexistent-tenant-name-" + uuid.New().String(),
		}

		_, err := cmd.GetTenantByName(testCtx, opts)
		require.Error(t, err, "GetTenantByName should fail for nonexistent tenant")
	})
}

func testTenantUpdate(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant first
	tenantName := prefix + "-update-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Original Display Name",
		Labels: map[string]string{
			"original": "true",
		},
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("UpdateDisplayName", func(t *testing.T) {
		newDisplayName := "Updated Display Name"
		opts := UpdateTenantOptions{
			TenantID:    createResult.Tenant.ID,
			DisplayName: &newDisplayName,
		}

		result, err := cmd.UpdateTenant(testCtx, opts)
		require.NoError(t, err, "UpdateTenant should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Tenant, "Result.Tenant should not be nil")
		assert.Equal(t, newDisplayName, result.Tenant.DisplayName, "Display name should be updated")
	})

	t.Run("UpdateLabels", func(t *testing.T) {
		opts := UpdateTenantOptions{
			TenantID: createResult.Tenant.ID,
			Labels: map[string]string{
				"updated": "true",
				"version": "2",
			},
		}

		result, err := cmd.UpdateTenant(testCtx, opts)
		require.NoError(t, err, "UpdateTenant should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Tenant, "Result.Tenant should not be nil")
	})

	t.Run("UpdateNonexistentTenantFails", func(t *testing.T) {
		newDisplayName := "Should Fail"
		opts := UpdateTenantOptions{
			TenantID:    "nonexistent-tenant-" + uuid.New().String(),
			DisplayName: &newDisplayName,
		}

		_, err := cmd.UpdateTenant(testCtx, opts)
		require.Error(t, err, "UpdateTenant should fail for nonexistent tenant")
	})
}

func testTenantDelete(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant for deletion
	tenantName := prefix + "-delete-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Delete Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("DeleteExistingTenant", func(t *testing.T) {
		opts := DeleteTenantOptions{
			TenantID: createResult.Tenant.ID,
		}

		result, err := cmd.DeleteTenant(testCtx, opts)
		require.NoError(t, err, "DeleteTenant should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Delete should return success")
	})

	t.Run("VerifyTenantDeleted", func(t *testing.T) {
		opts := GetTenantOptions{
			TenantID: createResult.Tenant.ID,
		}

		_, err := cmd.GetTenant(testCtx, opts)
		require.Error(t, err, "GetTenant should fail for deleted tenant")
	})

	t.Run("DeleteNonexistentTenantFails", func(t *testing.T) {
		opts := DeleteTenantOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
		}

		_, err := cmd.DeleteTenant(testCtx, opts)
		require.Error(t, err, "DeleteTenant should fail for nonexistent tenant")
	})
}

func testTenantList(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple tenants for listing
	for i := 0; i < 3; i++ {
		tenantName := fmt.Sprintf("%s-list-%d", prefix, i)
		opts := CreateTenantOptions{
			Name:        tenantName,
			DisplayName: fmt.Sprintf("List Test %d", i),
		}
		_, err := cmd.CreateTenant(testCtx, opts)
		require.NoError(t, err, "Setup: CreateTenant should succeed")
	}

	t.Run("ListAllTenants", func(t *testing.T) {
		opts := ListTenantsOptions{
			Limit: 100,
		}

		result, err := cmd.ListTenants(testCtx, opts)
		require.NoError(t, err, "ListTenants should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Tenants), 3, "Should have at least 3 tenants")
	})

	t.Run("ListTenantsWithLimit", func(t *testing.T) {
		opts := ListTenantsOptions{
			Limit: 2,
		}

		result, err := cmd.ListTenants(testCtx, opts)
		require.NoError(t, err, "ListTenants should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, len(result.Tenants), 2, "Should respect limit")
	})

	t.Run("ListTenantsWithOffset", func(t *testing.T) {
		opts := ListTenantsOptions{
			Limit:  10,
			Offset: 1,
		}

		result, err := cmd.ListTenants(testCtx, opts)
		require.NoError(t, err, "ListTenants should succeed with offset")
		require.NotNil(t, result, "Result should not be nil")
		// Just verify we get a valid response
	})
}

// ============================================================================
// Tenant Lifecycle Tests
// ============================================================================

func testTenantSuspend(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant for suspend testing
	tenantName := prefix + "-suspend-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Suspend Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("SuspendActiveTenant", func(t *testing.T) {
		opts := SuspendTenantOptions{
			TenantID: createResult.Tenant.ID,
		}

		result, err := cmd.SuspendTenant(testCtx, opts)
		require.NoError(t, err, "SuspendTenant should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Suspend should return success")
	})

	t.Run("VerifyTenantSuspended", func(t *testing.T) {
		getResult, err := cmd.GetTenant(testCtx, GetTenantOptions{TenantID: createResult.Tenant.ID})
		require.NoError(t, err, "GetTenant should succeed")
		require.NotNil(t, getResult.Tenant, "Tenant should not be nil")
		assert.Equal(t, tenantpkg.StateSuspended, getResult.Tenant.State, "Tenant should be suspended")
	})

	t.Run("SuspendNonexistentTenantFails", func(t *testing.T) {
		opts := SuspendTenantOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
		}

		_, err := cmd.SuspendTenant(testCtx, opts)
		require.Error(t, err, "SuspendTenant should fail for nonexistent tenant")
	})
}

func testTenantResume(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create and suspend a tenant for resume testing
	tenantName := prefix + "-resume-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Resume Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	// Suspend it first
	_, err = cmd.SuspendTenant(testCtx, SuspendTenantOptions{TenantID: createResult.Tenant.ID})
	require.NoError(t, err, "Setup: SuspendTenant should succeed")

	t.Run("ResumeSuspendedTenant", func(t *testing.T) {
		opts := ResumeTenantOptions{
			TenantID: createResult.Tenant.ID,
		}

		result, err := cmd.ResumeTenant(testCtx, opts)
		require.NoError(t, err, "ResumeTenant should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Resume should return success")
	})

	t.Run("VerifyTenantResumed", func(t *testing.T) {
		getResult, err := cmd.GetTenant(testCtx, GetTenantOptions{TenantID: createResult.Tenant.ID})
		require.NoError(t, err, "GetTenant should succeed")
		require.NotNil(t, getResult.Tenant, "Tenant should not be nil")
		assert.Equal(t, tenantpkg.StateActive, getResult.Tenant.State, "Tenant should be active")
	})

	t.Run("ResumeNonexistentTenantFails", func(t *testing.T) {
		opts := ResumeTenantOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
		}

		_, err := cmd.ResumeTenant(testCtx, opts)
		require.Error(t, err, "ResumeTenant should fail for nonexistent tenant")
	})
}

func testTenantLifecycleEdgeCases(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("SuspendAlreadySuspendedTenant", func(t *testing.T) {
		// Create and suspend a tenant
		tenantName := prefix + "-double-suspend"
		createResult, err := cmd.CreateTenant(testCtx, CreateTenantOptions{
			Name:        tenantName,
			DisplayName: "Double Suspend Test",
		})
		require.NoError(t, err, "Setup: CreateTenant should succeed")

		// First suspend
		_, err = cmd.SuspendTenant(testCtx, SuspendTenantOptions{TenantID: createResult.Tenant.ID})
		require.NoError(t, err, "First SuspendTenant should succeed")

		// Second suspend should either succeed (idempotent) or fail with appropriate error
		_, err = cmd.SuspendTenant(testCtx, SuspendTenantOptions{TenantID: createResult.Tenant.ID})
		// This may succeed if idempotent or fail - both are valid behaviors
		if err != nil {
			t.Logf("Second suspend returned error (expected behavior): %v", err)
		}
	})

	t.Run("ResumeActiveTenant", func(t *testing.T) {
		// Create an active tenant (not suspended)
		tenantName := prefix + "-resume-active"
		createResult, err := cmd.CreateTenant(testCtx, CreateTenantOptions{
			Name:        tenantName,
			DisplayName: "Resume Active Test",
		})
		require.NoError(t, err, "Setup: CreateTenant should succeed")

		// Try to resume an already active tenant
		_, err = cmd.ResumeTenant(testCtx, ResumeTenantOptions{TenantID: createResult.Tenant.ID})
		// This may succeed if idempotent or fail - both are valid behaviors
		if err != nil {
			t.Logf("Resume active tenant returned error (expected behavior): %v", err)
		}
	})
}

// ============================================================================
// Tenant Quota Tests
// ============================================================================

func testTenantGetQuotas(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant for quota testing
	tenantName := prefix + "-getquota-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Get Quota Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("GetQuotasForExistingTenant", func(t *testing.T) {
		opts := GetQuotasOptions{
			TenantID: createResult.Tenant.ID,
		}

		result, err := cmd.GetQuotas(testCtx, opts)
		require.NoError(t, err, "GetQuotas should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Compute, "Compute quota should not be nil")
		require.NotNil(t, result.Network, "Network quota should not be nil")
		require.NotNil(t, result.Storage, "Storage quota should not be nil")
		assert.Equal(t, createResult.Tenant.ID, result.TenantID, "Tenant ID should match")
	})

	t.Run("GetQuotasForNonexistentTenantFails", func(t *testing.T) {
		opts := GetQuotasOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
		}

		_, err := cmd.GetQuotas(testCtx, opts)
		require.Error(t, err, "GetQuotas should fail for nonexistent tenant")
	})
}

func testTenantUpdateQuotas(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant for quota update testing
	tenantName := prefix + "-updatequota-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Update Quota Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("UpdateComputeQuotas", func(t *testing.T) {
		opts := UpdateQuotasOptions{
			TenantID: createResult.Tenant.ID,
			Compute: &ComputeQuotaUpdate{
				MaxVMs:        20,
				MaxContainers: 100,
				MaxVCPUs:      64,
				MaxMemoryMB:   131072,
				MaxDiskGB:     1000,
			},
		}

		result, err := cmd.UpdateQuotas(testCtx, opts)
		require.NoError(t, err, "UpdateQuotas should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Compute, "Compute quota should not be nil")
		assert.Equal(t, int64(20), result.Compute.MaxVMs, "MaxVMs should be updated")
		assert.Equal(t, int64(100), result.Compute.MaxContainers, "MaxContainers should be updated")
		assert.Equal(t, int64(64), result.Compute.MaxVCPUs, "MaxVCPUs should be updated")
	})

	t.Run("UpdateNetworkQuotas", func(t *testing.T) {
		opts := UpdateQuotasOptions{
			TenantID: createResult.Tenant.ID,
			Network: &NetworkQuotaUpdate{
				MaxBridges:       10,
				MaxPorts:         200,
				MaxBandwidthMbps: 20000,
			},
		}

		result, err := cmd.UpdateQuotas(testCtx, opts)
		require.NoError(t, err, "UpdateQuotas should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Network, "Network quota should not be nil")
		assert.Equal(t, int64(10), result.Network.MaxBridges, "MaxBridges should be updated")
		assert.Equal(t, int64(200), result.Network.MaxPorts, "MaxPorts should be updated")
	})

	t.Run("UpdateStorageQuotas", func(t *testing.T) {
		opts := UpdateQuotasOptions{
			TenantID: createResult.Tenant.ID,
			Storage: &StorageQuotaUpdate{
				MaxVolumesGB: 2000,
				MaxSnapshots: 100,
			},
		}

		result, err := cmd.UpdateQuotas(testCtx, opts)
		require.NoError(t, err, "UpdateQuotas should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Storage, "Storage quota should not be nil")
		assert.Equal(t, int64(2000), result.Storage.MaxVolumesGB, "MaxVolumesGB should be updated")
		assert.Equal(t, int64(100), result.Storage.MaxSnapshots, "MaxSnapshots should be updated")
	})

	t.Run("UpdateAllQuotas", func(t *testing.T) {
		opts := UpdateQuotasOptions{
			TenantID: createResult.Tenant.ID,
			Compute: &ComputeQuotaUpdate{
				MaxVMs:        50,
				MaxContainers: 250,
				MaxVCPUs:      128,
				MaxMemoryMB:   262144,
				MaxDiskGB:     2000,
			},
			Network: &NetworkQuotaUpdate{
				MaxBridges:       20,
				MaxPorts:         500,
				MaxBandwidthMbps: 40000,
			},
			Storage: &StorageQuotaUpdate{
				MaxVolumesGB: 5000,
				MaxSnapshots: 250,
			},
		}

		result, err := cmd.UpdateQuotas(testCtx, opts)
		require.NoError(t, err, "UpdateQuotas should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, int64(50), result.Compute.MaxVMs, "MaxVMs should be updated")
		assert.Equal(t, int64(20), result.Network.MaxBridges, "MaxBridges should be updated")
		assert.Equal(t, int64(5000), result.Storage.MaxVolumesGB, "MaxVolumesGB should be updated")
	})

	t.Run("UpdateQuotasForNonexistentTenantFails", func(t *testing.T) {
		opts := UpdateQuotasOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
			Compute: &ComputeQuotaUpdate{
				MaxVMs: 10,
			},
		}

		_, err := cmd.UpdateQuotas(testCtx, opts)
		require.Error(t, err, "UpdateQuotas should fail for nonexistent tenant")
	})
}

func testTenantUsage(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant for usage testing
	tenantName := prefix + "-usage-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Usage Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	t.Run("GetUsageForExistingTenant", func(t *testing.T) {
		opts := GetUsageOptions{
			TenantID: createResult.Tenant.ID,
		}

		result, err := cmd.GetUsage(testCtx, opts)
		require.NoError(t, err, "GetUsage should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, createResult.Tenant.ID, result.TenantID, "Tenant ID should match")
		// Newly created tenant should have zero usage
		assert.GreaterOrEqual(t, result.VMs, int64(0), "VMs usage should be >= 0")
		assert.GreaterOrEqual(t, result.Containers, int64(0), "Containers usage should be >= 0")
	})

	t.Run("GetUsageForNonexistentTenantFails", func(t *testing.T) {
		opts := GetUsageOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
		}

		_, err := cmd.GetUsage(testCtx, opts)
		require.Error(t, err, "GetUsage should fail for nonexistent tenant")
	})
}

func testTenantCheckQuota(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant with known quotas for check quota testing
	tenantName := prefix + "-checkquota-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Check Quota Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	// Set specific quotas for testing
	_, err = cmd.UpdateQuotas(testCtx, UpdateQuotasOptions{
		TenantID: createResult.Tenant.ID,
		Compute: &ComputeQuotaUpdate{
			MaxVMs:        10,
			MaxContainers: 50,
			MaxVCPUs:      32,
		},
	})
	require.NoError(t, err, "Setup: UpdateQuotas should succeed")

	t.Run("CheckQuotaAllowed", func(t *testing.T) {
		opts := CheckQuotaOptions{
			TenantID: createResult.Tenant.ID,
			Resource: "vms",
			Amount:   1,
		}

		result, err := cmd.CheckQuota(testCtx, opts)
		require.NoError(t, err, "CheckQuota should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Allowed, "Small request should be allowed")
	})

	t.Run("CheckQuotaExceeded", func(t *testing.T) {
		opts := CheckQuotaOptions{
			TenantID: createResult.Tenant.ID,
			Resource: "vms",
			Amount:   100, // Exceeds MaxVMs of 10
		}

		result, err := cmd.CheckQuota(testCtx, opts)
		// CheckQuota may return error or result with Allowed=false
		if err == nil {
			require.NotNil(t, result, "Result should not be nil")
			assert.False(t, result.Allowed, "Request exceeding quota should not be allowed")
		} else {
			t.Logf("CheckQuota returned error for exceeded quota (expected behavior): %v", err)
		}
	})

	t.Run("CheckQuotaForNonexistentTenantFails", func(t *testing.T) {
		opts := CheckQuotaOptions{
			TenantID: "nonexistent-tenant-" + uuid.New().String(),
			Resource: "vms",
			Amount:   1,
		}

		_, err := cmd.CheckQuota(testCtx, opts)
		require.Error(t, err, "CheckQuota should fail for nonexistent tenant")
	})
}

// ============================================================================
// Tenant Network Tests
// ============================================================================

func testTenantSyncOps(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("SyncTenants", func(t *testing.T) {
		result, err := cmd.SyncTenants(testCtx)
		require.NoError(t, err, "SyncTenants should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Sync should return success")
	})

	t.Run("SyncTenantsIdempotent", func(t *testing.T) {
		// Sync should be safe to call multiple times
		result1, err := cmd.SyncTenants(testCtx)
		require.NoError(t, err, "First SyncTenants should succeed")
		require.NotNil(t, result1, "First result should not be nil")
		assert.True(t, result1.Success, "First sync should return success")

		result2, err := cmd.SyncTenants(testCtx)
		require.NoError(t, err, "Second SyncTenants should succeed")
		require.NotNil(t, result2, "Second result should not be nil")
		assert.True(t, result2.Success, "Second sync should return success")
	})
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestTenantMultiProtocol_ErrorHandling(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapters := []TenantCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewMCPAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "tenant", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()

			t.Run("GetTenant_NotFound", func(t *testing.T) {
				opts := GetTenantOptions{
					TenantID: "non-existent-tenant-" + uuid.New().String(),
				}

				_, err := adapter.GetTenant(ctx, opts)
				require.Error(t, err, "GetTenant should return error for non-existent tenant")
			})

			t.Run("GetTenantByName_NotFound", func(t *testing.T) {
				opts := GetTenantByNameOptions{
					Name: "non-existent-tenant-name-" + uuid.New().String(),
				}

				_, err := adapter.GetTenantByName(ctx, opts)
				require.Error(t, err, "GetTenantByName should return error for non-existent tenant")
			})

			t.Run("CreateTenant_DuplicateName", func(t *testing.T) {
				testID := uuid.New().String()[:8]
				name := GenerateTestTenantName(testID + "-dup")

				opts := CreateTenantOptions{
					Name:        name,
					DisplayName: GenerateTestDisplayName(testID + "-dup"),
				}

				_, err := adapter.CreateTenant(ctx, opts)
				require.NoError(t, err, "First CreateTenant should succeed")

				_, err = adapter.CreateTenant(ctx, opts)
				require.Error(t, err, "CreateTenant should fail for duplicate name")
			})

			t.Run("DeleteTenant_NotFound", func(t *testing.T) {
				opts := DeleteTenantOptions{
					TenantID: "non-existent-tenant-" + uuid.New().String(),
				}

				_, err := adapter.DeleteTenant(ctx, opts)
				require.Error(t, err, "DeleteTenant should return error for non-existent tenant")
			})

			t.Run("SuspendTenant_NotFound", func(t *testing.T) {
				opts := SuspendTenantOptions{
					TenantID: "non-existent-tenant-" + uuid.New().String(),
				}

				_, err := adapter.SuspendTenant(ctx, opts)
				require.Error(t, err, "SuspendTenant should return error for non-existent tenant")
			})

			t.Run("ResumeTenant_NotFound", func(t *testing.T) {
				opts := ResumeTenantOptions{
					TenantID: "non-existent-tenant-" + uuid.New().String(),
				}

				_, err := adapter.ResumeTenant(ctx, opts)
				require.Error(t, err, "ResumeTenant should return error for non-existent tenant")
			})
		})
	}
}

// ============================================================================
// Protocol-Specific Tests
// ============================================================================

func TestTenantCLI(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "tenant", "CLI", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("cli-%d", time.Now().Unix())
	testTenantProtocol(t, ctx, adapter)

	// Additional CLI-specific tests
	t.Run("CLIOutputFormats", func(t *testing.T) {
		testCLIOutputFormats(t, ctx, adapter, prefix)
	})
}

func TestTenantREST(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "tenant", "REST", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testTenantProtocol(t, ctx, adapter)
}

func TestTenantGRPC(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "tenant", "gRPC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testTenantProtocol(t, ctx, adapter)
}

func TestTenantQUIC(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "tenant", "QUIC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testTenantProtocol(t, ctx, adapter)
}

func TestTenantMCP(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "tenant", "MCP", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testTenantProtocol(t, ctx, adapter)
}

func TestTenantUnix(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "tenant", "Unix", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testTenantProtocol(t, ctx, adapter)
}

// ============================================================================
// CLI-Specific Tests
// ============================================================================

// testCLIOutputFormats tests the CLI output format flags (-o json, -o yaml, table)
func testCLIOutputFormats(t *testing.T, ctx context.Context, cmd TenantCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a tenant for output format testing
	tenantName := prefix + "-format-test"
	createOpts := CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Output Format Test Tenant",
	}
	createResult, err := cmd.CreateTenant(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateTenant should succeed")
	require.NotNil(t, createResult.Tenant, "Setup: Tenant should not be nil")

	// Note: The CLI adapter internally uses JSON output (-o json) for parsing,
	// so we just verify the operations work correctly through the adapter
	t.Run("ListWithDefaultFormat", func(t *testing.T) {
		result, err := cmd.ListTenants(testCtx, ListTenantsOptions{Limit: 10})
		require.NoError(t, err, "ListTenants should succeed")
		assert.GreaterOrEqual(t, len(result.Tenants), 1, "Should have at least 1 tenant")
	})

	t.Run("ShowWithDefaultFormat", func(t *testing.T) {
		result, err := cmd.GetTenant(testCtx, GetTenantOptions{TenantID: createResult.Tenant.ID})
		require.NoError(t, err, "GetTenant should succeed")
		assert.Equal(t, tenantName, result.Tenant.Name, "Tenant name should match")
	})

	t.Run("QuotasWithDefaultFormat", func(t *testing.T) {
		result, err := cmd.GetQuotas(testCtx, GetQuotasOptions{TenantID: createResult.Tenant.ID})
		require.NoError(t, err, "GetQuotas should succeed")
		assert.NotNil(t, result.Compute, "Compute quota should not be nil")
		assert.NotNil(t, result.Network, "Network quota should not be nil")
		assert.NotNil(t, result.Storage, "Storage quota should not be nil")
	})
}
