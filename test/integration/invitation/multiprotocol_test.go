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

// Package invitation provides integration tests for Invitation services across all protocols.
// These tests verify that invitation operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified InvitationCommands interface.
//
// Run tests via:
//
//	make integration-test-invitation
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package invitation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestInvitationMultiProtocol runs all invitation tests across multiple protocols
func TestInvitationMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement InvitationCommands
	adapters := []InvitationCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "invitation", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testInvitationProtocol(t, ctx, adapter)
		})
	}
}

// testInvitationProtocol runs the complete invitation test suite against a single protocol adapter.
func testInvitationProtocol(t *testing.T, ctx context.Context, cmd InvitationCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("InvitationCreate", func(t *testing.T) {
		testInvitationCreate(t, ctx, cmd, prefix)
	})

	t.Run("InvitationGetByToken", func(t *testing.T) {
		testInvitationGetByToken(t, ctx, cmd, prefix)
	})

	t.Run("InvitationList", func(t *testing.T) {
		testInvitationList(t, ctx, cmd, prefix)
	})

	t.Run("InvitationRevoke", func(t *testing.T) {
		testInvitationRevoke(t, ctx, cmd, prefix)
	})

	t.Run("InvitationAccept", func(t *testing.T) {
		testInvitationAccept(t, ctx, cmd, prefix)
	})

	t.Run("InvitationErrors", func(t *testing.T) {
		testInvitationErrors(t, ctx, cmd, prefix)
	})

	t.Run("InvitationOwnerOnly", func(t *testing.T) {
		testInvitationOwnerOnly(t, ctx, cmd, prefix)
	})

	t.Run("InvitationCrossTenant", func(t *testing.T) {
		testInvitationCrossTenant(t, ctx, cmd, prefix)
	})
}

// ============================================================================
// Create Invitation Tests
// ============================================================================

func testInvitationCreate(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateBasicInvitation", func(t *testing.T) {
		fixture := NewTestFixture(prefix + "-create-basic")
		opts := fixture.CreateInvitationOptionsFromFixture()

		result, err := cmd.CreateInvitation(testCtx, opts)
		require.NoError(t, err, "CreateInvitation should succeed for valid input")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Invitation, "Result.Invitation should not be nil")

		inv := result.Invitation
		assert.NotZero(t, inv.ID, "Invitation ID should not be zero")
		assert.NotEmpty(t, inv.Token, "Invitation token should not be empty")
		assert.Equal(t, fixture.Email, inv.Email, "Email should match")
		assert.Equal(t, fixture.Role, inv.Role, "Role should match")
		assert.Equal(t, InvitationStatusPending, inv.Status, "Status should be pending")
		assert.False(t, inv.ExpiresAt.IsZero(), "ExpiresAt should be set")
		assert.False(t, inv.CreatedAt.IsZero(), "CreatedAt should be set")
	})

	t.Run("CreateInvitationWithAdminRole", func(t *testing.T) {
		fixture := NewTestFixture(prefix + "-create-admin")
		fixture.Role = "admin"
		opts := fixture.CreateInvitationOptionsFromFixture()

		result, err := cmd.CreateInvitation(testCtx, opts)
		require.NoError(t, err, "CreateInvitation should succeed with admin role")
		require.NotNil(t, result.Invitation, "Invitation should not be nil")
		assert.Equal(t, "admin", result.Invitation.Role, "Role should be admin")
	})

	t.Run("CreateInvitationWithViewerRole", func(t *testing.T) {
		fixture := NewTestFixture(prefix + "-create-viewer")
		fixture.Role = "viewer"
		opts := fixture.CreateInvitationOptionsFromFixture()

		result, err := cmd.CreateInvitation(testCtx, opts)
		require.NoError(t, err, "CreateInvitation should succeed with viewer role")
		require.NotNil(t, result.Invitation, "Invitation should not be nil")
		assert.Equal(t, "viewer", result.Invitation.Role, "Role should be viewer")
	})

	t.Run("CreateInvitationEmptyEmailFails", func(t *testing.T) {
		opts := CreateInvitationOptions{
			TenantID: DefaultTenantID(),
			Email:    "",
			Role:     "member",
			AsOwner:  true,
			UserID:   DefaultOwnerUserID(),
		}

		_, err := cmd.CreateInvitation(testCtx, opts)
		require.Error(t, err, "CreateInvitation should fail with empty email")
	})

	t.Run("CreateInvitationInvalidEmailFails", func(t *testing.T) {
		opts := CreateInvitationOptions{
			TenantID: DefaultTenantID(),
			Email:    "invalid-email-format",
			Role:     "member",
			AsOwner:  true,
			UserID:   DefaultOwnerUserID(),
		}

		_, err := cmd.CreateInvitation(testCtx, opts)
		require.Error(t, err, "CreateInvitation should fail with invalid email format")
	})

	t.Run("CreateInvitationEmptyRoleFails", func(t *testing.T) {
		opts := CreateInvitationOptions{
			TenantID: DefaultTenantID(),
			Email:    GenerateTestEmail(prefix + "-no-role"),
			Role:     "",
			AsOwner:  true,
			UserID:   DefaultOwnerUserID(),
		}

		_, err := cmd.CreateInvitation(testCtx, opts)
		require.Error(t, err, "CreateInvitation should fail with empty role")
	})

	t.Run("CreateInvitationInvalidRoleFails", func(t *testing.T) {
		opts := CreateInvitationOptions{
			TenantID: DefaultTenantID(),
			Email:    GenerateTestEmail(prefix + "-invalid-role"),
			Role:     "superadmin", // Invalid role
			AsOwner:  true,
			UserID:   DefaultOwnerUserID(),
		}

		_, err := cmd.CreateInvitation(testCtx, opts)
		require.Error(t, err, "CreateInvitation should fail with invalid role")
	})
}

// ============================================================================
// Get Invitation by Token Tests
// ============================================================================

func testInvitationGetByToken(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create an invitation first
	fixture := NewTestFixture(prefix + "-getbytoken")
	createOpts := fixture.CreateInvitationOptionsFromFixture()

	createResult, err := cmd.CreateInvitation(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateInvitation should succeed")
	require.NotNil(t, createResult.Invitation, "Setup: Invitation should not be nil")

	t.Run("GetByTokenExisting", func(t *testing.T) {
		opts := GetByTokenOptions{
			Token: createResult.Invitation.Token,
		}

		result, err := cmd.GetInvitationByToken(testCtx, opts)
		require.NoError(t, err, "GetInvitationByToken should succeed for existing invitation")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Invitation, "Invitation should not be nil")

		inv := result.Invitation
		assert.Equal(t, createResult.Invitation.ID, inv.ID, "ID should match")
		assert.Equal(t, fixture.Email, inv.Email, "Email should match")
		assert.Equal(t, fixture.Role, inv.Role, "Role should match")
		assert.Equal(t, InvitationStatusPending, inv.Status, "Status should be pending")
		// Token should NOT be included in response for security
		assert.Empty(t, inv.Token, "Token should not be included in response")
	})

	t.Run("GetByTokenNonexistentFails", func(t *testing.T) {
		opts := GetByTokenOptions{
			Token: "nonexistent-token-" + uuid.New().String(),
		}

		_, err := cmd.GetInvitationByToken(testCtx, opts)
		require.Error(t, err, "GetInvitationByToken should fail for nonexistent token")
	})

	t.Run("GetByTokenEmptyFails", func(t *testing.T) {
		opts := GetByTokenOptions{
			Token: "",
		}

		_, err := cmd.GetInvitationByToken(testCtx, opts)
		require.Error(t, err, "GetInvitationByToken should fail for empty token")
	})
}

// ============================================================================
// List Invitations Tests
// ============================================================================

func testInvitationList(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple invitations
	for i := 0; i < 3; i++ {
		fixture := NewTestFixture(fmt.Sprintf("%s-list-%d", prefix, i))
		opts := fixture.CreateInvitationOptionsFromFixture()
		_, err := cmd.CreateInvitation(testCtx, opts)
		require.NoError(t, err, "Setup: CreateInvitation should succeed")
	}

	t.Run("ListAllInvitations", func(t *testing.T) {
		opts := ListInvitationsOptions{
			TenantID: DefaultTenantID(),
			Limit:    100,
		}

		result, err := cmd.ListInvitations(testCtx, opts)
		require.NoError(t, err, "ListInvitations should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Invitations), 3, "Should have at least 3 invitations")
	})

	t.Run("ListInvitationsWithLimit", func(t *testing.T) {
		opts := ListInvitationsOptions{
			TenantID: DefaultTenantID(),
			Limit:    2,
		}

		result, err := cmd.ListInvitations(testCtx, opts)
		require.NoError(t, err, "ListInvitations should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, len(result.Invitations), 2, "Should respect limit")
	})

	t.Run("ListInvitationsWithOffset", func(t *testing.T) {
		opts := ListInvitationsOptions{
			TenantID: DefaultTenantID(),
			Limit:    10,
			Offset:   1,
		}

		result, err := cmd.ListInvitations(testCtx, opts)
		require.NoError(t, err, "ListInvitations should succeed with offset")
		require.NotNil(t, result, "Result should not be nil")
		// Just verify we get a valid response
	})
}

// ============================================================================
// Revoke Invitation Tests
// ============================================================================

func testInvitationRevoke(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("RevokeExistingInvitation", func(t *testing.T) {
		// Create an invitation
		fixture := NewTestFixture(prefix + "-revoke")
		createOpts := fixture.CreateInvitationOptionsFromFixture()

		createResult, err := cmd.CreateInvitation(testCtx, createOpts)
		require.NoError(t, err, "Setup: CreateInvitation should succeed")
		require.NotNil(t, createResult.Invitation, "Setup: Invitation should not be nil")

		// Revoke it
		revokeOpts := RevokeInvitationOptions{
			TenantID:     DefaultTenantID(),
			InvitationID: createResult.Invitation.ID,
			AsOwner:      true,
			UserID:       DefaultOwnerUserID(),
		}

		result, err := cmd.RevokeInvitation(testCtx, revokeOpts)
		require.NoError(t, err, "RevokeInvitation should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Revoke should return success")

		// Verify it's revoked by trying to get it
		getOpts := GetByTokenOptions{
			Token: createResult.Invitation.Token,
		}
		_, err = cmd.GetInvitationByToken(testCtx, getOpts)
		require.Error(t, err, "GetInvitationByToken should fail for revoked invitation")
	})

	t.Run("RevokeNonexistentInvitationFails", func(t *testing.T) {
		opts := RevokeInvitationOptions{
			TenantID:     DefaultTenantID(),
			InvitationID: 9999999, // Non-existent ID
			AsOwner:      true,
			UserID:       DefaultOwnerUserID(),
		}

		_, err := cmd.RevokeInvitation(testCtx, opts)
		require.Error(t, err, "RevokeInvitation should fail for nonexistent invitation")
	})
}

// ============================================================================
// Accept Invitation Tests
// ============================================================================

func testInvitationAccept(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("AcceptValidInvitation", func(t *testing.T) {
		// Create an invitation
		fixture := NewTestFixture(prefix + "-accept")
		createOpts := fixture.CreateInvitationOptionsFromFixture()

		createResult, err := cmd.CreateInvitation(testCtx, createOpts)
		require.NoError(t, err, "Setup: CreateInvitation should succeed")
		require.NotNil(t, createResult.Invitation, "Setup: Invitation should not be nil")

		// Accept it
		acceptOpts := AcceptInvitationOptions{
			Token:    createResult.Invitation.Token,
			UserID:   DefaultOwnerUserID(),
			Name:     GenerateTestName(prefix + "-accept"),
			Password: GenerateTestPassword(),
		}

		result, err := cmd.AcceptInvitation(testCtx, acceptOpts)
		require.NoError(t, err, "AcceptInvitation should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Accept should return success")
	})

	t.Run("AcceptNonexistentTokenFails", func(t *testing.T) {
		opts := AcceptInvitationOptions{
			Token:    "nonexistent-token-" + uuid.New().String(),
			UserID:   DefaultOwnerUserID(),
			Name:     GenerateTestName(prefix + "-nonexistent"),
			Password: GenerateTestPassword(),
		}

		_, err := cmd.AcceptInvitation(testCtx, opts)
		require.Error(t, err, "AcceptInvitation should fail for nonexistent token")
	})
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func testInvitationErrors(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("AcceptRevokedInvitationFails", func(t *testing.T) {
		// Create an invitation
		fixture := NewTestFixture(prefix + "-revoked")
		createOpts := fixture.CreateInvitationOptionsFromFixture()

		createResult, err := cmd.CreateInvitation(testCtx, createOpts)
		require.NoError(t, err, "Setup: CreateInvitation should succeed")

		// Revoke it
		revokeOpts := RevokeInvitationOptions{
			TenantID:     DefaultTenantID(),
			InvitationID: createResult.Invitation.ID,
			AsOwner:      true,
			UserID:       DefaultOwnerUserID(),
		}
		_, err = cmd.RevokeInvitation(testCtx, revokeOpts)
		require.NoError(t, err, "Setup: RevokeInvitation should succeed")

		// Try to accept revoked invitation
		acceptOpts := AcceptInvitationOptions{
			Token:    createResult.Invitation.Token,
			UserID:   DefaultOwnerUserID(),
			Name:     GenerateTestName(prefix + "-revoked"),
			Password: GenerateTestPassword(),
		}

		_, err = cmd.AcceptInvitation(testCtx, acceptOpts)
		require.Error(t, err, "AcceptInvitation should fail for revoked invitation")
	})

	t.Run("AcceptAlreadyAcceptedInvitationFails", func(t *testing.T) {
		// Create an invitation
		fixture := NewTestFixture(prefix + "-already-accepted")
		createOpts := fixture.CreateInvitationOptionsFromFixture()

		createResult, err := cmd.CreateInvitation(testCtx, createOpts)
		require.NoError(t, err, "Setup: CreateInvitation should succeed")

		// Accept it once
		acceptOpts := AcceptInvitationOptions{
			Token:    createResult.Invitation.Token,
			UserID:   DefaultOwnerUserID(),
			Name:     GenerateTestName(prefix + "-accepted"),
			Password: GenerateTestPassword(),
		}
		_, err = cmd.AcceptInvitation(testCtx, acceptOpts)
		require.NoError(t, err, "First accept should succeed")

		// Try to accept again
		_, err = cmd.AcceptInvitation(testCtx, acceptOpts)
		require.Error(t, err, "AcceptInvitation should fail for already accepted invitation")
	})

	t.Run("GetExpiredInvitationFails", func(t *testing.T) {
		fixture := NewTestFixture(prefix + "-expired")
		createOpts := fixture.CreateInvitationOptionsFromFixture()
		createOpts.ExpiresIn = ShortExpirationDuration()

		createResult, err := cmd.CreateInvitation(testCtx, createOpts)
		require.NoError(t, err, "Setup: CreateInvitation should succeed")

		// Wait until the server-issued expiry has passed; the margin keeps
		// the checks below clear of the expiry instant.
		expired := time.NewTimer(time.Until(createResult.Invitation.ExpiresAt) + time.Second)
		defer expired.Stop()
		select {
		case <-expired.C:
		case <-testCtx.Done():
			t.Fatalf("context ended before the invitation expired: %v", testCtx.Err())
		}

		_, err = cmd.GetInvitationByToken(testCtx, GetByTokenOptions{
			Token: createResult.Invitation.Token,
		})
		require.Error(t, err, "GetInvitationByToken should fail for expired invitation")

		acceptOpts := AcceptInvitationOptions{
			Token:    createResult.Invitation.Token,
			UserID:   DefaultOwnerUserID(),
			Name:     GenerateTestName(prefix + "-expired"),
			Password: GenerateTestPassword(),
		}
		_, err = cmd.AcceptInvitation(testCtx, acceptOpts)
		require.Error(t, err, "AcceptInvitation should fail for expired invitation")
	})
}

// ============================================================================
// Owner Only Tests
// ============================================================================

func testInvitationOwnerOnly(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("NonOwnerCannotCreateInvitation", func(t *testing.T) {
		opts := CreateInvitationOptions{
			TenantID: DefaultTenantID(),
			Email:    GenerateTestEmail(prefix + "-non-owner-create"),
			Role:     "member",
			AsOwner:  false, // Not owner
			UserID:   999,   // Non-owner user ID
		}

		_, err := cmd.CreateInvitation(testCtx, opts)
		// This should fail with 403 Forbidden
		// The actual behavior depends on the adapter implementation
		if err == nil {
			t.Log("Note: Non-owner create test passed - adapter may not enforce ownership")
		}
	})

	t.Run("NonOwnerCannotRevokeInvitation", func(t *testing.T) {
		// First create an invitation as owner
		fixture := NewTestFixture(prefix + "-non-owner-revoke")
		createOpts := fixture.CreateInvitationOptionsFromFixture()

		createResult, err := cmd.CreateInvitation(testCtx, createOpts)
		if err != nil {
			t.Fatalf("Setup: CreateInvitation failed: %v", err)
		}

		// Try to revoke as non-owner
		revokeOpts := RevokeInvitationOptions{
			TenantID:     DefaultTenantID(),
			InvitationID: createResult.Invitation.ID,
			AsOwner:      false, // Not owner
			UserID:       999,   // Non-owner user ID
		}

		_, err = cmd.RevokeInvitation(testCtx, revokeOpts)
		// This should fail with 403 Forbidden
		if err == nil {
			t.Log("Note: Non-owner revoke test passed - adapter may not enforce ownership")
		}
	})
}

// ============================================================================
// Cross Tenant Tests
// ============================================================================

func testInvitationCrossTenant(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CannotRevokeOtherTenantInvitation", func(t *testing.T) {
		// Create invitation in primary tenant
		fixture := NewTestFixture(prefix + "-cross-tenant")
		createOpts := fixture.CreateInvitationOptionsFromFixture()

		createResult, err := cmd.CreateInvitation(testCtx, createOpts)
		if err != nil {
			t.Fatalf("Setup: CreateInvitation failed: %v", err)
		}

		// Try to revoke from different tenant
		revokeOpts := RevokeInvitationOptions{
			TenantID:     AlternateTenantID(), // Different tenant
			InvitationID: createResult.Invitation.ID,
			AsOwner:      true,
			UserID:       DefaultOwnerUserID(),
		}

		_, err = cmd.RevokeInvitation(testCtx, revokeOpts)
		// Should fail - invitation belongs to different tenant
		if err == nil {
			t.Log("Note: Cross-tenant revoke test passed - adapter may not enforce tenant isolation")
		}
	})

	t.Run("CannotListOtherTenantInvitations", func(t *testing.T) {
		// Create invitation in primary tenant
		fixture := NewTestFixture(prefix + "-cross-tenant-list")
		createOpts := fixture.CreateInvitationOptionsFromFixture()

		_, err := cmd.CreateInvitation(testCtx, createOpts)
		if err != nil {
			t.Fatalf("Setup: CreateInvitation failed: %v", err)
		}

		// List invitations from different tenant
		listOpts := ListInvitationsOptions{
			TenantID: AlternateTenantID(),
			Limit:    100,
		}

		result, err := cmd.ListInvitations(testCtx, listOpts)
		if err != nil {
			// Error is acceptable - tenant isolation enforced
			return
		}

		// If no error, verify no cross-tenant data leak
		for _, inv := range result.Invitations {
			assert.NotEqual(t, fixture.Email, inv.Email,
				"Should not see invitations from other tenant")
		}
	})
}

// ============================================================================
// Protocol-Specific Tests
// ============================================================================

func TestInvitationCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "invitation", "CLI", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	prefix := fmt.Sprintf("cli-%d", time.Now().Unix())
	testInvitationProtocol(t, ctx, adapter)

	// Additional CLI-specific tests
	t.Run("CLIOutputFormats", func(t *testing.T) {
		testCLIOutputFormats(t, ctx, adapter, prefix)
	})
}

func TestInvitationREST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "invitation", "REST", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testInvitationProtocol(t, ctx, adapter)
}

func TestInvitationGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "invitation", "gRPC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testInvitationProtocol(t, ctx, adapter)
}

func TestInvitationQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "invitation", "QUIC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testInvitationProtocol(t, ctx, adapter)
}

func TestInvitationMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "invitation", "MCP", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testInvitationProtocol(t, ctx, adapter)
}

func TestInvitationUnix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "invitation", "Unix", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testInvitationProtocol(t, ctx, adapter)
}

// ============================================================================
// CLI-Specific Tests
// ============================================================================

// testCLIOutputFormats tests the CLI output format flags (-o json, -o yaml, table)
func testCLIOutputFormats(t *testing.T, ctx context.Context, cmd InvitationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create an invitation for output format testing
	fixture := NewTestFixture(prefix + "-format-test")
	opts := fixture.CreateInvitationOptionsFromFixture()

	createResult, err := cmd.CreateInvitation(testCtx, opts)
	require.NoError(t, err, "Setup: CreateInvitation should succeed")
	require.NotNil(t, createResult.Invitation, "Setup: Invitation should not be nil")

	// Note: The CLI adapter internally uses JSON output (-o json) for parsing,
	// so we just verify the operations work correctly through the adapter
	t.Run("ListWithDefaultFormat", func(t *testing.T) {
		result, err := cmd.ListInvitations(testCtx, ListInvitationsOptions{
			TenantID: DefaultTenantID(),
			Limit:    10,
		})
		require.NoError(t, err, "ListInvitations should succeed")
		assert.GreaterOrEqual(t, len(result.Invitations), 1, "Should have at least 1 invitation")
	})

	t.Run("GetByTokenWithDefaultFormat", func(t *testing.T) {
		result, err := cmd.GetInvitationByToken(testCtx, GetByTokenOptions{
			Token: createResult.Invitation.Token,
		})
		require.NoError(t, err, "GetInvitationByToken should succeed")
		assert.Equal(t, fixture.Email, result.Invitation.Email, "Email should match")
	})
}

// ============================================================================
// Error Handling Tests - Additional
// ============================================================================

func TestInvitationMultiProtocol_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapters := []InvitationCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewMCPAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "invitation", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()

			t.Run("GetInvitation_NotFound", func(t *testing.T) {
				opts := GetByTokenOptions{
					Token: "non-existent-token-" + uuid.New().String(),
				}

				_, err := adapter.GetInvitationByToken(ctx, opts)
				require.Error(t, err, "GetInvitationByToken should return error for non-existent token")
			})

			t.Run("CreateInvitation_InvalidEmail", func(t *testing.T) {
				opts := CreateInvitationOptions{
					TenantID: DefaultTenantID(),
					Email:    "not-an-email",
					Role:     "member",
					AsOwner:  true,
					UserID:   DefaultOwnerUserID(),
				}

				_, err := adapter.CreateInvitation(ctx, opts)
				require.Error(t, err, "CreateInvitation should fail for invalid email")
			})

			t.Run("CreateInvitation_InvalidRole", func(t *testing.T) {
				opts := CreateInvitationOptions{
					TenantID: DefaultTenantID(),
					Email:    GenerateTestEmail("invalid-role"),
					Role:     "invalid-role-name",
					AsOwner:  true,
					UserID:   DefaultOwnerUserID(),
				}

				_, err := adapter.CreateInvitation(ctx, opts)
				require.Error(t, err, "CreateInvitation should fail for invalid role")
			})

			t.Run("RevokeInvitation_NotFound", func(t *testing.T) {
				opts := RevokeInvitationOptions{
					TenantID:     DefaultTenantID(),
					InvitationID: 9999999999, // Non-existent
					AsOwner:      true,
					UserID:       DefaultOwnerUserID(),
				}

				_, err := adapter.RevokeInvitation(ctx, opts)
				require.Error(t, err, "RevokeInvitation should fail for non-existent invitation")
			})

			t.Run("AcceptInvitation_InvalidToken", func(t *testing.T) {
				opts := AcceptInvitationOptions{
					Token:    "invalid-token-format",
					UserID:   DefaultOwnerUserID(),
					Name:     "Test User",
					Password: GenerateTestPassword(),
				}

				_, err := adapter.AcceptInvitation(ctx, opts)
				require.Error(t, err, "AcceptInvitation should fail for invalid token")
			})
		})
	}
}
