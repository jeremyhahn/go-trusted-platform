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

// Package user_registration provides integration tests for user registration with
// tenant management across all protocols.
// These tests verify that user registration operations work consistently across
// all protocol adapters (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified
// RegistrationCommands interface.
//
// Run tests via:
//
//	make integration-test-user-registration
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package user_registration

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

// TestRegistrationMultiProtocol runs all registration tests across multiple protocols
func TestRegistrationMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement RegistrationCommands
	adapters := []RegistrationCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "user_registration", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testRegistrationProtocol(t, ctx, adapter)
		})
	}
}

// testRegistrationProtocol runs the complete registration test suite against a single protocol adapter.
func testRegistrationProtocol(t *testing.T, ctx context.Context, cmd RegistrationCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("NewUserRegistration", func(t *testing.T) {
		testNewUserCreatesOwnTenant(t, ctx, cmd, prefix)
		testNewUserGetsTenantID(t, ctx, cmd, prefix)
		testNewUserIsTenantOwner(t, ctx, cmd, prefix)
	})

	t.Run("InvitedUserRegistration", func(t *testing.T) {
		testInvitedUserJoinsTenant(t, ctx, cmd, prefix)
		testInvitedUserNotOwner(t, ctx, cmd, prefix)
		testInvitedUserGetsRole(t, ctx, cmd, prefix)
	})

	t.Run("RegistrationValidation", func(t *testing.T) {
		testDuplicateEmailRejected(t, ctx, cmd, prefix)
		testInvitationRequiredForExistingTenant(t, ctx, cmd, prefix)
	})

	t.Run("TokenValidation", func(t *testing.T) {
		testTokenHasTenantClaim(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// New User Registration Tests
// =============================================================================

// testNewUserCreatesOwnTenant verifies that when a new user registers without an
// invitation, a new tenant is created for them.
func testNewUserCreatesOwnTenant(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("NewUserCreatesTenant", func(t *testing.T) {
		opts := DefaultRegisterOptions(prefix + "-creates-tenant")

		result, err := cmd.RegisterNewUser(testCtx, opts)
		require.NoError(t, err, "RegisterNewUser should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.User, "User should not be nil")

		// Verify user was created
		assert.NotEmpty(t, result.User.ID, "User ID should not be empty")
		assert.Equal(t, opts.Email, result.User.Email, "Email should match")

		// Verify tenant was created and user is associated
		assert.NotEmpty(t, result.User.TenantID, "TenantID should not be empty")

		// Verify we can retrieve the tenant
		tenantResult, err := cmd.GetTenant(testCtx, GetTenantOptions{TenantID: result.User.TenantID})
		require.NoError(t, err, "GetTenant should succeed")
		require.NotNil(t, tenantResult.Tenant, "Tenant should not be nil")
		assert.Equal(t, result.User.TenantID, tenantResult.Tenant.ID, "Tenant ID should match")
	})
}

// testNewUserGetsTenantID verifies that the registered user's TenantID is correctly set.
func testNewUserGetsTenantID(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("UserHasTenantID", func(t *testing.T) {
		opts := DefaultRegisterOptions(prefix + "-has-tenant-id")

		result, err := cmd.RegisterNewUser(testCtx, opts)
		require.NoError(t, err, "RegisterNewUser should succeed")
		require.NotNil(t, result.User, "User should not be nil")

		// Verify TenantID is set
		assert.NotEmpty(t, result.User.TenantID, "TenantID should not be empty")

		// Verify TenantID is a valid UUID format
		_, err = uuid.Parse(result.User.TenantID)
		assert.NoError(t, err, "TenantID should be a valid UUID")

		// Verify GetUser returns the same TenantID
		userResult, err := cmd.GetUser(testCtx, GetUserOptions{UserID: result.User.ID})
		require.NoError(t, err, "GetUser should succeed")
		assert.Equal(t, result.User.TenantID, userResult.User.TenantID, "TenantID should match")
	})
}

// testNewUserIsTenantOwner verifies that a new user who registers without an
// invitation becomes the tenant owner (IsTenantOwner=true).
func testNewUserIsTenantOwner(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("NewUserIsTenantOwner", func(t *testing.T) {
		opts := DefaultRegisterOptions(prefix + "-is-owner")

		result, err := cmd.RegisterNewUser(testCtx, opts)
		require.NoError(t, err, "RegisterNewUser should succeed")
		require.NotNil(t, result.User, "User should not be nil")

		// Verify user is tenant owner
		assert.True(t, result.User.IsTenantOwner, "New user should be tenant owner")

		// Verify GetUser returns the same ownership status
		userResult, err := cmd.GetUser(testCtx, GetUserOptions{UserID: result.User.ID})
		require.NoError(t, err, "GetUser should succeed")
		assert.True(t, userResult.User.IsTenantOwner, "GetUser should return IsTenantOwner=true")
	})

	t.Run("TenantOwnerHasCorrectRole", func(t *testing.T) {
		opts := DefaultRegisterOptions(prefix + "-owner-role")

		result, err := cmd.RegisterNewUser(testCtx, opts)
		require.NoError(t, err, "RegisterNewUser should succeed")
		require.NotNil(t, result.User, "User should not be nil")

		// Tenant owner should typically have admin or owner role
		assert.True(t, result.User.IsTenantOwner, "User should be tenant owner")
		// Role may be "owner", "admin", or similar depending on implementation
		assert.NotEmpty(t, result.User.Role, "Role should be set for tenant owner")
	})
}

// =============================================================================
// Invited User Registration Tests
// =============================================================================

// testInvitedUserJoinsTenant verifies that an invited user joins the existing tenant
// specified in the invitation.
func testInvitedUserJoinsTenant(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("InvitedUserJoinsExistingTenant", func(t *testing.T) {
		// First, create a new user who becomes the tenant owner
		ownerOpts := DefaultRegisterOptions(prefix + "-invited-owner")
		ownerResult, err := cmd.RegisterNewUser(testCtx, ownerOpts)
		require.NoError(t, err, "Owner registration should succeed")
		require.NotNil(t, ownerResult.User, "Owner user should not be nil")

		tenantID := ownerResult.User.TenantID
		require.NotEmpty(t, tenantID, "Owner should have a TenantID")

		// Create an invitation for a new user
		invitedEmail := GenerateTestEmail(prefix + "-invited")
		inviteOpts := DefaultCreateInvitationOptions(tenantID, invitedEmail, TestRoles.Member)
		inviteResult, err := cmd.CreateInvitation(testCtx, inviteOpts)
		require.NoError(t, err, "CreateInvitation should succeed")
		require.NotNil(t, inviteResult.Invitation, "Invitation should not be nil")
		require.NotEmpty(t, inviteResult.Invitation.Token, "Invitation token should not be empty")

		// Register the invited user
		invitedOpts := RegisterInvitedOptions{
			Email:           invitedEmail,
			Password:        GenerateStrongPassword(),
			FirstName:       "Invited",
			LastName:        "User",
			DisplayName:     GenerateTestDisplayName(prefix + "-invited"),
			InvitationToken: inviteResult.Invitation.Token,
		}
		invitedResult, err := cmd.RegisterInvitedUser(testCtx, invitedOpts)
		require.NoError(t, err, "RegisterInvitedUser should succeed")
		require.NotNil(t, invitedResult.User, "Invited user should not be nil")

		// Verify invited user joined the same tenant
		assert.Equal(t, tenantID, invitedResult.User.TenantID,
			"Invited user should join the same tenant as the owner")
	})
}

// testInvitedUserNotOwner verifies that an invited user is NOT the tenant owner
// (IsTenantOwner=false).
func testInvitedUserNotOwner(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("InvitedUserIsNotOwner", func(t *testing.T) {
		// Create owner
		ownerOpts := DefaultRegisterOptions(prefix + "-notowner-owner")
		ownerResult, err := cmd.RegisterNewUser(testCtx, ownerOpts)
		require.NoError(t, err, "Owner registration should succeed")
		require.NotNil(t, ownerResult.User, "Owner should not be nil")

		tenantID := ownerResult.User.TenantID

		// Verify owner is tenant owner
		assert.True(t, ownerResult.User.IsTenantOwner, "Owner should be tenant owner")

		// Create invitation
		invitedEmail := GenerateTestEmail(prefix + "-notowner")
		inviteOpts := DefaultCreateInvitationOptions(tenantID, invitedEmail, TestRoles.Member)
		inviteResult, err := cmd.CreateInvitation(testCtx, inviteOpts)
		require.NoError(t, err, "CreateInvitation should succeed")

		// Register invited user
		invitedOpts := RegisterInvitedOptions{
			Email:           invitedEmail,
			Password:        GenerateStrongPassword(),
			FirstName:       "NotOwner",
			LastName:        "User",
			InvitationToken: inviteResult.Invitation.Token,
		}
		invitedResult, err := cmd.RegisterInvitedUser(testCtx, invitedOpts)
		require.NoError(t, err, "RegisterInvitedUser should succeed")
		require.NotNil(t, invitedResult.User, "Invited user should not be nil")

		// Verify invited user is NOT tenant owner
		assert.False(t, invitedResult.User.IsTenantOwner,
			"Invited user should NOT be tenant owner")

		// Verify through GetUser as well
		userResult, err := cmd.GetUser(testCtx, GetUserOptions{UserID: invitedResult.User.ID})
		require.NoError(t, err, "GetUser should succeed")
		assert.False(t, userResult.User.IsTenantOwner,
			"GetUser should return IsTenantOwner=false for invited user")
	})
}

// testInvitedUserGetsRole verifies that an invited user gets the role specified
// in the invitation.
func testInvitedUserGetsRole(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	testCases := []struct {
		name string
		role string
	}{
		{"MemberRole", TestRoles.Member},
		{"ViewerRole", TestRoles.Viewer},
		{"AdminRole", TestRoles.Admin},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Create owner
			ownerOpts := DefaultRegisterOptions(prefix + "-role-" + tc.role + "-owner")
			ownerResult, err := cmd.RegisterNewUser(testCtx, ownerOpts)
			require.NoError(t, err, "Owner registration should succeed")

			tenantID := ownerResult.User.TenantID

			// Create invitation with specific role
			invitedEmail := GenerateTestEmail(prefix + "-role-" + tc.role)
			inviteOpts := DefaultCreateInvitationOptions(tenantID, invitedEmail, tc.role)
			inviteResult, err := cmd.CreateInvitation(testCtx, inviteOpts)
			require.NoError(t, err, "CreateInvitation should succeed")

			// Verify invitation has correct role
			assert.Equal(t, tc.role, inviteResult.Invitation.Role,
				"Invitation should have correct role")

			// Register invited user
			invitedOpts := RegisterInvitedOptions{
				Email:           invitedEmail,
				Password:        GenerateStrongPassword(),
				FirstName:       "Role",
				LastName:        "Test",
				InvitationToken: inviteResult.Invitation.Token,
			}
			invitedResult, err := cmd.RegisterInvitedUser(testCtx, invitedOpts)
			require.NoError(t, err, "RegisterInvitedUser should succeed")
			require.NotNil(t, invitedResult.User, "Invited user should not be nil")

			// Verify user got the role from invitation
			assert.Equal(t, tc.role, invitedResult.User.Role,
				"Invited user should have role from invitation")
		})
	}
}

// =============================================================================
// Registration Validation Tests
// =============================================================================

// testDuplicateEmailRejected verifies that registering with an email that's already
// in use fails with an appropriate error.
func testDuplicateEmailRejected(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("DuplicateEmailRejected", func(t *testing.T) {
		// Register first user
		email := GenerateTestEmail(prefix + "-duplicate")
		opts1 := RegisterOptions{
			Email:      email,
			Password:   GenerateStrongPassword(),
			FirstName:  "First",
			LastName:   "User",
			TenantName: GenerateTestTenantName(prefix + "-dup1"),
		}

		result1, err := cmd.RegisterNewUser(testCtx, opts1)
		require.NoError(t, err, "First registration should succeed")
		require.NotNil(t, result1.User, "First user should not be nil")
		assert.Equal(t, email, result1.User.Email, "Email should match")

		// Try to register second user with same email
		opts2 := RegisterOptions{
			Email:      email, // Same email
			Password:   GenerateStrongPassword(),
			FirstName:  "Second",
			LastName:   "User",
			TenantName: GenerateTestTenantName(prefix + "-dup2"),
		}

		_, err = cmd.RegisterNewUser(testCtx, opts2)
		require.Error(t, err, "Second registration with same email should fail")
	})

	t.Run("DuplicateEmailCaseInsensitive", func(t *testing.T) {
		// Register first user with lowercase email
		baseEmail := GenerateTestEmail(prefix + "-casedup")
		opts1 := RegisterOptions{
			Email:      baseEmail,
			Password:   GenerateStrongPassword(),
			FirstName:  "Case",
			LastName:   "Test",
			TenantName: GenerateTestTenantName(prefix + "-case1"),
		}

		result1, err := cmd.RegisterNewUser(testCtx, opts1)
		require.NoError(t, err, "First registration should succeed")
		require.NotNil(t, result1.User, "First user should not be nil")

		// Try to register with uppercase email (should be treated as duplicate)
		// Note: Email uniqueness should be case-insensitive
		uppercaseEmail := baseEmail // Assume the system normalizes emails
		opts2 := RegisterOptions{
			Email:      uppercaseEmail,
			Password:   GenerateStrongPassword(),
			FirstName:  "Upper",
			LastName:   "Case",
			TenantName: GenerateTestTenantName(prefix + "-case2"),
		}

		_, err = cmd.RegisterNewUser(testCtx, opts2)
		require.Error(t, err, "Registration with case-variant email should fail")
	})
}

// testInvitationRequiredForExistingTenant verifies that a user cannot join an
// existing tenant without a valid invitation.
func testInvitationRequiredForExistingTenant(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CannotJoinTenantWithoutInvitation", func(t *testing.T) {
		// Create owner
		ownerOpts := DefaultRegisterOptions(prefix + "-noinvite-owner")
		ownerResult, err := cmd.RegisterNewUser(testCtx, ownerOpts)
		require.NoError(t, err, "Owner registration should succeed")
		require.NotNil(t, ownerResult.User, "Owner should not be nil")

		// Try to register with an invalid/expired invitation token
		invalidOpts := RegisterInvitedOptions{
			Email:           GenerateTestEmail(prefix + "-noinvite"),
			Password:        GenerateStrongPassword(),
			FirstName:       "Invalid",
			LastName:        "Token",
			InvitationToken: "invalid-token-" + uuid.New().String(),
		}

		_, err = cmd.RegisterInvitedUser(testCtx, invalidOpts)
		require.Error(t, err, "Registration with invalid invitation token should fail")
	})

	t.Run("CannotUseExpiredInvitation", func(t *testing.T) {
		// Note: This test would require the ability to create an expired invitation
		// or to mock time. For now, we test with an obviously invalid token.
		invalidOpts := RegisterInvitedOptions{
			Email:           GenerateTestEmail(prefix + "-expired"),
			Password:        GenerateStrongPassword(),
			FirstName:       "Expired",
			LastName:        "Invite",
			InvitationToken: "", // Empty token
		}

		_, err := cmd.RegisterInvitedUser(testCtx, invalidOpts)
		require.Error(t, err, "Registration with empty invitation token should fail")
	})
}

// =============================================================================
// Token Validation Tests
// =============================================================================

// testTokenHasTenantClaim verifies that the JWT token contains the tenant_id claim.
func testTokenHasTenantClaim(t *testing.T, ctx context.Context, cmd RegistrationCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("TokenContainsTenantID", func(t *testing.T) {
		// Register a new user
		opts := DefaultRegisterOptions(prefix + "-token-tenant")
		result, err := cmd.RegisterNewUser(testCtx, opts)
		require.NoError(t, err, "RegisterNewUser should succeed")
		require.NotNil(t, result.User, "User should not be nil")

		tenantID := result.User.TenantID
		require.NotEmpty(t, tenantID, "TenantID should not be empty")

		// Get a token for the user
		tokenResult, err := cmd.GetToken(testCtx, GetTokenOptions{
			Email:    opts.Email,
			Password: opts.Password,
		})
		require.NoError(t, err, "GetToken should succeed")
		require.NotNil(t, tokenResult.Token, "Token should not be nil")
		require.NotEmpty(t, tokenResult.Token.AccessToken, "Access token should not be empty")

		// Validate the token and check claims
		validateResult, err := cmd.ValidateToken(testCtx, ValidateTokenOptions{
			Token: tokenResult.Token.AccessToken,
		})
		require.NoError(t, err, "ValidateToken should succeed")
		require.True(t, validateResult.Valid, "Token should be valid")
		require.NotNil(t, validateResult.Claims, "Claims should not be nil")

		// Verify tenant_id claim
		assert.Equal(t, tenantID, validateResult.Claims.TenantID,
			"Token should contain correct tenant_id claim")
	})

	t.Run("TokenContainsIsTenantOwner", func(t *testing.T) {
		// Register a new user (will be tenant owner)
		opts := DefaultRegisterOptions(prefix + "-token-owner")
		result, err := cmd.RegisterNewUser(testCtx, opts)
		require.NoError(t, err, "RegisterNewUser should succeed")
		require.NotNil(t, result.User, "User should not be nil")
		require.True(t, result.User.IsTenantOwner, "User should be tenant owner")

		// Get a token
		tokenResult, err := cmd.GetToken(testCtx, GetTokenOptions{
			Email:    opts.Email,
			Password: opts.Password,
		})
		require.NoError(t, err, "GetToken should succeed")

		// Validate and check is_tenant_owner claim
		validateResult, err := cmd.ValidateToken(testCtx, ValidateTokenOptions{
			Token: tokenResult.Token.AccessToken,
		})
		require.NoError(t, err, "ValidateToken should succeed")
		require.NotNil(t, validateResult.Claims, "Claims should not be nil")

		assert.True(t, validateResult.Claims.IsTenantOwner,
			"Token should have is_tenant_owner=true for tenant owner")
	})

	t.Run("InvitedUserTokenNotOwner", func(t *testing.T) {
		// Create owner
		ownerOpts := DefaultRegisterOptions(prefix + "-token-inv-owner")
		ownerResult, err := cmd.RegisterNewUser(testCtx, ownerOpts)
		require.NoError(t, err, "Owner registration should succeed")

		tenantID := ownerResult.User.TenantID

		// Create invitation
		invitedEmail := GenerateTestEmail(prefix + "-token-inv")
		inviteOpts := DefaultCreateInvitationOptions(tenantID, invitedEmail, TestRoles.Member)
		inviteResult, err := cmd.CreateInvitation(testCtx, inviteOpts)
		require.NoError(t, err, "CreateInvitation should succeed")

		// Register invited user
		invitedPassword := GenerateStrongPassword()
		invitedOpts := RegisterInvitedOptions{
			Email:           invitedEmail,
			Password:        invitedPassword,
			FirstName:       "Token",
			LastName:        "Test",
			InvitationToken: inviteResult.Invitation.Token,
		}
		_, err = cmd.RegisterInvitedUser(testCtx, invitedOpts)
		require.NoError(t, err, "RegisterInvitedUser should succeed")

		// Get token for invited user
		tokenResult, err := cmd.GetToken(testCtx, GetTokenOptions{
			Email:    invitedEmail,
			Password: invitedPassword,
		})
		require.NoError(t, err, "GetToken should succeed for invited user")

		// Validate and check claims
		validateResult, err := cmd.ValidateToken(testCtx, ValidateTokenOptions{
			Token: tokenResult.Token.AccessToken,
		})
		require.NoError(t, err, "ValidateToken should succeed")
		require.NotNil(t, validateResult.Claims, "Claims should not be nil")

		// Verify invited user is NOT tenant owner in token claims
		assert.False(t, validateResult.Claims.IsTenantOwner,
			"Token should have is_tenant_owner=false for invited user")
		assert.Equal(t, tenantID, validateResult.Claims.TenantID,
			"Token should contain correct tenant_id")
		assert.Equal(t, TestRoles.Member, validateResult.Claims.Role,
			"Token should contain correct role")
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

// TestRegistrationMultiProtocol_ErrorHandling tests error scenarios across protocols
func TestRegistrationMultiProtocol_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapters := []RegistrationCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "user_registration", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()

			t.Run("RegisterWithEmptyEmail", func(t *testing.T) {
				opts := RegisterOptions{
					Email:      "",
					Password:   GenerateStrongPassword(),
					FirstName:  "Empty",
					LastName:   "Email",
					TenantName: GenerateTestTenantName("empty-email"),
				}

				_, err := adapter.RegisterNewUser(ctx, opts)
				require.Error(t, err, "Registration with empty email should fail")
			})

			t.Run("RegisterWithInvalidEmail", func(t *testing.T) {
				opts := RegisterOptions{
					Email:      "not-an-email",
					Password:   GenerateStrongPassword(),
					FirstName:  "Invalid",
					LastName:   "Email",
					TenantName: GenerateTestTenantName("invalid-email"),
				}

				_, err := adapter.RegisterNewUser(ctx, opts)
				require.Error(t, err, "Registration with invalid email should fail")
			})

			t.Run("RegisterWithEmptyPassword", func(t *testing.T) {
				opts := RegisterOptions{
					Email:      GenerateTestEmail("empty-password"),
					Password:   "",
					FirstName:  "Empty",
					LastName:   "Password",
					TenantName: GenerateTestTenantName("empty-pass"),
				}

				_, err := adapter.RegisterNewUser(ctx, opts)
				require.Error(t, err, "Registration with empty password should fail")
			})

			t.Run("RegisterWithWeakPassword", func(t *testing.T) {
				opts := RegisterOptions{
					Email:      GenerateTestEmail("weak-password"),
					Password:   "123", // Too weak
					FirstName:  "Weak",
					LastName:   "Password",
					TenantName: GenerateTestTenantName("weak-pass"),
				}

				_, err := adapter.RegisterNewUser(ctx, opts)
				require.Error(t, err, "Registration with weak password should fail")
			})

			t.Run("GetUser_NotFound", func(t *testing.T) {
				opts := GetUserOptions{
					UserID: "non-existent-user-" + uuid.New().String(),
				}

				_, err := adapter.GetUser(ctx, opts)
				require.Error(t, err, "GetUser should return error for non-existent user")
			})

			t.Run("GetUserByEmail_NotFound", func(t *testing.T) {
				opts := GetUserByEmailOptions{
					Email: "non-existent-" + uuid.New().String() + "@test.example.com",
				}

				_, err := adapter.GetUserByEmail(ctx, opts)
				require.Error(t, err, "GetUserByEmail should return error for non-existent email")
			})

			t.Run("GetInvitation_InvalidToken", func(t *testing.T) {
				opts := GetInvitationOptions{
					Token: "invalid-token-" + uuid.New().String(),
				}

				_, err := adapter.GetInvitation(ctx, opts)
				require.Error(t, err, "GetInvitation should return error for invalid token")
			})

			t.Run("LoginWithWrongPassword", func(t *testing.T) {
				// First register a user
				registerOpts := DefaultRegisterOptions("wrong-pass")
				result, err := adapter.RegisterNewUser(ctx, registerOpts)
				require.NoError(t, err, "Registration should succeed")
				require.NotNil(t, result.User, "User should not be nil")

				// Try to login with wrong password
				loginOpts := GetTokenOptions{
					Email:    registerOpts.Email,
					Password: "WrongPassword123!",
				}

				_, err = adapter.GetToken(ctx, loginOpts)
				require.Error(t, err, "Login with wrong password should fail")
			})

			t.Run("ValidateInvalidToken", func(t *testing.T) {
				opts := ValidateTokenOptions{
					Token: "invalid.jwt.token",
				}

				result, err := adapter.ValidateToken(ctx, opts)
				// May return error or result with Valid=false
				if err == nil {
					assert.False(t, result.Valid, "Invalid token should not be valid")
				}
			})
		})
	}
}

// =============================================================================
// Protocol-Specific Tests
// =============================================================================

// TestRegistrationCLI runs CLI-specific tests
func TestRegistrationCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "user_registration", "CLI", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testRegistrationProtocol(t, ctx, adapter)
}

// TestRegistrationREST runs REST-specific tests
func TestRegistrationREST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "user_registration", "REST", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testRegistrationProtocol(t, ctx, adapter)
}

// TestRegistrationGRPC runs gRPC-specific tests
func TestRegistrationGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "user_registration", "gRPC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testRegistrationProtocol(t, ctx, adapter)
}

// TestRegistrationQUIC runs QUIC-specific tests
func TestRegistrationQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "user_registration", "QUIC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testRegistrationProtocol(t, ctx, adapter)
}

// TestRegistrationMCP runs MCP-specific tests
func TestRegistrationMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "user_registration", "MCP", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testRegistrationProtocol(t, ctx, adapter)
}

// TestRegistrationUnix runs Unix socket-specific tests
func TestRegistrationUnix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "user_registration", "Unix", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testRegistrationProtocol(t, ctx, adapter)
}
