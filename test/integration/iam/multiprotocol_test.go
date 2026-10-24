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

package iam

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// The role permissions the suite grants. go-qrdb's role store accepts only
// permissions in its registry (pkg/role validatePermissions returns
// InvalidPermissionError otherwise), and the pinned registry names the
// secrets vocabulary but no device:* scope, so the suite uses secrets:*.
const (
	permSecretsRead   = "secrets:read"
	permSecretsWrite  = "secrets:write"
	permSecretsDelete = "secrets:delete"
)

// TestIAMMultiProtocol runs all IAM tests across multiple protocols
func TestIAMMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapters := []IAMCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "iam", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // capture range variable
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown failed: %v", err)
				}
			}()

			// Run all test suites
			t.Run("UserCRUD", func(t *testing.T) {
				testUserCRUD(t, ctx, adapter)
			})
			t.Run("GroupCRUD", func(t *testing.T) {
				testGroupCRUD(t, ctx, adapter)
			})
			t.Run("RoleCRUD", func(t *testing.T) {
				testRoleCRUD(t, ctx, adapter)
			})
			t.Run("PermissionCheck", func(t *testing.T) {
				testPermissionCheck(t, ctx, adapter)
			})
			t.Run("RoleHierarchy", func(t *testing.T) {
				testRoleHierarchy(t, ctx, adapter)
			})
		})
	}
}

// ============================================================================
// User CRUD Tests
// ============================================================================

func testUserCRUD(t *testing.T, ctx context.Context, adapter IAMCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("CreateUser", func(t *testing.T) {
		opts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID),
			Name:     "Test User " + testID,
		}

		result, err := adapter.CreateUser(ctx, opts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		if result.User == nil {
			t.Fatal("CreateUser returned nil user")
		}

		if result.User.Email != opts.Email {
			t.Errorf("User email mismatch: got %s, want %s", result.User.Email, opts.Email)
		}

		if result.User.Name != opts.Name {
			t.Errorf("User name mismatch: got %s, want %s", result.User.Name, opts.Name)
		}
	})

	t.Run("GetUser", func(t *testing.T) {
		// First create a user
		createOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-get"),
			Name:     "Test User Get " + testID,
		}

		createResult, err := adapter.CreateUser(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Now get the user
		getOpts := GetUserOptions{
			TenantID: tenantID,
			UserID:   createResult.User.ID,
		}

		getResult, err := adapter.GetUser(ctx, getOpts)
		if err != nil {
			t.Fatalf("GetUser failed: %v", err)
		}

		if getResult.User == nil {
			t.Fatal("GetUser returned nil user")
		}

		if getResult.User.ID != createResult.User.ID {
			t.Errorf("User ID mismatch: got %s, want %s", getResult.User.ID, createResult.User.ID)
		}

		if getResult.User.Email != createOpts.Email {
			t.Errorf("User email mismatch: got %s, want %s", getResult.User.Email, createOpts.Email)
		}
	})

	t.Run("UpdateUser", func(t *testing.T) {
		// First create a user
		createOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-update"),
			Name:     "Test User Original",
		}

		createResult, err := adapter.CreateUser(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Update the user
		updateOpts := UpdateUserOptions{
			TenantID: tenantID,
			UserID:   createResult.User.ID,
			Name:     "Test User Updated",
		}

		updateResult, err := adapter.UpdateUser(ctx, updateOpts)
		if err != nil {
			t.Fatalf("UpdateUser failed: %v", err)
		}

		if updateResult.User == nil {
			t.Fatal("UpdateUser returned nil user")
		}

		if updateResult.User.Name != updateOpts.Name {
			t.Errorf("User name not updated: got %s, want %s", updateResult.User.Name, updateOpts.Name)
		}
	})

	t.Run("DeleteUser", func(t *testing.T) {
		// First create a user
		createOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-delete"),
			Name:     "Test User Delete",
		}

		createResult, err := adapter.CreateUser(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Delete the user
		deleteOpts := DeleteUserOptions{
			TenantID: tenantID,
			UserID:   createResult.User.ID,
		}

		deleteResult, err := adapter.DeleteUser(ctx, deleteOpts)
		if err != nil {
			t.Fatalf("DeleteUser failed: %v", err)
		}

		if !deleteResult.Success {
			t.Error("DeleteUser did not return success")
		}

		// Verify user is deleted
		getOpts := GetUserOptions{
			TenantID: tenantID,
			UserID:   createResult.User.ID,
		}

		_, err = adapter.GetUser(ctx, getOpts)
		if err == nil {
			t.Error("GetUser should fail for deleted user")
		}
	})

	t.Run("ListUsers", func(t *testing.T) {
		// Create multiple users
		for i := 0; i < 3; i++ {
			createOpts := CreateUserOptions{
				TenantID: tenantID,
				Email:    GenerateTestEmail(testID + "-list-" + string(rune('a'+i))),
				Name:     "Test User List " + testID,
			}

			_, err := adapter.CreateUser(ctx, createOpts)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}
		}

		// List users
		listOpts := ListUsersOptions{
			TenantID: tenantID,
			Limit:    10,
		}

		listResult, err := adapter.ListUsers(ctx, listOpts)
		if err != nil {
			t.Fatalf("ListUsers failed: %v", err)
		}

		if len(listResult.Users) == 0 {
			t.Error("ListUsers returned no users")
		}
	})
}

// ============================================================================
// Group CRUD Tests
// ============================================================================

func testGroupCRUD(t *testing.T, ctx context.Context, adapter IAMCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("CreateGroup", func(t *testing.T) {
		opts := CreateGroupOptions{
			TenantID:    tenantID,
			ID:          GenerateTestGroupID(testID),
			Name:        "Test Group " + testID,
			Description: "Test group description",
		}

		result, err := adapter.CreateGroup(ctx, opts)
		if err != nil {
			t.Fatalf("CreateGroup failed: %v", err)
		}

		if result.Group == nil {
			t.Fatal("CreateGroup returned nil group")
		}

		if result.Group.ID != opts.ID {
			t.Errorf("Group ID mismatch: got %s, want %s", result.Group.ID, opts.ID)
		}

		if result.Group.Name != opts.Name {
			t.Errorf("Group name mismatch: got %s, want %s", result.Group.Name, opts.Name)
		}
	})

	t.Run("GetGroup", func(t *testing.T) {
		// First create a group
		createOpts := CreateGroupOptions{
			TenantID:    tenantID,
			ID:          GenerateTestGroupID(testID + "-get"),
			Name:        "Test Group Get " + testID,
			Description: "Test group for get operation",
		}

		createResult, err := adapter.CreateGroup(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateGroup failed: %v", err)
		}

		// Now get the group
		getOpts := GetGroupOptions{
			TenantID: tenantID,
			GroupID:  createResult.Group.ID,
		}

		getResult, err := adapter.GetGroup(ctx, getOpts)
		if err != nil {
			t.Fatalf("GetGroup failed: %v", err)
		}

		if getResult.Group == nil {
			t.Fatal("GetGroup returned nil group")
		}

		if getResult.Group.ID != createResult.Group.ID {
			t.Errorf("Group ID mismatch: got %s, want %s", getResult.Group.ID, createResult.Group.ID)
		}
	})

	t.Run("UpdateGroup", func(t *testing.T) {
		// First create a group
		createOpts := CreateGroupOptions{
			TenantID:    tenantID,
			ID:          GenerateTestGroupID(testID + "-update"),
			Name:        "Test Group Original",
			Description: "Original description",
		}

		createResult, err := adapter.CreateGroup(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateGroup failed: %v", err)
		}

		// Update the group
		updateOpts := UpdateGroupOptions{
			TenantID:    tenantID,
			GroupID:     createResult.Group.ID,
			Name:        "Test Group Updated",
			Description: "Updated description",
		}

		updateResult, err := adapter.UpdateGroup(ctx, updateOpts)
		if err != nil {
			t.Fatalf("UpdateGroup failed: %v", err)
		}

		if updateResult.Group == nil {
			t.Fatal("UpdateGroup returned nil group")
		}

		if updateResult.Group.Name != updateOpts.Name {
			t.Errorf("Group name not updated: got %s, want %s", updateResult.Group.Name, updateOpts.Name)
		}

		if updateResult.Group.Description != updateOpts.Description {
			t.Errorf("Group description not updated: got %s, want %s",
				updateResult.Group.Description, updateOpts.Description)
		}
	})

	t.Run("DeleteGroup", func(t *testing.T) {
		// First create a group
		createOpts := CreateGroupOptions{
			TenantID:    tenantID,
			ID:          GenerateTestGroupID(testID + "-delete"),
			Name:        "Test Group Delete",
			Description: "Test group for deletion",
		}

		createResult, err := adapter.CreateGroup(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateGroup failed: %v", err)
		}

		// Delete the group
		deleteOpts := DeleteGroupOptions{
			TenantID: tenantID,
			GroupID:  createResult.Group.ID,
		}

		deleteResult, err := adapter.DeleteGroup(ctx, deleteOpts)
		if err != nil {
			t.Fatalf("DeleteGroup failed: %v", err)
		}

		if !deleteResult.Success {
			t.Error("DeleteGroup did not return success")
		}

		// Verify group is deleted
		getOpts := GetGroupOptions{
			TenantID: tenantID,
			GroupID:  createResult.Group.ID,
		}

		_, err = adapter.GetGroup(ctx, getOpts)
		if err == nil {
			t.Error("GetGroup should fail for deleted group")
		}
	})

	t.Run("ListGroups", func(t *testing.T) {
		// Create multiple groups
		for i := 0; i < 3; i++ {
			createOpts := CreateGroupOptions{
				TenantID:    tenantID,
				ID:          GenerateTestGroupID(testID + "-list-" + string(rune('a'+i))),
				Name:        "Test Group List " + testID,
				Description: "Test group for listing",
			}

			_, err := adapter.CreateGroup(ctx, createOpts)
			if err != nil {
				t.Fatalf("CreateGroup failed: %v", err)
			}
		}

		// List groups
		listOpts := ListGroupsOptions{
			TenantID: tenantID,
			Limit:    10,
		}

		listResult, err := adapter.ListGroups(ctx, listOpts)
		if err != nil {
			t.Fatalf("ListGroups failed: %v", err)
		}

		if len(listResult.Groups) == 0 {
			t.Error("ListGroups returned no groups")
		}
	})

	t.Run("GroupMembership", func(t *testing.T) {
		// Create a group
		groupOpts := CreateGroupOptions{
			TenantID:    tenantID,
			ID:          GenerateTestGroupID(testID + "-membership"),
			Name:        "Test Group Membership",
			Description: "Test group for membership operations",
		}

		groupResult, err := adapter.CreateGroup(ctx, groupOpts)
		if err != nil {
			t.Fatalf("CreateGroup failed: %v", err)
		}

		// Create a user
		userOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-membership"),
			Name:     "Test User Membership",
		}

		userResult, err := adapter.CreateUser(ctx, userOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Add user to group
		addOpts := AddMemberOptions{
			TenantID: tenantID,
			GroupID:  groupResult.Group.ID,
			UserID:   userResult.User.ID,
		}

		addResult, err := adapter.AddMember(ctx, addOpts)
		if err != nil {
			t.Fatalf("AddMember failed: %v", err)
		}

		if !addResult.Success {
			t.Error("AddMember did not return success")
		}

		// Verify user is in group
		getGroupOpts := GetGroupOptions{
			TenantID: tenantID,
			GroupID:  groupResult.Group.ID,
		}

		getGroupResult, err := adapter.GetGroup(ctx, getGroupOpts)
		if err != nil {
			t.Fatalf("GetGroup failed: %v", err)
		}

		found := false
		for _, member := range getGroupResult.Group.Members {
			if member == userResult.User.ID {
				found = true
				break
			}
		}
		if !found {
			t.Error("User not found in group members")
		}

		// Remove user from group
		removeOpts := RemoveMemberOptions{
			TenantID: tenantID,
			GroupID:  groupResult.Group.ID,
			UserID:   userResult.User.ID,
		}

		removeResult, err := adapter.RemoveMember(ctx, removeOpts)
		if err != nil {
			t.Fatalf("RemoveMember failed: %v", err)
		}

		if !removeResult.Success {
			t.Error("RemoveMember did not return success")
		}
	})
}

// ============================================================================
// Role CRUD Tests
// ============================================================================

func testRoleCRUD(t *testing.T, ctx context.Context, adapter IAMCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("CreateRole", func(t *testing.T) {
		// Roles carry the platform's documented device scopes
		// (docs/device/api-reference-rest.md, Device Endpoints).
		opts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          GenerateTestRoleID(testID),
			Name:        GenerateTestRoleName(testID),
			Description: "Test role description",
			Permissions: []string{permSecretsRead, permSecretsWrite},
		}

		result, err := adapter.CreateRole(ctx, opts)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, opts.ID)

		if result.Role == nil {
			t.Fatal("CreateRole returned nil role")
		}

		if result.Role.ID != opts.ID {
			t.Errorf("Role ID mismatch: got %s, want %s", result.Role.ID, opts.ID)
		}

		if result.Role.Name != opts.Name {
			t.Errorf("Role name mismatch: got %s, want %s", result.Role.Name, opts.Name)
		}
	})

	t.Run("GetRole", func(t *testing.T) {
		// First create a role
		createOpts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          GenerateTestRoleID(testID + "-get"),
			Name:        GenerateTestRoleName(testID + " Get"),
			Description: "Test role for get operation",
			Permissions: []string{permSecretsRead},
		}

		createResult, err := adapter.CreateRole(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, createOpts.ID)

		// Now get the role
		getOpts := GetRoleOptions{
			TenantID: tenantID,
			RoleID:   createResult.Role.ID,
		}

		getResult, err := adapter.GetRole(ctx, getOpts)
		if err != nil {
			t.Fatalf("GetRole failed: %v", err)
		}

		if getResult.Role == nil {
			t.Fatal("GetRole returned nil role")
		}

		if getResult.Role.ID != createResult.Role.ID {
			t.Errorf("Role ID mismatch: got %s, want %s", getResult.Role.ID, createResult.Role.ID)
		}
	})

	t.Run("UpdateRole", func(t *testing.T) {
		// First create a role
		createOpts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          GenerateTestRoleID(testID + "-update"),
			Name:        GenerateTestRoleName(testID + " Original"),
			Description: "Original description",
			Permissions: []string{permSecretsRead},
		}

		createResult, err := adapter.CreateRole(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, createOpts.ID)

		// Update the role
		updateOpts := UpdateRoleOptions{
			TenantID:    tenantID,
			RoleID:      createResult.Role.ID,
			Name:        GenerateTestRoleName(testID + " Updated"),
			Description: "Updated description",
			Permissions: []string{permSecretsRead, permSecretsWrite, permSecretsDelete},
		}

		updateResult, err := adapter.UpdateRole(ctx, updateOpts)
		if err != nil {
			t.Fatalf("UpdateRole failed: %v", err)
		}

		if updateResult.Role == nil {
			t.Fatal("UpdateRole returned nil role")
		}

		if updateResult.Role.Name != updateOpts.Name {
			t.Errorf("Role name not updated: got %s, want %s", updateResult.Role.Name, updateOpts.Name)
		}

		if len(updateResult.Role.Permissions) != len(updateOpts.Permissions) {
			t.Errorf("Role permissions not updated: got %d, want %d",
				len(updateResult.Role.Permissions), len(updateOpts.Permissions))
		}
	})

	t.Run("DeleteRole", func(t *testing.T) {
		// First create a role
		createOpts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          GenerateTestRoleID(testID + "-delete"),
			Name:        GenerateTestRoleName(testID + " Delete"),
			Description: "Test role for deletion",
			Permissions: []string{permSecretsRead},
		}

		createResult, err := adapter.CreateRole(ctx, createOpts)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}

		// Delete the role
		deleteOpts := DeleteRoleOptions{
			TenantID: tenantID,
			RoleID:   createResult.Role.ID,
		}

		deleteResult, err := adapter.DeleteRole(ctx, deleteOpts)
		if err != nil {
			t.Fatalf("DeleteRole failed: %v", err)
		}

		if !deleteResult.Success {
			t.Error("DeleteRole did not return success")
		}

		// Verify role is deleted
		getOpts := GetRoleOptions{
			TenantID: tenantID,
			RoleID:   createResult.Role.ID,
		}

		_, err = adapter.GetRole(ctx, getOpts)
		if err == nil {
			t.Error("GetRole should fail for deleted role")
		}
	})

	t.Run("ListRoles", func(t *testing.T) {
		// Create multiple roles
		for i := 0; i < 3; i++ {
			createOpts := CreateRoleOptions{
				TenantID:    tenantID,
				ID:          GenerateTestRoleID(testID + "-list-" + string(rune('a'+i))),
				Name:        GenerateTestRoleName(testID + " List " + string(rune('a'+i))),
				Description: "Test role for listing",
				Permissions: []string{permSecretsRead},
			}

			_, err := adapter.CreateRole(ctx, createOpts)
			if err != nil {
				t.Fatalf("CreateRole failed: %v", err)
			}
			CleanupRole(t, ctx, adapter, tenantID, createOpts.ID)
		}

		// List roles
		listOpts := ListRolesOptions{
			TenantID: tenantID,
			Limit:    10,
		}

		listResult, err := adapter.ListRoles(ctx, listOpts)
		if err != nil {
			t.Fatalf("ListRoles failed: %v", err)
		}

		if len(listResult.Roles) == 0 {
			t.Error("ListRoles returned no roles")
		}
	})
}

// ============================================================================
// Permission Check Tests
// ============================================================================

func testPermissionCheck(t *testing.T, ctx context.Context, adapter IAMCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("CheckPermission_Allowed", func(t *testing.T) {
		// Create a role with permissions
		roleID := GenerateTestRoleID(testID + "-perm-allow")
		roleOpts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          roleID,
			Name:        GenerateTestRoleName(testID + " Permission Allow"),
			Description: "Test role for permission check",
			Permissions: []string{permSecretsRead, permSecretsWrite},
		}

		_, err := adapter.CreateRole(ctx, roleOpts)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, roleOpts.ID)

		// Create a user with the role
		userOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-perm-allow"),
			Name:     "Test User Permission Allow",
			Roles:    []string{roleID},
		}

		userResult, err := adapter.CreateUser(ctx, userOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		CleanupUser(t, ctx, adapter, tenantID, userResult.User.ID)

		// Check permission
		checkOpts := CheckPermissionOptions{
			TenantID:  tenantID,
			SubjectID: userResult.User.ID,
			Action:    "read",
			Resource:  "secrets",
			Roles:     []string{roleID},
		}

		checkResult, err := adapter.CheckPermission(ctx, checkOpts)
		if err != nil {
			t.Fatalf("CheckPermission failed: %v", err)
		}

		if !checkResult.Allowed {
			t.Error("Permission check should return allowed")
		}
	})

	t.Run("CheckPermission_Denied", func(t *testing.T) {
		// Create a user without any roles
		userOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-perm-deny"),
			Name:     "Test User Permission Deny",
		}

		userResult, err := adapter.CreateUser(ctx, userOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		CleanupUser(t, ctx, adapter, tenantID, userResult.User.ID)

		// Check permission for an action the user doesn't have
		checkOpts := CheckPermissionOptions{
			TenantID:  tenantID,
			SubjectID: userResult.User.ID,
			Action:    "admin",
			Resource:  "system",
		}

		checkResult, err := adapter.CheckPermission(ctx, checkOpts)
		if err != nil {
			// Some implementations may return an error instead of denied
			t.Logf("CheckPermission returned error (may be expected): %v", err)
			return
		}

		if checkResult.Allowed {
			t.Error("Permission check should return denied")
		}
	})
}

// ============================================================================
// Role Hierarchy Tests
// ============================================================================

func testRoleHierarchy(t *testing.T, ctx context.Context, adapter IAMCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("AssignRole", func(t *testing.T) {
		// Create a role
		roleID := GenerateTestRoleID(testID + "-assign")
		roleOpts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          roleID,
			Name:        GenerateTestRoleName(testID + " Assign"),
			Description: "Test role for assignment",
			Permissions: []string{permSecretsRead},
		}

		_, err := adapter.CreateRole(ctx, roleOpts)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, roleOpts.ID)

		// Create a user without roles
		userOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-assign"),
			Name:     "Test User Assign",
		}

		userResult, err := adapter.CreateUser(ctx, userOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		CleanupUser(t, ctx, adapter, tenantID, userResult.User.ID)

		// Assign role to user
		assignOpts := AssignRoleOptions{
			TenantID: tenantID,
			UserID:   userResult.User.ID,
			RoleID:   roleID,
		}

		assignResult, err := adapter.AssignRole(ctx, assignOpts)
		if err != nil {
			t.Fatalf("AssignRole failed: %v", err)
		}

		if !assignResult.Success {
			t.Error("AssignRole did not return success")
		}

		// Verify user has the role
		getOpts := GetUserOptions{
			TenantID: tenantID,
			UserID:   userResult.User.ID,
		}

		getResult, err := adapter.GetUser(ctx, getOpts)
		if err != nil {
			t.Fatalf("GetUser failed: %v", err)
		}

		found := false
		for _, role := range getResult.User.Roles {
			if role == roleID {
				found = true
				break
			}
		}
		if !found {
			t.Error("Role not found in user's roles after assignment")
		}
	})

	t.Run("RevokeRole", func(t *testing.T) {
		// Create a role
		roleID := GenerateTestRoleID(testID + "-revoke")
		roleOpts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          roleID,
			Name:        GenerateTestRoleName(testID + " Revoke"),
			Description: "Test role for revocation",
			Permissions: []string{permSecretsRead},
		}

		_, err := adapter.CreateRole(ctx, roleOpts)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, roleOpts.ID)

		// Create a user with the role
		userOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-revoke"),
			Name:     "Test User Revoke",
			Roles:    []string{roleID},
		}

		userResult, err := adapter.CreateUser(ctx, userOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		CleanupUser(t, ctx, adapter, tenantID, userResult.User.ID)

		// Revoke role from user
		revokeOpts := RevokeRoleOptions{
			TenantID: tenantID,
			UserID:   userResult.User.ID,
			RoleID:   roleID,
		}

		revokeResult, err := adapter.RevokeRole(ctx, revokeOpts)
		if err != nil {
			t.Fatalf("RevokeRole failed: %v", err)
		}

		if !revokeResult.Success {
			t.Error("RevokeRole did not return success")
		}

		// Verify user no longer has the role
		getOpts := GetUserOptions{
			TenantID: tenantID,
			UserID:   userResult.User.ID,
		}

		getResult, err := adapter.GetUser(ctx, getOpts)
		if err != nil {
			t.Fatalf("GetUser failed: %v", err)
		}

		for _, role := range getResult.User.Roles {
			if role == roleID {
				t.Error("Role still found in user's roles after revocation")
				break
			}
		}
	})

	t.Run("MultipleRoles", func(t *testing.T) {
		// Create multiple roles
		role1ID := GenerateTestRoleID(testID + "-multi1")
		role1Opts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          role1ID,
			Name:        GenerateTestRoleName(testID + " Multi 1"),
			Description: "Test role 1 for multiple role assignment",
			Permissions: []string{permSecretsRead},
		}

		_, err := adapter.CreateRole(ctx, role1Opts)
		if err != nil {
			t.Fatalf("CreateRole 1 failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, role1Opts.ID)

		role2ID := GenerateTestRoleID(testID + "-multi2")
		role2Opts := CreateRoleOptions{
			TenantID:    tenantID,
			ID:          role2ID,
			Name:        GenerateTestRoleName(testID + " Multi 2"),
			Description: "Test role 2 for multiple role assignment",
			Permissions: []string{permSecretsWrite},
		}

		_, err = adapter.CreateRole(ctx, role2Opts)
		if err != nil {
			t.Fatalf("CreateRole 2 failed: %v", err)
		}
		CleanupRole(t, ctx, adapter, tenantID, role2Opts.ID)

		// Create a user with both roles
		userOpts := CreateUserOptions{
			TenantID: tenantID,
			Email:    GenerateTestEmail(testID + "-multi"),
			Name:     "Test User Multi Roles",
			Roles:    []string{role1ID, role2ID},
		}

		userResult, err := adapter.CreateUser(ctx, userOpts)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		CleanupUser(t, ctx, adapter, tenantID, userResult.User.ID)

		// Verify user has both roles
		getOpts := GetUserOptions{
			TenantID: tenantID,
			UserID:   userResult.User.ID,
		}

		getResult, err := adapter.GetUser(ctx, getOpts)
		if err != nil {
			t.Fatalf("GetUser failed: %v", err)
		}

		if len(getResult.User.Roles) < 2 {
			t.Errorf("User should have at least 2 roles, got %d", len(getResult.User.Roles))
		}

		foundRole1 := false
		foundRole2 := false
		for _, role := range getResult.User.Roles {
			if role == role1ID {
				foundRole1 = true
			}
			if role == role2ID {
				foundRole2 = true
			}
		}

		if !foundRole1 {
			t.Error("Role 1 not found in user's roles")
		}
		if !foundRole2 {
			t.Error("Role 2 not found in user's roles")
		}
	})
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestIAMMultiProtocol_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapters := []IAMCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewMCPAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "iam", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()

			t.Run("GetUser_NotFound", func(t *testing.T) {
				opts := GetUserOptions{
					TenantID: DefaultTenantID(),
					UserID:   "non-existent-user-" + uuid.New().String()[:8],
				}

				_, err := adapter.GetUser(ctx, opts)
				if err == nil {
					t.Error("GetUser should return error for non-existent user")
				}
			})

			t.Run("GetGroup_NotFound", func(t *testing.T) {
				opts := GetGroupOptions{
					TenantID: DefaultTenantID(),
					GroupID:  "non-existent-group-" + uuid.New().String()[:8],
				}

				_, err := adapter.GetGroup(ctx, opts)
				if err == nil {
					t.Error("GetGroup should return error for non-existent group")
				}
			})

			t.Run("GetRole_NotFound", func(t *testing.T) {
				opts := GetRoleOptions{
					TenantID: DefaultTenantID(),
					RoleID:   "non-existent-role-" + uuid.New().String()[:8],
				}

				_, err := adapter.GetRole(ctx, opts)
				if err == nil {
					t.Error("GetRole should return error for non-existent role")
				}
			})

			t.Run("CreateUser_DuplicateEmail", func(t *testing.T) {
				testID := uuid.New().String()[:8]
				email := GenerateTestEmail(testID + "-dup")

				// Create first user
				opts := CreateUserOptions{
					TenantID: DefaultTenantID(),
					Email:    email,
					Name:     "Test User Dup 1",
				}

				_, err := adapter.CreateUser(ctx, opts)
				if err != nil {
					t.Fatalf("First CreateUser failed: %v", err)
				}

				// Try to create second user with same email
				opts.Name = "Test User Dup 2"
				_, err = adapter.CreateUser(ctx, opts)
				if err == nil {
					t.Error("CreateUser should fail for duplicate email")
				}
			})

			t.Run("CreateGroup_DuplicateID", func(t *testing.T) {
				testID := uuid.New().String()[:8]
				groupID := GenerateTestGroupID(testID + "-dup")

				// Create first group
				opts := CreateGroupOptions{
					TenantID:    DefaultTenantID(),
					ID:          groupID,
					Name:        "Test Group Dup 1",
					Description: "First group",
				}

				_, err := adapter.CreateGroup(ctx, opts)
				if err != nil {
					t.Fatalf("First CreateGroup failed: %v", err)
				}

				// Try to create second group with same ID
				opts.Name = "Test Group Dup 2"
				_, err = adapter.CreateGroup(ctx, opts)
				if err == nil {
					t.Error("CreateGroup should fail for duplicate ID")
				}
			})

			t.Run("CreateRole_DuplicateID", func(t *testing.T) {
				testID := uuid.New().String()[:8]
				roleID := GenerateTestRoleID(testID + "-dup")

				// Create first role
				opts := CreateRoleOptions{
					TenantID:    DefaultTenantID(),
					ID:          roleID,
					Name:        "Test Role Dup 1",
					Description: "First role",
					Permissions: []string{permSecretsRead},
				}

				_, err := adapter.CreateRole(ctx, opts)
				if err != nil {
					t.Fatalf("First CreateRole failed: %v", err)
				}

				// Try to create second role with same ID
				opts.Name = "Test Role Dup 2"
				_, err = adapter.CreateRole(ctx, opts)
				if err == nil {
					t.Error("CreateRole should fail for duplicate ID")
				}
			})

			t.Run("AssignRole_NonExistentRole", func(t *testing.T) {
				testID := uuid.New().String()[:8]

				// Create a user
				userOpts := CreateUserOptions{
					TenantID: DefaultTenantID(),
					Email:    GenerateTestEmail(testID + "-assign-err"),
					Name:     "Test User Assign Error",
				}

				userResult, err := adapter.CreateUser(ctx, userOpts)
				if err != nil {
					t.Fatalf("CreateUser failed: %v", err)
				}

				// Try to assign non-existent role
				assignOpts := AssignRoleOptions{
					TenantID: DefaultTenantID(),
					UserID:   userResult.User.ID,
					RoleID:   "non-existent-role-" + testID,
				}

				_, err = adapter.AssignRole(ctx, assignOpts)
				if err == nil {
					t.Error("AssignRole should fail for non-existent role")
				}
			})

			t.Run("AddMember_NonExistentUser", func(t *testing.T) {
				testID := uuid.New().String()[:8]

				// Create a group
				groupOpts := CreateGroupOptions{
					TenantID:    DefaultTenantID(),
					ID:          GenerateTestGroupID(testID + "-member-err"),
					Name:        "Test Group Member Error",
					Description: "Test group for member error",
				}

				groupResult, err := adapter.CreateGroup(ctx, groupOpts)
				if err != nil {
					t.Fatalf("CreateGroup failed: %v", err)
				}

				// Try to add non-existent user to group
				addOpts := AddMemberOptions{
					TenantID: DefaultTenantID(),
					GroupID:  groupResult.Group.ID,
					UserID:   "non-existent-user-" + testID,
				}

				_, err = adapter.AddMember(ctx, addOpts)
				if err == nil {
					t.Error("AddMember should fail for non-existent user")
				}
			})
		})
	}
}

// ============================================================================
// Protocol-Specific Tests
// ============================================================================

func TestIAMCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "iam", "CLI", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testUserCRUD(t, ctx, adapter)
	testGroupCRUD(t, ctx, adapter)
	testRoleCRUD(t, ctx, adapter)
}

func TestIAMREST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "iam", "REST", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testUserCRUD(t, ctx, adapter)
	testGroupCRUD(t, ctx, adapter)
	testRoleCRUD(t, ctx, adapter)
}

func TestIAMGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "iam", "gRPC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testUserCRUD(t, ctx, adapter)
	testGroupCRUD(t, ctx, adapter)
	testRoleCRUD(t, ctx, adapter)
}

func TestIAMQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "iam", "QUIC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testUserCRUD(t, ctx, adapter)
	testGroupCRUD(t, ctx, adapter)
	testRoleCRUD(t, ctx, adapter)
}

func TestIAMMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "iam", "MCP", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testUserCRUD(t, ctx, adapter)
	testGroupCRUD(t, ctx, adapter)
	testRoleCRUD(t, ctx, adapter)
}

func TestIAMUnix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "iam", "Unix", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testUserCRUD(t, ctx, adapter)
	testGroupCRUD(t, ctx, adapter)
	testRoleCRUD(t, ctx, adapter)
}
