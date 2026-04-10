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

import "fmt"

// User Errors

type ErrCreateUserFailed struct {
	Cause error
}

func (e *ErrCreateUserFailed) Error() string {
	return fmt.Sprintf("failed to create user: %v", e.Cause)
}

func (e *ErrCreateUserFailed) Unwrap() error { return e.Cause }

type ErrGetUserFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetUserFailed) Error() string {
	return fmt.Sprintf("failed to get user %s: %v", e.ID, e.Cause)
}

func (e *ErrGetUserFailed) Unwrap() error { return e.Cause }

type ErrListUsersFailed struct {
	Cause error
}

func (e *ErrListUsersFailed) Error() string {
	return fmt.Sprintf("failed to list users: %v", e.Cause)
}

func (e *ErrListUsersFailed) Unwrap() error { return e.Cause }

type ErrUpdateUserFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateUserFailed) Error() string {
	return fmt.Sprintf("failed to update user %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateUserFailed) Unwrap() error { return e.Cause }

type ErrDeleteUserFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteUserFailed) Error() string {
	return fmt.Sprintf("failed to delete user %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteUserFailed) Unwrap() error { return e.Cause }

// Role Errors

type ErrCreateRoleFailed struct {
	Cause error
}

func (e *ErrCreateRoleFailed) Error() string {
	return fmt.Sprintf("failed to create role: %v", e.Cause)
}

func (e *ErrCreateRoleFailed) Unwrap() error { return e.Cause }

type ErrGetRoleFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetRoleFailed) Error() string {
	return fmt.Sprintf("failed to get role %s: %v", e.ID, e.Cause)
}

func (e *ErrGetRoleFailed) Unwrap() error { return e.Cause }

type ErrListRolesFailed struct {
	Cause error
}

func (e *ErrListRolesFailed) Error() string {
	return fmt.Sprintf("failed to list roles: %v", e.Cause)
}

func (e *ErrListRolesFailed) Unwrap() error { return e.Cause }

type ErrUpdateRoleFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateRoleFailed) Error() string {
	return fmt.Sprintf("failed to update role %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateRoleFailed) Unwrap() error { return e.Cause }

type ErrDeleteRoleFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteRoleFailed) Error() string {
	return fmt.Sprintf("failed to delete role %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteRoleFailed) Unwrap() error { return e.Cause }

type ErrAssignRoleFailed struct {
	UserID string
	RoleID string
	Cause  error
}

func (e *ErrAssignRoleFailed) Error() string {
	return fmt.Sprintf("failed to assign role %s to user %s: %v", e.RoleID, e.UserID, e.Cause)
}

func (e *ErrAssignRoleFailed) Unwrap() error { return e.Cause }

type ErrRevokeRoleFailed struct {
	UserID string
	RoleID string
	Cause  error
}

func (e *ErrRevokeRoleFailed) Error() string {
	return fmt.Sprintf("failed to revoke role %s from user %s: %v", e.RoleID, e.UserID, e.Cause)
}

func (e *ErrRevokeRoleFailed) Unwrap() error { return e.Cause }

// Group Errors

type ErrCreateGroupFailed struct {
	Cause error
}

func (e *ErrCreateGroupFailed) Error() string {
	return fmt.Sprintf("failed to create group: %v", e.Cause)
}

func (e *ErrCreateGroupFailed) Unwrap() error { return e.Cause }

type ErrGetGroupFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetGroupFailed) Error() string {
	return fmt.Sprintf("failed to get group %s: %v", e.ID, e.Cause)
}

func (e *ErrGetGroupFailed) Unwrap() error { return e.Cause }

type ErrListGroupsFailed struct {
	Cause error
}

func (e *ErrListGroupsFailed) Error() string {
	return fmt.Sprintf("failed to list groups: %v", e.Cause)
}

func (e *ErrListGroupsFailed) Unwrap() error { return e.Cause }

type ErrUpdateGroupFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateGroupFailed) Error() string {
	return fmt.Sprintf("failed to update group %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateGroupFailed) Unwrap() error { return e.Cause }

type ErrDeleteGroupFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteGroupFailed) Error() string {
	return fmt.Sprintf("failed to delete group %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteGroupFailed) Unwrap() error { return e.Cause }

type ErrAddGroupMemberFailed struct {
	GroupID string
	UserID  string
	Cause   error
}

func (e *ErrAddGroupMemberFailed) Error() string {
	return fmt.Sprintf("failed to add user %s to group %s: %v", e.UserID, e.GroupID, e.Cause)
}

func (e *ErrAddGroupMemberFailed) Unwrap() error { return e.Cause }

type ErrRemoveGroupMemberFailed struct {
	GroupID string
	UserID  string
	Cause   error
}

func (e *ErrRemoveGroupMemberFailed) Error() string {
	return fmt.Sprintf("failed to remove user %s from group %s: %v", e.UserID, e.GroupID, e.Cause)
}

func (e *ErrRemoveGroupMemberFailed) Unwrap() error { return e.Cause }

// Auth Errors

type ErrCheckPermissionFailed struct {
	Cause error
}

func (e *ErrCheckPermissionFailed) Error() string {
	return fmt.Sprintf("failed to check permission: %v", e.Cause)
}

func (e *ErrCheckPermissionFailed) Unwrap() error { return e.Cause }

type ErrCreateTokenFailed struct {
	Cause error
}

func (e *ErrCreateTokenFailed) Error() string {
	return fmt.Sprintf("failed to create token: %v", e.Cause)
}

func (e *ErrCreateTokenFailed) Unwrap() error { return e.Cause }

type ErrRevokeTokenFailed struct {
	TokenID string
	Cause   error
}

func (e *ErrRevokeTokenFailed) Error() string {
	return fmt.Sprintf("failed to revoke token %s: %v", e.TokenID, e.Cause)
}

func (e *ErrRevokeTokenFailed) Unwrap() error { return e.Cause }

type ErrVerifyTokenFailed struct {
	Cause error
}

func (e *ErrVerifyTokenFailed) Error() string {
	return fmt.Sprintf("failed to verify token: %v", e.Cause)
}

func (e *ErrVerifyTokenFailed) Unwrap() error { return e.Cause }

// Tenant Errors

type ErrCreateTenantFailed struct {
	Cause error
}

func (e *ErrCreateTenantFailed) Error() string {
	return fmt.Sprintf("failed to create tenant: %v", e.Cause)
}

func (e *ErrCreateTenantFailed) Unwrap() error { return e.Cause }

type ErrGetTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetTenantFailed) Error() string {
	return fmt.Sprintf("failed to get tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrGetTenantFailed) Unwrap() error { return e.Cause }

type ErrListTenantsFailed struct {
	Cause error
}

func (e *ErrListTenantsFailed) Error() string {
	return fmt.Sprintf("failed to list tenants: %v", e.Cause)
}

func (e *ErrListTenantsFailed) Unwrap() error { return e.Cause }

type ErrUpdateTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateTenantFailed) Error() string {
	return fmt.Sprintf("failed to update tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateTenantFailed) Unwrap() error { return e.Cause }

type ErrDeleteTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteTenantFailed) Error() string {
	return fmt.Sprintf("failed to delete tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteTenantFailed) Unwrap() error { return e.Cause }

// Policy Errors

type ErrCreatePolicyFailed struct {
	Cause error
}

func (e *ErrCreatePolicyFailed) Error() string {
	return fmt.Sprintf("failed to create policy: %v", e.Cause)
}

func (e *ErrCreatePolicyFailed) Unwrap() error { return e.Cause }

type ErrGetPolicyFailed struct {
	Name  string
	Cause error
}

func (e *ErrGetPolicyFailed) Error() string {
	return fmt.Sprintf("failed to get policy %s: %v", e.Name, e.Cause)
}

func (e *ErrGetPolicyFailed) Unwrap() error { return e.Cause }

type ErrListPoliciesFailed struct {
	Cause error
}

func (e *ErrListPoliciesFailed) Error() string {
	return fmt.Sprintf("failed to list policies: %v", e.Cause)
}

func (e *ErrListPoliciesFailed) Unwrap() error { return e.Cause }

type ErrUpdatePolicyFailed struct {
	Name  string
	Cause error
}

func (e *ErrUpdatePolicyFailed) Error() string {
	return fmt.Sprintf("failed to update policy %s: %v", e.Name, e.Cause)
}

func (e *ErrUpdatePolicyFailed) Unwrap() error { return e.Cause }

type ErrDeletePolicyFailed struct {
	Name  string
	Cause error
}

func (e *ErrDeletePolicyFailed) Error() string {
	return fmt.Sprintf("failed to delete policy %s: %v", e.Name, e.Cause)
}

func (e *ErrDeletePolicyFailed) Unwrap() error { return e.Cause }

type ErrValidatePolicyFailed struct {
	Cause error
}

func (e *ErrValidatePolicyFailed) Error() string {
	return fmt.Sprintf("failed to validate policy: %v", e.Cause)
}

func (e *ErrValidatePolicyFailed) Unwrap() error { return e.Cause }

type ErrTestPolicyFailed struct {
	Cause error
}

func (e *ErrTestPolicyFailed) Error() string {
	return fmt.Sprintf("failed to test policy: %v", e.Cause)
}

func (e *ErrTestPolicyFailed) Unwrap() error { return e.Cause }

// App Errors

type ErrRegisterAppFailed struct {
	Cause error
}

func (e *ErrRegisterAppFailed) Error() string {
	return fmt.Sprintf("failed to register app: %v", e.Cause)
}

func (e *ErrRegisterAppFailed) Unwrap() error { return e.Cause }

type ErrGetAppFailed struct {
	ClientID string
	Cause    error
}

func (e *ErrGetAppFailed) Error() string {
	return fmt.Sprintf("failed to get app %s: %v", e.ClientID, e.Cause)
}

func (e *ErrGetAppFailed) Unwrap() error { return e.Cause }

type ErrListAppsFailed struct {
	Cause error
}

func (e *ErrListAppsFailed) Error() string {
	return fmt.Sprintf("failed to list apps: %v", e.Cause)
}

func (e *ErrListAppsFailed) Unwrap() error { return e.Cause }

type ErrUpdateAppFailed struct {
	ClientID string
	Cause    error
}

func (e *ErrUpdateAppFailed) Error() string {
	return fmt.Sprintf("failed to update app %s: %v", e.ClientID, e.Cause)
}

func (e *ErrUpdateAppFailed) Unwrap() error { return e.Cause }

type ErrDeleteAppFailed struct {
	ClientID string
	Cause    error
}

func (e *ErrDeleteAppFailed) Error() string {
	return fmt.Sprintf("failed to delete app %s: %v", e.ClientID, e.Cause)
}

func (e *ErrDeleteAppFailed) Unwrap() error { return e.Cause }

type ErrRotateAppSecretFailed struct {
	ClientID string
	Cause    error
}

func (e *ErrRotateAppSecretFailed) Error() string {
	return fmt.Sprintf("failed to rotate app secret for %s: %v", e.ClientID, e.Cause)
}

func (e *ErrRotateAppSecretFailed) Unwrap() error { return e.Cause }
