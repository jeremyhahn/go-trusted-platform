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

//go:build integration

package iam

import (
	"context"
	"time"
)

// IAMCommands defines the interface for IAM operations across all protocols
type IAMCommands interface {
	// Setup prepares the adapter for testing
	Setup(ctx context.Context) error

	// Teardown cleans up after testing
	Teardown(ctx context.Context) error

	// Name returns the adapter name
	Name() string

	// User CRUD Operations

	// CreateUser creates a new user
	CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error)

	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error)

	// UpdateUser updates an existing user
	UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error)

	// DeleteUser removes a user
	DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error)

	// ListUsers lists all users with optional filtering
	ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error)

	// User Role Operations

	// AssignRole assigns a role to a user
	AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error)

	// RevokeRole revokes a role from a user
	RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error)

	// Role CRUD Operations

	// CreateRole creates a new role
	CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error)

	// GetRole retrieves a role by ID
	GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error)

	// UpdateRole updates an existing role
	UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error)

	// DeleteRole removes a role
	DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error)

	// ListRoles lists all roles with optional filtering
	ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error)

	// Permission Operations

	// CheckPermission checks if a subject has permission for an action on a resource
	CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error)
}

// ============================================================================
// User Types
// ============================================================================

// User represents an IAM user
type User struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Email       string            `json:"email"`
	Name        string            `json:"name,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	MFAVerified bool              `json:"mfa_verified"`
	CreatedAt   *time.Time        `json:"created_at,omitempty"`
	UpdatedAt   *time.Time        `json:"updated_at,omitempty"`
	LastAuth    *time.Time        `json:"last_auth,omitempty"`
}

// CreateUserOptions contains options for creating a user
type CreateUserOptions struct {
	TenantID   string            `json:"tenant_id"`
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// CreateUserResult contains the result of user creation
type CreateUserResult struct {
	User *User `json:"user"`
}

// GetUserOptions contains options for getting a user
type GetUserOptions struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
}

// GetUserResult contains the result of getting a user
type GetUserResult struct {
	User *User `json:"user"`
}

// UpdateUserOptions contains options for updating a user
type UpdateUserOptions struct {
	TenantID   string            `json:"tenant_id"`
	UserID     string            `json:"user_id"`
	Email      string            `json:"email,omitempty"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// UpdateUserResult contains the result of updating a user
type UpdateUserResult struct {
	User *User `json:"user"`
}

// DeleteUserOptions contains options for deleting a user
type DeleteUserOptions struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
}

// DeleteUserResult contains the result of deleting a user
type DeleteUserResult struct {
	Success bool `json:"success"`
}

// ListUsersOptions contains options for listing users
type ListUsersOptions struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role,omitempty"`
	Limit    int32  `json:"limit,omitempty"`
	Offset   int32  `json:"offset,omitempty"`
}

// ListUsersResult contains the result of listing users
type ListUsersResult struct {
	Users  []*User `json:"users"`
	Total  int64   `json:"total"`
	Limit  int32   `json:"limit"`
	Offset int32   `json:"offset"`
}

// AssignRoleOptions contains options for assigning a role to a user
type AssignRoleOptions struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	RoleID   string `json:"role_id"`
}

// AssignRoleResult contains the result of assigning a role
type AssignRoleResult struct {
	Success bool `json:"success"`
}

// RevokeRoleOptions contains options for revoking a role from a user
type RevokeRoleOptions struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	RoleID   string `json:"role_id"`
}

// RevokeRoleResult contains the result of revoking a role
type RevokeRoleResult struct {
	Success bool `json:"success"`
}

// ============================================================================
// Role Types
// ============================================================================

// Role represents an IAM role
type Role struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// CreateRoleOptions contains options for creating a role
type CreateRoleOptions struct {
	TenantID    string   `json:"tenant_id"`
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// CreateRoleResult contains the result of role creation
type CreateRoleResult struct {
	Role *Role `json:"role"`
}

// GetRoleOptions contains options for getting a role
type GetRoleOptions struct {
	TenantID string `json:"tenant_id"`
	RoleID   string `json:"role_id"`
}

// GetRoleResult contains the result of getting a role
type GetRoleResult struct {
	Role *Role `json:"role"`
}

// UpdateRoleOptions contains options for updating a role
type UpdateRoleOptions struct {
	TenantID    string   `json:"tenant_id"`
	RoleID      string   `json:"role_id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdateRoleResult contains the result of updating a role
type UpdateRoleResult struct {
	Role *Role `json:"role"`
}

// DeleteRoleOptions contains options for deleting a role
type DeleteRoleOptions struct {
	TenantID string `json:"tenant_id"`
	RoleID   string `json:"role_id"`
}

// DeleteRoleResult contains the result of deleting a role
type DeleteRoleResult struct {
	Success bool `json:"success"`
}

// ListRolesOptions contains options for listing roles
type ListRolesOptions struct {
	TenantID string `json:"tenant_id"`
	Limit    int32  `json:"limit,omitempty"`
	Offset   int32  `json:"offset,omitempty"`
}

// ListRolesResult contains the result of listing roles
type ListRolesResult struct {
	Roles  []*Role `json:"roles"`
	Total  int64   `json:"total"`
	Limit  int32   `json:"limit"`
	Offset int32   `json:"offset"`
}

// ============================================================================
// Permission Types
// ============================================================================

// CheckPermissionOptions contains options for checking a permission
type CheckPermissionOptions struct {
	TenantID   string            `json:"tenant_id"`
	SubjectID  string            `json:"subject_id"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Context    map[string]string `json:"context,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// CheckPermissionResult contains the result of checking a permission
type CheckPermissionResult struct {
	Allowed          bool   `json:"allowed"`
	MatchedPolicy    string `json:"matched_policy,omitempty"`
	MatchedRule      string `json:"matched_rule,omitempty"`
	EvaluationTimeNs int64  `json:"evaluation_time_ns,omitempty"`
}
