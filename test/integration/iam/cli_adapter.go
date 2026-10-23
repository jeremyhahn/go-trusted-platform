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
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CLIAdapterError represents an error from the CLI adapter
type CLIAdapterError struct {
	Operation string
	Message   string
	Output    string
}

func (e *CLIAdapterError) Error() string {
	return fmt.Sprintf("CLI adapter error [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// CLIAdapter implements IAMCommands using the platformctl CLI
type CLIAdapter struct {
	cliPath string
}

// NewCLIAdapter creates a new CLI adapter
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup prepares the adapter for testing
func (a *CLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return &CLIAdapterError{
			Operation: "Setup",
			Message:   "CLI not found",
		}
	}
	return nil
}

// Teardown cleans up after testing
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command and returns the output
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, a.cliPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    string(output),
		}
	}
	return output, nil
}

// ============================================================================
// User CRUD Operations
// ============================================================================

// CreateUser creates a new user
func (a *CLIAdapter) CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error) {
	args := []string{"iam", "user", "create",
		"--tenant", opts.TenantID,
		"--email", opts.Email,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if len(opts.Roles) > 0 {
		args = append(args, "--roles", strings.Join(opts.Roles, ","))
	}
	if len(opts.Groups) > 0 {
		args = append(args, "--groups", strings.Join(opts.Groups, ","))
	}
	if len(opts.Attributes) > 0 {
		attrs := formatAttributesForCLI(opts.Attributes)
		args = append(args, "--attributes", attrs)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(output, &user); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateUser",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateUserResult{User: &user}, nil
}

// GetUser retrieves a user by ID
func (a *CLIAdapter) GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error) {
	args := []string{"iam", "user", "get",
		opts.TenantID,
		opts.UserID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(output, &user); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetUser",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetUserResult{User: &user}, nil
}

// UpdateUser updates an existing user
func (a *CLIAdapter) UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error) {
	args := []string{"iam", "user", "update",
		"--tenant", opts.TenantID,
		"--user-id", opts.UserID,
		"--output", "json",
	}

	if opts.Email != "" {
		args = append(args, "--email", opts.Email)
	}
	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if len(opts.Roles) > 0 {
		args = append(args, "--roles", strings.Join(opts.Roles, ","))
	}
	if len(opts.Groups) > 0 {
		args = append(args, "--groups", strings.Join(opts.Groups, ","))
	}
	if len(opts.Attributes) > 0 {
		attrs := formatAttributesForCLI(opts.Attributes)
		args = append(args, "--attributes", attrs)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(output, &user); err != nil {
		return nil, &CLIAdapterError{
			Operation: "UpdateUser",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UpdateUserResult{User: &user}, nil
}

// DeleteUser removes a user
func (a *CLIAdapter) DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error) {
	args := []string{"iam", "user", "delete",
		opts.TenantID,
		opts.UserID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return &DeleteUserResult{Success: true}, nil
	}

	return &DeleteUserResult{Success: resp.Success}, nil
}

// ListUsers lists all users with optional filtering
func (a *CLIAdapter) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	args := []string{"iam", "user", "list",
		"--tenant", opts.TenantID,
		"--output", "json",
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}
	if opts.Email != "" {
		args = append(args, "--email", opts.Email)
	}
	if opts.Role != "" {
		args = append(args, "--role", opts.Role)
	}
	if opts.Group != "" {
		args = append(args, "--group", opts.Group)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListUsersResult
	if err := json.Unmarshal(output, &result); err != nil {
		var users []*User
		if err := json.Unmarshal(output, &users); err != nil {
			return nil, &CLIAdapterError{
				Operation: "ListUsers",
				Message:   "failed to parse response",
				Output:    string(output),
			}
		}
		result.Users = users
		result.Total = int64(len(users))
	}

	return &result, nil
}

// AssignRole assigns a role to a user
func (a *CLIAdapter) AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error) {
	args := []string{"iam", "user", "assign-role",
		opts.TenantID,
		opts.UserID,
		opts.RoleID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return &AssignRoleResult{Success: true}, nil
	}

	return &AssignRoleResult{Success: resp.Success}, nil
}

// RevokeRole revokes a role from a user
func (a *CLIAdapter) RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error) {
	args := []string{"iam", "user", "revoke-role",
		opts.TenantID,
		opts.UserID,
		opts.RoleID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return &RevokeRoleResult{Success: true}, nil
	}

	return &RevokeRoleResult{Success: resp.Success}, nil
}

// ============================================================================
// Group CRUD Operations
// ============================================================================

// CreateGroup creates a new group
func (a *CLIAdapter) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*CreateGroupResult, error) {
	args := []string{"iam", "group", "create",
		opts.ID,
		"--tenant", opts.TenantID,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(output, &group); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateGroup",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateGroupResult{Group: &group}, nil
}

// GetGroup retrieves a group by ID
func (a *CLIAdapter) GetGroup(ctx context.Context, opts GetGroupOptions) (*GetGroupResult, error) {
	args := []string{"iam", "group", "get",
		opts.TenantID,
		opts.GroupID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(output, &group); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetGroup",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetGroupResult{Group: &group}, nil
}

// UpdateGroup updates an existing group
func (a *CLIAdapter) UpdateGroup(ctx context.Context, opts UpdateGroupOptions) (*UpdateGroupResult, error) {
	args := []string{"iam", "group", "update",
		opts.GroupID,
		"--tenant", opts.TenantID,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(output, &group); err != nil {
		return nil, &CLIAdapterError{
			Operation: "UpdateGroup",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UpdateGroupResult{Group: &group}, nil
}

// DeleteGroup removes a group
func (a *CLIAdapter) DeleteGroup(ctx context.Context, opts DeleteGroupOptions) (*DeleteGroupResult, error) {
	args := []string{"iam", "group", "delete",
		opts.TenantID,
		opts.GroupID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return &DeleteGroupResult{Success: true}, nil
	}

	return &DeleteGroupResult{Success: resp.Success}, nil
}

// ListGroups lists all groups with optional filtering
func (a *CLIAdapter) ListGroups(ctx context.Context, opts ListGroupsOptions) (*ListGroupsResult, error) {
	args := []string{"iam", "group", "list",
		"--tenant", opts.TenantID,
		"--output", "json",
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListGroupsResult
	if err := json.Unmarshal(output, &result); err != nil {
		var groups []*Group
		if err := json.Unmarshal(output, &groups); err != nil {
			return nil, &CLIAdapterError{
				Operation: "ListGroups",
				Message:   "failed to parse response",
				Output:    string(output),
			}
		}
		result.Groups = groups
		result.Total = int64(len(groups))
	}

	return &result, nil
}

// AddMember adds a user to a group
func (a *CLIAdapter) AddMember(ctx context.Context, opts AddMemberOptions) (*AddMemberResult, error) {
	args := []string{"iam", "group", "add-member",
		opts.TenantID,
		opts.GroupID,
		opts.UserID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return &AddMemberResult{Success: true}, nil
	}

	return &AddMemberResult{Success: resp.Success}, nil
}

// RemoveMember removes a user from a group
func (a *CLIAdapter) RemoveMember(ctx context.Context, opts RemoveMemberOptions) (*RemoveMemberResult, error) {
	args := []string{"iam", "group", "remove-member",
		opts.TenantID,
		opts.GroupID,
		opts.UserID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return &RemoveMemberResult{Success: true}, nil
	}

	return &RemoveMemberResult{Success: resp.Success}, nil
}

// ============================================================================
// Role CRUD Operations
// ============================================================================

// CreateRole creates a new role
func (a *CLIAdapter) CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error) {
	args := []string{"iam", "role", "create",
		opts.ID,
		"--tenant", opts.TenantID,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	if len(opts.Permissions) > 0 {
		args = append(args, "--permissions", strings.Join(opts.Permissions, ","))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var role Role
	if err := json.Unmarshal(output, &role); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateRole",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateRoleResult{Role: &role}, nil
}

// GetRole retrieves a role by ID
func (a *CLIAdapter) GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error) {
	args := []string{"iam", "role", "get",
		opts.TenantID,
		opts.RoleID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var role Role
	if err := json.Unmarshal(output, &role); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetRole",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetRoleResult{Role: &role}, nil
}

// UpdateRole updates an existing role
func (a *CLIAdapter) UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error) {
	args := []string{"iam", "role", "update",
		opts.RoleID,
		"--tenant", opts.TenantID,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	if len(opts.Permissions) > 0 {
		args = append(args, "--permissions", strings.Join(opts.Permissions, ","))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var role Role
	if err := json.Unmarshal(output, &role); err != nil {
		return nil, &CLIAdapterError{
			Operation: "UpdateRole",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UpdateRoleResult{Role: &role}, nil
}

// DeleteRole removes a role
func (a *CLIAdapter) DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error) {
	args := []string{"iam", "role", "delete",
		opts.TenantID,
		opts.RoleID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(output, &resp); err != nil {
		return &DeleteRoleResult{Success: true}, nil
	}

	return &DeleteRoleResult{Success: resp.Success}, nil
}

// ListRoles lists all roles with optional filtering
func (a *CLIAdapter) ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error) {
	args := []string{"iam", "role", "list",
		"--tenant", opts.TenantID,
		"--output", "json",
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListRolesResult
	if err := json.Unmarshal(output, &result); err != nil {
		var roles []*Role
		if err := json.Unmarshal(output, &roles); err != nil {
			return nil, &CLIAdapterError{
				Operation: "ListRoles",
				Message:   "failed to parse response",
				Output:    string(output),
			}
		}
		result.Roles = roles
		result.Total = int64(len(roles))
	}

	return &result, nil
}

// ============================================================================
// Permission Operations
// ============================================================================

// CheckPermission checks if a subject has permission for an action on a resource
func (a *CLIAdapter) CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error) {
	args := []string{"iam", "permission", "check",
		"--tenant", opts.TenantID,
		"--subject", opts.SubjectID,
		"--action", opts.Action,
		"--resource", opts.Resource,
		"--output", "json",
	}

	if len(opts.Roles) > 0 {
		args = append(args, "--roles", strings.Join(opts.Roles, ","))
	}
	if len(opts.Groups) > 0 {
		args = append(args, "--groups", strings.Join(opts.Groups, ","))
	}
	if len(opts.Context) > 0 {
		args = append(args, "--context", formatAttributesForCLI(opts.Context))
	}
	if len(opts.Attributes) > 0 {
		args = append(args, "--attributes", formatAttributesForCLI(opts.Attributes))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result CheckPermissionResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CheckPermission",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// formatAttributesForCLI formats a map of attributes for CLI input
func formatAttributesForCLI(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(attrs))
	for k, v := range attrs {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(pairs, ",")
}

// Verify CLIAdapter implements IAMCommands
var _ IAMCommands = (*CLIAdapter)(nil)
