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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// MCPAdapterError represents an error from the MCP adapter
type MCPAdapterError struct {
	Operation string
	Code      int
	Message   string
}

func (e *MCPAdapterError) Error() string {
	return fmt.Sprintf("MCP adapter error [%s]: %s (code: %d)", e.Operation, e.Message, e.Code)
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// ToolCallParams represents MCP tool call parameters
type ToolCallParams struct {
	Name      string      `json:"name"`
	Arguments interface{} `json:"arguments"`
}

// MCPAdapter implements IAMCommands using MCP (Model Context Protocol)
type MCPAdapter struct {
	endpoint  string
	client    *http.Client
	requestID int64
}

// NewMCPAdapter creates a new MCP adapter
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		endpoint: GetMCPEndpoint(),
		client:   helpers.NewHTTPClient(30 * time.Second),
	}
}

// NewTenantMCPAdapter is NewMCPAdapter acting as the caller bound to
// helpers.ForeignTenantID.
func NewTenantMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		endpoint: GetMCPEndpoint(),
		client:   helpers.NewTenantHTTPClient(30 * time.Second),
	}
}

// Setup prepares the adapter for testing
func (a *MCPAdapter) Setup(ctx context.Context) error {
	// Verify endpoint is reachable with initialize request
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "iam-integration-test",
				"version": "1.0.0",
			},
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	_, err := a.doRequest(ctx, req)
	if err != nil {
		return &MCPAdapterError{
			Operation: "Setup",
			Message:   "failed to initialize: " + err.Error(),
		}
	}

	return nil
}

// Teardown cleans up after testing
func (a *MCPAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *MCPAdapter) Name() string {
	return "MCP"
}

// doRequest performs a JSON-RPC request and returns the response
func (a *MCPAdapter) doRequest(ctx context.Context, req JSONRPCRequest) (json.RawMessage, error) {
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, helpers.MCPEndpointURL(a.endpoint), bytes.NewReader(reqData))
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to read response: " + err.Error(),
		}
	}

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respData, &rpcResp); err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	if rpcResp.Error != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Code:      rpcResp.Error.Code,
			Message:   rpcResp.Error.Message,
		}
	}

	return rpcResp.Result, nil
}

// callTool invokes an MCP tool and returns the result
func (a *MCPAdapter) callTool(ctx context.Context, toolName string, args interface{}) (json.RawMessage, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: ToolCallParams{
			Name:      toolName,
			Arguments: args,
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	return a.doRequest(ctx, req)
}

// callToolInto calls a tool and decodes its reply into out. The IAM tools
// answer with the gRPC response message marshalled by encoding/json
// ({"user": {...}}, {"users": [...], "total": n}), so the reply decodes into
// the same generated type the gRPC and QUIC adapters receive.
func (a *MCPAdapter) callToolInto(ctx context.Context, operation, toolName string, args interface{}, out interface{}) error {
	result, err := a.callTool(ctx, toolName, args)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(result, out); err != nil {
		return &MCPAdapterError{
			Operation: operation,
			Message:   "failed to parse response: " + err.Error(),
		}
	}
	return nil
}

// mcpPagination is the pagination argument of the IAM list tools.
func mcpPagination(limit int32) map[string]interface{} {
	return map[string]interface{}{"page_size": limit}
}

// ============================================================================
// User Operations
// ============================================================================

// CreateUser creates a new user
func (a *MCPAdapter) CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"email":     opts.Email,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if len(opts.Roles) > 0 {
		args["roles"] = opts.Roles
	}
	if len(opts.Groups) > 0 {
		args["groups"] = opts.Groups
	}
	if len(opts.Attributes) > 0 {
		args["attributes"] = opts.Attributes
	}

	var resp platformv1.IAMUserResponse
	if err := a.callToolInto(ctx, "CreateUser", "iam_create_user", args, &resp); err != nil {
		return nil, err
	}

	return &CreateUserResult{User: pbUserToUser(resp.GetUser())}, nil
}

// GetUser retrieves a user by ID
func (a *MCPAdapter) GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"user_id":   opts.UserID,
	}

	var resp platformv1.IAMUserResponse
	if err := a.callToolInto(ctx, "GetUser", "iam_get_user", args, &resp); err != nil {
		return nil, err
	}

	return &GetUserResult{User: pbUserToUser(resp.GetUser())}, nil
}

// UpdateUser updates an existing user
func (a *MCPAdapter) UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"user_id":   opts.UserID,
	}
	if opts.Email != "" {
		args["email"] = opts.Email
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if len(opts.Roles) > 0 {
		args["roles"] = opts.Roles
	}
	if len(opts.Groups) > 0 {
		args["groups"] = opts.Groups
	}
	if len(opts.Attributes) > 0 {
		args["attributes"] = opts.Attributes
	}

	var resp platformv1.IAMUserResponse
	if err := a.callToolInto(ctx, "UpdateUser", "iam_update_user", args, &resp); err != nil {
		return nil, err
	}

	return &UpdateUserResult{User: pbUserToUser(resp.GetUser())}, nil
}

// DeleteUser removes a user
func (a *MCPAdapter) DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"user_id":   opts.UserID,
	}

	_, err := a.callTool(ctx, "iam_delete_user", args)
	if err != nil {
		return nil, err
	}

	return &DeleteUserResult{Success: true}, nil
}

// ListUsers lists all users with optional filtering
func (a *MCPAdapter) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
	}
	if opts.Limit > 0 {
		args["pagination"] = mcpPagination(opts.Limit)
	}
	if opts.Email != "" {
		args["email_filter"] = opts.Email
	}
	if opts.Role != "" {
		args["role_filter"] = opts.Role
	}
	if opts.Group != "" {
		args["group_filter"] = opts.Group
	}

	var resp platformv1.ListIAMUsersResponse
	if err := a.callToolInto(ctx, "ListUsers", "iam_list_users", args, &resp); err != nil {
		return nil, err
	}

	users := make([]*User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		users = append(users, pbUserToUser(u))
	}
	return &ListUsersResult{Users: users, Total: resp.GetTotal(), Limit: opts.Limit, Offset: opts.Offset}, nil
}

// AssignRole assigns a role to a user
func (a *MCPAdapter) AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"user_id":   opts.UserID,
		"role":      opts.RoleID,
	}

	_, err := a.callTool(ctx, "iam_assign_role", args)
	if err != nil {
		return nil, err
	}

	return &AssignRoleResult{Success: true}, nil
}

// RevokeRole revokes a role from a user
func (a *MCPAdapter) RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"user_id":   opts.UserID,
		"role":      opts.RoleID,
	}

	_, err := a.callTool(ctx, "iam_revoke_role", args)
	if err != nil {
		return nil, err
	}

	return &RevokeRoleResult{Success: true}, nil
}

// ============================================================================
// Group Operations
// ============================================================================

// CreateGroup creates a new group
func (a *MCPAdapter) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*CreateGroupResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"id":        opts.ID,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}

	var resp platformv1.IAMGroupResponse
	if err := a.callToolInto(ctx, "CreateGroup", "iam_create_group", args, &resp); err != nil {
		return nil, err
	}

	return &CreateGroupResult{Group: pbGroupToGroup(resp.GetGroup())}, nil
}

// GetGroup retrieves a group by ID
func (a *MCPAdapter) GetGroup(ctx context.Context, opts GetGroupOptions) (*GetGroupResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"group_id":  opts.GroupID,
	}

	var resp platformv1.IAMGroupResponse
	if err := a.callToolInto(ctx, "GetGroup", "iam_get_group", args, &resp); err != nil {
		return nil, err
	}

	return &GetGroupResult{Group: pbGroupToGroup(resp.GetGroup())}, nil
}

// UpdateGroup updates an existing group
func (a *MCPAdapter) UpdateGroup(ctx context.Context, opts UpdateGroupOptions) (*UpdateGroupResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"group_id":  opts.GroupID,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}

	var resp platformv1.IAMGroupResponse
	if err := a.callToolInto(ctx, "UpdateGroup", "iam_update_group", args, &resp); err != nil {
		return nil, err
	}

	return &UpdateGroupResult{Group: pbGroupToGroup(resp.GetGroup())}, nil
}

// DeleteGroup removes a group
func (a *MCPAdapter) DeleteGroup(ctx context.Context, opts DeleteGroupOptions) (*DeleteGroupResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"group_id":  opts.GroupID,
	}

	_, err := a.callTool(ctx, "iam_delete_group", args)
	if err != nil {
		return nil, err
	}

	return &DeleteGroupResult{Success: true}, nil
}

// ListGroups lists all groups with optional filtering
func (a *MCPAdapter) ListGroups(ctx context.Context, opts ListGroupsOptions) (*ListGroupsResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
	}
	if opts.Limit > 0 {
		args["pagination"] = mcpPagination(opts.Limit)
	}

	var resp platformv1.ListIAMGroupsResponse
	if err := a.callToolInto(ctx, "ListGroups", "iam_list_groups", args, &resp); err != nil {
		return nil, err
	}

	groups := make([]*Group, 0, len(resp.GetGroups()))
	for _, g := range resp.GetGroups() {
		groups = append(groups, pbGroupToGroup(g))
	}
	return &ListGroupsResult{Groups: groups, Total: resp.GetTotal(), Limit: opts.Limit, Offset: opts.Offset}, nil
}

// AddMember adds a user to a group
func (a *MCPAdapter) AddMember(ctx context.Context, opts AddMemberOptions) (*AddMemberResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"group_id":  opts.GroupID,
		"user_id":   opts.UserID,
	}

	_, err := a.callTool(ctx, "iam_add_group_member", args)
	if err != nil {
		return nil, err
	}

	return &AddMemberResult{Success: true}, nil
}

// RemoveMember removes a user from a group
func (a *MCPAdapter) RemoveMember(ctx context.Context, opts RemoveMemberOptions) (*RemoveMemberResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"group_id":  opts.GroupID,
		"user_id":   opts.UserID,
	}

	_, err := a.callTool(ctx, "iam_remove_group_member", args)
	if err != nil {
		return nil, err
	}

	return &RemoveMemberResult{Success: true}, nil
}

// ============================================================================
// Role Operations
// ============================================================================

// CreateRole creates a new role
func (a *MCPAdapter) CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"id":        opts.ID,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if len(opts.Permissions) > 0 {
		args["permissions"] = opts.Permissions
	}

	var resp platformv1.IAMRoleResponse
	if err := a.callToolInto(ctx, "CreateRole", "iam_create_role", args, &resp); err != nil {
		return nil, err
	}

	return &CreateRoleResult{Role: pbRoleToRole(resp.GetRole())}, nil
}

// GetRole retrieves a role by ID
func (a *MCPAdapter) GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"role_id":   opts.RoleID,
	}

	var resp platformv1.IAMRoleResponse
	if err := a.callToolInto(ctx, "GetRole", "iam_get_role", args, &resp); err != nil {
		return nil, err
	}

	return &GetRoleResult{Role: pbRoleToRole(resp.GetRole())}, nil
}

// UpdateRole updates an existing role
func (a *MCPAdapter) UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"role_id":   opts.RoleID,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if len(opts.Permissions) > 0 {
		args["permissions"] = opts.Permissions
	}

	var resp platformv1.IAMRoleResponse
	if err := a.callToolInto(ctx, "UpdateRole", "iam_update_role", args, &resp); err != nil {
		return nil, err
	}

	return &UpdateRoleResult{Role: pbRoleToRole(resp.GetRole())}, nil
}

// DeleteRole removes a role
func (a *MCPAdapter) DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"role_id":   opts.RoleID,
	}

	_, err := a.callTool(ctx, "iam_delete_role", args)
	if err != nil {
		return nil, err
	}

	return &DeleteRoleResult{Success: true}, nil
}

// ListRoles lists all roles with optional filtering
func (a *MCPAdapter) ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
	}
	if opts.Limit > 0 {
		args["pagination"] = mcpPagination(opts.Limit)
	}

	var resp platformv1.ListIAMRolesResponse
	if err := a.callToolInto(ctx, "ListRoles", "iam_list_roles", args, &resp); err != nil {
		return nil, err
	}

	roles := make([]*Role, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		roles = append(roles, pbRoleToRole(r))
	}
	return &ListRolesResult{Roles: roles, Total: resp.GetTotal(), Limit: opts.Limit, Offset: opts.Offset}, nil
}

// ============================================================================
// Permission Operations
// ============================================================================

// CheckPermission checks if a subject has permission for an action on a resource
func (a *MCPAdapter) CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
		"user_id":   opts.SubjectID,
		"resource":  opts.Resource,
		"action":    opts.Action,
	}
	if len(opts.Roles) > 0 {
		args["roles"] = opts.Roles
	}
	if len(opts.Groups) > 0 {
		args["groups"] = opts.Groups
	}
	if len(opts.Context) > 0 {
		args["context"] = opts.Context
	}
	if len(opts.Attributes) > 0 {
		args["attributes"] = opts.Attributes
	}

	result, err := a.callTool(ctx, "iam_check_permission", args)
	if err != nil {
		return nil, err
	}

	var checkResult CheckPermissionResult
	if err := json.Unmarshal(result, &checkResult); err != nil {
		// Try parsing as boolean directly
		var allowed bool
		if err := json.Unmarshal(result, &allowed); err != nil {
			return nil, &MCPAdapterError{
				Operation: "CheckPermission",
				Message:   "failed to parse response: " + err.Error(),
			}
		}
		checkResult.Allowed = allowed
	}

	return &checkResult, nil
}

// Verify MCPAdapter implements IAMCommands
var _ IAMCommands = (*MCPAdapter)(nil)
