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
	"crypto/tls"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// QUICAdapterError represents an error from the QUIC adapter
type QUICAdapterError struct {
	Operation string
	Message   string
}

func (e *QUICAdapterError) Error() string {
	return fmt.Sprintf("QUIC adapter error [%s]: %s", e.Operation, e.Message)
}

// QUICNotSupportedError represents an operation not supported by QUIC protocol
type QUICNotSupportedError struct {
	Operation string
}

func (e *QUICNotSupportedError) Error() string {
	return fmt.Sprintf("QUIC protocol does not support operation: %s", e.Operation)
}

// QUICAdapter implements IAMCommands using QUIC binary protocol
type QUICAdapter struct {
	endpoint   string
	conn       *quicgo.Conn
	tlsConfig  *tls.Config
	quicConfig *quicgo.Config
	token      string
}

// NewQUICAdapter creates a new QUIC adapter
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:  GetQUICEndpoint(),
		tlsConfig: helpers.QUICTLSConfig([]string{"iam-quic"}),
		quicConfig: &quicgo.Config{
			EnableDatagrams: true,
		},
		token: GetAdminToken(),
	}
}

// Setup prepares the adapter for testing
func (a *QUICAdapter) Setup(ctx context.Context) error {
	conn, err := quicgo.DialAddr(ctx, a.endpoint, a.tlsConfig, a.quicConfig)
	if err != nil {
		return &QUICAdapterError{
			Operation: "Setup",
			Message:   "failed to connect: " + err.Error(),
		}
	}

	a.conn = conn
	return nil
}

// Teardown cleans up after testing
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.CloseWithError(0, "teardown")
	}
	return nil
}

// Name returns the adapter name
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// doRequest performs a QUIC binary protocol request and returns the response
func (a *QUICAdapter) doRequest(ctx context.Context, opcode byte, payload interface{}) ([]byte, error) {
	stream, err := a.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: quic.OpcodeToString(opcode),
			Message:   "failed to open stream: " + err.Error(),
		}
	}
	defer stream.Close()

	// Encode payload
	var encodedPayload []byte
	if payload != nil {
		encodedPayload, err = quic.EncodePayload(payload)
		if err != nil {
			return nil, &QUICAdapterError{
				Operation: quic.OpcodeToString(opcode),
				Message:   "failed to encode payload: " + err.Error(),
			}
		}
	}

	// Create and write request
	req := &quic.Request{
		Opcode:  opcode,
		Token:   a.token,
		Payload: encodedPayload,
	}

	if err := quic.WriteRequest(stream, req); err != nil {
		return nil, &QUICAdapterError{
			Operation: quic.OpcodeToString(opcode),
			Message:   "failed to write request: " + err.Error(),
		}
	}

	// Close write side to signal end of request
	if err := stream.Close(); err != nil {
		return nil, &QUICAdapterError{
			Operation: quic.OpcodeToString(opcode),
			Message:   "failed to close write: " + err.Error(),
		}
	}

	// Read response
	resp, err := quic.ReadResponse(stream)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: quic.OpcodeToString(opcode),
			Message:   "failed to read response: " + err.Error(),
		}
	}

	if resp.Status != quic.StatusOK {
		return nil, &QUICAdapterError{
			Operation: quic.OpcodeToString(opcode),
			Message:   fmt.Sprintf("server returned status: %s", quic.StatusToString(resp.Status)),
		}
	}

	return resp.Payload, nil
}

// =============================================================================
// User CRUD Operations
// =============================================================================

// CreateUser creates a new user
func (a *QUICAdapter) CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error) {
	req := daemon.CreateUserRequest{
		TenantID:   opts.TenantID,
		Email:      opts.Email,
		Name:       opts.Name,
		Enabled:    true,
		Attributes: opts.Attributes,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMUserCreate, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMUserResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "CreateUser",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &CreateUserResult{
		User: convertUserResponse(&resp),
	}, nil
}

// GetUser retrieves a user by ID
func (a *QUICAdapter) GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error) {
	req := daemon.GetUserRequest{
		TenantID: opts.TenantID,
		UserID:   opts.UserID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMUserGet, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMUserResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetUser",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &GetUserResult{
		User: convertUserResponse(&resp),
	}, nil
}

// UpdateUser updates an existing user
func (a *QUICAdapter) UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error) {
	req := daemon.UpdateUserRequest{
		TenantID:   opts.TenantID,
		UserID:     opts.UserID,
		Email:      opts.Email,
		Name:       opts.Name,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Attributes: opts.Attributes,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMUserUpdate, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMUserResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "UpdateUser",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &UpdateUserResult{
		User: convertUserResponse(&resp),
	}, nil
}

// DeleteUser removes a user
func (a *QUICAdapter) DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error) {
	req := daemon.DeleteUserRequest{
		TenantID: opts.TenantID,
		UserID:   opts.UserID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMUserDelete, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.GenericIAMResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "DeleteUser",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &DeleteUserResult{
		Success: resp.Success,
	}, nil
}

// ListUsers lists all users with optional filtering
func (a *QUICAdapter) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	req := daemon.ListIAMRequest{
		TenantID: opts.TenantID,
		Limit:    int(opts.Limit),
		Offset:   int(opts.Offset),
	}

	payload, err := a.doRequest(ctx, quic.OpIAMUserList, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMUserListResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "ListUsers",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	users := make([]*User, 0, len(resp.Users))
	for _, u := range resp.Users {
		users = append(users, convertUserResponse(u))
	}

	return &ListUsersResult{
		Users:  users,
		Total:  int64(resp.Total),
		Limit:  int32(resp.Limit),
		Offset: int32(resp.Offset),
	}, nil
}

// AssignRole assigns a role to a user
func (a *QUICAdapter) AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error) {
	req := daemon.AssignRoleRequest{
		TenantID: opts.TenantID,
		UserID:   opts.UserID,
		RoleID:   opts.RoleID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMRoleAssign, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.GenericIAMResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "AssignRole",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &AssignRoleResult{
		Success: resp.Success,
	}, nil
}

// RevokeRole revokes a role from a user
func (a *QUICAdapter) RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error) {
	req := daemon.RevokeRoleRequest{
		TenantID: opts.TenantID,
		UserID:   opts.UserID,
		RoleID:   opts.RoleID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMRoleRevoke, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.GenericIAMResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "RevokeRole",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &RevokeRoleResult{
		Success: resp.Success,
	}, nil
}

// =============================================================================
// Role CRUD Operations
// =============================================================================

// CreateRole creates a new role
func (a *QUICAdapter) CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error) {
	req := daemon.CreateRoleRequest{
		TenantID:    opts.TenantID,
		RoleID:      opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMRoleCreate, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMRoleResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "CreateRole",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &CreateRoleResult{
		Role: convertRoleResponse(&resp),
	}, nil
}

// GetRole retrieves a role by ID
func (a *QUICAdapter) GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error) {
	req := daemon.GetRoleRequest{
		TenantID: opts.TenantID,
		RoleID:   opts.RoleID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMRoleGet, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMRoleResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetRole",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &GetRoleResult{
		Role: convertRoleResponse(&resp),
	}, nil
}

// UpdateRole updates an existing role
// NOTE: The QUIC protocol does not have a dedicated UpdateRole opcode.
// This operation is not supported via QUIC.
func (a *QUICAdapter) UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error) {
	return nil, &QUICNotSupportedError{Operation: "UpdateRole"}
}

// DeleteRole removes a role
func (a *QUICAdapter) DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error) {
	req := daemon.DeleteRoleRequest{
		TenantID: opts.TenantID,
		RoleID:   opts.RoleID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMRoleDelete, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.GenericIAMResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "DeleteRole",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &DeleteRoleResult{
		Success: resp.Success,
	}, nil
}

// ListRoles lists all roles with optional filtering
func (a *QUICAdapter) ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error) {
	req := daemon.ListIAMRequest{
		TenantID: opts.TenantID,
		Limit:    int(opts.Limit),
		Offset:   int(opts.Offset),
	}

	payload, err := a.doRequest(ctx, quic.OpIAMRoleList, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMRoleListResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "ListRoles",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	roles := make([]*Role, 0, len(resp.Roles))
	for _, r := range resp.Roles {
		roles = append(roles, convertRoleResponse(r))
	}

	return &ListRolesResult{
		Roles:  roles,
		Total:  int64(resp.Total),
		Limit:  int32(resp.Limit),
		Offset: int32(resp.Offset),
	}, nil
}

// =============================================================================
// Group CRUD Operations
// =============================================================================

// CreateGroup creates a new group
func (a *QUICAdapter) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*CreateGroupResult, error) {
	req := daemon.CreateGroupRequest{
		TenantID:    opts.TenantID,
		GroupID:     opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMGroupCreate, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMGroupResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "CreateGroup",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &CreateGroupResult{
		Group: convertGroupResponse(&resp),
	}, nil
}

// GetGroup retrieves a group by ID
func (a *QUICAdapter) GetGroup(ctx context.Context, opts GetGroupOptions) (*GetGroupResult, error) {
	req := daemon.GetGroupRequest{
		TenantID: opts.TenantID,
		GroupID:  opts.GroupID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMGroupGet, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMGroupResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetGroup",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &GetGroupResult{
		Group: convertGroupResponse(&resp),
	}, nil
}

// UpdateGroup updates an existing group
// NOTE: The QUIC protocol does not have a dedicated UpdateGroup opcode.
// This operation is not supported via QUIC.
func (a *QUICAdapter) UpdateGroup(ctx context.Context, opts UpdateGroupOptions) (*UpdateGroupResult, error) {
	return nil, &QUICNotSupportedError{Operation: "UpdateGroup"}
}

// DeleteGroup removes a group
func (a *QUICAdapter) DeleteGroup(ctx context.Context, opts DeleteGroupOptions) (*DeleteGroupResult, error) {
	req := daemon.DeleteGroupRequest{
		TenantID: opts.TenantID,
		GroupID:  opts.GroupID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMGroupDelete, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.GenericIAMResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "DeleteGroup",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &DeleteGroupResult{
		Success: resp.Success,
	}, nil
}

// ListGroups lists all groups with optional filtering
func (a *QUICAdapter) ListGroups(ctx context.Context, opts ListGroupsOptions) (*ListGroupsResult, error) {
	req := daemon.ListIAMRequest{
		TenantID: opts.TenantID,
		Limit:    int(opts.Limit),
		Offset:   int(opts.Offset),
	}

	payload, err := a.doRequest(ctx, quic.OpIAMGroupList, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.IAMGroupListResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "ListGroups",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	groups := make([]*Group, 0, len(resp.Groups))
	for _, g := range resp.Groups {
		groups = append(groups, convertGroupResponse(g))
	}

	return &ListGroupsResult{
		Groups: groups,
		Total:  int64(resp.Total),
		Limit:  int32(resp.Limit),
		Offset: int32(resp.Offset),
	}, nil
}

// AddMember adds a user to a group
func (a *QUICAdapter) AddMember(ctx context.Context, opts AddMemberOptions) (*AddMemberResult, error) {
	req := daemon.GroupMemberRequest{
		TenantID: opts.TenantID,
		GroupID:  opts.GroupID,
		UserID:   opts.UserID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMGroupAddMember, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.GenericIAMResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "AddMember",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &AddMemberResult{
		Success: resp.Success,
	}, nil
}

// RemoveMember removes a user from a group
func (a *QUICAdapter) RemoveMember(ctx context.Context, opts RemoveMemberOptions) (*RemoveMemberResult, error) {
	req := daemon.GroupMemberRequest{
		TenantID: opts.TenantID,
		GroupID:  opts.GroupID,
		UserID:   opts.UserID,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMGroupRemoveMember, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.GenericIAMResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "RemoveMember",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &RemoveMemberResult{
		Success: resp.Success,
	}, nil
}

// =============================================================================
// Permission Operations
// =============================================================================

// CheckPermission checks if a subject has permission for an action on a resource
func (a *QUICAdapter) CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error) {
	req := daemon.CheckPermissionRequest{
		TenantID:  opts.TenantID,
		SubjectID: opts.SubjectID,
		Resource:  opts.Resource,
		Action:    opts.Action,
		Context:   opts.Context,
	}

	payload, err := a.doRequest(ctx, quic.OpIAMCheckPermission, req)
	if err != nil {
		return nil, err
	}

	var resp daemon.CheckPermissionResponse
	if err := quic.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: "CheckPermission",
			Message:   "failed to decode response: " + err.Error(),
		}
	}

	return &CheckPermissionResult{
		Allowed: resp.Allowed,
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// convertUserResponse converts daemon.IAMUserResponse to User
func convertUserResponse(resp *daemon.IAMUserResponse) *User {
	if resp == nil {
		return nil
	}

	var createdAt, updatedAt *time.Time
	if resp.CreatedAt > 0 {
		t := time.Unix(resp.CreatedAt, 0)
		createdAt = &t
	}
	if resp.UpdatedAt > 0 {
		t := time.Unix(resp.UpdatedAt, 0)
		updatedAt = &t
	}

	return &User{
		ID:         resp.ID,
		TenantID:   resp.TenantID,
		Email:      resp.Email,
		Name:       resp.Name,
		Roles:      resp.Roles,
		Groups:     resp.Groups,
		Attributes: resp.Attributes,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
	}
}

// convertRoleResponse converts daemon.IAMRoleResponse to Role
func convertRoleResponse(resp *daemon.IAMRoleResponse) *Role {
	if resp == nil {
		return nil
	}

	var createdAt, updatedAt *time.Time
	if resp.CreatedAt > 0 {
		t := time.Unix(resp.CreatedAt, 0)
		createdAt = &t
	}
	if resp.UpdatedAt > 0 {
		t := time.Unix(resp.UpdatedAt, 0)
		updatedAt = &t
	}

	return &Role{
		ID:          resp.ID,
		TenantID:    resp.TenantID,
		Name:        resp.Name,
		Description: resp.Description,
		Permissions: resp.Permissions,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

// convertGroupResponse converts daemon.IAMGroupResponse to Group
func convertGroupResponse(resp *daemon.IAMGroupResponse) *Group {
	if resp == nil {
		return nil
	}

	var createdAt, updatedAt *time.Time
	if resp.CreatedAt > 0 {
		t := time.Unix(resp.CreatedAt, 0)
		createdAt = &t
	}
	if resp.UpdatedAt > 0 {
		t := time.Unix(resp.UpdatedAt, 0)
		updatedAt = &t
	}

	return &Group{
		ID:          resp.ID,
		TenantID:    resp.TenantID,
		Name:        resp.Name,
		Description: resp.Description,
		Members:     resp.Members,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

// Verify QUICAdapter implements IAMCommands
var _ IAMCommands = (*QUICAdapter)(nil)
