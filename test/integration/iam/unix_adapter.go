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

// Package iam provides integration test adapters for IAM services.
// This file implements the IAMCommands interface using gRPC over Unix socket.
package iam

import (
	"context"
	"fmt"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixConnectionFailed indicates a Unix socket connection failure.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// UnixAdapter implements IAMCommands using Unix domain socket
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     pb.PlatformIAMServiceClient
}

// NewUnixAdapter creates a new Unix socket adapter
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup prepares the adapter for testing
func (a *UnixAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.NewClient("unix://"+a.socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return ErrUnixConnectionFailed{
			Path: a.socketPath,
			Err:  err,
		}
	}

	a.conn = conn
	a.client = pb.NewPlatformIAMServiceClient(conn)
	return nil
}

// Teardown cleans up after testing
func (a *UnixAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name
func (a *UnixAdapter) Name() string {
	return "Unix"
}

// =============================================================================
// User CRUD Operations
// =============================================================================

// CreateUser creates a new user
func (a *UnixAdapter) CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error) {
	req := &pb.CreateIAMUserRequest{
		TenantId:   opts.TenantID,
		Email:      opts.Email,
		Name:       opts.Name,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Attributes: opts.Attributes,
	}

	resp, err := a.client.CreateUser(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateUser", Err: err}
	}

	return &CreateUserResult{
		User: unixProtoToUser(resp.GetUser()),
	}, nil
}

// GetUser retrieves a user by ID
func (a *UnixAdapter) GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error) {
	req := &pb.GetIAMUserRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.GetUser(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetUser", Err: err}
	}

	return &GetUserResult{
		User: unixProtoToUser(resp.GetUser()),
	}, nil
}

// UpdateUser updates an existing user
func (a *UnixAdapter) UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error) {
	req := &pb.UpdateIAMUserRequest{
		TenantId:   opts.TenantID,
		UserId:     opts.UserID,
		Email:      opts.Email,
		Name:       opts.Name,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Attributes: opts.Attributes,
	}

	resp, err := a.client.UpdateUser(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateUser", Err: err}
	}

	return &UpdateUserResult{
		User: unixProtoToUser(resp.GetUser()),
	}, nil
}

// DeleteUser removes a user
func (a *UnixAdapter) DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error) {
	req := &pb.DeleteIAMUserRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.DeleteUser(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteUser", Err: err}
	}

	return &DeleteUserResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListUsers lists all users with optional filtering
func (a *UnixAdapter) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	page := uint32(1)
	if opts.Limit > 0 && opts.Offset > 0 {
		page = uint32(opts.Offset/opts.Limit) + 1
	}

	req := &pb.ListIAMUsersRequest{
		TenantId: opts.TenantID,
		Pagination: &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     page,
		},
		EmailFilter: opts.Email,
		RoleFilter:  opts.Role,
		GroupFilter: opts.Group,
	}

	resp, err := a.client.ListUsers(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListUsers", Err: err}
	}

	users := make([]*User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		users = append(users, unixProtoToUser(u))
	}

	return &ListUsersResult{
		Users:  users,
		Total:  resp.GetTotal(),
		Limit:  opts.Limit,
		Offset: opts.Offset,
	}, nil
}

// =============================================================================
// User Role Operations
// =============================================================================

// AssignRole assigns a role to a user
func (a *UnixAdapter) AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error) {
	req := &pb.AssignIAMRoleRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.AssignRole(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AssignRole", Err: err}
	}

	return &AssignRoleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// RevokeRole revokes a role from a user
func (a *UnixAdapter) RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error) {
	req := &pb.RevokeIAMRoleRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.RevokeRole(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RevokeRole", Err: err}
	}

	return &RevokeRoleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// =============================================================================
// Group CRUD Operations
// =============================================================================

// CreateGroup creates a new group
func (a *UnixAdapter) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*CreateGroupResult, error) {
	req := &pb.CreateIAMGroupRequest{
		TenantId:    opts.TenantID,
		Id:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
	}

	resp, err := a.client.CreateGroup(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateGroup", Err: err}
	}

	return &CreateGroupResult{
		Group: unixProtoToGroup(resp.GetGroup()),
	}, nil
}

// GetGroup retrieves a group by ID
func (a *UnixAdapter) GetGroup(ctx context.Context, opts GetGroupOptions) (*GetGroupResult, error) {
	req := &pb.GetIAMGroupRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
	}

	resp, err := a.client.GetGroup(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetGroup", Err: err}
	}

	return &GetGroupResult{
		Group: unixProtoToGroup(resp.GetGroup()),
	}, nil
}

// UpdateGroup updates an existing group
func (a *UnixAdapter) UpdateGroup(ctx context.Context, opts UpdateGroupOptions) (*UpdateGroupResult, error) {
	req := &pb.UpdateIAMGroupRequest{
		TenantId:    opts.TenantID,
		GroupId:     opts.GroupID,
		Name:        opts.Name,
		Description: opts.Description,
	}

	resp, err := a.client.UpdateGroup(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateGroup", Err: err}
	}

	return &UpdateGroupResult{
		Group: unixProtoToGroup(resp.GetGroup()),
	}, nil
}

// DeleteGroup removes a group
func (a *UnixAdapter) DeleteGroup(ctx context.Context, opts DeleteGroupOptions) (*DeleteGroupResult, error) {
	req := &pb.DeleteIAMGroupRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
	}

	resp, err := a.client.DeleteGroup(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteGroup", Err: err}
	}

	return &DeleteGroupResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListGroups lists all groups with optional filtering
func (a *UnixAdapter) ListGroups(ctx context.Context, opts ListGroupsOptions) (*ListGroupsResult, error) {
	page := uint32(1)
	if opts.Limit > 0 && opts.Offset > 0 {
		page = uint32(opts.Offset/opts.Limit) + 1
	}

	req := &pb.ListIAMGroupsRequest{
		TenantId: opts.TenantID,
		Pagination: &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     page,
		},
	}

	resp, err := a.client.ListGroups(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListGroups", Err: err}
	}

	groups := make([]*Group, 0, len(resp.GetGroups()))
	for _, g := range resp.GetGroups() {
		groups = append(groups, unixProtoToGroup(g))
	}

	return &ListGroupsResult{
		Groups: groups,
		Total:  resp.GetTotal(),
		Limit:  opts.Limit,
		Offset: opts.Offset,
	}, nil
}

// =============================================================================
// Group Membership Operations
// =============================================================================

// AddMember adds a user to a group
func (a *UnixAdapter) AddMember(ctx context.Context, opts AddMemberOptions) (*AddMemberResult, error) {
	req := &pb.AddGroupMemberRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.AddGroupMember(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AddGroupMember", Err: err}
	}

	return &AddMemberResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// RemoveMember removes a user from a group
func (a *UnixAdapter) RemoveMember(ctx context.Context, opts RemoveMemberOptions) (*RemoveMemberResult, error) {
	req := &pb.RemoveGroupMemberRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.RemoveGroupMember(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RemoveGroupMember", Err: err}
	}

	return &RemoveMemberResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// =============================================================================
// Role CRUD Operations
// =============================================================================

// CreateRole creates a new role
func (a *UnixAdapter) CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error) {
	req := &pb.CreateIAMRoleRequest{
		TenantId:    opts.TenantID,
		Id:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	}

	resp, err := a.client.CreateRole(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateRole", Err: err}
	}

	return &CreateRoleResult{
		Role: unixProtoToRole(resp.GetRole()),
	}, nil
}

// GetRole retrieves a role by ID
func (a *UnixAdapter) GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error) {
	req := &pb.GetIAMRoleRequest{
		TenantId: opts.TenantID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.GetRole(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetRole", Err: err}
	}

	return &GetRoleResult{
		Role: unixProtoToRole(resp.GetRole()),
	}, nil
}

// UpdateRole updates an existing role
func (a *UnixAdapter) UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error) {
	req := &pb.UpdateIAMRoleRequest{
		TenantId:    opts.TenantID,
		RoleId:      opts.RoleID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	}

	resp, err := a.client.UpdateRole(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateRole", Err: err}
	}

	return &UpdateRoleResult{
		Role: unixProtoToRole(resp.GetRole()),
	}, nil
}

// DeleteRole removes a role
func (a *UnixAdapter) DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error) {
	req := &pb.DeleteIAMRoleRequest{
		TenantId: opts.TenantID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.DeleteRole(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteRole", Err: err}
	}

	return &DeleteRoleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListRoles lists all roles with optional filtering
func (a *UnixAdapter) ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error) {
	page := uint32(1)
	if opts.Limit > 0 && opts.Offset > 0 {
		page = uint32(opts.Offset/opts.Limit) + 1
	}

	req := &pb.ListIAMRolesRequest{
		TenantId: opts.TenantID,
		Pagination: &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     page,
		},
	}

	resp, err := a.client.ListRoles(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListRoles", Err: err}
	}

	roles := make([]*Role, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		roles = append(roles, unixProtoToRole(r))
	}

	return &ListRolesResult{
		Roles:  roles,
		Total:  resp.GetTotal(),
		Limit:  opts.Limit,
		Offset: opts.Offset,
	}, nil
}

// =============================================================================
// Permission Operations
// =============================================================================

// CheckPermission checks if a subject has permission for an action on a resource
func (a *UnixAdapter) CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error) {
	req := &pb.CheckIAMPermissionRequest{
		TenantId:   opts.TenantID,
		SubjectId:  opts.SubjectID,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Action:     opts.Action,
		Resource:   opts.Resource,
		Context:    opts.Context,
		Attributes: opts.Attributes,
	}

	resp, err := a.client.CheckPermission(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CheckPermission", Err: err}
	}

	return &CheckPermissionResult{
		Allowed:          resp.GetAllowed(),
		MatchedPolicy:    resp.GetMatchedPolicy(),
		MatchedRule:      resp.GetMatchedRule(),
		EvaluationTimeNs: resp.GetEvaluationTimeNs(),
	}, nil
}

// =============================================================================
// Proto Conversion Helpers (Unix-specific to avoid name collisions)
// =============================================================================

// unixProtoToUser converts a proto user to a domain user
func unixProtoToUser(u *pb.IAMUser) *User {
	if u == nil {
		return nil
	}

	user := &User{
		ID:          u.GetId(),
		TenantID:    u.GetTenantId(),
		Email:       u.GetEmail(),
		Name:        u.GetName(),
		Roles:       u.GetRoles(),
		Groups:      u.GetGroups(),
		Attributes:  u.GetAttributes(),
		MFAVerified: u.GetMfaVerified(),
	}

	if u.GetCreatedAt() != nil {
		t := u.GetCreatedAt().AsTime()
		user.CreatedAt = &t
	}
	if u.GetUpdatedAt() != nil {
		t := u.GetUpdatedAt().AsTime()
		user.UpdatedAt = &t
	}
	if u.GetLastAuth() != nil {
		t := u.GetLastAuth().AsTime()
		user.LastAuth = &t
	}

	return user
}

// unixProtoToRole converts a proto role to a domain role
func unixProtoToRole(r *pb.IAMRole) *Role {
	if r == nil {
		return nil
	}

	role := &Role{
		ID:          r.GetId(),
		TenantID:    r.GetTenantId(),
		Name:        r.GetName(),
		Description: r.GetDescription(),
		Permissions: r.GetPermissions(),
	}

	if r.GetCreatedAt() != nil {
		t := r.GetCreatedAt().AsTime()
		role.CreatedAt = &t
	}
	if r.GetUpdatedAt() != nil {
		t := r.GetUpdatedAt().AsTime()
		role.UpdatedAt = &t
	}

	return role
}

// unixProtoToGroup converts a proto group to a domain group
func unixProtoToGroup(g *pb.IAMGroup) *Group {
	if g == nil {
		return nil
	}

	group := &Group{
		ID:          g.GetId(),
		TenantID:    g.GetTenantId(),
		Name:        g.GetName(),
		Description: g.GetDescription(),
		Members:     g.GetMembers(),
	}

	if g.GetCreatedAt() != nil {
		t := g.GetCreatedAt().AsTime()
		group.CreatedAt = &t
	}
	if g.GetUpdatedAt() != nil {
		t := g.GetUpdatedAt().AsTime()
		group.UpdatedAt = &t
	}

	return group
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify UnixAdapter implements IAMCommands
var _ IAMCommands = (*UnixAdapter)(nil)
