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
// This file implements the IAMCommands interface using gRPC protocol.
package iam

import (
	"context"
	"crypto/tls"
	"fmt"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements IAMCommands using gRPC API
type GRPCAdapter struct {
	endpoint  string
	tlsConfig *tls.Config
	conn      *grpc.ClientConn
	client    pb.PlatformIAMServiceClient
}

// NewGRPCAdapter creates a new gRPC adapter
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint:  GetGRPCEndpoint(),
		tlsConfig: helpers.TLSConfigOrInsecure(),
	}
}

// NewTenantGRPCAdapter is NewGRPCAdapter acting as the caller bound to
// helpers.ForeignTenantID.
func NewTenantGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint:  GetGRPCEndpoint(),
		tlsConfig: helpers.TenantTLSConfig(),
	}
}

// Setup prepares the adapter for testing
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.DialContext(ctx, a.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(a.tlsConfig)),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{
			Endpoint: a.endpoint,
			Err:      err,
		}
	}

	a.conn = conn
	a.client = pb.NewPlatformIAMServiceClient(conn)
	return nil
}

// Teardown cleans up after testing
func (a *GRPCAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name
func (a *GRPCAdapter) Name() string {
	return "gRPC"
}

// =============================================================================
// User CRUD Operations
// =============================================================================

// CreateUser creates a new user
func (a *GRPCAdapter) CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "CreateUser", Err: err}
	}

	return &CreateUserResult{
		User: protoToUser(resp.GetUser()),
	}, nil
}

// GetUser retrieves a user by ID
func (a *GRPCAdapter) GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error) {
	req := &pb.GetIAMUserRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.GetUser(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetUser", Err: err}
	}

	return &GetUserResult{
		User: protoToUser(resp.GetUser()),
	}, nil
}

// UpdateUser updates an existing user
func (a *GRPCAdapter) UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "UpdateUser", Err: err}
	}

	return &UpdateUserResult{
		User: protoToUser(resp.GetUser()),
	}, nil
}

// DeleteUser removes a user
func (a *GRPCAdapter) DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error) {
	req := &pb.DeleteIAMUserRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.DeleteUser(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteUser", Err: err}
	}

	return &DeleteUserResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListUsers lists all users with optional filtering
func (a *GRPCAdapter) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "ListUsers", Err: err}
	}

	users := make([]*User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		users = append(users, protoToUser(u))
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
func (a *GRPCAdapter) AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error) {
	req := &pb.AssignIAMRoleRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.AssignRole(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AssignRole", Err: err}
	}

	return &AssignRoleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// RevokeRole revokes a role from a user
func (a *GRPCAdapter) RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error) {
	req := &pb.RevokeIAMRoleRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.RevokeRole(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RevokeRole", Err: err}
	}

	return &RevokeRoleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// =============================================================================
// Group CRUD Operations
// =============================================================================

// CreateGroup creates a new group
func (a *GRPCAdapter) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*CreateGroupResult, error) {
	req := &pb.CreateIAMGroupRequest{
		TenantId:    opts.TenantID,
		Id:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
	}

	resp, err := a.client.CreateGroup(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateGroup", Err: err}
	}

	return &CreateGroupResult{
		Group: protoToGroup(resp.GetGroup()),
	}, nil
}

// GetGroup retrieves a group by ID
func (a *GRPCAdapter) GetGroup(ctx context.Context, opts GetGroupOptions) (*GetGroupResult, error) {
	req := &pb.GetIAMGroupRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
	}

	resp, err := a.client.GetGroup(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetGroup", Err: err}
	}

	return &GetGroupResult{
		Group: protoToGroup(resp.GetGroup()),
	}, nil
}

// UpdateGroup updates an existing group
func (a *GRPCAdapter) UpdateGroup(ctx context.Context, opts UpdateGroupOptions) (*UpdateGroupResult, error) {
	req := &pb.UpdateIAMGroupRequest{
		TenantId:    opts.TenantID,
		GroupId:     opts.GroupID,
		Name:        opts.Name,
		Description: opts.Description,
	}

	resp, err := a.client.UpdateGroup(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateGroup", Err: err}
	}

	return &UpdateGroupResult{
		Group: protoToGroup(resp.GetGroup()),
	}, nil
}

// DeleteGroup removes a group
func (a *GRPCAdapter) DeleteGroup(ctx context.Context, opts DeleteGroupOptions) (*DeleteGroupResult, error) {
	req := &pb.DeleteIAMGroupRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
	}

	resp, err := a.client.DeleteGroup(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteGroup", Err: err}
	}

	return &DeleteGroupResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListGroups lists all groups with optional filtering
func (a *GRPCAdapter) ListGroups(ctx context.Context, opts ListGroupsOptions) (*ListGroupsResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "ListGroups", Err: err}
	}

	groups := make([]*Group, 0, len(resp.GetGroups()))
	for _, g := range resp.GetGroups() {
		groups = append(groups, protoToGroup(g))
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
func (a *GRPCAdapter) AddMember(ctx context.Context, opts AddMemberOptions) (*AddMemberResult, error) {
	req := &pb.AddGroupMemberRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.AddGroupMember(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AddGroupMember", Err: err}
	}

	return &AddMemberResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// RemoveMember removes a user from a group
func (a *GRPCAdapter) RemoveMember(ctx context.Context, opts RemoveMemberOptions) (*RemoveMemberResult, error) {
	req := &pb.RemoveGroupMemberRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
		UserId:   opts.UserID,
	}

	resp, err := a.client.RemoveGroupMember(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RemoveGroupMember", Err: err}
	}

	return &RemoveMemberResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// =============================================================================
// Role CRUD Operations
// =============================================================================

// CreateRole creates a new role
func (a *GRPCAdapter) CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error) {
	req := &pb.CreateIAMRoleRequest{
		TenantId:    opts.TenantID,
		Id:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	}

	resp, err := a.client.CreateRole(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateRole", Err: err}
	}

	return &CreateRoleResult{
		Role: protoToRole(resp.GetRole()),
	}, nil
}

// GetRole retrieves a role by ID
func (a *GRPCAdapter) GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error) {
	req := &pb.GetIAMRoleRequest{
		TenantId: opts.TenantID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.GetRole(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetRole", Err: err}
	}

	return &GetRoleResult{
		Role: protoToRole(resp.GetRole()),
	}, nil
}

// UpdateRole updates an existing role
func (a *GRPCAdapter) UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error) {
	req := &pb.UpdateIAMRoleRequest{
		TenantId:    opts.TenantID,
		RoleId:      opts.RoleID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	}

	resp, err := a.client.UpdateRole(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateRole", Err: err}
	}

	return &UpdateRoleResult{
		Role: protoToRole(resp.GetRole()),
	}, nil
}

// DeleteRole removes a role
func (a *GRPCAdapter) DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error) {
	req := &pb.DeleteIAMRoleRequest{
		TenantId: opts.TenantID,
		RoleId:   opts.RoleID,
	}

	resp, err := a.client.DeleteRole(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteRole", Err: err}
	}

	return &DeleteRoleResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListRoles lists all roles with optional filtering
func (a *GRPCAdapter) ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "ListRoles", Err: err}
	}

	roles := make([]*Role, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		roles = append(roles, protoToRole(r))
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

// CheckPermission checks if a subject has permission to perform an action
func (a *GRPCAdapter) CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "CheckPermission", Err: err}
	}

	return &CheckPermissionResult{
		Allowed:          resp.GetAllowed(),
		MatchedPolicy:    resp.GetMatchedPolicy(),
		MatchedRule:      resp.GetMatchedRule(),
		EvaluationTimeNs: resp.GetEvaluationTimeNs(),
	}, nil
}

// =============================================================================
// Proto Conversion Helpers
// =============================================================================

// protoToUser converts a proto user to a domain user
func protoToUser(u *pb.IAMUser) *User {
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

// protoToRole converts a proto role to a domain role
func protoToRole(r *pb.IAMRole) *Role {
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

// protoToGroup converts a proto group to a domain group
func protoToGroup(g *pb.IAMGroup) *Group {
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

// Verify GRPCAdapter implements IAMCommands
var _ IAMCommands = (*GRPCAdapter)(nil)
