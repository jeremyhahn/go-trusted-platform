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

// Package iam provides multi-protocol integration test adapters for IAM
// services. This file implements the IAMCommands interface using the platform
// binary QUIC protocol. The wire contract is the platform.v1 protobuf
// request/response messages themselves, exactly like the SDK QUIC transport:
// the adapter hands the generated pb request struct to quicwire.EncodePayload (the
// server's own codec) and decodes the pb response struct, so the daemon's
// converged pb-delegating handlers see the real SDK wire shape.
package iam

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// QUICAdapterError represents an error from the QUIC adapter.
type QUICAdapterError struct {
	Operation string
	Message   string
}

func (e *QUICAdapterError) Error() string {
	return fmt.Sprintf("QUIC adapter error [%s]: %s", e.Operation, e.Message)
}

// ErrQUICStatus reports a non-OK status byte from the daemon, carrying the
// byte itself so a test can assert WHICH refusal it got rather than only
// that something failed.
//
// The distinction is the point of #486: a broken adapter also errors. Before
// this, iam's framing was already correct and had never once executed,
// because the ALPN handshake failed before a stream was opened -- and every
// call returned a generic adapter error that looked exactly like a refusal.
// Only an adapter speaking the server's framing can produce this type.
type ErrQUICStatus struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICStatus) Error() string {
	return fmt.Sprintf("QUIC %s refused with status 0x%02X: %s", e.Operation, e.Status, e.Message)
}

// QUICNotSupportedError represents an operation with no QUIC opcode. Role
// update has no PlatformIAMService QUIC opcode; the multi-protocol harness
// treats this as a skip.
type QUICNotSupportedError struct {
	Operation string
}

func (e *QUICNotSupportedError) Error() string {
	return fmt.Sprintf("QUIC protocol does not support operation: %s", e.Operation)
}

// QUICAdapter implements IAMCommands using the platform binary QUIC protocol.
type QUICAdapter struct {
	endpoint   string
	conn       *quicgo.Conn
	tlsConfig  *tls.Config
	quicConfig *quicgo.Config
	token      string
}

// NewQUICAdapter creates a new QUIC adapter.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:  GetQUICEndpoint(),
		tlsConfig: helpers.QUICTLSConfig(),
		quicConfig: &quicgo.Config{
			EnableDatagrams: true,
		},
		token: GetAdminToken(),
	}
}

// Setup prepares the adapter for testing.
func (a *QUICAdapter) Setup(ctx context.Context) error {
	conn, err := quicgo.DialAddr(ctx, a.endpoint, a.tlsConfig, a.quicConfig)
	if err != nil {
		return &QUICAdapterError{Operation: "Setup", Message: "failed to connect: " + err.Error()}
	}
	a.conn = conn
	return nil
}

// Teardown cleans up after testing.
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.CloseWithError(0, "teardown")
	}
	return nil
}

// Name returns the adapter name.
func (a *QUICAdapter) Name() string { return "QUIC" }

// doRequest performs one binary QUIC request/response round trip. body is a
// platform.v1 request message (or nil).
func (a *QUICAdapter) doRequest(ctx context.Context, opcode byte, body interface{}) ([]byte, error) {
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = quicwire.EncodePayload(body)
		if err != nil {
			return nil, &QUICAdapterError{Operation: quicwire.OpcodeToString(opcode), Message: "failed to encode payload: " + err.Error()}
		}
	}
	return a.send(ctx, opcode, encoded)
}

// doCategoryRequest sends body under a category opcode: the sub-opcode is
// payload[0] and the encoded body follows it.
func (a *QUICAdapter) doCategoryRequest(ctx context.Context, opcode, sub byte, body interface{}) ([]byte, error) {
	encoded, err := quicwire.EncodePayload(body)
	if err != nil {
		return nil, &QUICAdapterError{Operation: quicwire.OpcodeToString(opcode), Message: "failed to encode payload: " + err.Error()}
	}
	return a.send(ctx, opcode, append([]byte{sub}, encoded...))
}

// send writes one request on a new stream and returns the OK response payload.
func (a *QUICAdapter) send(ctx context.Context, opcode byte, encoded []byte) ([]byte, error) {
	stream, err := a.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, &QUICAdapterError{Operation: quicwire.OpcodeToString(opcode), Message: "failed to open stream: " + err.Error()}
	}
	defer stream.Close()

	req := &quicwire.Request{Opcode: opcode, Token: a.token, Payload: encoded}
	if err := quicwire.WriteRequest(stream, req); err != nil {
		return nil, &QUICAdapterError{Operation: quicwire.OpcodeToString(opcode), Message: "failed to write request: " + err.Error()}
	}
	if err := stream.Close(); err != nil {
		return nil, &QUICAdapterError{Operation: quicwire.OpcodeToString(opcode), Message: "failed to close write: " + err.Error()}
	}

	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return nil, &QUICAdapterError{Operation: quicwire.OpcodeToString(opcode), Message: "failed to read response: " + err.Error()}
	}
	if resp.Status != quicwire.StatusOK {
		msg := string(resp.Payload)
		if msg == "" {
			msg = quicwire.StatusToString(resp.Status)
		}
		return nil, ErrQUICStatus{Operation: quicwire.OpcodeToString(opcode), Status: resp.Status, Message: msg}
	}
	return resp.Payload, nil
}

// =============================================================================
// User CRUD Operations
// =============================================================================

// CreateUser creates a new user. The pb request carries Roles/Groups the flat
// struct lacked.
func (a *QUICAdapter) CreateUser(ctx context.Context, opts CreateUserOptions) (*CreateUserResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMUserCreate, &platformv1.CreateIAMUserRequest{
		TenantId:   opts.TenantID,
		Email:      opts.Email,
		Name:       opts.Name,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Attributes: opts.Attributes,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMUserResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "CreateUser", Message: "failed to decode response: " + err.Error()}
	}
	return &CreateUserResult{User: pbUserToUser(resp.GetUser())}, nil
}

// GetUser retrieves a user by ID.
func (a *QUICAdapter) GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMUserGet, &platformv1.GetIAMUserRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMUserResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "GetUser", Message: "failed to decode response: " + err.Error()}
	}
	return &GetUserResult{User: pbUserToUser(resp.GetUser())}, nil
}

// UpdateUser updates an existing user.
func (a *QUICAdapter) UpdateUser(ctx context.Context, opts UpdateUserOptions) (*UpdateUserResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMUserUpdate, &platformv1.UpdateIAMUserRequest{
		TenantId:   opts.TenantID,
		UserId:     opts.UserID,
		Email:      opts.Email,
		Name:       opts.Name,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Attributes: opts.Attributes,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMUserResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "UpdateUser", Message: "failed to decode response: " + err.Error()}
	}
	return &UpdateUserResult{User: pbUserToUser(resp.GetUser())}, nil
}

// DeleteUser removes a user.
func (a *QUICAdapter) DeleteUser(ctx context.Context, opts DeleteUserOptions) (*DeleteUserResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMUserDelete, &platformv1.DeleteIAMUserRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.DeleteIAMUserResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "DeleteUser", Message: "failed to decode response: " + err.Error()}
	}
	return &DeleteUserResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// ListUsers lists users with optional filtering.
func (a *QUICAdapter) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	req := &platformv1.ListIAMUsersRequest{
		TenantId:    opts.TenantID,
		EmailFilter: opts.Email,
		RoleFilter:  opts.Role,
		GroupFilter: opts.Group,
	}
	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{PageSize: uint32(opts.Limit)}
	}

	payload, err := a.doRequest(ctx, quicwire.OpIAMUserList, req)
	if err != nil {
		return nil, err
	}
	var resp platformv1.ListIAMUsersResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "ListUsers", Message: "failed to decode response: " + err.Error()}
	}
	users := make([]*User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		users = append(users, pbUserToUser(u))
	}
	return &ListUsersResult{Users: users, Total: resp.GetTotal(), Limit: opts.Limit, Offset: opts.Offset}, nil
}

// =============================================================================
// User Role Operations
// =============================================================================

// AssignRole assigns a role to a user.
func (a *QUICAdapter) AssignRole(ctx context.Context, opts AssignRoleOptions) (*AssignRoleResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMRoleAssign, &platformv1.AssignIAMRoleRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
		RoleId:   opts.RoleID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.AssignIAMRoleResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "AssignRole", Message: "failed to decode response: " + err.Error()}
	}
	return &AssignRoleResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// RevokeRole revokes a role from a user.
func (a *QUICAdapter) RevokeRole(ctx context.Context, opts RevokeRoleOptions) (*RevokeRoleResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMRoleRevoke, &platformv1.RevokeIAMRoleRequest{
		TenantId: opts.TenantID,
		UserId:   opts.UserID,
		RoleId:   opts.RoleID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.RevokeIAMRoleResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "RevokeRole", Message: "failed to decode response: " + err.Error()}
	}
	return &RevokeRoleResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// =============================================================================
// Role CRUD Operations
// =============================================================================

// CreateRole creates a new role.
func (a *QUICAdapter) CreateRole(ctx context.Context, opts CreateRoleOptions) (*CreateRoleResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMRoleCreate, &platformv1.CreateIAMRoleRequest{
		TenantId:    opts.TenantID,
		Id:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMRoleResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "CreateRole", Message: "failed to decode response: " + err.Error()}
	}
	return &CreateRoleResult{Role: pbRoleToRole(resp.GetRole())}, nil
}

// GetRole retrieves a role by ID.
func (a *QUICAdapter) GetRole(ctx context.Context, opts GetRoleOptions) (*GetRoleResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMRoleGet, &platformv1.GetIAMRoleRequest{
		TenantId: opts.TenantID,
		RoleId:   opts.RoleID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMRoleResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "GetRole", Message: "failed to decode response: " + err.Error()}
	}
	return &GetRoleResult{Role: pbRoleToRole(resp.GetRole())}, nil
}

// UpdateRole has no QUIC opcode on the PlatformIAMService surface.
func (a *QUICAdapter) UpdateRole(ctx context.Context, opts UpdateRoleOptions) (*UpdateRoleResult, error) {
	return nil, &QUICNotSupportedError{Operation: "UpdateRole"}
}

// DeleteRole removes a role.
func (a *QUICAdapter) DeleteRole(ctx context.Context, opts DeleteRoleOptions) (*DeleteRoleResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMRoleDelete, &platformv1.DeleteIAMRoleRequest{
		TenantId: opts.TenantID,
		RoleId:   opts.RoleID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.DeleteIAMRoleResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "DeleteRole", Message: "failed to decode response: " + err.Error()}
	}
	return &DeleteRoleResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// ListRoles lists roles with optional filtering.
func (a *QUICAdapter) ListRoles(ctx context.Context, opts ListRolesOptions) (*ListRolesResult, error) {
	req := &platformv1.ListIAMRolesRequest{TenantId: opts.TenantID}
	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{PageSize: uint32(opts.Limit)}
	}

	payload, err := a.doRequest(ctx, quicwire.OpIAMRoleList, req)
	if err != nil {
		return nil, err
	}
	var resp platformv1.ListIAMRolesResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "ListRoles", Message: "failed to decode response: " + err.Error()}
	}
	roles := make([]*Role, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		roles = append(roles, pbRoleToRole(r))
	}
	return &ListRolesResult{Roles: roles, Total: resp.GetTotal(), Limit: opts.Limit, Offset: opts.Offset}, nil
}

// =============================================================================
// Group CRUD Operations
// =============================================================================

// CreateGroup creates a new group.
func (a *QUICAdapter) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*CreateGroupResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMGroupCreate, &platformv1.CreateIAMGroupRequest{
		TenantId:    opts.TenantID,
		Id:          opts.ID,
		Name:        opts.Name,
		Description: opts.Description,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMGroupResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "CreateGroup", Message: "failed to decode response: " + err.Error()}
	}
	return &CreateGroupResult{Group: pbGroupToGroup(resp.GetGroup())}, nil
}

// GetGroup retrieves a group by ID.
func (a *QUICAdapter) GetGroup(ctx context.Context, opts GetGroupOptions) (*GetGroupResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMGroupGet, &platformv1.GetIAMGroupRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMGroupResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "GetGroup", Message: "failed to decode response: " + err.Error()}
	}
	return &GetGroupResult{Group: pbGroupToGroup(resp.GetGroup())}, nil
}

// UpdateGroup rides the IAM category opcode (0x51) as sub-opcode
// IAMSubGroupUpdate: the group opcode bytes have no room for an update.
func (a *QUICAdapter) UpdateGroup(ctx context.Context, opts UpdateGroupOptions) (*UpdateGroupResult, error) {
	payload, err := a.doCategoryRequest(ctx, quicwire.OpIAMCategory, quicwire.IAMSubGroupUpdate, &platformv1.UpdateIAMGroupRequest{
		TenantId:    opts.TenantID,
		GroupId:     opts.GroupID,
		Name:        opts.Name,
		Description: opts.Description,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.IAMGroupResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "UpdateGroup", Message: "failed to decode response: " + err.Error()}
	}
	return &UpdateGroupResult{Group: pbGroupToGroup(resp.GetGroup())}, nil
}

// DeleteGroup removes a group.
func (a *QUICAdapter) DeleteGroup(ctx context.Context, opts DeleteGroupOptions) (*DeleteGroupResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMGroupDelete, &platformv1.DeleteIAMGroupRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.DeleteIAMGroupResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "DeleteGroup", Message: "failed to decode response: " + err.Error()}
	}
	return &DeleteGroupResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// ListGroups lists groups with optional filtering.
func (a *QUICAdapter) ListGroups(ctx context.Context, opts ListGroupsOptions) (*ListGroupsResult, error) {
	req := &platformv1.ListIAMGroupsRequest{TenantId: opts.TenantID}
	if opts.Limit > 0 {
		req.Pagination = &platformv1.PaginationRequest{PageSize: uint32(opts.Limit)}
	}

	payload, err := a.doRequest(ctx, quicwire.OpIAMGroupList, req)
	if err != nil {
		return nil, err
	}
	var resp platformv1.ListIAMGroupsResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "ListGroups", Message: "failed to decode response: " + err.Error()}
	}
	groups := make([]*Group, 0, len(resp.GetGroups()))
	for _, g := range resp.GetGroups() {
		groups = append(groups, pbGroupToGroup(g))
	}
	return &ListGroupsResult{Groups: groups, Total: resp.GetTotal(), Limit: opts.Limit, Offset: opts.Offset}, nil
}

// =============================================================================
// Group Membership Operations
// =============================================================================

// AddMember adds a user to a group.
func (a *QUICAdapter) AddMember(ctx context.Context, opts AddMemberOptions) (*AddMemberResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMGroupAddMember, &platformv1.AddGroupMemberRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
		UserId:   opts.UserID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.AddGroupMemberResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "AddMember", Message: "failed to decode response: " + err.Error()}
	}
	return &AddMemberResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// RemoveMember removes a user from a group.
func (a *QUICAdapter) RemoveMember(ctx context.Context, opts RemoveMemberOptions) (*RemoveMemberResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMGroupRemoveMember, &platformv1.RemoveGroupMemberRequest{
		TenantId: opts.TenantID,
		GroupId:  opts.GroupID,
		UserId:   opts.UserID,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.RemoveGroupMemberResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "RemoveMember", Message: "failed to decode response: " + err.Error()}
	}
	return &RemoveMemberResult{Success: resp.GetStatus().GetSuccess()}, nil
}

// =============================================================================
// Permission Operations
// =============================================================================

// CheckPermission checks if a subject has permission for an action on a resource.
func (a *QUICAdapter) CheckPermission(ctx context.Context, opts CheckPermissionOptions) (*CheckPermissionResult, error) {
	payload, err := a.doRequest(ctx, quicwire.OpIAMCheckPermission, &platformv1.CheckIAMPermissionRequest{
		TenantId:   opts.TenantID,
		SubjectId:  opts.SubjectID,
		Action:     opts.Action,
		Resource:   opts.Resource,
		Roles:      opts.Roles,
		Groups:     opts.Groups,
		Context:    opts.Context,
		Attributes: opts.Attributes,
	})
	if err != nil {
		return nil, err
	}
	var resp platformv1.CheckIAMPermissionResponse
	if err := quicwire.DecodePayload(payload, &resp); err != nil {
		return nil, &QUICAdapterError{Operation: "CheckPermission", Message: "failed to decode response: " + err.Error()}
	}
	return &CheckPermissionResult{
		Allowed:          resp.GetAllowed(),
		MatchedPolicy:    resp.GetMatchedPolicy(),
		MatchedRule:      resp.GetMatchedRule(),
		EvaluationTimeNs: resp.GetEvaluationTimeNs(),
	}, nil
}

// =============================================================================
// Conversion helpers
// =============================================================================

func pbUserToUser(u *platformv1.IAMUser) *User {
	if u == nil {
		return nil
	}
	return &User{
		ID:          u.GetId(),
		TenantID:    u.GetTenantId(),
		Email:       u.GetEmail(),
		Name:        u.GetName(),
		Roles:       u.GetRoles(),
		Groups:      u.GetGroups(),
		Attributes:  u.GetAttributes(),
		MFAVerified: u.GetMfaVerified(),
		CreatedAt:   pbTimePtr(u.GetCreatedAt()),
		UpdatedAt:   pbTimePtr(u.GetUpdatedAt()),
		LastAuth:    pbTimePtr(u.GetLastAuth()),
	}
}

func pbRoleToRole(r *platformv1.IAMRole) *Role {
	if r == nil {
		return nil
	}
	return &Role{
		ID:          r.GetId(),
		TenantID:    r.GetTenantId(),
		Name:        r.GetName(),
		Description: r.GetDescription(),
		Permissions: r.GetPermissions(),
		CreatedAt:   pbTimePtr(r.GetCreatedAt()),
		UpdatedAt:   pbTimePtr(r.GetUpdatedAt()),
	}
}

func pbGroupToGroup(g *platformv1.IAMGroup) *Group {
	if g == nil {
		return nil
	}
	return &Group{
		ID:          g.GetId(),
		TenantID:    g.GetTenantId(),
		Name:        g.GetName(),
		Description: g.GetDescription(),
		Members:     g.GetMembers(),
		CreatedAt:   pbTimePtr(g.GetCreatedAt()),
		UpdatedAt:   pbTimePtr(g.GetUpdatedAt()),
	}
}

// pbTimePtr converts a protobuf timestamp to a *time.Time, returning nil for a
// nil/zero timestamp so the JSON result omits it.
func pbTimePtr(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	if t.IsZero() {
		return nil
	}
	return &t
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

var _ IAMCommands = (*QUICAdapter)(nil)
