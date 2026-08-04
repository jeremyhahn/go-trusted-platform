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

// Package iam provides a client for Identity and Access Management service operations.
package iam

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to IAM service operations.
type Client struct {
	grpc platformv1.PlatformIAMServiceClient
}

// NewClient creates a new IAM service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewPlatformIAMServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new IAM service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.PlatformIAMServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// User Operations

// CreateUser creates a new user.
func (c *Client) CreateUser(ctx context.Context, req *platformv1.CreateIAMUserRequest) (*platformv1.IAMUser, error) {
	resp, err := c.grpc.CreateUser(ctx, req)
	if err != nil {
		return nil, &ErrCreateUserFailed{Cause: err}
	}
	return resp.User, nil
}

// GetUser retrieves a user by ID.
func (c *Client) GetUser(ctx context.Context, tenantID, userID string) (*platformv1.IAMUser, error) {
	resp, err := c.grpc.GetUser(ctx, &platformv1.GetIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	if err != nil {
		return nil, &ErrGetUserFailed{ID: userID, Cause: err}
	}
	return resp.User, nil
}

// ListUsers lists users with optional filtering.
func (c *Client) ListUsers(ctx context.Context, req *platformv1.ListIAMUsersRequest) ([]*platformv1.IAMUser, int64, error) {
	resp, err := c.grpc.ListUsers(ctx, req)
	if err != nil {
		return nil, 0, &ErrListUsersFailed{Cause: err}
	}
	return resp.Users, resp.Total, nil
}

// UpdateUser updates an existing user.
func (c *Client) UpdateUser(ctx context.Context, req *platformv1.UpdateIAMUserRequest) (*platformv1.IAMUser, error) {
	resp, err := c.grpc.UpdateUser(ctx, req)
	if err != nil {
		return nil, &ErrUpdateUserFailed{ID: req.UserId, Cause: err}
	}
	return resp.User, nil
}

// DeleteUser deletes a user.
func (c *Client) DeleteUser(ctx context.Context, tenantID, userID string) error {
	_, err := c.grpc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	if err != nil {
		return &ErrDeleteUserFailed{ID: userID, Cause: err}
	}
	return nil
}

// Role Operations

// CreateRole creates a new role.
func (c *Client) CreateRole(ctx context.Context, req *platformv1.CreateIAMRoleRequest) (*platformv1.IAMRole, error) {
	resp, err := c.grpc.CreateRole(ctx, req)
	if err != nil {
		return nil, &ErrCreateRoleFailed{Cause: err}
	}
	return resp.Role, nil
}

// GetRole retrieves a role by ID.
func (c *Client) GetRole(ctx context.Context, tenantID, roleID string) (*platformv1.IAMRole, error) {
	resp, err := c.grpc.GetRole(ctx, &platformv1.GetIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, &ErrGetRoleFailed{ID: roleID, Cause: err}
	}
	return resp.Role, nil
}

// ListRoles lists roles with optional filtering.
func (c *Client) ListRoles(ctx context.Context, req *platformv1.ListIAMRolesRequest) ([]*platformv1.IAMRole, int64, error) {
	resp, err := c.grpc.ListRoles(ctx, req)
	if err != nil {
		return nil, 0, &ErrListRolesFailed{Cause: err}
	}
	return resp.Roles, resp.Total, nil
}

// UpdateRole updates an existing role.
func (c *Client) UpdateRole(ctx context.Context, req *platformv1.UpdateIAMRoleRequest) (*platformv1.IAMRole, error) {
	resp, err := c.grpc.UpdateRole(ctx, req)
	if err != nil {
		return nil, &ErrUpdateRoleFailed{ID: req.RoleId, Cause: err}
	}
	return resp.Role, nil
}

// DeleteRole deletes a role.
func (c *Client) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	_, err := c.grpc.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	if err != nil {
		return &ErrDeleteRoleFailed{ID: roleID, Cause: err}
	}
	return nil
}

// AssignRole assigns a role to a user.
func (c *Client) AssignRole(ctx context.Context, tenantID, userID, roleID string) error {
	_, err := c.grpc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		RoleId:   roleID,
	})
	if err != nil {
		return &ErrAssignRoleFailed{UserID: userID, RoleID: roleID, Cause: err}
	}
	return nil
}

// RevokeRole revokes a role from a user.
func (c *Client) RevokeRole(ctx context.Context, tenantID, userID, roleID string) error {
	_, err := c.grpc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		RoleId:   roleID,
	})
	if err != nil {
		return &ErrRevokeRoleFailed{UserID: userID, RoleID: roleID, Cause: err}
	}
	return nil
}

// Group Operations

// CreateGroup creates a new group.
func (c *Client) CreateGroup(ctx context.Context, req *platformv1.CreateIAMGroupRequest) (*platformv1.IAMGroup, error) {
	resp, err := c.grpc.CreateGroup(ctx, req)
	if err != nil {
		return nil, &ErrCreateGroupFailed{Cause: err}
	}
	return resp.Group, nil
}

// GetGroup retrieves a group by ID.
func (c *Client) GetGroup(ctx context.Context, tenantID, groupID string) (*platformv1.IAMGroup, error) {
	resp, err := c.grpc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	})
	if err != nil {
		return nil, &ErrGetGroupFailed{ID: groupID, Cause: err}
	}
	return resp.Group, nil
}

// ListGroups lists groups with optional filtering.
func (c *Client) ListGroups(ctx context.Context, req *platformv1.ListIAMGroupsRequest) ([]*platformv1.IAMGroup, int64, error) {
	resp, err := c.grpc.ListGroups(ctx, req)
	if err != nil {
		return nil, 0, &ErrListGroupsFailed{Cause: err}
	}
	return resp.Groups, resp.Total, nil
}

// UpdateGroup updates an existing group.
func (c *Client) UpdateGroup(ctx context.Context, req *platformv1.UpdateIAMGroupRequest) (*platformv1.IAMGroup, error) {
	resp, err := c.grpc.UpdateGroup(ctx, req)
	if err != nil {
		return nil, &ErrUpdateGroupFailed{ID: req.GroupId, Cause: err}
	}
	return resp.Group, nil
}

// DeleteGroup deletes a group.
func (c *Client) DeleteGroup(ctx context.Context, tenantID, groupID string) error {
	_, err := c.grpc.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	})
	if err != nil {
		return &ErrDeleteGroupFailed{ID: groupID, Cause: err}
	}
	return nil
}

// AddGroupMember adds a user to a group.
func (c *Client) AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	_, err := c.grpc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{
		TenantId: tenantID,
		GroupId:  groupID,
		UserId:   userID,
	})
	if err != nil {
		return &ErrAddGroupMemberFailed{GroupID: groupID, UserID: userID, Cause: err}
	}
	return nil
}

// RemoveGroupMember removes a user from a group.
func (c *Client) RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	_, err := c.grpc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{
		TenantId: tenantID,
		GroupId:  groupID,
		UserId:   userID,
	})
	if err != nil {
		return &ErrRemoveGroupMemberFailed{GroupID: groupID, UserID: userID, Cause: err}
	}
	return nil
}

// Authorization

// CheckPermission checks if a subject has permission to perform an action.
func (c *Client) CheckPermission(ctx context.Context, req *platformv1.CheckIAMPermissionRequest) (*platformv1.CheckIAMPermissionResponse, error) {
	resp, err := c.grpc.CheckPermission(ctx, req)
	if err != nil {
		return nil, &ErrCheckPermissionFailed{Cause: err}
	}
	return resp, nil
}

// CreateToken creates an access token.
func (c *Client) CreateToken(ctx context.Context, req *platformv1.CreateIAMTokenRequest) (*platformv1.CreateIAMTokenResponse, error) {
	resp, err := c.grpc.CreateToken(ctx, req)
	if err != nil {
		return nil, &ErrCreateTokenFailed{Cause: err}
	}
	return resp, nil
}

// RevokeToken revokes a token.
func (c *Client) RevokeToken(ctx context.Context, tokenID, token string) error {
	_, err := c.grpc.RevokeToken(ctx, &platformv1.RevokeIAMTokenRequest{
		TokenId: tokenID,
		Token:   token,
	})
	if err != nil {
		return &ErrRevokeTokenFailed{TokenID: tokenID, Cause: err}
	}
	return nil
}

// VerifyToken verifies a token.
func (c *Client) VerifyToken(ctx context.Context, token string) (*platformv1.VerifyIAMTokenResponse, error) {
	resp, err := c.grpc.VerifyToken(ctx, &platformv1.VerifyIAMTokenRequest{Token: token})
	if err != nil {
		return nil, &ErrVerifyTokenFailed{Cause: err}
	}
	return resp, nil
}

// Tenant Operations

// CreateTenant creates a new tenant.
func (c *Client) CreateTenant(ctx context.Context, req *platformv1.CreateIAMTenantRequest) (*platformv1.IAMTenant, error) {
	resp, err := c.grpc.CreateTenant(ctx, req)
	if err != nil {
		return nil, &ErrCreateTenantFailed{Cause: err}
	}
	return resp.Tenant, nil
}

// GetTenant retrieves a tenant by ID.
func (c *Client) GetTenant(ctx context.Context, tenantID string) (*platformv1.IAMTenant, error) {
	resp, err := c.grpc.GetTenant(ctx, &platformv1.GetIAMTenantRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrGetTenantFailed{ID: tenantID, Cause: err}
	}
	return resp.Tenant, nil
}

// ListTenants lists tenants with optional pagination.
func (c *Client) ListTenants(ctx context.Context, req *platformv1.ListIAMTenantsRequest) ([]*platformv1.IAMTenant, int64, error) {
	resp, err := c.grpc.ListTenants(ctx, req)
	if err != nil {
		return nil, 0, &ErrListTenantsFailed{Cause: err}
	}
	return resp.Tenants, resp.Total, nil
}

// UpdateTenant updates an existing tenant.
func (c *Client) UpdateTenant(ctx context.Context, req *platformv1.UpdateIAMTenantRequest) (*platformv1.IAMTenant, error) {
	resp, err := c.grpc.UpdateTenant(ctx, req)
	if err != nil {
		return nil, &ErrUpdateTenantFailed{ID: req.TenantId, Cause: err}
	}
	return resp.Tenant, nil
}

// DeleteTenant deletes a tenant.
func (c *Client) DeleteTenant(ctx context.Context, tenantID string) error {
	_, err := c.grpc.DeleteTenant(ctx, &platformv1.DeleteIAMTenantRequest{TenantId: tenantID})
	if err != nil {
		return &ErrDeleteTenantFailed{ID: tenantID, Cause: err}
	}
	return nil
}

// Policy Operations

// CreatePolicy creates a new policy.
func (c *Client) CreatePolicy(ctx context.Context, req *platformv1.CreateIAMPolicyRequest) (*platformv1.IAMPolicy, error) {
	resp, err := c.grpc.CreatePolicy(ctx, req)
	if err != nil {
		return nil, &ErrCreatePolicyFailed{Cause: err}
	}
	return resp.Policy, nil
}

// GetPolicy retrieves a policy by name.
func (c *Client) GetPolicy(ctx context.Context, tenantID, policyName string) (*platformv1.IAMPolicy, error) {
	resp, err := c.grpc.GetPolicy(ctx, &platformv1.GetIAMPolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyName,
	})
	if err != nil {
		return nil, &ErrGetPolicyFailed{Name: policyName, Cause: err}
	}
	return resp.Policy, nil
}

// ListPolicies lists policies with optional filtering.
func (c *Client) ListPolicies(ctx context.Context, req *platformv1.ListIAMPoliciesRequest) ([]*platformv1.IAMPolicy, int64, error) {
	resp, err := c.grpc.ListPolicies(ctx, req)
	if err != nil {
		return nil, 0, &ErrListPoliciesFailed{Cause: err}
	}
	return resp.Policies, resp.Total, nil
}

// UpdatePolicy updates an existing policy.
func (c *Client) UpdatePolicy(ctx context.Context, req *platformv1.UpdateIAMPolicyRequest) (*platformv1.IAMPolicy, error) {
	resp, err := c.grpc.UpdatePolicy(ctx, req)
	if err != nil {
		return nil, &ErrUpdatePolicyFailed{Name: req.PolicyName, Cause: err}
	}
	return resp.Policy, nil
}

// DeletePolicy deletes a policy.
func (c *Client) DeletePolicy(ctx context.Context, tenantID, policyName string) error {
	_, err := c.grpc.DeletePolicy(ctx, &platformv1.DeleteIAMPolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyName,
	})
	if err != nil {
		return &ErrDeletePolicyFailed{Name: policyName, Cause: err}
	}
	return nil
}

// ValidatePolicy validates a policy.
func (c *Client) ValidatePolicy(ctx context.Context, tenantID string, specYAML []byte) (bool, []string, error) {
	resp, err := c.grpc.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
		TenantId: tenantID,
		SpecYaml: specYAML,
	})
	if err != nil {
		return false, nil, &ErrValidatePolicyFailed{Cause: err}
	}
	return resp.Valid, resp.Errors, nil
}

// TestPolicy tests a policy.
func (c *Client) TestPolicy(ctx context.Context, req *platformv1.TestIAMPolicyRequest) (*platformv1.TestIAMPolicyResponse, error) {
	resp, err := c.grpc.TestPolicy(ctx, req)
	if err != nil {
		return nil, &ErrTestPolicyFailed{Cause: err}
	}
	return resp, nil
}

// Application Operations

// RegisterApp registers a new application.
func (c *Client) RegisterApp(ctx context.Context, req *platformv1.RegisterIAMAppRequest) (*platformv1.IAMApp, error) {
	resp, err := c.grpc.RegisterApp(ctx, req)
	if err != nil {
		return nil, &ErrRegisterAppFailed{Cause: err}
	}
	return resp.App, nil
}

// GetApp retrieves an application by client ID.
func (c *Client) GetApp(ctx context.Context, tenantID, clientID string) (*platformv1.IAMApp, error) {
	resp, err := c.grpc.GetApp(ctx, &platformv1.GetIAMAppRequest{
		TenantId: tenantID,
		ClientId: clientID,
	})
	if err != nil {
		return nil, &ErrGetAppFailed{ClientID: clientID, Cause: err}
	}
	return resp.App, nil
}

// ListApps lists applications with optional filtering.
func (c *Client) ListApps(ctx context.Context, req *platformv1.ListIAMAppsRequest) ([]*platformv1.IAMApp, int64, error) {
	resp, err := c.grpc.ListApps(ctx, req)
	if err != nil {
		return nil, 0, &ErrListAppsFailed{Cause: err}
	}
	return resp.Apps, resp.Total, nil
}

// UpdateApp updates an existing application.
func (c *Client) UpdateApp(ctx context.Context, req *platformv1.UpdateIAMAppRequest) (*platformv1.IAMApp, error) {
	resp, err := c.grpc.UpdateApp(ctx, req)
	if err != nil {
		return nil, &ErrUpdateAppFailed{ClientID: req.ClientId, Cause: err}
	}
	return resp.App, nil
}

// DeleteApp deletes an application.
func (c *Client) DeleteApp(ctx context.Context, tenantID, clientID string) error {
	_, err := c.grpc.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{
		TenantId: tenantID,
		ClientId: clientID,
	})
	if err != nil {
		return &ErrDeleteAppFailed{ClientID: clientID, Cause: err}
	}
	return nil
}

// RotateAppSecret rotates an application's client secret.
func (c *Client) RotateAppSecret(ctx context.Context, tenantID, clientID string) (*platformv1.RotateIAMAppSecretResponse, error) {
	resp, err := c.grpc.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{
		TenantId: tenantID,
		ClientId: clientID,
	})
	if err != nil {
		return nil, &ErrRotateAppSecretFailed{ClientID: clientID, Cause: err}
	}
	return resp, nil
}
