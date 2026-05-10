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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// Domain-typed convenience methods
//
// These methods return domain types instead of proto types, enabling callers
// to avoid importing platformv1 directly.

// User Domain Methods

// CreateUserDomain creates a new user and returns domain types.
func (c *Client) CreateUserDomain(ctx context.Context, tenantID, email, name string, roles, groups []string, attributes map[string]string) (*User, error) {
	resp, err := c.grpc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
		TenantId:   tenantID,
		Email:      email,
		Name:       name,
		Roles:      roles,
		Groups:     groups,
		Attributes: attributes,
	})
	if err != nil {
		return nil, &ErrCreateUserFailed{Cause: err}
	}
	return UserFromProto(resp.User), nil
}

// GetUserDomain retrieves a user and returns domain types.
func (c *Client) GetUserDomain(ctx context.Context, tenantID, userID string) (*User, error) {
	resp, err := c.grpc.GetUser(ctx, &platformv1.GetIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	if err != nil {
		return nil, &ErrGetUserFailed{ID: userID, Cause: err}
	}
	return UserFromProto(resp.User), nil
}

// ListUsersDomain lists users and returns domain types.
func (c *Client) ListUsersDomain(ctx context.Context, tenantID string, page, pageSize uint32) (*ListUsersResult, error) {
	resp, err := c.grpc.ListUsers(ctx, &platformv1.ListIAMUsersRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	})
	if err != nil {
		return nil, &ErrListUsersFailed{Cause: err}
	}
	result := &ListUsersResult{Total: uint64(resp.Total)}
	if len(resp.Users) > 0 {
		result.Users = make([]*User, len(resp.Users))
		for i, u := range resp.Users {
			result.Users[i] = UserFromProto(u)
		}
	}
	return result, nil
}

// UpdateUserDomain updates a user and returns domain types.
func (c *Client) UpdateUserDomain(ctx context.Context, tenantID, userID, email, name string, roles, groups []string, attributes map[string]string) (*User, error) {
	resp, err := c.grpc.UpdateUser(ctx, &platformv1.UpdateIAMUserRequest{
		TenantId:   tenantID,
		UserId:     userID,
		Email:      email,
		Name:       name,
		Roles:      roles,
		Groups:     groups,
		Attributes: attributes,
	})
	if err != nil {
		return nil, &ErrUpdateUserFailed{ID: userID, Cause: err}
	}
	return UserFromProto(resp.User), nil
}

// DeleteUserDomain deletes a user and returns the operation status.
func (c *Client) DeleteUserDomain(ctx context.Context, tenantID, userID string) (*OperationStatus, error) {
	resp, err := c.grpc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	if err != nil {
		return nil, &ErrDeleteUserFailed{ID: userID, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// AssignRoleDomain assigns a role to a user and returns the operation status.
func (c *Client) AssignRoleDomain(ctx context.Context, tenantID, userID, roleID string) (*OperationStatus, error) {
	resp, err := c.grpc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, &ErrAssignRoleFailed{UserID: userID, RoleID: roleID, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// RevokeRoleDomain revokes a role from a user and returns the operation status.
func (c *Client) RevokeRoleDomain(ctx context.Context, tenantID, userID, roleID string) (*OperationStatus, error) {
	resp, err := c.grpc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, &ErrRevokeRoleFailed{UserID: userID, RoleID: roleID, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// Group Domain Methods

// CreateGroupDomain creates a new group and returns domain types.
func (c *Client) CreateGroupDomain(ctx context.Context, tenantID, groupID, name, description string) (*Group, error) {
	resp, err := c.grpc.CreateGroup(ctx, &platformv1.CreateIAMGroupRequest{
		TenantId:    tenantID,
		Id:          groupID,
		Name:        name,
		Description: description,
	})
	if err != nil {
		return nil, &ErrCreateGroupFailed{Cause: err}
	}
	return GroupFromProto(resp.Group), nil
}

// GetGroupDomain retrieves a group and returns domain types.
func (c *Client) GetGroupDomain(ctx context.Context, tenantID, groupID string) (*Group, error) {
	resp, err := c.grpc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	})
	if err != nil {
		return nil, &ErrGetGroupFailed{ID: groupID, Cause: err}
	}
	return GroupFromProto(resp.Group), nil
}

// ListGroupsDomain lists groups and returns domain types.
func (c *Client) ListGroupsDomain(ctx context.Context, tenantID string, page, pageSize uint32) (*ListGroupsResult, error) {
	resp, err := c.grpc.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	})
	if err != nil {
		return nil, &ErrListGroupsFailed{Cause: err}
	}
	result := &ListGroupsResult{Total: uint64(resp.Total)}
	if len(resp.Groups) > 0 {
		result.Groups = make([]*Group, len(resp.Groups))
		for i, g := range resp.Groups {
			result.Groups[i] = GroupFromProto(g)
		}
	}
	return result, nil
}

// UpdateGroupDomain updates a group and returns domain types.
func (c *Client) UpdateGroupDomain(ctx context.Context, tenantID, groupID, name, description string) (*Group, error) {
	resp, err := c.grpc.UpdateGroup(ctx, &platformv1.UpdateIAMGroupRequest{
		TenantId:    tenantID,
		GroupId:     groupID,
		Name:        name,
		Description: description,
	})
	if err != nil {
		return nil, &ErrUpdateGroupFailed{ID: groupID, Cause: err}
	}
	return GroupFromProto(resp.Group), nil
}

// DeleteGroupDomain deletes a group and returns the operation status.
func (c *Client) DeleteGroupDomain(ctx context.Context, tenantID, groupID string) (*OperationStatus, error) {
	resp, err := c.grpc.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{
		TenantId: tenantID,
		GroupId:  groupID,
	})
	if err != nil {
		return nil, &ErrDeleteGroupFailed{ID: groupID, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// Role Domain Methods

// CreateRoleDomain creates a new role and returns domain types.
func (c *Client) CreateRoleDomain(ctx context.Context, tenantID, roleID, name, description string, permissions []string) (*Role, error) {
	resp, err := c.grpc.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
		TenantId:    tenantID,
		Id:          roleID,
		Name:        name,
		Description: description,
		Permissions: permissions,
	})
	if err != nil {
		return nil, &ErrCreateRoleFailed{Cause: err}
	}
	return RoleFromProto(resp.Role), nil
}

// GetRoleDomain retrieves a role and returns domain types.
func (c *Client) GetRoleDomain(ctx context.Context, tenantID, roleID string) (*Role, error) {
	resp, err := c.grpc.GetRole(ctx, &platformv1.GetIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, &ErrGetRoleFailed{ID: roleID, Cause: err}
	}
	return RoleFromProto(resp.Role), nil
}

// ListRolesDomain lists roles and returns domain types.
func (c *Client) ListRolesDomain(ctx context.Context, tenantID string, page, pageSize uint32) (*ListRolesResult, error) {
	resp, err := c.grpc.ListRoles(ctx, &platformv1.ListIAMRolesRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	})
	if err != nil {
		return nil, &ErrListRolesFailed{Cause: err}
	}
	result := &ListRolesResult{Total: uint64(resp.Total)}
	if len(resp.Roles) > 0 {
		result.Roles = make([]*Role, len(resp.Roles))
		for i, r := range resp.Roles {
			result.Roles[i] = RoleFromProto(r)
		}
	}
	return result, nil
}

// UpdateRoleDomain updates a role and returns domain types.
func (c *Client) UpdateRoleDomain(ctx context.Context, tenantID, roleID, name, description string, permissions []string) (*Role, error) {
	resp, err := c.grpc.UpdateRole(ctx, &platformv1.UpdateIAMRoleRequest{
		TenantId:    tenantID,
		RoleId:      roleID,
		Name:        name,
		Description: description,
		Permissions: permissions,
	})
	if err != nil {
		return nil, &ErrUpdateRoleFailed{ID: roleID, Cause: err}
	}
	return RoleFromProto(resp.Role), nil
}

// DeleteRoleDomain deletes a role and returns the operation status.
func (c *Client) DeleteRoleDomain(ctx context.Context, tenantID, roleID string) (*OperationStatus, error) {
	resp, err := c.grpc.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, &ErrDeleteRoleFailed{ID: roleID, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// Policy Domain Methods

// CreatePolicyDomain creates a new policy and returns domain types.
func (c *Client) CreatePolicyDomain(ctx context.Context, tenantID, name, description string, priority int32, specYAML []byte, labels map[string]string) (*Policy, error) {
	resp, err := c.grpc.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
		TenantId:    tenantID,
		Name:        name,
		Description: description,
		Priority:    priority,
		SpecYaml:    specYAML,
		Labels:      labels,
	})
	if err != nil {
		return nil, &ErrCreatePolicyFailed{Cause: err}
	}
	return PolicyFromProto(resp.Policy), nil
}

// GetPolicyDomain retrieves a policy and returns domain types.
func (c *Client) GetPolicyDomain(ctx context.Context, tenantID, policyName string) (*Policy, error) {
	resp, err := c.grpc.GetPolicy(ctx, &platformv1.GetIAMPolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyName,
	})
	if err != nil {
		return nil, &ErrGetPolicyFailed{Name: policyName, Cause: err}
	}
	return PolicyFromProto(resp.Policy), nil
}

// ListPoliciesDomain lists policies and returns domain types.
func (c *Client) ListPoliciesDomain(ctx context.Context, tenantID string, page, pageSize uint32) (*ListPoliciesResult, error) {
	resp, err := c.grpc.ListPolicies(ctx, &platformv1.ListIAMPoliciesRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	})
	if err != nil {
		return nil, &ErrListPoliciesFailed{Cause: err}
	}
	result := &ListPoliciesResult{Total: uint64(resp.Total)}
	if len(resp.Policies) > 0 {
		result.Policies = make([]*Policy, len(resp.Policies))
		for i, p := range resp.Policies {
			result.Policies[i] = PolicyFromProto(p)
		}
	}
	return result, nil
}

// UpdatePolicyDomain updates a policy and returns domain types.
func (c *Client) UpdatePolicyDomain(ctx context.Context, tenantID, name, description string, priority int32, specYAML []byte, labels map[string]string) (*Policy, error) {
	resp, err := c.grpc.UpdatePolicy(ctx, &platformv1.UpdateIAMPolicyRequest{
		TenantId:    tenantID,
		PolicyName:  name,
		Description: description,
		Priority:    priority,
		SpecYaml:    specYAML,
		Labels:      labels,
	})
	if err != nil {
		return nil, &ErrUpdatePolicyFailed{Name: name, Cause: err}
	}
	return PolicyFromProto(resp.Policy), nil
}

// DeletePolicyDomain deletes a policy and returns the operation status.
func (c *Client) DeletePolicyDomain(ctx context.Context, tenantID, policyName string) (*OperationStatus, error) {
	resp, err := c.grpc.DeletePolicy(ctx, &platformv1.DeleteIAMPolicyRequest{
		TenantId:   tenantID,
		PolicyName: policyName,
	})
	if err != nil {
		return nil, &ErrDeletePolicyFailed{Name: policyName, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// ValidatePolicyDomain validates a policy and returns domain types.
func (c *Client) ValidatePolicyDomain(ctx context.Context, tenantID string, specYAML []byte) (*ValidatePolicyResult, error) {
	resp, err := c.grpc.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
		TenantId: tenantID,
		SpecYaml: specYAML,
	})
	if err != nil {
		return nil, &ErrValidatePolicyFailed{Cause: err}
	}
	return &ValidatePolicyResult{
		Valid:  resp.Valid,
		Errors: resp.Errors,
	}, nil
}

// TestPolicyDomain tests a policy and returns domain types.
func (c *Client) TestPolicyDomain(ctx context.Context, tenantID, subjectID string, roles, groups []string, action, resource string, contextAttrs map[string]string) (*TestPolicyResult, error) {
	resp, err := c.grpc.TestPolicy(ctx, &platformv1.TestIAMPolicyRequest{
		TenantId:   tenantID,
		SubjectId:  subjectID,
		Roles:      roles,
		Groups:     groups,
		Action:     action,
		Resource:   resource,
		Context:    contextAttrs,
		Attributes: contextAttrs,
	})
	if err != nil {
		return nil, &ErrTestPolicyFailed{Cause: err}
	}
	return &TestPolicyResult{
		Allowed:          resp.Allowed,
		MatchedPolicy:    resp.MatchedPolicy,
		MatchedRule:      resp.MatchedRule,
		EvaluationTimeNs: resp.EvaluationTimeNs,
	}, nil
}

// Tenant Domain Methods

// CreateTenantDomain creates a new tenant and returns domain types.
func (c *Client) CreateTenantDomain(ctx context.Context, id, name string, settings *TenantSettings) (*Tenant, error) {
	resp, err := c.grpc.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{
		Id:       id,
		Name:     name,
		Settings: TenantSettingsToProto(settings),
	})
	if err != nil {
		return nil, &ErrCreateTenantFailed{Cause: err}
	}
	return TenantFromProto(resp.Tenant), nil
}

// GetTenantDomain retrieves a tenant and returns domain types.
func (c *Client) GetTenantDomain(ctx context.Context, tenantID string) (*Tenant, error) {
	resp, err := c.grpc.GetTenant(ctx, &platformv1.GetIAMTenantRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrGetTenantFailed{ID: tenantID, Cause: err}
	}
	return TenantFromProto(resp.Tenant), nil
}

// ListTenantsDomain lists tenants and returns domain types.
func (c *Client) ListTenantsDomain(ctx context.Context, page, pageSize uint32) (*ListTenantsResult, error) {
	resp, err := c.grpc.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	})
	if err != nil {
		return nil, &ErrListTenantsFailed{Cause: err}
	}
	result := &ListTenantsResult{Total: uint64(resp.Total)}
	if len(resp.Tenants) > 0 {
		result.Tenants = make([]*Tenant, len(resp.Tenants))
		for i, t := range resp.Tenants {
			result.Tenants[i] = TenantFromProto(t)
		}
	}
	return result, nil
}

// UpdateTenantDomain updates a tenant and returns domain types.
func (c *Client) UpdateTenantDomain(ctx context.Context, id, name string, settings *TenantSettings) (*Tenant, error) {
	resp, err := c.grpc.UpdateTenant(ctx, &platformv1.UpdateIAMTenantRequest{
		TenantId: id,
		Name:     name,
		Settings: TenantSettingsToProto(settings),
	})
	if err != nil {
		return nil, &ErrUpdateTenantFailed{ID: id, Cause: err}
	}
	return TenantFromProto(resp.Tenant), nil
}

// DeleteTenantDomain deletes a tenant and returns the operation status.
func (c *Client) DeleteTenantDomain(ctx context.Context, tenantID string) (*OperationStatus, error) {
	resp, err := c.grpc.DeleteTenant(ctx, &platformv1.DeleteIAMTenantRequest{TenantId: tenantID})
	if err != nil {
		return nil, &ErrDeleteTenantFailed{ID: tenantID, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// App Domain Methods

// RegisterAppDomain registers a new app and returns domain types.
func (c *Client) RegisterAppDomain(ctx context.Context, tenantID, name string, redirectURIs, grantTypes, responseTypes []string, resourcePrefix string) (*App, error) {
	resp, err := c.grpc.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{
		TenantId:       tenantID,
		Name:           name,
		RedirectUris:   redirectURIs,
		GrantTypes:     grantTypes,
		ResponseTypes:  responseTypes,
		ResourcePrefix: resourcePrefix,
	})
	if err != nil {
		return nil, &ErrRegisterAppFailed{Cause: err}
	}
	return AppFromProto(resp.App), nil
}

// GetAppDomain retrieves an app and returns domain types.
func (c *Client) GetAppDomain(ctx context.Context, tenantID, clientID string) (*App, error) {
	resp, err := c.grpc.GetApp(ctx, &platformv1.GetIAMAppRequest{
		TenantId: tenantID,
		ClientId: clientID,
	})
	if err != nil {
		return nil, &ErrGetAppFailed{ClientID: clientID, Cause: err}
	}
	return AppFromProto(resp.App), nil
}

// ListAppsDomain lists apps and returns domain types.
func (c *Client) ListAppsDomain(ctx context.Context, tenantID string, page, pageSize uint32) (*ListAppsResult, error) {
	resp, err := c.grpc.ListApps(ctx, &platformv1.ListIAMAppsRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	})
	if err != nil {
		return nil, &ErrListAppsFailed{Cause: err}
	}
	result := &ListAppsResult{Total: uint64(resp.Total)}
	if len(resp.Apps) > 0 {
		result.Apps = make([]*App, len(resp.Apps))
		for i, a := range resp.Apps {
			result.Apps[i] = AppFromProto(a)
		}
	}
	return result, nil
}

// UpdateAppDomain updates an app and returns domain types.
func (c *Client) UpdateAppDomain(ctx context.Context, tenantID, clientID, name string, redirectURIs, grantTypes, responseTypes []string, resourcePrefix string) (*App, error) {
	resp, err := c.grpc.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{
		TenantId:       tenantID,
		ClientId:       clientID,
		Name:           name,
		RedirectUris:   redirectURIs,
		GrantTypes:     grantTypes,
		ResponseTypes:  responseTypes,
		ResourcePrefix: resourcePrefix,
	})
	if err != nil {
		return nil, &ErrUpdateAppFailed{ClientID: clientID, Cause: err}
	}
	return AppFromProto(resp.App), nil
}

// DeleteAppDomain deletes an app and returns the operation status.
func (c *Client) DeleteAppDomain(ctx context.Context, tenantID, clientID string) (*OperationStatus, error) {
	resp, err := c.grpc.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{
		TenantId: tenantID,
		ClientId: clientID,
	})
	if err != nil {
		return nil, &ErrDeleteAppFailed{ClientID: clientID, Cause: err}
	}
	return StatusFromProto(resp.Status), nil
}

// RotateAppSecretDomain rotates an app's client secret and returns domain types.
func (c *Client) RotateAppSecretDomain(ctx context.Context, tenantID, clientID string) (*RotateSecretResult, error) {
	resp, err := c.grpc.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{
		TenantId: tenantID,
		ClientId: clientID,
	})
	if err != nil {
		return nil, &ErrRotateAppSecretFailed{ClientID: clientID, Cause: err}
	}
	return &RotateSecretResult{
		ClientID:     resp.ClientId,
		Name:         resp.Name,
		ClientSecret: resp.ClientSecret,
	}, nil
}
