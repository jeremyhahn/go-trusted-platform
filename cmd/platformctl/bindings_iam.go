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

package main

import (
	"log/slog"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// IAMBinding exposes Platform IAM service methods to the Wails frontend.
type IAMBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewIAMBinding creates a new IAMBinding.
func NewIAMBinding(logger *slog.Logger, conn *ConnectionBinding) *IAMBinding {
	return &IAMBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *IAMBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// CreateUser creates a new IAM user.
func (b *IAMBinding) CreateUser(tenantID, email, name string, roles, groups []string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().CreateUser(b.conn.ctx, &platformv1.CreateIAMUserRequest{
		TenantId: tenantID,
		Email:    email,
		Name:     name,
		Roles:    roles,
		Groups:   groups,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetUser retrieves an IAM user by ID.
func (b *IAMBinding) GetUser(tenantID, userID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().GetUser(b.conn.ctx, &platformv1.GetIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ListUsers returns a list of IAM users for a tenant.
func (b *IAMBinding) ListUsers(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().ListUsers(b.conn.ctx, &platformv1.ListIAMUsersRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// DeleteUser deletes an IAM user by ID.
func (b *IAMBinding) DeleteUser(tenantID, userID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().DeleteUser(b.conn.ctx, &platformv1.DeleteIAMUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// CreateRole creates a new IAM role.
func (b *IAMBinding) CreateRole(tenantID, roleID, name, description string, permissions []string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().CreateRole(b.conn.ctx, &platformv1.CreateIAMRoleRequest{
		TenantId:    tenantID,
		Id:          roleID,
		Name:        name,
		Description: description,
		Permissions: permissions,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetRole retrieves an IAM role by ID.
func (b *IAMBinding) GetRole(tenantID, roleID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().GetRole(b.conn.ctx, &platformv1.GetIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ListRoles returns a list of IAM roles for a tenant.
func (b *IAMBinding) ListRoles(tenantID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().ListRoles(b.conn.ctx, &platformv1.ListIAMRolesRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// DeleteRole deletes an IAM role by ID.
func (b *IAMBinding) DeleteRole(tenantID, roleID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().DeleteRole(b.conn.ctx, &platformv1.DeleteIAMRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// AssignRole assigns a role to a user.
func (b *IAMBinding) AssignRole(tenantID, userID, roleID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().AssignRole(b.conn.ctx, &platformv1.AssignIAMRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// RevokeRole revokes a role from a user.
func (b *IAMBinding) RevokeRole(tenantID, userID, roleID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().RevokeRole(b.conn.ctx, &platformv1.RevokeIAMRoleRequest{
		TenantId: tenantID,
		UserId:   userID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// CreateToken creates an authentication token for a user.
func (b *IAMBinding) CreateToken(tenantID, userID string, scopes []string, expiresIn int64) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().CreateToken(b.conn.ctx, &platformv1.CreateIAMTokenRequest{
		TenantId:  tenantID,
		UserId:    userID,
		Scopes:    scopes,
		ExpiresIn: expiresIn,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// VerifyToken verifies an authentication token.
func (b *IAMBinding) VerifyToken(token string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().VerifyToken(b.conn.ctx, &platformv1.VerifyIAMTokenRequest{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// CheckPermission checks whether a subject has a specific permission.
func (b *IAMBinding) CheckPermission(tenantID, subjectID, action, resource string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.IAM().CheckPermission(b.conn.ctx, &platformv1.CheckIAMPermissionRequest{
		TenantId:  tenantID,
		SubjectId: subjectID,
		Action:    action,
		Resource:  resource,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}
