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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Mock IAM Client
// =============================================================================

type mockIAMClient struct {
	// User responses
	createUserResp *platformv1.IAMUserResponse
	createUserErr  error
	getUserResp    *platformv1.IAMUserResponse
	getUserErr     error
	listUsersResp  *platformv1.ListIAMUsersResponse
	listUsersErr   error
	updateUserResp *platformv1.IAMUserResponse
	updateUserErr  error
	deleteUserResp *platformv1.DeleteIAMUserResponse
	deleteUserErr  error

	// Role responses
	createRoleResp *platformv1.IAMRoleResponse
	createRoleErr  error
	getRoleResp    *platformv1.IAMRoleResponse
	getRoleErr     error
	listRolesResp  *platformv1.ListIAMRolesResponse
	listRolesErr   error
	updateRoleResp *platformv1.IAMRoleResponse
	updateRoleErr  error
	deleteRoleResp *platformv1.DeleteIAMRoleResponse
	deleteRoleErr  error
	assignRoleErr  error
	revokeRoleErr  error

	// Group responses
	createGroupResp      *platformv1.IAMGroupResponse
	createGroupErr       error
	getGroupResp         *platformv1.IAMGroupResponse
	getGroupErr          error
	listGroupsResp       *platformv1.ListIAMGroupsResponse
	listGroupsErr        error
	updateGroupResp      *platformv1.IAMGroupResponse
	updateGroupErr       error
	deleteGroupResp      *platformv1.DeleteIAMGroupResponse
	deleteGroupErr       error
	addGroupMemberErr    error
	removeGroupMemberErr error

	// Policy responses
	createPolicyResp  *platformv1.IAMPolicyResponse
	createPolicyErr   error
	getPolicyResp     *platformv1.IAMPolicyResponse
	getPolicyErr      error
	listPoliciesResp  *platformv1.ListIAMPoliciesResponse
	listPoliciesErr   error
	updatePolicyResp  *platformv1.IAMPolicyResponse
	updatePolicyErr   error
	deletePolicyResp  *platformv1.DeleteIAMPolicyResponse
	deletePolicyErr   error
	validatePolicyErr error
	testPolicyErr     error

	// Token responses
	createTokenResp *platformv1.CreateIAMTokenResponse
	createTokenErr  error
	verifyTokenResp *platformv1.VerifyIAMTokenResponse
	verifyTokenErr  error
	revokeTokenResp *platformv1.RevokeIAMTokenResponse
	revokeTokenErr  error

	// Authorization responses
	checkPermissionErr error

	// Tenant responses
	createTenantErr error
	getTenantErr    error
	listTenantsErr  error
	updateTenantErr error
	deleteTenantErr error

	// App responses
	registerAppErr     error
	getAppErr          error
	listAppsErr        error
	updateAppErr       error
	deleteAppErr       error
	rotateAppSecretErr error
}

func newMockIAMClient() *mockIAMClient {
	return &mockIAMClient{}
}

// User operations
func (m *mockIAMClient) CreateUser(ctx context.Context, in *platformv1.CreateIAMUserRequest, opts ...grpc.CallOption) (*platformv1.IAMUserResponse, error) {
	if m.createUserErr != nil {
		return nil, m.createUserErr
	}
	if m.createUserResp != nil {
		return m.createUserResp, nil
	}
	return &platformv1.IAMUserResponse{
		User: &platformv1.IAMUser{
			Id:        "user-123",
			TenantId:  in.TenantId,
			Email:     in.Email,
			Name:      in.Name,
			Roles:     in.Roles,
			Groups:    in.Groups,
			CreatedAt: timestamppb.Now(),
			UpdatedAt: timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) GetUser(ctx context.Context, in *platformv1.GetIAMUserRequest, opts ...grpc.CallOption) (*platformv1.IAMUserResponse, error) {
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	if m.getUserResp != nil {
		return m.getUserResp, nil
	}
	return &platformv1.IAMUserResponse{
		User: &platformv1.IAMUser{
			Id:        in.UserId,
			TenantId:  in.TenantId,
			Email:     "test@example.com",
			Name:      "Test User",
			CreatedAt: timestamppb.Now(),
			UpdatedAt: timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) ListUsers(ctx context.Context, in *platformv1.ListIAMUsersRequest, opts ...grpc.CallOption) (*platformv1.ListIAMUsersResponse, error) {
	if m.listUsersErr != nil {
		return nil, m.listUsersErr
	}
	if m.listUsersResp != nil {
		return m.listUsersResp, nil
	}
	return &platformv1.ListIAMUsersResponse{
		Users: []*platformv1.IAMUser{
			{
				Id:        "user-1",
				TenantId:  in.TenantId,
				Email:     "user1@example.com",
				Name:      "User One",
				CreatedAt: timestamppb.Now(),
			},
			{
				Id:        "user-2",
				TenantId:  in.TenantId,
				Email:     "user2@example.com",
				Name:      "User Two",
				CreatedAt: timestamppb.Now(),
			},
		},
		Total: 2,
	}, nil
}

func (m *mockIAMClient) UpdateUser(ctx context.Context, in *platformv1.UpdateIAMUserRequest, opts ...grpc.CallOption) (*platformv1.IAMUserResponse, error) {
	if m.updateUserErr != nil {
		return nil, m.updateUserErr
	}
	if m.updateUserResp != nil {
		return m.updateUserResp, nil
	}
	return &platformv1.IAMUserResponse{
		User: &platformv1.IAMUser{
			Id:        in.UserId,
			TenantId:  in.TenantId,
			Email:     in.Email,
			Name:      in.Name,
			Roles:     in.Roles,
			Groups:    in.Groups,
			UpdatedAt: timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) DeleteUser(ctx context.Context, in *platformv1.DeleteIAMUserRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAMUserResponse, error) {
	if m.deleteUserErr != nil {
		return nil, m.deleteUserErr
	}
	if m.deleteUserResp != nil {
		return m.deleteUserResp, nil
	}
	return &platformv1.DeleteIAMUserResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "user deleted",
		},
	}, nil
}

// Role operations
func (m *mockIAMClient) CreateRole(ctx context.Context, in *platformv1.CreateIAMRoleRequest, opts ...grpc.CallOption) (*platformv1.IAMRoleResponse, error) {
	if m.createRoleErr != nil {
		return nil, m.createRoleErr
	}
	if m.createRoleResp != nil {
		return m.createRoleResp, nil
	}
	return &platformv1.IAMRoleResponse{
		Role: &platformv1.IAMRole{
			Id:          in.Id,
			TenantId:    in.TenantId,
			Name:        in.Name,
			Description: in.Description,
			Permissions: in.Permissions,
			CreatedAt:   timestamppb.Now(),
			UpdatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) GetRole(ctx context.Context, in *platformv1.GetIAMRoleRequest, opts ...grpc.CallOption) (*platformv1.IAMRoleResponse, error) {
	if m.getRoleErr != nil {
		return nil, m.getRoleErr
	}
	if m.getRoleResp != nil {
		return m.getRoleResp, nil
	}
	return &platformv1.IAMRoleResponse{
		Role: &platformv1.IAMRole{
			Id:          in.RoleId,
			TenantId:    in.TenantId,
			Name:        "admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
			CreatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) ListRoles(ctx context.Context, in *platformv1.ListIAMRolesRequest, opts ...grpc.CallOption) (*platformv1.ListIAMRolesResponse, error) {
	if m.listRolesErr != nil {
		return nil, m.listRolesErr
	}
	if m.listRolesResp != nil {
		return m.listRolesResp, nil
	}
	return &platformv1.ListIAMRolesResponse{
		Roles: []*platformv1.IAMRole{
			{
				Id:          "role-1",
				TenantId:    in.TenantId,
				Name:        "admin",
				Description: "Administrator",
				Permissions: []string{"*"},
			},
			{
				Id:          "role-2",
				TenantId:    in.TenantId,
				Name:        "viewer",
				Description: "Read-only access",
				Permissions: []string{"read"},
			},
		},
		Total: 2,
	}, nil
}

func (m *mockIAMClient) UpdateRole(ctx context.Context, in *platformv1.UpdateIAMRoleRequest, opts ...grpc.CallOption) (*platformv1.IAMRoleResponse, error) {
	if m.updateRoleErr != nil {
		return nil, m.updateRoleErr
	}
	if m.updateRoleResp != nil {
		return m.updateRoleResp, nil
	}
	return &platformv1.IAMRoleResponse{
		Role: &platformv1.IAMRole{
			Id:          in.RoleId,
			TenantId:    in.TenantId,
			Name:        in.Name,
			Description: in.Description,
			Permissions: in.Permissions,
			UpdatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) DeleteRole(ctx context.Context, in *platformv1.DeleteIAMRoleRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAMRoleResponse, error) {
	if m.deleteRoleErr != nil {
		return nil, m.deleteRoleErr
	}
	if m.deleteRoleResp != nil {
		return m.deleteRoleResp, nil
	}
	return &platformv1.DeleteIAMRoleResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

func (m *mockIAMClient) AssignRole(ctx context.Context, in *platformv1.AssignIAMRoleRequest, opts ...grpc.CallOption) (*platformv1.AssignIAMRoleResponse, error) {
	if m.assignRoleErr != nil {
		return nil, m.assignRoleErr
	}
	return &platformv1.AssignIAMRoleResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

func (m *mockIAMClient) RevokeRole(ctx context.Context, in *platformv1.RevokeIAMRoleRequest, opts ...grpc.CallOption) (*platformv1.RevokeIAMRoleResponse, error) {
	if m.revokeRoleErr != nil {
		return nil, m.revokeRoleErr
	}
	return &platformv1.RevokeIAMRoleResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

// Group operations
func (m *mockIAMClient) CreateGroup(ctx context.Context, in *platformv1.CreateIAMGroupRequest, opts ...grpc.CallOption) (*platformv1.IAMGroupResponse, error) {
	if m.createGroupErr != nil {
		return nil, m.createGroupErr
	}
	if m.createGroupResp != nil {
		return m.createGroupResp, nil
	}
	return &platformv1.IAMGroupResponse{
		Group: &platformv1.IAMGroup{
			Id:          in.Id,
			TenantId:    in.TenantId,
			Name:        in.Name,
			Description: in.Description,
			CreatedAt:   timestamppb.Now(),
			UpdatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) GetGroup(ctx context.Context, in *platformv1.GetIAMGroupRequest, opts ...grpc.CallOption) (*platformv1.IAMGroupResponse, error) {
	if m.getGroupErr != nil {
		return nil, m.getGroupErr
	}
	if m.getGroupResp != nil {
		return m.getGroupResp, nil
	}
	return &platformv1.IAMGroupResponse{
		Group: &platformv1.IAMGroup{
			Id:          in.GroupId,
			TenantId:    in.TenantId,
			Name:        "developers",
			Description: "Development team",
			Members:     []string{"user-1", "user-2"},
			CreatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) ListGroups(ctx context.Context, in *platformv1.ListIAMGroupsRequest, opts ...grpc.CallOption) (*platformv1.ListIAMGroupsResponse, error) {
	if m.listGroupsErr != nil {
		return nil, m.listGroupsErr
	}
	if m.listGroupsResp != nil {
		return m.listGroupsResp, nil
	}
	return &platformv1.ListIAMGroupsResponse{
		Groups: []*platformv1.IAMGroup{
			{
				Id:          "group-1",
				TenantId:    in.TenantId,
				Name:        "developers",
				Description: "Dev team",
			},
			{
				Id:          "group-2",
				TenantId:    in.TenantId,
				Name:        "operations",
				Description: "Ops team",
			},
		},
		Total: 2,
	}, nil
}

func (m *mockIAMClient) UpdateGroup(ctx context.Context, in *platformv1.UpdateIAMGroupRequest, opts ...grpc.CallOption) (*platformv1.IAMGroupResponse, error) {
	if m.updateGroupErr != nil {
		return nil, m.updateGroupErr
	}
	if m.updateGroupResp != nil {
		return m.updateGroupResp, nil
	}
	return &platformv1.IAMGroupResponse{
		Group: &platformv1.IAMGroup{
			Id:          in.GroupId,
			TenantId:    in.TenantId,
			Name:        in.Name,
			Description: in.Description,
			UpdatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) DeleteGroup(ctx context.Context, in *platformv1.DeleteIAMGroupRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAMGroupResponse, error) {
	if m.deleteGroupErr != nil {
		return nil, m.deleteGroupErr
	}
	if m.deleteGroupResp != nil {
		return m.deleteGroupResp, nil
	}
	return &platformv1.DeleteIAMGroupResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

func (m *mockIAMClient) AddGroupMember(ctx context.Context, in *platformv1.AddGroupMemberRequest, opts ...grpc.CallOption) (*platformv1.AddGroupMemberResponse, error) {
	if m.addGroupMemberErr != nil {
		return nil, m.addGroupMemberErr
	}
	return &platformv1.AddGroupMemberResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

func (m *mockIAMClient) RemoveGroupMember(ctx context.Context, in *platformv1.RemoveGroupMemberRequest, opts ...grpc.CallOption) (*platformv1.RemoveGroupMemberResponse, error) {
	if m.removeGroupMemberErr != nil {
		return nil, m.removeGroupMemberErr
	}
	return &platformv1.RemoveGroupMemberResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

// Authorization operations
func (m *mockIAMClient) CheckPermission(ctx context.Context, in *platformv1.CheckIAMPermissionRequest, opts ...grpc.CallOption) (*platformv1.CheckIAMPermissionResponse, error) {
	if m.checkPermissionErr != nil {
		return nil, m.checkPermissionErr
	}
	return &platformv1.CheckIAMPermissionResponse{
		Allowed: true,
	}, nil
}

func (m *mockIAMClient) CreateToken(ctx context.Context, in *platformv1.CreateIAMTokenRequest, opts ...grpc.CallOption) (*platformv1.CreateIAMTokenResponse, error) {
	if m.createTokenErr != nil {
		return nil, m.createTokenErr
	}
	if m.createTokenResp != nil {
		return m.createTokenResp, nil
	}
	return &platformv1.CreateIAMTokenResponse{
		TokenId:      "token-123",
		AccessToken:  "access-token-xyz",
		RefreshToken: "refresh-token-abc",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	}, nil
}

func (m *mockIAMClient) RevokeToken(ctx context.Context, in *platformv1.RevokeIAMTokenRequest, opts ...grpc.CallOption) (*platformv1.RevokeIAMTokenResponse, error) {
	if m.revokeTokenErr != nil {
		return nil, m.revokeTokenErr
	}
	if m.revokeTokenResp != nil {
		return m.revokeTokenResp, nil
	}
	return &platformv1.RevokeIAMTokenResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

func (m *mockIAMClient) VerifyToken(ctx context.Context, in *platformv1.VerifyIAMTokenRequest, opts ...grpc.CallOption) (*platformv1.VerifyIAMTokenResponse, error) {
	if m.verifyTokenErr != nil {
		return nil, m.verifyTokenErr
	}
	if m.verifyTokenResp != nil {
		return m.verifyTokenResp, nil
	}
	return &platformv1.VerifyIAMTokenResponse{
		Valid:     true,
		UserId:    "user-123",
		TenantId:  "tenant-123",
		Scopes:    []string{"read", "write"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, nil
}

// Tenant operations
func (m *mockIAMClient) CreateTenant(ctx context.Context, in *platformv1.CreateIAMTenantRequest, opts ...grpc.CallOption) (*platformv1.IAMTenantResponse, error) {
	if m.createTenantErr != nil {
		return nil, m.createTenantErr
	}
	return &platformv1.IAMTenantResponse{
		Tenant: &platformv1.IAMTenant{
			Id:   in.Id,
			Name: in.Name,
		},
	}, nil
}

func (m *mockIAMClient) GetTenant(ctx context.Context, in *platformv1.GetIAMTenantRequest, opts ...grpc.CallOption) (*platformv1.IAMTenantResponse, error) {
	if m.getTenantErr != nil {
		return nil, m.getTenantErr
	}
	return &platformv1.IAMTenantResponse{
		Tenant: &platformv1.IAMTenant{
			Id:   in.TenantId,
			Name: "Test Tenant",
		},
	}, nil
}

func (m *mockIAMClient) ListTenants(ctx context.Context, in *platformv1.ListIAMTenantsRequest, opts ...grpc.CallOption) (*platformv1.ListIAMTenantsResponse, error) {
	if m.listTenantsErr != nil {
		return nil, m.listTenantsErr
	}
	return &platformv1.ListIAMTenantsResponse{
		Tenants: []*platformv1.IAMTenant{
			{Id: "tenant-1", Name: "Tenant One"},
		},
		Total: 1,
	}, nil
}

func (m *mockIAMClient) UpdateTenant(ctx context.Context, in *platformv1.UpdateIAMTenantRequest, opts ...grpc.CallOption) (*platformv1.IAMTenantResponse, error) {
	if m.updateTenantErr != nil {
		return nil, m.updateTenantErr
	}
	return &platformv1.IAMTenantResponse{
		Tenant: &platformv1.IAMTenant{
			Id:   in.TenantId,
			Name: in.Name,
		},
	}, nil
}

func (m *mockIAMClient) DeleteTenant(ctx context.Context, in *platformv1.DeleteIAMTenantRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAMTenantResponse, error) {
	if m.deleteTenantErr != nil {
		return nil, m.deleteTenantErr
	}
	return &platformv1.DeleteIAMTenantResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

// Policy operations
func (m *mockIAMClient) CreatePolicy(ctx context.Context, in *platformv1.CreateIAMPolicyRequest, opts ...grpc.CallOption) (*platformv1.IAMPolicyResponse, error) {
	if m.createPolicyErr != nil {
		return nil, m.createPolicyErr
	}
	if m.createPolicyResp != nil {
		return m.createPolicyResp, nil
	}
	return &platformv1.IAMPolicyResponse{
		Policy: &platformv1.IAMPolicy{
			Name:        in.Name,
			TenantId:    in.TenantId,
			Description: in.Description,
			Priority:    in.Priority,
			SpecYaml:    in.SpecYaml,
			Labels:      in.Labels,
			CreatedAt:   timestamppb.Now(),
			UpdatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) GetPolicy(ctx context.Context, in *platformv1.GetIAMPolicyRequest, opts ...grpc.CallOption) (*platformv1.IAMPolicyResponse, error) {
	if m.getPolicyErr != nil {
		return nil, m.getPolicyErr
	}
	if m.getPolicyResp != nil {
		return m.getPolicyResp, nil
	}
	return &platformv1.IAMPolicyResponse{
		Policy: &platformv1.IAMPolicy{
			Name:        in.PolicyName,
			TenantId:    in.TenantId,
			Description: "Test policy",
			Priority:    100,
			SpecYaml:    []byte("rules: []"),
			CreatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) ListPolicies(ctx context.Context, in *platformv1.ListIAMPoliciesRequest, opts ...grpc.CallOption) (*platformv1.ListIAMPoliciesResponse, error) {
	if m.listPoliciesErr != nil {
		return nil, m.listPoliciesErr
	}
	if m.listPoliciesResp != nil {
		return m.listPoliciesResp, nil
	}
	return &platformv1.ListIAMPoliciesResponse{
		Policies: []*platformv1.IAMPolicy{
			{
				Name:        "policy-1",
				TenantId:    in.TenantId,
				Description: "Policy One",
				Priority:    100,
			},
			{
				Name:        "policy-2",
				TenantId:    in.TenantId,
				Description: "Policy Two",
				Priority:    200,
			},
		},
		Total: 2,
	}, nil
}

func (m *mockIAMClient) UpdatePolicy(ctx context.Context, in *platformv1.UpdateIAMPolicyRequest, opts ...grpc.CallOption) (*platformv1.IAMPolicyResponse, error) {
	if m.updatePolicyErr != nil {
		return nil, m.updatePolicyErr
	}
	if m.updatePolicyResp != nil {
		return m.updatePolicyResp, nil
	}
	return &platformv1.IAMPolicyResponse{
		Policy: &platformv1.IAMPolicy{
			Name:        in.PolicyName,
			TenantId:    in.TenantId,
			Description: in.Description,
			Priority:    in.Priority,
			SpecYaml:    in.SpecYaml,
			Labels:      in.Labels,
			UpdatedAt:   timestamppb.Now(),
		},
	}, nil
}

func (m *mockIAMClient) DeletePolicy(ctx context.Context, in *platformv1.DeleteIAMPolicyRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAMPolicyResponse, error) {
	if m.deletePolicyErr != nil {
		return nil, m.deletePolicyErr
	}
	if m.deletePolicyResp != nil {
		return m.deletePolicyResp, nil
	}
	return &platformv1.DeleteIAMPolicyResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

func (m *mockIAMClient) ValidatePolicy(ctx context.Context, in *platformv1.ValidateIAMPolicyRequest, opts ...grpc.CallOption) (*platformv1.ValidateIAMPolicyResponse, error) {
	if m.validatePolicyErr != nil {
		return nil, m.validatePolicyErr
	}
	return &platformv1.ValidateIAMPolicyResponse{
		Valid: true,
	}, nil
}

func (m *mockIAMClient) TestPolicy(ctx context.Context, in *platformv1.TestIAMPolicyRequest, opts ...grpc.CallOption) (*platformv1.TestIAMPolicyResponse, error) {
	if m.testPolicyErr != nil {
		return nil, m.testPolicyErr
	}
	return &platformv1.TestIAMPolicyResponse{
		Allowed:       true,
		MatchedPolicy: "default",
	}, nil
}

// App operations
func (m *mockIAMClient) RegisterApp(ctx context.Context, in *platformv1.RegisterIAMAppRequest, opts ...grpc.CallOption) (*platformv1.IAMAppResponse, error) {
	if m.registerAppErr != nil {
		return nil, m.registerAppErr
	}
	return &platformv1.IAMAppResponse{
		App: &platformv1.IAMApp{
			ClientId:     "client-123",
			ClientSecret: "secret-xyz",
			TenantId:     in.TenantId,
			Name:         in.Name,
		},
	}, nil
}

func (m *mockIAMClient) GetApp(ctx context.Context, in *platformv1.GetIAMAppRequest, opts ...grpc.CallOption) (*platformv1.IAMAppResponse, error) {
	if m.getAppErr != nil {
		return nil, m.getAppErr
	}
	return &platformv1.IAMAppResponse{
		App: &platformv1.IAMApp{
			ClientId: in.ClientId,
			TenantId: in.TenantId,
			Name:     "Test App",
		},
	}, nil
}

func (m *mockIAMClient) ListApps(ctx context.Context, in *platformv1.ListIAMAppsRequest, opts ...grpc.CallOption) (*platformv1.ListIAMAppsResponse, error) {
	if m.listAppsErr != nil {
		return nil, m.listAppsErr
	}
	return &platformv1.ListIAMAppsResponse{
		Apps:  []*platformv1.IAMApp{{ClientId: "app-1", Name: "App One"}},
		Total: 1,
	}, nil
}

func (m *mockIAMClient) UpdateApp(ctx context.Context, in *platformv1.UpdateIAMAppRequest, opts ...grpc.CallOption) (*platformv1.IAMAppResponse, error) {
	if m.updateAppErr != nil {
		return nil, m.updateAppErr
	}
	return &platformv1.IAMAppResponse{
		App: &platformv1.IAMApp{
			ClientId: in.ClientId,
			TenantId: in.TenantId,
			Name:     in.Name,
		},
	}, nil
}

func (m *mockIAMClient) DeleteApp(ctx context.Context, in *platformv1.DeleteIAMAppRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAMAppResponse, error) {
	if m.deleteAppErr != nil {
		return nil, m.deleteAppErr
	}
	return &platformv1.DeleteIAMAppResponse{
		Status: &platformv1.Status{Success: true},
	}, nil
}

func (m *mockIAMClient) RotateAppSecret(ctx context.Context, in *platformv1.RotateIAMAppSecretRequest, opts ...grpc.CallOption) (*platformv1.RotateIAMAppSecretResponse, error) {
	if m.rotateAppSecretErr != nil {
		return nil, m.rotateAppSecretErr
	}
	return &platformv1.RotateIAMAppSecretResponse{
		ClientId:     in.ClientId,
		ClientSecret: "new-secret",
		Name:         "App",
	}, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestIAMHandlers(client *mockIAMClient) *IAMHandlers {
	logger := slog.Default()
	return NewIAMHandlers(client, logger)
}

func newTestRouter(handlers *IAMHandlers) *mux.Router {
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return router
}

func makeJSONRequest(t *testing.T, method, path string, body interface{}, headers map[string]string) *http.Request {
	var bodyReader *bytes.Buffer
	if body != nil {
		jsonData, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewBuffer(jsonData)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// =============================================================================
// User Handler Tests
// =============================================================================

func TestIAMHandlers_CreateUser_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateUserRequest{
		Email:  "test@example.com",
		Name:   "Test User",
		Roles:  []string{"admin"},
		Groups: []string{"developers"},
	}

	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/users", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp IAMUserResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "user-123", resp.ID)
	assert.Equal(t, "test@example.com", resp.Email)
	assert.Equal(t, "Test User", resp.Name)
}

func TestIAMHandlers_CreateUser_MissingTenantID(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateUserRequest{Email: "test@example.com"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/users", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var resp IAMErrorResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "tenant ID is required")
}

func TestIAMHandlers_CreateUser_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/users", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreateUser_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.createUserErr = status.Error(codes.AlreadyExists, "user already exists")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateUserRequest{Email: "test@example.com"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/users", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestIAMHandlers_ListUsers_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?limit=10&offset=0", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMListUsersResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, int64(2), resp.Total)
	assert.Len(t, resp.Users, 2)
}

func TestIAMHandlers_ListUsers_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.listUsersErr = status.Error(codes.Internal, "internal error")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestIAMHandlers_GetUser_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users/user-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMUserResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "user-123", resp.ID)
}

func TestIAMHandlers_GetUser_NotFound(t *testing.T) {
	client := newMockIAMClient()
	client.getUserErr = status.Error(codes.NotFound, "user not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users/nonexistent", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_UpdateUser_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdateUserRequest{
		Name:  "Updated User",
		Email: "updated@example.com",
	}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/users/user-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMUserResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Updated User", resp.Name)
}

func TestIAMHandlers_UpdateUser_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/users/user-123", bytes.NewBufferString("{invalid}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_UpdateUser_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.updateUserErr = status.Error(codes.NotFound, "user not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdateUserRequest{Name: "Updated User"}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/users/user-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_DeleteUser_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/users/user-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMSuccessResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestIAMHandlers_DeleteUser_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.deleteUserErr = status.Error(codes.NotFound, "user not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/users/user-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// =============================================================================
// Role Handler Tests
// =============================================================================

func TestIAMHandlers_CreateRole_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateRoleRequest{
		ID:          "admin-role",
		Name:        "Administrator",
		Description: "Full access role",
		Permissions: []string{"read", "write", "delete"},
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/roles", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp IAMRoleResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "admin-role", resp.ID)
	assert.Equal(t, "Administrator", resp.Name)
}

func TestIAMHandlers_CreateRole_MissingTenantID(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateRoleRequest{ID: "admin", Name: "Admin"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/roles", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreateRole_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/roles", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreateRole_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.createRoleErr = status.Error(codes.AlreadyExists, "role already exists")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateRoleRequest{ID: "admin", Name: "Admin"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/roles", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestIAMHandlers_ListRoles_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/roles", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMListRolesResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, int64(2), resp.Total)
	assert.Len(t, resp.Roles, 2)
}

func TestIAMHandlers_ListRoles_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.listRolesErr = status.Error(codes.Internal, "internal error")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/roles", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestIAMHandlers_GetRole_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/roles/role-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMRoleResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "role-123", resp.ID)
}

func TestIAMHandlers_GetRole_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.getRoleErr = status.Error(codes.NotFound, "role not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/roles/role-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_UpdateRole_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdateRoleRequest{
		Name:        "Updated Role",
		Description: "Updated description",
		Permissions: []string{"read"},
	}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/roles/role-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_UpdateRole_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/roles/role-123", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_UpdateRole_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.updateRoleErr = status.Error(codes.NotFound, "role not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdateRoleRequest{Name: "Updated Role"}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/roles/role-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_DeleteRole_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/roles/role-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_DeleteRole_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.deleteRoleErr = status.Error(codes.NotFound, "role not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/roles/role-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// =============================================================================
// Group Handler Tests
// =============================================================================

func TestIAMHandlers_CreateGroup_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateGroupRequest{
		ID:          "dev-group",
		Name:        "Developers",
		Description: "Development team",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/groups", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp IAMGroupResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "dev-group", resp.ID)
}

func TestIAMHandlers_CreateGroup_MissingTenantID(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateGroupRequest{ID: "group-1", Name: "Group"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/groups", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreateGroup_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/groups", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreateGroup_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.createGroupErr = status.Error(codes.AlreadyExists, "group already exists")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreateGroupRequest{ID: "group-1", Name: "Group"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/groups", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestIAMHandlers_ListGroups_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/groups", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMListGroupsResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, int64(2), resp.Total)
}

func TestIAMHandlers_ListGroups_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.listGroupsErr = status.Error(codes.Internal, "internal error")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/groups", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestIAMHandlers_GetGroup_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/groups/group-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMGroupResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "group-123", resp.ID)
}

func TestIAMHandlers_GetGroup_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.getGroupErr = status.Error(codes.NotFound, "group not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/groups/group-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_UpdateGroup_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdateGroupRequest{
		Name:        "Updated Group",
		Description: "Updated description",
	}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/groups/group-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_UpdateGroup_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/groups/group-123", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_UpdateGroup_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.updateGroupErr = status.Error(codes.NotFound, "group not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdateGroupRequest{Name: "Updated Group"}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/groups/group-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_DeleteGroup_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/groups/group-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_DeleteGroup_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.deleteGroupErr = status.Error(codes.NotFound, "group not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/groups/group-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// =============================================================================
// Policy Handler Tests
// =============================================================================

func TestIAMHandlers_CreatePolicy_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreatePolicyRequest{
		Name:        "admin-policy",
		Description: "Administrator access policy",
		Priority:    100,
		SpecYAML:    "rules:\n  - allow: true",
		Labels:      map[string]string{"env": "prod"},
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/policies", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp IAMPolicyResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "admin-policy", resp.Name)
}

func TestIAMHandlers_CreatePolicy_MissingTenantID(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreatePolicyRequest{Name: "test", SpecYAML: "rules: []"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/policies", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreatePolicy_MissingName(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreatePolicyRequest{
		SpecYAML: "rules: []",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/policies", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreatePolicy_MissingSpec(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreatePolicyRequest{
		Name: "test-policy",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/policies", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreatePolicy_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/policies", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_CreatePolicy_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.createPolicyErr = status.Error(codes.AlreadyExists, "policy already exists")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMCreatePolicyRequest{Name: "test", SpecYAML: "rules: []"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/policies", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestIAMHandlers_ListPolicies_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/policies", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMListPoliciesResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, int64(2), resp.Total)
}

func TestIAMHandlers_ListPolicies_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.listPoliciesErr = status.Error(codes.Internal, "internal error")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/policies", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestIAMHandlers_GetPolicy_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/policies/policy-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMPolicyResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "policy-123", resp.Name)
}

func TestIAMHandlers_GetPolicy_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.getPolicyErr = status.Error(codes.NotFound, "policy not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/policies/policy-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_UpdatePolicy_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdatePolicyRequest{
		Description: "Updated policy",
		Priority:    200,
	}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/policies/policy-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_UpdatePolicy_WithSpecYAML(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdatePolicyRequest{
		Description: "Updated policy",
		Priority:    200,
		SpecYAML:    "rules:\n  - action: allow",
	}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/policies/policy-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_UpdatePolicy_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/policies/policy-123", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_UpdatePolicy_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.updatePolicyErr = status.Error(codes.NotFound, "policy not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMUpdatePolicyRequest{Description: "Updated policy"}
	req := makeJSONRequest(t, http.MethodPut, "/api/v1/iam/policies/policy-123", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_DeletePolicy_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/policies/policy-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_DeletePolicy_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.deletePolicyErr = status.Error(codes.NotFound, "policy not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodDelete, "/api/v1/iam/policies/policy-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// =============================================================================
// Token Handler Tests
// =============================================================================

func TestIAMHandlers_IssueToken_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMIssueTokenRequest{
		UserID:    "user-123",
		Scopes:    []string{"read", "write"},
		ExpiresIn: 3600,
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp IAMIssueTokenResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "token-123", resp.TokenID)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestIAMHandlers_IssueToken_MissingTenantID(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMIssueTokenRequest{UserID: "user-123"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_IssueToken_MissingUserID(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMIssueTokenRequest{
		Scopes: []string{"read"},
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_IssueToken_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tokens", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_IssueToken_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.createTokenErr = status.Error(codes.NotFound, "user not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMIssueTokenRequest{UserID: "user-123"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens", body, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestIAMHandlers_ValidateToken_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMValidateTokenRequest{
		Token: "valid-token",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/validate", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMValidateTokenResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.Equal(t, "user-123", resp.UserID)
}

func TestIAMHandlers_ValidateToken_MissingToken(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMValidateTokenRequest{}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/validate", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_ValidateToken_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tokens/validate", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_ValidateToken_InvalidToken(t *testing.T) {
	client := newMockIAMClient()
	client.verifyTokenResp = &platformv1.VerifyIAMTokenResponse{
		Valid: false,
	}
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMValidateTokenRequest{
		Token: "invalid-token",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/validate", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMValidateTokenResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Valid)
}

func TestIAMHandlers_ValidateToken_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.verifyTokenErr = status.Error(codes.Internal, "internal error")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMValidateTokenRequest{Token: "some-token"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/validate", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestIAMHandlers_RefreshToken_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/refresh", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMIssueTokenResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestIAMHandlers_RefreshToken_MissingToken(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRefreshTokenRequest{}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/refresh", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_RefreshToken_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tokens/refresh", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_RefreshToken_InvalidToken(t *testing.T) {
	client := newMockIAMClient()
	client.verifyTokenResp = &platformv1.VerifyIAMTokenResponse{
		Valid: false,
	}
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/refresh", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestIAMHandlers_RefreshToken_VerifyGRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.verifyTokenErr = status.Error(codes.Unauthenticated, "unauthenticated")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRefreshTokenRequest{RefreshToken: "some-token"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/refresh", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestIAMHandlers_RefreshToken_CreateGRPCError(t *testing.T) {
	client := newMockIAMClient()
	// First verify succeeds, but create fails
	client.verifyTokenResp = &platformv1.VerifyIAMTokenResponse{
		Valid:    true,
		UserId:   "user-123",
		TenantId: "tenant-123",
		Scopes:   []string{"read"},
	}
	client.createTokenErr = status.Error(codes.Internal, "internal error")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRefreshTokenRequest{RefreshToken: "valid-token"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/refresh", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestIAMHandlers_RevokeToken_Success(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRevokeTokenRequest{
		TokenID: "token-123",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/revoke", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMSuccessResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestIAMHandlers_RevokeToken_WithTokenValue(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRevokeTokenRequest{
		Token: "access-token-value",
	}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/revoke", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestIAMHandlers_RevokeToken_MissingToken(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRevokeTokenRequest{}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/revoke", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_RevokeToken_InvalidJSON(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tokens/revoke", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIAMHandlers_RevokeToken_GRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.revokeTokenErr = status.Error(codes.NotFound, "token not found")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	body := IAMRevokeTokenRequest{TokenID: "token-123"}
	req := makeJSONRequest(t, http.MethodPost, "/api/v1/iam/tokens/revoke", body, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// =============================================================================
// Service Unavailable Tests
// =============================================================================

func TestIAMHandlers_ServiceUnavailable(t *testing.T) {
	handlers := NewIAMHandlers(nil, nil)
	router := newTestRouter(handlers)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"CreateUser", http.MethodPost, "/api/v1/iam/users"},
		{"ListUsers", http.MethodGet, "/api/v1/iam/users"},
		{"GetUser", http.MethodGet, "/api/v1/iam/users/user-123"},
		{"UpdateUser", http.MethodPut, "/api/v1/iam/users/user-123"},
		{"DeleteUser", http.MethodDelete, "/api/v1/iam/users/user-123"},
		{"CreateRole", http.MethodPost, "/api/v1/iam/roles"},
		{"ListRoles", http.MethodGet, "/api/v1/iam/roles"},
		{"GetRole", http.MethodGet, "/api/v1/iam/roles/role-123"},
		{"UpdateRole", http.MethodPut, "/api/v1/iam/roles/role-123"},
		{"DeleteRole", http.MethodDelete, "/api/v1/iam/roles/role-123"},
		{"CreateGroup", http.MethodPost, "/api/v1/iam/groups"},
		{"ListGroups", http.MethodGet, "/api/v1/iam/groups"},
		{"GetGroup", http.MethodGet, "/api/v1/iam/groups/group-123"},
		{"UpdateGroup", http.MethodPut, "/api/v1/iam/groups/group-123"},
		{"DeleteGroup", http.MethodDelete, "/api/v1/iam/groups/group-123"},
		{"CreatePolicy", http.MethodPost, "/api/v1/iam/policies"},
		{"ListPolicies", http.MethodGet, "/api/v1/iam/policies"},
		{"GetPolicy", http.MethodGet, "/api/v1/iam/policies/policy-123"},
		{"UpdatePolicy", http.MethodPut, "/api/v1/iam/policies/policy-123"},
		{"DeletePolicy", http.MethodDelete, "/api/v1/iam/policies/policy-123"},
		{"IssueToken", http.MethodPost, "/api/v1/iam/tokens"},
		{"ValidateToken", http.MethodPost, "/api/v1/iam/tokens/validate"},
		{"RefreshToken", http.MethodPost, "/api/v1/iam/tokens/refresh"},
		{"RevokeToken", http.MethodPost, "/api/v1/iam/tokens/revoke"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.method == http.MethodPost || tt.method == http.MethodPut {
				req = makeJSONRequest(t, tt.method, tt.path, map[string]string{}, nil)
			} else {
				req = makeJSONRequest(t, tt.method, tt.path, nil, nil)
			}
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
		})
	}
}

// =============================================================================
// GRPC Error Mapping Tests
// =============================================================================

func TestIAMHandlers_GRPCErrorMapping(t *testing.T) {
	tests := []struct {
		name           string
		grpcErr        error
		expectedStatus int
	}{
		{"NotFound", status.Error(codes.NotFound, "not found"), http.StatusNotFound},
		{"InvalidArgument", status.Error(codes.InvalidArgument, "invalid"), http.StatusBadRequest},
		{"AlreadyExists", status.Error(codes.AlreadyExists, "exists"), http.StatusConflict},
		{"PermissionDenied", status.Error(codes.PermissionDenied, "denied"), http.StatusForbidden},
		{"Unauthenticated", status.Error(codes.Unauthenticated, "unauthenticated"), http.StatusUnauthorized},
		{"ResourceExhausted", status.Error(codes.ResourceExhausted, "exhausted"), http.StatusTooManyRequests},
		{"FailedPrecondition", status.Error(codes.FailedPrecondition, "failed"), http.StatusPreconditionFailed},
		{"Unavailable", status.Error(codes.Unavailable, "unavailable"), http.StatusServiceUnavailable},
		{"DeadlineExceeded", status.Error(codes.DeadlineExceeded, "timeout"), http.StatusGatewayTimeout},
		{"Internal", status.Error(codes.Internal, "internal"), http.StatusInternalServerError},
		{"Unknown", status.Error(codes.Unknown, "unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newMockIAMClient()
			client.getUserErr = tt.grpcErr
			handlers := newTestIAMHandlers(client)
			router := newTestRouter(handlers)

			req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users/user-123", nil, map[string]string{
				"X-Tenant-ID": "tenant-123",
			})
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestIAMHandlers_NonGRPCError(t *testing.T) {
	client := newMockIAMClient()
	client.getUserErr = errors.New("plain error")
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users/user-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// =============================================================================
// Pagination Tests
// =============================================================================

func TestIAMHandlers_Pagination(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	t.Run("CustomLimitAndOffset", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?limit=25&offset=10", nil, map[string]string{
			"X-Tenant-ID": "tenant-123",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp IAMListUsersResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int32(25), resp.Limit)
		assert.Equal(t, int32(10), resp.Offset)
	})

	t.Run("MaxLimitEnforced", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?limit=5000", nil, map[string]string{
			"X-Tenant-ID": "tenant-123",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp IAMListUsersResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int32(maxIAMLimit), resp.Limit)
	})

	t.Run("DefaultValues", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users", nil, map[string]string{
			"X-Tenant-ID": "tenant-123",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp IAMListUsersResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int32(defaultIAMLimit), resp.Limit)
		assert.Equal(t, int32(defaultIAMOffset), resp.Offset)
	})

	t.Run("InvalidLimitUsesDefault", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?limit=abc", nil, map[string]string{
			"X-Tenant-ID": "tenant-123",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp IAMListUsersResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int32(defaultIAMLimit), resp.Limit)
	})

	t.Run("NegativeLimitUsesDefault", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?limit=-10", nil, map[string]string{
			"X-Tenant-ID": "tenant-123",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp IAMListUsersResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int32(defaultIAMLimit), resp.Limit)
	})

	t.Run("NegativeOffsetUsesDefault", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?offset=-10", nil, map[string]string{
			"X-Tenant-ID": "tenant-123",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp IAMListUsersResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int32(defaultIAMOffset), resp.Offset)
	})

	t.Run("InvalidOffsetUsesDefault", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?offset=abc", nil, map[string]string{
			"X-Tenant-ID": "tenant-123",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp IAMListUsersResponse
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int32(defaultIAMOffset), resp.Offset)
	})
}

// =============================================================================
// Tenant ID Source Tests
// =============================================================================

func TestIAMHandlers_TenantIDSource(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	t.Run("FromHeader", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users", nil, map[string]string{
			"X-Tenant-ID": "header-tenant",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("FromQueryParam", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?tenant_id=query-tenant", nil, nil)
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("HeaderTakesPrecedence", func(t *testing.T) {
		req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users?tenant_id=query-tenant", nil, map[string]string{
			"X-Tenant-ID": "header-tenant",
		})
		rr := httptest.NewRecorder()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestIAMErrors(t *testing.T) {
	t.Run("ErrIAMServiceUnavailable", func(t *testing.T) {
		err := ErrIAMServiceUnavailable{}
		assert.Equal(t, "IAM service not available", err.Error())
	})

	t.Run("ErrIAMMissingTenantID", func(t *testing.T) {
		err := ErrIAMMissingTenantID{}
		assert.Equal(t, "tenant ID is required", err.Error())
	})

	t.Run("ErrIAMMissingUserID", func(t *testing.T) {
		err := ErrIAMMissingUserID{}
		assert.Equal(t, "user ID is required", err.Error())
	})

	t.Run("ErrIAMMissingRoleID", func(t *testing.T) {
		err := ErrIAMMissingRoleID{}
		assert.Equal(t, "role ID is required", err.Error())
	})

	t.Run("ErrIAMMissingGroupID", func(t *testing.T) {
		err := ErrIAMMissingGroupID{}
		assert.Equal(t, "group ID is required", err.Error())
	})

	t.Run("ErrIAMMissingPolicyID", func(t *testing.T) {
		err := ErrIAMMissingPolicyID{}
		assert.Equal(t, "policy ID is required", err.Error())
	})

	t.Run("ErrIAMMissingToken", func(t *testing.T) {
		err := ErrIAMMissingToken{}
		assert.Equal(t, "token is required", err.Error())
	})

	t.Run("ErrIAMInvalidRequestBody", func(t *testing.T) {
		err := ErrIAMInvalidRequestBody{Reason: "invalid JSON"}
		assert.Equal(t, "invalid request body: invalid JSON", err.Error())
	})

	t.Run("ErrIAMOperationFailed", func(t *testing.T) {
		cause := status.Error(codes.Internal, "internal error")
		err := ErrIAMOperationFailed{Operation: "create_user", Cause: cause}
		assert.Contains(t, err.Error(), "create_user failed")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Route Registration Test
// =============================================================================

func TestIAMHandlers_RegisterRoutes(t *testing.T) {
	client := newMockIAMClient()
	handlers := newTestIAMHandlers(client)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)

	routes := []struct {
		method string
		path   string
	}{
		// User routes
		{http.MethodPost, "/api/v1/iam/users"},
		{http.MethodGet, "/api/v1/iam/users"},
		{http.MethodGet, "/api/v1/iam/users/test-id"},
		{http.MethodPut, "/api/v1/iam/users/test-id"},
		{http.MethodDelete, "/api/v1/iam/users/test-id"},

		// Role routes
		{http.MethodPost, "/api/v1/iam/roles"},
		{http.MethodGet, "/api/v1/iam/roles"},
		{http.MethodGet, "/api/v1/iam/roles/test-id"},
		{http.MethodPut, "/api/v1/iam/roles/test-id"},
		{http.MethodDelete, "/api/v1/iam/roles/test-id"},

		// Group routes
		{http.MethodPost, "/api/v1/iam/groups"},
		{http.MethodGet, "/api/v1/iam/groups"},
		{http.MethodGet, "/api/v1/iam/groups/test-id"},
		{http.MethodPut, "/api/v1/iam/groups/test-id"},
		{http.MethodDelete, "/api/v1/iam/groups/test-id"},

		// Policy routes
		{http.MethodPost, "/api/v1/iam/policies"},
		{http.MethodGet, "/api/v1/iam/policies"},
		{http.MethodGet, "/api/v1/iam/policies/test-id"},
		{http.MethodPut, "/api/v1/iam/policies/test-id"},
		{http.MethodDelete, "/api/v1/iam/policies/test-id"},

		// Token routes
		{http.MethodPost, "/api/v1/iam/tokens"},
		{http.MethodPost, "/api/v1/iam/tokens/validate"},
		{http.MethodPost, "/api/v1/iam/tokens/refresh"},
		{http.MethodPost, "/api/v1/iam/tokens/revoke"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			match := &mux.RouteMatch{}
			req := httptest.NewRequest(route.method, route.path, nil)
			matched := router.Match(req, match)
			assert.True(t, matched, "Route should match: %s %s", route.method, route.path)
		})
	}
}

// =============================================================================
// User Response Conversion Tests
// =============================================================================

func TestIAMHandlers_UserToResponse_WithAllFields(t *testing.T) {
	client := newMockIAMClient()
	now := timestamppb.Now()
	client.getUserResp = &platformv1.IAMUserResponse{
		User: &platformv1.IAMUser{
			Id:          "user-123",
			TenantId:    "tenant-123",
			Email:       "test@example.com",
			Name:        "Test User",
			Roles:       []string{"admin"},
			Groups:      []string{"developers"},
			Attributes:  map[string]string{"key": "value"},
			MfaVerified: true,
			CreatedAt:   now,
			UpdatedAt:   now,
			LastAuth:    now,
		},
	}
	handlers := newTestIAMHandlers(client)
	router := newTestRouter(handlers)

	req := makeJSONRequest(t, http.MethodGet, "/api/v1/iam/users/user-123", nil, map[string]string{
		"X-Tenant-ID": "tenant-123",
	})
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp IAMUserResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "user-123", resp.ID)
	assert.Equal(t, "tenant-123", resp.TenantID)
	assert.True(t, resp.MFAVerified)
	assert.NotNil(t, resp.CreatedAt)
	assert.NotNil(t, resp.UpdatedAt)
	assert.NotNil(t, resp.LastAuth)
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestNewIAMHandlers_NilLogger(t *testing.T) {
	client := newMockIAMClient()
	handlers := NewIAMHandlers(client, nil)
	assert.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
}
