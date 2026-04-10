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

package grpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockIAMService implements IAMService for testing.
type mockIAMService struct {
	createUserResp       *IAMUserResponse
	createUserErr        error
	getUserResp          *IAMUserResponse
	getUserErr           error
	updateUserResp       *IAMUserResponse
	updateUserErr        error
	deleteUserErr        error
	listUsersResp        *IAMListUsersResponse
	listUsersErr         error
	createRoleResp       *IAMRoleResponse
	createRoleErr        error
	getRoleResp          *IAMRoleResponse
	getRoleErr           error
	updateRoleResp       *IAMRoleResponse
	updateRoleErr        error
	deleteRoleErr        error
	listRolesResp        *IAMListRolesResponse
	listRolesErr         error
	assignRoleErr        error
	revokeRoleErr        error
	createGroupResp      *IAMGroupResponse
	createGroupErr       error
	getGroupResp         *IAMGroupResponse
	getGroupErr          error
	updateGroupResp      *IAMGroupResponse
	updateGroupErr       error
	deleteGroupErr       error
	listGroupsResp       *IAMListGroupsResponse
	listGroupsErr        error
	addGroupMemberErr    error
	removeGroupMemberErr error
	createPolicyResp     *IAMPolicyResponse
	createPolicyErr      error
	getPolicyResp        *IAMPolicyResponse
	getPolicyErr         error
	updatePolicyResp     *IAMPolicyResponse
	updatePolicyErr      error
	deletePolicyErr      error
	listPoliciesResp     *IAMListPoliciesResponse
	listPoliciesErr      error
	checkPermissionResp  *IAMCheckPermissionResponse
	checkPermissionErr   error
	issueTokenResp       *IAMIssueTokenResponse
	issueTokenErr        error
	validateTokenResp    *IAMValidateTokenResponse
	validateTokenErr     error
	refreshTokenResp     *IAMIssueTokenResponse
	refreshTokenErr      error
	revokeTokenErr       error
}

func newMockIAMService() *mockIAMService {
	now := time.Now().Unix()
	return &mockIAMService{
		createUserResp: &IAMUserResponse{
			ID:        "user-123",
			TenantID:  "tenant-1",
			Email:     "test@example.com",
			Name:      "Test User",
			Roles:     []string{"admin"},
			Groups:    []string{"developers"},
			CreatedAt: now,
			UpdatedAt: now,
		},
		getUserResp: &IAMUserResponse{
			ID:        "user-123",
			TenantID:  "tenant-1",
			Email:     "test@example.com",
			Name:      "Test User",
			Roles:     []string{"admin"},
			Groups:    []string{"developers"},
			CreatedAt: now,
			UpdatedAt: now,
		},
		updateUserResp: &IAMUserResponse{
			ID:        "user-123",
			TenantID:  "tenant-1",
			Email:     "updated@example.com",
			Name:      "Updated User",
			Roles:     []string{"admin", "user"},
			Groups:    []string{"developers", "admins"},
			CreatedAt: now,
			UpdatedAt: now,
		},
		listUsersResp: &IAMListUsersResponse{
			Users: []*IAMUserResponse{
				{ID: "user-1", TenantID: "tenant-1", Email: "user1@example.com"},
				{ID: "user-2", TenantID: "tenant-1", Email: "user2@example.com"},
			},
			Total: 2,
		},
		createRoleResp: &IAMRoleResponse{
			ID:          "role-123",
			TenantID:    "tenant-1",
			Name:        "admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		getRoleResp: &IAMRoleResponse{
			ID:          "role-123",
			TenantID:    "tenant-1",
			Name:        "admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		updateRoleResp: &IAMRoleResponse{
			ID:          "role-123",
			TenantID:    "tenant-1",
			Name:        "admin",
			Description: "Updated role",
			Permissions: []string{"read", "write"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		listRolesResp: &IAMListRolesResponse{
			Roles: []*IAMRoleResponse{
				{ID: "role-1", TenantID: "tenant-1", Name: "admin"},
				{ID: "role-2", TenantID: "tenant-1", Name: "user"},
			},
			Total: 2,
		},
		createGroupResp: &IAMGroupResponse{
			ID:          "group-123",
			TenantID:    "tenant-1",
			Name:        "developers",
			Description: "Development team",
			Members:     []string{"user-1", "user-2"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		getGroupResp: &IAMGroupResponse{
			ID:          "group-123",
			TenantID:    "tenant-1",
			Name:        "developers",
			Description: "Development team",
			Members:     []string{"user-1", "user-2"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		updateGroupResp: &IAMGroupResponse{
			ID:          "group-123",
			TenantID:    "tenant-1",
			Name:        "developers",
			Description: "Updated team",
			Members:     []string{"user-1", "user-2", "user-3"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		listGroupsResp: &IAMListGroupsResponse{
			Groups: []*IAMGroupResponse{
				{ID: "group-1", TenantID: "tenant-1", Name: "developers"},
				{ID: "group-2", TenantID: "tenant-1", Name: "admins"},
			},
			Total: 2,
		},
		createPolicyResp: &IAMPolicyResponse{
			ID:          "policy-123",
			TenantID:    "tenant-1",
			Name:        "default-policy",
			Description: "Default access policy",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		getPolicyResp: &IAMPolicyResponse{
			ID:          "policy-123",
			TenantID:    "tenant-1",
			Name:        "default-policy",
			Description: "Default access policy",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		updatePolicyResp: &IAMPolicyResponse{
			ID:          "policy-123",
			TenantID:    "tenant-1",
			Name:        "default-policy",
			Description: "Updated policy",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		listPoliciesResp: &IAMListPoliciesResponse{
			Policies: []*IAMPolicyResponse{
				{ID: "policy-1", TenantID: "tenant-1", Name: "policy-1"},
				{ID: "policy-2", TenantID: "tenant-1", Name: "policy-2"},
			},
			Total: 2,
		},
		checkPermissionResp: &IAMCheckPermissionResponse{
			Allowed: true,
			Reason:  "allowed by default policy",
		},
		issueTokenResp: &IAMIssueTokenResponse{
			TokenID:      "token-123",
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		},
		validateTokenResp: &IAMValidateTokenResponse{
			Valid:     true,
			UserID:    "user-123",
			TenantID:  "tenant-1",
			Scopes:    []string{"read", "write"},
			ExpiresAt: now + 3600,
		},
		refreshTokenResp: &IAMIssueTokenResponse{
			TokenID:      "token-456",
			AccessToken:  "refreshed-access-token",
			RefreshToken: "refreshed-refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		},
	}
}

// User operations
func (m *mockIAMService) CreateUser(ctx context.Context, req *IAMCreateUserRequest) (*IAMUserResponse, error) {
	if m.createUserErr != nil {
		return nil, m.createUserErr
	}
	return m.createUserResp, nil
}

func (m *mockIAMService) GetUser(ctx context.Context, req *IAMGetUserRequest) (*IAMUserResponse, error) {
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	return m.getUserResp, nil
}

func (m *mockIAMService) UpdateUser(ctx context.Context, req *IAMUpdateUserRequest) (*IAMUserResponse, error) {
	if m.updateUserErr != nil {
		return nil, m.updateUserErr
	}
	return m.updateUserResp, nil
}

func (m *mockIAMService) DeleteUser(ctx context.Context, req *IAMDeleteUserRequest) error {
	return m.deleteUserErr
}

func (m *mockIAMService) ListUsers(ctx context.Context, req *IAMListRequest) (*IAMListUsersResponse, error) {
	if m.listUsersErr != nil {
		return nil, m.listUsersErr
	}
	return m.listUsersResp, nil
}

// Role operations
func (m *mockIAMService) CreateRole(ctx context.Context, req *IAMCreateRoleRequest) (*IAMRoleResponse, error) {
	if m.createRoleErr != nil {
		return nil, m.createRoleErr
	}
	return m.createRoleResp, nil
}

func (m *mockIAMService) GetRole(ctx context.Context, req *IAMGetRoleRequest) (*IAMRoleResponse, error) {
	if m.getRoleErr != nil {
		return nil, m.getRoleErr
	}
	return m.getRoleResp, nil
}

func (m *mockIAMService) UpdateRole(ctx context.Context, req *IAMUpdateRoleRequest) (*IAMRoleResponse, error) {
	if m.updateRoleErr != nil {
		return nil, m.updateRoleErr
	}
	return m.updateRoleResp, nil
}

func (m *mockIAMService) DeleteRole(ctx context.Context, req *IAMDeleteRoleRequest) error {
	return m.deleteRoleErr
}

func (m *mockIAMService) ListRoles(ctx context.Context, req *IAMListRequest) (*IAMListRolesResponse, error) {
	if m.listRolesErr != nil {
		return nil, m.listRolesErr
	}
	return m.listRolesResp, nil
}

func (m *mockIAMService) AssignRoleToUser(ctx context.Context, req *IAMRoleAssignmentRequest) error {
	return m.assignRoleErr
}

func (m *mockIAMService) RevokeRoleFromUser(ctx context.Context, req *IAMRoleAssignmentRequest) error {
	return m.revokeRoleErr
}

// Group operations
func (m *mockIAMService) CreateGroup(ctx context.Context, req *IAMCreateGroupRequest) (*IAMGroupResponse, error) {
	if m.createGroupErr != nil {
		return nil, m.createGroupErr
	}
	return m.createGroupResp, nil
}

func (m *mockIAMService) GetGroup(ctx context.Context, req *IAMGetGroupRequest) (*IAMGroupResponse, error) {
	if m.getGroupErr != nil {
		return nil, m.getGroupErr
	}
	return m.getGroupResp, nil
}

func (m *mockIAMService) UpdateGroup(ctx context.Context, req *IAMUpdateGroupRequest) (*IAMGroupResponse, error) {
	if m.updateGroupErr != nil {
		return nil, m.updateGroupErr
	}
	return m.updateGroupResp, nil
}

func (m *mockIAMService) DeleteGroup(ctx context.Context, req *IAMDeleteGroupRequest) error {
	return m.deleteGroupErr
}

func (m *mockIAMService) ListGroups(ctx context.Context, req *IAMListRequest) (*IAMListGroupsResponse, error) {
	if m.listGroupsErr != nil {
		return nil, m.listGroupsErr
	}
	return m.listGroupsResp, nil
}

func (m *mockIAMService) AddGroupMember(ctx context.Context, req *IAMGroupMemberRequest) error {
	return m.addGroupMemberErr
}

func (m *mockIAMService) RemoveGroupMember(ctx context.Context, req *IAMGroupMemberRequest) error {
	return m.removeGroupMemberErr
}

// Policy operations
func (m *mockIAMService) CreatePolicy(ctx context.Context, req *IAMCreatePolicyRequest) (*IAMPolicyResponse, error) {
	if m.createPolicyErr != nil {
		return nil, m.createPolicyErr
	}
	return m.createPolicyResp, nil
}

func (m *mockIAMService) GetPolicy(ctx context.Context, req *IAMGetPolicyRequest) (*IAMPolicyResponse, error) {
	if m.getPolicyErr != nil {
		return nil, m.getPolicyErr
	}
	return m.getPolicyResp, nil
}

func (m *mockIAMService) UpdatePolicy(ctx context.Context, req *IAMUpdatePolicyRequest) (*IAMPolicyResponse, error) {
	if m.updatePolicyErr != nil {
		return nil, m.updatePolicyErr
	}
	return m.updatePolicyResp, nil
}

func (m *mockIAMService) DeletePolicy(ctx context.Context, req *IAMDeletePolicyRequest) error {
	return m.deletePolicyErr
}

func (m *mockIAMService) ListPolicies(ctx context.Context, req *IAMListRequest) (*IAMListPoliciesResponse, error) {
	if m.listPoliciesErr != nil {
		return nil, m.listPoliciesErr
	}
	return m.listPoliciesResp, nil
}

// Permission check
func (m *mockIAMService) CheckPermission(ctx context.Context, req *IAMCheckPermissionRequest) (*IAMCheckPermissionResponse, error) {
	if m.checkPermissionErr != nil {
		return nil, m.checkPermissionErr
	}
	return m.checkPermissionResp, nil
}

// Token operations
func (m *mockIAMService) IssueToken(ctx context.Context, req *IAMIssueTokenRequest) (*IAMIssueTokenResponse, error) {
	if m.issueTokenErr != nil {
		return nil, m.issueTokenErr
	}
	return m.issueTokenResp, nil
}

func (m *mockIAMService) ValidateToken(ctx context.Context, req *IAMValidateTokenRequest) (*IAMValidateTokenResponse, error) {
	if m.validateTokenErr != nil {
		return nil, m.validateTokenErr
	}
	return m.validateTokenResp, nil
}

func (m *mockIAMService) RefreshToken(ctx context.Context, req *IAMRefreshTokenRequest) (*IAMIssueTokenResponse, error) {
	if m.refreshTokenErr != nil {
		return nil, m.refreshTokenErr
	}
	return m.refreshTokenResp, nil
}

func (m *mockIAMService) RevokeToken(ctx context.Context, req *IAMRevokeTokenRequest) error {
	return m.revokeTokenErr
}

// Ensure mockIAMService implements IAMService at compile time.
var _ IAMService = (*mockIAMService)(nil)

func newTestIAMService() (*IAMGRPCService, *mockIAMService) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	mock := newMockIAMService()
	service := NewIAMGRPCService(logger, mock)
	return service, mock
}

// =============================================================================
// User Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateUser_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMUserRequest{
		TenantId: "tenant-1",
		Email:    "test@example.com",
		Name:     "Test User",
	}

	resp, err := service.CreateUser(ctx, req)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if resp.GetUser() == nil {
		t.Fatal("Expected user in response")
	}

	if resp.GetUser().GetId() != "user-123" {
		t.Errorf("Expected user ID 'user-123', got '%s'", resp.GetUser().GetId())
	}

	if resp.GetUser().GetEmail() != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", resp.GetUser().GetEmail())
	}
}

func TestIAMGRPCService_CreateUser_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewIAMGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.CreateIAMUserRequest{
		TenantId: "tenant-1",
		Email:    "test@example.com",
	}

	_, err := service.CreateUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestIAMGRPCService_CreateUser_MissingTenantID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMUserRequest{
		Email: "test@example.com",
	}

	_, err := service.CreateUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing tenant ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_CreateUser_MissingEmail(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMUserRequest{
		TenantId: "tenant-1",
	}

	_, err := service.CreateUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing email")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_CreateUser_ServiceError(t *testing.T) {
	service, mock := newTestIAMService()
	mock.createUserErr = errors.New("database error")
	ctx := context.Background()

	req := &platformv1.CreateIAMUserRequest{
		TenantId: "tenant-1",
		Email:    "test@example.com",
	}

	_, err := service.CreateUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal error, got %v", st.Code())
	}
}

func TestIAMGRPCService_GetUser_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	}

	resp, err := service.GetUser(ctx, req)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if resp.GetUser() == nil || resp.GetUser().GetId() != "user-123" {
		t.Error("Expected user in response")
	}
}

func TestIAMGRPCService_GetUser_MissingUserID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMUserRequest{
		TenantId: "tenant-1",
	}

	_, err := service.GetUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListUsers_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMUsersRequest{
		TenantId: "tenant-1",
	}

	resp, err := service.ListUsers(ctx, req)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if len(resp.GetUsers()) != 2 {
		t.Errorf("Expected 2 users, got %d", len(resp.GetUsers()))
	}
}

func TestIAMGRPCService_UpdateUser_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
		Email:    "updated@example.com",
		Name:     "Updated User",
	}

	resp, err := service.UpdateUser(ctx, req)
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	if resp.GetUser() == nil {
		t.Error("Expected user in response")
	}
}

func TestIAMGRPCService_UpdateUser_MissingUserID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMUserRequest{
		TenantId: "tenant-1",
		Email:    "updated@example.com",
	}

	_, err := service.UpdateUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_DeleteUser_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	}

	resp, err := service.DeleteUser(ctx, req)
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_DeleteUser_MissingUserID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMUserRequest{
		TenantId: "tenant-1",
	}

	_, err := service.DeleteUser(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// =============================================================================
// Role Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateRole_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMRoleRequest{
		TenantId:    "tenant-1",
		Name:        "admin",
		Description: "Administrator role",
		Permissions: []string{"read", "write"},
	}

	resp, err := service.CreateRole(ctx, req)
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	if resp.GetRole() == nil {
		t.Fatal("Expected role in response")
	}

	if resp.GetRole().GetName() != "admin" {
		t.Errorf("Expected role name 'admin', got '%s'", resp.GetRole().GetName())
	}
}

func TestIAMGRPCService_CreateRole_MissingName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMRoleRequest{
		TenantId: "tenant-1",
	}

	_, err := service.CreateRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_GetRole_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	}

	resp, err := service.GetRole(ctx, req)
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}

	if resp.GetRole() == nil {
		t.Error("Expected role in response")
	}
}

func TestIAMGRPCService_GetRole_MissingRoleID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMRoleRequest{
		TenantId: "tenant-1",
	}

	_, err := service.GetRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing role ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListRoles_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMRolesRequest{
		TenantId: "tenant-1",
	}

	resp, err := service.ListRoles(ctx, req)
	if err != nil {
		t.Fatalf("ListRoles failed: %v", err)
	}

	if len(resp.GetRoles()) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(resp.GetRoles()))
	}
}

func TestIAMGRPCService_UpdateRole_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMRoleRequest{
		TenantId:    "tenant-1",
		RoleId:      "role-123",
		Name:        "admin",
		Description: "Updated role",
	}

	resp, err := service.UpdateRole(ctx, req)
	if err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}

	if resp.GetRole() == nil {
		t.Error("Expected role in response")
	}
}

func TestIAMGRPCService_UpdateRole_MissingRoleID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMRoleRequest{
		TenantId: "tenant-1",
		Name:     "admin",
	}

	_, err := service.UpdateRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing role ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_DeleteRole_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	}

	resp, err := service.DeleteRole(ctx, req)
	if err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_DeleteRole_MissingRoleID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMRoleRequest{
		TenantId: "tenant-1",
	}

	_, err := service.DeleteRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing role ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_AssignRole_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.AssignIAMRoleRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
		RoleId:   "role-123",
	}

	resp, err := service.AssignRole(ctx, req)
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_AssignRole_MissingUserID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.AssignIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	}

	_, err := service.AssignRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_AssignRole_MissingRoleID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.AssignIAMRoleRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	}

	_, err := service.AssignRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing role ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_RevokeRole_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RevokeIAMRoleRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
		RoleId:   "role-123",
	}

	resp, err := service.RevokeRole(ctx, req)
	if err != nil {
		t.Fatalf("RevokeRole failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

// =============================================================================
// Group Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateGroup_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMGroupRequest{
		TenantId:    "tenant-1",
		Name:        "developers",
		Description: "Development team",
	}

	resp, err := service.CreateGroup(ctx, req)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	if resp.GetGroup() == nil {
		t.Fatal("Expected group in response")
	}

	if resp.GetGroup().GetName() != "developers" {
		t.Errorf("Expected group name 'developers', got '%s'", resp.GetGroup().GetName())
	}
}

func TestIAMGRPCService_CreateGroup_MissingName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMGroupRequest{
		TenantId: "tenant-1",
	}

	_, err := service.CreateGroup(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_GetGroup_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMGroupRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
	}

	resp, err := service.GetGroup(ctx, req)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}

	if resp.GetGroup() == nil {
		t.Error("Expected group in response")
	}
}

func TestIAMGRPCService_GetGroup_MissingGroupID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMGroupRequest{
		TenantId: "tenant-1",
	}

	_, err := service.GetGroup(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing group ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListGroups_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMGroupsRequest{
		TenantId: "tenant-1",
	}

	resp, err := service.ListGroups(ctx, req)
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}

	if len(resp.GetGroups()) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(resp.GetGroups()))
	}
}

func TestIAMGRPCService_UpdateGroup_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMGroupRequest{
		TenantId:    "tenant-1",
		GroupId:     "group-123",
		Name:        "developers",
		Description: "Updated team",
	}

	resp, err := service.UpdateGroup(ctx, req)
	if err != nil {
		t.Fatalf("UpdateGroup failed: %v", err)
	}

	if resp.GetGroup() == nil {
		t.Error("Expected group in response")
	}
}

func TestIAMGRPCService_UpdateGroup_MissingGroupID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMGroupRequest{
		TenantId: "tenant-1",
		Name:     "developers",
	}

	_, err := service.UpdateGroup(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing group ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_DeleteGroup_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMGroupRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
	}

	resp, err := service.DeleteGroup(ctx, req)
	if err != nil {
		t.Fatalf("DeleteGroup failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_DeleteGroup_MissingGroupID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMGroupRequest{
		TenantId: "tenant-1",
	}

	_, err := service.DeleteGroup(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing group ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_AddGroupMember_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.AddGroupMemberRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
		UserId:   "user-123",
	}

	resp, err := service.AddGroupMember(ctx, req)
	if err != nil {
		t.Fatalf("AddGroupMember failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_AddGroupMember_MissingUserID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.AddGroupMemberRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
	}

	_, err := service.AddGroupMember(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_RemoveGroupMember_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RemoveGroupMemberRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
		UserId:   "user-123",
	}

	resp, err := service.RemoveGroupMember(ctx, req)
	if err != nil {
		t.Fatalf("RemoveGroupMember failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

// =============================================================================
// Authorization Tests
// =============================================================================

func TestIAMGRPCService_CheckPermission_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CheckIAMPermissionRequest{
		TenantId:  "tenant-1",
		SubjectId: "user-123",
		Action:    "read",
		Resource:  "documents/123",
	}

	resp, err := service.CheckPermission(ctx, req)
	if err != nil {
		t.Fatalf("CheckPermission failed: %v", err)
	}

	if !resp.GetAllowed() {
		t.Error("Expected permission to be allowed")
	}
}

func TestIAMGRPCService_CheckPermission_MissingSubjectID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CheckIAMPermissionRequest{
		TenantId: "tenant-1",
		Action:   "read",
		Resource: "documents/123",
	}

	_, err := service.CheckPermission(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing subject ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_CheckPermission_MissingAction(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CheckIAMPermissionRequest{
		TenantId:  "tenant-1",
		SubjectId: "user-123",
		Resource:  "documents/123",
	}

	_, err := service.CheckPermission(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing action")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_CheckPermission_MissingResource(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CheckIAMPermissionRequest{
		TenantId:  "tenant-1",
		SubjectId: "user-123",
		Action:    "read",
	}

	_, err := service.CheckPermission(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing resource")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_CreateToken_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMTokenRequest{
		TenantId:  "tenant-1",
		UserId:    "user-123",
		Scopes:    []string{"read", "write"},
		ExpiresIn: 3600,
	}

	resp, err := service.CreateToken(ctx, req)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	if resp.GetAccessToken() == "" {
		t.Error("Expected access token in response")
	}
}

func TestIAMGRPCService_CreateToken_MissingUserID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMTokenRequest{
		TenantId: "tenant-1",
	}

	_, err := service.CreateToken(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_RevokeToken_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RevokeIAMTokenRequest{
		TokenId: "token-123",
	}

	resp, err := service.RevokeToken(ctx, req)
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_RevokeToken_MissingToken(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RevokeIAMTokenRequest{}

	_, err := service.RevokeToken(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing token")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_VerifyToken_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.VerifyIAMTokenRequest{
		Token: "access-token-xyz",
	}

	resp, err := service.VerifyToken(ctx, req)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	if !resp.GetValid() {
		t.Error("Expected token to be valid")
	}

	if resp.GetUserId() != "user-123" {
		t.Errorf("Expected user ID 'user-123', got '%s'", resp.GetUserId())
	}
}

func TestIAMGRPCService_VerifyToken_MissingToken(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.VerifyIAMTokenRequest{}

	_, err := service.VerifyToken(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing token")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// =============================================================================
// Tenant Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateTenant_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMTenantRequest{
		Id:   "tenant-new",
		Name: "New Tenant",
		Settings: &platformv1.IAMTenantSettings{
			MaxUsers:    100,
			MfaRequired: true,
		},
	}

	resp, err := service.CreateTenant(ctx, req)
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	if resp.GetTenant() == nil {
		t.Fatal("Expected tenant in response")
	}

	if resp.GetTenant().GetName() != "New Tenant" {
		t.Errorf("Expected tenant name 'New Tenant', got '%s'", resp.GetTenant().GetName())
	}
}

func TestIAMGRPCService_CreateTenant_MissingName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMTenantRequest{
		Id: "tenant-new",
	}

	_, err := service.CreateTenant(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_GetTenant_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMTenantRequest{
		TenantId: "tenant-1",
	}

	resp, err := service.GetTenant(ctx, req)
	if err != nil {
		t.Fatalf("GetTenant failed: %v", err)
	}

	if resp.GetTenant() == nil {
		t.Error("Expected tenant in response")
	}
}

func TestIAMGRPCService_GetTenant_MissingTenantID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMTenantRequest{}

	_, err := service.GetTenant(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing tenant ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListTenants_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMTenantsRequest{}

	resp, err := service.ListTenants(ctx, req)
	if err != nil {
		t.Fatalf("ListTenants failed: %v", err)
	}

	if resp == nil {
		t.Error("Expected response")
	}
}

func TestIAMGRPCService_UpdateTenant_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMTenantRequest{
		TenantId: "tenant-1",
		Name:     "Updated Tenant",
	}

	resp, err := service.UpdateTenant(ctx, req)
	if err != nil {
		t.Fatalf("UpdateTenant failed: %v", err)
	}

	if resp.GetTenant() == nil {
		t.Error("Expected tenant in response")
	}
}

func TestIAMGRPCService_UpdateTenant_MissingTenantID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMTenantRequest{
		Name: "Updated Tenant",
	}

	_, err := service.UpdateTenant(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing tenant ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_DeleteTenant_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMTenantRequest{
		TenantId: "tenant-1",
	}

	resp, err := service.DeleteTenant(ctx, req)
	if err != nil {
		t.Fatalf("DeleteTenant failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_DeleteTenant_MissingTenantID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMTenantRequest{}

	_, err := service.DeleteTenant(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing tenant ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// =============================================================================
// Policy Operation Tests
// =============================================================================

func TestIAMGRPCService_CreatePolicy_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMPolicyRequest{
		TenantId:    "tenant-1",
		Name:        "default-policy",
		Description: "Default access policy",
		SpecYaml:    []byte("rules: []"),
	}

	resp, err := service.CreatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	if resp.GetPolicy() == nil {
		t.Fatal("Expected policy in response")
	}
}

func TestIAMGRPCService_CreatePolicy_MissingName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.CreateIAMPolicyRequest{
		TenantId: "tenant-1",
	}

	_, err := service.CreatePolicy(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_GetPolicy_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMPolicyRequest{
		TenantId:   "tenant-1",
		PolicyName: "default-policy",
	}

	resp, err := service.GetPolicy(ctx, req)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}

	if resp.GetPolicy() == nil {
		t.Error("Expected policy in response")
	}
}

func TestIAMGRPCService_GetPolicy_MissingPolicyName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMPolicyRequest{
		TenantId: "tenant-1",
	}

	_, err := service.GetPolicy(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing policy name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListPolicies_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMPoliciesRequest{
		TenantId: "tenant-1",
	}

	resp, err := service.ListPolicies(ctx, req)
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}

	if resp == nil {
		t.Error("Expected response")
	}
}

func TestIAMGRPCService_UpdatePolicy_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMPolicyRequest{
		TenantId:    "tenant-1",
		PolicyName:  "default-policy",
		Description: "Updated policy",
	}

	resp, err := service.UpdatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("UpdatePolicy failed: %v", err)
	}

	if resp.GetPolicy() == nil {
		t.Error("Expected policy in response")
	}
}

func TestIAMGRPCService_UpdatePolicy_MissingPolicyName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMPolicyRequest{
		TenantId:    "tenant-1",
		Description: "Updated policy",
	}

	_, err := service.UpdatePolicy(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing policy name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_DeletePolicy_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMPolicyRequest{
		TenantId:   "tenant-1",
		PolicyName: "default-policy",
	}

	resp, err := service.DeletePolicy(ctx, req)
	if err != nil {
		t.Fatalf("DeletePolicy failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_DeletePolicy_MissingPolicyName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMPolicyRequest{
		TenantId: "tenant-1",
	}

	_, err := service.DeletePolicy(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing policy name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ValidatePolicy_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ValidateIAMPolicyRequest{
		TenantId: "tenant-1",
		SpecYaml: []byte("rules: []"),
	}

	resp, err := service.ValidatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("ValidatePolicy failed: %v", err)
	}

	if !resp.GetValid() {
		t.Error("Expected policy to be valid")
	}
}

func TestIAMGRPCService_ValidatePolicy_MissingSpec(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ValidateIAMPolicyRequest{
		TenantId: "tenant-1",
	}

	_, err := service.ValidatePolicy(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing spec")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_TestPolicy_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.TestIAMPolicyRequest{
		TenantId:  "tenant-1",
		SubjectId: "user-123",
		Action:    "read",
		Resource:  "documents/123",
	}

	resp, err := service.TestPolicy(ctx, req)
	if err != nil {
		t.Fatalf("TestPolicy failed: %v", err)
	}

	if !resp.GetAllowed() {
		t.Error("Expected action to be allowed")
	}
}

func TestIAMGRPCService_TestPolicy_MissingSubjectID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.TestIAMPolicyRequest{
		TenantId: "tenant-1",
		Action:   "read",
		Resource: "documents/123",
	}

	_, err := service.TestPolicy(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing subject ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// =============================================================================
// Application Operation Tests
// =============================================================================

func TestIAMGRPCService_RegisterApp_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RegisterIAMAppRequest{
		TenantId:     "tenant-1",
		Name:         "myapp",
		RedirectUris: []string{"https://myapp.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}

	resp, err := service.RegisterApp(ctx, req)
	if err != nil {
		t.Fatalf("RegisterApp failed: %v", err)
	}

	if resp.GetApp() == nil {
		t.Fatal("Expected app in response")
	}

	if resp.GetApp().GetClientId() == "" {
		t.Error("Expected client ID in response")
	}

	if resp.GetApp().GetClientSecret() == "" {
		t.Error("Expected client secret in response")
	}
}

func TestIAMGRPCService_RegisterApp_MissingName(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RegisterIAMAppRequest{
		TenantId: "tenant-1",
	}

	_, err := service.RegisterApp(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_GetApp_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMAppRequest{
		TenantId: "tenant-1",
		ClientId: "app-123",
	}

	resp, err := service.GetApp(ctx, req)
	if err != nil {
		t.Fatalf("GetApp failed: %v", err)
	}

	if resp.GetApp() == nil {
		t.Error("Expected app in response")
	}
}

func TestIAMGRPCService_GetApp_MissingClientID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.GetIAMAppRequest{
		TenantId: "tenant-1",
	}

	_, err := service.GetApp(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing client ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListApps_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMAppsRequest{
		TenantId: "tenant-1",
	}

	resp, err := service.ListApps(ctx, req)
	if err != nil {
		t.Fatalf("ListApps failed: %v", err)
	}

	if resp == nil {
		t.Error("Expected response")
	}
}

func TestIAMGRPCService_UpdateApp_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMAppRequest{
		TenantId: "tenant-1",
		ClientId: "app-123",
		Name:     "Updated App",
	}

	resp, err := service.UpdateApp(ctx, req)
	if err != nil {
		t.Fatalf("UpdateApp failed: %v", err)
	}

	if resp.GetApp() == nil {
		t.Error("Expected app in response")
	}
}

func TestIAMGRPCService_UpdateApp_MissingClientID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.UpdateIAMAppRequest{
		TenantId: "tenant-1",
		Name:     "Updated App",
	}

	_, err := service.UpdateApp(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing client ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_DeleteApp_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMAppRequest{
		TenantId: "tenant-1",
		ClientId: "app-123",
	}

	resp, err := service.DeleteApp(ctx, req)
	if err != nil {
		t.Fatalf("DeleteApp failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestIAMGRPCService_DeleteApp_MissingClientID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.DeleteIAMAppRequest{
		TenantId: "tenant-1",
	}

	_, err := service.DeleteApp(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing client ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_RotateAppSecret_Success(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RotateIAMAppSecretRequest{
		TenantId: "tenant-1",
		ClientId: "app-123",
	}

	resp, err := service.RotateAppSecret(ctx, req)
	if err != nil {
		t.Fatalf("RotateAppSecret failed: %v", err)
	}

	if resp.GetClientSecret() == "" {
		t.Error("Expected new client secret in response")
	}
}

func TestIAMGRPCService_RotateAppSecret_MissingClientID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RotateIAMAppSecretRequest{
		TenantId: "tenant-1",
	}

	_, err := service.RotateAppSecret(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing client ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrNilIAMService_Error(t *testing.T) {
	err := ErrNilIAMService{}
	expected := "IAM service is nil"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingTenantID_Error(t *testing.T) {
	err := ErrMissingTenantID{}
	expected := "tenant ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingUserID_Error(t *testing.T) {
	err := ErrMissingUserID{}
	expected := "user ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingEmail_Error(t *testing.T) {
	err := ErrMissingEmail{}
	expected := "email is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingRoleID_Error(t *testing.T) {
	err := ErrMissingRoleID{}
	expected := "role ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingRoleName_Error(t *testing.T) {
	err := ErrMissingRoleName{}
	expected := "role name is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingGroupID_Error(t *testing.T) {
	err := ErrMissingGroupID{}
	expected := "group ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingGroupName_Error(t *testing.T) {
	err := ErrMissingGroupName{}
	expected := "group name is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingToken_Error(t *testing.T) {
	err := ErrMissingToken{}
	expected := "token is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingSubjectID_Error(t *testing.T) {
	err := ErrMissingSubjectID{}
	expected := "subject ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingAction_Error(t *testing.T) {
	err := ErrMissingAction{}
	expected := "action is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingResource_Error(t *testing.T) {
	err := ErrMissingResource{}
	expected := "resource is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingTenantName_Error(t *testing.T) {
	err := ErrMissingTenantName{}
	expected := "tenant name is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingPolicyName_Error(t *testing.T) {
	err := ErrMissingPolicyName{}
	expected := "policy name is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingPolicySpec_Error(t *testing.T) {
	err := ErrMissingPolicySpec{}
	expected := "policy spec is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingAppName_Error(t *testing.T) {
	err := ErrMissingAppName{}
	expected := "app name is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingClientID_Error(t *testing.T) {
	err := ErrMissingClientID{}
	expected := "client ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrIAMOperationFailed_Error(t *testing.T) {
	err := ErrIAMOperationFailed{Operation: "CreateUser", Reason: "database error"}
	expected := "IAM operation CreateUser failed: database error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestIAMGRPCService_mapError_ErrIAMOperationFailed(t *testing.T) {
	service, _ := newTestIAMService()
	err := ErrIAMOperationFailed{Operation: "test", Reason: "error"}

	grpcErr := service.mapError("test", err)
	st, ok := status.FromError(grpcErr)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

func TestIAMGRPCService_mapError_UnixErrors(t *testing.T) {
	service, _ := newTestIAMService()

	testCases := []struct {
		err  error
		code codes.Code
	}{
		{ErrIAMServiceNil{}, codes.FailedPrecondition},
		{ErrIAMTenantIDRequired{}, codes.InvalidArgument},
		{ErrIAMUserIDRequired{}, codes.InvalidArgument},
		{ErrIAMEmailRequired{}, codes.InvalidArgument},
		{ErrIAMRoleIDRequired{}, codes.InvalidArgument},
		{ErrIAMGroupIDRequired{}, codes.InvalidArgument},
		{ErrIAMNameRequired{}, codes.InvalidArgument},
		{ErrIAMTokenRequired{}, codes.InvalidArgument},
		{ErrIAMSubjectIDRequired{}, codes.InvalidArgument},
		{ErrIAMResourceRequired{}, codes.InvalidArgument},
		{ErrIAMActionRequired{}, codes.InvalidArgument},
	}

	for _, tc := range testCases {
		grpcErr := service.mapError("test", tc.err)
		st, ok := status.FromError(grpcErr)
		if !ok {
			t.Fatalf("Expected gRPC status error for %T", tc.err)
		}

		if st.Code() != tc.code {
			t.Errorf("For %T: expected %v, got %v", tc.err, tc.code, st.Code())
		}
	}
}

func TestIAMGRPCService_mapError_GenericError(t *testing.T) {
	service, _ := newTestIAMService()
	err := errors.New("generic error")

	grpcErr := service.mapError("test", err)
	st, ok := status.FromError(grpcErr)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

func TestIAMGRPCService_mapError_NilError(t *testing.T) {
	service, _ := newTestIAMService()
	grpcErr := service.mapError("test", nil)
	if grpcErr != nil {
		t.Error("Expected nil for nil input")
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestUnixUserToProto_Nil(t *testing.T) {
	result := iamUserToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestUnixRoleToProto_Nil(t *testing.T) {
	result := iamRoleToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestUnixGroupToProto_Nil(t *testing.T) {
	result := iamGroupToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestIAMSuccessStatus(t *testing.T) {
	status := iamSuccessStatus("test message")
	if status == nil {
		t.Fatal("Expected non-nil status")
	}

	if !status.GetSuccess() {
		t.Error("Expected success to be true")
	}

	if status.GetMessage() != "test message" {
		t.Errorf("Expected 'test message', got '%s'", status.GetMessage())
	}
}

// Additional validation tests for better coverage

func TestIAMGRPCService_RevokeRole_MissingUserID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RevokeIAMRoleRequest{
		TenantId: "tenant-123",
		RoleId:   "role-456",
	}

	_, err := service.RevokeRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_RevokeRole_MissingRoleID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RevokeIAMRoleRequest{
		TenantId: "tenant-123",
		UserId:   "user-123",
	}

	_, err := service.RevokeRole(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing role ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_RemoveGroupMember_MissingUserIDValidation(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RemoveGroupMemberRequest{
		TenantId: "tenant-123",
		GroupId:  "group-456",
	}

	_, err := service.RemoveGroupMember(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_RemoveGroupMember_MissingGroupIDValidation(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.RemoveGroupMemberRequest{
		TenantId: "tenant-123",
		UserId:   "user-123",
	}

	_, err := service.RemoveGroupMember(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing group ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListApps_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewIAMGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ListIAMAppsRequest{
		TenantId: "tenant-123",
	}

	_, err := service.ListApps(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListApps_MissingTenantID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMAppsRequest{}

	_, err := service.ListApps(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing tenant ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListPolicies_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewIAMGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ListIAMPoliciesRequest{
		TenantId: "tenant-123",
	}

	_, err := service.ListPolicies(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListPolicies_MissingTenantID(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.ListIAMPoliciesRequest{}

	_, err := service.ListPolicies(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing tenant ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_ListTenants_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewIAMGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ListIAMTenantsRequest{}

	_, err := service.ListTenants(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestIAMGRPCService_AddGroupMember_MissingUserIDValidation(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.AddGroupMemberRequest{
		TenantId: "tenant-123",
		GroupId:  "group-456",
	}

	_, err := service.AddGroupMember(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing user ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestIAMGRPCService_AddGroupMember_MissingGroupIDValidation(t *testing.T) {
	service, _ := newTestIAMService()
	ctx := context.Background()

	req := &platformv1.AddGroupMemberRequest{
		TenantId: "tenant-123",
		UserId:   "user-123",
	}

	_, err := service.AddGroupMember(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing group ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}
