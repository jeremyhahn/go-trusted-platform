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

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Mock IAM Client for IAM operations coverage tests
// =============================================================================

// mockIAMClientForTests implements iampb.IAMServiceClient for testing
type mockIAMClientForTests struct {
	iampb.IAMServiceClient // Embed to satisfy interface for unimplemented methods

	// User operations
	createUserResp *iampb.User
	createUserErr  error
	deleteUserResp *iampb.DeleteUserResponse
	deleteUserErr  error
	getUserResp    *iampb.User
	getUserErr     error
	listUsersResp  *iampb.ListUsersResponse
	listUsersErr   error

	// Role operations
	createRoleResp *iampb.Role
	createRoleErr  error
	deleteRoleResp *iampb.DeleteRoleResponse
	deleteRoleErr  error
	getRoleResp    *iampb.Role
	getRoleErr     error
	listRolesResp  *iampb.ListRolesResponse
	listRolesErr   error

	// Role assignment operations
	assignRoleResp *iampb.AssignRoleResponse
	assignRoleErr  error
	revokeRoleResp *iampb.RevokeRoleResponse
	revokeRoleErr  error

	// Group operations
	createGroupResp         *iampb.Group
	createGroupErr          error
	deleteGroupResp         *iampb.DeleteGroupResponse
	deleteGroupErr          error
	getGroupResp            *iampb.Group
	getGroupErr             error
	listGroupsResp          *iampb.ListGroupsResponse
	listGroupsErr           error
	addUserToGroupResp      *iampb.AddUserToGroupResponse
	addUserToGroupErr       error
	removeUserFromGroupResp *iampb.RemoveUserFromGroupResponse
	removeUserFromGroupErr  error

	// Tenant operations
	createTenantResp *iampb.Tenant
	createTenantErr  error
	deleteTenantResp *iampb.DeleteTenantResponse
	deleteTenantErr  error
	getTenantResp    *iampb.Tenant
	getTenantErr     error
	listTenantsResp  *iampb.ListTenantsResponse
	listTenantsErr   error
}

func (m *mockIAMClientForTests) CreateUser(ctx context.Context, in *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.createUserErr != nil {
		return nil, m.createUserErr
	}
	return m.createUserResp, nil
}

func (m *mockIAMClientForTests) DeleteUser(ctx context.Context, in *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
	if m.deleteUserErr != nil {
		return nil, m.deleteUserErr
	}
	return m.deleteUserResp, nil
}

func (m *mockIAMClientForTests) GetUser(ctx context.Context, in *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	return m.getUserResp, nil
}

func (m *mockIAMClientForTests) ListUsers(ctx context.Context, in *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
	if m.listUsersErr != nil {
		return nil, m.listUsersErr
	}
	return m.listUsersResp, nil
}

func (m *mockIAMClientForTests) CreateRole(ctx context.Context, in *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.createRoleErr != nil {
		return nil, m.createRoleErr
	}
	return m.createRoleResp, nil
}

func (m *mockIAMClientForTests) DeleteRole(ctx context.Context, in *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
	if m.deleteRoleErr != nil {
		return nil, m.deleteRoleErr
	}
	return m.deleteRoleResp, nil
}

func (m *mockIAMClientForTests) GetRole(ctx context.Context, in *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.getRoleErr != nil {
		return nil, m.getRoleErr
	}
	return m.getRoleResp, nil
}

func (m *mockIAMClientForTests) ListRoles(ctx context.Context, in *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
	if m.listRolesErr != nil {
		return nil, m.listRolesErr
	}
	return m.listRolesResp, nil
}

func (m *mockIAMClientForTests) AssignRole(ctx context.Context, in *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
	if m.assignRoleErr != nil {
		return nil, m.assignRoleErr
	}
	return m.assignRoleResp, nil
}

func (m *mockIAMClientForTests) RevokeRole(ctx context.Context, in *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
	if m.revokeRoleErr != nil {
		return nil, m.revokeRoleErr
	}
	return m.revokeRoleResp, nil
}

func (m *mockIAMClientForTests) CreateGroup(ctx context.Context, in *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.createGroupErr != nil {
		return nil, m.createGroupErr
	}
	return m.createGroupResp, nil
}

func (m *mockIAMClientForTests) DeleteGroup(ctx context.Context, in *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
	if m.deleteGroupErr != nil {
		return nil, m.deleteGroupErr
	}
	return m.deleteGroupResp, nil
}

func (m *mockIAMClientForTests) GetGroup(ctx context.Context, in *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.getGroupErr != nil {
		return nil, m.getGroupErr
	}
	return m.getGroupResp, nil
}

func (m *mockIAMClientForTests) ListGroups(ctx context.Context, in *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
	if m.listGroupsErr != nil {
		return nil, m.listGroupsErr
	}
	return m.listGroupsResp, nil
}

func (m *mockIAMClientForTests) AddUserToGroup(ctx context.Context, in *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
	if m.addUserToGroupErr != nil {
		return nil, m.addUserToGroupErr
	}
	return m.addUserToGroupResp, nil
}

func (m *mockIAMClientForTests) RemoveUserFromGroup(ctx context.Context, in *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
	if m.removeUserFromGroupErr != nil {
		return nil, m.removeUserFromGroupErr
	}
	return m.removeUserFromGroupResp, nil
}

func (m *mockIAMClientForTests) CreateTenant(ctx context.Context, in *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.createTenantErr != nil {
		return nil, m.createTenantErr
	}
	return m.createTenantResp, nil
}

func (m *mockIAMClientForTests) DeleteTenant(ctx context.Context, in *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error) {
	if m.deleteTenantErr != nil {
		return nil, m.deleteTenantErr
	}
	return m.deleteTenantResp, nil
}

func (m *mockIAMClientForTests) GetTenant(ctx context.Context, in *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.getTenantErr != nil {
		return nil, m.getTenantErr
	}
	return m.getTenantResp, nil
}

func (m *mockIAMClientForTests) ListTenants(ctx context.Context, in *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
	if m.listTenantsErr != nil {
		return nil, m.listTenantsErr
	}
	return m.listTenantsResp, nil
}

// mockPEPClientForTests implements iampb.PEPServiceClient for testing
type mockPEPClientForTests struct {
	iampb.PEPServiceClient
	checkResp *iampb.CheckResponse
	checkErr  error
}

func (m *mockPEPClientForTests) Check(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
	if m.checkErr != nil {
		return nil, m.checkErr
	}
	return m.checkResp, nil
}

// =============================================================================
// CA Operations Tests
// =============================================================================

func TestMCPServiceProvider_CAGet_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAGet(ctx, "abc123", true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAList_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAList(ctx, 10, "", "active")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAList_DefaultPageSize(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAList(ctx, 0, "", "")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

func TestMCPServiceProvider_CARevoke_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARevoke(ctx, "abc123", 1, false)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CARenew_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARenew(ctx, "abc123", 365, true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAVerify_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAVerify(ctx, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", nil, true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAVerify_WithDER(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	derData := []byte{0x30, 0x82, 0x01, 0x22}
	_, err := provider.CAVerify(ctx, "", derData, false)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CACRL_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CACRL(ctx)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CABundle_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CABundle(ctx, "software", "RSA")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CABundle_WithParameters(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	testCases := []struct {
		name      string
		storeType string
		algorithm string
	}{
		{"software RSA", "software", "RSA"},
		{"tpm ECC", "tpm", "ECC"},
		{"empty params", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.CABundle(ctx, tc.storeType, tc.algorithm)
			if err == nil {
				t.Fatal("expected error for nil CA service")
			}
			if _, ok := err.(ErrServiceNotAvailable); !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T", err)
			}
		})
	}
}

// =============================================================================
// IAM User Operations Tests
// =============================================================================

func TestMCPServiceProvider_IAMCreateUser_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMCreateUser(ctx, &mcp.IAMCreateUserRequest{
		TenantID: "tenant1",
		Email:    "test@example.com",
	})
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMCreateUser_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateUser(ctx, &mcp.IAMCreateUserRequest{
		TenantID: "",
		Email:    "test@example.com",
	})
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCreateUser_MissingEmail(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateUser(ctx, &mcp.IAMCreateUserRequest{
		TenantID: "tenant1",
		Email:    "",
	})
	if err == nil {
		t.Fatal("expected error for missing email")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "email" {
		t.Errorf("expected parameter='email', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCreateUser_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		createUserResp: &iampb.User{
			Id:       "user1",
			TenantId: "tenant1",
			Email:    "test@example.com",
			Name:     "Test User",
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMCreateUser(ctx, &mcp.IAMCreateUserRequest{
		TenantID: "tenant1",
		Email:    "test@example.com",
		Name:     "Test User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if userMap["email"] != "test@example.com" {
		t.Errorf("expected email='test@example.com', got %v", userMap["email"])
	}
}

func TestMCPServiceProvider_IAMCreateUser_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		createUserErr: errors.New("user already exists"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateUser(ctx, &mcp.IAMCreateUserRequest{
		TenantID: "tenant1",
		Email:    "test@example.com",
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "CreateUser" {
		t.Errorf("expected Operation='CreateUser', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteUser_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMDeleteUser(ctx, "tenant1", "user1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMDeleteUser_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteUser(ctx, "", "user1")
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMDeleteUser_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteUser(ctx, "tenant1", "")
	if err == nil {
		t.Fatal("expected error for missing user_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "user_id" {
		t.Errorf("expected parameter='user_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMDeleteUser_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		deleteUserResp: &iampb.DeleteUserResponse{
			Success: true,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteUser(ctx, "tenant1", "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMDeleteUser_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		deleteUserResp: &iampb.DeleteUserResponse{
			Success: false,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteUser(ctx, "tenant1", "nonexistent")
	if err == nil {
		t.Fatal("expected error for user not found")
	}

	notFoundErr, ok := err.(ErrIAMUserNotFound)
	if !ok {
		t.Fatalf("expected ErrIAMUserNotFound, got %T: %v", err, err)
	}
	if notFoundErr.TenantID != "tenant1" {
		t.Errorf("expected TenantID='tenant1', got %q", notFoundErr.TenantID)
	}
}

func TestMCPServiceProvider_IAMDeleteUser_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		deleteUserErr: errors.New("database error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteUser(ctx, "tenant1", "user1")
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteUser" {
		t.Errorf("expected Operation='DeleteUser', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMGetUser_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMGetUser(ctx, "tenant1", "user1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMGetUser_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetUser(ctx, "", "user1")
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMGetUser_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetUser(ctx, "tenant1", "")
	if err == nil {
		t.Fatal("expected error for missing user_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "user_id" {
		t.Errorf("expected parameter='user_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMGetUser_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		getUserResp: &iampb.User{
			Id:       "user1",
			TenantId: "tenant1",
			Email:    "test@example.com",
			Name:     "Test User",
			Roles:    []string{"admin", "user"},
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMGetUser(ctx, "tenant1", "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if userMap["id"] != "user1" {
		t.Errorf("expected id='user1', got %v", userMap["id"])
	}
	if userMap["email"] != "test@example.com" {
		t.Errorf("expected email='test@example.com', got %v", userMap["email"])
	}
}

func TestMCPServiceProvider_IAMGetUser_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		getUserErr: errors.New("user not found"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetUser(ctx, "tenant1", "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found user")
	}

	notFoundErr, ok := err.(ErrIAMUserNotFound)
	if !ok {
		t.Fatalf("expected ErrIAMUserNotFound, got %T: %v", err, err)
	}
	if notFoundErr.TenantID != "tenant1" {
		t.Errorf("expected TenantID='tenant1', got %q", notFoundErr.TenantID)
	}
	if notFoundErr.UserID != "nonexistent" {
		t.Errorf("expected UserID='nonexistent', got %q", notFoundErr.UserID)
	}
}

func TestMCPServiceProvider_IAMListUsers_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMListUsers(ctx, "tenant1", 10, 0)
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMListUsers_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMListUsers(ctx, "", 10, 0)
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMListUsers_DefaultValues(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listUsersResp: &iampb.ListUsersResponse{
			Users: []*iampb.User{
				{Id: "user1", TenantId: "tenant1", Email: "user1@example.com"},
				{Id: "user2", TenantId: "tenant1", Email: "user2@example.com"},
			},
			Total: 2,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListUsers(ctx, "tenant1", 0, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["limit"] != 50 {
		t.Errorf("expected limit=50 (default), got %v", resultMap["limit"])
	}
	if resultMap["offset"] != 0 {
		t.Errorf("expected offset=0 (corrected from -1), got %v", resultMap["offset"])
	}
}

func TestMCPServiceProvider_IAMListUsers_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listUsersResp: &iampb.ListUsersResponse{
			Users: []*iampb.User{
				{Id: "user1", TenantId: "tenant1", Email: "user1@example.com"},
				{Id: "user2", TenantId: "tenant1", Email: "user2@example.com"},
			},
			Total: 2,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListUsers(ctx, "tenant1", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	users, ok := resultMap["users"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected []map[string]interface{} for users, got %T", resultMap["users"])
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestMCPServiceProvider_IAMListUsers_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listUsersErr: errors.New("database error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMListUsers(ctx, "tenant1", 10, 0)
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "ListUsers" {
		t.Errorf("expected Operation='ListUsers', got %q", opErr.Operation)
	}
}

// =============================================================================
// IAM Role Operations Tests
// =============================================================================

func TestMCPServiceProvider_IAMCreateRole_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMCreateRole(ctx, &mcp.IAMCreateRoleRequest{
		TenantID: "tenant1",
		ID:       "role1",
		Name:     "Admin",
	})
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMCreateRole_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateRole(ctx, &mcp.IAMCreateRoleRequest{
		TenantID: "",
		ID:       "role1",
	})
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCreateRole_MissingID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateRole(ctx, &mcp.IAMCreateRoleRequest{
		TenantID: "tenant1",
		ID:       "",
	})
	if err == nil {
		t.Fatal("expected error for missing id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "id" {
		t.Errorf("expected parameter='id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCreateRole_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		createRoleResp: &iampb.Role{
			Id:          "role1",
			TenantId:    "tenant1",
			Name:        "Admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "admin"},
			CreatedAt:   timestamppb.Now(),
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMCreateRole(ctx, &mcp.IAMCreateRoleRequest{
		TenantID:    "tenant1",
		ID:          "role1",
		Name:        "Admin",
		Description: "Administrator role",
		Permissions: []string{"read", "write", "admin"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	roleMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if roleMap["id"] != "role1" {
		t.Errorf("expected id='role1', got %v", roleMap["id"])
	}
}

func TestMCPServiceProvider_IAMCreateRole_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		createRoleErr: errors.New("role already exists"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateRole(ctx, &mcp.IAMCreateRoleRequest{
		TenantID: "tenant1",
		ID:       "role1",
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "CreateRole" {
		t.Errorf("expected Operation='CreateRole', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteRole_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMDeleteRole(ctx, "tenant1", "role1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMDeleteRole_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteRole(ctx, "", "role1")
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMDeleteRole_MissingRoleID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteRole(ctx, "tenant1", "")
	if err == nil {
		t.Fatal("expected error for missing role_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "role_id" {
		t.Errorf("expected parameter='role_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMDeleteRole_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		deleteRoleResp: &iampb.DeleteRoleResponse{
			Success: true,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteRole(ctx, "tenant1", "role1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMDeleteRole_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		deleteRoleResp: &iampb.DeleteRoleResponse{
			Success: false,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteRole(ctx, "tenant1", "nonexistent")
	if err == nil {
		t.Fatal("expected error for role not found")
	}

	notFoundErr, ok := err.(ErrIAMRoleNotFound)
	if !ok {
		t.Fatalf("expected ErrIAMRoleNotFound, got %T: %v", err, err)
	}
	if notFoundErr.TenantID != "tenant1" {
		t.Errorf("expected TenantID='tenant1', got %q", notFoundErr.TenantID)
	}
}

func TestMCPServiceProvider_IAMDeleteRole_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		deleteRoleErr: errors.New("database error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteRole(ctx, "tenant1", "role1")
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteRole" {
		t.Errorf("expected Operation='DeleteRole', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMGetRole_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMGetRole(ctx, "tenant1", "role1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMGetRole_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetRole(ctx, "", "role1")
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMGetRole_MissingRoleID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetRole(ctx, "tenant1", "")
	if err == nil {
		t.Fatal("expected error for missing role_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "role_id" {
		t.Errorf("expected parameter='role_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMGetRole_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		getRoleResp: &iampb.Role{
			Id:          "role1",
			TenantId:    "tenant1",
			Name:        "Admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write"},
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMGetRole(ctx, "tenant1", "role1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	roleMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if roleMap["id"] != "role1" {
		t.Errorf("expected id='role1', got %v", roleMap["id"])
	}
	if roleMap["name"] != "Admin" {
		t.Errorf("expected name='Admin', got %v", roleMap["name"])
	}
}

func TestMCPServiceProvider_IAMGetRole_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		getRoleErr: errors.New("role not found"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetRole(ctx, "tenant1", "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found role")
	}

	notFoundErr, ok := err.(ErrIAMRoleNotFound)
	if !ok {
		t.Fatalf("expected ErrIAMRoleNotFound, got %T: %v", err, err)
	}
	if notFoundErr.TenantID != "tenant1" {
		t.Errorf("expected TenantID='tenant1', got %q", notFoundErr.TenantID)
	}
}

func TestMCPServiceProvider_IAMListRoles_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMListRoles(ctx, "tenant1", 10, 0)
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMListRoles_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMListRoles(ctx, "", 10, 0)
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMListRoles_DefaultValues(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listRolesResp: &iampb.ListRolesResponse{
			Roles: []*iampb.Role{
				{Id: "role1", TenantId: "tenant1", Name: "Admin"},
			},
			Total: 1,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListRoles(ctx, "tenant1", 0, -5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["limit"] != 50 {
		t.Errorf("expected limit=50 (default), got %v", resultMap["limit"])
	}
	if resultMap["offset"] != 0 {
		t.Errorf("expected offset=0 (corrected), got %v", resultMap["offset"])
	}
}

func TestMCPServiceProvider_IAMListRoles_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listRolesResp: &iampb.ListRolesResponse{
			Roles: []*iampb.Role{
				{Id: "role1", TenantId: "tenant1", Name: "Admin"},
				{Id: "role2", TenantId: "tenant1", Name: "User"},
				{Id: "role3", TenantId: "tenant1", Name: "Guest"},
			},
			Total: 3,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListRoles(ctx, "tenant1", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	roles, ok := resultMap["roles"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected []map[string]interface{} for roles, got %T", resultMap["roles"])
	}
	if len(roles) != 3 {
		t.Errorf("expected 3 roles, got %d", len(roles))
	}
	if resultMap["total"] != int32(3) {
		t.Errorf("expected total=3, got %v", resultMap["total"])
	}
}

func TestMCPServiceProvider_IAMListRoles_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listRolesErr: errors.New("database error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMListRoles(ctx, "tenant1", 10, 0)
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "ListRoles" {
		t.Errorf("expected Operation='ListRoles', got %q", opErr.Operation)
	}
}

// =============================================================================
// IAM Role Assignment Tests
// =============================================================================

func TestMCPServiceProvider_IAMAssignRole_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMAssignRole(ctx, "tenant1", "user1", "admin")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMAssignRole_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAssignRole(ctx, "", "user1", "admin")
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMAssignRole_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAssignRole(ctx, "tenant1", "", "admin")
	if err == nil {
		t.Fatal("expected error for missing user_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "user_id" {
		t.Errorf("expected parameter='user_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMAssignRole_MissingRole(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAssignRole(ctx, "tenant1", "user1", "")
	if err == nil {
		t.Fatal("expected error for missing role")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "role" {
		t.Errorf("expected parameter='role', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMAssignRole_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		assignRoleResp: &iampb.AssignRoleResponse{
			Success: true,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAssignRole(ctx, "tenant1", "user1", "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMAssignRole_Failed(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		assignRoleResp: &iampb.AssignRoleResponse{
			Success: false,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAssignRole(ctx, "tenant1", "user1", "admin")
	if err == nil {
		t.Fatal("expected error for failed assignment")
	}

	assignErr, ok := err.(ErrIAMRoleAssignmentFailed)
	if !ok {
		t.Fatalf("expected ErrIAMRoleAssignmentFailed, got %T: %v", err, err)
	}
	if assignErr.UserID != "user1" {
		t.Errorf("expected UserID='user1', got %q", assignErr.UserID)
	}
}

func TestMCPServiceProvider_IAMAssignRole_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		assignRoleErr: errors.New("database error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAssignRole(ctx, "tenant1", "user1", "admin")
	if err == nil {
		t.Fatal("expected error from service")
	}

	assignErr, ok := err.(ErrIAMRoleAssignmentFailed)
	if !ok {
		t.Fatalf("expected ErrIAMRoleAssignmentFailed, got %T: %v", err, err)
	}
	if assignErr.UserID != "user1" {
		t.Errorf("expected UserID='user1', got %q", assignErr.UserID)
	}
}

func TestMCPServiceProvider_IAMRevokeRole_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMRevokeRole(ctx, "tenant1", "user1", "admin")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMRevokeRole_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeRole(ctx, "", "user1", "admin")
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMRevokeRole_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeRole(ctx, "tenant1", "", "admin")
	if err == nil {
		t.Fatal("expected error for missing user_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "user_id" {
		t.Errorf("expected parameter='user_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMRevokeRole_MissingRole(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeRole(ctx, "tenant1", "user1", "")
	if err == nil {
		t.Fatal("expected error for missing role")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "role" {
		t.Errorf("expected parameter='role', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMRevokeRole_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		revokeRoleResp: &iampb.RevokeRoleResponse{
			Success: true,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeRole(ctx, "tenant1", "user1", "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMRevokeRole_Failed(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		revokeRoleResp: &iampb.RevokeRoleResponse{
			Success: false,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeRole(ctx, "tenant1", "user1", "admin")
	if err == nil {
		t.Fatal("expected error for failed revocation")
	}

	revokeErr, ok := err.(ErrIAMRoleRevocationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMRoleRevocationFailed, got %T: %v", err, err)
	}
	if revokeErr.UserID != "user1" {
		t.Errorf("expected UserID='user1', got %q", revokeErr.UserID)
	}
}

func TestMCPServiceProvider_IAMRevokeRole_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		revokeRoleErr: errors.New("database error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeRole(ctx, "tenant1", "user1", "admin")
	if err == nil {
		t.Fatal("expected error from service")
	}

	revokeErr, ok := err.(ErrIAMRoleRevocationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMRoleRevocationFailed, got %T: %v", err, err)
	}
	if revokeErr.UserID != "user1" {
		t.Errorf("expected UserID='user1', got %q", revokeErr.UserID)
	}
}

// =============================================================================
// IAM Check Permission Tests
// =============================================================================

func TestMCPServiceProvider_IAMCheckPermission_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMCheckPermission(ctx, "tenant1", "user1", "documents", "read")
	if err == nil {
		t.Fatal("expected error for nil PEP client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMCheckPermission_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockPEP := &mockPEPClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PEPClient: mockPEP,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCheckPermission(ctx, "", "user1", "documents", "read")
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCheckPermission_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockPEP := &mockPEPClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PEPClient: mockPEP,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCheckPermission(ctx, "tenant1", "", "documents", "read")
	if err == nil {
		t.Fatal("expected error for missing user_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "user_id" {
		t.Errorf("expected parameter='user_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCheckPermission_MissingResource(t *testing.T) {
	ctx := context.Background()
	mockPEP := &mockPEPClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PEPClient: mockPEP,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCheckPermission(ctx, "tenant1", "user1", "", "read")
	if err == nil {
		t.Fatal("expected error for missing resource")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "resource" {
		t.Errorf("expected parameter='resource', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCheckPermission_MissingAction(t *testing.T) {
	ctx := context.Background()
	mockPEP := &mockPEPClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PEPClient: mockPEP,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCheckPermission(ctx, "tenant1", "user1", "documents", "")
	if err == nil {
		t.Fatal("expected error for missing action")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "action" {
		t.Errorf("expected parameter='action', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCheckPermission_Allowed(t *testing.T) {
	ctx := context.Background()
	mockPEP := &mockPEPClientForTests{
		checkResp: &iampb.CheckResponse{
			Allowed: true,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PEPClient: mockPEP,
		Logger:    slog.Default(),
	})

	allowed, err := provider.IAMCheckPermission(ctx, "tenant1", "user1", "documents", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}
}

func TestMCPServiceProvider_IAMCheckPermission_Denied(t *testing.T) {
	ctx := context.Background()
	mockPEP := &mockPEPClientForTests{
		checkResp: &iampb.CheckResponse{
			Allowed: false,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PEPClient: mockPEP,
		Logger:    slog.Default(),
	})

	allowed, err := provider.IAMCheckPermission(ctx, "tenant1", "user1", "documents", "delete")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected allowed=false")
	}
}

func TestMCPServiceProvider_IAMCheckPermission_Error(t *testing.T) {
	ctx := context.Background()
	mockPEP := &mockPEPClientForTests{
		checkErr: errors.New("policy engine error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PEPClient: mockPEP,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCheckPermission(ctx, "tenant1", "user1", "documents", "read")
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "CheckPermission" {
		t.Errorf("expected Operation='CheckPermission', got %q", opErr.Operation)
	}
}

// =============================================================================
// IAM Authenticate Tests
// =============================================================================

func TestMCPServiceProvider_IAMAuthenticate_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMAuthenticate(ctx, &mcp.IAMAuthenticateRequest{
		TenantID: "tenant1",
		Email:    "test@example.com",
	})
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMAuthenticate_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMAuthenticate(ctx, &mcp.IAMAuthenticateRequest{
		TenantID: "",
		Email:    "test@example.com",
	})
	if err == nil {
		t.Fatal("expected error for missing tenant_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "tenant_id" {
		t.Errorf("expected parameter='tenant_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMAuthenticate_MissingEmail(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMAuthenticate(ctx, &mcp.IAMAuthenticateRequest{
		TenantID: "tenant1",
		Email:    "",
	})
	if err == nil {
		t.Fatal("expected error for missing email")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "email" {
		t.Errorf("expected parameter='email', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMAuthenticate_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listUsersResp: &iampb.ListUsersResponse{
			Users: []*iampb.User{
				{Id: "user1", TenantId: "tenant1", Email: "test@example.com"},
			},
			Total: 1,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMAuthenticate(ctx, &mcp.IAMAuthenticateRequest{
		TenantID: "tenant1",
		Email:    "test@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["authenticated"] != true {
		t.Error("expected authenticated=true")
	}
}

func TestMCPServiceProvider_IAMAuthenticate_UserNotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listUsersResp: &iampb.ListUsersResponse{
			Users: []*iampb.User{},
			Total: 0,
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMAuthenticate(ctx, &mcp.IAMAuthenticateRequest{
		TenantID: "tenant1",
		Email:    "nonexistent@example.com",
	})
	if err == nil {
		t.Fatal("expected error for user not found")
	}

	authErr, ok := err.(ErrIAMAuthenticationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMAuthenticationFailed, got %T: %v", err, err)
	}
	if authErr.Reason != "user not found" {
		t.Errorf("expected Reason='user not found', got %q", authErr.Reason)
	}
}

func TestMCPServiceProvider_IAMAuthenticate_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMClientForTests{
		listUsersErr: errors.New("database error"),
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMAuthenticate(ctx, &mcp.IAMAuthenticateRequest{
		TenantID: "tenant1",
		Email:    "test@example.com",
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	_, ok := err.(ErrIAMAuthenticationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMAuthenticationFailed, got %T: %v", err, err)
	}
}
