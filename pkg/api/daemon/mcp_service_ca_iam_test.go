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
	"time"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		createUserFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateUserRequest) (*sdkiam.User, error) {
			return &sdkiam.User{
				ID:          "user1",
				TenantID:    "tenant1",
				Email:       "test@example.com",
				DisplayName: "Test User",
			}, nil
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
	mockClient := &mockIAMServiceClient{
		createUserFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateUserRequest) (*sdkiam.User, error) {
			return nil, errors.New("user already exists")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		deleteUserFunc: func(ctx context.Context, tenantID, userID string) error {
			return nil
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
	mockClient := &mockIAMServiceClient{
		deleteUserFunc: func(ctx context.Context, tenantID, userID string) error {
			return errors.New("user not found")
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

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteUser" {
		t.Errorf("expected Operation='DeleteUser', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteUser_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteUserFunc: func(ctx context.Context, tenantID, userID string) error {
			return errors.New("database error")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		getUserFunc: func(ctx context.Context, tenantID, userID string) (*sdkiam.User, error) {
			return &sdkiam.User{
				ID:          "user1",
				TenantID:    "tenant1",
				Email:       "test@example.com",
				DisplayName: "Test User",
				Roles:       []string{"admin", "user"},
			}, nil
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
	mockClient := &mockIAMServiceClient{
		getUserFunc: func(ctx context.Context, tenantID, userID string) (*sdkiam.User, error) {
			return nil, errors.New("user not found")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		listUsersFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return &sdkiam.ListUsersResponse{
				Users: []sdkiam.User{
					{ID: "user1", TenantID: "tenant1", Email: "user1@example.com"},
					{ID: "user2", TenantID: "tenant1", Email: "user2@example.com"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 2},
			}, nil
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
	mockClient := &mockIAMServiceClient{
		listUsersFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return &sdkiam.ListUsersResponse{
				Users: []sdkiam.User{
					{ID: "user1", TenantID: "tenant1", Email: "user1@example.com"},
					{ID: "user2", TenantID: "tenant1", Email: "user2@example.com"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 2},
			}, nil
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
	mockClient := &mockIAMServiceClient{
		listUsersFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return nil, errors.New("database error")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	now := time.Now()
	mockClient := &mockIAMServiceClient{
		createRoleFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateRoleRequest) (*sdkiam.Role, error) {
			return &sdkiam.Role{
				ID:          "role1",
				TenantID:    "tenant1",
				Name:        "Admin",
				Description: "Administrator role",
				Permissions: []string{"read", "write", "admin"},
				CreatedAt:   now,
			}, nil
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
	mockClient := &mockIAMServiceClient{
		createRoleFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateRoleRequest) (*sdkiam.Role, error) {
			return nil, errors.New("role already exists")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		deleteRoleFunc: func(ctx context.Context, tenantID, roleID string) error {
			return nil
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
	mockClient := &mockIAMServiceClient{
		deleteRoleFunc: func(ctx context.Context, tenantID, roleID string) error {
			return errors.New("role not found")
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

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteRole" {
		t.Errorf("expected Operation='DeleteRole', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteRole_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteRoleFunc: func(ctx context.Context, tenantID, roleID string) error {
			return errors.New("database error")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		getRoleFunc: func(ctx context.Context, tenantID, roleID string) (*sdkiam.Role, error) {
			return &sdkiam.Role{
				ID:          "role1",
				TenantID:    "tenant1",
				Name:        "Admin",
				Description: "Administrator role",
				Permissions: []string{"read", "write"},
			}, nil
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
	mockClient := &mockIAMServiceClient{
		getRoleFunc: func(ctx context.Context, tenantID, roleID string) (*sdkiam.Role, error) {
			return nil, errors.New("role not found")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		listRolesFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListRolesRequest) (*sdkiam.ListRolesResponse, error) {
			return &sdkiam.ListRolesResponse{
				Roles: []sdkiam.Role{
					{ID: "role1", TenantID: "tenant1", Name: "Admin"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 1},
			}, nil
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
	mockClient := &mockIAMServiceClient{
		listRolesFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListRolesRequest) (*sdkiam.ListRolesResponse, error) {
			return &sdkiam.ListRolesResponse{
				Roles: []sdkiam.Role{
					{ID: "role1", TenantID: "tenant1", Name: "Admin"},
					{ID: "role2", TenantID: "tenant1", Name: "User"},
					{ID: "role3", TenantID: "tenant1", Name: "Guest"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 3},
			}, nil
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
	if resultMap["total"] != int(3) {
		t.Errorf("expected total=3, got %v", resultMap["total"])
	}
}

func TestMCPServiceProvider_IAMListRoles_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		listRolesFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListRolesRequest) (*sdkiam.ListRolesResponse, error) {
			return nil, errors.New("database error")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		assignRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
			return nil
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
	mockClient := &mockIAMServiceClient{
		assignRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
			return errors.New("assignment failed")
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
	mockClient := &mockIAMServiceClient{
		assignRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
			return errors.New("database error")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		revokeRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
			return nil
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
	mockClient := &mockIAMServiceClient{
		revokeRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
			return errors.New("revocation failed")
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
	mockClient := &mockIAMServiceClient{
		revokeRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
			return errors.New("database error")
		},
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
	mockPEP := &mockPEPServiceClient{}
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
	mockPEP := &mockPEPServiceClient{}
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
	mockPEP := &mockPEPServiceClient{}
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
	mockPEP := &mockPEPServiceClient{}
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
	mockPEP := &mockPEPServiceClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{Allowed: true}, nil
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
	mockPEP := &mockPEPServiceClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{Allowed: false}, nil
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
	mockPEP := &mockPEPServiceClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return nil, errors.New("policy engine error")
		},
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{}
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
	mockClient := &mockIAMServiceClient{
		listUsersFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return &sdkiam.ListUsersResponse{
				Users: []sdkiam.User{
					{ID: "user1", TenantID: "tenant1", Email: "test@example.com"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 1},
			}, nil
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
	mockClient := &mockIAMServiceClient{
		listUsersFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return &sdkiam.ListUsersResponse{
				Users:      []sdkiam.User{},
				Pagination: sdkiam.PaginationInfo{TotalCount: 0},
			}, nil
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
	mockClient := &mockIAMServiceClient{
		listUsersFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
			return nil, errors.New("database error")
		},
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
