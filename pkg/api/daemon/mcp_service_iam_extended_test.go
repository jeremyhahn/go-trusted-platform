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
// IAM Group Operations Tests
// =============================================================================

func TestMCPServiceProvider_IAMCreateGroup_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMCreateGroup(ctx, &mcp.IAMCreateGroupRequest{
		TenantID: "tenant1",
		Name:     "admins",
	})
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMCreateGroup_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateGroup(ctx, &mcp.IAMCreateGroupRequest{
		TenantID: "",
		Name:     "admins",
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

func TestMCPServiceProvider_IAMCreateGroup_MissingIDAndName(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateGroup(ctx, &mcp.IAMCreateGroupRequest{
		TenantID: "tenant1",
		ID:       "",
		Name:     "",
	})
	if err == nil {
		t.Fatal("expected error for missing id or name")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "id or name" {
		t.Errorf("expected parameter='id or name', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMCreateGroup_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	mockClient := &mockIAMServiceClient{
		createGroupFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateGroupRequest) (*sdkiam.Group, error) {
			return &sdkiam.Group{
				ID:          "group1",
				TenantID:    "tenant1",
				Name:        "admins",
				Description: "Administrators group",
				CreatedAt:   now,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMCreateGroup(ctx, &mcp.IAMCreateGroupRequest{
		TenantID:    "tenant1",
		ID:          "group1",
		Name:        "admins",
		Description: "Administrators group",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	groupMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if groupMap["id"] != "group1" {
		t.Errorf("expected id='group1', got %v", groupMap["id"])
	}
	if groupMap["name"] != "admins" {
		t.Errorf("expected name='admins', got %v", groupMap["name"])
	}
}

func TestMCPServiceProvider_IAMCreateGroup_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		createGroupFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateGroupRequest) (*sdkiam.Group, error) {
			return nil, errors.New("group already exists")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateGroup(ctx, &mcp.IAMCreateGroupRequest{
		TenantID: "tenant1",
		Name:     "admins",
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "CreateGroup" {
		t.Errorf("expected Operation='CreateGroup', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteGroup_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMDeleteGroup(ctx, "tenant1", "group1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMDeleteGroup_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteGroup(ctx, "", "group1")
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

func TestMCPServiceProvider_IAMDeleteGroup_MissingGroupID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteGroup(ctx, "tenant1", "")
	if err == nil {
		t.Fatal("expected error for missing group_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "group_id" {
		t.Errorf("expected parameter='group_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMDeleteGroup_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteGroupFunc: func(ctx context.Context, tenantID, groupID string) error {
			return nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteGroup(ctx, "tenant1", "group1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMDeleteGroup_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteGroupFunc: func(ctx context.Context, tenantID, groupID string) error {
			return errors.New("group not found")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteGroup(ctx, "tenant1", "nonexistent")
	if err == nil {
		t.Fatal("expected error for group not found")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteGroup" {
		t.Errorf("expected Operation='DeleteGroup', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteGroup_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteGroupFunc: func(ctx context.Context, tenantID, groupID string) error {
			return errors.New("database error")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteGroup(ctx, "tenant1", "group1")
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteGroup" {
		t.Errorf("expected Operation='DeleteGroup', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMGetGroup_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMGetGroup(ctx, "tenant1", "group1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMGetGroup_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetGroup(ctx, "", "group1")
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

func TestMCPServiceProvider_IAMGetGroup_MissingGroupID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetGroup(ctx, "tenant1", "")
	if err == nil {
		t.Fatal("expected error for missing group_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "group_id" {
		t.Errorf("expected parameter='group_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMGetGroup_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		getGroupFunc: func(ctx context.Context, tenantID, groupID string) (*sdkiam.Group, error) {
			return &sdkiam.Group{
				ID:          "group1",
				TenantID:    "tenant1",
				Name:        "admins",
				Description: "Administrators group",
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMGetGroup(ctx, "tenant1", "group1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	groupMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if groupMap["id"] != "group1" {
		t.Errorf("expected id='group1', got %v", groupMap["id"])
	}
	if groupMap["name"] != "admins" {
		t.Errorf("expected name='admins', got %v", groupMap["name"])
	}
}

func TestMCPServiceProvider_IAMGetGroup_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		getGroupFunc: func(ctx context.Context, tenantID, groupID string) (*sdkiam.Group, error) {
			return nil, errors.New("group not found")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetGroup(ctx, "tenant1", "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found group")
	}

	notFoundErr, ok := err.(ErrIAMGroupNotFound)
	if !ok {
		t.Fatalf("expected ErrIAMGroupNotFound, got %T: %v", err, err)
	}
	if notFoundErr.TenantID != "tenant1" {
		t.Errorf("expected TenantID='tenant1', got %q", notFoundErr.TenantID)
	}
}

func TestMCPServiceProvider_IAMListGroups_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMListGroups(ctx, "tenant1", 10, 0)
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMListGroups_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMListGroups(ctx, "", 10, 0)
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

func TestMCPServiceProvider_IAMListGroups_DefaultValues(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		listGroupsFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListGroupsRequest) (*sdkiam.ListGroupsResponse, error) {
			return &sdkiam.ListGroupsResponse{
				Groups: []sdkiam.Group{
					{ID: "group1", TenantID: "tenant1", Name: "admins"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 1},
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListGroups(ctx, "tenant1", 0, -5)
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

func TestMCPServiceProvider_IAMListGroups_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		listGroupsFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListGroupsRequest) (*sdkiam.ListGroupsResponse, error) {
			return &sdkiam.ListGroupsResponse{
				Groups: []sdkiam.Group{
					{ID: "group1", TenantID: "tenant1", Name: "admins"},
					{ID: "group2", TenantID: "tenant1", Name: "users"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 2},
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListGroups(ctx, "tenant1", 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	groups, ok := resultMap["groups"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected []map[string]interface{} for groups, got %T", resultMap["groups"])
	}
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
}

func TestMCPServiceProvider_IAMListGroups_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		listGroupsFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListGroupsRequest) (*sdkiam.ListGroupsResponse, error) {
			return nil, errors.New("database error")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMListGroups(ctx, "tenant1", 10, 0)
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "ListGroups" {
		t.Errorf("expected Operation='ListGroups', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMAddGroupMember_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMAddGroupMember(ctx, "tenant1", "group1", "user1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMAddGroupMember_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAddGroupMember(ctx, "", "group1", "user1")
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

func TestMCPServiceProvider_IAMAddGroupMember_MissingGroupID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAddGroupMember(ctx, "tenant1", "", "user1")
	if err == nil {
		t.Fatal("expected error for missing group_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "group_id" {
		t.Errorf("expected parameter='group_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMAddGroupMember_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAddGroupMember(ctx, "tenant1", "group1", "")
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

func TestMCPServiceProvider_IAMAddGroupMember_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		addUserToGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
			return nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAddGroupMember(ctx, "tenant1", "group1", "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMAddGroupMember_Failed(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		addUserToGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
			return errors.New("membership operation failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAddGroupMember(ctx, "tenant1", "group1", "user1")
	if err == nil {
		t.Fatal("expected error for failed operation")
	}

	memberErr, ok := err.(ErrIAMGroupMembershipFailed)
	if !ok {
		t.Fatalf("expected ErrIAMGroupMembershipFailed, got %T: %v", err, err)
	}
	if memberErr.GroupID != "group1" {
		t.Errorf("expected GroupID='group1', got %q", memberErr.GroupID)
	}
}

func TestMCPServiceProvider_IAMAddGroupMember_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		addUserToGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
			return errors.New("database error")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMAddGroupMember(ctx, "tenant1", "group1", "user1")
	if err == nil {
		t.Fatal("expected error from service")
	}

	memberErr, ok := err.(ErrIAMGroupMembershipFailed)
	if !ok {
		t.Fatalf("expected ErrIAMGroupMembershipFailed, got %T: %v", err, err)
	}
	if memberErr.GroupID != "group1" {
		t.Errorf("expected GroupID='group1', got %q", memberErr.GroupID)
	}
}

func TestMCPServiceProvider_IAMRemoveGroupMember_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMRemoveGroupMember(ctx, "tenant1", "group1", "user1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMRemoveGroupMember_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRemoveGroupMember(ctx, "", "group1", "user1")
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

func TestMCPServiceProvider_IAMRemoveGroupMember_MissingGroupID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRemoveGroupMember(ctx, "tenant1", "", "user1")
	if err == nil {
		t.Fatal("expected error for missing group_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "group_id" {
		t.Errorf("expected parameter='group_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMRemoveGroupMember_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRemoveGroupMember(ctx, "tenant1", "group1", "")
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

func TestMCPServiceProvider_IAMRemoveGroupMember_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		removeUserFromGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
			return nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRemoveGroupMember(ctx, "tenant1", "group1", "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMRemoveGroupMember_Failed(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		removeUserFromGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
			return errors.New("remove membership failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRemoveGroupMember(ctx, "tenant1", "group1", "user1")
	if err == nil {
		t.Fatal("expected error for failed operation")
	}

	memberErr, ok := err.(ErrIAMGroupMembershipFailed)
	if !ok {
		t.Fatalf("expected ErrIAMGroupMembershipFailed, got %T: %v", err, err)
	}
	if memberErr.GroupID != "group1" {
		t.Errorf("expected GroupID='group1', got %q", memberErr.GroupID)
	}
}

func TestMCPServiceProvider_IAMRemoveGroupMember_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		removeUserFromGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
			return errors.New("database error")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRemoveGroupMember(ctx, "tenant1", "group1", "user1")
	if err == nil {
		t.Fatal("expected error from service")
	}

	memberErr, ok := err.(ErrIAMGroupMembershipFailed)
	if !ok {
		t.Fatalf("expected ErrIAMGroupMembershipFailed, got %T: %v", err, err)
	}
	if memberErr.GroupID != "group1" {
		t.Errorf("expected GroupID='group1', got %q", memberErr.GroupID)
	}
}

// =============================================================================
// IAM Tenant Operations Tests
// =============================================================================

func TestMCPServiceProvider_IAMCreateTenant_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMCreateTenant(ctx, &mcp.IAMCreateTenantRequest{
		ID:   "tenant1",
		Name: "Acme Corp",
	})
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMCreateTenant_MissingID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateTenant(ctx, &mcp.IAMCreateTenantRequest{
		ID:   "",
		Name: "Acme Corp",
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

func TestMCPServiceProvider_IAMCreateTenant_Success(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	mockClient := &mockIAMServiceClient{
		createTenantFunc: func(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
			return &sdkiam.Tenant{
				ID:        "tenant1",
				Name:      "Acme Corp",
				CreatedAt: now,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMCreateTenant(ctx, &mcp.IAMCreateTenantRequest{
		ID:   "tenant1",
		Name: "Acme Corp",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tenantMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if tenantMap["id"] != "tenant1" {
		t.Errorf("expected id='tenant1', got %v", tenantMap["id"])
	}
	if tenantMap["name"] != "Acme Corp" {
		t.Errorf("expected name='Acme Corp', got %v", tenantMap["name"])
	}
}

func TestMCPServiceProvider_IAMCreateTenant_WithSettings(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	mockClient := &mockIAMServiceClient{
		createTenantFunc: func(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
			return &sdkiam.Tenant{
				ID:   "tenant1",
				Name: "Acme Corp",
				Settings: map[string]string{
					"mfa_required": "true",
					"max_users":    "100",
				},
				CreatedAt: now,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMCreateTenant(ctx, &mcp.IAMCreateTenantRequest{
		ID:   "tenant1",
		Name: "Acme Corp",
		Settings: &mcp.IAMTenantSettings{
			MaxUsers:    100,
			MFARequired: true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tenantMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if tenantMap["id"] != "tenant1" {
		t.Errorf("expected id='tenant1', got %v", tenantMap["id"])
	}
}

func TestMCPServiceProvider_IAMCreateTenant_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		createTenantFunc: func(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
			return nil, errors.New("tenant already exists")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateTenant(ctx, &mcp.IAMCreateTenantRequest{
		ID:   "tenant1",
		Name: "Acme Corp",
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "CreateTenant" {
		t.Errorf("expected Operation='CreateTenant', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteTenant_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMDeleteTenant(ctx, "tenant1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMDeleteTenant_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteTenant(ctx, "")
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

func TestMCPServiceProvider_IAMDeleteTenant_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteTenant(ctx, "tenant1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMDeleteTenant_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return errors.New("tenant not found")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteTenant(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for tenant not found")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteTenant" {
		t.Errorf("expected Operation='DeleteTenant', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMDeleteTenant_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		deleteTenantFunc: func(ctx context.Context, tenantID string) error {
			return errors.New("database error")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMDeleteTenant(ctx, "tenant1")
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteTenant" {
		t.Errorf("expected Operation='DeleteTenant', got %q", opErr.Operation)
	}
}

func TestMCPServiceProvider_IAMGetTenant_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMGetTenant(ctx, "tenant1")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMGetTenant_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetTenant(ctx, "")
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

func TestMCPServiceProvider_IAMGetTenant_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		getTenantFunc: func(ctx context.Context, tenantID string) (*sdkiam.Tenant, error) {
			return &sdkiam.Tenant{
				ID:   "tenant1",
				Name: "Acme Corp",
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMGetTenant(ctx, "tenant1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tenantMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if tenantMap["id"] != "tenant1" {
		t.Errorf("expected id='tenant1', got %v", tenantMap["id"])
	}
	if tenantMap["name"] != "Acme Corp" {
		t.Errorf("expected name='Acme Corp', got %v", tenantMap["name"])
	}
}

func TestMCPServiceProvider_IAMGetTenant_NotFound(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		getTenantFunc: func(ctx context.Context, tenantID string) (*sdkiam.Tenant, error) {
			return nil, errors.New("tenant not found")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMGetTenant(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found tenant")
	}

	notFoundErr, ok := err.(ErrIAMTenantNotFound)
	if !ok {
		t.Fatalf("expected ErrIAMTenantNotFound, got %T: %v", err, err)
	}
	if notFoundErr.TenantID != "nonexistent" {
		t.Errorf("expected TenantID='nonexistent', got %q", notFoundErr.TenantID)
	}
}

func TestMCPServiceProvider_IAMListTenants_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMListTenants(ctx, 10, 0)
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMListTenants_DefaultValues(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		listTenantsFunc: func(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
			return &sdkiam.ListTenantsResponse{
				Tenants: []sdkiam.Tenant{
					{ID: "tenant1", Name: "Acme Corp"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 1},
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListTenants(ctx, 0, -5)
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

func TestMCPServiceProvider_IAMListTenants_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		listTenantsFunc: func(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
			return &sdkiam.ListTenantsResponse{
				Tenants: []sdkiam.Tenant{
					{ID: "tenant1", Name: "Acme Corp"},
					{ID: "tenant2", Name: "Beta Inc"},
				},
				Pagination: sdkiam.PaginationInfo{TotalCount: 2},
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMListTenants(ctx, 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	tenants, ok := resultMap["tenants"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected []map[string]interface{} for tenants, got %T", resultMap["tenants"])
	}
	if len(tenants) != 2 {
		t.Errorf("expected 2 tenants, got %d", len(tenants))
	}
}

func TestMCPServiceProvider_IAMListTenants_Error(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		listTenantsFunc: func(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
			return nil, errors.New("database error")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMListTenants(ctx, 10, 0)
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrIAMOperationFailed)
	if !ok {
		t.Fatalf("expected ErrIAMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "ListTenants" {
		t.Errorf("expected Operation='ListTenants', got %q", opErr.Operation)
	}
}

// =============================================================================
// IAM Token Operations Tests
// =============================================================================

func TestMCPServiceProvider_IAMCreateToken_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMCreateToken(ctx, &mcp.IAMCreateTokenRequest{
		TenantID: "tenant1",
		UserID:   "user1",
	})
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMCreateToken_MissingTenantID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateToken(ctx, &mcp.IAMCreateTokenRequest{
		TenantID: "",
		UserID:   "user1",
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

func TestMCPServiceProvider_IAMCreateToken_MissingUserID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMCreateToken(ctx, &mcp.IAMCreateTokenRequest{
		TenantID: "tenant1",
		UserID:   "",
	})
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

func TestMCPServiceProvider_IAMCreateToken_UserNotFound(t *testing.T) {
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

	_, err := provider.IAMCreateToken(ctx, &mcp.IAMCreateTokenRequest{
		TenantID: "tenant1",
		UserID:   "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for user not found")
	}

	notFoundErr, ok := err.(ErrIAMUserNotFound)
	if !ok {
		t.Fatalf("expected ErrIAMUserNotFound, got %T: %v", err, err)
	}
	if notFoundErr.UserID != "nonexistent" {
		t.Errorf("expected UserID='nonexistent', got %q", notFoundErr.UserID)
	}
}

func TestMCPServiceProvider_IAMCreateToken_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		getUserFunc: func(ctx context.Context, tenantID, userID string) (*sdkiam.User, error) {
			return &sdkiam.User{
				ID:       "user1",
				TenantID: "tenant1",
				Email:    "test@example.com",
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMCreateToken(ctx, &mcp.IAMCreateTokenRequest{
		TenantID:    "tenant1",
		UserID:      "user1",
		Scopes:      []string{"read", "write"},
		ExpiresIn:   3600,
		Description: "Test token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tokenMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if tokenMap["tenant_id"] != "tenant1" {
		t.Errorf("expected tenant_id='tenant1', got %v", tokenMap["tenant_id"])
	}
	if tokenMap["user_id"] != "user1" {
		t.Errorf("expected user_id='user1', got %v", tokenMap["user_id"])
	}
	if tokenMap["user_email"] != "test@example.com" {
		t.Errorf("expected user_email='test@example.com', got %v", tokenMap["user_email"])
	}
	if _, ok := tokenMap["token_id"].(string); !ok {
		t.Error("expected token_id to be present")
	}
	if _, ok := tokenMap["expires_at"].(string); !ok {
		t.Error("expected expires_at to be present")
	}
}

func TestMCPServiceProvider_IAMCreateToken_DefaultExpiration(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{
		getUserFunc: func(ctx context.Context, tenantID, userID string) (*sdkiam.User, error) {
			return &sdkiam.User{
				ID:       "user1",
				TenantID: "tenant1",
				Email:    "test@example.com",
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMCreateToken(ctx, &mcp.IAMCreateTokenRequest{
		TenantID:  "tenant1",
		UserID:    "user1",
		ExpiresIn: 0, // Should default to 3600
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tokenMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	// Token should be created with default expiration
	if _, ok := tokenMap["expires_at"].(string); !ok {
		t.Error("expected expires_at to be present")
	}
}

func TestMCPServiceProvider_IAMRevokeToken_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	err := provider.IAMRevokeToken(ctx, "token123")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMRevokeToken_MissingTokenID(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeToken(ctx, "")
	if err == nil {
		t.Fatal("expected error for missing token_id")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "token_id" {
		t.Errorf("expected parameter='token_id', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMRevokeToken_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	err := provider.IAMRevokeToken(ctx, "token123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_IAMVerifyToken_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.IAMVerifyToken(ctx, "token123")
	if err == nil {
		t.Fatal("expected error for nil IAM client")
	}

	if _, ok := err.(ErrIAMServiceNotAvailable); !ok {
		t.Fatalf("expected ErrIAMServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_IAMVerifyToken_MissingToken(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	_, err := provider.IAMVerifyToken(ctx, "")
	if err == nil {
		t.Fatal("expected error for missing token")
	}

	paramErr, ok := err.(ErrIAMMissingParameter)
	if !ok {
		t.Fatalf("expected ErrIAMMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "token" {
		t.Errorf("expected parameter='token', got %q", paramErr.Parameter)
	}
}

func TestMCPServiceProvider_IAMVerifyToken_Success(t *testing.T) {
	ctx := context.Background()
	mockClient := &mockIAMServiceClient{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient: mockClient,
		Logger:    slog.Default(),
	})

	result, err := provider.IAMVerifyToken(ctx, "token123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if _, ok := resultMap["valid"].(bool); !ok {
		t.Error("expected valid to be present")
	}
}
