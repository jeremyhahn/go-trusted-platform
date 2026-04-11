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
	"testing"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// RevokeRole Additional Coverage Tests
// =============================================================================

func TestIAMGRPCService_RevokeRole_MissingTenantID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
		UserId: "user-123",
		RoleId: "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_RevokeRole_MissingUserID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_RevokeRole_MissingRoleID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_RevokeRole_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		revokeRoleFunc: func(ctx context.Context, in *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
			return nil, status.Error(codes.NotFound, "role not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
		RoleId:   "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

// =============================================================================
// RemoveGroupMember Additional Coverage Tests
// =============================================================================

func TestIAMGRPCService_RemoveGroupMember_MissingTenantID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{
		GroupId: "group-123",
		UserId:  "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_RemoveGroupMember_MissingGroupID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_RemoveGroupMember_MissingUserID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_RemoveGroupMember_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		removeUserFromGroupFunc: func(ctx context.Context, in *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
			return nil, status.Error(codes.NotFound, "group not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
		UserId:   "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

// =============================================================================
// Additional Parameter Validation Tests for Other Operations
// =============================================================================

func TestIAMGRPCService_AssignRole_MissingTenantID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
		UserId: "user-123",
		RoleId: "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_AssignRole_MissingUserID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_AssignRole_MissingRoleID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.InvalidArgument)
}

func TestIAMGRPCService_AssignRole_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		assignRoleFunc: func(ctx context.Context, in *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "role already assigned")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
		RoleId:   "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.AlreadyExists)
}

// =============================================================================
// convertGRPCError Tests
// =============================================================================

func TestIAMGRPCService_ConvertGRPCError_NonStatusError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Use a mock that returns a non-gRPC status error
	mockIAM := &mockIAMServiceClient{
		getUserFunc: func(ctx context.Context, in *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return nil, context.DeadlineExceeded // Not a gRPC status error
		},
	}

	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.GetUser(ctx, &platformv1.GetIAMUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	})

	if resp != nil {
		t.Error("expected nil response")
	}
	if err == nil {
		t.Error("expected error")
	}

	// Should be converted to Internal error
	st, ok := status.FromError(err)
	if !ok {
		t.Error("expected gRPC status error")
	}
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal code, got %v", st.Code())
	}
}

// =============================================================================
// Helper Conversion Tests
// =============================================================================

func TestIAMGRPCService_SDKUserToPlatformUser_Nil(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	result := sdkUserToPlatformUser(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestIAMGRPCService_SDKRoleToPlatformRole_Nil(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	result := sdkRoleToPlatformRole(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestIAMGRPCService_SDKGroupToPlatformGroup_Nil(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	result := sdkGroupToPlatformGroup(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestIAMGRPCService_SDKTenantToPlatformTenant_Nil(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	result := sdkTenantToPlatformTenant(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestIAMGRPCService_SDKPolicyToPlatformPolicy_Nil(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	result := sdkPolicyToPlatformPolicy(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestIAMGRPCService_SDKAppToPlatformApp_Nil(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	result := sdkAppToPlatformApp(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

// =============================================================================
// getPagination Tests
// =============================================================================

func TestIAMGRPCService_GetPagination_NilRequest(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	limit, offset := svc.getPagination(nil)

	if limit != iamDefaultPageSize {
		t.Errorf("expected default page size %d, got %d", iamDefaultPageSize, limit)
	}
	if offset != 0 {
		t.Errorf("expected offset 0, got %d", offset)
	}
}

func TestIAMGRPCService_GetPagination_ExceedsMaxPageSize(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	req := &platformv1.PaginationRequest{
		PageSize: 2000, // Exceeds iamMaxPageSize
		Page:     1,
	}
	limit, _ := svc.getPagination(req)

	if limit != iamMaxPageSize {
		t.Errorf("expected max page size %d, got %d", iamMaxPageSize, limit)
	}
}

func TestIAMGRPCService_GetPagination_ValidRequest(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	req := &platformv1.PaginationRequest{
		PageSize: 25,
		Page:     3, // Should give offset = (3-1) * 25 = 50
	}
	limit, offset := svc.getPagination(req)

	if limit != 25 {
		t.Errorf("expected limit 25, got %d", limit)
	}
	if offset != 50 {
		t.Errorf("expected offset 50, got %d", offset)
	}
}

func TestIAMGRPCService_GetPagination_ZeroPageSize(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	req := &platformv1.PaginationRequest{
		PageSize: 0,
		Page:     1,
	}
	limit, _ := svc.getPagination(req)

	if limit != iamDefaultPageSize {
		t.Errorf("expected default page size %d, got %d", iamDefaultPageSize, limit)
	}
}

func TestIAMGRPCService_GetPagination_ZeroPage(t *testing.T) {
	t.Parallel()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
	req := &platformv1.PaginationRequest{
		PageSize: 25,
		Page:     0,
	}
	_, offset := svc.getPagination(req)

	if offset != 0 {
		t.Errorf("expected offset 0, got %d", offset)
	}
}

// =============================================================================
// Backend Error Propagation Tests
// =============================================================================

func TestIAMGRPCService_CreateUser_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		createUserFunc: func(ctx context.Context, in *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
		TenantId: "tenant-1",
		Email:    "test@example.com",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.AlreadyExists)
}

func TestIAMGRPCService_ListUsers_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		listUsersFunc: func(ctx context.Context, in *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
			return nil, status.Error(codes.Unavailable, "service unavailable")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.ListUsers(ctx, &platformv1.ListIAMUsersRequest{
		TenantId: "tenant-1",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.Unavailable)
}

func TestIAMGRPCService_UpdateUser_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		updateUserFunc: func(ctx context.Context, in *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.UpdateUser(ctx, &platformv1.UpdateIAMUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
		Email:    "updated@example.com",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

func TestIAMGRPCService_DeleteUser_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		deleteUserFunc: func(ctx context.Context, in *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.PermissionDenied)
}

func TestIAMGRPCService_GetUser_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		getUserFunc: func(ctx context.Context, in *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.GetUser(ctx, &platformv1.GetIAMUserRequest{
		TenantId: "tenant-1",
		UserId:   "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

func TestIAMGRPCService_CreateRole_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		createRoleFunc: func(ctx context.Context, in *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return nil, status.Error(codes.AlreadyExists, "role already exists")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
		TenantId: "tenant-1",
		Name:     "admin",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.AlreadyExists)
}

func TestIAMGRPCService_GetRole_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		getRoleFunc: func(ctx context.Context, in *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return nil, status.Error(codes.NotFound, "role not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.GetRole(ctx, &platformv1.GetIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

func TestIAMGRPCService_ListRoles_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		listRolesFunc: func(ctx context.Context, in *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
			return nil, status.Error(codes.Unavailable, "service unavailable")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.ListRoles(ctx, &platformv1.ListIAMRolesRequest{
		TenantId: "tenant-1",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.Unavailable)
}

func TestIAMGRPCService_UpdateRole_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		updateRoleFunc: func(ctx context.Context, in *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return nil, status.Error(codes.NotFound, "role not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.UpdateRole(ctx, &platformv1.UpdateIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

func TestIAMGRPCService_DeleteRole_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		deleteRoleFunc: func(ctx context.Context, in *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{
		TenantId: "tenant-1",
		RoleId:   "role-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.PermissionDenied)
}

func TestIAMGRPCService_CreateGroup_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		createGroupFunc: func(ctx context.Context, in *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return nil, status.Error(codes.AlreadyExists, "group already exists")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.CreateGroup(ctx, &platformv1.CreateIAMGroupRequest{
		TenantId: "tenant-1",
		Name:     "developers",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.AlreadyExists)
}

func TestIAMGRPCService_GetGroup_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		getGroupFunc: func(ctx context.Context, in *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return nil, status.Error(codes.NotFound, "group not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

func TestIAMGRPCService_ListGroups_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		listGroupsFunc: func(ctx context.Context, in *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
			return nil, status.Error(codes.Unavailable, "service unavailable")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{
		TenantId: "tenant-1",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.Unavailable)
}

func TestIAMGRPCService_UpdateGroup_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		updateGroupFunc: func(ctx context.Context, in *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return nil, status.Error(codes.NotFound, "group not found")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.UpdateGroup(ctx, &platformv1.UpdateIAMGroupRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.NotFound)
}

func TestIAMGRPCService_DeleteGroup_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		deleteGroupFunc: func(ctx context.Context, in *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.PermissionDenied)
}

func TestIAMGRPCService_AddGroupMember_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockIAM := &mockIAMServiceClient{
		addUserToGroupFunc: func(ctx context.Context, in *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "user already in group")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
	resp, err := svc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{
		TenantId: "tenant-1",
		GroupId:  "group-123",
		UserId:   "user-123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.AlreadyExists)
}

func TestIAMGRPCService_CheckPermission_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mockPEP := &mockPEPServiceClient{
		checkFunc: func(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
			return nil, status.Error(codes.Unavailable, "PEP service unavailable")
		},
	}
	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, mockPEP)
	resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
		TenantId:  "tenant-1",
		SubjectId: "user-123",
		Action:    "read",
		Resource:  "resource:123",
	})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.Unavailable)
}
