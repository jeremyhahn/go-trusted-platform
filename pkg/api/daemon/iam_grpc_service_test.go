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
	"log/slog"
	"os"
	"testing"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Mock IAMServiceClient
// =============================================================================

type mockIAMServiceClient struct {
	// User operations
	createUserFunc func(ctx context.Context, in *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error)
	getUserFunc    func(ctx context.Context, in *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error)
	updateUserFunc func(ctx context.Context, in *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error)
	deleteUserFunc func(ctx context.Context, in *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error)
	listUsersFunc  func(ctx context.Context, in *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error)

	// Role operations
	createRoleFunc func(ctx context.Context, in *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error)
	getRoleFunc    func(ctx context.Context, in *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error)
	updateRoleFunc func(ctx context.Context, in *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error)
	deleteRoleFunc func(ctx context.Context, in *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error)
	listRolesFunc  func(ctx context.Context, in *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error)
	assignRoleFunc func(ctx context.Context, in *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error)
	revokeRoleFunc func(ctx context.Context, in *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error)

	// Group operations
	createGroupFunc         func(ctx context.Context, in *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error)
	getGroupFunc            func(ctx context.Context, in *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error)
	updateGroupFunc         func(ctx context.Context, in *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error)
	deleteGroupFunc         func(ctx context.Context, in *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error)
	listGroupsFunc          func(ctx context.Context, in *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error)
	addUserToGroupFunc      func(ctx context.Context, in *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error)
	removeUserFromGroupFunc func(ctx context.Context, in *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error)

	// Tenant operations
	createTenantFunc func(ctx context.Context, in *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error)
	getTenantFunc    func(ctx context.Context, in *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error)
	updateTenantFunc func(ctx context.Context, in *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error)
	deleteTenantFunc func(ctx context.Context, in *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error)
	listTenantsFunc  func(ctx context.Context, in *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error)

	// Policy operations
	createPolicyFunc   func(ctx context.Context, in *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error)
	getPolicyFunc      func(ctx context.Context, in *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error)
	updatePolicyFunc   func(ctx context.Context, in *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error)
	deletePolicyFunc   func(ctx context.Context, in *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error)
	listPoliciesFunc   func(ctx context.Context, in *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error)
	validatePolicyFunc func(ctx context.Context, in *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error)
	testPolicyFunc     func(ctx context.Context, in *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error)

	// App operations
	registerAppFunc     func(ctx context.Context, in *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error)
	getAppFunc          func(ctx context.Context, in *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error)
	updateAppFunc       func(ctx context.Context, in *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error)
	deleteAppFunc       func(ctx context.Context, in *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error)
	listAppsFunc        func(ctx context.Context, in *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error)
	rotateAppSecretFunc func(ctx context.Context, in *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error)
}

func (m *mockIAMServiceClient) CreateUser(ctx context.Context, in *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetUser(ctx context.Context, in *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.getUserFunc != nil {
		return m.getUserFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) UpdateUser(ctx context.Context, in *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.updateUserFunc != nil {
		return m.updateUserFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) DeleteUser(ctx context.Context, in *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
	if m.deleteUserFunc != nil {
		return m.deleteUserFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListUsers(ctx context.Context, in *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
	if m.listUsersFunc != nil {
		return m.listUsersFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) CreateRole(ctx context.Context, in *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.createRoleFunc != nil {
		return m.createRoleFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetRole(ctx context.Context, in *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.getRoleFunc != nil {
		return m.getRoleFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) UpdateRole(ctx context.Context, in *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.updateRoleFunc != nil {
		return m.updateRoleFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) DeleteRole(ctx context.Context, in *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
	if m.deleteRoleFunc != nil {
		return m.deleteRoleFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListRoles(ctx context.Context, in *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
	if m.listRolesFunc != nil {
		return m.listRolesFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) AssignRole(ctx context.Context, in *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
	if m.assignRoleFunc != nil {
		return m.assignRoleFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) RevokeRole(ctx context.Context, in *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
	if m.revokeRoleFunc != nil {
		return m.revokeRoleFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) CreateGroup(ctx context.Context, in *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.createGroupFunc != nil {
		return m.createGroupFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetGroup(ctx context.Context, in *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.getGroupFunc != nil {
		return m.getGroupFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) UpdateGroup(ctx context.Context, in *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.updateGroupFunc != nil {
		return m.updateGroupFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) DeleteGroup(ctx context.Context, in *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
	if m.deleteGroupFunc != nil {
		return m.deleteGroupFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListGroups(ctx context.Context, in *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
	if m.listGroupsFunc != nil {
		return m.listGroupsFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) AddUserToGroup(ctx context.Context, in *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
	if m.addUserToGroupFunc != nil {
		return m.addUserToGroupFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) RemoveUserFromGroup(ctx context.Context, in *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
	if m.removeUserFromGroupFunc != nil {
		return m.removeUserFromGroupFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) CreateTenant(ctx context.Context, in *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.createTenantFunc != nil {
		return m.createTenantFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetTenant(ctx context.Context, in *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.getTenantFunc != nil {
		return m.getTenantFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) UpdateTenant(ctx context.Context, in *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.updateTenantFunc != nil {
		return m.updateTenantFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) DeleteTenant(ctx context.Context, in *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error) {
	if m.deleteTenantFunc != nil {
		return m.deleteTenantFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListTenants(ctx context.Context, in *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
	if m.listTenantsFunc != nil {
		return m.listTenantsFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) CreatePolicy(ctx context.Context, in *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	if m.createPolicyFunc != nil {
		return m.createPolicyFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetPolicy(ctx context.Context, in *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	if m.getPolicyFunc != nil {
		return m.getPolicyFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) UpdatePolicy(ctx context.Context, in *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	if m.updatePolicyFunc != nil {
		return m.updatePolicyFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) DeletePolicy(ctx context.Context, in *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error) {
	if m.deletePolicyFunc != nil {
		return m.deletePolicyFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListPolicies(ctx context.Context, in *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error) {
	if m.listPoliciesFunc != nil {
		return m.listPoliciesFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ValidatePolicy(ctx context.Context, in *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
	if m.validatePolicyFunc != nil {
		return m.validatePolicyFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) TestPolicy(ctx context.Context, in *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error) {
	if m.testPolicyFunc != nil {
		return m.testPolicyFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) RegisterApp(ctx context.Context, in *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.registerAppFunc != nil {
		return m.registerAppFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetApp(ctx context.Context, in *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.getAppFunc != nil {
		return m.getAppFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) UpdateApp(ctx context.Context, in *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.updateAppFunc != nil {
		return m.updateAppFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) DeleteApp(ctx context.Context, in *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error) {
	if m.deleteAppFunc != nil {
		return m.deleteAppFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListApps(ctx context.Context, in *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error) {
	if m.listAppsFunc != nil {
		return m.listAppsFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) RotateAppSecret(ctx context.Context, in *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.rotateAppSecretFunc != nil {
		return m.rotateAppSecretFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// Stub methods for additional IAMServiceClient interface methods
func (m *mockIAMServiceClient) CreateAdminAssignment(ctx context.Context, in *iampb.CreateAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.AdminAssignment, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetAdminAssignment(ctx context.Context, in *iampb.GetAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.AdminAssignment, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) UpdateAdminAssignment(ctx context.Context, in *iampb.UpdateAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.AdminAssignment, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) DeleteAdminAssignment(ctx context.Context, in *iampb.DeleteAdminAssignmentRequest, opts ...grpc.CallOption) (*iampb.DeleteAdminAssignmentResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListAdminAssignments(ctx context.Context, in *iampb.ListAdminAssignmentsRequest, opts ...grpc.CallOption) (*iampb.AdminAssignmentList, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) CheckAdminPermission(ctx context.Context, in *iampb.CheckAdminPermissionRequest, opts ...grpc.CallOption) (*iampb.CheckAdminPermissionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) StartImpersonation(ctx context.Context, in *iampb.StartImpersonationRequest, opts ...grpc.CallOption) (*iampb.ImpersonationSession, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) EndImpersonation(ctx context.Context, in *iampb.EndImpersonationRequest, opts ...grpc.CallOption) (*iampb.EndImpersonationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetActiveImpersonations(ctx context.Context, in *iampb.GetActiveImpersonationsRequest, opts ...grpc.CallOption) (*iampb.ImpersonationSessionList, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GrantConsent(ctx context.Context, in *iampb.GrantConsentRequest, opts ...grpc.CallOption) (*iampb.Consent, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) WithdrawConsent(ctx context.Context, in *iampb.WithdrawConsentRequest, opts ...grpc.CallOption) (*iampb.WithdrawConsentResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetConsent(ctx context.Context, in *iampb.GetConsentRequest, opts ...grpc.CallOption) (*iampb.Consent, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ListUserConsents(ctx context.Context, in *iampb.ListUserConsentsRequest, opts ...grpc.CallOption) (*iampb.ConsentList, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) RequestExport(ctx context.Context, in *iampb.RequestExportRequest, opts ...grpc.CallOption) (*iampb.DataExportRequest, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetExportStatus(ctx context.Context, in *iampb.GetExportStatusRequest, opts ...grpc.CallOption) (*iampb.DataExportRequest, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GenerateExport(ctx context.Context, in *iampb.GenerateExportRequest, opts ...grpc.CallOption) (*iampb.UserDataExport, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) RequestDeletion(ctx context.Context, in *iampb.RequestDeletionRequest, opts ...grpc.CallOption) (*iampb.DataDeletionRequest, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) CancelDeletion(ctx context.Context, in *iampb.CancelDeletionRequest, opts ...grpc.CallOption) (*iampb.CancelDeletionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) ProcessDeletion(ctx context.Context, in *iampb.ProcessDeletionRequest, opts ...grpc.CallOption) (*iampb.DeletionSummary, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMServiceClient) GetDeletionStatus(ctx context.Context, in *iampb.GetDeletionStatusRequest, opts ...grpc.CallOption) (*iampb.DataDeletionRequest, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// =============================================================================
// Mock PEPServiceClient
// =============================================================================

type mockPEPServiceClient struct {
	checkFunc func(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error)
}

func (m *mockPEPServiceClient) Check(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
	if m.checkFunc != nil {
		return m.checkFunc(ctx, in, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockPEPServiceClient) CheckBatch(ctx context.Context, in *iampb.CheckBatchRequest, opts ...grpc.CallOption) (*iampb.CheckBatchResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockPEPServiceClient) Subscribe(ctx context.Context, in *iampb.SubscribeRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[iampb.PolicyUpdate], error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func iamTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func assertIAMGRPCError(t *testing.T, err error, expectedCode codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != expectedCode {
		t.Errorf("expected code %v, got %v: %s", expectedCode, st.Code(), st.Message())
	}
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewIAMGRPCService(t *testing.T) {
	t.Parallel()

	t.Run("creates service with nil clients", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})

	t.Run("creates service with mock clients", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{}
		mockPEP := &mockPEPServiceClient{}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, mockPEP)
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})
}

// =============================================================================
// User Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
			TenantId: "tenant-1",
			Email:    "user@example.com",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
			Email: "user@example.com",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing email returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			createUserFunc: func(ctx context.Context, in *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
				return &iampb.User{
					Id:       "user-123",
					TenantId: in.TenantId,
					Email:    in.Email,
					Name:     in.Name,
					Roles:    in.Roles,
					Groups:   in.Groups,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
			TenantId: "tenant-1",
			Email:    "user@example.com",
			Name:     "Test User",
			Roles:    []string{"admin"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.User == nil {
			t.Fatal("expected non-nil response with user")
		}
		if resp.User.Id != "user-123" {
			t.Errorf("expected user ID 'user-123', got %q", resp.User.Id)
		}
		if resp.User.Email != "user@example.com" {
			t.Errorf("expected email 'user@example.com', got %q", resp.User.Email)
		}
	})

	t.Run("upstream error is propagated", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			createUserFunc: func(ctx context.Context, in *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
				return nil, status.Error(codes.AlreadyExists, "user already exists")
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
			TenantId: "tenant-1",
			Email:    "user@example.com",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.AlreadyExists)
	})
}

func TestIAMGRPCService_GetUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.GetUser(ctx, &platformv1.GetIAMUserRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetUser(ctx, &platformv1.GetIAMUserRequest{
			UserId: "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing user_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetUser(ctx, &platformv1.GetIAMUserRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			getUserFunc: func(ctx context.Context, in *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
				return &iampb.User{
					Id:       in.UserId,
					TenantId: in.TenantId,
					Email:    "user@example.com",
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.GetUser(ctx, &platformv1.GetIAMUserRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.User == nil {
			t.Fatal("expected non-nil response with user")
		}
		if resp.User.Id != "user-123" {
			t.Errorf("expected user ID 'user-123', got %q", resp.User.Id)
		}
	})
}

func TestIAMGRPCService_ListUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.ListUsers(ctx, &platformv1.ListIAMUsersRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.ListUsers(ctx, &platformv1.ListIAMUsersRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success with pagination", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			listUsersFunc: func(ctx context.Context, in *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
				return &iampb.ListUsersResponse{
					Users: []*iampb.User{
						{Id: "user-1", TenantId: in.TenantId, Email: "user1@example.com"},
						{Id: "user-2", TenantId: in.TenantId, Email: "user2@example.com"},
					},
					Total: 2,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ListUsers(ctx, &platformv1.ListIAMUsersRequest{
			TenantId: "tenant-1",
			Pagination: &platformv1.PaginationRequest{
				Page:     1,
				PageSize: 10,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Users) != 2 {
			t.Errorf("expected 2 users, got %d", len(resp.Users))
		}
		if resp.Total != 2 {
			t.Errorf("expected total 2, got %d", resp.Total)
		}
	})
}

func TestIAMGRPCService_UpdateUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.UpdateUser(ctx, &platformv1.UpdateIAMUserRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateUser(ctx, &platformv1.UpdateIAMUserRequest{
			UserId: "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing user_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateUser(ctx, &platformv1.UpdateIAMUserRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			updateUserFunc: func(ctx context.Context, in *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
				return &iampb.User{
					Id:       in.UserId,
					TenantId: in.TenantId,
					Email:    in.Email,
					Name:     in.Name,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.UpdateUser(ctx, &platformv1.UpdateIAMUserRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
			Name:     "Updated Name",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.User == nil {
			t.Fatal("expected non-nil response with user")
		}
	})
}

func TestIAMGRPCService_DeleteUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{
			UserId: "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing user_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			deleteUserFunc: func(ctx context.Context, in *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
				return &iampb.DeleteUserResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.DeleteUser(ctx, &platformv1.DeleteIAMUserRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}

// =============================================================================
// Role Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
			TenantId: "tenant-1",
			Name:     "admin",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
			Name: "admin",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing id and name returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			createRoleFunc: func(ctx context.Context, in *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
				return &iampb.Role{
					Id:          "role-123",
					TenantId:    in.TenantId,
					Name:        in.Name,
					Description: in.Description,
					Permissions: in.Permissions,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.CreateRole(ctx, &platformv1.CreateIAMRoleRequest{
			TenantId:    "tenant-1",
			Name:        "admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Role == nil {
			t.Fatal("expected non-nil response with role")
		}
		if resp.Role.Name != "admin" {
			t.Errorf("expected role name 'admin', got %q", resp.Role.Name)
		}
	})
}

func TestIAMGRPCService_GetRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.GetRole(ctx, &platformv1.GetIAMRoleRequest{
			TenantId: "tenant-1",
			RoleId:   "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetRole(ctx, &platformv1.GetIAMRoleRequest{
			RoleId: "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing role_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetRole(ctx, &platformv1.GetIAMRoleRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			getRoleFunc: func(ctx context.Context, in *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
				return &iampb.Role{
					Id:       in.RoleId,
					TenantId: in.TenantId,
					Name:     "admin",
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.GetRole(ctx, &platformv1.GetIAMRoleRequest{
			TenantId: "tenant-1",
			RoleId:   "role-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Role == nil {
			t.Fatal("expected non-nil response with role")
		}
	})
}

func TestIAMGRPCService_AssignRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
			RoleId:   "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
			UserId: "user-123",
			RoleId: "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing user_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
			TenantId: "tenant-1",
			RoleId:   "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing role_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			assignRoleFunc: func(ctx context.Context, in *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
				return &iampb.AssignRoleResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.AssignRole(ctx, &platformv1.AssignIAMRoleRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
			RoleId:   "role-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}

func TestIAMGRPCService_RevokeRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
			RoleId:   "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			revokeRoleFunc: func(ctx context.Context, in *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
				return &iampb.RevokeRoleResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.RevokeRole(ctx, &platformv1.RevokeIAMRoleRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
			RoleId:   "role-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
	})
}

// =============================================================================
// Group Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.CreateGroup(ctx, &platformv1.CreateIAMGroupRequest{
			TenantId: "tenant-1",
			Name:     "developers",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreateGroup(ctx, &platformv1.CreateIAMGroupRequest{
			Name: "developers",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing id and name returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreateGroup(ctx, &platformv1.CreateIAMGroupRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			createGroupFunc: func(ctx context.Context, in *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
				return &iampb.Group{
					Id:          "group-123",
					TenantId:    in.TenantId,
					Name:        in.Name,
					Description: in.Description,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.CreateGroup(ctx, &platformv1.CreateIAMGroupRequest{
			TenantId:    "tenant-1",
			Name:        "developers",
			Description: "Development team",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Group == nil {
			t.Fatal("expected non-nil response with group")
		}
		if resp.Group.Name != "developers" {
			t.Errorf("expected group name 'developers', got %q", resp.Group.Name)
		}
	})
}

func TestIAMGRPCService_AddGroupMember(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
			UserId:   "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{
			GroupId: "group-123",
			UserId:  "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing group_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{
			TenantId: "tenant-1",
			UserId:   "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing user_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			addUserToGroupFunc: func(ctx context.Context, in *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
				return &iampb.AddUserToGroupResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.AddGroupMember(ctx, &platformv1.AddGroupMemberRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
			UserId:   "user-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}

func TestIAMGRPCService_RemoveGroupMember(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
			UserId:   "user-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			removeUserFromGroupFunc: func(ctx context.Context, in *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
				return &iampb.RemoveUserFromGroupResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.RemoveGroupMember(ctx, &platformv1.RemoveGroupMemberRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
			UserId:   "user-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
	})
}

// =============================================================================
// Token Operation Tests (Unimplemented Methods - Token management via OIDC)
// =============================================================================

func TestIAMGRPCService_CreateToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, &mockPEPServiceClient{})
	resp, err := svc.CreateToken(ctx, &platformv1.CreateIAMTokenRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.Unimplemented)
}

func TestIAMGRPCService_RevokeToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, &mockPEPServiceClient{})
	resp, err := svc.RevokeToken(ctx, &platformv1.RevokeIAMTokenRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.Unimplemented)
}

func TestIAMGRPCService_VerifyToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, &mockPEPServiceClient{})
	resp, err := svc.VerifyToken(ctx, &platformv1.VerifyIAMTokenRequest{})
	if resp != nil {
		t.Error("expected nil response")
	}
	assertIAMGRPCError(t, err, codes.Unimplemented)
}

func TestIAMGRPCService_CheckPermission(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			TenantId:  "tenant-1",
			SubjectId: "user-123",
			Action:    "read",
			Resource:  "resource:123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, &mockPEPServiceClient{})
		resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			SubjectId: "user-123",
			Action:    "read",
			Resource:  "resource:123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing subject_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, &mockPEPServiceClient{})
		resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			TenantId: "tenant-1",
			Action:   "read",
			Resource: "resource:123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing action returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, &mockPEPServiceClient{})
		resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			TenantId:  "tenant-1",
			SubjectId: "user-123",
			Resource:  "resource:123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing resource returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, &mockPEPServiceClient{})
		resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			TenantId:  "tenant-1",
			SubjectId: "user-123",
			Action:    "read",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success - allowed", func(t *testing.T) {
		mockPEP := &mockPEPServiceClient{
			checkFunc: func(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
				return &iampb.CheckResponse{
					Allowed:          true,
					MatchedPolicy:    "policy-1",
					MatchedRule:      "rule-1",
					EvaluationTimeNs: 1000,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, mockPEP)
		resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			TenantId:  "tenant-1",
			SubjectId: "user-123",
			Action:    "read",
			Resource:  "resource:123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if !resp.Allowed {
			t.Error("expected allowed to be true")
		}
		if resp.MatchedPolicy != "policy-1" {
			t.Errorf("expected matched policy 'policy-1', got %q", resp.MatchedPolicy)
		}
	})

	t.Run("success - denied", func(t *testing.T) {
		mockPEP := &mockPEPServiceClient{
			checkFunc: func(ctx context.Context, in *iampb.CheckRequest, opts ...grpc.CallOption) (*iampb.CheckResponse, error) {
				return &iampb.CheckResponse{
					Allowed: false,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, mockPEP)
		resp, err := svc.CheckPermission(ctx, &platformv1.CheckIAMPermissionRequest{
			TenantId:  "tenant-1",
			SubjectId: "user-123",
			Action:    "delete",
			Resource:  "resource:123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Allowed {
			t.Error("expected allowed to be false")
		}
	})
}

// =============================================================================
// Tenant Operation Tests
// =============================================================================

func TestIAMGRPCService_CreateTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{
			Id:   "tenant-1",
			Name: "Test Tenant",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{
			Name: "Test Tenant",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			createTenantFunc: func(ctx context.Context, in *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
				return &iampb.Tenant{
					Id:   in.Id,
					Name: in.Name,
					Settings: &iampb.TenantSettings{
						MaxUsers:    100,
						MfaRequired: true,
					},
					CreatedAt: timestamppb.Now(),
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{
			Id:   "tenant-1",
			Name: "Test Tenant",
			Settings: &platformv1.IAMTenantSettings{
				MaxUsers:    100,
				MfaRequired: true,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Tenant == nil {
			t.Fatal("expected non-nil response with tenant")
		}
		if resp.Tenant.Id != "tenant-1" {
			t.Errorf("expected tenant ID 'tenant-1', got %q", resp.Tenant.Id)
		}
	})
}

func TestIAMGRPCService_GetTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.GetTenant(ctx, &platformv1.GetIAMTenantRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetTenant(ctx, &platformv1.GetIAMTenantRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			getTenantFunc: func(ctx context.Context, in *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
				return &iampb.Tenant{
					Id:   in.Id,
					Name: "Test Tenant",
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.GetTenant(ctx, &platformv1.GetIAMTenantRequest{
			TenantId: "tenant-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Tenant == nil {
			t.Fatal("expected non-nil response with tenant")
		}
	})
}

func TestIAMGRPCService_ListTenants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			listTenantsFunc: func(ctx context.Context, in *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
				return &iampb.ListTenantsResponse{
					Tenants: []*iampb.Tenant{
						{Id: "tenant-1", Name: "Tenant 1"},
						{Id: "tenant-2", Name: "Tenant 2"},
					},
					Total: 2,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ListTenants(ctx, &platformv1.ListIAMTenantsRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Tenants) != 2 {
			t.Errorf("expected 2 tenants, got %d", len(resp.Tenants))
		}
	})
}

// =============================================================================
// Policy Operation Tests
// =============================================================================

func TestIAMGRPCService_CreatePolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
			TenantId: "tenant-1",
			Name:     "test-policy",
			SpecYaml: []byte("rules: []"),
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
			Name:     "test-policy",
			SpecYaml: []byte("rules: []"),
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing name returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
			TenantId: "tenant-1",
			SpecYaml: []byte("rules: []"),
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing spec_yaml returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
			TenantId: "tenant-1",
			Name:     "test-policy",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			createPolicyFunc: func(ctx context.Context, in *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
				return &iampb.Policy{
					Name:        in.Name,
					TenantId:    in.TenantId,
					Description: in.Description,
					Priority:    in.Priority,
					SpecYaml:    in.SpecYaml,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
			TenantId:    "tenant-1",
			Name:        "test-policy",
			Description: "Test policy",
			SpecYaml:    []byte("rules: []"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Policy == nil {
			t.Fatal("expected non-nil response with policy")
		}
		if resp.Policy.Name != "test-policy" {
			t.Errorf("expected policy name 'test-policy', got %q", resp.Policy.Name)
		}
	})
}

func TestIAMGRPCService_ValidatePolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
			TenantId: "tenant-1",
			SpecYaml: []byte("rules: []"),
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
			SpecYaml: []byte("rules: []"),
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing spec_yaml returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success - valid", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			validatePolicyFunc: func(ctx context.Context, in *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
				return &iampb.ValidatePolicyResponse{
					Valid:  true,
					Errors: nil,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
			TenantId: "tenant-1",
			SpecYaml: []byte("rules: []"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if !resp.Valid {
			t.Error("expected valid to be true")
		}
	})

	t.Run("success - invalid", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			validatePolicyFunc: func(ctx context.Context, in *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
				return &iampb.ValidatePolicyResponse{
					Valid:  false,
					Errors: []string{"invalid syntax", "missing required field"},
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
			TenantId: "tenant-1",
			SpecYaml: []byte("invalid"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Valid {
			t.Error("expected valid to be false")
		}
		if len(resp.Errors) != 2 {
			t.Errorf("expected 2 errors, got %d", len(resp.Errors))
		}
	})
}

func TestIAMGRPCService_TestPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.TestPolicy(ctx, &platformv1.TestIAMPolicyRequest{
			TenantId:  "tenant-1",
			SubjectId: "user-123",
			Action:    "read",
			Resource:  "resource:123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.TestPolicy(ctx, &platformv1.TestIAMPolicyRequest{
			SubjectId: "user-123",
			Action:    "read",
			Resource:  "resource:123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing subject_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.TestPolicy(ctx, &platformv1.TestIAMPolicyRequest{
			TenantId: "tenant-1",
			Action:   "read",
			Resource: "resource:123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			testPolicyFunc: func(ctx context.Context, in *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error) {
				return &iampb.TestPolicyResponse{
					Allowed:          true,
					MatchedPolicy:    "test-policy",
					MatchedRule:      "rule-1",
					EvaluationTimeNs: 500,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.TestPolicy(ctx, &platformv1.TestIAMPolicyRequest{
			TenantId:  "tenant-1",
			SubjectId: "user-123",
			Action:    "read",
			Resource:  "resource:123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if !resp.Allowed {
			t.Error("expected allowed to be true")
		}
	})
}

// =============================================================================
// App Operation Tests
// =============================================================================

func TestIAMGRPCService_RegisterApp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{
			TenantId: "tenant-1",
			Name:     "test-app",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{
			Name: "test-app",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing name returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			registerAppFunc: func(ctx context.Context, in *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
				return &iampb.Application{
					ClientId:     "client-123",
					ClientSecret: "secret-456",
					TenantId:     in.TenantId,
					Name:         in.Name,
					RedirectUris: in.RedirectUris,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{
			TenantId:     "tenant-1",
			Name:         "test-app",
			RedirectUris: []string{"https://example.com/callback"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.App == nil {
			t.Fatal("expected non-nil response with app")
		}
		if resp.App.ClientId != "client-123" {
			t.Errorf("expected client ID 'client-123', got %q", resp.App.ClientId)
		}
	})
}

func TestIAMGRPCService_RotateAppSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{
			TenantId: "tenant-1",
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing client_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			rotateAppSecretFunc: func(ctx context.Context, in *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
				return &iampb.Application{
					ClientId:     in.ClientId,
					ClientSecret: "new-secret-789",
					Name:         "test-app",
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{
			TenantId: "tenant-1",
			ClientId: "client-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.ClientSecret != "new-secret-789" {
			t.Errorf("expected client secret 'new-secret-789', got %q", resp.ClientSecret)
		}
	})
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestIAMGRPCService_GetPagination(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{}

	t.Run("nil pagination returns defaults", func(t *testing.T) {
		limit, offset := svc.getPagination(nil)
		if limit != iamDefaultPageSize {
			t.Errorf("expected default limit %d, got %d", iamDefaultPageSize, limit)
		}
		if offset != 0 {
			t.Errorf("expected offset 0, got %d", offset)
		}
	})

	t.Run("custom page size", func(t *testing.T) {
		limit, offset := svc.getPagination(&platformv1.PaginationRequest{
			PageSize: 25,
			Page:     1,
		})
		if limit != 25 {
			t.Errorf("expected limit 25, got %d", limit)
		}
		if offset != 0 {
			t.Errorf("expected offset 0, got %d", offset)
		}
	})

	t.Run("page 2 calculates correct offset", func(t *testing.T) {
		limit, offset := svc.getPagination(&platformv1.PaginationRequest{
			PageSize: 10,
			Page:     2,
		})
		if limit != 10 {
			t.Errorf("expected limit 10, got %d", limit)
		}
		if offset != 10 {
			t.Errorf("expected offset 10, got %d", offset)
		}
	})

	t.Run("page size exceeds max is capped", func(t *testing.T) {
		limit, offset := svc.getPagination(&platformv1.PaginationRequest{
			PageSize: 5000,
			Page:     1,
		})
		if limit != iamMaxPageSize {
			t.Errorf("expected limit %d (max), got %d", iamMaxPageSize, limit)
		}
		if offset != 0 {
			t.Errorf("expected offset 0, got %d", offset)
		}
	})
}

func TestIAMGRPCService_ConvertGRPCError(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{logger: iamTestLogger()}

	t.Run("preserves gRPC status error", func(t *testing.T) {
		originalErr := status.Error(codes.NotFound, "not found")
		convertedErr := svc.convertGRPCError(originalErr)
		st, ok := status.FromError(convertedErr)
		if !ok {
			t.Fatal("expected gRPC status error")
		}
		if st.Code() != codes.NotFound {
			t.Errorf("expected NotFound, got %v", st.Code())
		}
	})

	t.Run("converts non-gRPC error to Internal", func(t *testing.T) {
		originalErr := context.DeadlineExceeded
		convertedErr := svc.convertGRPCError(originalErr)
		st, ok := status.FromError(convertedErr)
		if !ok {
			t.Fatal("expected gRPC status error")
		}
		if st.Code() != codes.Internal {
			t.Errorf("expected Internal, got %v", st.Code())
		}
	})
}

// =============================================================================
// Type Conversion Tests
// =============================================================================

func TestIAMGRPCService_DragonUserToPlatformUser(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{}

	t.Run("nil user returns nil", func(t *testing.T) {
		result := svc.dragonUserToPlatformUser(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		now := timestamppb.Now()
		dragonUser := &iampb.User{
			Id:          "user-123",
			TenantId:    "tenant-1",
			Email:       "user@example.com",
			Name:        "Test User",
			Roles:       []string{"admin", "user"},
			Groups:      []string{"dev", "ops"},
			Attributes:  map[string]string{"dept": "engineering"},
			MfaVerified: true,
			CreatedAt:   now,
			UpdatedAt:   now,
			LastAuth:    now,
		}

		result := svc.dragonUserToPlatformUser(dragonUser)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Id != "user-123" {
			t.Errorf("expected ID 'user-123', got %q", result.Id)
		}
		if result.Email != "user@example.com" {
			t.Errorf("expected email 'user@example.com', got %q", result.Email)
		}
		if !result.MfaVerified {
			t.Error("expected MfaVerified to be true")
		}
		if len(result.Roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(result.Roles))
		}
	})
}

func TestIAMGRPCService_DragonRoleToPlatformRole(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{}

	t.Run("nil role returns nil", func(t *testing.T) {
		result := svc.dragonRoleToPlatformRole(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		dragonRole := &iampb.Role{
			Id:          "role-123",
			TenantId:    "tenant-1",
			Name:        "admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
		}

		result := svc.dragonRoleToPlatformRole(dragonRole)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Name != "admin" {
			t.Errorf("expected name 'admin', got %q", result.Name)
		}
		if len(result.Permissions) != 3 {
			t.Errorf("expected 3 permissions, got %d", len(result.Permissions))
		}
	})
}

func TestIAMGRPCService_DragonGroupToPlatformGroup(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{}

	t.Run("nil group returns nil", func(t *testing.T) {
		result := svc.dragonGroupToPlatformGroup(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		dragonGroup := &iampb.Group{
			Id:          "group-123",
			TenantId:    "tenant-1",
			Name:        "developers",
			Description: "Development team",
			Members:     []string{"user-1", "user-2"},
		}

		result := svc.dragonGroupToPlatformGroup(dragonGroup)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Name != "developers" {
			t.Errorf("expected name 'developers', got %q", result.Name)
		}
		if len(result.Members) != 2 {
			t.Errorf("expected 2 members, got %d", len(result.Members))
		}
	})
}

func TestIAMGRPCService_DragonTenantToPlatformTenant(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{}

	t.Run("nil tenant returns nil", func(t *testing.T) {
		result := svc.dragonTenantToPlatformTenant(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields including settings", func(t *testing.T) {
		dragonTenant := &iampb.Tenant{
			Id:   "tenant-123",
			Name: "Test Tenant",
			Settings: &iampb.TenantSettings{
				MaxUsers:    100,
				MfaRequired: true,
			},
		}

		result := svc.dragonTenantToPlatformTenant(dragonTenant)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Id != "tenant-123" {
			t.Errorf("expected ID 'tenant-123', got %q", result.Id)
		}
		if result.Settings == nil {
			t.Fatal("expected non-nil settings")
		}
		if result.Settings.MaxUsers != 100 {
			t.Errorf("expected MaxUsers 100, got %d", result.Settings.MaxUsers)
		}
		if !result.Settings.MfaRequired {
			t.Error("expected MfaRequired to be true")
		}
	})

	t.Run("handles nil settings", func(t *testing.T) {
		dragonTenant := &iampb.Tenant{
			Id:   "tenant-123",
			Name: "Test Tenant",
		}

		result := svc.dragonTenantToPlatformTenant(dragonTenant)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Settings != nil {
			t.Error("expected nil settings")
		}
	})
}

func TestIAMGRPCService_DragonPolicyToPlatformPolicy(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{}

	t.Run("nil policy returns nil", func(t *testing.T) {
		result := svc.dragonPolicyToPlatformPolicy(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		dragonPolicy := &iampb.Policy{
			Name:        "test-policy",
			TenantId:    "tenant-1",
			Description: "Test policy",
			Priority:    10,
			SpecYaml:    []byte("rules: []"),
			Labels:      map[string]string{"env": "prod"},
		}

		result := svc.dragonPolicyToPlatformPolicy(dragonPolicy)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Name != "test-policy" {
			t.Errorf("expected name 'test-policy', got %q", result.Name)
		}
		if result.Priority != 10 {
			t.Errorf("expected priority 10, got %d", result.Priority)
		}
	})
}

func TestIAMGRPCService_DragonAppToPlatformApp(t *testing.T) {
	t.Parallel()

	svc := &IAMGRPCService{}

	t.Run("nil app returns nil", func(t *testing.T) {
		result := svc.dragonAppToPlatformApp(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		dragonApp := &iampb.Application{
			ClientId:       "client-123",
			ClientSecret:   "secret-456",
			TenantId:       "tenant-1",
			Name:           "test-app",
			RedirectUris:   []string{"https://example.com/callback"},
			GrantTypes:     []string{"authorization_code"},
			ResponseTypes:  []string{"code"},
			ResourcePrefix: "app:",
		}

		result := svc.dragonAppToPlatformApp(dragonApp)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.ClientId != "client-123" {
			t.Errorf("expected ClientId 'client-123', got %q", result.ClientId)
		}
		if result.Name != "test-app" {
			t.Errorf("expected name 'test-app', got %q", result.Name)
		}
		if len(result.RedirectUris) != 1 {
			t.Errorf("expected 1 redirect URI, got %d", len(result.RedirectUris))
		}
	})
}

// =============================================================================
// Additional Role Operation Tests
// =============================================================================

func TestIAMGRPCService_ListRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.ListRoles(ctx, &platformv1.ListIAMRolesRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.ListRoles(ctx, &platformv1.ListIAMRolesRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			listRolesFunc: func(ctx context.Context, in *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
				return &iampb.ListRolesResponse{
					Roles: []*iampb.Role{
						{Id: "role-1", TenantId: in.TenantId, Name: "admin"},
						{Id: "role-2", TenantId: in.TenantId, Name: "user"},
					},
					Total: 2,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ListRoles(ctx, &platformv1.ListIAMRolesRequest{
			TenantId: "tenant-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(resp.Roles))
		}
	})
}

func TestIAMGRPCService_UpdateRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.UpdateRole(ctx, &platformv1.UpdateIAMRoleRequest{
			TenantId: "tenant-1",
			RoleId:   "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateRole(ctx, &platformv1.UpdateIAMRoleRequest{
			RoleId: "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing role_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateRole(ctx, &platformv1.UpdateIAMRoleRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			updateRoleFunc: func(ctx context.Context, in *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
				return &iampb.Role{
					Id:          in.RoleId,
					TenantId:    in.TenantId,
					Name:        in.Name,
					Description: in.Description,
					Permissions: in.Permissions,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.UpdateRole(ctx, &platformv1.UpdateIAMRoleRequest{
			TenantId:    "tenant-1",
			RoleId:      "role-123",
			Name:        "updated-admin",
			Description: "Updated admin role",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Role == nil {
			t.Fatal("expected non-nil response with role")
		}
		if resp.Role.Name != "updated-admin" {
			t.Errorf("expected role name 'updated-admin', got %q", resp.Role.Name)
		}
	})
}

func TestIAMGRPCService_DeleteRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{
			TenantId: "tenant-1",
			RoleId:   "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{
			RoleId: "role-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing role_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			deleteRoleFunc: func(ctx context.Context, in *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
				return &iampb.DeleteRoleResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.DeleteRole(ctx, &platformv1.DeleteIAMRoleRequest{
			TenantId: "tenant-1",
			RoleId:   "role-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}

// =============================================================================
// Additional Group Operation Tests
// =============================================================================

func TestIAMGRPCService_GetGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{
			GroupId: "group-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing group_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			getGroupFunc: func(ctx context.Context, in *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
				return &iampb.Group{
					Id:          in.GroupId,
					TenantId:    in.TenantId,
					Name:        "developers",
					Description: "Developer group",
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.GetGroup(ctx, &platformv1.GetIAMGroupRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Group == nil {
			t.Fatal("expected non-nil response with group")
		}
	})
}

func TestIAMGRPCService_ListGroups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			listGroupsFunc: func(ctx context.Context, in *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
				return &iampb.ListGroupsResponse{
					Groups: []*iampb.Group{
						{Id: "group-1", TenantId: in.TenantId, Name: "developers"},
						{Id: "group-2", TenantId: in.TenantId, Name: "admins"},
					},
					Total: 2,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ListGroups(ctx, &platformv1.ListIAMGroupsRequest{
			TenantId: "tenant-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Groups) != 2 {
			t.Errorf("expected 2 groups, got %d", len(resp.Groups))
		}
	})
}

func TestIAMGRPCService_UpdateGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.UpdateGroup(ctx, &platformv1.UpdateIAMGroupRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateGroup(ctx, &platformv1.UpdateIAMGroupRequest{
			GroupId: "group-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing group_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateGroup(ctx, &platformv1.UpdateIAMGroupRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			updateGroupFunc: func(ctx context.Context, in *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
				return &iampb.Group{
					Id:          in.GroupId,
					TenantId:    in.TenantId,
					Name:        in.Name,
					Description: in.Description,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.UpdateGroup(ctx, &platformv1.UpdateIAMGroupRequest{
			TenantId:    "tenant-1",
			GroupId:     "group-123",
			Name:        "updated-developers",
			Description: "Updated developer group",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Group == nil {
			t.Fatal("expected non-nil response with group")
		}
	})
}

func TestIAMGRPCService_DeleteGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{
			GroupId: "group-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing group_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			deleteGroupFunc: func(ctx context.Context, in *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
				return &iampb.DeleteGroupResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.DeleteGroup(ctx, &platformv1.DeleteIAMGroupRequest{
			TenantId: "tenant-1",
			GroupId:  "group-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}

// =============================================================================
// Additional Tenant Operation Tests
// =============================================================================

func TestIAMGRPCService_UpdateTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.UpdateTenant(ctx, &platformv1.UpdateIAMTenantRequest{
			TenantId: "tenant-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateTenant(ctx, &platformv1.UpdateIAMTenantRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			updateTenantFunc: func(ctx context.Context, in *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
				return &iampb.Tenant{
					Id:   in.Id,
					Name: in.Name,
					Settings: &iampb.TenantSettings{
						MaxUsers:    in.Settings.MaxUsers,
						MfaRequired: in.Settings.MfaRequired,
					},
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.UpdateTenant(ctx, &platformv1.UpdateIAMTenantRequest{
			TenantId: "tenant-123",
			Name:     "Updated Tenant",
			Settings: &platformv1.IAMTenantSettings{
				MaxUsers:    200,
				MfaRequired: true,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Tenant == nil {
			t.Fatal("expected non-nil response with tenant")
		}
	})
}

func TestIAMGRPCService_DeleteTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.DeleteTenant(ctx, &platformv1.DeleteIAMTenantRequest{
			TenantId: "tenant-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteTenant(ctx, &platformv1.DeleteIAMTenantRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			deleteTenantFunc: func(ctx context.Context, in *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error) {
				return &iampb.DeleteTenantResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.DeleteTenant(ctx, &platformv1.DeleteIAMTenantRequest{
			TenantId: "tenant-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}

// =============================================================================
// Additional Policy Operation Tests
// =============================================================================

func TestIAMGRPCService_GetPolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.GetPolicy(ctx, &platformv1.GetIAMPolicyRequest{
			TenantId:   "tenant-1",
			PolicyName: "admin-policy",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetPolicy(ctx, &platformv1.GetIAMPolicyRequest{
			PolicyName: "admin-policy",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing policy_name returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetPolicy(ctx, &platformv1.GetIAMPolicyRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			getPolicyFunc: func(ctx context.Context, in *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
				return &iampb.Policy{
					Name:        in.PolicyName,
					TenantId:    in.TenantId,
					Description: "Admin access policy",
					Priority:    100,
					SpecYaml:    []byte("rules: []"),
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.GetPolicy(ctx, &platformv1.GetIAMPolicyRequest{
			TenantId:   "tenant-1",
			PolicyName: "admin-policy",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Policy == nil {
			t.Fatal("expected non-nil response with policy")
		}
	})
}

func TestIAMGRPCService_ListPolicies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.ListPolicies(ctx, &platformv1.ListIAMPoliciesRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.ListPolicies(ctx, &platformv1.ListIAMPoliciesRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			listPoliciesFunc: func(ctx context.Context, in *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error) {
				return &iampb.ListPoliciesResponse{
					Policies: []*iampb.Policy{
						{Name: "policy-1", TenantId: in.TenantId},
						{Name: "policy-2", TenantId: in.TenantId},
					},
					Total: 2,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ListPolicies(ctx, &platformv1.ListIAMPoliciesRequest{
			TenantId: "tenant-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Policies) != 2 {
			t.Errorf("expected 2 policies, got %d", len(resp.Policies))
		}
	})
}

func TestIAMGRPCService_UpdatePolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.UpdatePolicy(ctx, &platformv1.UpdateIAMPolicyRequest{
			TenantId:   "tenant-1",
			PolicyName: "admin-policy",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdatePolicy(ctx, &platformv1.UpdateIAMPolicyRequest{
			PolicyName: "admin-policy",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing policy_name returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdatePolicy(ctx, &platformv1.UpdateIAMPolicyRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			updatePolicyFunc: func(ctx context.Context, in *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
				return &iampb.Policy{
					Name:        in.PolicyName,
					TenantId:    in.TenantId,
					Description: in.Description,
					Priority:    in.Priority,
					SpecYaml:    in.SpecYaml,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.UpdatePolicy(ctx, &platformv1.UpdateIAMPolicyRequest{
			TenantId:    "tenant-1",
			PolicyName:  "admin-policy",
			Description: "Updated admin policy",
			Priority:    200,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Policy == nil {
			t.Fatal("expected non-nil response with policy")
		}
	})
}

func TestIAMGRPCService_DeletePolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.DeletePolicy(ctx, &platformv1.DeleteIAMPolicyRequest{
			TenantId:   "tenant-1",
			PolicyName: "admin-policy",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeletePolicy(ctx, &platformv1.DeleteIAMPolicyRequest{
			PolicyName: "admin-policy",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing policy_name returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeletePolicy(ctx, &platformv1.DeleteIAMPolicyRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			deletePolicyFunc: func(ctx context.Context, in *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error) {
				return &iampb.DeletePolicyResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.DeletePolicy(ctx, &platformv1.DeleteIAMPolicyRequest{
			TenantId:   "tenant-1",
			PolicyName: "admin-policy",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}

// =============================================================================
// Additional App Operation Tests
// =============================================================================

func TestIAMGRPCService_GetApp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.GetApp(ctx, &platformv1.GetIAMAppRequest{
			TenantId: "tenant-1",
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetApp(ctx, &platformv1.GetIAMAppRequest{
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing client_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.GetApp(ctx, &platformv1.GetIAMAppRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			getAppFunc: func(ctx context.Context, in *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
				return &iampb.Application{
					ClientId: in.ClientId,
					TenantId: in.TenantId,
					Name:     "test-app",
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.GetApp(ctx, &platformv1.GetIAMAppRequest{
			TenantId: "tenant-1",
			ClientId: "client-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.App == nil {
			t.Fatal("expected non-nil response with app")
		}
	})
}

func TestIAMGRPCService_ListApps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.ListApps(ctx, &platformv1.ListIAMAppsRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.ListApps(ctx, &platformv1.ListIAMAppsRequest{})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			listAppsFunc: func(ctx context.Context, in *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error) {
				return &iampb.ListAppsResponse{
					Apps: []*iampb.Application{
						{ClientId: "client-1", TenantId: in.TenantId, Name: "app-1"},
						{ClientId: "client-2", TenantId: in.TenantId, Name: "app-2"},
					},
					Total: 2,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.ListApps(ctx, &platformv1.ListIAMAppsRequest{
			TenantId: "tenant-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Apps) != 2 {
			t.Errorf("expected 2 apps, got %d", len(resp.Apps))
		}
	})
}

func TestIAMGRPCService_UpdateApp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{
			TenantId: "tenant-1",
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing client_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			updateAppFunc: func(ctx context.Context, in *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
				return &iampb.Application{
					ClientId:       in.ClientId,
					TenantId:       in.TenantId,
					Name:           in.Name,
					RedirectUris:   in.RedirectUris,
					ResourcePrefix: in.ResourcePrefix,
				}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{
			TenantId:     "tenant-1",
			ClientId:     "client-123",
			Name:         "updated-app",
			RedirectUris: []string{"https://updated.example.com/callback"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.App == nil {
			t.Fatal("expected non-nil response with app")
		}
		if resp.App.Name != "updated-app" {
			t.Errorf("expected app name 'updated-app', got %q", resp.App.Name)
		}
	})
}

func TestIAMGRPCService_DeleteApp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("nil client returns FailedPrecondition", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), nil, nil)
		resp, err := svc.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{
			TenantId: "tenant-1",
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.FailedPrecondition)
	})

	t.Run("missing tenant_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{
			ClientId: "client-123",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("missing client_id returns InvalidArgument", func(t *testing.T) {
		svc := NewIAMGRPCService(iamTestLogger(), &mockIAMServiceClient{}, nil)
		resp, err := svc.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{
			TenantId: "tenant-1",
		})
		if resp != nil {
			t.Error("expected nil response")
		}
		assertIAMGRPCError(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		mockIAM := &mockIAMServiceClient{
			deleteAppFunc: func(ctx context.Context, in *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error) {
				return &iampb.DeleteAppResponse{Success: true}, nil
			},
		}
		svc := NewIAMGRPCService(iamTestLogger(), mockIAM, nil)
		resp, err := svc.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{
			TenantId: "tenant-1",
			ClientId: "client-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil || resp.Status == nil {
			t.Fatal("expected non-nil response with status")
		}
		if !resp.Status.Success {
			t.Error("expected success to be true")
		}
	})
}
