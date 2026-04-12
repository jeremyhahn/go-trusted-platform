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
	"time"

	clipkg "github.com/jeremyhahn/go-quicbaas/pkg/cli"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock IAMServiceClient — implements iam.Client via sub-client delegation
// =============================================================================

// mockIAMServiceClient holds function fields for all IAM sub-client operations.
// Sub-client adapter structs delegate each method call to the corresponding
// function field on this parent struct.
type mockIAMServiceClient struct {
	// User operations
	createUserFunc func(ctx context.Context, tenantID string, req *sdkiam.CreateUserRequest) (*sdkiam.User, error)
	getUserFunc    func(ctx context.Context, tenantID, userID string) (*sdkiam.User, error)
	updateUserFunc func(ctx context.Context, tenantID, userID string, req *sdkiam.UpdateUserRequest) (*sdkiam.User, error)
	deleteUserFunc func(ctx context.Context, tenantID, userID string) error
	listUsersFunc  func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error)
	assignRoleFunc func(ctx context.Context, tenantID, userID, roleID string) error
	revokeRoleFunc func(ctx context.Context, tenantID, userID, roleID string) error

	// Role operations
	createRoleFunc func(ctx context.Context, tenantID string, req *sdkiam.CreateRoleRequest) (*sdkiam.Role, error)
	getRoleFunc    func(ctx context.Context, tenantID, roleID string) (*sdkiam.Role, error)
	updateRoleFunc func(ctx context.Context, tenantID, roleID string, req *sdkiam.UpdateRoleRequest) (*sdkiam.Role, error)
	deleteRoleFunc func(ctx context.Context, tenantID, roleID string) error
	listRolesFunc  func(ctx context.Context, tenantID string, req *sdkiam.ListRolesRequest) (*sdkiam.ListRolesResponse, error)

	// Group operations
	createGroupFunc         func(ctx context.Context, tenantID string, req *sdkiam.CreateGroupRequest) (*sdkiam.Group, error)
	getGroupFunc            func(ctx context.Context, tenantID, groupID string) (*sdkiam.Group, error)
	updateGroupFunc         func(ctx context.Context, tenantID, groupID string, req *sdkiam.UpdateGroupRequest) (*sdkiam.Group, error)
	deleteGroupFunc         func(ctx context.Context, tenantID, groupID string) error
	listGroupsFunc          func(ctx context.Context, tenantID string, req *sdkiam.ListGroupsRequest) (*sdkiam.ListGroupsResponse, error)
	addUserToGroupFunc      func(ctx context.Context, tenantID, groupID, userID string) error
	removeUserFromGroupFunc func(ctx context.Context, tenantID, groupID, userID string) error

	// Tenant operations
	createTenantFunc func(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error)
	getTenantFunc    func(ctx context.Context, tenantID string) (*sdkiam.Tenant, error)
	updateTenantFunc func(ctx context.Context, tenantID string, req *sdkiam.UpdateTenantRequest) (*sdkiam.Tenant, error)
	deleteTenantFunc func(ctx context.Context, tenantID string) error
	listTenantsFunc  func(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error)

	// Policy operations
	createPolicyFunc   func(ctx context.Context, tenantID string, req *sdkiam.CreatePolicyRequest) (*sdkiam.Policy, error)
	getPolicyFunc      func(ctx context.Context, tenantID, policyName string) (*sdkiam.Policy, error)
	updatePolicyFunc   func(ctx context.Context, tenantID, policyName string, req *sdkiam.UpdatePolicyRequest) (*sdkiam.Policy, error)
	deletePolicyFunc   func(ctx context.Context, tenantID, policyName string) error
	listPoliciesFunc   func(ctx context.Context, tenantID string, req *sdkiam.ListPoliciesRequest) (*sdkiam.ListPoliciesResponse, error)
	validatePolicyFunc func(ctx context.Context, tenantID string, policy *sdkiam.Policy) (*sdkiam.ValidationResult, error)
	testPolicyFunc     func(ctx context.Context, tenantID string, req *sdkiam.TestPolicyRequest) (*sdkiam.TestPolicyResponse, error)

	// App operations
	registerAppFunc     func(ctx context.Context, tenantID string, req *sdkiam.RegisterAppRequest) (*sdkiam.Application, error)
	getAppFunc          func(ctx context.Context, tenantID, clientID string) (*sdkiam.Application, error)
	updateAppFunc       func(ctx context.Context, tenantID, clientID string, req *sdkiam.UpdateAppRequest) (*sdkiam.Application, error)
	deleteAppFunc       func(ctx context.Context, tenantID, clientID string) error
	listAppsFunc        func(ctx context.Context, tenantID string) (*sdkiam.ListAppsResponse, error)
	rotateAppSecretFunc func(ctx context.Context, tenantID, clientID string) (*sdkiam.RotateSecretResponse, error)
}

// Sub-client adapters

type mockUserSubClient struct{ m *mockIAMServiceClient }

func (c *mockUserSubClient) Create(ctx context.Context, tenantID string, req *sdkiam.CreateUserRequest) (*sdkiam.User, error) {
	if c.m.createUserFunc != nil {
		return c.m.createUserFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) Get(ctx context.Context, tenantID, userID string) (*sdkiam.User, error) {
	if c.m.getUserFunc != nil {
		return c.m.getUserFunc(ctx, tenantID, userID)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) GetByEmail(ctx context.Context, tenantID, email string) (*sdkiam.User, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) Update(ctx context.Context, tenantID, userID string, req *sdkiam.UpdateUserRequest) (*sdkiam.User, error) {
	if c.m.updateUserFunc != nil {
		return c.m.updateUserFunc(ctx, tenantID, userID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) Delete(ctx context.Context, tenantID, userID string) error {
	if c.m.deleteUserFunc != nil {
		return c.m.deleteUserFunc(ctx, tenantID, userID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) List(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
	if c.m.listUsersFunc != nil {
		return c.m.listUsersFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) AssignRole(ctx context.Context, tenantID, userID, roleID string) error {
	if c.m.assignRoleFunc != nil {
		return c.m.assignRoleFunc(ctx, tenantID, userID, roleID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) RevokeRole(ctx context.Context, tenantID, userID, roleID string) error {
	if c.m.revokeRoleFunc != nil {
		return c.m.revokeRoleFunc(ctx, tenantID, userID, roleID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) AddToGroup(ctx context.Context, tenantID, userID, groupID string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) RemoveFromGroup(ctx context.Context, tenantID, userID, groupID string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) Suspend(ctx context.Context, tenantID, userID string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockUserSubClient) Unsuspend(ctx context.Context, tenantID, userID string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}

type mockRoleSubClient struct{ m *mockIAMServiceClient }

func (c *mockRoleSubClient) Create(ctx context.Context, tenantID string, req *sdkiam.CreateRoleRequest) (*sdkiam.Role, error) {
	if c.m.createRoleFunc != nil {
		return c.m.createRoleFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockRoleSubClient) Get(ctx context.Context, tenantID, roleID string) (*sdkiam.Role, error) {
	if c.m.getRoleFunc != nil {
		return c.m.getRoleFunc(ctx, tenantID, roleID)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockRoleSubClient) Update(ctx context.Context, tenantID, roleID string, req *sdkiam.UpdateRoleRequest) (*sdkiam.Role, error) {
	if c.m.updateRoleFunc != nil {
		return c.m.updateRoleFunc(ctx, tenantID, roleID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockRoleSubClient) Delete(ctx context.Context, tenantID, roleID string) error {
	if c.m.deleteRoleFunc != nil {
		return c.m.deleteRoleFunc(ctx, tenantID, roleID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockRoleSubClient) List(ctx context.Context, tenantID string, req *sdkiam.ListRolesRequest) (*sdkiam.ListRolesResponse, error) {
	if c.m.listRolesFunc != nil {
		return c.m.listRolesFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type mockGroupSubClient struct{ m *mockIAMServiceClient }

func (c *mockGroupSubClient) Create(ctx context.Context, tenantID string, req *sdkiam.CreateGroupRequest) (*sdkiam.Group, error) {
	if c.m.createGroupFunc != nil {
		return c.m.createGroupFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockGroupSubClient) Get(ctx context.Context, tenantID, groupID string) (*sdkiam.Group, error) {
	if c.m.getGroupFunc != nil {
		return c.m.getGroupFunc(ctx, tenantID, groupID)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockGroupSubClient) Update(ctx context.Context, tenantID, groupID string, req *sdkiam.UpdateGroupRequest) (*sdkiam.Group, error) {
	if c.m.updateGroupFunc != nil {
		return c.m.updateGroupFunc(ctx, tenantID, groupID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockGroupSubClient) Delete(ctx context.Context, tenantID, groupID string) error {
	if c.m.deleteGroupFunc != nil {
		return c.m.deleteGroupFunc(ctx, tenantID, groupID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockGroupSubClient) List(ctx context.Context, tenantID string, req *sdkiam.ListGroupsRequest) (*sdkiam.ListGroupsResponse, error) {
	if c.m.listGroupsFunc != nil {
		return c.m.listGroupsFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockGroupSubClient) AddMember(ctx context.Context, tenantID, groupID, userID string) error {
	if c.m.addUserToGroupFunc != nil {
		return c.m.addUserToGroupFunc(ctx, tenantID, groupID, userID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockGroupSubClient) RemoveMember(ctx context.Context, tenantID, groupID, userID string) error {
	if c.m.removeUserFromGroupFunc != nil {
		return c.m.removeUserFromGroupFunc(ctx, tenantID, groupID, userID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockGroupSubClient) ListMembers(ctx context.Context, tenantID, groupID string) (*sdkiam.ListMembersResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type mockTenantSubClient struct{ m *mockIAMServiceClient }

func (c *mockTenantSubClient) Create(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
	if c.m.createTenantFunc != nil {
		return c.m.createTenantFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockTenantSubClient) Get(ctx context.Context, tenantID string) (*sdkiam.Tenant, error) {
	if c.m.getTenantFunc != nil {
		return c.m.getTenantFunc(ctx, tenantID)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockTenantSubClient) Update(ctx context.Context, tenantID string, req *sdkiam.UpdateTenantRequest) (*sdkiam.Tenant, error) {
	if c.m.updateTenantFunc != nil {
		return c.m.updateTenantFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockTenantSubClient) Delete(ctx context.Context, tenantID string) error {
	if c.m.deleteTenantFunc != nil {
		return c.m.deleteTenantFunc(ctx, tenantID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockTenantSubClient) List(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
	if c.m.listTenantsFunc != nil {
		return c.m.listTenantsFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type mockPolicySubClient struct{ m *mockIAMServiceClient }

func (c *mockPolicySubClient) Create(ctx context.Context, tenantID string, req *sdkiam.CreatePolicyRequest) (*sdkiam.Policy, error) {
	if c.m.createPolicyFunc != nil {
		return c.m.createPolicyFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) Get(ctx context.Context, tenantID, policyName string) (*sdkiam.Policy, error) {
	if c.m.getPolicyFunc != nil {
		return c.m.getPolicyFunc(ctx, tenantID, policyName)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) Update(ctx context.Context, tenantID, policyName string, req *sdkiam.UpdatePolicyRequest) (*sdkiam.Policy, error) {
	if c.m.updatePolicyFunc != nil {
		return c.m.updatePolicyFunc(ctx, tenantID, policyName, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) Delete(ctx context.Context, tenantID, policyName string) error {
	if c.m.deletePolicyFunc != nil {
		return c.m.deletePolicyFunc(ctx, tenantID, policyName)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) List(ctx context.Context, tenantID string, req *sdkiam.ListPoliciesRequest) (*sdkiam.ListPoliciesResponse, error) {
	if c.m.listPoliciesFunc != nil {
		return c.m.listPoliciesFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) Validate(ctx context.Context, tenantID string, policy *sdkiam.Policy) (*sdkiam.ValidationResult, error) {
	if c.m.validatePolicyFunc != nil {
		return c.m.validatePolicyFunc(ctx, tenantID, policy)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) Test(ctx context.Context, tenantID string, req *sdkiam.TestPolicyRequest) (*sdkiam.TestPolicyResponse, error) {
	if c.m.testPolicyFunc != nil {
		return c.m.testPolicyFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) Simulate(ctx context.Context, tenantID string, req *sdkiam.SimulateRequest) (*sdkiam.SimulateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockPolicySubClient) GetEffectivePermissions(ctx context.Context, tenantID string, req *sdkiam.EffectivePermissionsRequest) (*sdkiam.EffectivePermissionsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type mockAppSubClient struct{ m *mockIAMServiceClient }

func (c *mockAppSubClient) Register(ctx context.Context, tenantID string, req *sdkiam.RegisterAppRequest) (*sdkiam.Application, error) {
	if c.m.registerAppFunc != nil {
		return c.m.registerAppFunc(ctx, tenantID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockAppSubClient) Get(ctx context.Context, tenantID, clientID string) (*sdkiam.Application, error) {
	if c.m.getAppFunc != nil {
		return c.m.getAppFunc(ctx, tenantID, clientID)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockAppSubClient) Update(ctx context.Context, tenantID, clientID string, req *sdkiam.UpdateAppRequest) (*sdkiam.Application, error) {
	if c.m.updateAppFunc != nil {
		return c.m.updateAppFunc(ctx, tenantID, clientID, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockAppSubClient) Delete(ctx context.Context, tenantID, clientID string) error {
	if c.m.deleteAppFunc != nil {
		return c.m.deleteAppFunc(ctx, tenantID, clientID)
	}
	return status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockAppSubClient) List(ctx context.Context, tenantID string) (*sdkiam.ListAppsResponse, error) {
	if c.m.listAppsFunc != nil {
		return c.m.listAppsFunc(ctx, tenantID)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (c *mockAppSubClient) RotateSecret(ctx context.Context, tenantID, clientID string) (*sdkiam.RotateSecretResponse, error) {
	if c.m.rotateAppSecretFunc != nil {
		return c.m.rotateAppSecretFunc(ctx, tenantID, clientID)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// mockIAMServiceClient implements iam.Client by returning sub-client adapters.

func (m *mockIAMServiceClient) User() sdkiam.UserClient    { return &mockUserSubClient{m} }
func (m *mockIAMServiceClient) Role() sdkiam.RoleClient    { return &mockRoleSubClient{m} }
func (m *mockIAMServiceClient) Group() sdkiam.GroupClient  { return &mockGroupSubClient{m} }
func (m *mockIAMServiceClient) Tenant() sdkiam.TenantClient { return &mockTenantSubClient{m} }
func (m *mockIAMServiceClient) Policy() sdkiam.PolicyClient { return &mockPolicySubClient{m} }
func (m *mockIAMServiceClient) App() sdkiam.AppClient      { return &mockAppSubClient{m} }
func (m *mockIAMServiceClient) PEP() sdkiam.PEPClient      { return &mockPEPServiceClient{} }
func (m *mockIAMServiceClient) Session() sdkiam.SessionClient { return nil }
func (m *mockIAMServiceClient) Audit() sdkiam.AuditClient  { return nil }
func (m *mockIAMServiceClient) GDPR() sdkiam.GDPRClient    { return nil }
func (m *mockIAMServiceClient) Admin() sdkiam.AdminClient  { return nil }
func (m *mockIAMServiceClient) Close() error               { return nil }

// Federation stubs
func (m *mockIAMServiceClient) CreateProvider(ctx context.Context, opts *clipkg.CreateProviderOptions) (*clipkg.Provider, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) GetProvider(ctx context.Context, tenantID, providerID string) (*clipkg.Provider, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) UpdateProvider(ctx context.Context, opts *clipkg.UpdateProviderOptions) (*clipkg.Provider, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) DeleteProvider(ctx context.Context, tenantID, providerID string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) ListProviders(ctx context.Context, tenantID string) ([]*clipkg.Provider, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// Identity stubs
func (m *mockIAMServiceClient) LinkIdentity(ctx context.Context, opts *clipkg.LinkIdentityOptions) (*clipkg.FederatedIdentity, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) UnlinkIdentity(ctx context.Context, tenantID, userID, providerID string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) ListUserIdentities(ctx context.Context, tenantID, userID string) ([]*clipkg.FederatedIdentity, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// MFA stubs
func (m *mockIAMServiceClient) GetMFAStatus(ctx context.Context, tenantID, userID string) (*clipkg.MFAStatus, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) BeginMFAEnrollment(ctx context.Context, tenantID, userID, method string) (*clipkg.MFAEnrollment, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) CompleteMFAEnrollment(ctx context.Context, enrollmentID, code string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) DisableMFA(ctx context.Context, tenantID, userID string) error {
	return status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) GetBackupCodeStatus(ctx context.Context, tenantID, userID string) (*clipkg.BackupCodeStatus, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (m *mockIAMServiceClient) GenerateBackupCodes(ctx context.Context, tenantID, userID string) ([]string, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// =============================================================================
// Mock PEPServiceClient — implements iam.PEPClient
// =============================================================================

type mockPEPServiceClient struct {
	checkFunc func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error)
}

func (m *mockPEPServiceClient) Check(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	if m.checkFunc != nil {
		return m.checkFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockPEPServiceClient) CheckBatch(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// compile-time interface checks
var _ sdkiam.PEPClient = (*mockPEPServiceClient)(nil)

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
			createUserFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateUserRequest) (*sdkiam.User, error) {
				return &sdkiam.User{
					ID:          "user-123",
					TenantID:    tenantID,
					Email:       req.Email,
					DisplayName: req.DisplayName,
					Roles:       req.Roles,
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
			createUserFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateUserRequest) (*sdkiam.User, error) {
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
			getUserFunc: func(ctx context.Context, tenantID, userID string) (*sdkiam.User, error) {
				return &sdkiam.User{
					ID:       userID,
					TenantID: tenantID,
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
			listUsersFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
				return &sdkiam.ListUsersResponse{
					Users: []sdkiam.User{
						{ID: "user-1", TenantID: tenantID, Email: "user1@example.com"},
						{ID: "user-2", TenantID: tenantID, Email: "user2@example.com"},
					},
					Pagination: sdkiam.PaginationInfo{TotalCount: 2},
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
			updateUserFunc: func(ctx context.Context, tenantID, userID string, req *sdkiam.UpdateUserRequest) (*sdkiam.User, error) {
				return &sdkiam.User{
					ID:          userID,
					TenantID:    tenantID,
					DisplayName: req.DisplayName,
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
			deleteUserFunc: func(ctx context.Context, tenantID, userID string) error {
				return nil
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
			createRoleFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateRoleRequest) (*sdkiam.Role, error) {
				return &sdkiam.Role{
					ID:          "role-123",
					TenantID:    tenantID,
					Name:        req.Name,
					Description: req.Description,
					Permissions: req.Permissions,
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
			getRoleFunc: func(ctx context.Context, tenantID, roleID string) (*sdkiam.Role, error) {
				return &sdkiam.Role{
					ID:       roleID,
					TenantID: tenantID,
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
			assignRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
				return nil
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
			revokeRoleFunc: func(ctx context.Context, tenantID, userID, roleID string) error {
				return nil
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
			createGroupFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreateGroupRequest) (*sdkiam.Group, error) {
				return &sdkiam.Group{
					ID:          "group-123",
					TenantID:    tenantID,
					Name:        req.Name,
					Description: req.Description,
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
			addUserToGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
				return nil
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
			removeUserFromGroupFunc: func(ctx context.Context, tenantID, groupID, userID string) error {
				return nil
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
			checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
				return &sdkiam.CheckResponse{
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
			checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
				return &sdkiam.CheckResponse{
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
			createTenantFunc: func(ctx context.Context, req *sdkiam.CreateTenantRequest) (*sdkiam.Tenant, error) {
				return &sdkiam.Tenant{
					ID:        req.ID,
					Name:      req.Name,
					Settings:  map[string]string{"mfa_required": "true"},
					CreatedAt: time.Now(),
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
			getTenantFunc: func(ctx context.Context, tenantID string) (*sdkiam.Tenant, error) {
				return &sdkiam.Tenant{
					ID:   tenantID,
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
			listTenantsFunc: func(ctx context.Context, req *sdkiam.ListTenantsRequest) (*sdkiam.ListTenantsResponse, error) {
				return &sdkiam.ListTenantsResponse{
					Tenants: []sdkiam.Tenant{
						{ID: "tenant-1", Name: "Tenant 1"},
						{ID: "tenant-2", Name: "Tenant 2"},
					},
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
			createPolicyFunc: func(ctx context.Context, tenantID string, req *sdkiam.CreatePolicyRequest) (*sdkiam.Policy, error) {
				return &sdkiam.Policy{
					Name:        req.Name,
					TenantID:    tenantID,
					Description: req.Description,
					SpecYAML:    req.SpecYAML,
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
			validatePolicyFunc: func(ctx context.Context, tenantID string, policy *sdkiam.Policy) (*sdkiam.ValidationResult, error) {
				return &sdkiam.ValidationResult{
					Valid:   true,
					Errors:  nil,
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
			validatePolicyFunc: func(ctx context.Context, tenantID string, policy *sdkiam.Policy) (*sdkiam.ValidationResult, error) {
				return &sdkiam.ValidationResult{
					Valid: false,
					Errors: []sdkiam.ValidationError{
						{Message: "invalid syntax"},
						{Message: "missing required field"},
					},
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
			testPolicyFunc: func(ctx context.Context, tenantID string, req *sdkiam.TestPolicyRequest) (*sdkiam.TestPolicyResponse, error) {
				return &sdkiam.TestPolicyResponse{
					Results: []sdkiam.TestCaseResult{
						{Passed: true, MatchedRule: "rule-1", EvaluationTimeNs: 500},
					},
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
			registerAppFunc: func(ctx context.Context, tenantID string, req *sdkiam.RegisterAppRequest) (*sdkiam.Application, error) {
				return &sdkiam.Application{
					ClientID:     "client-123",
					ClientSecret: "secret-456",
					TenantID:     tenantID,
					Name:         req.Name,
					RedirectURIs: req.RedirectURIs,
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
			rotateAppSecretFunc: func(ctx context.Context, tenantID, clientID string) (*sdkiam.RotateSecretResponse, error) {
				return &sdkiam.RotateSecretResponse{
					ClientID:     clientID,
					ClientSecret: "new-secret-789",
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
		convertedErr := svc.wrapError(originalErr)
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
		convertedErr := svc.wrapError(originalErr)
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

func TestIAMGRPCService_SDKUserToPlatformUser(t *testing.T) {
	t.Parallel()

	t.Run("nil user returns nil", func(t *testing.T) {
		result := sdkUserToPlatformUser(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		now := time.Now()
		lastLogin := now
		sdkUser := &sdkiam.User{
			ID:          "user-123",
			TenantID:    "tenant-1",
			Email:       "user@example.com",
			DisplayName: "Test User",
			Roles:       []string{"admin", "user"},
			Groups:      []string{"dev", "ops"},
			Metadata:    map[string]string{"dept": "engineering"},
			MFAEnabled:  true,
			CreatedAt:   now,
			UpdatedAt:   now,
			LastLoginAt: &lastLogin,
		}

		result := sdkUserToPlatformUser(sdkUser)
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
			t.Error("expected MfaVerified (MFAEnabled) to be true")
		}
		if len(result.Roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(result.Roles))
		}
	})
}

func TestIAMGRPCService_SDKRoleToPlatformRole(t *testing.T) {
	t.Parallel()

	t.Run("nil role returns nil", func(t *testing.T) {
		result := sdkRoleToPlatformRole(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		sdkRole := &sdkiam.Role{
			ID:          "role-123",
			TenantID:    "tenant-1",
			Name:        "admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
		}

		result := sdkRoleToPlatformRole(sdkRole)
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

func TestIAMGRPCService_SDKGroupToPlatformGroup(t *testing.T) {
	t.Parallel()

	t.Run("nil group returns nil", func(t *testing.T) {
		result := sdkGroupToPlatformGroup(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		sdkGroup := &sdkiam.Group{
			ID:          "group-123",
			TenantID:    "tenant-1",
			Name:        "developers",
			Description: "Development team",
		}

		result := sdkGroupToPlatformGroup(sdkGroup)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Name != "developers" {
			t.Errorf("expected name 'developers', got %q", result.Name)
		}
		if result.Id != "group-123" {
			t.Errorf("expected ID 'group-123', got %q", result.Id)
		}
	})
}

func TestIAMGRPCService_SDKTenantToPlatformTenant(t *testing.T) {
	t.Parallel()

	t.Run("nil tenant returns nil", func(t *testing.T) {
		result := sdkTenantToPlatformTenant(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields including settings", func(t *testing.T) {
		sdkTenant := &sdkiam.Tenant{
			ID:       "tenant-123",
			Name:     "Test Tenant",
			Settings: map[string]string{"mfa_required": "true"},
		}

		result := sdkTenantToPlatformTenant(sdkTenant)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Id != "tenant-123" {
			t.Errorf("expected ID 'tenant-123', got %q", result.Id)
		}
		if result.Settings == nil {
			t.Fatal("expected non-nil settings")
		}
		if !result.Settings.MfaRequired {
			t.Error("expected MfaRequired to be true")
		}
	})

	t.Run("handles nil settings", func(t *testing.T) {
		sdkTenant := &sdkiam.Tenant{
			ID:   "tenant-123",
			Name: "Test Tenant",
		}

		result := sdkTenantToPlatformTenant(sdkTenant)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Settings != nil {
			t.Error("expected nil settings")
		}
	})
}

func TestIAMGRPCService_SDKPolicyToPlatformPolicy(t *testing.T) {
	t.Parallel()

	t.Run("nil policy returns nil", func(t *testing.T) {
		result := sdkPolicyToPlatformPolicy(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		sdkPolicy := &sdkiam.Policy{
			Name:        "test-policy",
			TenantID:    "tenant-1",
			Description: "Test policy",
			Priority:    10,
			SpecYAML:    []byte("rules: []"),
			Labels:      map[string]string{"env": "prod"},
		}

		result := sdkPolicyToPlatformPolicy(sdkPolicy)
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

func TestIAMGRPCService_SDKAppToPlatformApp(t *testing.T) {
	t.Parallel()

	t.Run("nil app returns nil", func(t *testing.T) {
		result := sdkAppToPlatformApp(nil)
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		sdkApp := &sdkiam.Application{
			ClientID:     "client-123",
			ClientSecret: "secret-456",
			TenantID:     "tenant-1",
			Name:         "test-app",
			RedirectURIs: []string{"https://example.com/callback"},
			GrantTypes:   []sdkiam.GrantType{sdkiam.GrantTypeAuthorizationCode},
		}

		result := sdkAppToPlatformApp(sdkApp)
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
			listRolesFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListRolesRequest) (*sdkiam.ListRolesResponse, error) {
				return &sdkiam.ListRolesResponse{
					Roles: []sdkiam.Role{
						{ID: "role-1", TenantID: tenantID, Name: "admin"},
						{ID: "role-2", TenantID: tenantID, Name: "user"},
					},
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
			updateRoleFunc: func(ctx context.Context, tenantID, roleID string, req *sdkiam.UpdateRoleRequest) (*sdkiam.Role, error) {
				return &sdkiam.Role{
					ID:          roleID,
					TenantID:    tenantID,
					Name:        req.Name,
					Description: req.Description,
					Permissions: req.Permissions,
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
			deleteRoleFunc: func(ctx context.Context, tenantID, roleID string) error {
				return nil
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
			getGroupFunc: func(ctx context.Context, tenantID, groupID string) (*sdkiam.Group, error) {
				return &sdkiam.Group{
					ID:          groupID,
					TenantID:    tenantID,
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
			listGroupsFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListGroupsRequest) (*sdkiam.ListGroupsResponse, error) {
				return &sdkiam.ListGroupsResponse{
					Groups: []sdkiam.Group{
						{ID: "group-1", TenantID: tenantID, Name: "developers"},
						{ID: "group-2", TenantID: tenantID, Name: "admins"},
					},
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
			updateGroupFunc: func(ctx context.Context, tenantID, groupID string, req *sdkiam.UpdateGroupRequest) (*sdkiam.Group, error) {
				return &sdkiam.Group{
					ID:          groupID,
					TenantID:    tenantID,
					Name:        req.Name,
					Description: req.Description,
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
			deleteGroupFunc: func(ctx context.Context, tenantID, groupID string) error {
				return nil
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
			updateTenantFunc: func(ctx context.Context, tenantID string, req *sdkiam.UpdateTenantRequest) (*sdkiam.Tenant, error) {
				return &sdkiam.Tenant{
					ID:          tenantID,
					DisplayName: req.DisplayName,
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
			deleteTenantFunc: func(ctx context.Context, tenantID string) error {
				return nil
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
			getPolicyFunc: func(ctx context.Context, tenantID, policyName string) (*sdkiam.Policy, error) {
				return &sdkiam.Policy{
					Name:        policyName,
					TenantID:    tenantID,
					Description: "Admin access policy",
					Priority:    100,
					SpecYAML:    []byte("rules: []"),
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
			listPoliciesFunc: func(ctx context.Context, tenantID string, req *sdkiam.ListPoliciesRequest) (*sdkiam.ListPoliciesResponse, error) {
				return &sdkiam.ListPoliciesResponse{
					Policies: []sdkiam.Policy{
						{Name: "policy-1", TenantID: tenantID},
						{Name: "policy-2", TenantID: tenantID},
					},
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
			updatePolicyFunc: func(ctx context.Context, tenantID, policyName string, req *sdkiam.UpdatePolicyRequest) (*sdkiam.Policy, error) {
				return &sdkiam.Policy{
					Name:     policyName,
					TenantID: tenantID,
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
			deletePolicyFunc: func(ctx context.Context, tenantID, policyName string) error {
				return nil
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
			getAppFunc: func(ctx context.Context, tenantID, clientID string) (*sdkiam.Application, error) {
				return &sdkiam.Application{
					ClientID: clientID,
					TenantID: tenantID,
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
			listAppsFunc: func(ctx context.Context, tenantID string) (*sdkiam.ListAppsResponse, error) {
				return &sdkiam.ListAppsResponse{
					Applications: []sdkiam.Application{
						{ClientID: "client-1", TenantID: tenantID, Name: "app-1"},
						{ClientID: "client-2", TenantID: tenantID, Name: "app-2"},
					},
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
			updateAppFunc: func(ctx context.Context, tenantID, clientID string, req *sdkiam.UpdateAppRequest) (*sdkiam.Application, error) {
				return &sdkiam.Application{
					ClientID:     clientID,
					TenantID:     tenantID,
					Name:         req.Name,
					RedirectURIs: req.RedirectURIs,
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
			deleteAppFunc: func(ctx context.Context, tenantID, clientID string) error {
				return nil
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
