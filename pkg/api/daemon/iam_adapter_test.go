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
	"testing"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// mockIAMServiceServer implements iampb.IAMServiceServer and delegates all
// calls to return a deterministic marker error so we can verify delegation.
type mockIAMServiceServer struct {
	iampb.UnimplementedIAMServiceServer
	called string
}

// markCalled returns a successful response and records the method name.
func (m *mockIAMServiceServer) CreateTenant(ctx context.Context, req *iampb.CreateTenantRequest) (*iampb.Tenant, error) {
	m.called = "CreateTenant"
	return &iampb.Tenant{Name: "test"}, nil
}

func (m *mockIAMServiceServer) GetTenant(ctx context.Context, req *iampb.GetTenantRequest) (*iampb.Tenant, error) {
	m.called = "GetTenant"
	return &iampb.Tenant{Name: "test"}, nil
}

func (m *mockIAMServiceServer) UpdateTenant(ctx context.Context, req *iampb.UpdateTenantRequest) (*iampb.Tenant, error) {
	m.called = "UpdateTenant"
	return &iampb.Tenant{}, nil
}

func (m *mockIAMServiceServer) DeleteTenant(ctx context.Context, req *iampb.DeleteTenantRequest) (*iampb.DeleteTenantResponse, error) {
	m.called = "DeleteTenant"
	return &iampb.DeleteTenantResponse{}, nil
}

func (m *mockIAMServiceServer) ListTenants(ctx context.Context, req *iampb.ListTenantsRequest) (*iampb.ListTenantsResponse, error) {
	m.called = "ListTenants"
	return &iampb.ListTenantsResponse{}, nil
}

func (m *mockIAMServiceServer) CreateUser(ctx context.Context, req *iampb.CreateUserRequest) (*iampb.User, error) {
	m.called = "CreateUser"
	return &iampb.User{}, nil
}

func (m *mockIAMServiceServer) GetUser(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error) {
	m.called = "GetUser"
	return &iampb.User{}, nil
}

func (m *mockIAMServiceServer) UpdateUser(ctx context.Context, req *iampb.UpdateUserRequest) (*iampb.User, error) {
	m.called = "UpdateUser"
	return &iampb.User{}, nil
}

func (m *mockIAMServiceServer) DeleteUser(ctx context.Context, req *iampb.DeleteUserRequest) (*iampb.DeleteUserResponse, error) {
	m.called = "DeleteUser"
	return &iampb.DeleteUserResponse{}, nil
}

func (m *mockIAMServiceServer) ListUsers(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error) {
	m.called = "ListUsers"
	return &iampb.ListUsersResponse{}, nil
}

func (m *mockIAMServiceServer) CreateRole(ctx context.Context, req *iampb.CreateRoleRequest) (*iampb.Role, error) {
	m.called = "CreateRole"
	return &iampb.Role{}, nil
}

func (m *mockIAMServiceServer) GetRole(ctx context.Context, req *iampb.GetRoleRequest) (*iampb.Role, error) {
	m.called = "GetRole"
	return &iampb.Role{}, nil
}

func (m *mockIAMServiceServer) UpdateRole(ctx context.Context, req *iampb.UpdateRoleRequest) (*iampb.Role, error) {
	m.called = "UpdateRole"
	return &iampb.Role{}, nil
}

func (m *mockIAMServiceServer) DeleteRole(ctx context.Context, req *iampb.DeleteRoleRequest) (*iampb.DeleteRoleResponse, error) {
	m.called = "DeleteRole"
	return &iampb.DeleteRoleResponse{}, nil
}

func (m *mockIAMServiceServer) ListRoles(ctx context.Context, req *iampb.ListRolesRequest) (*iampb.ListRolesResponse, error) {
	m.called = "ListRoles"
	return &iampb.ListRolesResponse{}, nil
}

func (m *mockIAMServiceServer) AssignRole(ctx context.Context, req *iampb.AssignRoleRequest) (*iampb.AssignRoleResponse, error) {
	m.called = "AssignRole"
	return &iampb.AssignRoleResponse{}, nil
}

func (m *mockIAMServiceServer) RevokeRole(ctx context.Context, req *iampb.RevokeRoleRequest) (*iampb.RevokeRoleResponse, error) {
	m.called = "RevokeRole"
	return &iampb.RevokeRoleResponse{}, nil
}

func (m *mockIAMServiceServer) RegisterApp(ctx context.Context, req *iampb.RegisterAppRequest) (*iampb.Application, error) {
	m.called = "RegisterApp"
	return &iampb.Application{}, nil
}

func (m *mockIAMServiceServer) GetApp(ctx context.Context, req *iampb.GetAppRequest) (*iampb.Application, error) {
	m.called = "GetApp"
	return &iampb.Application{}, nil
}

func (m *mockIAMServiceServer) UpdateApp(ctx context.Context, req *iampb.UpdateAppRequest) (*iampb.Application, error) {
	m.called = "UpdateApp"
	return &iampb.Application{}, nil
}

func (m *mockIAMServiceServer) DeleteApp(ctx context.Context, req *iampb.DeleteAppRequest) (*iampb.DeleteAppResponse, error) {
	m.called = "DeleteApp"
	return &iampb.DeleteAppResponse{}, nil
}

func (m *mockIAMServiceServer) ListApps(ctx context.Context, req *iampb.ListAppsRequest) (*iampb.ListAppsResponse, error) {
	m.called = "ListApps"
	return &iampb.ListAppsResponse{}, nil
}

func (m *mockIAMServiceServer) RotateAppSecret(ctx context.Context, req *iampb.RotateAppSecretRequest) (*iampb.Application, error) {
	m.called = "RotateAppSecret"
	return &iampb.Application{}, nil
}

func (m *mockIAMServiceServer) CreatePolicy(ctx context.Context, req *iampb.CreatePolicyRequest) (*iampb.Policy, error) {
	m.called = "CreatePolicy"
	return &iampb.Policy{}, nil
}

func (m *mockIAMServiceServer) GetPolicy(ctx context.Context, req *iampb.GetPolicyRequest) (*iampb.Policy, error) {
	m.called = "GetPolicy"
	return &iampb.Policy{}, nil
}

func (m *mockIAMServiceServer) UpdatePolicy(ctx context.Context, req *iampb.UpdatePolicyRequest) (*iampb.Policy, error) {
	m.called = "UpdatePolicy"
	return &iampb.Policy{}, nil
}

func (m *mockIAMServiceServer) DeletePolicy(ctx context.Context, req *iampb.DeletePolicyRequest) (*iampb.DeletePolicyResponse, error) {
	m.called = "DeletePolicy"
	return &iampb.DeletePolicyResponse{}, nil
}

func (m *mockIAMServiceServer) ListPolicies(ctx context.Context, req *iampb.ListPoliciesRequest) (*iampb.ListPoliciesResponse, error) {
	m.called = "ListPolicies"
	return &iampb.ListPoliciesResponse{}, nil
}

func (m *mockIAMServiceServer) ValidatePolicy(ctx context.Context, req *iampb.ValidatePolicyRequest) (*iampb.ValidatePolicyResponse, error) {
	m.called = "ValidatePolicy"
	return &iampb.ValidatePolicyResponse{}, nil
}

func (m *mockIAMServiceServer) TestPolicy(ctx context.Context, req *iampb.TestPolicyRequest) (*iampb.TestPolicyResponse, error) {
	m.called = "TestPolicy"
	return &iampb.TestPolicyResponse{}, nil
}

func (m *mockIAMServiceServer) CreateAdminAssignment(ctx context.Context, req *iampb.CreateAdminAssignmentRequest) (*iampb.AdminAssignment, error) {
	return &iampb.AdminAssignment{}, nil
}

func (m *mockIAMServiceServer) GetAdminAssignment(ctx context.Context, req *iampb.GetAdminAssignmentRequest) (*iampb.AdminAssignment, error) {
	return &iampb.AdminAssignment{}, nil
}

func (m *mockIAMServiceServer) UpdateAdminAssignment(ctx context.Context, req *iampb.UpdateAdminAssignmentRequest) (*iampb.AdminAssignment, error) {
	return &iampb.AdminAssignment{}, nil
}

func (m *mockIAMServiceServer) DeleteAdminAssignment(ctx context.Context, req *iampb.DeleteAdminAssignmentRequest) (*iampb.DeleteAdminAssignmentResponse, error) {
	return &iampb.DeleteAdminAssignmentResponse{}, nil
}

func (m *mockIAMServiceServer) ListAdminAssignments(ctx context.Context, req *iampb.ListAdminAssignmentsRequest) (*iampb.AdminAssignmentList, error) {
	return &iampb.AdminAssignmentList{}, nil
}

func (m *mockIAMServiceServer) CheckAdminPermission(ctx context.Context, req *iampb.CheckAdminPermissionRequest) (*iampb.CheckAdminPermissionResponse, error) {
	return &iampb.CheckAdminPermissionResponse{}, nil
}

func (m *mockIAMServiceServer) StartImpersonation(ctx context.Context, req *iampb.StartImpersonationRequest) (*iampb.ImpersonationSession, error) {
	return &iampb.ImpersonationSession{}, nil
}

func (m *mockIAMServiceServer) EndImpersonation(ctx context.Context, req *iampb.EndImpersonationRequest) (*iampb.EndImpersonationResponse, error) {
	return &iampb.EndImpersonationResponse{}, nil
}

func (m *mockIAMServiceServer) GetActiveImpersonations(ctx context.Context, req *iampb.GetActiveImpersonationsRequest) (*iampb.ImpersonationSessionList, error) {
	return &iampb.ImpersonationSessionList{}, nil
}

func (m *mockIAMServiceServer) GrantConsent(ctx context.Context, req *iampb.GrantConsentRequest) (*iampb.Consent, error) {
	return &iampb.Consent{}, nil
}

func (m *mockIAMServiceServer) WithdrawConsent(ctx context.Context, req *iampb.WithdrawConsentRequest) (*iampb.WithdrawConsentResponse, error) {
	return &iampb.WithdrawConsentResponse{}, nil
}

func (m *mockIAMServiceServer) GetConsent(ctx context.Context, req *iampb.GetConsentRequest) (*iampb.Consent, error) {
	return &iampb.Consent{}, nil
}

func (m *mockIAMServiceServer) ListUserConsents(ctx context.Context, req *iampb.ListUserConsentsRequest) (*iampb.ConsentList, error) {
	return &iampb.ConsentList{}, nil
}

func (m *mockIAMServiceServer) RequestExport(ctx context.Context, req *iampb.RequestExportRequest) (*iampb.DataExportRequest, error) {
	return &iampb.DataExportRequest{}, nil
}

func (m *mockIAMServiceServer) GetExportStatus(ctx context.Context, req *iampb.GetExportStatusRequest) (*iampb.DataExportRequest, error) {
	return &iampb.DataExportRequest{}, nil
}

func (m *mockIAMServiceServer) GenerateExport(ctx context.Context, req *iampb.GenerateExportRequest) (*iampb.UserDataExport, error) {
	return &iampb.UserDataExport{}, nil
}

func (m *mockIAMServiceServer) RequestDeletion(ctx context.Context, req *iampb.RequestDeletionRequest) (*iampb.DataDeletionRequest, error) {
	return &iampb.DataDeletionRequest{}, nil
}

func (m *mockIAMServiceServer) CancelDeletion(ctx context.Context, req *iampb.CancelDeletionRequest) (*iampb.CancelDeletionResponse, error) {
	return &iampb.CancelDeletionResponse{}, nil
}

func (m *mockIAMServiceServer) ProcessDeletion(ctx context.Context, req *iampb.ProcessDeletionRequest) (*iampb.DeletionSummary, error) {
	return &iampb.DeletionSummary{}, nil
}

func (m *mockIAMServiceServer) GetDeletionStatus(ctx context.Context, req *iampb.GetDeletionStatusRequest) (*iampb.DataDeletionRequest, error) {
	return &iampb.DataDeletionRequest{}, nil
}

// TestNewIAMServiceClientAdapter verifies adapter construction.
func TestNewIAMServiceClientAdapter(t *testing.T) {
	client := NewIAMServiceClientAdapter(&mockIAMServiceServer{})
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

// TestIAMServiceClientAdapter_AllOps exercises all adapter delegation methods.
func TestIAMServiceClientAdapter_AllOps(t *testing.T) {
	server := &mockIAMServiceServer{}
	client := NewIAMServiceClientAdapter(server)
	ctx := context.Background()

	ops := []struct {
		name string
		fn   func() error
	}{
		{"CreateTenant", func() error { _, err := client.CreateTenant(ctx, &iampb.CreateTenantRequest{}); return err }},
		{"GetTenant", func() error { _, err := client.GetTenant(ctx, &iampb.GetTenantRequest{}); return err }},
		{"UpdateTenant", func() error { _, err := client.UpdateTenant(ctx, &iampb.UpdateTenantRequest{}); return err }},
		{"DeleteTenant", func() error { _, err := client.DeleteTenant(ctx, &iampb.DeleteTenantRequest{}); return err }},
		{"ListTenants", func() error { _, err := client.ListTenants(ctx, &iampb.ListTenantsRequest{}); return err }},
		{"CreateUser", func() error { _, err := client.CreateUser(ctx, &iampb.CreateUserRequest{}); return err }},
		{"GetUser", func() error { _, err := client.GetUser(ctx, &iampb.GetUserRequest{}); return err }},
		{"UpdateUser", func() error { _, err := client.UpdateUser(ctx, &iampb.UpdateUserRequest{}); return err }},
		{"DeleteUser", func() error { _, err := client.DeleteUser(ctx, &iampb.DeleteUserRequest{}); return err }},
		{"ListUsers", func() error { _, err := client.ListUsers(ctx, &iampb.ListUsersRequest{}); return err }},
		{"CreateRole", func() error { _, err := client.CreateRole(ctx, &iampb.CreateRoleRequest{}); return err }},
		{"GetRole", func() error { _, err := client.GetRole(ctx, &iampb.GetRoleRequest{}); return err }},
		{"UpdateRole", func() error { _, err := client.UpdateRole(ctx, &iampb.UpdateRoleRequest{}); return err }},
		{"DeleteRole", func() error { _, err := client.DeleteRole(ctx, &iampb.DeleteRoleRequest{}); return err }},
		{"ListRoles", func() error { _, err := client.ListRoles(ctx, &iampb.ListRolesRequest{}); return err }},
		{"AssignRole", func() error { _, err := client.AssignRole(ctx, &iampb.AssignRoleRequest{}); return err }},
		{"RevokeRole", func() error { _, err := client.RevokeRole(ctx, &iampb.RevokeRoleRequest{}); return err }},
		{"RegisterApp", func() error { _, err := client.RegisterApp(ctx, &iampb.RegisterAppRequest{}); return err }},
		{"GetApp", func() error { _, err := client.GetApp(ctx, &iampb.GetAppRequest{}); return err }},
		{"UpdateApp", func() error { _, err := client.UpdateApp(ctx, &iampb.UpdateAppRequest{}); return err }},
		{"DeleteApp", func() error { _, err := client.DeleteApp(ctx, &iampb.DeleteAppRequest{}); return err }},
		{"ListApps", func() error { _, err := client.ListApps(ctx, &iampb.ListAppsRequest{}); return err }},
		{"RotateAppSecret", func() error { _, err := client.RotateAppSecret(ctx, &iampb.RotateAppSecretRequest{}); return err }},
		{"CreatePolicy", func() error { _, err := client.CreatePolicy(ctx, &iampb.CreatePolicyRequest{}); return err }},
		{"GetPolicy", func() error { _, err := client.GetPolicy(ctx, &iampb.GetPolicyRequest{}); return err }},
		{"UpdatePolicy", func() error { _, err := client.UpdatePolicy(ctx, &iampb.UpdatePolicyRequest{}); return err }},
		{"DeletePolicy", func() error { _, err := client.DeletePolicy(ctx, &iampb.DeletePolicyRequest{}); return err }},
		{"ListPolicies", func() error { _, err := client.ListPolicies(ctx, &iampb.ListPoliciesRequest{}); return err }},
		{"ValidatePolicy", func() error { _, err := client.ValidatePolicy(ctx, &iampb.ValidatePolicyRequest{}); return err }},
		{"TestPolicy", func() error { _, err := client.TestPolicy(ctx, &iampb.TestPolicyRequest{}); return err }},
		{"CreateAdminAssignment", func() error {
			_, err := client.CreateAdminAssignment(ctx, &iampb.CreateAdminAssignmentRequest{})
			return err
		}},
		{"GetAdminAssignment", func() error { _, err := client.GetAdminAssignment(ctx, &iampb.GetAdminAssignmentRequest{}); return err }},
		{"UpdateAdminAssignment", func() error {
			_, err := client.UpdateAdminAssignment(ctx, &iampb.UpdateAdminAssignmentRequest{})
			return err
		}},
		{"DeleteAdminAssignment", func() error {
			_, err := client.DeleteAdminAssignment(ctx, &iampb.DeleteAdminAssignmentRequest{})
			return err
		}},
		{"ListAdminAssignments", func() error {
			_, err := client.ListAdminAssignments(ctx, &iampb.ListAdminAssignmentsRequest{})
			return err
		}},
		{"CheckAdminPermission", func() error {
			_, err := client.CheckAdminPermission(ctx, &iampb.CheckAdminPermissionRequest{})
			return err
		}},
		{"StartImpersonation", func() error { _, err := client.StartImpersonation(ctx, &iampb.StartImpersonationRequest{}); return err }},
		{"EndImpersonation", func() error { _, err := client.EndImpersonation(ctx, &iampb.EndImpersonationRequest{}); return err }},
		{"GetActiveImpersonations", func() error {
			_, err := client.GetActiveImpersonations(ctx, &iampb.GetActiveImpersonationsRequest{})
			return err
		}},
		{"GrantConsent", func() error { _, err := client.GrantConsent(ctx, &iampb.GrantConsentRequest{}); return err }},
		{"WithdrawConsent", func() error { _, err := client.WithdrawConsent(ctx, &iampb.WithdrawConsentRequest{}); return err }},
		{"GetConsent", func() error { _, err := client.GetConsent(ctx, &iampb.GetConsentRequest{}); return err }},
		{"ListUserConsents", func() error { _, err := client.ListUserConsents(ctx, &iampb.ListUserConsentsRequest{}); return err }},
		{"RequestExport", func() error { _, err := client.RequestExport(ctx, &iampb.RequestExportRequest{}); return err }},
		{"GetExportStatus", func() error { _, err := client.GetExportStatus(ctx, &iampb.GetExportStatusRequest{}); return err }},
		{"GenerateExport", func() error { _, err := client.GenerateExport(ctx, &iampb.GenerateExportRequest{}); return err }},
		{"RequestDeletion", func() error { _, err := client.RequestDeletion(ctx, &iampb.RequestDeletionRequest{}); return err }},
		{"CancelDeletion", func() error { _, err := client.CancelDeletion(ctx, &iampb.CancelDeletionRequest{}); return err }},
		{"ProcessDeletion", func() error { _, err := client.ProcessDeletion(ctx, &iampb.ProcessDeletionRequest{}); return err }},
		{"GetDeletionStatus", func() error { _, err := client.GetDeletionStatus(ctx, &iampb.GetDeletionStatusRequest{}); return err }},
	}

	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			if err := op.fn(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// PEP Adapter Tests
// =============================================================================

type mockPEPServiceServer struct {
	iampb.UnimplementedPEPServiceServer
}

func (m *mockPEPServiceServer) Check(ctx context.Context, req *iampb.CheckRequest) (*iampb.CheckResponse, error) {
	return &iampb.CheckResponse{Allowed: true, MatchedPolicy: "test-policy"}, nil
}

func (m *mockPEPServiceServer) CheckBatch(ctx context.Context, req *iampb.CheckBatchRequest) (*iampb.CheckBatchResponse, error) {
	return &iampb.CheckBatchResponse{Results: []bool{true, false}}, nil
}

// TestNewPEPServiceClientAdapter verifies PEP adapter construction and delegation.
func TestNewPEPServiceClientAdapter(t *testing.T) {
	server := &mockPEPServiceServer{}
	client := NewPEPServiceClientAdapter(server)
	ctx := context.Background()

	t.Run("Check", func(t *testing.T) {
		resp, err := client.Check(ctx, &iampb.CheckRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.GetAllowed() {
			t.Error("expected allowed=true")
		}
	})

	t.Run("CheckBatch", func(t *testing.T) {
		resp, err := client.CheckBatch(ctx, &iampb.CheckBatchRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.GetResults()) != 2 {
			t.Errorf("expected 2 results, got %d", len(resp.GetResults()))
		}
	})

	t.Run("Subscribe returns streaming not supported", func(t *testing.T) {
		_, err := client.Subscribe(ctx, &iampb.SubscribeRequest{})
		if _, ok := err.(ErrStreamingNotSupported); !ok {
			t.Errorf("expected ErrStreamingNotSupported, got %T: %v", err, err)
		}
	})
}

// TestErrStreamingNotSupported_Error verifies the error message.
func TestErrStreamingNotSupported_Error(t *testing.T) {
	err := ErrStreamingNotSupported{}
	if err.Error() != "streaming RPCs are not supported by in-process adapters" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// TestErrPEPClientNotAvailable_Error verifies the error message.
func TestErrPEPClientNotAvailable_Error(t *testing.T) {
	err := ErrPEPClientNotAvailable{}
	if err.Error() != "PEP client is not available" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// =============================================================================
// SDK PEP Client Adapter Tests
// =============================================================================

// TestNewSDKPEPClientAdapter_NilClient verifies nil client returns nil.
func TestNewSDKPEPClientAdapter_NilClient(t *testing.T) {
	client := NewSDKPEPClientAdapter(nil)
	if client != nil {
		t.Error("expected nil for nil input")
	}
}

// TestSDKPEPClientAdapter_Subscribe verifies streaming is not supported.
func TestSDKPEPClientAdapter_Subscribe(t *testing.T) {
	adapter := &SDKPEPClientAdapter{client: &mockSDKPEPClient{}}
	_, err := adapter.Subscribe(context.Background(), &iampb.SubscribeRequest{})
	if _, ok := err.(ErrStreamingNotSupported); !ok {
		t.Errorf("expected ErrStreamingNotSupported, got %T: %v", err, err)
	}
}

// TestSDKPEPClientAdapter_Check_NilClient verifies nil client error.
func TestSDKPEPClientAdapter_Check_NilClient(t *testing.T) {
	adapter := &SDKPEPClientAdapter{client: nil}
	_, err := adapter.Check(context.Background(), &iampb.CheckRequest{})
	if _, ok := err.(ErrPEPClientNotAvailable); !ok {
		t.Errorf("expected ErrPEPClientNotAvailable, got %T: %v", err, err)
	}
}

// TestSDKPEPClientAdapter_CheckBatch_NilClient verifies nil client error.
func TestSDKPEPClientAdapter_CheckBatch_NilClient(t *testing.T) {
	adapter := &SDKPEPClientAdapter{client: nil}
	_, err := adapter.CheckBatch(context.Background(), &iampb.CheckBatchRequest{})
	if _, ok := err.(ErrPEPClientNotAvailable); !ok {
		t.Errorf("expected ErrPEPClientNotAvailable, got %T: %v", err, err)
	}
}

// TestSDKPEPClientAdapter_Check_Success verifies successful check delegation.
func TestSDKPEPClientAdapter_Check_Success(t *testing.T) {
	mock := &mockSDKPEPClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{Allowed: true, MatchedPolicy: "policy-1"}, nil
		},
	}
	adapter := &SDKPEPClientAdapter{client: mock}
	resp, err := adapter.Check(context.Background(), &iampb.CheckRequest{
		Subject:  &iampb.Subject{Id: "user-1", TenantId: "t1", Roles: []string{"admin"}, Groups: []string{"ops"}, Attributes: map[string]string{"dept": "eng"}},
		Action:   "read",
		Resource: "resource-1",
		Context:  map[string]string{"ip": "10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetAllowed() {
		t.Error("expected allowed=true")
	}
}

// TestSDKPEPClientAdapter_Check_Error verifies error propagation.
func TestSDKPEPClientAdapter_Check_Error(t *testing.T) {
	mock := &mockSDKPEPClient{
		checkFunc: func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return nil, errors.New("check failed")
		},
	}
	adapter := &SDKPEPClientAdapter{client: mock}
	_, err := adapter.Check(context.Background(), &iampb.CheckRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestSDKPEPClientAdapter_CheckBatch_Success verifies successful batch check.
func TestSDKPEPClientAdapter_CheckBatch_Success(t *testing.T) {
	mock := &mockSDKPEPClient{
		checkBatchFunc: func(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
			results := make([]sdkiam.CheckResponse, len(req.Requests))
			for i := range req.Requests {
				results[i] = sdkiam.CheckResponse{Allowed: i == 0}
			}
			return &sdkiam.CheckBatchResponse{Results: results, TotalEvaluationTimeNs: 1000}, nil
		},
	}
	adapter := &SDKPEPClientAdapter{client: mock}
	resp, err := adapter.CheckBatch(context.Background(), &iampb.CheckBatchRequest{
		Subject:   &iampb.Subject{Id: "user-1", TenantId: "t1", Attributes: map[string]string{"dept": "eng"}},
		Action:    "read",
		Resources: []string{"resource-1", "resource-2"},
		Context:   map[string]string{"ip": "10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetResults()) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.GetResults()))
	}
}

// TestConvertProtoCheckRequestToSDK_Nil verifies nil input handling.
func TestConvertProtoCheckRequestToSDK_Nil(t *testing.T) {
	if convertProtoCheckRequestToSDK(nil) != nil {
		t.Error("expected nil")
	}
}

// TestConvertSDKCheckResponseToProto_Nil verifies nil input handling.
func TestConvertSDKCheckResponseToProto_Nil(t *testing.T) {
	if convertSDKCheckResponseToProto(nil) != nil {
		t.Error("expected nil")
	}
}

// TestConvertProtoCheckBatchRequestToSDK_Nil verifies nil input handling.
func TestConvertProtoCheckBatchRequestToSDK_Nil(t *testing.T) {
	if convertProtoCheckBatchRequestToSDK(nil) != nil {
		t.Error("expected nil")
	}
}

// TestConvertSDKCheckBatchResponseToProto_Nil verifies nil input handling.
func TestConvertSDKCheckBatchResponseToProto_Nil(t *testing.T) {
	if convertSDKCheckBatchResponseToProto(nil) != nil {
		t.Error("expected nil")
	}
}

// =============================================================================
// Mock SDK PEP Client
// =============================================================================

type mockSDKPEPClient struct {
	checkFunc      func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error)
	checkBatchFunc func(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error)
}

func (m *mockSDKPEPClient) Check(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	if m.checkFunc != nil {
		return m.checkFunc(ctx, req)
	}
	return &sdkiam.CheckResponse{}, nil
}

func (m *mockSDKPEPClient) CheckBatch(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
	if m.checkBatchFunc != nil {
		return m.checkBatchFunc(ctx, req)
	}
	return &sdkiam.CheckBatchResponse{}, nil
}
