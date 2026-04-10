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

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// Mock gRPC clients for testing

type mockIAMClient struct {
	iampb.IAMServiceClient

	// User methods
	createUserFn func(ctx context.Context, req *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error)
	listUsersFn  func(ctx context.Context, req *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error)
	getUserFn    func(ctx context.Context, req *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error)
	updateUserFn func(ctx context.Context, req *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error)
	deleteUserFn func(ctx context.Context, req *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error)
	assignRoleFn func(ctx context.Context, req *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error)
	revokeRoleFn func(ctx context.Context, req *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error)

	// Group methods
	createGroupFn         func(ctx context.Context, req *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error)
	listGroupsFn          func(ctx context.Context, req *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error)
	getGroupFn            func(ctx context.Context, req *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error)
	updateGroupFn         func(ctx context.Context, req *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error)
	deleteGroupFn         func(ctx context.Context, req *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error)
	addUserToGroupFn      func(ctx context.Context, req *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error)
	removeUserFromGroupFn func(ctx context.Context, req *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error)

	// Role methods
	createRoleFn func(ctx context.Context, req *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error)
	listRolesFn  func(ctx context.Context, req *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error)
	getRoleFn    func(ctx context.Context, req *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error)
	updateRoleFn func(ctx context.Context, req *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error)
	deleteRoleFn func(ctx context.Context, req *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error)

	// Tenant methods
	createTenantFn func(ctx context.Context, req *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error)
	listTenantsFn  func(ctx context.Context, req *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error)
	getTenantFn    func(ctx context.Context, req *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error)
	updateTenantFn func(ctx context.Context, req *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error)
	deleteTenantFn func(ctx context.Context, req *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error)

	// Policy methods
	createPolicyFn   func(ctx context.Context, req *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error)
	listPoliciesFn   func(ctx context.Context, req *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error)
	getPolicyFn      func(ctx context.Context, req *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error)
	updatePolicyFn   func(ctx context.Context, req *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error)
	deletePolicyFn   func(ctx context.Context, req *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error)
	validatePolicyFn func(ctx context.Context, req *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error)
	testPolicyFn     func(ctx context.Context, req *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error)

	// App methods
	registerAppFn     func(ctx context.Context, req *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error)
	listAppsFn        func(ctx context.Context, req *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error)
	getAppFn          func(ctx context.Context, req *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error)
	updateAppFn       func(ctx context.Context, req *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error)
	deleteAppFn       func(ctx context.Context, req *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error)
	rotateAppSecretFn func(ctx context.Context, req *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error)
}

func (m *mockIAMClient) CreateUser(ctx context.Context, req *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.createUserFn != nil {
		return m.createUserFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) ListUsers(ctx context.Context, req *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
	if m.listUsersFn != nil {
		return m.listUsersFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) GetUser(ctx context.Context, req *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.getUserFn != nil {
		return m.getUserFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) UpdateUser(ctx context.Context, req *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
	if m.updateUserFn != nil {
		return m.updateUserFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) DeleteUser(ctx context.Context, req *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
	if m.deleteUserFn != nil {
		return m.deleteUserFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) AssignRole(ctx context.Context, req *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
	if m.assignRoleFn != nil {
		return m.assignRoleFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) RevokeRole(ctx context.Context, req *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
	if m.revokeRoleFn != nil {
		return m.revokeRoleFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) CreateGroup(ctx context.Context, req *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.createGroupFn != nil {
		return m.createGroupFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) ListGroups(ctx context.Context, req *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
	if m.listGroupsFn != nil {
		return m.listGroupsFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) GetGroup(ctx context.Context, req *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.getGroupFn != nil {
		return m.getGroupFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) UpdateGroup(ctx context.Context, req *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
	if m.updateGroupFn != nil {
		return m.updateGroupFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) DeleteGroup(ctx context.Context, req *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
	if m.deleteGroupFn != nil {
		return m.deleteGroupFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) AddUserToGroup(ctx context.Context, req *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
	if m.addUserToGroupFn != nil {
		return m.addUserToGroupFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) RemoveUserFromGroup(ctx context.Context, req *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
	if m.removeUserFromGroupFn != nil {
		return m.removeUserFromGroupFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) CreateRole(ctx context.Context, req *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.createRoleFn != nil {
		return m.createRoleFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) ListRoles(ctx context.Context, req *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
	if m.listRolesFn != nil {
		return m.listRolesFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) GetRole(ctx context.Context, req *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.getRoleFn != nil {
		return m.getRoleFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) UpdateRole(ctx context.Context, req *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
	if m.updateRoleFn != nil {
		return m.updateRoleFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) DeleteRole(ctx context.Context, req *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
	if m.deleteRoleFn != nil {
		return m.deleteRoleFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) CreateTenant(ctx context.Context, req *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.createTenantFn != nil {
		return m.createTenantFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) ListTenants(ctx context.Context, req *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
	if m.listTenantsFn != nil {
		return m.listTenantsFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) GetTenant(ctx context.Context, req *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.getTenantFn != nil {
		return m.getTenantFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) UpdateTenant(ctx context.Context, req *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
	if m.updateTenantFn != nil {
		return m.updateTenantFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) DeleteTenant(ctx context.Context, req *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error) {
	if m.deleteTenantFn != nil {
		return m.deleteTenantFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) CreatePolicy(ctx context.Context, req *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	if m.createPolicyFn != nil {
		return m.createPolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) ListPolicies(ctx context.Context, req *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error) {
	if m.listPoliciesFn != nil {
		return m.listPoliciesFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) GetPolicy(ctx context.Context, req *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	if m.getPolicyFn != nil {
		return m.getPolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) UpdatePolicy(ctx context.Context, req *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
	if m.updatePolicyFn != nil {
		return m.updatePolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) DeletePolicy(ctx context.Context, req *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error) {
	if m.deletePolicyFn != nil {
		return m.deletePolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) ValidatePolicy(ctx context.Context, req *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
	if m.validatePolicyFn != nil {
		return m.validatePolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) TestPolicy(ctx context.Context, req *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error) {
	if m.testPolicyFn != nil {
		return m.testPolicyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) RegisterApp(ctx context.Context, req *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.registerAppFn != nil {
		return m.registerAppFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) ListApps(ctx context.Context, req *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error) {
	if m.listAppsFn != nil {
		return m.listAppsFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) GetApp(ctx context.Context, req *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.getAppFn != nil {
		return m.getAppFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) UpdateApp(ctx context.Context, req *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.updateAppFn != nil {
		return m.updateAppFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) DeleteApp(ctx context.Context, req *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error) {
	if m.deleteAppFn != nil {
		return m.deleteAppFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIAMClient) RotateAppSecret(ctx context.Context, req *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
	if m.rotateAppSecretFn != nil {
		return m.rotateAppSecretFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type mockPEPClient struct {
	iampb.PEPServiceClient
}

// Mock HttpWriter for response handling
type mockHttpWriter struct {
	lastStatus  int
	lastPayload interface{}
	lastError   error
}

func (m *mockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusOK
	m.lastPayload = payload
	w.WriteHeader(http.StatusOK)
	resp := response.WebServiceResponse{Code: 200, Success: true, Payload: payload}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Success200(w, r, payload)
}

func (m *mockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastPayload = payload
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusOK
	m.lastError = err
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusBadRequest
	m.lastError = err
	w.WriteHeader(http.StatusBadRequest)
	resp := response.WebServiceResponse{Code: 400, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusUnauthorized
	m.lastError = err
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.lastStatus = http.StatusForbidden
	m.lastError = err
	m.lastPayload = payload
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
	resp := response.WebServiceResponse{Code: 404, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusInternalServerError
	m.lastError = err
	w.WriteHeader(http.StatusInternalServerError)
	resp := response.WebServiceResponse{Code: 500, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

// Helper functions for tests

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func newTestHandlers(iamClient *mockIAMClient, pepClient *mockPEPClient) (*IAMHandlers, *mockHttpWriter) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewIAMHandlers(logger, iamClient, pepClient, writer)
	return handlers, writer
}

func createRequestWithVars(method, path string, body interface{}, vars map[string]string) *http.Request {
	var reqBody bytes.Buffer
	if body != nil {
		json.NewEncoder(&reqBody).Encode(body)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}

	return req
}

// Tests for NewIAMHandlers

func TestNewIAMHandlers(t *testing.T) {
	logger := newTestLogger()
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	handlers := NewIAMHandlers(logger, iamClient, pepClient, writer)

	require.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
	assert.NotNil(t, handlers.iamClient)
	assert.NotNil(t, handlers.pepClient)
	assert.NotNil(t, handlers.respWriter)
}

// Tests for User Handlers

func TestCreateUser_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		createUserFn: func(ctx context.Context, req *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return &iampb.User{
				Id:       "user-123",
				TenantId: req.TenantId,
				Email:    req.Email,
				Name:     req.Name,
				Roles:    req.Roles,
				Groups:   req.Groups,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateUserRequest{
		Email:  "test@example.com",
		Name:   "Test User",
		Roles:  []string{"admin"},
		Groups: []string{"engineering"},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/users", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreateUser(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(UserResponse)
	require.True(t, ok)
	assert.Equal(t, "user-123", payload.ID)
	assert.Equal(t, "test@example.com", payload.Email)
}

func TestCreateUser_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := CreateUserRequest{Email: "test@example.com"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//users", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.CreateUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingTenantID)
	assert.True(t, ok)
}

func TestCreateUser_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants/tenant-1/users", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestCreateUser_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		createUserFn: func(ctx context.Context, req *iampb.CreateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateUserRequest{Email: "test@example.com"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/users", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreateUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListUsers_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		listUsersFn: func(ctx context.Context, req *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{Id: "user-1", TenantId: req.TenantId, Email: "user1@example.com"},
					{Id: "user-2", TenantId: req.TenantId, Email: "user2@example.com"},
				},
				Total: 2,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/users", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListUsers(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListUsersResponse)
	require.True(t, ok)
	assert.Len(t, payload.Users, 2)
	assert.Equal(t, int64(2), payload.Total)
}

func TestListUsers_WithPagination(t *testing.T) {
	iamClient := &mockIAMClient{
		listUsersFn: func(ctx context.Context, req *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
			assert.Equal(t, int32(25), req.Limit)
			assert.Equal(t, int32(50), req.Offset)
			return &iampb.ListUsersResponse{
				Users: []*iampb.User{
					{Id: "user-51", Email: "user51@example.com"},
				},
				Total: 100,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/tenants/tenant-1/users?limit=25&offset=50", nil)
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListUsers(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListUsersResponse)
	require.True(t, ok)
	assert.Equal(t, int32(25), payload.Limit)
	assert.Equal(t, int32(50), payload.Offset)
}

func TestListUsers_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//users", nil, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.ListUsers(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetUser_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		getUserFn: func(ctx context.Context, req *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return &iampb.User{
				Id:          req.UserId,
				TenantId:    req.TenantId,
				Email:       "test@example.com",
				Name:        "Test User",
				MfaVerified: true,
				CreatedAt:   timestamppb.Now(),
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/users/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "user-123"})
	rec := httptest.NewRecorder()

	handlers.GetUser(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(UserResponse)
	require.True(t, ok)
	assert.Equal(t, "user-123", payload.ID)
	assert.True(t, payload.MFAVerified)
}

func TestGetUser_NotFound(t *testing.T) {
	iamClient := &mockIAMClient{
		getUserFn: func(ctx context.Context, req *iampb.GetUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/users/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetUser(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestGetUser_MissingUserID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/users/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.GetUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingUserID)
	assert.True(t, ok)
}

func TestUpdateUser_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		updateUserFn: func(ctx context.Context, req *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return &iampb.User{
				Id:       req.UserId,
				TenantId: req.TenantId,
				Email:    req.Email,
				Name:     req.Name,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateUserRequest{Name: "Updated Name", Email: "updated@example.com"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/users/user-123", body, map[string]string{"tenant": "tenant-1", "id": "user-123"})
	rec := httptest.NewRecorder()

	handlers.UpdateUser(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(UserResponse)
	require.True(t, ok)
	assert.Equal(t, "Updated Name", payload.Name)
}

func TestUpdateUser_NotFound(t *testing.T) {
	iamClient := &mockIAMClient{
		updateUserFn: func(ctx context.Context, req *iampb.UpdateUserRequest, opts ...grpc.CallOption) (*iampb.User, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateUserRequest{Name: "Updated Name"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/users/nonexistent", body, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.UpdateUser(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteUser_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteUserFn: func(ctx context.Context, req *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
			return &iampb.DeleteUserResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "user-123"})
	rec := httptest.NewRecorder()

	handlers.DeleteUser(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(SuccessResponse)
	require.True(t, ok)
	assert.True(t, payload.Success)
}

func TestDeleteUser_NotFound(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteUserFn: func(ctx context.Context, req *iampb.DeleteUserRequest, opts ...grpc.CallOption) (*iampb.DeleteUserResponse, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteUser(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestAssignUserRole_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		assignRoleFn: func(ctx context.Context, req *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
			return &iampb.AssignRoleResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/admin", nil, map[string]string{"tenant": "tenant-1", "id": "user-123", "role": "admin"})
	rec := httptest.NewRecorder()

	handlers.AssignUserRole(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(SuccessResponse)
	require.True(t, ok)
	assert.True(t, payload.Success)
}

func TestAssignUserRole_MissingRole(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/", nil, map[string]string{"tenant": "tenant-1", "id": "user-123", "role": ""})
	rec := httptest.NewRecorder()

	handlers.AssignUserRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestAssignUserRole_Error(t *testing.T) {
	iamClient := &mockIAMClient{
		assignRoleFn: func(ctx context.Context, req *iampb.AssignRoleRequest, opts ...grpc.CallOption) (*iampb.AssignRoleResponse, error) {
			return nil, status.Error(codes.NotFound, "role not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "user-123", "role": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.AssignUserRole(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestRevokeUserRole_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		revokeRoleFn: func(ctx context.Context, req *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
			return &iampb.RevokeRoleResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/admin", nil, map[string]string{"tenant": "tenant-1", "id": "user-123", "role": "admin"})
	rec := httptest.NewRecorder()

	handlers.RevokeUserRole(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestRevokeUserRole_Error(t *testing.T) {
	iamClient := &mockIAMClient{
		revokeRoleFn: func(ctx context.Context, req *iampb.RevokeRoleRequest, opts ...grpc.CallOption) (*iampb.RevokeRoleResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "role not assigned")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/admin", nil, map[string]string{"tenant": "tenant-1", "id": "user-123", "role": "admin"})
	rec := httptest.NewRecorder()

	handlers.RevokeUserRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// Tests for Group Handlers

func TestCreateGroup_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		createGroupFn: func(ctx context.Context, req *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return &iampb.Group{
				Id:          req.Id,
				TenantId:    req.TenantId,
				Name:        req.Name,
				Description: req.Description,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateGroupRequest{ID: "engineering", Name: "Engineering", Description: "Engineering team"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreateGroup(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GroupResponse)
	require.True(t, ok)
	assert.Equal(t, "engineering", payload.ID)
}

func TestListGroups_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		listGroupsFn: func(ctx context.Context, req *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
			return &iampb.ListGroupsResponse{
				Groups: []*iampb.Group{
					{Id: "group-1", Name: "Group 1"},
					{Id: "group-2", Name: "Group 2"},
				},
				Total: 2,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/groups", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListGroups(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListGroupsResponse)
	require.True(t, ok)
	assert.Len(t, payload.Groups, 2)
}

func TestGetGroup_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		getGroupFn: func(ctx context.Context, req *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return &iampb.Group{
				Id:      req.GroupId,
				Name:    "Engineering",
				Members: []string{"user-1", "user-2"},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/groups/engineering", nil, map[string]string{"tenant": "tenant-1", "id": "engineering"})
	rec := httptest.NewRecorder()

	handlers.GetGroup(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdateGroup_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		updateGroupFn: func(ctx context.Context, req *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return &iampb.Group{
				Id:          req.GroupId,
				Name:        req.Name,
				Description: req.Description,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateGroupRequest{Name: "Updated Group", Description: "Updated description"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/groups/group-1", body, map[string]string{"tenant": "tenant-1", "id": "group-1"})
	rec := httptest.NewRecorder()

	handlers.UpdateGroup(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteGroup_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteGroupFn: func(ctx context.Context, req *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
			return &iampb.DeleteGroupResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/group-1", nil, map[string]string{"tenant": "tenant-1", "id": "group-1"})
	rec := httptest.NewRecorder()

	handlers.DeleteGroup(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddGroupMember_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		addUserToGroupFn: func(ctx context.Context, req *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
			return &iampb.AddUserToGroupResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "group-1", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.AddGroupMember(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddGroupMember_MissingMember(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/", nil, map[string]string{"tenant": "tenant-1", "id": "group-1", "user": ""})
	rec := httptest.NewRecorder()

	handlers.AddGroupMember(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRemoveGroupMember_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		removeUserFromGroupFn: func(ctx context.Context, req *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
			return &iampb.RemoveUserFromGroupResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "group-1", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.RemoveGroupMember(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// Tests for Role Handlers

func TestCreateRole_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		createRoleFn: func(ctx context.Context, req *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return &iampb.Role{
				Id:          req.Id,
				TenantId:    req.TenantId,
				Name:        req.Name,
				Description: req.Description,
				Permissions: req.Permissions,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateRoleRequest{ID: "admin", Name: "Administrator", Permissions: []string{"read", "write"}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/roles", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreateRole(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestListRoles_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		listRolesFn: func(ctx context.Context, req *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
			return &iampb.ListRolesResponse{
				Roles: []*iampb.Role{
					{Id: "admin", Name: "Administrator"},
					{Id: "viewer", Name: "Viewer"},
				},
				Total: 2,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/roles", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListRoles(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetRole_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		getRoleFn: func(ctx context.Context, req *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return &iampb.Role{
				Id:          req.RoleId,
				Name:        "Administrator",
				Permissions: []string{"all"},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/roles/admin", nil, map[string]string{"tenant": "tenant-1", "id": "admin"})
	rec := httptest.NewRecorder()

	handlers.GetRole(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdateRole_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		updateRoleFn: func(ctx context.Context, req *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return &iampb.Role{
				Id:          req.RoleId,
				Name:        req.Name,
				Permissions: req.Permissions,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateRoleRequest{Name: "Updated Role", Permissions: []string{"read"}}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/roles/admin", body, map[string]string{"tenant": "tenant-1", "id": "admin"})
	rec := httptest.NewRecorder()

	handlers.UpdateRole(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRole_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteRoleFn: func(ctx context.Context, req *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
			return &iampb.DeleteRoleResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/roles/admin", nil, map[string]string{"tenant": "tenant-1", "id": "admin"})
	rec := httptest.NewRecorder()

	handlers.DeleteRole(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// Tests for Tenant Handlers

func TestCreateTenant_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		createTenantFn: func(ctx context.Context, req *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
			return &iampb.Tenant{
				Id:   req.Id,
				Name: req.Name,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateTenantRequest{ID: "acme", Name: "Acme Corporation"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTenant(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestCreateTenant_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := CreateTenantRequest{Name: "Acme Corporation"} // Missing ID
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTenant(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateTenant_WithSettings(t *testing.T) {
	iamClient := &mockIAMClient{
		createTenantFn: func(ctx context.Context, req *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
			return &iampb.Tenant{
				Id:       req.Id,
				Name:     req.Name,
				Settings: req.Settings,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateTenantRequest{
		ID:   "acme",
		Name: "Acme Corporation",
		Settings: &TenantSettings{
			MaxUsers:    100,
			MFARequired: true,
		},
	}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTenant(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestListTenants_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		listTenantsFn: func(ctx context.Context, req *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
			return &iampb.ListTenantsResponse{
				Tenants: []*iampb.Tenant{
					{Id: "tenant-1", Name: "Tenant 1"},
					{Id: "tenant-2", Name: "Tenant 2"},
				},
				Total: 2,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListTenants(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetTenant_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		getTenantFn: func(ctx context.Context, req *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
			return &iampb.Tenant{
				Id:   req.Id,
				Name: "Acme Corporation",
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/acme", nil, map[string]string{"tenant": "acme"})
	rec := httptest.NewRecorder()

	handlers.GetTenant(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdateTenant_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		updateTenantFn: func(ctx context.Context, req *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
			return &iampb.Tenant{
				Id:   req.Id,
				Name: req.Name,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateTenantRequest{Name: "Updated Corporation"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/acme", body, map[string]string{"tenant": "acme"})
	rec := httptest.NewRecorder()

	handlers.UpdateTenant(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteTenant_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteTenantFn: func(ctx context.Context, req *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error) {
			return &iampb.DeleteTenantResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/acme", nil, map[string]string{"tenant": "acme"})
	rec := httptest.NewRecorder()

	handlers.DeleteTenant(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// Tests for Policy Handlers

func TestCreatePolicy_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		createPolicyFn: func(ctx context.Context, req *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
			return &iampb.Policy{
				Name:        req.Name,
				TenantId:    req.TenantId,
				Description: req.Description,
				Priority:    req.Priority,
				SpecYaml:    req.SpecYaml,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreatePolicyRequest{
		Name:        "admin-policy",
		Description: "Admin access policy",
		Priority:    100,
		SpecYAML:    "rules:\n  - effect: allow",
	}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreatePolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestCreatePolicy_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := CreatePolicyRequest{SpecYAML: "rules: []"} // Missing Name
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreatePolicy_MissingSpec(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := CreatePolicyRequest{Name: "test-policy"} // Missing SpecYAML
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListPolicies_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		listPoliciesFn: func(ctx context.Context, req *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error) {
			return &iampb.ListPoliciesResponse{
				Policies: []*iampb.Policy{
					{Name: "policy-1", Priority: 100},
					{Name: "policy-2", Priority: 200},
				},
				Total: 2,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/policies", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListPolicies(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetPolicy_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		getPolicyFn: func(ctx context.Context, req *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
			return &iampb.Policy{
				Name:     req.PolicyName,
				TenantId: req.TenantId,
				Priority: 100,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/policies/admin-policy", nil, map[string]string{"tenant": "tenant-1", "id": "admin-policy"})
	rec := httptest.NewRecorder()

	handlers.GetPolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdatePolicy_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		updatePolicyFn: func(ctx context.Context, req *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
			return &iampb.Policy{
				Name:        req.PolicyName,
				Description: req.Description,
				Priority:    req.Priority,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdatePolicyRequest{Description: "Updated policy", Priority: 200}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/policies/admin-policy", body, map[string]string{"tenant": "tenant-1", "id": "admin-policy"})
	rec := httptest.NewRecorder()

	handlers.UpdatePolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeletePolicy_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		deletePolicyFn: func(ctx context.Context, req *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error) {
			return &iampb.DeletePolicyResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/policies/admin-policy", nil, map[string]string{"tenant": "tenant-1", "id": "admin-policy"})
	rec := httptest.NewRecorder()

	handlers.DeletePolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestValidatePolicy_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		validatePolicyFn: func(ctx context.Context, req *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
			return &iampb.ValidatePolicyResponse{
				Valid:  true,
				Errors: nil,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := ValidatePolicyRequest{SpecYAML: "rules:\n  - effect: allow"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/validate", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ValidatePolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestValidatePolicy_MissingSpec(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := ValidatePolicyRequest{} // Missing SpecYAML
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/validate", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ValidatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestValidatePolicy_Invalid(t *testing.T) {
	iamClient := &mockIAMClient{
		validatePolicyFn: func(ctx context.Context, req *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
			return &iampb.ValidatePolicyResponse{
				Valid:  false,
				Errors: []string{"invalid syntax", "missing rules"},
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := ValidatePolicyRequest{SpecYAML: "invalid"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/validate", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ValidatePolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ValidatePolicyResponse)
	require.True(t, ok)
	assert.False(t, payload.Valid)
	assert.Len(t, payload.Errors, 2)
}

func TestTestPolicy_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		testPolicyFn: func(ctx context.Context, req *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error) {
			return &iampb.TestPolicyResponse{
				Allowed:          true,
				MatchedPolicy:    "admin-policy",
				MatchedRule:      "rule-1",
				EvaluationTimeNs: 1500,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := TestPolicyRequest{
		SubjectID: "user-123",
		Action:    "write",
		Resource:  "documents/*",
		Roles:     []string{"admin"},
	}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.TestPolicy(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(TestPolicyResponse)
	require.True(t, ok)
	assert.True(t, payload.Allowed)
	assert.Equal(t, "admin-policy", payload.MatchedPolicy)
}

func TestTestPolicy_MissingSubjectID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := TestPolicyRequest{Action: "read", Resource: "files/*"} // Missing SubjectID
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.TestPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestTestPolicy_MissingAction(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := TestPolicyRequest{SubjectID: "user-123", Resource: "files/*"} // Missing Action
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.TestPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestTestPolicy_MissingResource(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := TestPolicyRequest{SubjectID: "user-123", Action: "read"} // Missing Resource
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.TestPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// Tests for App Handlers

func TestRegisterApp_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		registerAppFn: func(ctx context.Context, req *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return &iampb.Application{
				ClientId:     "client-abc-123",
				ClientSecret: "secret-xyz",
				TenantId:     req.TenantId,
				Name:         req.Name,
				RedirectUris: req.RedirectUris,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := RegisterAppRequest{
		Name:         "My App",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.RegisterApp(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(AppResponse)
	require.True(t, ok)
	assert.NotEmpty(t, payload.ClientID)
	assert.NotEmpty(t, payload.ClientSecret)
}

func TestRegisterApp_MissingName(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := RegisterAppRequest{RedirectURIs: []string{"https://app.example.com"}} // Missing Name
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.RegisterApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListApps_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		listAppsFn: func(ctx context.Context, req *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error) {
			return &iampb.ListAppsResponse{
				Apps: []*iampb.Application{
					{ClientId: "app-1", Name: "App 1"},
					{ClientId: "app-2", Name: "App 2"},
				},
				Total: 2,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/apps", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListApps(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestGetApp_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		getAppFn: func(ctx context.Context, req *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return &iampb.Application{
				ClientId: req.ClientId,
				TenantId: req.TenantId,
				Name:     "My App",
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/apps/client-abc", nil, map[string]string{"tenant": "tenant-1", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.GetApp(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestUpdateApp_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		updateAppFn: func(ctx context.Context, req *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return &iampb.Application{
				ClientId: req.ClientId,
				Name:     req.Name,
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateAppRequest{Name: "Updated App"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/apps/client-abc", body, map[string]string{"tenant": "tenant-1", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.UpdateApp(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteApp_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteAppFn: func(ctx context.Context, req *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error) {
			return &iampb.DeleteAppResponse{Success: true}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/apps/client-abc", nil, map[string]string{"tenant": "tenant-1", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.DeleteApp(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestRotateAppSecret_Success(t *testing.T) {
	iamClient := &mockIAMClient{
		rotateAppSecretFn: func(ctx context.Context, req *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return &iampb.Application{
				ClientId:     req.ClientId,
				Name:         "My App",
				ClientSecret: "new-secret-xyz",
			}, nil
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps/client-abc/rotate", nil, map[string]string{"tenant": "tenant-1", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.RotateAppSecret(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(RotateSecretResponse)
	require.True(t, ok)
	assert.Equal(t, "new-secret-xyz", payload.ClientSecret)
}

func TestRotateAppSecret_MissingAppID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps//rotate", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.RotateAppSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// Tests for helper methods

func TestGetPaginationParams_Defaults(t *testing.T) {
	handlers, _ := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, defaultLimit, limit)
	assert.Equal(t, defaultOffset, offset)
}

func TestGetPaginationParams_CustomValues(t *testing.T) {
	handlers, _ := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test?limit=100&offset=50", nil)
	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, int32(100), limit)
	assert.Equal(t, int32(50), offset)
}

func TestGetPaginationParams_ExceedsMaxLimit(t *testing.T) {
	handlers, _ := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test?limit=5000", nil)
	limit, _ := handlers.getPaginationParams(req)

	assert.Equal(t, maxLimit, limit)
}

func TestGetPaginationParams_NegativeLimit(t *testing.T) {
	handlers, _ := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test?limit=-10", nil)
	limit, _ := handlers.getPaginationParams(req)

	assert.Equal(t, defaultLimit, limit)
}

func TestGetPaginationParams_NegativeOffset(t *testing.T) {
	handlers, _ := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test?offset=-10", nil)
	_, offset := handlers.getPaginationParams(req)

	assert.Equal(t, defaultOffset, offset)
}

func TestGetPaginationParams_InvalidValues(t *testing.T) {
	handlers, _ := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test?limit=abc&offset=xyz", nil)
	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, defaultLimit, limit)
	assert.Equal(t, defaultOffset, offset)
}

// Tests for GRPC error handling

func TestHandleGRPCError_NotFound(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleGRPCError(rec, req, status.Error(codes.NotFound, "not found"))

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestHandleGRPCError_InvalidArgument(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleGRPCError(rec, req, status.Error(codes.InvalidArgument, "invalid"))

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestHandleGRPCError_PermissionDenied(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleGRPCError(rec, req, status.Error(codes.PermissionDenied, "denied"))

	assert.Equal(t, http.StatusUnauthorized, writer.lastStatus)
}

func TestHandleGRPCError_Unauthenticated(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleGRPCError(rec, req, status.Error(codes.Unauthenticated, "unauthenticated"))

	assert.Equal(t, http.StatusUnauthorized, writer.lastStatus)
}

func TestHandleGRPCError_AlreadyExists(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleGRPCError(rec, req, status.Error(codes.AlreadyExists, "exists"))

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestHandleGRPCError_Internal(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleGRPCError(rec, req, status.Error(codes.Internal, "internal error"))

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestHandleGRPCError_NonGRPCError(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleGRPCError(rec, req, assert.AnError)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test timeFromTimestamp helper

func TestTimeFromTimestamp_Nil(t *testing.T) {
	result := timeFromTimestamp(nil)
	assert.Nil(t, result)
}

func TestTimeFromTimestamp_Valid(t *testing.T) {
	ts := timestamppb.Now()
	result := timeFromTimestamp(ts)
	require.NotNil(t, result)
	assert.False(t, result.IsZero())
}

// Additional error path tests for User handlers

func TestUpdateUser_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateUserRequest{Name: "Updated Name"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants//users/user-123", body, map[string]string{"tenant": "", "id": "user-123"})
	rec := httptest.NewRecorder()

	handlers.UpdateUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingTenantID)
	assert.True(t, ok)
}

func TestUpdateUser_MissingUserID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateUserRequest{Name: "Updated Name"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/users/", body, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.UpdateUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingUserID)
	assert.True(t, ok)
}

func TestUpdateUser_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/tenants/tenant-1/users/user-123", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1", "id": "user-123"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdateUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestDeleteUser_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants//users/user-123", nil, map[string]string{"tenant": "", "id": "user-123"})
	rec := httptest.NewRecorder()

	handlers.DeleteUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteUser_MissingUserID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestAssignUserRole_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//users/user-123/roles/admin", nil, map[string]string{"tenant": "", "id": "user-123", "role": "admin"})
	rec := httptest.NewRecorder()

	handlers.AssignUserRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestAssignUserRole_MissingUserID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/users//roles/admin", nil, map[string]string{"tenant": "tenant-1", "id": "", "role": "admin"})
	rec := httptest.NewRecorder()

	handlers.AssignUserRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRevokeUserRole_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants//users/user-123/roles/admin", nil, map[string]string{"tenant": "", "id": "user-123", "role": "admin"})
	rec := httptest.NewRecorder()

	handlers.RevokeUserRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRevokeUserRole_MissingUserID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users//roles/admin", nil, map[string]string{"tenant": "tenant-1", "id": "", "role": "admin"})
	rec := httptest.NewRecorder()

	handlers.RevokeUserRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRevokeUserRole_MissingRole(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/", nil, map[string]string{"tenant": "tenant-1", "id": "user-123", "role": ""})
	rec := httptest.NewRecorder()

	handlers.RevokeUserRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// Additional error path tests for Group handlers

func TestCreateGroup_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := CreateGroupRequest{ID: "engineering", Name: "Engineering"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//groups", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.CreateGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateGroup_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateGroup_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		createGroupFn: func(ctx context.Context, req *iampb.CreateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return nil, status.Error(codes.AlreadyExists, "group already exists")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateGroupRequest{ID: "engineering", Name: "Engineering"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreateGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListGroups_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//groups", nil, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.ListGroups(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListGroups_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		listGroupsFn: func(ctx context.Context, req *iampb.ListGroupsRequest, opts ...grpc.CallOption) (*iampb.ListGroupsResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/groups", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListGroups(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetGroup_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//groups/engineering", nil, map[string]string{"tenant": "", "id": "engineering"})
	rec := httptest.NewRecorder()

	handlers.GetGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetGroup_MissingGroupID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/groups/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.GetGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetGroup_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		getGroupFn: func(ctx context.Context, req *iampb.GetGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return nil, status.Error(codes.NotFound, "group not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/groups/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetGroup(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestUpdateGroup_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateGroupRequest{Name: "Updated Group"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants//groups/group-1", body, map[string]string{"tenant": "", "id": "group-1"})
	rec := httptest.NewRecorder()

	handlers.UpdateGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateGroup_MissingGroupID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateGroupRequest{Name: "Updated Group"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/groups/", body, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.UpdateGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateGroup_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/tenants/tenant-1/groups/group-1", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1", "id": "group-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdateGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateGroup_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		updateGroupFn: func(ctx context.Context, req *iampb.UpdateGroupRequest, opts ...grpc.CallOption) (*iampb.Group, error) {
			return nil, status.Error(codes.NotFound, "group not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateGroupRequest{Name: "Updated Group"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/groups/nonexistent", body, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.UpdateGroup(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteGroup_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants//groups/group-1", nil, map[string]string{"tenant": "", "id": "group-1"})
	rec := httptest.NewRecorder()

	handlers.DeleteGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteGroup_MissingGroupID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteGroup(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteGroup_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteGroupFn: func(ctx context.Context, req *iampb.DeleteGroupRequest, opts ...grpc.CallOption) (*iampb.DeleteGroupResponse, error) {
			return nil, status.Error(codes.NotFound, "group not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteGroup(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestAddGroupMember_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//groups/group-1/members/user-123", nil, map[string]string{"tenant": "", "id": "group-1", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.AddGroupMember(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestAddGroupMember_MissingGroupID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups//members/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.AddGroupMember(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestAddGroupMember_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		addUserToGroupFn: func(ctx context.Context, req *iampb.AddUserToGroupRequest, opts ...grpc.CallOption) (*iampb.AddUserToGroupResponse, error) {
			return nil, status.Error(codes.NotFound, "user or group not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "group-1", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.AddGroupMember(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestRemoveGroupMember_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants//groups/group-1/members/user-123", nil, map[string]string{"tenant": "", "id": "group-1", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.RemoveGroupMember(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRemoveGroupMember_MissingGroupID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups//members/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.RemoveGroupMember(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRemoveGroupMember_MissingMember(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/", nil, map[string]string{"tenant": "tenant-1", "id": "group-1", "user": ""})
	rec := httptest.NewRecorder()

	handlers.RemoveGroupMember(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRemoveGroupMember_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		removeUserFromGroupFn: func(ctx context.Context, req *iampb.RemoveUserFromGroupRequest, opts ...grpc.CallOption) (*iampb.RemoveUserFromGroupResponse, error) {
			return nil, status.Error(codes.NotFound, "member not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/user-123", nil, map[string]string{"tenant": "tenant-1", "id": "group-1", "user": "user-123"})
	rec := httptest.NewRecorder()

	handlers.RemoveGroupMember(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Additional error path tests for Role handlers

func TestCreateRole_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := CreateRoleRequest{ID: "admin", Name: "Administrator"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//roles", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.CreateRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateRole_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants/tenant-1/roles", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateRole_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		createRoleFn: func(ctx context.Context, req *iampb.CreateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return nil, status.Error(codes.AlreadyExists, "role already exists")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateRoleRequest{ID: "admin", Name: "Administrator"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/roles", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreateRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListRoles_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//roles", nil, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.ListRoles(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListRoles_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		listRolesFn: func(ctx context.Context, req *iampb.ListRolesRequest, opts ...grpc.CallOption) (*iampb.ListRolesResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/roles", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListRoles(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetRole_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//roles/admin", nil, map[string]string{"tenant": "", "id": "admin"})
	rec := httptest.NewRecorder()

	handlers.GetRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetRole_MissingRoleID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/roles/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.GetRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetRole_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		getRoleFn: func(ctx context.Context, req *iampb.GetRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return nil, status.Error(codes.NotFound, "role not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/roles/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetRole(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestUpdateRole_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateRoleRequest{Name: "Updated Role"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants//roles/admin", body, map[string]string{"tenant": "", "id": "admin"})
	rec := httptest.NewRecorder()

	handlers.UpdateRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateRole_MissingRoleID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateRoleRequest{Name: "Updated Role"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/roles/", body, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.UpdateRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateRole_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/tenants/tenant-1/roles/admin", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1", "id": "admin"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdateRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateRole_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		updateRoleFn: func(ctx context.Context, req *iampb.UpdateRoleRequest, opts ...grpc.CallOption) (*iampb.Role, error) {
			return nil, status.Error(codes.NotFound, "role not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateRoleRequest{Name: "Updated Role"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/roles/nonexistent", body, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.UpdateRole(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteRole_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants//roles/admin", nil, map[string]string{"tenant": "", "id": "admin"})
	rec := httptest.NewRecorder()

	handlers.DeleteRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteRole_MissingRoleID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/roles/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteRole(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteRole_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteRoleFn: func(ctx context.Context, req *iampb.DeleteRoleRequest, opts ...grpc.CallOption) (*iampb.DeleteRoleResponse, error) {
			return nil, status.Error(codes.NotFound, "role not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/roles/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteRole(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Additional error path tests for Tenant handlers

func TestCreateTenant_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateTenant(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreateTenant_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		createTenantFn: func(ctx context.Context, req *iampb.CreateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
			return nil, status.Error(codes.AlreadyExists, "tenant already exists")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreateTenantRequest{ID: "acme", Name: "Acme Corporation"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTenant(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListTenants_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		listTenantsFn: func(ctx context.Context, req *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListTenants(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetTenant_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/", nil, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.GetTenant(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetTenant_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		getTenantFn: func(ctx context.Context, req *iampb.GetTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/nonexistent", nil, map[string]string{"tenant": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetTenant(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestUpdateTenant_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateTenantRequest{Name: "Updated Corporation"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.UpdateTenant(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateTenant_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/tenants/acme", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "acme"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdateTenant(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateTenant_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		updateTenantFn: func(ctx context.Context, req *iampb.UpdateTenantRequest, opts ...grpc.CallOption) (*iampb.Tenant, error) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateTenantRequest{Name: "Updated Corporation"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/nonexistent", body, map[string]string{"tenant": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.UpdateTenant(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteTenant_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/", nil, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteTenant(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteTenant_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteTenantFn: func(ctx context.Context, req *iampb.DeleteTenantRequest, opts ...grpc.CallOption) (*iampb.DeleteTenantResponse, error) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/nonexistent", nil, map[string]string{"tenant": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteTenant(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Additional error path tests for Policy handlers

func TestCreatePolicy_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := CreatePolicyRequest{Name: "test-policy", SpecYAML: "rules: []"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//policies", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.CreatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreatePolicy_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestCreatePolicy_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		createPolicyFn: func(ctx context.Context, req *iampb.CreatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
			return nil, status.Error(codes.AlreadyExists, "policy already exists")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := CreatePolicyRequest{Name: "test-policy", SpecYAML: "rules: []"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.CreatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListPolicies_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//policies", nil, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.ListPolicies(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListPolicies_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		listPoliciesFn: func(ctx context.Context, req *iampb.ListPoliciesRequest, opts ...grpc.CallOption) (*iampb.ListPoliciesResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/policies", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListPolicies(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetPolicy_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//policies/admin-policy", nil, map[string]string{"tenant": "", "id": "admin-policy"})
	rec := httptest.NewRecorder()

	handlers.GetPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetPolicy_MissingPolicyID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/policies/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.GetPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetPolicy_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		getPolicyFn: func(ctx context.Context, req *iampb.GetPolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
			return nil, status.Error(codes.NotFound, "policy not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/policies/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetPolicy(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestUpdatePolicy_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdatePolicyRequest{Description: "Updated policy"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants//policies/admin-policy", body, map[string]string{"tenant": "", "id": "admin-policy"})
	rec := httptest.NewRecorder()

	handlers.UpdatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdatePolicy_MissingPolicyID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdatePolicyRequest{Description: "Updated policy"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/policies/", body, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.UpdatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdatePolicy_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/tenants/tenant-1/policies/admin-policy", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1", "id": "admin-policy"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdatePolicy_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		updatePolicyFn: func(ctx context.Context, req *iampb.UpdatePolicyRequest, opts ...grpc.CallOption) (*iampb.Policy, error) {
			return nil, status.Error(codes.NotFound, "policy not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdatePolicyRequest{Description: "Updated policy"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/policies/nonexistent", body, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.UpdatePolicy(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeletePolicy_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants//policies/admin-policy", nil, map[string]string{"tenant": "", "id": "admin-policy"})
	rec := httptest.NewRecorder()

	handlers.DeletePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeletePolicy_MissingPolicyID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/policies/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.DeletePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeletePolicy_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		deletePolicyFn: func(ctx context.Context, req *iampb.DeletePolicyRequest, opts ...grpc.CallOption) (*iampb.DeletePolicyResponse, error) {
			return nil, status.Error(codes.NotFound, "policy not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/policies/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeletePolicy(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestValidatePolicy_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := ValidatePolicyRequest{SpecYAML: "rules: []"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//policies/validate", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.ValidatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestValidatePolicy_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/validate", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.ValidatePolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestValidatePolicy_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		validatePolicyFn: func(ctx context.Context, req *iampb.ValidatePolicyRequest, opts ...grpc.CallOption) (*iampb.ValidatePolicyResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := ValidatePolicyRequest{SpecYAML: "rules: []"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/validate", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ValidatePolicy(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestTestPolicy_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := TestPolicyRequest{SubjectID: "user-123", Action: "read", Resource: "files/*"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//policies/test", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.TestPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestTestPolicy_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.TestPolicy(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestTestPolicy_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		testPolicyFn: func(ctx context.Context, req *iampb.TestPolicyRequest, opts ...grpc.CallOption) (*iampb.TestPolicyResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := TestPolicyRequest{SubjectID: "user-123", Action: "read", Resource: "files/*"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.TestPolicy(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Additional error path tests for App handlers

func TestRegisterApp_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := RegisterAppRequest{Name: "My App", RedirectURIs: []string{"https://app.example.com"}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//apps", body, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.RegisterApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRegisterApp_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.RegisterApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRegisterApp_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		registerAppFn: func(ctx context.Context, req *iampb.RegisterAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return nil, status.Error(codes.AlreadyExists, "app already exists")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := RegisterAppRequest{Name: "My App", RedirectURIs: []string{"https://app.example.com"}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps", body, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.RegisterApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListApps_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//apps", nil, map[string]string{"tenant": ""})
	rec := httptest.NewRecorder()

	handlers.ListApps(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListApps_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		listAppsFn: func(ctx context.Context, req *iampb.ListAppsRequest, opts ...grpc.CallOption) (*iampb.ListAppsResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/apps", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListApps(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetApp_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//apps/client-abc", nil, map[string]string{"tenant": "", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.GetApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetApp_MissingAppID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/apps/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.GetApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetApp_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		getAppFn: func(ctx context.Context, req *iampb.GetAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return nil, status.Error(codes.NotFound, "app not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/apps/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetApp(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestUpdateApp_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateAppRequest{Name: "Updated App"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants//apps/client-abc", body, map[string]string{"tenant": "", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.UpdateApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateApp_MissingAppID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	body := UpdateAppRequest{Name: "Updated App"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/apps/", body, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.UpdateApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateApp_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/iam/tenants/tenant-1/apps/client-abc", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"tenant": "tenant-1", "id": "client-abc"})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.UpdateApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateApp_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		updateAppFn: func(ctx context.Context, req *iampb.UpdateAppRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return nil, status.Error(codes.NotFound, "app not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	body := UpdateAppRequest{Name: "Updated App"}
	req := createRequestWithVars(http.MethodPut, "/api/v1/iam/tenants/tenant-1/apps/nonexistent", body, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.UpdateApp(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteApp_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants//apps/client-abc", nil, map[string]string{"tenant": "", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.DeleteApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteApp_MissingAppID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/apps/", nil, map[string]string{"tenant": "tenant-1", "id": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteApp(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteApp_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		deleteAppFn: func(ctx context.Context, req *iampb.DeleteAppRequest, opts ...grpc.CallOption) (*iampb.DeleteAppResponse, error) {
			return nil, status.Error(codes.NotFound, "app not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/iam/tenants/tenant-1/apps/nonexistent", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteApp(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestRotateAppSecret_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants//apps/client-abc/rotate", nil, map[string]string{"tenant": "", "id": "client-abc"})
	rec := httptest.NewRecorder()

	handlers.RotateAppSecret(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRotateAppSecret_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		rotateAppSecretFn: func(ctx context.Context, req *iampb.RotateAppSecretRequest, opts ...grpc.CallOption) (*iampb.Application, error) {
			return nil, status.Error(codes.NotFound, "app not found")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps/nonexistent/rotate", nil, map[string]string{"tenant": "tenant-1", "id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.RotateAppSecret(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Tests for User list error paths

func TestListUsers_GRPCError(t *testing.T) {
	iamClient := &mockIAMClient{
		listUsersFn: func(ctx context.Context, req *iampb.ListUsersRequest, opts ...grpc.CallOption) (*iampb.ListUsersResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, writer := newTestHandlers(iamClient, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants/tenant-1/users", nil, map[string]string{"tenant": "tenant-1"})
	rec := httptest.NewRecorder()

	handlers.ListUsers(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestGetUser_MissingTenantID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockIAMClient{}, &mockPEPClient{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/iam/tenants//users/user-123", nil, map[string]string{"tenant": "", "id": "user-123"})
	rec := httptest.NewRecorder()

	handlers.GetUser(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}
