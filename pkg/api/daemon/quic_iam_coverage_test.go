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

//go:build codec_msgpack

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Extended Mock IAM Service with Error Support
// =============================================================================

// MockIAMServiceWithErrors extends the mock with configurable error behavior
type MockIAMServiceWithErrors struct {
	*MockIAMService
	shouldFail       bool
	failureError     error
	deleteUserFail   bool
	listUsersFail    bool
	updateUserFail   bool
	deleteRoleFail   bool
	getRoleFail      bool
	listRolesFail    bool
	assignRoleFail   bool
	revokeRoleFail   bool
	deleteGroupFail  bool
	getGroupFail     bool
	listGroupsFail   bool
	addMemberFail    bool
	removeMemberFail bool
	createTokenFail  bool
	revokeTokenFail  bool
}

func NewMockIAMServiceWithErrors() *MockIAMServiceWithErrors {
	return &MockIAMServiceWithErrors{
		MockIAMService: NewMockIAMService(),
		failureError:   errors.New("mock IAM service error"),
	}
}

func (m *MockIAMServiceWithErrors) DeleteUser(ctx context.Context, tenantID, userID string) error {
	if m.shouldFail || m.deleteUserFail {
		return m.failureError
	}
	return m.MockIAMService.DeleteUser(ctx, tenantID, userID)
}

func (m *MockIAMServiceWithErrors) ListUsers(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMUserListResponse, error) {
	if m.shouldFail || m.listUsersFail {
		return nil, m.failureError
	}
	return m.MockIAMService.ListUsers(ctx, tenantID, opts)
}

func (m *MockIAMServiceWithErrors) UpdateUser(ctx context.Context, tenantID, userID string, opts UpdateUserRequest) (*IAMUserResponse, error) {
	if m.shouldFail || m.updateUserFail {
		return nil, m.failureError
	}
	return m.MockIAMService.UpdateUser(ctx, tenantID, userID, opts)
}

func (m *MockIAMServiceWithErrors) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	if m.shouldFail || m.deleteRoleFail {
		return m.failureError
	}
	return m.MockIAMService.DeleteRole(ctx, tenantID, roleID)
}

func (m *MockIAMServiceWithErrors) GetRole(ctx context.Context, tenantID, roleID string) (*IAMRoleResponse, error) {
	if m.shouldFail || m.getRoleFail {
		return nil, m.failureError
	}
	return m.MockIAMService.GetRole(ctx, tenantID, roleID)
}

func (m *MockIAMServiceWithErrors) ListRoles(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMRoleListResponse, error) {
	if m.shouldFail || m.listRolesFail {
		return nil, m.failureError
	}
	return m.MockIAMService.ListRoles(ctx, tenantID, opts)
}

func (m *MockIAMServiceWithErrors) AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string) error {
	if m.shouldFail || m.assignRoleFail {
		return m.failureError
	}
	return m.MockIAMService.AssignRoleToUser(ctx, tenantID, userID, roleID)
}

func (m *MockIAMServiceWithErrors) RevokeRoleFromUser(ctx context.Context, tenantID, userID, roleID string) error {
	if m.shouldFail || m.revokeRoleFail {
		return m.failureError
	}
	return m.MockIAMService.RevokeRoleFromUser(ctx, tenantID, userID, roleID)
}

func (m *MockIAMServiceWithErrors) DeleteGroup(ctx context.Context, tenantID, groupID string) error {
	if m.shouldFail || m.deleteGroupFail {
		return m.failureError
	}
	return m.MockIAMService.DeleteGroup(ctx, tenantID, groupID)
}

func (m *MockIAMServiceWithErrors) GetGroup(ctx context.Context, tenantID, groupID string) (*IAMGroupResponse, error) {
	if m.shouldFail || m.getGroupFail {
		return nil, m.failureError
	}
	return m.MockIAMService.GetGroup(ctx, tenantID, groupID)
}

func (m *MockIAMServiceWithErrors) ListGroups(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMGroupListResponse, error) {
	if m.shouldFail || m.listGroupsFail {
		return nil, m.failureError
	}
	return m.MockIAMService.ListGroups(ctx, tenantID, opts)
}

func (m *MockIAMServiceWithErrors) AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	if m.shouldFail || m.addMemberFail {
		return m.failureError
	}
	return m.MockIAMService.AddGroupMember(ctx, tenantID, groupID, userID)
}

func (m *MockIAMServiceWithErrors) RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	if m.shouldFail || m.removeMemberFail {
		return m.failureError
	}
	return m.MockIAMService.RemoveGroupMember(ctx, tenantID, groupID, userID)
}

func (m *MockIAMServiceWithErrors) CreateToken(ctx context.Context, tenantID, userID string, opts CreateTokenRequest) (*TokenResponse, error) {
	if m.shouldFail || m.createTokenFail {
		return nil, m.failureError
	}
	return m.MockIAMService.CreateToken(ctx, tenantID, userID, opts)
}

func (m *MockIAMServiceWithErrors) RevokeToken(ctx context.Context, tokenID string) error {
	if m.shouldFail || m.revokeTokenFail {
		return m.failureError
	}
	return m.MockIAMService.RevokeToken(ctx, tokenID)
}

// =============================================================================
// handleIAMOperation Tests
// =============================================================================

func TestHandleIAMOperation_UnknownOpcode(t *testing.T) {
	logger := logging.DefaultLogger()
	// Handler WITHOUT IAM service configured - IAM opcodes should return Unavailable
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()

	// Use an IAM opcode (0xFA = OpIAMTokenRevoke) without IAM service configured
	// This tests that IAM operations return Unavailable when service is not available
	req := &quic.Request{
		Opcode:  0xFA, // OpIAMTokenRevoke - should return Unavailable without IAM service
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	// Without IAM service configured, IAM opcodes return Unavailable
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleIAMUserDelete Tests
// =============================================================================

func TestHandleIAMUserDelete(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        DeleteUserRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				// Pre-create user to delete
				_, _ = mock.CreateUser(ctx, "test-tenant", CreateUserRequest{
					TenantID: "test-tenant",
					UserID:   "user-to-delete",
					Email:    "delete@example.com",
				})
				return mock
			},
			request: DeleteUserRequest{
				TenantID: "test-tenant",
				UserID:   "user-to-delete",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: DeleteUserRequest{
				UserID: "user-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_user_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: DeleteUserRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "user_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.deleteUserFail = true
				return mock
			},
			request: DeleteUserRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMUserDelete,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var deleteResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &deleteResp)
				require.NoError(t, err)
				assert.True(t, deleteResp.Success)
			}
		})
	}
}

func TestHandleIAMUserDelete_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMUserDelete,
		Payload: []byte("invalid payload"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMUserList Tests
// =============================================================================

func TestHandleIAMUserList(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        ListIAMRequest
		expectedStatus byte
		expectedCount  int
		shouldContain  string
	}{
		{
			name: "success_with_users",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateUser(ctx, "test-tenant", CreateUserRequest{
					TenantID: "test-tenant",
					UserID:   "user-1",
					Email:    "user1@example.com",
				})
				_, _ = mock.CreateUser(ctx, "test-tenant", CreateUserRequest{
					TenantID: "test-tenant",
					UserID:   "user-2",
					Email:    "user2@example.com",
				})
				return mock
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
				Limit:    10,
			},
			expectedStatus: quic.StatusOK,
			expectedCount:  2,
		},
		{
			name: "success_empty_list",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusOK,
			expectedCount:  0,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request:        ListIAMRequest{},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.listUsersFail = true
				return mock
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMUserList,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var listResp IAMUserListResponse
				err = quic.DecodePayload(resp.Payload, &listResp)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCount, listResp.Total)
			}
		})
	}
}

func TestHandleIAMUserList_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMUserList,
		Payload: []byte("invalid payload data"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMUserUpdate Tests
// =============================================================================

func TestHandleIAMUserUpdate(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        UpdateUserRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateUser(ctx, "test-tenant", CreateUserRequest{
					TenantID: "test-tenant",
					UserID:   "user-123",
					Email:    "old@example.com",
					Name:     "Old Name",
				})
				return mock
			},
			request: UpdateUserRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
				Email:    "new@example.com",
				Name:     "New Name",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: UpdateUserRequest{
				UserID: "user-123",
				Email:  "new@example.com",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_user_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: UpdateUserRequest{
				TenantID: "test-tenant",
				Email:    "new@example.com",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "user_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.updateUserFail = true
				return mock
			},
			request: UpdateUserRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
				Email:    "new@example.com",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMUserUpdate,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var userResp IAMUserResponse
				err = quic.DecodePayload(resp.Payload, &userResp)
				require.NoError(t, err)
				assert.Equal(t, tc.request.UserID, userResp.ID)
			}
		})
	}
}

func TestHandleIAMUserUpdate_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMUserUpdate,
		Payload: []byte("invalid payload"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMRoleDelete Tests
// =============================================================================

func TestHandleIAMRoleDelete(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        DeleteRoleRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateRole(ctx, "test-tenant", CreateRoleRequest{
					TenantID: "test-tenant",
					RoleID:   "role-to-delete",
					Name:     "Admin",
				})
				return mock
			},
			request: DeleteRoleRequest{
				TenantID: "test-tenant",
				RoleID:   "role-to-delete",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: DeleteRoleRequest{
				RoleID: "role-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_role_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: DeleteRoleRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "role_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.deleteRoleFail = true
				return mock
			},
			request: DeleteRoleRequest{
				TenantID: "test-tenant",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMRoleDelete,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var deleteResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &deleteResp)
				require.NoError(t, err)
				assert.True(t, deleteResp.Success)
			}
		})
	}
}

func TestHandleIAMRoleDelete_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMRoleDelete,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMRoleGet Tests
// =============================================================================

func TestHandleIAMRoleGet(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        GetRoleRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateRole(ctx, "test-tenant", CreateRoleRequest{
					TenantID:    "test-tenant",
					RoleID:      "role-123",
					Name:        "Admin",
					Description: "Administrator role",
				})
				return mock
			},
			request: GetRoleRequest{
				TenantID: "test-tenant",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GetRoleRequest{
				RoleID: "role-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_role_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GetRoleRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "role_id",
		},
		{
			name: "role_not_found",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GetRoleRequest{
				TenantID: "test-tenant",
				RoleID:   "nonexistent-role",
			},
			expectedStatus: quic.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMRoleGet,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var roleResp IAMRoleResponse
				err = quic.DecodePayload(resp.Payload, &roleResp)
				require.NoError(t, err)
				assert.Equal(t, tc.request.RoleID, roleResp.ID)
			}
		})
	}
}

func TestHandleIAMRoleGet_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMRoleGet,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMRoleList Tests
// =============================================================================

func TestHandleIAMRoleList(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        ListIAMRequest
		expectedStatus byte
		expectedCount  int
		shouldContain  string
	}{
		{
			name: "success_with_roles",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateRole(ctx, "test-tenant", CreateRoleRequest{
					TenantID: "test-tenant",
					RoleID:   "role-1",
					Name:     "Admin",
				})
				_, _ = mock.CreateRole(ctx, "test-tenant", CreateRoleRequest{
					TenantID: "test-tenant",
					RoleID:   "role-2",
					Name:     "User",
				})
				return mock
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusOK,
			expectedCount:  2,
		},
		{
			name: "success_empty_list",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusOK,
			expectedCount:  0,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request:        ListIAMRequest{},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.listRolesFail = true
				return mock
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMRoleList,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var listResp IAMRoleListResponse
				err = quic.DecodePayload(resp.Payload, &listResp)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCount, listResp.Total)
			}
		})
	}
}

func TestHandleIAMRoleList_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMRoleList,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMRoleAssign Tests
// =============================================================================

func TestHandleIAMRoleAssign(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        AssignRoleRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateUser(ctx, "test-tenant", CreateUserRequest{
					TenantID: "test-tenant",
					UserID:   "user-123",
					Email:    "user@example.com",
				})
				_, _ = mock.CreateRole(ctx, "test-tenant", CreateRoleRequest{
					TenantID: "test-tenant",
					RoleID:   "role-123",
					Name:     "Admin",
				})
				return mock
			},
			request: AssignRoleRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: AssignRoleRequest{
				UserID: "user-123",
				RoleID: "role-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_user_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: AssignRoleRequest{
				TenantID: "test-tenant",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "user_id",
		},
		{
			name: "missing_role_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: AssignRoleRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "role_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.assignRoleFail = true
				return mock
			},
			request: AssignRoleRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMRoleAssign,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var assignResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &assignResp)
				require.NoError(t, err)
				assert.True(t, assignResp.Success)
			}
		})
	}
}

func TestHandleIAMRoleAssign_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMRoleAssign,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMRoleRevoke Tests
// =============================================================================

func TestHandleIAMRoleRevoke(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        RevokeRoleRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateUser(ctx, "test-tenant", CreateUserRequest{
					TenantID: "test-tenant",
					UserID:   "user-123",
					Email:    "user@example.com",
				})
				_ = mock.AssignRoleToUser(ctx, "test-tenant", "user-123", "role-123")
				return mock
			},
			request: RevokeRoleRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: RevokeRoleRequest{
				UserID: "user-123",
				RoleID: "role-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_user_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: RevokeRoleRequest{
				TenantID: "test-tenant",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "user_id",
		},
		{
			name: "missing_role_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: RevokeRoleRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "role_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.revokeRoleFail = true
				return mock
			},
			request: RevokeRoleRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
				RoleID:   "role-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMRoleRevoke,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var revokeResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &revokeResp)
				require.NoError(t, err)
				assert.True(t, revokeResp.Success)
			}
		})
	}
}

func TestHandleIAMRoleRevoke_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMRoleRevoke,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMGroupDelete Tests
// =============================================================================

func TestHandleIAMGroupDelete(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        DeleteGroupRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateGroup(ctx, "test-tenant", CreateGroupRequest{
					TenantID: "test-tenant",
					GroupID:  "group-to-delete",
					Name:     "Admins",
				})
				return mock
			},
			request: DeleteGroupRequest{
				TenantID: "test-tenant",
				GroupID:  "group-to-delete",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: DeleteGroupRequest{
				GroupID: "group-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_group_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: DeleteGroupRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "group_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.deleteGroupFail = true
				return mock
			},
			request: DeleteGroupRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMGroupDelete,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var deleteResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &deleteResp)
				require.NoError(t, err)
				assert.True(t, deleteResp.Success)
			}
		})
	}
}

func TestHandleIAMGroupDelete_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMGroupDelete,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMGroupGet Tests
// =============================================================================

func TestHandleIAMGroupGet(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        GetGroupRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateGroup(ctx, "test-tenant", CreateGroupRequest{
					TenantID:    "test-tenant",
					GroupID:     "group-123",
					Name:        "Admins",
					Description: "Administrator group",
				})
				return mock
			},
			request: GetGroupRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GetGroupRequest{
				GroupID: "group-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_group_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GetGroupRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "group_id",
		},
		{
			name: "group_not_found",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GetGroupRequest{
				TenantID: "test-tenant",
				GroupID:  "nonexistent-group",
			},
			expectedStatus: quic.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMGroupGet,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var groupResp IAMGroupResponse
				err = quic.DecodePayload(resp.Payload, &groupResp)
				require.NoError(t, err)
				assert.Equal(t, tc.request.GroupID, groupResp.ID)
			}
		})
	}
}

func TestHandleIAMGroupGet_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMGroupGet,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMGroupList Tests
// =============================================================================

func TestHandleIAMGroupList(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        ListIAMRequest
		expectedStatus byte
		expectedCount  int
		shouldContain  string
	}{
		{
			name: "success_with_groups",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateGroup(ctx, "test-tenant", CreateGroupRequest{
					TenantID: "test-tenant",
					GroupID:  "group-1",
					Name:     "Admins",
				})
				_, _ = mock.CreateGroup(ctx, "test-tenant", CreateGroupRequest{
					TenantID: "test-tenant",
					GroupID:  "group-2",
					Name:     "Users",
				})
				return mock
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusOK,
			expectedCount:  2,
		},
		{
			name: "success_empty_list",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusOK,
			expectedCount:  0,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request:        ListIAMRequest{},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.listGroupsFail = true
				return mock
			},
			request: ListIAMRequest{
				TenantID: "test-tenant",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMGroupList,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var listResp IAMGroupListResponse
				err = quic.DecodePayload(resp.Payload, &listResp)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCount, listResp.Total)
			}
		})
	}
}

func TestHandleIAMGroupList_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMGroupList,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMGroupAddMember Tests
// =============================================================================

func TestHandleIAMGroupAddMember(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        GroupMemberRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateGroup(ctx, "test-tenant", CreateGroupRequest{
					TenantID: "test-tenant",
					GroupID:  "group-123",
					Name:     "Admins",
				})
				_, _ = mock.CreateUser(ctx, "test-tenant", CreateUserRequest{
					TenantID: "test-tenant",
					UserID:   "user-123",
					Email:    "user@example.com",
				})
				return mock
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GroupMemberRequest{
				GroupID: "group-123",
				UserID:  "user-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_group_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "group_id",
		},
		{
			name: "missing_user_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "user_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.addMemberFail = true
				return mock
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMGroupAddMember,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var addResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &addResp)
				require.NoError(t, err)
				assert.True(t, addResp.Success)
			}
		})
	}
}

func TestHandleIAMGroupAddMember_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMGroupAddMember,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMGroupRemoveMember Tests
// =============================================================================

func TestHandleIAMGroupRemoveMember(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        GroupMemberRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				_, _ = mock.CreateGroup(ctx, "test-tenant", CreateGroupRequest{
					TenantID: "test-tenant",
					GroupID:  "group-123",
					Name:     "Admins",
				})
				_ = mock.AddGroupMember(ctx, "test-tenant", "group-123", "user-123")
				return mock
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GroupMemberRequest{
				GroupID: "group-123",
				UserID:  "user-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_group_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "group_id",
		},
		{
			name: "missing_user_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "user_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.removeMemberFail = true
				return mock
			},
			request: GroupMemberRequest{
				TenantID: "test-tenant",
				GroupID:  "group-123",
				UserID:   "user-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMGroupRemoveMember,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var removeResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &removeResp)
				require.NoError(t, err)
				assert.True(t, removeResp.Success)
			}
		})
	}
}

func TestHandleIAMGroupRemoveMember_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMGroupRemoveMember,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMTokenCreate Tests
// =============================================================================

func TestHandleIAMTokenCreate(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        CreateTokenRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: CreateTokenRequest{
				TenantID:  "test-tenant",
				UserID:    "user-123",
				Scopes:    []string{"read", "write"},
				ExpiresIn: 3600,
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_tenant_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: CreateTokenRequest{
				UserID:    "user-123",
				ExpiresIn: 3600,
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "tenant_id",
		},
		{
			name: "missing_user_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: CreateTokenRequest{
				TenantID:  "test-tenant",
				ExpiresIn: 3600,
			},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "user_id",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.createTokenFail = true
				return mock
			},
			request: CreateTokenRequest{
				TenantID:  "test-tenant",
				UserID:    "user-123",
				ExpiresIn: 3600,
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMTokenCreate,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var tokenResp TokenResponse
				err = quic.DecodePayload(resp.Payload, &tokenResp)
				require.NoError(t, err)
				assert.NotEmpty(t, tokenResp.AccessToken)
			}
		})
	}
}

func TestHandleIAMTokenCreate_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMTokenCreate,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// handleIAMTokenRevoke Tests
// =============================================================================

func TestHandleIAMTokenRevoke(t *testing.T) {
	logger := logging.DefaultLogger()
	ctx := context.Background()

	testCases := []struct {
		name           string
		setupMock      func() *MockIAMServiceWithErrors
		request        RevokeTokenRequest
		expectedStatus byte
		shouldContain  string
	}{
		{
			name: "success_with_token_id",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: RevokeTokenRequest{
				TokenID: "token-123",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "success_with_token",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request: RevokeTokenRequest{
				Token: "actual-token-value",
			},
			expectedStatus: quic.StatusOK,
		},
		{
			name: "missing_token_id_and_token",
			setupMock: func() *MockIAMServiceWithErrors {
				return NewMockIAMServiceWithErrors()
			},
			request:        RevokeTokenRequest{},
			expectedStatus: quic.StatusInvalidArgument,
			shouldContain:  "token_id or token",
		},
		{
			name: "service_error",
			setupMock: func() *MockIAMServiceWithErrors {
				mock := NewMockIAMServiceWithErrors()
				mock.revokeTokenFail = true
				return mock
			},
			request: RevokeTokenRequest{
				TokenID: "token-123",
			},
			expectedStatus: quic.StatusInternalError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockIAM := tc.setupMock()
			handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

			payload, err := quic.EncodePayload(tc.request)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpIAMTokenRevoke,
				Payload: payload,
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tc.expectedStatus, resp.Status)

			if tc.shouldContain != "" {
				assert.Contains(t, string(resp.Payload), tc.shouldContain)
			}

			if tc.expectedStatus == quic.StatusOK {
				var revokeResp GenericIAMResponse
				err = quic.DecodePayload(resp.Payload, &revokeResp)
				require.NoError(t, err)
				assert.True(t, revokeResp.Success)
			}
		})
	}
}

func TestHandleIAMTokenRevoke_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpIAMTokenRevoke,
		Payload: []byte("invalid"),
	}

	resp := handler.HandleRequest(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// =============================================================================
// Additional IAM Request/Response Type Tests
// =============================================================================

func TestIAMRequestResponseTypes_Serialization(t *testing.T) {
	t.Run("DeleteUserRequest", func(t *testing.T) {
		original := DeleteUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DeleteUserRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.TenantID, decoded.TenantID)
		assert.Equal(t, original.UserID, decoded.UserID)
	})

	t.Run("UpdateUserRequest", func(t *testing.T) {
		original := UpdateUserRequest{
			TenantID:   "tenant-1",
			UserID:     "user-1",
			Email:      "updated@example.com",
			Username:   "updateduser",
			Name:       "Updated Name",
			Enabled:    true,
			Roles:      []string{"admin", "user"},
			Groups:     []string{"group-1"},
			Attributes: map[string]string{"key": "value"},
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded UpdateUserRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.TenantID, decoded.TenantID)
		assert.Equal(t, original.UserID, decoded.UserID)
		assert.Equal(t, original.Email, decoded.Email)
		assert.Equal(t, original.Roles, decoded.Roles)
		assert.Equal(t, original.Groups, decoded.Groups)
	})

	t.Run("GenericIAMResponse", func(t *testing.T) {
		original := GenericIAMResponse{
			Success:   true,
			Message:   "operation completed",
			Timestamp: time.Now().Unix(),
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded GenericIAMResponse
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Success, decoded.Success)
		assert.Equal(t, original.Message, decoded.Message)
		assert.Equal(t, original.Timestamp, decoded.Timestamp)
	})

	t.Run("IAMGroupResponse", func(t *testing.T) {
		original := IAMGroupResponse{
			ID:          "group-1",
			TenantID:    "tenant-1",
			Name:        "Administrators",
			Description: "Admin group",
			Members:     []string{"user-1", "user-2"},
			Attributes:  map[string]string{"key": "value"},
			CreatedAt:   time.Now().Unix(),
			UpdatedAt:   time.Now().Unix(),
			Timestamp:   time.Now().Unix(),
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded IAMGroupResponse
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.ID, decoded.ID)
		assert.Equal(t, original.Name, decoded.Name)
		assert.Equal(t, original.Members, decoded.Members)
	})

	t.Run("TokenResponse", func(t *testing.T) {
		original := TokenResponse{
			TokenID:      "token-1",
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
			Timestamp:    time.Now().Unix(),
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded TokenResponse
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.TokenID, decoded.TokenID)
		assert.Equal(t, original.AccessToken, decoded.AccessToken)
		assert.Equal(t, original.TokenType, decoded.TokenType)
	})

	t.Run("RevokeTokenRequest", func(t *testing.T) {
		original := RevokeTokenRequest{
			TokenID: "token-1",
			Token:   "actual-token",
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded RevokeTokenRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.TokenID, decoded.TokenID)
		assert.Equal(t, original.Token, decoded.Token)
	})
}

// =============================================================================
// IAM Error Type Tests
// =============================================================================

func TestIAMErrorTypes(t *testing.T) {
	t.Run("ErrIAMServiceNotAvailable", func(t *testing.T) {
		err := ErrIAMServiceNotAvailable{}
		assert.Equal(t, "IAM service not available", err.Error())
	})

	t.Run("ErrIAMMissingParameter", func(t *testing.T) {
		err := ErrIAMMissingParameter{Parameter: "tenant_id"}
		assert.Equal(t, "missing required IAM parameter: tenant_id", err.Error())
	})

	t.Run("ErrIAMUserNotFound", func(t *testing.T) {
		err := ErrIAMUserNotFound{TenantID: "tenant-1", UserID: "user-1"}
		assert.Contains(t, err.Error(), "user-1")
		assert.Contains(t, err.Error(), "tenant-1")
	})

	t.Run("ErrIAMRoleNotFound", func(t *testing.T) {
		err := ErrIAMRoleNotFound{TenantID: "tenant-1", RoleID: "role-1"}
		assert.Contains(t, err.Error(), "role-1")
		assert.Contains(t, err.Error(), "tenant-1")
	})

	t.Run("ErrIAMGroupNotFound", func(t *testing.T) {
		err := ErrIAMGroupNotFound{TenantID: "tenant-1", GroupID: "group-1"}
		assert.Contains(t, err.Error(), "group-1")
		assert.Contains(t, err.Error(), "tenant-1")
	})

	t.Run("ErrIAMTokenNotFound", func(t *testing.T) {
		err := ErrIAMTokenNotFound{TokenID: "token-1"}
		assert.Contains(t, err.Error(), "token-1")
	})

	t.Run("ErrIAMTokenExpired", func(t *testing.T) {
		err := ErrIAMTokenExpired{TokenID: "token-1"}
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("ErrIAMTokenRevoked", func(t *testing.T) {
		err := ErrIAMTokenRevoked{TokenID: "token-1"}
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("ErrIAMOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrIAMOperationFailed{Operation: "CreateUser", Cause: cause}
		assert.Contains(t, err.Error(), "CreateUser")
		assert.Equal(t, cause, err.Unwrap())
	})
}
