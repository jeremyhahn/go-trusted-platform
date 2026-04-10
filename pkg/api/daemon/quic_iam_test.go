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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockIAMService implements QUICIAMService for testing
type MockIAMService struct {
	users  map[string]*IAMUserResponse
	roles  map[string]*IAMRoleResponse
	groups map[string]*IAMGroupResponse
}

func NewMockIAMService() *MockIAMService {
	return &MockIAMService{
		users:  make(map[string]*IAMUserResponse),
		roles:  make(map[string]*IAMRoleResponse),
		groups: make(map[string]*IAMGroupResponse),
	}
}

func (m *MockIAMService) CreateUser(ctx context.Context, tenantID string, opts CreateUserRequest) (*IAMUserResponse, error) {
	user := &IAMUserResponse{
		ID:         opts.UserID,
		TenantID:   tenantID,
		Email:      opts.Email,
		Username:   opts.Username,
		Name:       opts.Name,
		Enabled:    opts.Enabled,
		Attributes: opts.Attributes,
		CreatedAt:  time.Now().Unix(),
		UpdatedAt:  time.Now().Unix(),
		Timestamp:  time.Now().Unix(),
	}
	m.users[user.ID] = user
	return user, nil
}

func (m *MockIAMService) DeleteUser(ctx context.Context, tenantID, userID string) error {
	delete(m.users, userID)
	return nil
}

func (m *MockIAMService) GetUser(ctx context.Context, tenantID, userID string) (*IAMUserResponse, error) {
	user, exists := m.users[userID]
	if !exists {
		return nil, ErrServiceNotFound{ServiceName: "user"}
	}
	return user, nil
}

func (m *MockIAMService) ListUsers(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMUserListResponse, error) {
	users := make([]*IAMUserResponse, 0, len(m.users))
	for _, user := range m.users {
		if user.TenantID == tenantID {
			users = append(users, user)
		}
	}
	return &IAMUserListResponse{
		Users:     users,
		Total:     len(users),
		Limit:     opts.Limit,
		Offset:    opts.Offset,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *MockIAMService) UpdateUser(ctx context.Context, tenantID, userID string, opts UpdateUserRequest) (*IAMUserResponse, error) {
	user, exists := m.users[userID]
	if !exists {
		return nil, ErrServiceNotFound{ServiceName: "user"}
	}
	if opts.Email != "" {
		user.Email = opts.Email
	}
	if opts.Username != "" {
		user.Username = opts.Username
	}
	if opts.Name != "" {
		user.Name = opts.Name
	}
	user.UpdatedAt = time.Now().Unix()
	user.Timestamp = time.Now().Unix()
	return user, nil
}

func (m *MockIAMService) CreateRole(ctx context.Context, tenantID string, opts CreateRoleRequest) (*IAMRoleResponse, error) {
	role := &IAMRoleResponse{
		ID:          opts.RoleID,
		TenantID:    tenantID,
		Name:        opts.Name,
		Description: opts.Description,
		Permissions: opts.Permissions,
		Attributes:  opts.Attributes,
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		Timestamp:   time.Now().Unix(),
	}
	m.roles[role.ID] = role
	return role, nil
}

func (m *MockIAMService) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	delete(m.roles, roleID)
	return nil
}

func (m *MockIAMService) GetRole(ctx context.Context, tenantID, roleID string) (*IAMRoleResponse, error) {
	role, exists := m.roles[roleID]
	if !exists {
		return nil, ErrServiceNotFound{ServiceName: "role"}
	}
	return role, nil
}

func (m *MockIAMService) ListRoles(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMRoleListResponse, error) {
	roles := make([]*IAMRoleResponse, 0, len(m.roles))
	for _, role := range m.roles {
		if role.TenantID == tenantID {
			roles = append(roles, role)
		}
	}
	return &IAMRoleListResponse{
		Roles:     roles,
		Total:     len(roles),
		Limit:     opts.Limit,
		Offset:    opts.Offset,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *MockIAMService) UpdateRole(ctx context.Context, tenantID, roleID string, opts UpdateRoleRequest) (*IAMRoleResponse, error) {
	role, exists := m.roles[roleID]
	if !exists {
		return nil, ErrServiceNotFound{ServiceName: "role"}
	}
	if opts.Name != "" {
		role.Name = opts.Name
	}
	if opts.Description != "" {
		role.Description = opts.Description
	}
	role.UpdatedAt = time.Now().Unix()
	return role, nil
}

func (m *MockIAMService) AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string) error {
	user, exists := m.users[userID]
	if !exists {
		return ErrServiceNotFound{ServiceName: "user"}
	}
	user.Roles = append(user.Roles, roleID)
	return nil
}

func (m *MockIAMService) RevokeRoleFromUser(ctx context.Context, tenantID, userID, roleID string) error {
	user, exists := m.users[userID]
	if !exists {
		return ErrServiceNotFound{ServiceName: "user"}
	}
	newRoles := make([]string, 0)
	for _, r := range user.Roles {
		if r != roleID {
			newRoles = append(newRoles, r)
		}
	}
	user.Roles = newRoles
	return nil
}

func (m *MockIAMService) CreateGroup(ctx context.Context, tenantID string, opts CreateGroupRequest) (*IAMGroupResponse, error) {
	group := &IAMGroupResponse{
		ID:          opts.GroupID,
		TenantID:    tenantID,
		Name:        opts.Name,
		Description: opts.Description,
		Attributes:  opts.Attributes,
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
		Timestamp:   time.Now().Unix(),
	}
	m.groups[group.ID] = group
	return group, nil
}

func (m *MockIAMService) DeleteGroup(ctx context.Context, tenantID, groupID string) error {
	delete(m.groups, groupID)
	return nil
}

func (m *MockIAMService) GetGroup(ctx context.Context, tenantID, groupID string) (*IAMGroupResponse, error) {
	group, exists := m.groups[groupID]
	if !exists {
		return nil, ErrServiceNotFound{ServiceName: "group"}
	}
	return group, nil
}

func (m *MockIAMService) ListGroups(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMGroupListResponse, error) {
	groups := make([]*IAMGroupResponse, 0, len(m.groups))
	for _, group := range m.groups {
		if group.TenantID == tenantID {
			groups = append(groups, group)
		}
	}
	return &IAMGroupListResponse{
		Groups:    groups,
		Total:     len(groups),
		Limit:     opts.Limit,
		Offset:    opts.Offset,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *MockIAMService) UpdateGroup(ctx context.Context, tenantID, groupID string, opts UpdateGroupRequest) (*IAMGroupResponse, error) {
	group, exists := m.groups[groupID]
	if !exists {
		return nil, ErrServiceNotFound{ServiceName: "group"}
	}
	if opts.Name != "" {
		group.Name = opts.Name
	}
	if opts.Description != "" {
		group.Description = opts.Description
	}
	group.UpdatedAt = time.Now().Unix()
	return group, nil
}

func (m *MockIAMService) AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	group, exists := m.groups[groupID]
	if !exists {
		return ErrServiceNotFound{ServiceName: "group"}
	}
	group.Members = append(group.Members, userID)
	return nil
}

func (m *MockIAMService) RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	group, exists := m.groups[groupID]
	if !exists {
		return ErrServiceNotFound{ServiceName: "group"}
	}
	newMembers := make([]string, 0)
	for _, member := range group.Members {
		if member != userID {
			newMembers = append(newMembers, member)
		}
	}
	group.Members = newMembers
	return nil
}

func (m *MockIAMService) CheckPermission(ctx context.Context, req *CheckPermissionRequest) (*CheckPermissionResponse, error) {
	return &CheckPermissionResponse{
		Allowed:   true,
		Reason:    "mock permission check",
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *MockIAMService) Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	return &AuthenticateResponse{
		UserID:       "mock-user-id",
		TenantID:     req.TenantID,
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		Timestamp:    time.Now().Unix(),
	}, nil
}

func (m *MockIAMService) CreateToken(ctx context.Context, tenantID, userID string, opts CreateTokenRequest) (*TokenResponse, error) {
	return &TokenResponse{
		TokenID:      "mock-token-id",
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		ExpiresIn:    opts.ExpiresIn,
		TokenType:    "Bearer",
		Timestamp:    time.Now().Unix(),
	}, nil
}

func (m *MockIAMService) RevokeToken(ctx context.Context, tokenID string) error {
	return nil
}

func (m *MockIAMService) VerifyToken(ctx context.Context, token string) (*TokenVerifyResponse, error) {
	return &TokenVerifyResponse{
		Valid:     true,
		UserID:    "mock-user-id",
		TenantID:  "mock-tenant-id",
		Scopes:    []string{"read", "write"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Timestamp: time.Now().Unix(),
	}, nil
}

// TestHandleIAMOperation_ServiceNotAvailable tests that IAM operations return
// StatusUnavailable when the IAM service is not configured
func TestHandleIAMOperation_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"UserCreate", quic.OpIAMUserCreate},
		{"UserDelete", quic.OpIAMUserDelete},
		{"UserGet", quic.OpIAMUserGet},
		{"UserList", quic.OpIAMUserList},
		{"UserUpdate", quic.OpIAMUserUpdate},
		{"RoleCreate", quic.OpIAMRoleCreate},
		{"RoleDelete", quic.OpIAMRoleDelete},
		{"RoleGet", quic.OpIAMRoleGet},
		{"RoleList", quic.OpIAMRoleList},
		{"RoleAssign", quic.OpIAMRoleAssign},
		{"RoleRevoke", quic.OpIAMRoleRevoke},
		{"GroupCreate", quic.OpIAMGroupCreate},
		{"GroupDelete", quic.OpIAMGroupDelete},
		{"GroupGet", quic.OpIAMGroupGet},
		{"GroupList", quic.OpIAMGroupList},
		{"GroupAddMember", quic.OpIAMGroupAddMember},
		{"GroupRemoveMember", quic.OpIAMGroupRemoveMember},
		{"CheckPermission", quic.OpIAMCheckPermission},
		{"Authenticate", quic.OpIAMAuthenticate},
		{"TokenCreate", quic.OpIAMTokenCreate},
		{"TokenRevoke", quic.OpIAMTokenRevoke},
		{"TokenVerify", quic.OpIAMTokenVerify},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.Contains(t, string(resp.Payload), "iam")
		})
	}
}

// TestHandleIAMUserCreate tests creating a user via QUIC
func TestHandleIAMUserCreate(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		createReq := CreateUserRequest{
			TenantID: "test-tenant",
			UserID:   "user-123",
			Email:    "test@example.com",
			Username: "testuser",
			Name:     "Test User",
			Enabled:  true,
		}

		payload, err := quic.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMUserCreate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var userResp IAMUserResponse
		err = quic.DecodePayload(resp.Payload, &userResp)
		require.NoError(t, err)

		assert.Equal(t, "user-123", userResp.ID)
		assert.Equal(t, "test-tenant", userResp.TenantID)
		assert.Equal(t, "test@example.com", userResp.Email)
		assert.Equal(t, "testuser", userResp.Username)
	})

	t.Run("missing tenant_id", func(t *testing.T) {
		createReq := CreateUserRequest{
			Email:    "test@example.com",
			Username: "testuser",
		}

		payload, err := quic.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMUserCreate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "tenant_id")
	})

	t.Run("missing email", func(t *testing.T) {
		createReq := CreateUserRequest{
			TenantID: "test-tenant",
			Username: "testuser",
		}

		payload, err := quic.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMUserCreate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "email")
	})
}

// TestHandleIAMUserGet tests getting a user via QUIC
func TestHandleIAMUserGet(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	// Create a user first
	mockIAM.CreateUser(ctx, "test-tenant", CreateUserRequest{
		TenantID: "test-tenant",
		UserID:   "user-123",
		Email:    "test@example.com",
		Username: "testuser",
	})

	t.Run("success", func(t *testing.T) {
		getReq := GetUserRequest{
			TenantID: "test-tenant",
			UserID:   "user-123",
		}

		payload, err := quic.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMUserGet,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var userResp IAMUserResponse
		err = quic.DecodePayload(resp.Payload, &userResp)
		require.NoError(t, err)

		assert.Equal(t, "user-123", userResp.ID)
		assert.Equal(t, "test@example.com", userResp.Email)
	})

	t.Run("missing tenant_id", func(t *testing.T) {
		getReq := GetUserRequest{
			UserID: "user-123",
		}

		payload, err := quic.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMUserGet,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// TestHandleIAMRoleCreate tests creating a role via QUIC
func TestHandleIAMRoleCreate(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		createReq := CreateRoleRequest{
			TenantID:    "test-tenant",
			RoleID:      "role-123",
			Name:        "Admin Role",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
		}

		payload, err := quic.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMRoleCreate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var roleResp IAMRoleResponse
		err = quic.DecodePayload(resp.Payload, &roleResp)
		require.NoError(t, err)

		assert.Equal(t, "role-123", roleResp.ID)
		assert.Equal(t, "Admin Role", roleResp.Name)
		assert.Equal(t, []string{"read", "write", "delete"}, roleResp.Permissions)
	})

	t.Run("missing tenant_id", func(t *testing.T) {
		createReq := CreateRoleRequest{
			Name: "Admin Role",
		}

		payload, err := quic.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMRoleCreate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// TestHandleIAMGroupCreate tests creating a group via QUIC
func TestHandleIAMGroupCreate(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		createReq := CreateGroupRequest{
			TenantID:    "test-tenant",
			GroupID:     "group-123",
			Name:        "Admins",
			Description: "Administrator group",
		}

		payload, err := quic.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMGroupCreate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var groupResp IAMGroupResponse
		err = quic.DecodePayload(resp.Payload, &groupResp)
		require.NoError(t, err)

		assert.Equal(t, "group-123", groupResp.ID)
		assert.Equal(t, "Admins", groupResp.Name)
	})

	t.Run("missing name", func(t *testing.T) {
		createReq := CreateGroupRequest{
			TenantID: "test-tenant",
		}

		payload, err := quic.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMGroupCreate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// TestHandleIAMAuthenticate tests authentication via QUIC
func TestHandleIAMAuthenticate(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		authReq := AuthenticateRequest{
			TenantID: "test-tenant",
			Username: "testuser",
			Password: "testpassword",
		}

		payload, err := quic.EncodePayload(authReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMAuthenticate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var authResp AuthenticateResponse
		err = quic.DecodePayload(resp.Payload, &authResp)
		require.NoError(t, err)

		assert.NotEmpty(t, authResp.AccessToken)
		assert.NotEmpty(t, authResp.RefreshToken)
		assert.Equal(t, "Bearer", authResp.TokenType)
	})

	t.Run("missing username", func(t *testing.T) {
		authReq := AuthenticateRequest{
			Password: "testpassword",
		}

		payload, err := quic.EncodePayload(authReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMAuthenticate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing password", func(t *testing.T) {
		authReq := AuthenticateRequest{
			Username: "testuser",
		}

		payload, err := quic.EncodePayload(authReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMAuthenticate,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// TestHandleIAMCheckPermission tests permission checking via QUIC
func TestHandleIAMCheckPermission(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		checkReq := CheckPermissionRequest{
			TenantID:  "test-tenant",
			SubjectID: "user-123",
			Resource:  "document:123",
			Action:    "read",
		}

		payload, err := quic.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMCheckPermission,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var checkResp CheckPermissionResponse
		err = quic.DecodePayload(resp.Payload, &checkResp)
		require.NoError(t, err)

		assert.True(t, checkResp.Allowed)
	})

	t.Run("missing subject_id", func(t *testing.T) {
		checkReq := CheckPermissionRequest{
			TenantID: "test-tenant",
			Resource: "document:123",
			Action:   "read",
		}

		payload, err := quic.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMCheckPermission,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// TestHandleIAMTokenVerify tests token verification via QUIC
func TestHandleIAMTokenVerify(t *testing.T) {
	logger := logging.DefaultLogger()
	mockIAM := NewMockIAMService()
	handler := NewQUICServiceHandler(logger, WithQUICIAMService(mockIAM))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		verifyReq := VerifyTokenRequest{
			Token: "test-token",
		}

		payload, err := quic.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMTokenVerify,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var verifyResp TokenVerifyResponse
		err = quic.DecodePayload(resp.Payload, &verifyResp)
		require.NoError(t, err)

		assert.True(t, verifyResp.Valid)
		assert.NotEmpty(t, verifyResp.UserID)
	})

	t.Run("missing token", func(t *testing.T) {
		verifyReq := VerifyTokenRequest{}

		payload, err := quic.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpIAMTokenVerify,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// TestIAMRequestResponseTypes tests serialization of IAM request/response types
func TestIAMRequestResponseTypes(t *testing.T) {
	t.Run("CreateUserRequest", func(t *testing.T) {
		req := CreateUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
			Email:    "test@example.com",
			Username: "testuser",
			Name:     "Test User",
			Enabled:  true,
			Attributes: map[string]string{
				"department": "engineering",
			},
		}

		encoded, err := quic.EncodePayload(req)
		require.NoError(t, err)

		var decoded CreateUserRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, req.TenantID, decoded.TenantID)
		assert.Equal(t, req.UserID, decoded.UserID)
		assert.Equal(t, req.Email, decoded.Email)
		assert.Equal(t, req.Username, decoded.Username)
		assert.Equal(t, req.Name, decoded.Name)
		assert.Equal(t, req.Enabled, decoded.Enabled)
		assert.Equal(t, req.Attributes, decoded.Attributes)
	})

	t.Run("IAMUserResponse", func(t *testing.T) {
		resp := IAMUserResponse{
			ID:        "user-1",
			TenantID:  "tenant-1",
			Email:     "test@example.com",
			Username:  "testuser",
			Name:      "Test User",
			Enabled:   true,
			Roles:     []string{"admin", "user"},
			Groups:    []string{"group-1"},
			CreatedAt: time.Now().Unix(),
			UpdatedAt: time.Now().Unix(),
			Timestamp: time.Now().Unix(),
		}

		encoded, err := quic.EncodePayload(resp)
		require.NoError(t, err)

		var decoded IAMUserResponse
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, resp.ID, decoded.ID)
		assert.Equal(t, resp.TenantID, decoded.TenantID)
		assert.Equal(t, resp.Email, decoded.Email)
		assert.Equal(t, resp.Roles, decoded.Roles)
		assert.Equal(t, resp.Groups, decoded.Groups)
	})

	t.Run("CheckPermissionRequest", func(t *testing.T) {
		req := CheckPermissionRequest{
			TenantID:  "tenant-1",
			SubjectID: "user-1",
			Resource:  "document:123",
			Action:    "read",
			Context: map[string]string{
				"ip": "192.168.1.1",
			},
		}

		encoded, err := quic.EncodePayload(req)
		require.NoError(t, err)

		var decoded CheckPermissionRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, req.TenantID, decoded.TenantID)
		assert.Equal(t, req.SubjectID, decoded.SubjectID)
		assert.Equal(t, req.Resource, decoded.Resource)
		assert.Equal(t, req.Action, decoded.Action)
		assert.Equal(t, req.Context, decoded.Context)
	})
}
