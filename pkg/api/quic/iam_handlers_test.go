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

package quic

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = quicwire.SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock IAM Service
// =============================================================================

// mockIAMService implements IAMService for testing
type mockIAMService struct {
	users  map[string]*IAMUserInfo
	roles  map[string]*IAMRoleInfo
	groups map[string]*IAMGroupInfo
	tokens map[string]*mockToken

	createUserError        error
	getUserError           error
	listUsersError         error
	updateUserError        error
	deleteUserError        error
	createRoleError        error
	getRoleError           error
	listRolesError         error
	updateRoleError        error
	deleteRoleError        error
	assignRoleError        error
	revokeRoleError        error
	createGroupError       error
	getGroupError          error
	listGroupsError        error
	updateGroupError       error
	deleteGroupError       error
	addGroupMemberError    error
	removeGroupMemberError error
	checkPermissionError   error
	checkPermissionResult  *IAMCheckPermissionResponse
	createTokenError       error
	verifyTokenError       error
	verifyTokenResult      *IAMTokenVerifyResponse
	revokeTokenError       error
}

type mockToken struct {
	tokenID  string
	userID   string
	tenantID string
	scopes   []string
	expires  time.Time
}

func newMockIAMService() *mockIAMService {
	return &mockIAMService{
		users:  make(map[string]*IAMUserInfo),
		roles:  make(map[string]*IAMRoleInfo),
		groups: make(map[string]*IAMGroupInfo),
		tokens: make(map[string]*mockToken),
	}
}

func (m *mockIAMService) CreateUser(ctx context.Context, tenantID string, req *IAMCreateUserRequest) (*IAMUserInfo, error) {
	if m.createUserError != nil {
		return nil, m.createUserError
	}
	user := &IAMUserInfo{
		ID:         "user-" + req.Email,
		TenantID:   tenantID,
		Email:      req.Email,
		Username:   req.Username,
		Name:       req.Name,
		Roles:      req.Roles,
		Groups:     req.Groups,
		Attributes: req.Attributes,
		CreatedAt:  time.Now().Unix(),
		UpdatedAt:  time.Now().Unix(),
	}
	m.users[user.ID] = user
	return user, nil
}

func (m *mockIAMService) GetUser(ctx context.Context, tenantID, userID string) (*IAMUserInfo, error) {
	if m.getUserError != nil {
		return nil, m.getUserError
	}
	user, ok := m.users[userID]
	if !ok {
		return nil, ErrIAMUserNotFound{}
	}
	return user, nil
}

func (m *mockIAMService) ListUsers(ctx context.Context, tenantID string, req *IAMListRequest) (*IAMUserListResponse, error) {
	if m.listUsersError != nil {
		return nil, m.listUsersError
	}
	users := make([]*IAMUserInfo, 0, len(m.users))
	for _, u := range m.users {
		if u.TenantID == tenantID {
			users = append(users, u)
		}
	}
	return &IAMUserListResponse{
		Users:  users,
		Total:  int64(len(users)),
		Limit:  req.Limit,
		Offset: req.Offset,
	}, nil
}

func (m *mockIAMService) UpdateUser(ctx context.Context, tenantID, userID string, req *IAMUpdateUserRequest) (*IAMUserInfo, error) {
	if m.updateUserError != nil {
		return nil, m.updateUserError
	}
	user, ok := m.users[userID]
	if !ok {
		return nil, ErrIAMUserNotFound{}
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Name != "" {
		user.Name = req.Name
	}
	user.UpdatedAt = time.Now().Unix()
	return user, nil
}

func (m *mockIAMService) DeleteUser(ctx context.Context, tenantID, userID string) error {
	if m.deleteUserError != nil {
		return m.deleteUserError
	}
	if _, ok := m.users[userID]; !ok {
		return ErrIAMUserNotFound{}
	}
	delete(m.users, userID)
	return nil
}

func (m *mockIAMService) CreateRole(ctx context.Context, tenantID string, req *IAMCreateRoleRequest) (*IAMRoleInfo, error) {
	if m.createRoleError != nil {
		return nil, m.createRoleError
	}
	roleID := req.ID
	if roleID == "" {
		roleID = "role-" + req.Name
	}
	role := &IAMRoleInfo{
		ID:          roleID,
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
	}
	m.roles[role.ID] = role
	return role, nil
}

func (m *mockIAMService) GetRole(ctx context.Context, tenantID, roleID string) (*IAMRoleInfo, error) {
	if m.getRoleError != nil {
		return nil, m.getRoleError
	}
	role, ok := m.roles[roleID]
	if !ok {
		return nil, ErrIAMRoleNotFound{}
	}
	return role, nil
}

func (m *mockIAMService) ListRoles(ctx context.Context, tenantID string, req *IAMListRequest) (*IAMRoleListResponse, error) {
	if m.listRolesError != nil {
		return nil, m.listRolesError
	}
	roles := make([]*IAMRoleInfo, 0, len(m.roles))
	for _, r := range m.roles {
		if r.TenantID == tenantID {
			roles = append(roles, r)
		}
	}
	return &IAMRoleListResponse{
		Roles:  roles,
		Total:  int64(len(roles)),
		Limit:  req.Limit,
		Offset: req.Offset,
	}, nil
}

func (m *mockIAMService) UpdateRole(ctx context.Context, tenantID, roleID string, req *IAMUpdateRoleRequest) (*IAMRoleInfo, error) {
	if m.updateRoleError != nil {
		return nil, m.updateRoleError
	}
	role, ok := m.roles[roleID]
	if !ok {
		return nil, ErrIAMRoleNotFound{}
	}
	if req.Name != "" {
		role.Name = req.Name
	}
	if req.Description != "" {
		role.Description = req.Description
	}
	role.UpdatedAt = time.Now().Unix()
	return role, nil
}

func (m *mockIAMService) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	if m.deleteRoleError != nil {
		return m.deleteRoleError
	}
	if _, ok := m.roles[roleID]; !ok {
		return ErrIAMRoleNotFound{}
	}
	delete(m.roles, roleID)
	return nil
}

func (m *mockIAMService) AssignRole(ctx context.Context, tenantID, userID, roleID string) error {
	if m.assignRoleError != nil {
		return m.assignRoleError
	}
	user, ok := m.users[userID]
	if !ok {
		return ErrIAMUserNotFound{}
	}
	if _, ok := m.roles[roleID]; !ok {
		return ErrIAMRoleNotFound{}
	}
	user.Roles = append(user.Roles, roleID)
	return nil
}

func (m *mockIAMService) RevokeRole(ctx context.Context, tenantID, userID, roleID string) error {
	if m.revokeRoleError != nil {
		return m.revokeRoleError
	}
	user, ok := m.users[userID]
	if !ok {
		return ErrIAMUserNotFound{}
	}
	for i, r := range user.Roles {
		if r == roleID {
			user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
			return nil
		}
	}
	return ErrIAMRoleNotFound{}
}

func (m *mockIAMService) CreateGroup(ctx context.Context, tenantID string, req *IAMCreateGroupRequest) (*IAMGroupInfo, error) {
	if m.createGroupError != nil {
		return nil, m.createGroupError
	}
	groupID := req.ID
	if groupID == "" {
		groupID = "group-" + req.Name
	}
	group := &IAMGroupInfo{
		ID:          groupID,
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Members:     []string{},
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
	}
	m.groups[group.ID] = group
	return group, nil
}

func (m *mockIAMService) GetGroup(ctx context.Context, tenantID, groupID string) (*IAMGroupInfo, error) {
	if m.getGroupError != nil {
		return nil, m.getGroupError
	}
	group, ok := m.groups[groupID]
	if !ok {
		return nil, ErrIAMGroupNotFound{}
	}
	return group, nil
}

func (m *mockIAMService) ListGroups(ctx context.Context, tenantID string, req *IAMListRequest) (*IAMGroupListResponse, error) {
	if m.listGroupsError != nil {
		return nil, m.listGroupsError
	}
	groups := make([]*IAMGroupInfo, 0, len(m.groups))
	for _, g := range m.groups {
		if g.TenantID == tenantID {
			groups = append(groups, g)
		}
	}
	return &IAMGroupListResponse{
		Groups: groups,
		Total:  int64(len(groups)),
		Limit:  req.Limit,
		Offset: req.Offset,
	}, nil
}

func (m *mockIAMService) UpdateGroup(ctx context.Context, tenantID, groupID string, req *IAMUpdateGroupRequest) (*IAMGroupInfo, error) {
	if m.updateGroupError != nil {
		return nil, m.updateGroupError
	}
	group, ok := m.groups[groupID]
	if !ok {
		return nil, ErrIAMGroupNotFound{}
	}
	if req.Name != "" {
		group.Name = req.Name
	}
	if req.Description != "" {
		group.Description = req.Description
	}
	group.UpdatedAt = time.Now().Unix()
	return group, nil
}

func (m *mockIAMService) DeleteGroup(ctx context.Context, tenantID, groupID string) error {
	if m.deleteGroupError != nil {
		return m.deleteGroupError
	}
	if _, ok := m.groups[groupID]; !ok {
		return ErrIAMGroupNotFound{}
	}
	delete(m.groups, groupID)
	return nil
}

func (m *mockIAMService) AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	if m.addGroupMemberError != nil {
		return m.addGroupMemberError
	}
	group, ok := m.groups[groupID]
	if !ok {
		return ErrIAMGroupNotFound{}
	}
	if _, ok := m.users[userID]; !ok {
		return ErrIAMUserNotFound{}
	}
	group.Members = append(group.Members, userID)
	return nil
}

func (m *mockIAMService) RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	if m.removeGroupMemberError != nil {
		return m.removeGroupMemberError
	}
	group, ok := m.groups[groupID]
	if !ok {
		return ErrIAMGroupNotFound{}
	}
	for i, member := range group.Members {
		if member == userID {
			group.Members = append(group.Members[:i], group.Members[i+1:]...)
			return nil
		}
	}
	return ErrIAMUserNotFound{}
}

func (m *mockIAMService) CheckPermission(ctx context.Context, req *IAMCheckPermissionRequest) (*IAMCheckPermissionResponse, error) {
	if m.checkPermissionError != nil {
		return nil, m.checkPermissionError
	}
	if m.checkPermissionResult != nil {
		return m.checkPermissionResult, nil
	}
	return &IAMCheckPermissionResponse{
		Allowed: true,
		Reason:  "allowed by default",
	}, nil
}

func (m *mockIAMService) CreateToken(ctx context.Context, tenantID, userID string, req *IAMCreateTokenRequest) (*IAMTokenResponse, error) {
	if m.createTokenError != nil {
		return nil, m.createTokenError
	}
	tokenID := "token-" + userID
	m.tokens[tokenID] = &mockToken{
		tokenID:  tokenID,
		userID:   userID,
		tenantID: tenantID,
		scopes:   req.Scopes,
		expires:  time.Now().Add(time.Duration(req.ExpiresIn) * time.Second),
	}
	return &IAMTokenResponse{
		TokenID:      tokenID,
		AccessToken:  "access-" + tokenID,
		RefreshToken: "refresh-" + tokenID,
		ExpiresIn:    req.ExpiresIn,
		TokenType:    "Bearer",
	}, nil
}

func (m *mockIAMService) VerifyToken(ctx context.Context, token string) (*IAMTokenVerifyResponse, error) {
	if m.verifyTokenError != nil {
		return nil, m.verifyTokenError
	}
	if m.verifyTokenResult != nil {
		return m.verifyTokenResult, nil
	}
	return &IAMTokenVerifyResponse{
		Valid:     true,
		UserID:    "user-123",
		TenantID:  "tenant-123",
		Scopes:    []string{"read", "write"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, nil
}

func (m *mockIAMService) RevokeToken(ctx context.Context, tokenID string) error {
	if m.revokeTokenError != nil {
		return m.revokeTokenError
	}
	delete(m.tokens, tokenID)
	return nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestIAMLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestIAMHandler() (*IAMHandler, *mockIAMService) {
	logger := newTestIAMLogger()
	service := newMockIAMService()
	handler := NewIAMHandler(logger, service)
	return handler, service
}

func createTestUser(service *mockIAMService, id, tenantID, email string) *IAMUserInfo {
	user := &IAMUserInfo{
		ID:        id,
		TenantID:  tenantID,
		Email:     email,
		Username:  "testuser",
		Name:      "Test User",
		Roles:     []string{},
		Groups:    []string{},
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}
	service.users[id] = user
	return user
}

func createTestRole(service *mockIAMService, id, tenantID, name string) *IAMRoleInfo {
	role := &IAMRoleInfo{
		ID:          id,
		TenantID:    tenantID,
		Name:        name,
		Description: "Test Role",
		Permissions: []string{"read", "write"},
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
	}
	service.roles[id] = role
	return role
}

func createTestGroup(service *mockIAMService, id, tenantID, name string) *IAMGroupInfo {
	group := &IAMGroupInfo{
		ID:          id,
		TenantID:    tenantID,
		Name:        name,
		Description: "Test Group",
		Members:     []string{},
		CreatedAt:   time.Now().Unix(),
		UpdatedAt:   time.Now().Unix(),
	}
	service.groups[id] = group
	return group
}

// =============================================================================
// Test: NewIAMHandler
// =============================================================================

func TestNewIAMHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newTestIAMLogger()
		service := newMockIAMService()
		handler := NewIAMHandler(logger, service)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, service, handler.service)
	})

	t.Run("creates handler with nil service", func(t *testing.T) {
		logger := newTestIAMLogger()
		handler := NewIAMHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.service)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestIAMHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		req := &quicwire.Request{
			Opcode: 0x00, // Unknown opcode
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown IAM operation")
	})
}

// =============================================================================
// Test: User Create
// =============================================================================

func TestHandleUserCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates user successfully", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateUserRequest{
			TenantID: "tenant-1",
			Email:    "test@example.com",
			Username: "testuser",
			Name:     "Test User",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var userResp IAMUserResponse
		err = quicwire.DecodePayload(resp.Payload, &userResp)
		require.NoError(t, err)

		assert.NotNil(t, userResp.User)
		assert.Equal(t, "test@example.com", userResp.User.Email)
		assert.Equal(t, "testuser", userResp.User.Username)
		assert.Greater(t, userResp.Timestamp, int64(0))
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		createReq := &IAMCreateUserRequest{
			TenantID: "tenant-1",
			Email:    "test@example.com",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateUserRequest{
			Email: "test@example.com",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing email", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateUserRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserCreate,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		service.createUserError = ErrIAMUserAlreadyExists{}

		createReq := &IAMCreateUserRequest{
			TenantID: "tenant-1",
			Email:    "test@example.com",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})
}

// =============================================================================
// Test: User Get
// =============================================================================

func TestHandleUserGet(t *testing.T) {
	ctx := context.Background()

	t.Run("gets user successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestUser(service, "user-1", "tenant-1", "test@example.com")

		getReq := &IAMGetUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var userResp IAMUserResponse
		err = quicwire.DecodePayload(resp.Payload, &userResp)
		require.NoError(t, err)

		assert.NotNil(t, userResp.User)
		assert.Equal(t, "user-1", userResp.User.ID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		getReq := &IAMGetUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetUserRequest{
			UserID: "user-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing user ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetUserRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for user not found", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetUserRequest{
			TenantID: "tenant-1",
			UserID:   "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: User List
// =============================================================================

func TestHandleUserList(t *testing.T) {
	ctx := context.Background()

	t.Run("lists users successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestUser(service, "user-1", "tenant-1", "test1@example.com")
		createTestUser(service, "user-2", "tenant-1", "test2@example.com")

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
			Limit:    10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp IAMUserListResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int64(2), listResp.Total)
		assert.Len(t, listResp.Users, 2)
	})

	t.Run("applies default limit", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp IAMUserListResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, iamDefaultLimit, listResp.Limit)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
			Limit:    5000, // exceeds max
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp IAMUserListResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, iamMaxLimit, listResp.Limit)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		listReq := &IAMListRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		service.listUsersError = errors.New("database connection failed")

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: User Update
// =============================================================================

func TestHandleUserUpdate(t *testing.T) {
	ctx := context.Background()

	t.Run("updates user successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestUser(service, "user-1", "tenant-1", "test@example.com")

		updateReq := &IAMUpdateUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
			Name:     "Updated Name",
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var userResp IAMUserResponse
		err = quicwire.DecodePayload(resp.Payload, &userResp)
		require.NoError(t, err)

		assert.Equal(t, "Updated Name", userResp.User.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		updateReq := &IAMUpdateUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		updateReq := &IAMUpdateUserRequest{
			UserID: "user-1",
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing user ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		updateReq := &IAMUpdateUserRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for user not found", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		updateReq := &IAMUpdateUserRequest{
			TenantID: "tenant-1",
			UserID:   "nonexistent",
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserUpdate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: User Delete
// =============================================================================

func TestHandleUserDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes user successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestUser(service, "user-1", "tenant-1", "test@example.com")

		deleteReq := &IAMDeleteUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		deleteReq := &IAMDeleteUserRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteUserRequest{
			UserID: "user-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing user ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteUserRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for user not found", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteUserRequest{
			TenantID: "tenant-1",
			UserID:   "nonexistent",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMUserDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Role Create
// =============================================================================

func TestHandleRoleCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates role successfully", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateRoleRequest{
			TenantID:    "tenant-1",
			Name:        "admin",
			Description: "Administrator role",
			Permissions: []string{"read", "write", "delete"},
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var roleResp IAMRoleResponse
		err = quicwire.DecodePayload(resp.Payload, &roleResp)
		require.NoError(t, err)

		assert.NotNil(t, roleResp.Role)
		assert.Equal(t, "admin", roleResp.Role.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		createReq := &IAMCreateRoleRequest{
			TenantID: "tenant-1",
			Name:     "admin",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateRoleRequest{
			Name: "admin",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateRoleRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Role Get
// =============================================================================

func TestHandleRoleGet(t *testing.T) {
	ctx := context.Background()

	t.Run("gets role successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestRole(service, "role-1", "tenant-1", "admin")

		getReq := &IAMGetRoleRequest{
			TenantID: "tenant-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var roleResp IAMRoleResponse
		err = quicwire.DecodePayload(resp.Payload, &roleResp)
		require.NoError(t, err)

		assert.NotNil(t, roleResp.Role)
		assert.Equal(t, "role-1", roleResp.Role.ID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		getReq := &IAMGetRoleRequest{
			TenantID: "tenant-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetRoleRequest{
			RoleID: "role-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing role ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetRoleRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for role not found", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetRoleRequest{
			TenantID: "tenant-1",
			RoleID:   "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Role List
// =============================================================================

func TestHandleRoleList(t *testing.T) {
	ctx := context.Background()

	t.Run("lists roles successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestRole(service, "role-1", "tenant-1", "admin")
		createTestRole(service, "role-2", "tenant-1", "user")

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
			Limit:    10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp IAMRoleListResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int64(2), listResp.Total)
		assert.Len(t, listResp.Roles, 2)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		listReq := &IAMListRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Role Assign
// =============================================================================

func TestHandleRoleAssign(t *testing.T) {
	ctx := context.Background()

	t.Run("assigns role successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestUser(service, "user-1", "tenant-1", "test@example.com")
		createTestRole(service, "role-1", "tenant-1", "admin")

		assignReq := &IAMAssignRoleRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(assignReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleAssign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		assignReq := &IAMAssignRoleRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(assignReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleAssign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		assignReq := &IAMAssignRoleRequest{
			UserID: "user-1",
			RoleID: "role-1",
		}

		payload, err := quicwire.EncodePayload(assignReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleAssign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing user ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		assignReq := &IAMAssignRoleRequest{
			TenantID: "tenant-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(assignReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleAssign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing role ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		assignReq := &IAMAssignRoleRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(assignReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleAssign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Role Revoke
// =============================================================================

func TestHandleRoleRevoke(t *testing.T) {
	ctx := context.Background()

	t.Run("revokes role successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		user := createTestUser(service, "user-1", "tenant-1", "test@example.com")
		createTestRole(service, "role-1", "tenant-1", "admin")
		user.Roles = []string{"role-1"}

		revokeReq := &IAMRevokeRoleRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(revokeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleRevoke,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		revokeReq := &IAMRevokeRoleRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(revokeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleRevoke,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		revokeReq := &IAMRevokeRoleRequest{
			UserID: "user-1",
			RoleID: "role-1",
		}

		payload, err := quicwire.EncodePayload(revokeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleRevoke,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Role Delete
// =============================================================================

func TestHandleRoleDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes role successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestRole(service, "role-1", "tenant-1", "admin")

		deleteReq := &IAMDeleteRoleRequest{
			TenantID: "tenant-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		deleteReq := &IAMDeleteRoleRequest{
			TenantID: "tenant-1",
			RoleID:   "role-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteRoleRequest{
			RoleID: "role-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing role ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteRoleRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for role not found", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteRoleRequest{
			TenantID: "tenant-1",
			RoleID:   "nonexistent",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMRoleDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Group Create
// =============================================================================

func TestHandleGroupCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates group successfully", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateGroupRequest{
			TenantID:    "tenant-1",
			Name:        "developers",
			Description: "Development team",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var groupResp IAMGroupResponse
		err = quicwire.DecodePayload(resp.Payload, &groupResp)
		require.NoError(t, err)

		assert.NotNil(t, groupResp.Group)
		assert.Equal(t, "developers", groupResp.Group.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		createReq := &IAMCreateGroupRequest{
			TenantID: "tenant-1",
			Name:     "developers",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateGroupRequest{
			Name: "developers",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		createReq := &IAMCreateGroupRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Group Get
// =============================================================================

func TestHandleGroupGet(t *testing.T) {
	ctx := context.Background()

	t.Run("gets group successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestGroup(service, "group-1", "tenant-1", "developers")

		getReq := &IAMGetGroupRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var groupResp IAMGroupResponse
		err = quicwire.DecodePayload(resp.Payload, &groupResp)
		require.NoError(t, err)

		assert.NotNil(t, groupResp.Group)
		assert.Equal(t, "group-1", groupResp.Group.ID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		getReq := &IAMGetGroupRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetGroupRequest{
			GroupID: "group-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing group ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetGroupRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for group not found", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		getReq := &IAMGetGroupRequest{
			TenantID: "tenant-1",
			GroupID:  "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupGet,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Group List
// =============================================================================

func TestHandleGroupList(t *testing.T) {
	ctx := context.Background()

	t.Run("lists groups successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestGroup(service, "group-1", "tenant-1", "developers")
		createTestGroup(service, "group-2", "tenant-1", "testers")

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
			Limit:    10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp IAMGroupListResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int64(2), listResp.Total)
		assert.Len(t, listResp.Groups, 2)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		listReq := &IAMListRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		listReq := &IAMListRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Group Delete
// =============================================================================

func TestHandleGroupDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes group successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestGroup(service, "group-1", "tenant-1", "developers")

		deleteReq := &IAMDeleteGroupRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		deleteReq := &IAMDeleteGroupRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteGroupRequest{
			GroupID: "group-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing group ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteGroupRequest{
			TenantID: "tenant-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for group not found", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		deleteReq := &IAMDeleteGroupRequest{
			TenantID: "tenant-1",
			GroupID:  "nonexistent",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Group Add Member
// =============================================================================

func TestHandleGroupAddMember(t *testing.T) {
	ctx := context.Background()

	t.Run("adds member successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestUser(service, "user-1", "tenant-1", "test@example.com")
		createTestGroup(service, "group-1", "tenant-1", "developers")

		memberReq := &IAMGroupMemberRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupAddMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		memberReq := &IAMGroupMemberRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupAddMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		memberReq := &IAMGroupMemberRequest{
			GroupID: "group-1",
			UserID:  "user-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupAddMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing group ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		memberReq := &IAMGroupMemberRequest{
			TenantID: "tenant-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupAddMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing user ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		memberReq := &IAMGroupMemberRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupAddMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Group Remove Member
// =============================================================================

func TestHandleGroupRemoveMember(t *testing.T) {
	ctx := context.Background()

	t.Run("removes member successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		createTestUser(service, "user-1", "tenant-1", "test@example.com")
		group := createTestGroup(service, "group-1", "tenant-1", "developers")
		group.Members = []string{"user-1"}

		memberReq := &IAMGroupMemberRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupRemoveMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		memberReq := &IAMGroupMemberRequest{
			TenantID: "tenant-1",
			GroupID:  "group-1",
			UserID:   "user-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupRemoveMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		memberReq := &IAMGroupMemberRequest{
			GroupID: "group-1",
			UserID:  "user-1",
		}

		payload, err := quicwire.EncodePayload(memberReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMGroupRemoveMember,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Check Permission
// =============================================================================

func TestHandleCheckPermission(t *testing.T) {
	ctx := context.Background()

	t.Run("checks permission successfully", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		checkReq := &IAMCheckPermissionRequest{
			TenantID:  "tenant-1",
			SubjectID: "user-1",
			Resource:  "document:123",
			Action:    "read",
		}

		payload, err := quicwire.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMCheckPermission,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var checkResp IAMCheckPermissionResponse
		err = quicwire.DecodePayload(resp.Payload, &checkResp)
		require.NoError(t, err)

		assert.True(t, checkResp.Allowed)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		checkReq := &IAMCheckPermissionRequest{
			TenantID:  "tenant-1",
			SubjectID: "user-1",
			Resource:  "document:123",
			Action:    "read",
		}

		payload, err := quicwire.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMCheckPermission,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		checkReq := &IAMCheckPermissionRequest{
			SubjectID: "user-1",
			Resource:  "document:123",
			Action:    "read",
		}

		payload, err := quicwire.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMCheckPermission,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing subject ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		checkReq := &IAMCheckPermissionRequest{
			TenantID: "tenant-1",
			Resource: "document:123",
			Action:   "read",
		}

		payload, err := quicwire.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMCheckPermission,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing resource", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		checkReq := &IAMCheckPermissionRequest{
			TenantID:  "tenant-1",
			SubjectID: "user-1",
			Action:    "read",
		}

		payload, err := quicwire.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMCheckPermission,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing action", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		checkReq := &IAMCheckPermissionRequest{
			TenantID:  "tenant-1",
			SubjectID: "user-1",
			Resource:  "document:123",
		}

		payload, err := quicwire.EncodePayload(checkReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMCheckPermission,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Token Create
// =============================================================================

func TestHandleTokenCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates token successfully", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		tokenReq := &IAMCreateTokenRequest{
			TenantID:  "tenant-1",
			UserID:    "user-1",
			Scopes:    []string{"read", "write"},
			ExpiresIn: 3600,
		}

		payload, err := quicwire.EncodePayload(tokenReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var tokenResp IAMTokenResponse
		err = quicwire.DecodePayload(resp.Payload, &tokenResp)
		require.NoError(t, err)

		assert.NotEmpty(t, tokenResp.TokenID)
		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		tokenReq := &IAMCreateTokenRequest{
			TenantID:  "tenant-1",
			UserID:    "user-1",
			Scopes:    []string{"read"},
			ExpiresIn: 3600,
		}

		payload, err := quicwire.EncodePayload(tokenReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing tenant ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		tokenReq := &IAMCreateTokenRequest{
			UserID:    "user-1",
			ExpiresIn: 3600,
		}

		payload, err := quicwire.EncodePayload(tokenReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing user ID", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		tokenReq := &IAMCreateTokenRequest{
			TenantID:  "tenant-1",
			ExpiresIn: 3600,
		}

		payload, err := quicwire.EncodePayload(tokenReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Token Verify
// =============================================================================

func TestHandleTokenVerify(t *testing.T) {
	ctx := context.Background()

	t.Run("verifies token successfully", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		verifyReq := &IAMVerifyTokenRequest{
			Token: "valid-token",
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var verifyResp IAMTokenVerifyResponse
		err = quicwire.DecodePayload(resp.Payload, &verifyResp)
		require.NoError(t, err)

		assert.True(t, verifyResp.Valid)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		verifyReq := &IAMVerifyTokenRequest{
			Token: "some-token",
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing token", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		verifyReq := &IAMVerifyTokenRequest{}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid token", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		service.verifyTokenError = ErrIAMTokenInvalid{}

		verifyReq := &IAMVerifyTokenRequest{
			Token: "invalid-token",
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnauthorized, resp.Status)
	})
}

// =============================================================================
// Test: Token Revoke
// =============================================================================

func TestHandleTokenRevoke(t *testing.T) {
	ctx := context.Background()

	t.Run("revokes token by ID successfully", func(t *testing.T) {
		handler, service := createTestIAMHandler()
		service.tokens["token-123"] = &mockToken{tokenID: "token-123"}

		revokeReq := &IAMRevokeTokenRequest{
			TokenID: "token-123",
		}

		payload, err := quicwire.EncodePayload(revokeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenRevoke,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("revokes token by token value successfully", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		revokeReq := &IAMRevokeTokenRequest{
			Token: "access-token-value",
		}

		payload, err := quicwire.EncodePayload(revokeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenRevoke,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var successResp IAMSuccessResponse
		err = quicwire.DecodePayload(resp.Payload, &successResp)
		require.NoError(t, err)

		assert.True(t, successResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewIAMHandler(newTestIAMLogger(), nil)

		revokeReq := &IAMRevokeTokenRequest{
			TokenID: "token-123",
		}

		payload, err := quicwire.EncodePayload(revokeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenRevoke,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing token", func(t *testing.T) {
		handler, _ := createTestIAMHandler()

		revokeReq := &IAMRevokeTokenRequest{}

		payload, err := quicwire.EncodePayload(revokeReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpIAMTokenRevoke,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestIAMErrorTypes(t *testing.T) {
	t.Run("ErrIAMEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrIAMEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "failed to encode IAM payload")
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("ErrIAMDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrIAMDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "failed to decode IAM payload")
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("ErrIAMOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrIAMOperationFailed{Operation: "create", Cause: cause}

		assert.Contains(t, err.Error(), "IAM operation create failed")
		assert.Equal(t, cause, errors.Unwrap(err))
	})

	t.Run("ErrIAMUserNotFound", func(t *testing.T) {
		err := ErrIAMUserNotFound{}
		assert.Equal(t, "user not found", err.Error())
		assert.True(t, errors.Is(err, ErrIAMUserNotFound{}))
	})

	t.Run("ErrIAMRoleNotFound", func(t *testing.T) {
		err := ErrIAMRoleNotFound{}
		assert.Equal(t, "role not found", err.Error())
		assert.True(t, errors.Is(err, ErrIAMRoleNotFound{}))
	})

	t.Run("ErrIAMGroupNotFound", func(t *testing.T) {
		err := ErrIAMGroupNotFound{}
		assert.Equal(t, "group not found", err.Error())
		assert.True(t, errors.Is(err, ErrIAMGroupNotFound{}))
	})

	t.Run("ErrIAMUserAlreadyExists", func(t *testing.T) {
		err := ErrIAMUserAlreadyExists{}
		assert.Equal(t, "user already exists", err.Error())
		assert.True(t, errors.Is(err, ErrIAMUserAlreadyExists{}))
	})

	t.Run("ErrIAMRoleAlreadyExists", func(t *testing.T) {
		err := ErrIAMRoleAlreadyExists{}
		assert.Equal(t, "role already exists", err.Error())
		assert.True(t, errors.Is(err, ErrIAMRoleAlreadyExists{}))
	})

	t.Run("ErrIAMGroupAlreadyExists", func(t *testing.T) {
		err := ErrIAMGroupAlreadyExists{}
		assert.Equal(t, "group already exists", err.Error())
		assert.True(t, errors.Is(err, ErrIAMGroupAlreadyExists{}))
	})

	t.Run("ErrIAMPermissionDenied", func(t *testing.T) {
		err := ErrIAMPermissionDenied{}
		assert.Equal(t, "permission denied", err.Error())
		assert.True(t, errors.Is(err, ErrIAMPermissionDenied{}))
	})

	t.Run("ErrIAMTokenExpired", func(t *testing.T) {
		err := ErrIAMTokenExpired{}
		assert.Equal(t, "token expired", err.Error())
		assert.True(t, errors.Is(err, ErrIAMTokenExpired{}))
	})

	t.Run("ErrIAMTokenInvalid", func(t *testing.T) {
		err := ErrIAMTokenInvalid{}
		assert.Equal(t, "token invalid", err.Error())
		assert.True(t, errors.Is(err, ErrIAMTokenInvalid{}))
	})

	t.Run("ErrIAMTokenVerificationFailed", func(t *testing.T) {
		cause := errors.New("verification failed")
		err := ErrIAMTokenVerificationFailed{Cause: cause}

		assert.Contains(t, err.Error(), "token verification failed")
		assert.Equal(t, cause, errors.Unwrap(err))
	})
}

// =============================================================================
// Test: IAM Error Response Mapping
// =============================================================================

func TestIAMErrorResponseMapping(t *testing.T) {
	handler, service := createTestIAMHandler()
	ctx := context.Background()

	tests := []struct {
		name           string
		setupError     func()
		expectedStatus byte
	}{
		{
			name: "user not found maps to StatusNotFound",
			setupError: func() {
				service.getUserError = ErrIAMUserNotFound{}
			},
			expectedStatus: quicwire.StatusNotFound,
		},
		{
			name: "user already exists maps to StatusAlreadyExists",
			setupError: func() {
				service.createUserError = ErrIAMUserAlreadyExists{}
			},
			expectedStatus: quicwire.StatusAlreadyExists,
		},
		{
			name: "permission denied maps to StatusPermissionDenied",
			setupError: func() {
				service.checkPermissionError = ErrIAMPermissionDenied{}
			},
			expectedStatus: quicwire.StatusPermissionDenied,
		},
		{
			name: "token expired maps to StatusUnauthorized",
			setupError: func() {
				service.verifyTokenError = ErrIAMTokenExpired{}
			},
			expectedStatus: quicwire.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset errors
			service.getUserError = nil
			service.createUserError = nil
			service.checkPermissionError = nil
			service.verifyTokenError = nil

			tt.setupError()

			// Make appropriate request based on the error type
			var req *quicwire.Request
			var payload []byte
			var err error

			switch {
			case service.getUserError != nil:
				getReq := &IAMGetUserRequest{TenantID: "tenant-1", UserID: "user-1"}
				payload, err = quicwire.EncodePayload(getReq)
				require.NoError(t, err)
				req = &quicwire.Request{Opcode: quicwire.OpIAMUserGet, Payload: payload}

			case service.createUserError != nil:
				createReq := &IAMCreateUserRequest{TenantID: "tenant-1", Email: "test@example.com"}
				payload, err = quicwire.EncodePayload(createReq)
				require.NoError(t, err)
				req = &quicwire.Request{Opcode: quicwire.OpIAMUserCreate, Payload: payload}

			case service.checkPermissionError != nil:
				checkReq := &IAMCheckPermissionRequest{
					TenantID:  "tenant-1",
					SubjectID: "user-1",
					Resource:  "doc:1",
					Action:    "read",
				}
				payload, err = quicwire.EncodePayload(checkReq)
				require.NoError(t, err)
				req = &quicwire.Request{Opcode: quicwire.OpIAMCheckPermission, Payload: payload}

			case service.verifyTokenError != nil:
				verifyReq := &IAMVerifyTokenRequest{Token: "expired-token"}
				payload, err = quicwire.EncodePayload(verifyReq)
				require.NoError(t, err)
				req = &quicwire.Request{Opcode: quicwire.OpIAMTokenVerify, Payload: payload}
			}

			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, tt.expectedStatus, resp.Status)
		})
	}
}
