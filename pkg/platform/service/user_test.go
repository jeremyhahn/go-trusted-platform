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

package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockRoleDAO implements datastore.RoleDAO for testing
type MockRoleDAO struct {
	mock.Mock
}

func (m *MockRoleDAO) Save(ctx context.Context, role *entities.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRoleDAO) Get(ctx context.Context, id uint64) (*entities.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Role), args.Error(1)
}

func (m *MockRoleDAO) Delete(ctx context.Context, role *entities.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRoleDAO) GetByName(ctx context.Context, name string) (*entities.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Role), args.Error(1)
}

func (m *MockRoleDAO) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Role], error) {
	args := m.Called(ctx, pageQuery)
	return args.Get(0).(datastore.PageResult[*entities.Role]), args.Error(1)
}

func (m *MockRoleDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockRoleDAO) ForEachPage(ctx context.Context, pageQuery datastore.PageQuery, fn datastore.PagerFunc[*entities.Role]) error {
	args := m.Called(ctx, pageQuery, fn)
	return args.Error(0)
}

func TestNewUserService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	authServices := make(map[int]AuthServicer)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, authServices)

	require.NotNil(t, service)
	assert.IsType(t, &User{}, service)
}

func TestUser_Save_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	user := &entities.User{
		ID:    1,
		Email: "test@example.com",
	}

	mockUserDAO.On("Save", ctx, user).Return(nil)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	err := service.Save(ctx, user)

	require.NoError(t, err)
	mockUserDAO.AssertExpectations(t)
}

func TestUser_Save_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	user := &entities.User{
		ID:    1,
		Email: "test@example.com",
	}

	expectedErr := errors.New("database error")
	mockUserDAO.On("Save", ctx, user).Return(expectedErr)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	err := service.Save(ctx, user)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockUserDAO.AssertExpectations(t)
}

func TestUser_Delete_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	userID := uint64(123)

	mockUserDAO.On("Delete", ctx, &entities.User{ID: userID}).Return(nil)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	err := service.Delete(ctx, userID)

	require.NoError(t, err)
	mockUserDAO.AssertExpectations(t)
}

func TestUser_Delete_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	userID := uint64(123)

	expectedErr := errors.New("user not found")
	mockUserDAO.On("Delete", ctx, &entities.User{ID: userID}).Return(expectedErr)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	err := service.Delete(ctx, userID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockUserDAO.AssertExpectations(t)
}

func TestUser_Get_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	userID := uint64(456)
	expectedUser := &entities.User{
		ID:    userID,
		Email: "found@example.com",
	}

	mockUserDAO.On("Get", ctx, userID).Return(expectedUser, nil)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	user, err := service.Get(ctx, userID)

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, userID, user.ID)
	assert.Equal(t, "found@example.com", user.Email)
	mockUserDAO.AssertExpectations(t)
}

func TestUser_Get_NotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	userID := uint64(999)
	expectedErr := errors.New("record not found")

	mockUserDAO.On("Get", ctx, userID).Return(nil, expectedErr)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	user, err := service.Get(ctx, userID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, user)
	mockUserDAO.AssertExpectations(t)
}

func TestUser_Get_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	userID := uint64(123)
	expectedErr := errors.New("database connection error")

	mockUserDAO.On("Get", ctx, userID).Return(nil, expectedErr)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	user, err := service.Get(ctx, userID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, user)
	mockUserDAO.AssertExpectations(t)
}

func TestErrUnsupportedAuthType(t *testing.T) {
	assert.Equal(t, "unsupported auth type", ErrUnsupportedAuthType.Error())
}

func TestErrUserNotFound(t *testing.T) {
	// Test with no fields
	err := ErrUserNotFound{}
	assert.Equal(t, "user not found", err.Error())

	// Test with email
	errWithEmail := ErrUserNotFound{Email: "test@example.com"}
	assert.Equal(t, "user not found: email=test@example.com", errWithEmail.Error())

	// Test with ID
	errWithID := ErrUserNotFound{ID: 123}
	assert.Equal(t, "user not found: id=123", errWithID.Error())
}

func TestUserService_MultipleOperations(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	// Create user
	user := &entities.User{
		ID:    100,
		Email: "multi@example.com",
	}

	mockUserDAO.On("Save", ctx, user).Return(nil)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	err := service.Save(ctx, user)
	require.NoError(t, err)

	// Get user
	mockUserDAO.On("Get", ctx, user.ID).Return(user, nil)
	fetchedUser, err := service.Get(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, fetchedUser.Email)

	// Delete user
	mockUserDAO.On("Delete", ctx, &entities.User{ID: user.ID}).Return(nil)
	err = service.Delete(ctx, user.ID)
	require.NoError(t, err)

	mockUserDAO.AssertExpectations(t)
}

// TestUser_GetByEmail_Success verifies finding user by email
func TestUser_GetByEmail_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	email := "findme@example.com"
	expectedUser := &entities.User{
		ID:    42,
		Email: email,
	}

	// Mock ForEachPage to simulate finding the user
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			result := datastore.PageResult[*entities.User]{
				Entities: []*entities.User{
					{ID: 1, Email: "other@example.com"},
					expectedUser,
				},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(datastore.ErrStopIteration)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	user, err := service.GetByEmail(ctx, email)

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, uint64(42), user.ID)
	mockUserDAO.AssertExpectations(t)
}

// TestUser_GetByEmail_NotFound verifies error when email not found
func TestUser_GetByEmail_NotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	email := "notfound@example.com"

	// Mock ForEachPage with no matching user
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			result := datastore.PageResult[*entities.User]{
				Entities: []*entities.User{
					{ID: 1, Email: "other@example.com"},
					{ID: 2, Email: "another@example.com"},
				},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	user, err := service.GetByEmail(ctx, email)

	require.Error(t, err)
	assert.Nil(t, user)

	var errNotFound ErrUserNotFound
	assert.ErrorAs(t, err, &errNotFound)
	assert.Equal(t, email, errNotFound.Email)
	mockUserDAO.AssertExpectations(t)
}

// TestUser_GetByEmail_DAOError verifies error handling on DAO failure
func TestUser_GetByEmail_DAOError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	email := "test@example.com"
	expectedErr := errors.New("database connection lost")

	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).Return(expectedErr)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	user, err := service.GetByEmail(ctx, email)

	require.Error(t, err)
	assert.Nil(t, user)
	assert.Equal(t, expectedErr, err)
	mockUserDAO.AssertExpectations(t)
}

// TestUser_GetByTenant_Success verifies listing users by tenant
func TestUser_GetByTenant_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	tenantID := "tenant-123"
	expectedUsers := []*entities.User{
		{ID: 1, Email: "user1@example.com", TenantID: tenantID},
		{ID: 2, Email: "user2@example.com", TenantID: tenantID},
	}

	// Mock ForEachPage to return users in tenant
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			result := datastore.PageResult[*entities.User]{
				Entities: []*entities.User{
					{ID: 1, Email: "user1@example.com", TenantID: tenantID},
					{ID: 2, Email: "user2@example.com", TenantID: tenantID},
					{ID: 3, Email: "other@example.com", TenantID: "other-tenant"},
				},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	users, err := service.GetByTenant(ctx, tenantID)

	require.NoError(t, err)
	require.NotNil(t, users)
	assert.Len(t, users, 2)
	assert.Equal(t, expectedUsers[0].Email, users[0].Email)
	assert.Equal(t, expectedUsers[1].Email, users[1].Email)
	mockUserDAO.AssertExpectations(t)
}

// TestUser_GetByTenant_Empty verifies returning empty list for tenant with no users
func TestUser_GetByTenant_Empty(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	tenantID := "empty-tenant"

	// Mock ForEachPage with no matching users
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			result := datastore.PageResult[*entities.User]{
				Entities: []*entities.User{
					{ID: 1, Email: "user1@example.com", TenantID: "other-tenant"},
				},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	users, err := service.GetByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, users)
	mockUserDAO.AssertExpectations(t)
}

// TestUser_GetByTenant_DAOError verifies error handling on DAO failure
func TestUser_GetByTenant_DAOError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	tenantID := "tenant-123"
	expectedErr := errors.New("database error")

	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).Return(expectedErr)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	users, err := service.GetByTenant(ctx, tenantID)

	require.Error(t, err)
	assert.Nil(t, users)
	assert.Equal(t, expectedErr, err)
	mockUserDAO.AssertExpectations(t)
}

// TestUser_IsTenantOwner_Success verifies owner check
func TestUser_IsTenantOwner_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	t.Run("IsOwner", func(t *testing.T) {
		mockUserDAO2 := new(MockUserDAO)
		userID := uint64(123)
		user := &entities.User{
			ID:            userID,
			Email:         "owner@example.com",
			IsTenantOwner: true,
		}

		mockUserDAO2.On("Get", ctx, userID).Return(user, nil)

		service := NewUserService(logger, mockUserDAO2, mockRoleDAO, nil)
		isOwner, err := service.IsTenantOwner(ctx, userID)

		require.NoError(t, err)
		assert.True(t, isOwner)
		mockUserDAO2.AssertExpectations(t)
	})

	t.Run("NotOwner", func(t *testing.T) {
		mockUserDAO3 := new(MockUserDAO)
		userID := uint64(456)
		user := &entities.User{
			ID:            userID,
			Email:         "member@example.com",
			IsTenantOwner: false,
		}

		mockUserDAO3.On("Get", ctx, userID).Return(user, nil)

		service := NewUserService(logger, mockUserDAO3, mockRoleDAO, nil)
		isOwner, err := service.IsTenantOwner(ctx, userID)

		require.NoError(t, err)
		assert.False(t, isOwner)
		mockUserDAO3.AssertExpectations(t)
	})
}

// TestUser_IsTenantOwner_Error verifies error handling on DAO failure
func TestUser_IsTenantOwner_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockUserDAO := new(MockUserDAO)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	userID := uint64(999)
	expectedErr := errors.New("user not found")

	mockUserDAO.On("Get", ctx, userID).Return(nil, expectedErr)

	service := NewUserService(logger, mockUserDAO, mockRoleDAO, nil)
	isOwner, err := service.IsTenantOwner(ctx, userID)

	require.Error(t, err)
	assert.False(t, isOwner)
	assert.Equal(t, expectedErr, err)
	mockUserDAO.AssertExpectations(t)
}
