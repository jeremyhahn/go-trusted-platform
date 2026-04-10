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

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockOrganizationDAO implements datastore.OrganizationDAO for testing
type MockOrganizationDAO struct {
	mock.Mock
}

func (m *MockOrganizationDAO) Save(ctx context.Context, org *entities.Organization) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockOrganizationDAO) Get(ctx context.Context, id uint64) (*entities.Organization, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Organization), args.Error(1)
}

func (m *MockOrganizationDAO) Delete(ctx context.Context, org *entities.Organization) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockOrganizationDAO) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Organization], error) {
	args := m.Called(ctx, pageQuery)
	return args.Get(0).(datastore.PageResult[*entities.Organization]), args.Error(1)
}

func (m *MockOrganizationDAO) GetUsers(ctx context.Context, orgID uint64) ([]*entities.User, error) {
	args := m.Called(ctx, orgID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.User), args.Error(1)
}

func (m *MockOrganizationDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockOrganizationDAO) ForEachPage(ctx context.Context, pageQuery datastore.PageQuery, procFunc datastore.PagerFunc[*entities.Organization]) error {
	args := m.Called(ctx, pageQuery, procFunc)
	return args.Error(0)
}

func TestNewOrganizationService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	service := NewOrganizationService(logger, mockDAO)

	require.NotNil(t, service)
	assert.IsType(t, &Organization{}, service)
}

func TestOrganization_Create_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	org := &entities.Organization{
		Name: "Test Organization",
	}

	mockDAO.On("Save", mock.Anything, org).Return(nil)

	service := NewOrganizationService(logger, mockDAO)
	err := service.Create(ctx, org)

	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), org.ID) // ID should be set
	mockDAO.AssertExpectations(t)
}

func TestOrganization_Create_Error(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	org := &entities.Organization{
		Name: "Test Organization",
	}

	expectedErr := errors.New("database error")
	mockDAO.On("Save", mock.Anything, org).Return(expectedErr)

	service := NewOrganizationService(logger, mockDAO)
	err := service.Create(ctx, org)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockDAO.AssertExpectations(t)
}

func TestOrganization_Page_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	adminUser := &entities.User{
		ID:    1,
		Email: "admin@example.com",
		Roles: []*entities.Role{
			{Name: common.ROLE_ADMIN},
		},
	}

	session := CreateSession(logger, nil, 0, 0, nil, adminUser)

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}

	orgs := []*entities.Organization{
		{ID: 1, Name: "Org 1"},
		{ID: 2, Name: "Org 2"},
	}

	expectedResult := datastore.PageResult[*entities.Organization]{
		Entities: orgs,
		Page:     1,
		PageSize: 10,
		HasMore:  false,
	}

	mockDAO.On("Page", mock.Anything, pageQuery).Return(expectedResult, nil)

	service := NewOrganizationService(logger, mockDAO)
	result, err := service.Page(ctx, session, pageQuery)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.Equal(t, "Org 1", result.Entities[0].Name)
	mockDAO.AssertExpectations(t)
}

func TestOrganization_Page_PermissionDenied(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	nonAdminUser := &entities.User{
		ID:    2,
		Email: "user@example.com",
		Roles: []*entities.Role{
			{Name: "user"},
		},
	}

	session := CreateSession(logger, nil, 0, 0, nil, nonAdminUser)

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}

	service := NewOrganizationService(logger, mockDAO)
	result, err := service.Page(ctx, session, pageQuery)

	assert.Error(t, err)
	assert.Equal(t, ErrPermissionDenied, err)
	assert.Equal(t, 0, len(result.Entities))
}

func TestOrganization_GetUsers_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	adminUser := &entities.User{
		ID:    1,
		Email: "admin@example.com",
		Roles: []*entities.Role{
			{Name: common.ROLE_ADMIN},
		},
	}

	session := CreateSession(logger, []uint64{10}, 10, 0, nil, adminUser)

	users := []*entities.User{
		{ID: 1, Email: "user1@example.com"},
		{ID: 2, Email: "user2@example.com"},
	}

	mockDAO.On("GetUsers", mock.Anything, uint64(10)).Return(users, nil)

	service := NewOrganizationService(logger, mockDAO)
	result, err := service.GetUsers(ctx, session)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result))
	assert.Equal(t, "user1@example.com", result[0].Email)
	mockDAO.AssertExpectations(t)
}

func TestOrganization_GetUsers_PermissionDenied(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	nonAdminUser := &entities.User{
		ID:    2,
		Email: "user@example.com",
		Roles: []*entities.Role{
			{Name: "user"},
		},
	}

	session := CreateSession(logger, nil, 0, 0, nil, nonAdminUser)

	service := NewOrganizationService(logger, mockDAO)
	result, err := service.GetUsers(ctx, session)

	assert.Error(t, err)
	assert.Equal(t, ErrPermissionDenied, err)
	assert.Nil(t, result)
}

func TestOrganization_GetUsers_Error(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	adminUser := &entities.User{
		ID:    1,
		Email: "admin@example.com",
		Roles: []*entities.Role{
			{Name: common.ROLE_ADMIN},
		},
	}

	session := CreateSession(logger, []uint64{10}, 10, 0, nil, adminUser)

	expectedErr := errors.New("database error")
	mockDAO.On("GetUsers", mock.Anything, uint64(10)).Return(nil, expectedErr)

	service := NewOrganizationService(logger, mockDAO)
	result, err := service.GetUsers(ctx, session)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
	mockDAO.AssertExpectations(t)
}

func TestOrganization_Delete_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	adminUser := &entities.User{
		ID:    1,
		Email: "admin@example.com",
		Roles: []*entities.Role{
			{Name: common.ROLE_ADMIN},
		},
	}

	session := CreateSession(logger, []uint64{10}, 10, 0, nil, adminUser)

	mockDAO.On("Delete", mock.Anything, &entities.Organization{ID: 10}).Return(nil)

	service := NewOrganizationService(logger, mockDAO)
	err := service.Delete(ctx, session)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}

func TestOrganization_Delete_PermissionDenied(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	nonAdminUser := &entities.User{
		ID:    2,
		Email: "user@example.com",
		Roles: []*entities.Role{
			{Name: "user"},
		},
	}

	session := CreateSession(logger, nil, 0, 0, nil, nonAdminUser)

	service := NewOrganizationService(logger, mockDAO)
	err := service.Delete(ctx, session)

	assert.Error(t, err)
	assert.Equal(t, ErrPermissionDenied, err)
}

func TestOrganization_Delete_Error(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockOrganizationDAO)

	adminUser := &entities.User{
		ID:    1,
		Email: "admin@example.com",
		Roles: []*entities.Role{
			{Name: common.ROLE_ADMIN},
		},
	}

	session := CreateSession(logger, []uint64{10}, 10, 0, nil, adminUser)

	expectedErr := errors.New("database error")
	mockDAO.On("Delete", mock.Anything, &entities.Organization{ID: 10}).Return(expectedErr)

	service := NewOrganizationService(logger, mockDAO)
	err := service.Delete(ctx, session)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockDAO.AssertExpectations(t)
}

func TestErrOrganizationNotFound(t *testing.T) {
	assert.Equal(t, "organization not found", ErrOrganizationNotFound.Error())
}
