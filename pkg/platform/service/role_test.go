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
	"github.com/stretchr/testify/require"
)

func TestNewRoleService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)

	service := NewRoleService(logger, mockRoleDAO)

	require.NotNil(t, service)
	assert.IsType(t, &RoleService{}, service)
}

func TestRoleService_Page_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}

	roles := []*entities.Role{
		{ID: 1, Name: "admin"},
		{ID: 2, Name: "user"},
		{ID: 3, Name: "moderator"},
	}

	expectedResult := datastore.PageResult[*entities.Role]{
		Entities: roles,
		Page:     1,
		PageSize: 10,
		HasMore:  false,
	}

	mockRoleDAO.On("Page", ctx, pageQuery).Return(expectedResult, nil)

	service := NewRoleService(logger, mockRoleDAO)
	result, err := service.GetPage(ctx, pageQuery)

	require.NoError(t, err)
	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, "admin", result.Entities[0].Name)
	assert.Equal(t, "user", result.Entities[1].Name)
	assert.Equal(t, "moderator", result.Entities[2].Name)
	mockRoleDAO.AssertExpectations(t)
}

func TestRoleService_Page_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}

	expectedErr := errors.New("database error")
	mockRoleDAO.On("Page", ctx, pageQuery).
		Return(datastore.PageResult[*entities.Role]{}, expectedErr)

	service := NewRoleService(logger, mockRoleDAO)
	result, err := service.GetPage(ctx, pageQuery)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Equal(t, 0, len(result.Entities))
	mockRoleDAO.AssertExpectations(t)
}

func TestRoleService_Page_EmptyResult(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     5,
		PageSize: 10,
	}

	expectedResult := datastore.PageResult[*entities.Role]{
		Entities: []*entities.Role{},
		Page:     5,
		PageSize: 10,
		HasMore:  false,
	}

	mockRoleDAO.On("Page", ctx, pageQuery).Return(expectedResult, nil)

	service := NewRoleService(logger, mockRoleDAO)
	result, err := service.GetPage(ctx, pageQuery)

	require.NoError(t, err)
	assert.Equal(t, 0, len(result.Entities))
	assert.Equal(t, 5, result.Page)
	mockRoleDAO.AssertExpectations(t)
}

func TestRoleService_GetByName_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	roleName := "admin"
	expectedRole := &entities.Role{
		ID:   1,
		Name: roleName,
	}

	mockRoleDAO.On("GetByName", ctx, roleName).Return(expectedRole, nil)

	service := NewRoleService(logger, mockRoleDAO)
	role, err := service.GetByName(ctx, roleName)

	require.NoError(t, err)
	require.NotNil(t, role)
	assert.Equal(t, roleName, role.Name)
	assert.Equal(t, uint64(1), role.ID)
	mockRoleDAO.AssertExpectations(t)
}

func TestRoleService_GetByName_NotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	roleName := "nonexistent"
	expectedErr := ErrRoleNotFound

	mockRoleDAO.On("GetByName", ctx, roleName).Return(nil, expectedErr)

	service := NewRoleService(logger, mockRoleDAO)
	role, err := service.GetByName(ctx, roleName)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, role)
	mockRoleDAO.AssertExpectations(t)
}

func TestRoleService_GetByName_Error(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	roleName := "admin"
	expectedErr := errors.New("database connection error")

	mockRoleDAO.On("GetByName", ctx, roleName).Return(nil, expectedErr)

	service := NewRoleService(logger, mockRoleDAO)
	role, err := service.GetByName(ctx, roleName)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, role)
	mockRoleDAO.AssertExpectations(t)
}

func TestRoleService_GetByName_MultipleRoles(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	// Test retrieving multiple different roles
	roles := []struct {
		name string
		id   uint64
	}{
		{name: "admin", id: 1},
		{name: "user", id: 2},
	}

	for _, r := range roles {
		t.Run(r.name, func(t *testing.T) {
			role := &entities.Role{
				ID:   r.id,
				Name: r.name,
			}
			mockRoleDAO.On("GetByName", ctx, r.name).Return(role, nil).Once()

			service := NewRoleService(logger, mockRoleDAO)
			result, err := service.GetByName(ctx, r.name)

			require.NoError(t, err)
			assert.Equal(t, r.name, result.Name)
			assert.Equal(t, r.id, result.ID)
		})
	}

	mockRoleDAO.AssertExpectations(t)
}

func TestErrRoleNotFound(t *testing.T) {
	assert.Equal(t, "role not found", ErrRoleNotFound.Error())
}

func TestRoleService_FullWorkflow(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockRoleDAO := new(MockRoleDAO)
	ctx := context.Background()

	service := NewRoleService(logger, mockRoleDAO)

	// Get role by name
	adminRole := &entities.Role{
		ID:   1,
		Name: "admin",
	}
	mockRoleDAO.On("GetByName", ctx, "admin").Return(adminRole, nil)

	role, err := service.GetByName(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", role.Name)

	// Page through roles
	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 2,
	}

	roles := []*entities.Role{
		adminRole,
		{ID: 2, Name: "user"},
	}

	pageResult := datastore.PageResult[*entities.Role]{
		Entities: roles,
		Page:     1,
		PageSize: 2,
		HasMore:  false,
	}

	mockRoleDAO.On("Page", ctx, pageQuery).Return(pageResult, nil)

	page, err := service.GetPage(ctx, pageQuery)
	require.NoError(t, err)
	assert.Equal(t, 2, len(page.Entities))

	mockRoleDAO.AssertExpectations(t)
}
