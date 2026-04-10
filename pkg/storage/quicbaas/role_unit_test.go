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

package quicbaas

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockRoleDAO(t *testing.T) (*RoleDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewRoleDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestRoleDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	role := &entities.Role{Name: "admin"}
	err := dao.Save(ctx, role)

	require.NoError(t, err)
	assert.NotZero(t, role.ID)
	assert.Equal(t, 1, mock.Count(entityTypeRole))
}

func TestRoleDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	role := &entities.Role{ID: 12345, Name: "admin"}
	require.NoError(t, dao.Save(ctx, role))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "admin", retrieved.Name)
}

func TestRoleDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	role := &entities.Role{ID: 12345, Name: "admin"}
	require.NoError(t, dao.Save(ctx, role))
	assert.Equal(t, 1, mock.Count(entityTypeRole))

	err := dao.Delete(ctx, role)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeRole))
}

func TestRoleDAO_GetByName_Found_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Pre-populate data (simulating existing role)
	role := &entities.Role{ID: 12345, Name: "admin"}
	roleData, _ := json.Marshal(role)
	mock.SetData(entityTypeRole, 12345, roleData)

	found, err := dao.GetByName(ctx, "admin")

	require.NoError(t, err)
	assert.Equal(t, "admin", found.Name)
	assert.Equal(t, uint64(12345), found.ID)
}

func TestRoleDAO_GetByName_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByName(ctx, "nonexistent")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "Name", notFoundErr.IndexField)
	assert.Equal(t, "nonexistent", notFoundErr.Value)
}

func TestRoleDAO_GetByName_MultipleRoles_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Note: MockStorage.Query doesn't filter by field value, so we force scan
	// by injecting a QueryError. This tests the scan fallback path.
	mock.QueryError = errors.New("force scan fallback")

	// Add multiple roles
	roles := []struct {
		id   uint64
		name string
	}{
		{1, "admin"},
		{2, "user"},
		{3, "moderator"},
	}

	for _, r := range roles {
		role := &entities.Role{ID: r.id, Name: r.name}
		roleData, _ := json.Marshal(role)
		mock.SetData(entityTypeRole, r.id, roleData)
	}

	// Find each role via scan fallback
	for _, r := range roles {
		found, err := dao.GetByName(ctx, r.name)
		require.NoError(t, err)
		assert.Equal(t, r.name, found.Name)
	}
}

func TestRoleDAO_GetByName_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Query error forces fallback to scan
	mock.QueryError = errors.New("query not supported")
	mock.ListError = errors.New("storage unavailable")

	_, err := dao.GetByName(ctx, "admin")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestRoleDAO_GetByName_QueryFallbackToScan_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Query returns error, should fall back to scan
	mock.QueryError = errors.New("index not available")

	// Pre-populate data
	role := &entities.Role{ID: 12345, Name: "admin"}
	roleData, _ := json.Marshal(role)
	mock.SetData(entityTypeRole, 12345, roleData)

	found, err := dao.GetByName(ctx, "admin")

	require.NoError(t, err)
	assert.Equal(t, "admin", found.Name)
}

func TestRoleDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Add roles
	for i := 1; i <= 5; i++ {
		role := &entities.Role{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestRoleDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Add roles
	for i := 1; i <= 10; i++ {
		role := &entities.Role{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestRoleDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockRoleDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Add roles
	for i := 1; i <= 8; i++ {
		role := &entities.Role{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	var allRoles []*entities.Role
	processor := func(result datastore.PageResult[*entities.Role]) error {
		allRoles = append(allRoles, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allRoles))
}
