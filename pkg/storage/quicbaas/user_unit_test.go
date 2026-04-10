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

func setupMockUserDAO(t *testing.T) (*UserDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewUserDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestUserDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	err := dao.Save(ctx, user)

	require.NoError(t, err)
	assert.NotZero(t, user.ID)
	assert.Equal(t, 1, mock.Count(entityTypeUser))
}

func TestUserDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	user.ID = 12345
	err := dao.Save(ctx, user)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), user.ID)
}

func TestUserDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	user.ID = 12345
	require.NoError(t, dao.Save(ctx, user))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "test@example.com", retrieved.Email)
}

func TestUserDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestUserDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	user.ID = 12345
	require.NoError(t, dao.Save(ctx, user))
	assert.Equal(t, 1, mock.Count(entityTypeUser))

	err := dao.Delete(ctx, user)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeUser))
}

func TestUserDAO_Save_WithRoles_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	user := entities.NewUser("admin@example.com")
	user.Roles = []*entities.Role{
		{ID: 1, Name: "admin"},
		{ID: 2, Name: "user"},
	}

	err := dao.Save(ctx, user)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, user.ID)
	require.NoError(t, err)
	assert.Len(t, retrieved.Roles, 2)
	assert.Equal(t, "admin", retrieved.Roles[0].Name)
	assert.Equal(t, "user", retrieved.Roles[1].Name)
}

func TestUserDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	user.ID = 12345
	require.NoError(t, dao.Save(ctx, user))

	user.Email = "updated@example.com"
	require.NoError(t, dao.Save(ctx, user))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, "updated@example.com", retrieved.Email)
}

func TestUserDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		user := entities.NewUser("user@example.com")
		user.ID = uint64(i)
		require.NoError(t, dao.Save(ctx, user))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestUserDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.Count(ctx)
	require.Error(t, err)
}

func TestUserDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		user := entities.NewUser("user@example.com")
		user.ID = uint64(i)
		require.NoError(t, dao.Save(ctx, user))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestUserDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		user := entities.NewUser("user@example.com")
		user.ID = uint64(i)
		require.NoError(t, dao.Save(ctx, user))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestUserDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		user := entities.NewUser("user@example.com")
		user.ID = uint64(i)
		require.NoError(t, dao.Save(ctx, user))
	}

	var allUsers []*entities.User
	processor := func(result datastore.PageResult[*entities.User]) error {
		allUsers = append(allUsers, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allUsers))
}

func TestUserDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		user := entities.NewUser("user@example.com")
		user.ID = uint64(i)
		require.NoError(t, dao.Save(ctx, user))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.User]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestUserDAO_ComplexUser_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	user := entities.NewUser("complex@example.com")
	user.ID = 12345
	user.Roles = []*entities.Role{
		{ID: 1, Name: "admin"},
	}
	user.OrganizationRefs = []uint64{100, 200, 300}

	require.NoError(t, dao.Save(ctx, user))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)

	assert.Equal(t, "complex@example.com", retrieved.Email)
	assert.Len(t, retrieved.Roles, 1)
	assert.Equal(t, "admin", retrieved.Roles[0].Name)
	assert.Equal(t, []uint64{100, 200, 300}, retrieved.OrganizationRefs)
}

func TestUserDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	err := dao.Save(ctx, user)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestUserDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	// First save a user
	user := entities.NewUser("test@example.com")
	user.ID = 12345
	data, _ := json.Marshal(user)
	mock.SetData(entityTypeUser, 12345, data)

	// Then set error for Get
	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestUserDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	user.ID = 12345
	err := dao.Delete(ctx, user)

	require.Error(t, err)
}

func TestUserDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockUserDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}
