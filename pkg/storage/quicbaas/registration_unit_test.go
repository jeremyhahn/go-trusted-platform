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

func setupMockRegistrationDAO(t *testing.T) (*RegistrationDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewRegistrationDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestRegistrationDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	reg := entities.NewRegistration("test@example.com")
	err := dao.Save(ctx, reg)

	require.NoError(t, err)
	assert.NotZero(t, reg.ID)
	assert.Equal(t, 1, mock.Count(entityTypeRegistration))
}

func TestRegistrationDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	reg := &entities.Registration{
		ID:      12345,
		Email:   "test@example.com",
		OrgID:   100,
		OrgName: "TestOrg",
	}
	err := dao.Save(ctx, reg)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), reg.ID)
}

func TestRegistrationDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	reg := &entities.Registration{
		ID:      12345,
		Email:   "test@example.com",
		OrgID:   100,
		OrgName: "TestOrg",
	}
	require.NoError(t, dao.Save(ctx, reg))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "test@example.com", retrieved.Email)
	assert.Equal(t, uint64(100), retrieved.OrgID)
	assert.Equal(t, "TestOrg", retrieved.OrgName)
}

func TestRegistrationDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRegistrationDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	reg := &entities.Registration{ID: 12345, Email: "test@example.com"}
	require.NoError(t, dao.Save(ctx, reg))
	assert.Equal(t, 1, mock.Count(entityTypeRegistration))

	err := dao.Delete(ctx, reg)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeRegistration))
}

func TestRegistrationDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	reg := &entities.Registration{
		ID:      12345,
		Email:   "test@example.com",
		OrgID:   100,
		OrgName: "TestOrg",
	}
	require.NoError(t, dao.Save(ctx, reg))

	reg.OrgName = "UpdatedOrg"
	reg.Password = "newpassword"
	require.NoError(t, dao.Save(ctx, reg))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedOrg", retrieved.OrgName)
	assert.Equal(t, "newpassword", retrieved.Password)
}

func TestRegistrationDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		reg := &entities.Registration{ID: uint64(i), Email: "user@example.com"}
		require.NoError(t, dao.Save(ctx, reg))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestRegistrationDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.Count(ctx)
	require.Error(t, err)
}

func TestRegistrationDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		reg := &entities.Registration{ID: uint64(i), Email: "user@example.com"}
		require.NoError(t, dao.Save(ctx, reg))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestRegistrationDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		reg := &entities.Registration{ID: uint64(i), Email: "user@example.com"}
		require.NoError(t, dao.Save(ctx, reg))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestRegistrationDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		reg := &entities.Registration{ID: uint64(i), Email: "user@example.com"}
		require.NoError(t, dao.Save(ctx, reg))
	}

	var allRegs []*entities.Registration
	processor := func(result datastore.PageResult[*entities.Registration]) error {
		allRegs = append(allRegs, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allRegs))
}

func TestRegistrationDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		reg := &entities.Registration{ID: uint64(i), Email: "user@example.com"}
		require.NoError(t, dao.Save(ctx, reg))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.Registration]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestRegistrationDAO_WithSessionData_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	sessionData := []byte(`{"challenge": "abc123", "webauthn": true}`)
	reg := &entities.Registration{
		ID:          12345,
		Email:       "test@example.com",
		SessionData: sessionData,
	}
	require.NoError(t, dao.Save(ctx, reg))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, sessionData, retrieved.SessionData)
}

func TestRegistrationDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	reg := entities.NewRegistration("test@example.com")
	err := dao.Save(ctx, reg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestRegistrationDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	reg := &entities.Registration{ID: 12345, Email: "test@example.com"}
	data, _ := json.Marshal(reg)
	mock.SetData(entityTypeRegistration, 12345, data)

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestRegistrationDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	reg := &entities.Registration{ID: 12345, Email: "test@example.com"}
	err := dao.Delete(ctx, reg)

	require.Error(t, err)
}

func TestRegistrationDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}

func TestRegistrationDAO_CompleteRegistration_Mock(t *testing.T) {
	dao, mock := setupMockRegistrationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	reg := &entities.Registration{
		ID:          12345,
		Email:       "complete@example.com",
		Password:    "hashedpassword123",
		OrgID:       100,
		OrgName:     "CompleteOrg",
		SessionData: []byte(`{"complete": true}`),
	}
	require.NoError(t, dao.Save(ctx, reg))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)

	assert.Equal(t, "complete@example.com", retrieved.Email)
	assert.Equal(t, "hashedpassword123", retrieved.Password)
	assert.Equal(t, uint64(100), retrieved.OrgID)
	assert.Equal(t, "CompleteOrg", retrieved.OrgName)
	assert.Equal(t, []byte(`{"complete": true}`), retrieved.SessionData)
}
