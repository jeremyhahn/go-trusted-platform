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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockDeviceProfileDAO(t *testing.T) (*DeviceProfileDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewDeviceProfileDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestDeviceProfileDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		Model: "TestModel",
	}
	err := dao.Save(ctx, profile)

	require.NoError(t, err)
	assert.NotZero(t, profile.ID)
	assert.Equal(t, 1, mock.Count(entityTypeDeviceProfile))
}

func TestDeviceProfileDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "TestModel",
	}
	err := dao.Save(ctx, profile)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), profile.ID)
}

func TestDeviceProfileDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	eventLog := []byte{0x00, 0x01, 0x02, 0x03}
	profile := &entities.DeviceProfile{
		ID:       12345,
		Model:    "TestModel",
		EventLog: eventLog,
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "TestModel", retrieved.Model)
	assert.Equal(t, eventLog, retrieved.EventLog)
}

func TestDeviceProfileDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestDeviceProfileDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 12345, Model: "TestModel"}
	require.NoError(t, dao.Save(ctx, profile))
	assert.Equal(t, 1, mock.Count(entityTypeDeviceProfile))

	err := dao.Delete(ctx, profile)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeDeviceProfile))
}

func TestDeviceProfileDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "InitialModel",
	}
	require.NoError(t, dao.Save(ctx, profile))

	profile.Model = "UpdatedModel"
	profile.EventLog = []byte{0xFF, 0xFE}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedModel", retrieved.Model)
	assert.Equal(t, []byte{0xFF, 0xFE}, retrieved.EventLog)
}

func TestDeviceProfileDAO_GetByModel_WithScan_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profiles := []*entities.DeviceProfile{
		{ID: 1, Model: "ModelA"},
		{ID: 2, Model: "ModelB"},
		{ID: 3, Model: "ModelC"},
	}
	for _, profile := range profiles {
		require.NoError(t, dao.Save(ctx, profile))
	}

	// Force scan by making Query return error
	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByModel(ctx, "ModelB")

	require.NoError(t, err)
	assert.Equal(t, "ModelB", retrieved.Model)
}

func TestDeviceProfileDAO_GetByModel_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 1, Model: "ModelA"}
	require.NoError(t, dao.Save(ctx, profile))

	mock.QueryError = errors.New("no index")

	_, err := dao.GetByModel(ctx, "NonexistentModel")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestDeviceProfileDAO_GetByModel_WithIndex_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "IndexedModel",
	}
	data, _ := json.Marshal(profile)
	mock.SetQueryResult(entityTypeDeviceProfile, "Model", []byte("IndexedModel"), []*service.Entity{{ID: 12345, Data: data}})

	retrieved, err := dao.GetByModel(ctx, "IndexedModel")

	require.NoError(t, err)
	assert.Equal(t, "IndexedModel", retrieved.Model)
}

func TestDeviceProfileDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestDeviceProfileDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.Count(ctx)
	require.Error(t, err)
}

func TestDeviceProfileDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestDeviceProfileDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestDeviceProfileDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	var allProfiles []*entities.DeviceProfile
	processor := func(result datastore.PageResult[*entities.DeviceProfile]) error {
		allProfiles = append(allProfiles, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allProfiles))
}

func TestDeviceProfileDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.DeviceProfile]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestDeviceProfileDAO_WithLargeEventLog_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Create a large event log (4KB)
	largeEventLog := make([]byte, 4096)
	for i := range largeEventLog {
		largeEventLog[i] = byte(i % 256)
	}

	profile := &entities.DeviceProfile{
		ID:       12345,
		Model:    "LargeEventLogModel",
		EventLog: largeEventLog,
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, largeEventLog, retrieved.EventLog)
}

func TestDeviceProfileDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	profile := &entities.DeviceProfile{Model: "Test"}
	err := dao.Save(ctx, profile)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestDeviceProfileDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	profile := &entities.DeviceProfile{ID: 12345, Model: "Test"}
	data, _ := json.Marshal(profile)
	mock.SetData(entityTypeDeviceProfile, 12345, data)

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestDeviceProfileDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 12345, Model: "Test"}
	err := dao.Delete(ctx, profile)

	require.Error(t, err)
}

func TestDeviceProfileDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}

func TestDeviceProfileDAO_GetByModel_ListError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.QueryError = errors.New("no index")
	mock.ListError = errors.New("list failed")

	ctx := context.Background()
	_, err := dao.GetByModel(ctx, "Model")

	require.Error(t, err)
}

func TestDeviceProfileDAO_EmptyEventLog_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:       12345,
		Model:    "EmptyEventLogModel",
		EventLog: []byte{},
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Empty(t, retrieved.EventLog)
}

func TestDeviceProfileDAO_NilEventLog_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "NilEventLogModel",
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Nil(t, retrieved.EventLog)
}
