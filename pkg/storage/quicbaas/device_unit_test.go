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

func setupMockDeviceDAO(t *testing.T) (*DeviceDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewDeviceDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestDeviceDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{
		Model:      "TestModel",
		Serial:     "SN12345",
		HashAlgoId: 11, // SHA256
	}
	err := dao.Save(ctx, device)

	require.NoError(t, err)
	assert.NotZero(t, device.ID)
	assert.Equal(t, 1, mock.Count(entityTypeDevice))
}

func TestDeviceDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{
		ID:     12345,
		Model:  "TestModel",
		Serial: "SN12345",
	}
	err := dao.Save(ctx, device)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), device.ID)
}

func TestDeviceDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{
		ID:         12345,
		Model:      "TestModel",
		Serial:     "SN12345",
		HashAlgoId: 11,
		EKCert:     "test-ek-cert",
		AttestPub:  "test-attest-pub",
		SigningPub: "test-signing-pub",
	}
	require.NoError(t, dao.Save(ctx, device))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "TestModel", retrieved.Model)
	assert.Equal(t, "SN12345", retrieved.Serial)
	assert.Equal(t, uint32(11), retrieved.HashAlgoId)
	assert.Equal(t, "test-ek-cert", retrieved.EKCert)
	assert.Equal(t, "test-attest-pub", retrieved.AttestPub)
	assert.Equal(t, "test-signing-pub", retrieved.SigningPub)
}

func TestDeviceDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestDeviceDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{ID: 12345, Model: "TestModel", Serial: "SN12345"}
	require.NoError(t, dao.Save(ctx, device))
	assert.Equal(t, 1, mock.Count(entityTypeDevice))

	err := dao.Delete(ctx, device)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeDevice))
}

func TestDeviceDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{
		ID:     12345,
		Model:  "TestModel",
		Serial: "SN12345",
	}
	require.NoError(t, dao.Save(ctx, device))

	device.EKCert = "updated-ek-cert"
	device.AttestPub = "updated-attest-pub"
	require.NoError(t, dao.Save(ctx, device))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, "updated-ek-cert", retrieved.EKCert)
	assert.Equal(t, "updated-attest-pub", retrieved.AttestPub)
}

func TestDeviceDAO_FindBySerial_WithScan_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	devices := []*entities.Device{
		{ID: 1, Model: "Model1", Serial: "SN001"},
		{ID: 2, Model: "Model2", Serial: "SN002"},
		{ID: 3, Model: "Model3", Serial: "SN003"},
	}
	for _, device := range devices {
		require.NoError(t, dao.Save(ctx, device))
	}

	// Force scan by making Query return error
	mock.QueryError = errors.New("no index")

	retrieved, err := dao.FindBySerial(ctx, "SN002")

	require.NoError(t, err)
	assert.Equal(t, "SN002", retrieved.Serial)
	assert.Equal(t, "Model2", retrieved.Model)
}

func TestDeviceDAO_FindBySerial_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{ID: 1, Model: "Model1", Serial: "SN001"}
	require.NoError(t, dao.Save(ctx, device))

	mock.QueryError = errors.New("no index")

	_, err := dao.FindBySerial(ctx, "NONEXISTENT")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestDeviceDAO_FindBySerial_WithIndex_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{
		ID:     12345,
		Model:  "IndexedModel",
		Serial: "INDEXED-SN",
	}
	data, _ := json.Marshal(device)
	mock.SetQueryResult(entityTypeDevice, "Serial", []byte("INDEXED-SN"), []*service.Entity{{ID: 12345, Data: data}})

	retrieved, err := dao.FindBySerial(ctx, "INDEXED-SN")

	require.NoError(t, err)
	assert.Equal(t, "INDEXED-SN", retrieved.Serial)
}

func TestDeviceDAO_GetByModel_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	devices := []*entities.Device{
		{ID: 1, Model: "ModelA", Serial: "SN001"},
		{ID: 2, Model: "ModelB", Serial: "SN002"},
		{ID: 3, Model: "ModelA", Serial: "SN003"},
		{ID: 4, Model: "ModelC", Serial: "SN004"},
		{ID: 5, Model: "ModelA", Serial: "SN005"},
	}
	for _, device := range devices {
		require.NoError(t, dao.Save(ctx, device))
	}

	modelADevices, err := dao.GetByModel(ctx, "ModelA")

	require.NoError(t, err)
	assert.Len(t, modelADevices, 3)
	for _, d := range modelADevices {
		assert.Equal(t, "ModelA", d.Model)
	}
}

func TestDeviceDAO_GetByModel_Empty_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	device := &entities.Device{ID: 1, Model: "ModelA", Serial: "SN001"}
	require.NoError(t, dao.Save(ctx, device))

	devices, err := dao.GetByModel(ctx, "NonexistentModel")

	require.NoError(t, err)
	assert.Empty(t, devices)
}

func TestDeviceDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		device := &entities.Device{ID: uint64(i), Model: "Model", Serial: "SN"}
		require.NoError(t, dao.Save(ctx, device))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestDeviceDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.Count(ctx)
	require.Error(t, err)
}

func TestDeviceDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		device := &entities.Device{ID: uint64(i), Model: "Model", Serial: "SN"}
		require.NoError(t, dao.Save(ctx, device))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestDeviceDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		device := &entities.Device{ID: uint64(i), Model: "Model", Serial: "SN"}
		require.NoError(t, dao.Save(ctx, device))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestDeviceDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		device := &entities.Device{ID: uint64(i), Model: "Model", Serial: "SN"}
		require.NoError(t, dao.Save(ctx, device))
	}

	var allDevices []*entities.Device
	processor := func(result datastore.PageResult[*entities.Device]) error {
		allDevices = append(allDevices, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allDevices))
}

func TestDeviceDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		device := &entities.Device{ID: uint64(i), Model: "Model", Serial: "SN"}
		require.NoError(t, dao.Save(ctx, device))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.Device]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestDeviceDAO_WithEventLog_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	eventLog := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
	device := &entities.Device{
		ID:       12345,
		Model:    "TPM2.0Device",
		Serial:   "SN12345",
		EventLog: eventLog,
	}
	require.NoError(t, dao.Save(ctx, device))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, eventLog, retrieved.EventLog)
}

func TestDeviceDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	device := &entities.Device{Model: "Test", Serial: "SN"}
	err := dao.Save(ctx, device)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestDeviceDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	device := &entities.Device{ID: 12345, Model: "Test", Serial: "SN"}
	data, _ := json.Marshal(device)
	mock.SetData(entityTypeDevice, 12345, data)

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestDeviceDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	device := &entities.Device{ID: 12345, Model: "Test", Serial: "SN"}
	err := dao.Delete(ctx, device)

	require.Error(t, err)
}

func TestDeviceDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}

func TestDeviceDAO_FindBySerial_ListError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	mock.QueryError = errors.New("no index")
	mock.ListError = errors.New("list failed")

	ctx := context.Background()
	_, err := dao.FindBySerial(ctx, "SN12345")

	require.Error(t, err)
}

func TestDeviceDAO_GetByModel_ListError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("list failed")

	ctx := context.Background()
	_, err := dao.GetByModel(ctx, "Model")

	require.Error(t, err)
}
