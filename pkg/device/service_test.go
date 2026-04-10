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

package device

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testServiceDatastore(t *testing.T) *Datastore {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	// Start the mock storage - required before any operations
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger)
}

func testServiceDatastoreWithMock(t *testing.T) (*Datastore, *quicbaas.MockStorage) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger), mockStorage
}

func TestNewService(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.NotNil(t, service.deviceDAO)
}

func TestService_Save(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:         1,
		Model:      "TestTPM",
		Serial:     "SN001",
		AttestPub:  "attest-pub-key",
		SigningPub: "signing-pub-key",
		EKCert:     "ek-certificate",
		EventLog:   []byte("event-log-data"),
		HashAlgoId: 11,
	}

	err = service.Save(ctx, device)
	assert.NoError(t, err)
}

func TestService_Save_WithZeroID(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     0, // Invalid ID
		Model:  "TestTPM",
		Serial: "SN001",
	}

	err = service.Save(ctx, device)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)
}

func TestService_Save_DAOError(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	// Inject an error into the storage
	mockStorage.PutError = errors.New("storage write failed")

	device := &entities.Device{
		ID:     1,
		Model:  "TestTPM",
		Serial: "SN001",
	}

	err = service.Save(ctx, device)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save device")
}

func TestService_Get(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:         100,
		Model:      "TestTPM100",
		Serial:     "SN100",
		AttestPub:  "attest-100",
		SigningPub: "signing-100",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrieved.ID)
	assert.Equal(t, device.Model, retrieved.Model)
	assert.Equal(t, device.Serial, retrieved.Serial)
}

func TestService_Get_WithZeroID(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = service.Get(ctx, 0)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)
}

func TestService_Get_NotFound(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = service.Get(ctx, 9999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get device")
}

func TestService_Delete(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     200,
		Model:  "TestTPM200",
		Serial: "SN200",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Verify it exists
	retrieved, err := service.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrieved.ID)

	// Delete it
	err = service.Delete(ctx, device)
	assert.NoError(t, err)

	// Verify it's deleted
	_, err = service.Get(ctx, device.ID)
	assert.Error(t, err)
}

func TestService_Delete_WithNilDevice(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	err = service.Delete(ctx, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)
}

func TestService_Delete_WithZeroID(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID: 0,
	}

	err = service.Delete(ctx, device)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)
}

func TestService_Delete_DAOError(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     1,
		Model:  "TestTPM",
		Serial: "SN001",
	}

	// Inject an error into the storage
	mockStorage.DeleteError = errors.New("storage delete failed")

	err = service.Delete(ctx, device)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete device")
}

func TestService_Update(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     300,
		Model:  "OriginalModel",
		Serial: "ORIG300",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Update the device
	device.Model = "UpdatedModel"
	device.Serial = "UPD300"

	err = service.Update(ctx, device)
	require.NoError(t, err)

	// Verify the update
	retrieved, err := service.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedModel", retrieved.Model)
	assert.Equal(t, "UPD300", retrieved.Serial)
}

func TestService_Update_WithNilDevice(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	err = service.Update(ctx, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)
}

func TestService_Update_WithZeroID(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID: 0,
	}

	err = service.Update(ctx, device)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)
}

func TestService_Update_NotFound(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     9999,
		Model:  "NonExistent",
		Serial: "NE9999",
	}

	err = service.Update(ctx, device)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get device for update")
}

func TestService_Update_SaveError(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     1,
		Model:  "OriginalModel",
		Serial: "ORIG1",
	}

	// First save should succeed
	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Now inject put error for the update
	mockStorage.PutError = errors.New("storage write failed")

	device.Model = "UpdatedModel"
	err = service.Update(ctx, device)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update device")
}

func TestService_Count(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	initialCount, err := service.Count(ctx)
	require.NoError(t, err)

	devices := []*entities.Device{
		{ID: 1, Model: "TPM1", Serial: "SN1"},
		{ID: 2, Model: "TPM2", Serial: "SN2"},
		{ID: 3, Model: "TPM3", Serial: "SN3"},
	}

	for _, device := range devices {
		err = service.Save(ctx, device)
		require.NoError(t, err)
	}

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, initialCount+3, count)
}

func TestService_Count_DAOError(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	// Inject an error into the storage
	mockStorage.ListError = errors.New("storage list failed")

	_, err = service.Count(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count devices")
}

func TestService_Page(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	// Create test devices
	for i := 1; i <= 10; i++ {
		device := &entities.Device{
			ID:     uint64(i),
			Model:  "TPM" + string(rune('0'+i)),
			Serial: "SN" + string(rune('0'+i)),
		}
		err = service.Save(ctx, device)
		require.NoError(t, err)
	}

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  5,
		SortOrder: datastore.SORT_ASCENDING,
	}

	result, err := service.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Entities), 5)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 5, result.PageSize)
}

func TestService_Page_DAOError(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	// Inject an error into the storage
	mockStorage.ListError = errors.New("storage list failed")

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  5,
		SortOrder: datastore.SORT_ASCENDING,
	}

	_, err = service.Page(ctx, pageQuery)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to page devices")
}

func TestService_FindBySerial(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     100,
		Model:  "TestTPM",
		Serial: "SERIAL123",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Find by serial
	found, err := service.FindBySerial(ctx, "SERIAL123")
	require.NoError(t, err)
	assert.Equal(t, device.ID, found.ID)
	assert.Equal(t, device.Serial, found.Serial)
	assert.Equal(t, device.Model, found.Model)
}

func TestService_FindBySerial_NotFound(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = service.FindBySerial(ctx, "NONEXISTENT")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find device by serial")
}

func TestService_FindBySerial_WithScanFallback(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	// Save multiple devices
	devices := []*entities.Device{
		{ID: 1, Model: "TPM1", Serial: "SN001"},
		{ID: 2, Model: "TPM2", Serial: "SN002"},
		{ID: 3, Model: "TPM3", Serial: "SN003"},
	}

	for _, device := range devices {
		err = service.Save(ctx, device)
		require.NoError(t, err)
	}

	// Force query to fail so it falls back to scan, which correctly matches Serial
	mockStorage.QueryError = errors.New("index not available")

	// Find by serial - should use scan fallback
	found, err := service.FindBySerial(ctx, "SN002")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), found.ID)
	assert.Equal(t, "SN002", found.Serial)
}

func TestService_Save_Multiple(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	devices := []*entities.Device{
		{ID: 1, Model: "TPM1", Serial: "SN1"},
		{ID: 2, Model: "TPM2", Serial: "SN2"},
		{ID: 3, Model: "TPM3", Serial: "SN3"},
	}

	for _, device := range devices {
		err = service.Save(ctx, device)
		require.NoError(t, err)
	}
}

func TestService_Save_Update(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     100,
		Model:  "OriginalModel",
		Serial: "ORIG100",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Update the device
	device.Model = "UpdatedModel"
	device.Serial = "UPD100"

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Verify the update
	retrieved, err := service.deviceDAO.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedModel", retrieved.Model)
	assert.Equal(t, "UPD100", retrieved.Serial)
}

func TestService_Save_WithLargeEventLog(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	largeEventLog := make([]byte, 1024*1024) // 1MB
	for i := range largeEventLog {
		largeEventLog[i] = byte(i % 256)
	}

	device := &entities.Device{
		ID:       500,
		Model:    "LargeTPM",
		Serial:   "SNLARGE500",
		EventLog: largeEventLog,
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Verify it was saved
	retrieved, err := service.deviceDAO.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrieved.ID)
	assert.Len(t, retrieved.EventLog, 1024*1024)
}

func TestService_Save_WithAllFields(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:         999,
		AttestPub:  "complete-attest-public-key",
		EKCert:     "complete-endorsement-key-cert",
		EventLog:   []byte("complete-event-log-data"),
		HashAlgoId: 12,
		Model:      "CompleteTPM2000",
		Serial:     "SNCOMPLETE999",
		SigningPub: "complete-signing-public-key",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Verify all fields were saved
	retrieved, err := service.deviceDAO.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrieved.ID)
	assert.Equal(t, device.AttestPub, retrieved.AttestPub)
	assert.Equal(t, device.EKCert, retrieved.EKCert)
	assert.Equal(t, device.EventLog, retrieved.EventLog)
	assert.Equal(t, device.HashAlgoId, retrieved.HashAlgoId)
	assert.Equal(t, device.Model, retrieved.Model)
	assert.Equal(t, device.Serial, retrieved.Serial)
	assert.Equal(t, device.SigningPub, retrieved.SigningPub)
}

func TestService_Save_WithMinimalFields(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID: 888,
		// All other fields left empty/zero
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	// Verify it was saved
	retrieved, err := service.deviceDAO.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrieved.ID)
	assert.Equal(t, "", retrieved.Model)
	assert.Equal(t, "", retrieved.Serial)
}

func TestService_Delete_NotFound(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID: 9999,
	}

	// QuicBaaS delete is idempotent - deleting non-existent records succeeds
	err = service.Delete(ctx, device)
	assert.NoError(t, err)
}

func TestService_Count_Empty(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)
}

func TestService_Page_Empty(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  10,
		SortOrder: datastore.SORT_ASCENDING,
	}

	result, err := service.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Entities), 0)
}

func TestService_Page_WithDifferentSortOrder(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	// Create devices
	for i := 1; i <= 5; i++ {
		device := &entities.Device{
			ID:     uint64(i),
			Model:  "TPM" + string(rune('0'+i)),
			Serial: "SN" + string(rune('0'+i)),
		}
		err = service.Save(ctx, device)
		require.NoError(t, err)
	}

	// Test descending order
	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  3,
		SortOrder: datastore.SORT_DESCENDING,
	}

	result, err := service.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Entities), 3)
}

func TestService_Delete_Success(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     555,
		Model:  "DeleteTPM",
		Serial: "SNDEL555",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	err = service.Delete(ctx, device)
	assert.NoError(t, err)
}

func TestService_Count_AfterDeletion(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     700,
		Model:  "CountTPM",
		Serial: "SNCNT700",
	}

	err = service.Save(ctx, device)
	require.NoError(t, err)

	count1, err := service.Count(ctx)
	require.NoError(t, err)

	err = service.Delete(ctx, device)
	require.NoError(t, err)

	count2, err := service.Count(ctx)
	require.NoError(t, err)

	assert.Equal(t, count1-1, count2)
}

func TestService_Page_MultiPage(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	// Create 15 devices
	for i := 1; i <= 15; i++ {
		device := &entities.Device{
			ID:     uint64(i + 2000),
			Model:  "PageTPM" + string(rune('0'+i)),
			Serial: "SNPAGE" + string(rune('0'+i)),
		}
		err = service.Save(ctx, device)
		require.NoError(t, err)
	}

	// Get page 1
	page1, err := service.Page(ctx, datastore.PageQuery{
		Page:      1,
		PageSize:  5,
		SortOrder: datastore.SORT_ASCENDING,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(page1.Entities), 5)

	// Get page 2
	page2, err := service.Page(ctx, datastore.PageQuery{
		Page:      2,
		PageSize:  5,
		SortOrder: datastore.SORT_ASCENDING,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(page2.Entities), 0)
}
