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
	"time"

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

func TestService_RecordHeartbeat_BySerial(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	device := &entities.Device{ID: 200, Serial: "HB-SERIAL-1", Hostname: "hb1.example.internal"}
	require.NoError(t, service.Save(ctx, device))

	updated, err := service.RecordHeartbeat(ctx, "HB-SERIAL-1", "10.4.2.143:51234")
	require.NoError(t, err)
	assert.False(t, updated.LastHeartbeatAt.IsZero())
	assert.False(t, updated.UpdatedAt.IsZero())
	assert.Equal(t, "10.4.2.143:51234", updated.LastHeartbeatAddr)

	// The stamp is persisted, not just returned.
	stored, err := service.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, updated.LastHeartbeatAt, stored.LastHeartbeatAt)
	assert.Equal(t, "10.4.2.143:51234", stored.LastHeartbeatAddr)

	// A peer address that is not a transport address is not recorded, and
	// an empty one leaves the previous address in place.
	updated, err = service.RecordHeartbeat(ctx, "HB-SERIAL-1", "evil.example:1")
	require.NoError(t, err)
	assert.Equal(t, "10.4.2.143:51234", updated.LastHeartbeatAddr)
	updated, err = service.RecordHeartbeat(ctx, "HB-SERIAL-1", "")
	require.NoError(t, err)
	assert.Equal(t, "10.4.2.143:51234", updated.LastHeartbeatAddr)

	// Update with an empty address keeps the recorded one.
	stored.LastHeartbeatAddr = ""
	require.NoError(t, service.Update(ctx, stored))
	after, err := service.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, "10.4.2.143:51234", after.LastHeartbeatAddr)
}

func TestHeartbeatPeerAddr(t *testing.T) {
	assert.Equal(t, "10.0.0.1:5", heartbeatPeerAddr("10.0.0.1:5"))
	assert.Equal(t, "10.0.0.1", heartbeatPeerAddr(" 10.0.0.1 "))
	assert.Equal(t, "[2001:db8::1]:5", heartbeatPeerAddr("[2001:db8::1]:5"))
	assert.Equal(t, "", heartbeatPeerAddr("host.example:5"))
	assert.Equal(t, "", heartbeatPeerAddr(""))
}

// TestService_RecordHeartbeat_ByHostname proves the IDevID-FQDN
// fallback: enrolled nodes authenticate with certificates naming their
// hostname, not the hardware serial.
func TestService_RecordHeartbeat_ByHostname(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	device := &entities.Device{ID: 201, Serial: "HB-SERIAL-2", Hostname: "hb2.example.internal"}
	require.NoError(t, service.Save(ctx, device))

	updated, err := service.RecordHeartbeat(ctx, "hb2.example.internal", "")
	require.NoError(t, err)
	assert.Equal(t, device.ID, updated.ID)
	assert.False(t, updated.LastHeartbeatAt.IsZero())
}

func TestService_RecordHeartbeat_UnknownIdentity(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)

	_, err = service.RecordHeartbeat(context.Background(), "no-such-device", "")
	assert.Error(t, err)
}

func TestService_RecordHeartbeat_EmptyIdentity(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)

	_, err = service.RecordHeartbeat(context.Background(), "", "")
	assert.ErrorIs(t, err, ErrIdentityRequired)
}

// TestService_RecordHeartbeat_TypedNotFound pins the typed error the
// transport layer maps to 404.
func TestService_RecordHeartbeat_TypedNotFound(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)

	_, err = service.RecordHeartbeat(context.Background(), "no-such-device", "")
	var notFound *IdentityNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

// TestService_RecordHeartbeat_NeverStampsMismatchedDevice reproduces the
// live incident where a heartbeat for one identity resolved another
// node's record (an unfiltered secondary-index answer): a device whose
// serial and hostname both differ from the identity must never be
// stamped, regardless of what the lookup layer returns.
func TestService_RecordHeartbeat_NeverStampsMismatchedDevice(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	// A record with an EMPTY hostname — the shape enrolled fleet nodes
	// actually had when the incident occurred.
	device := &entities.Device{ID: 300, Serial: "OTHER-NODE-1"}
	require.NoError(t, service.Save(ctx, device))

	_, err = service.RecordHeartbeat(ctx, "node-01-gateway", "")
	var notFound *IdentityNotFoundError
	require.ErrorAs(t, err, &notFound)

	stored, err := service.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.True(t, stored.LastHeartbeatAt.IsZero(), "mismatched device must not be stamped")
}

// TestService_ResolveIdentity covers the lookup the heartbeat and a
// diskless node's boot delivery share: serial first, hostname second, and
// a typed miss — never another node's record — otherwise.
func TestService_ResolveIdentity(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	device := &entities.Device{ID: 310, Serial: "RES-SERIAL", Hostname: "res.example.internal"}
	require.NoError(t, service.Save(ctx, device))
	require.NoError(t, service.Save(ctx, &entities.Device{ID: 311, Serial: "UNNAMED-NODE"}))

	bySerial, err := service.ResolveIdentity(ctx, "RES-SERIAL")
	require.NoError(t, err)
	assert.Equal(t, device.ID, bySerial.ID)

	byHost, err := service.ResolveIdentity(ctx, "res.example.internal")
	require.NoError(t, err)
	assert.Equal(t, device.ID, byHost.ID)

	_, err = service.ResolveIdentity(ctx, "")
	assert.ErrorIs(t, err, ErrIdentityRequired)

	_, err = service.ResolveIdentity(ctx, "node-02-gateway")
	var notFound *IdentityNotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "node-02-gateway", notFound.Identity)
}

// TestService_Update_PreservesServerOwnedFields proves an ordinary
// update (which carries no lifecycle/liveness fields) does not erase
// the heartbeat timestamp, lifecycle state, or enrollment metadata.
func TestService_Update_PreservesServerOwnedFields(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	device := &entities.Device{
		ID: 400, Serial: "KEEP-1", Hostname: "keep1.example.internal",
		State:      entities.DeviceStateActivated,
		AttestPub:  "-----BEGIN PUBLIC KEY-----\nenrolled-ak\n-----END PUBLIC KEY-----",
		AttestCert: "-----BEGIN CERTIFICATE-----\nenrolled-ak-cert\n-----END CERTIFICATE-----",
		IDevIDCert: "-----BEGIN CERTIFICATE-----\nenrolled-idevid-cert\n-----END CERTIFICATE-----",
	}
	require.NoError(t, service.Save(ctx, device))
	_, err = service.RecordHeartbeat(ctx, "KEEP-1", "")
	require.NoError(t, err)

	// A dashboard-shaped update: identity fields only.
	require.NoError(t, service.Update(ctx, &entities.Device{
		ID: 400, Serial: "KEEP-1", Model: "NewModel",
	}))

	stored, err := service.Get(ctx, 400)
	require.NoError(t, err)
	assert.Equal(t, "NewModel", stored.Model)
	assert.False(t, stored.LastHeartbeatAt.IsZero(), "heartbeat erased by update")
	assert.Equal(t, "keep1.example.internal", stored.Hostname)
	assert.Equal(t, "activated", string(stored.State))
	// The attestation trust anchor must survive a partial update in BOTH of
	// its forms. An erased AttestPub is what let a caller-supplied AK become
	// the anchor (#252); an erased AttestCert would reopen the same hole one
	// field over, and would silently downgrade a device from a certificate
	// carrying verifiedTPMRestricted to a bare key that cannot (#374).
	assert.Equal(t, device.AttestPub, stored.AttestPub, "AttestPub erased by update")
	assert.Equal(t, device.AttestCert, stored.AttestCert, "AttestCert erased by update")
	// An erased IDevID chain strands a diskless node: it is the only copy of
	// the certificate the node presents on its next boot (#690).
	assert.Equal(t, device.IDevIDCert, stored.IDevIDCert, "IDevIDCert erased by update")
}

// TestService_Update_PreservesNetworkPortID proves a dashboard-shaped
// update cannot clear the OVS port stamped at SDN activation — an
// empty NetworkPortID makes the quarantine observer skip enforcement.
func TestService_Update_PreservesNetworkPortID(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.Device{
		ID: 401, Serial: "KEEP-2", NetworkPortID: "tap-401",
		SwitchName: "sw1", SwitchPort: "Eth1/3",
	}))
	require.NoError(t, service.Update(ctx, &entities.Device{
		ID: 401, Serial: "KEEP-2", Model: "Edited",
	}))
	stored, err := service.Get(ctx, 401)
	require.NoError(t, err)
	assert.Equal(t, "tap-401", stored.NetworkPortID)
	assert.Equal(t, "sw1", stored.SwitchName)
	assert.Equal(t, "Eth1/3", stored.SwitchPort)
}

// TestIsLookupMiss classifies the DAO's typed not-found errors as
// misses and everything else as storage faults.
func TestIsLookupMiss(t *testing.T) {
	assert.True(t, isLookupMiss(quicbaas.ErrNotFoundByIndex{EntityType: "device", IndexField: "Serial", Value: "x"}))
	assert.True(t, isLookupMiss(quicbaas.ErrNotFound{EntityType: "device", ID: 1}))
	assert.False(t, isLookupMiss(errors.New("storage unavailable")))
	assert.False(t, isLookupMiss(nil))
}

// TestService_RecordHeartbeat_StorageFaultIsNotNotFound proves a
// backend failure during lookup surfaces as a server error, never as
// the 404-mapped IdentityNotFoundError.
func TestService_RecordHeartbeat_StorageFaultIsNotNotFound(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)
	service, err := NewService(ds)
	require.NoError(t, err)

	// Stop the backend so lookups fail operationally, not as a miss.
	require.NoError(t, mockStorage.Stop(context.Background()))

	_, err = service.RecordHeartbeat(context.Background(), "any-node", "")
	require.Error(t, err)
	var notFound *IdentityNotFoundError
	assert.False(t, errors.As(err, &notFound),
		"storage fault must not be classified as device-not-found: %v", err)
}

// TestService_Update_PreservesIdentityFields is the regression guard for #252.
//
// Update restored the lifecycle fields but not the identity ones, so a
// dashboard-shaped PUT that named none of them erased the device's TPM
// enrollment material — EKCert and AttestPub are what let an attested machine
// prove it is the same machine. Nothing reported the loss.
//
// The table is one case per field so a failure names the field that regressed
// rather than "an update erased something".
func TestService_Update_PreservesIdentityFields(t *testing.T) {
	stored := func() *entities.Device {
		return &entities.Device{
			ID:         500,
			TenantID:   "tenant-a",
			Serial:     "IDENT-1",
			Model:      "X10SDV",
			EKCert:     "-----BEGIN CERTIFICATE-----ek-----END CERTIFICATE-----",
			AttestPub:  "attest-public-key",
			SigningPub: "signing-public-key",
			EventLog:   []byte{0x01, 0x02, 0x03},
			HashAlgoId: 11,
		}
	}

	cases := []struct {
		field  string
		assert func(t *testing.T, got *entities.Device)
	}{
		{"TenantID", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, "tenant-a", got.TenantID, "tenant binding erased: the device is detached from its tenant")
		}},
		{"EKCert", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, stored().EKCert, got.EKCert, "EK certificate erased: the device can no longer prove its TPM identity")
		}},
		{"AttestPub", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, "attest-public-key", got.AttestPub, "attestation key erased")
		}},
		{"SigningPub", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, "signing-public-key", got.SigningPub, "signing key erased")
		}},
		{"EventLog", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, []byte{0x01, 0x02, 0x03}, got.EventLog, "event log erased")
		}},
		{"HashAlgoId", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, uint32(11), got.HashAlgoId, "hash algorithm erased")
		}},
		{"Model", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, "X10SDV", got.Model, "model erased")
		}},
		{"Serial", func(t *testing.T, got *entities.Device) {
			assert.Equal(t, "IDENT-1", got.Serial, "serial erased: the device lost its identifier")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.field+" survives an update that does not mention it", func(t *testing.T) {
			ds := testServiceDatastore(t)
			service, err := NewService(ds)
			require.NoError(t, err)
			ctx := context.Background()

			require.NoError(t, service.Save(ctx, stored()))

			// The minimum a caller can send: an ID and nothing else. This is
			// the shape a partial dashboard edit produces, and TenantID
			// cannot be sent at all because DeviceRequest has no field for it.
			require.NoError(t, service.Update(ctx, &entities.Device{ID: 500}))

			got, err := service.Get(ctx, 500)
			require.NoError(t, err)
			tc.assert(t, got)
		})
	}
}

// TestService_Update_IdentityFieldsRemainEditable is the companion: preserving
// a zero value must not freeze the field. A caller that sends a new value still
// wins, which is what keeps Model and Serial editable from the dashboard.
func TestService_Update_IdentityFieldsRemainEditable(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.Device{
		ID: 501, TenantID: "tenant-a", Serial: "EDIT-1", Model: "OldModel",
		EKCert: "old-ek", AttestPub: "old-attest", SigningPub: "old-signing",
		EventLog: []byte{0x01}, HashAlgoId: 11,
	}))

	require.NoError(t, service.Update(ctx, &entities.Device{
		ID: 501, TenantID: "tenant-b", Serial: "EDIT-2", Model: "NewModel",
		EKCert: "new-ek", AttestPub: "new-attest", SigningPub: "new-signing",
		EventLog: []byte{0x02}, HashAlgoId: 12,
	}))

	got, err := service.Get(ctx, 501)
	require.NoError(t, err)
	assert.Equal(t, "tenant-b", got.TenantID)
	assert.Equal(t, "EDIT-2", got.Serial)
	assert.Equal(t, "NewModel", got.Model)
	assert.Equal(t, "new-ek", got.EKCert)
	assert.Equal(t, "new-attest", got.AttestPub)
	assert.Equal(t, "new-signing", got.SigningPub)
	assert.Equal(t, []byte{0x02}, got.EventLog)
	assert.Equal(t, uint32(12), got.HashAlgoId)
}

// TestService_Create_AssignsIdentityWhenCallerHasNone is the #525
// regression: every transport's create verb called Save, which requires
// a non-zero ID, so a caller with no ID yet — the only state a device
// being created can be in — was refused with ErrInvalidDeviceID.
func TestService_Create_AssignsIdentityWhenCallerHasNone(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		Model:  "TestTPM",
		Serial: "SN-CREATE-001",
	}

	require.NoError(t, service.Create(ctx, device))
	assert.NotZero(t, device.ID, "Create must assign an ID the caller could not supply")

	// The record is readable afterwards under the assigned ID, which is
	// the acceptance condition the device suite asserts per transport.
	stored, err := service.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, "SN-CREATE-001", stored.Serial)
	assert.Equal(t, device.ID, stored.ID)
}

// TestService_Create_HonoursCallerSuppliedID pins the affordance the
// REST create handler has always had: an explicit ID still wins, so
// moving identity assignment into the service is not a contract change
// for the callers that do supply one.
func TestService_Create_HonoursCallerSuppliedID(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	device := &entities.Device{
		ID:     4242,
		Model:  "TestTPM",
		Serial: "SN-CREATE-002",
	}

	require.NoError(t, service.Create(ctx, device))
	assert.Equal(t, uint64(4242), device.ID)

	stored, err := service.Get(ctx, 4242)
	require.NoError(t, err)
	assert.Equal(t, "SN-CREATE-002", stored.Serial)
}

// Every transport creates through Service.Create, so the defaults it fills
// in are what makes the same body persist the same entity on each (#484).
func TestService_Create_DefaultsStateAndTimestamps(t *testing.T) {
	service, err := NewService(testServiceDatastore(t))
	require.NoError(t, err)

	device := &entities.Device{Serial: "SN-CREATE-DEFAULTS"}
	require.NoError(t, service.Create(context.Background(), device))

	stored, err := service.Get(context.Background(), device.ID)
	require.NoError(t, err)
	assert.Equal(t, entities.DeviceStateRegistered, stored.State)
	assert.False(t, stored.CreatedAt.IsZero(), "CreatedAt must be stamped")
	assert.True(t, stored.UpdatedAt.Equal(stored.CreatedAt), "a new device was last updated when it was created")
}

func TestService_Create_KeepsCallerStateAndTimestamps(t *testing.T) {
	service, err := NewService(testServiceDatastore(t))
	require.NoError(t, err)

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	device := &entities.Device{
		Serial:    "SN-CREATE-CALLER",
		State:     entities.DeviceStateActivated,
		CreatedAt: created,
		UpdatedAt: updated,
	}
	require.NoError(t, service.Create(context.Background(), device))

	stored, err := service.Get(context.Background(), device.ID)
	require.NoError(t, err)
	assert.Equal(t, entities.DeviceStateActivated, stored.State)
	assert.True(t, stored.CreatedAt.Equal(created))
	assert.True(t, stored.UpdatedAt.Equal(updated))
}

// TestService_Create_MintsDistinctIdentities guards the one thing a
// minted ID must do: two creates must not collide, or the second
// silently overwrites the first.
func TestService_Create_MintsDistinctIdentities(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	ctx := context.Background()

	first := &entities.Device{Serial: "SN-CREATE-003"}
	second := &entities.Device{Serial: "SN-CREATE-004"}

	require.NoError(t, service.Create(ctx, first))
	require.NoError(t, service.Create(ctx, second))

	assert.NotEqual(t, first.ID, second.ID)

	storedFirst, err := service.Get(ctx, first.ID)
	require.NoError(t, err)
	assert.Equal(t, "SN-CREATE-003", storedFirst.Serial)
}

// TestService_Create_NilDevice is the failure case: a nil device is a
// caller bug, and it must be a typed error rather than a panic.
func TestService_Create_NilDevice(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	err = service.Create(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNilDevice)
}

// TestService_Create_DAOError asserts a storage failure surfaces from
// Create rather than being swallowed once an ID has been assigned.
func TestService_Create_DAOError(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	mockStorage.PutError = errors.New("storage write failed")

	device := &entities.Device{Serial: "SN-CREATE-005"}

	err = service.Create(context.Background(), device)
	assert.Error(t, err)
	assert.NotZero(t, device.ID, "the ID is assigned before the write is attempted")
}

func TestService_Create_RefusesATakenSerial(t *testing.T) {
	service, err := NewService(testServiceDatastore(t))
	require.NoError(t, err)
	ctx := context.Background()

	first := &entities.Device{Serial: "SN-TAKEN", Model: "first"}
	require.NoError(t, service.Create(ctx, first))

	err = service.Create(ctx, &entities.Device{Serial: "SN-TAKEN", Model: "second"})
	assert.Equal(t, ErrDeviceSerialExists{Serial: "SN-TAKEN"}, err)
	assert.Equal(t, "device already exists with serial: SN-TAKEN", err.Error())

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "the refused create must not write a second row")
	stored, err := service.Get(ctx, first.ID)
	require.NoError(t, err)
	assert.Equal(t, "first", stored.Model)
}

// A create without a serial is refused by the service itself, so every
// transport refuses it, including gRPC and QUIC, whose decoders do not check
// the serial (#949).
func TestService_Create_RefusesAnEmptySerial(t *testing.T) {
	service, err := NewService(testServiceDatastore(t))
	require.NoError(t, err)
	ctx := context.Background()

	device := &entities.Device{Model: "no-serial"}
	err = service.Create(ctx, device)
	assert.Equal(t, ErrDeviceSerialRequired{}, err)
	assert.Zero(t, device.ID, "a refused create must not be assigned an ID")

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count, "the refused create must not write a row")
}

func TestService_Create_SerialCheckStorageFaultIsNotADuplicate(t *testing.T) {
	ds, mockStorage := testServiceDatastoreWithMock(t)
	service, err := NewService(ds)
	require.NoError(t, err)

	// Stop the backend so the serial lookup fails operationally, not as a miss.
	require.NoError(t, mockStorage.Stop(context.Background()))

	err = service.Create(context.Background(), &entities.Device{Serial: "SN-FAULT"})
	require.Error(t, err)
	assert.False(t, errors.As(err, &ErrDeviceSerialExists{}), "a storage fault is not a taken serial: %v", err)
	var wrapped *WrappedError
	assert.ErrorAs(t, err, &wrapped)
}

// TestService_Save_NilDevice pins the nil guard Save gained alongside
// Create: Update and Delete already answered ErrInvalidDeviceID for a
// nil device while Save dereferenced it.
func TestService_Save_NilDevice(t *testing.T) {
	ds := testServiceDatastore(t)

	service, err := NewService(ds)
	require.NoError(t, err)

	err = service.Save(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNilDevice)
}
