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
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockZoneDAO(t *testing.T) (*ZoneDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewZoneDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestZoneDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		Name:        "example.com",
		TTL:         3600,
		Description: "Test zone",
	}
	err := dao.Save(ctx, zone)

	require.NoError(t, err)
	assert.NotZero(t, zone.ID)
	assert.Equal(t, 1, mock.Count(entityTypeZone))
}

func TestZoneDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		ID:          12345,
		Name:        "example.com",
		TTL:         3600,
		Description: "Test zone",
	}
	err := dao.Save(ctx, zone)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), zone.ID)
}

func TestZoneDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		ID:          12345,
		Name:        "example.com",
		TTL:         3600,
		Description: "Test zone",
		Internal:    true,
	}
	require.NoError(t, dao.Save(ctx, zone))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "example.com", retrieved.Name)
	assert.Equal(t, uint32(3600), retrieved.TTL)
	assert.Equal(t, "Test zone", retrieved.Description)
	assert.True(t, retrieved.Internal)
}

func TestZoneDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestZoneDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{ID: 12345, Name: "example.com"}
	require.NoError(t, dao.Save(ctx, zone))
	assert.Equal(t, 1, mock.Count(entityTypeZone))

	err := dao.Delete(ctx, zone)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeZone))
}

func TestZoneDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		ID:          12345,
		Name:        "example.com",
		TTL:         3600,
		Description: "Initial description",
	}
	require.NoError(t, dao.Save(ctx, zone))

	zone.TTL = 7200
	zone.Description = "Updated description"
	require.NoError(t, dao.Save(ctx, zone))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, uint32(7200), retrieved.TTL)
	assert.Equal(t, "Updated description", retrieved.Description)
}

func TestZoneDAO_GetByName_WithScan_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save multiple zones
	zones := []*entities.Zone{
		{ID: 1, Name: "example.com", TTL: 3600},
		{ID: 2, Name: "test.org", TTL: 7200},
		{ID: 3, Name: "internal.local", TTL: 1800},
	}
	for _, zone := range zones {
		require.NoError(t, dao.Save(ctx, zone))
	}

	// Force scan by making Query return error
	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByName(ctx, "test.org")

	require.NoError(t, err)
	assert.Equal(t, "test.org", retrieved.Name)
	assert.Equal(t, uint32(7200), retrieved.TTL)
}

func TestZoneDAO_GetByName_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{ID: 1, Name: "example.com"}
	require.NoError(t, dao.Save(ctx, zone))

	// Force scan
	mock.QueryError = errors.New("no index")

	_, err := dao.GetByName(ctx, "nonexistent.com")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestZoneDAO_GetByName_WithIndex_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		ID:   12345,
		Name: "indexed.com",
		TTL:  3600,
	}
	data, _ := json.Marshal(zone)
	mock.SetQueryResult(entityTypeZone, "Name", []byte("indexed.com"), []*service.Entity{{ID: 12345, Data: data}})

	retrieved, err := dao.GetByName(ctx, "indexed.com")

	require.NoError(t, err)
	assert.Equal(t, "indexed.com", retrieved.Name)
}

func TestZoneDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		zone := &entities.Zone{ID: uint64(i), Name: "zone" + string(rune('0'+i)) + ".com"}
		require.NoError(t, dao.Save(ctx, zone))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestZoneDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.Count(ctx)
	require.Error(t, err)
}

func TestZoneDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		zone := &entities.Zone{ID: uint64(i), Name: "zone" + string(rune('0'+i)) + ".com"}
		require.NoError(t, dao.Save(ctx, zone))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestZoneDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		zone := &entities.Zone{ID: uint64(i), Name: "zone.com"}
		require.NoError(t, dao.Save(ctx, zone))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestZoneDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		zone := &entities.Zone{ID: uint64(i), Name: "zone.com"}
		require.NoError(t, dao.Save(ctx, zone))
	}

	var allZones []*entities.Zone
	processor := func(result datastore.PageResult[*entities.Zone]) error {
		allZones = append(allZones, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allZones))
}

func TestZoneDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		zone := &entities.Zone{ID: uint64(i), Name: "zone.com"}
		require.NoError(t, dao.Save(ctx, zone))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.Zone]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestZoneDAO_WithRecordSet_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		ID:          12345,
		Name:        "example.com",
		TTL:         3600,
		Description: "Zone with records",
	}
	zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	zone.AddAAAARecord(&entities.AAAARecord{Name: "www", Value: "::1", TTL: 3600})
	zone.AddMXRecord(&entities.MXRecord{Name: "mail", Priority: 10, Value: "mail.example.com", TTL: 3600})

	require.NoError(t, dao.Save(ctx, zone))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.ARecords, 1)
	assert.Equal(t, "www", retrieved.RecordSet.ARecords[0].Name)
	assert.Equal(t, "192.168.1.1", retrieved.RecordSet.ARecords[0].Value)

	assert.Len(t, retrieved.RecordSet.AAAARecords, 1)
	assert.Equal(t, "::1", retrieved.RecordSet.AAAARecords[0].Value)

	assert.Len(t, retrieved.RecordSet.MXRecords, 1)
	assert.Equal(t, uint16(10), retrieved.RecordSet.MXRecords[0].Priority)
}

func TestZoneDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	zone := &entities.Zone{Name: "example.com"}
	err := dao.Save(ctx, zone)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestZoneDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	zone := &entities.Zone{ID: 12345, Name: "example.com"}
	data, _ := json.Marshal(zone)
	mock.SetData(entityTypeZone, 12345, data)

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestZoneDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	zone := &entities.Zone{ID: 12345, Name: "example.com"}
	err := dao.Delete(ctx, zone)

	require.Error(t, err)
}

func TestZoneDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}

func TestZoneDAO_GetByName_ListError_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	// Force scan (no query result)
	mock.QueryError = errors.New("no index")
	mock.ListError = errors.New("list failed")

	ctx := context.Background()
	_, err := dao.GetByName(ctx, "example.com")

	require.Error(t, err)
}

func TestZoneDAO_NewZoneRecordSetReadBySecondInstance_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		Name:        "recordset-test.com.",
		TTL:         3600,
		Description: "Zone with multiple record types",
		Internal:    true,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "recordset-test.com.",
				MName:      "ns1.recordset-test.com.",
				RName:      "admin.recordset-test.com.",
				Serial:     2024010101,
				Refresh:    7200,
				Retry:      3600,
				Expire:     1209600,
				MinimumTTL: 86400,
				TTL:        3600,
			},
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 300},
				{Name: "api", Value: "192.168.1.2", TTL: 300},
			},
			AAAARecords: []*entities.AAAARecord{
				{Name: "www", Value: "2001:db8::1", TTL: 300},
			},
			CNAMERecords: []*entities.CNAMERecord{
				{Name: "blog", Value: "www.recordset-test.com.", TTL: 300},
			},
			MXRecords: []*entities.MXRecord{
				{Name: "recordset-test.com.", Value: "mail.recordset-test.com.", Priority: 10, TTL: 3600},
			},
			TXTRecords: []*entities.TXTRecord{
				{Name: "recordset-test.com.", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			},
			NSRecords: []*entities.NSRecord{
				{Name: "recordset-test.com.", Value: "ns1.recordset-test.com.", TTL: 86400},
				{Name: "recordset-test.com.", Value: "ns2.recordset-test.com.", TTL: 86400},
			},
		},
	}
	assert.Zero(t, zone.ID)
	require.NoError(t, dao.Save(ctx, zone))
	assert.NotZero(t, zone.ID, "ID should be auto-generated")

	// A DAO opened later over the same store reads the zone and every record type back.
	dao2 := NewZoneDAO(mock, logging.DefaultLogger(), WithRequestTimeout(5*time.Second))
	retrieved, err := dao2.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Equal(t, zone.Name, retrieved.Name)
	assert.Equal(t, zone.TTL, retrieved.TTL)
	assert.Equal(t, zone.Description, retrieved.Description)
	assert.True(t, retrieved.Internal)

	assert.Equal(t, zone.RecordSet.SOARecord.MName, retrieved.RecordSet.SOARecord.MName)
	assert.Equal(t, zone.RecordSet.SOARecord.RName, retrieved.RecordSet.SOARecord.RName)
	assert.Equal(t, zone.RecordSet.SOARecord.Serial, retrieved.RecordSet.SOARecord.Serial)
	require.Len(t, retrieved.RecordSet.ARecords, 2)
	assert.Equal(t, "www", retrieved.RecordSet.ARecords[0].Name)
	assert.Equal(t, "192.168.1.1", retrieved.RecordSet.ARecords[0].Value)
	require.Len(t, retrieved.RecordSet.AAAARecords, 1)
	assert.Equal(t, "2001:db8::1", retrieved.RecordSet.AAAARecords[0].Value)
	require.Len(t, retrieved.RecordSet.CNAMERecords, 1)
	assert.Equal(t, "blog", retrieved.RecordSet.CNAMERecords[0].Name)
	require.Len(t, retrieved.RecordSet.MXRecords, 1)
	assert.Equal(t, uint16(10), retrieved.RecordSet.MXRecords[0].Priority)
	require.Len(t, retrieved.RecordSet.TXTRecords, 1)
	assert.Contains(t, retrieved.RecordSet.TXTRecords[0].Value, "v=spf1")
	assert.Len(t, retrieved.RecordSet.NSRecords, 2)

	byName, err := dao2.GetByName(ctx, "recordset-test.com.")
	require.NoError(t, err)
	assert.Equal(t, zone.ID, byName.ID)
}

func TestZoneDAO_AddRemoveARecordPersists_Mock(t *testing.T) {
	dao, mock := setupMockZoneDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	zone := &entities.Zone{
		Name: "modify-records.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www.modify-records.com.", Value: "192.168.1.10", TTL: 3600},
				{Name: "mail.modify-records.com.", Value: "192.168.1.20", TTL: 3600},
			},
		},
	}
	require.NoError(t, dao.Save(ctx, zone))

	zone.AddARecord(&entities.ARecord{Name: "new-host", Value: "192.168.1.200", TTL: 600})
	require.NoError(t, dao.Save(ctx, zone))

	retrieved, err := dao.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.ARecords, 3)

	zone.RemoveARecord("www.modify-records.com.")
	require.NoError(t, dao.Save(ctx, zone))

	retrieved, err = dao.Get(ctx, zone.ID)
	require.NoError(t, err)
	require.Len(t, retrieved.RecordSet.ARecords, 2)
	for _, record := range retrieved.RecordSet.ARecords {
		assert.NotEqual(t, "www.modify-records.com.", record.Name)
	}
}
