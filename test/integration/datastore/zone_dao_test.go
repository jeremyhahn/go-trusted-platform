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

//go:build integration

// Package datastore provides integration tests for the QuicBaaS ZoneDAO implementation.
// These tests verify DNS zone-specific operations using real QuicBaaS with embedded PebbleDB.
// Run via: make integration-test-datastore or INTEGRATION_TEST=1 go test ./test/integration/datastore/...
package datastore

import (
	"context"
	"errors"
	"testing"
	"time"

	dnsEntities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestZone creates a zone entity for testing.
func createTestZone(name string, internal bool) *dnsEntities.Zone {
	return &dnsEntities.Zone{
		Name:        name,
		TTL:         3600,
		Description: "Test zone for " + name,
		Internal:    internal,
		RecordSet: dnsEntities.RecordSet{
			SOARecord: dnsEntities.SOARecord{
				Name:       name,
				MName:      "ns1." + name,
				RName:      "admin." + name,
				Serial:     2024010101,
				Refresh:    7200,
				Retry:      3600,
				Expire:     1209600,
				MinimumTTL: 86400,
				TTL:        3600,
			},
			NSRecords: []*dnsEntities.NSRecord{
				{Name: name, Value: "ns1." + name, TTL: 3600},
				{Name: name, Value: "ns2." + name, TTL: 3600},
			},
			ARecords: []*dnsEntities.ARecord{
				{Name: "www." + name, Value: "192.168.1.100", TTL: 300},
				{Name: "mail." + name, Value: "192.168.1.101", TTL: 300},
			},
		},
	}
}

// TestZoneDAO_Save_NewZone tests saving a new zone with auto-generated ID.
func TestZoneDAO_Save_NewZone(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()
	zone := createTestZone("example.com.", false)

	// ID should be 0 before save
	assert.Zero(t, zone.ID)

	err := dao.Save(ctx, zone)
	require.NoError(t, err)

	// ID should be auto-generated after save
	assert.NotZero(t, zone.ID)

	// Verify zone can be retrieved
	retrieved, err := dao.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Equal(t, zone.Name, retrieved.Name)
	assert.Equal(t, zone.TTL, retrieved.TTL)
	assert.Equal(t, zone.Description, retrieved.Description)
	assert.Equal(t, zone.Internal, retrieved.Internal)
}

// TestZoneDAO_Save_UpdateZone tests updating an existing zone.
func TestZoneDAO_Save_UpdateZone(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()
	zone := createTestZone("update-test.com.", false)

	require.NoError(t, dao.Save(ctx, zone))
	originalID := zone.ID

	// Update zone
	zone.TTL = 7200
	zone.Description = "Updated description"
	zone.Internal = true
	require.NoError(t, dao.Save(ctx, zone))

	// ID should remain the same
	assert.Equal(t, originalID, zone.ID)

	// Verify update persisted
	retrieved, err := dao.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Equal(t, uint32(7200), retrieved.TTL)
	assert.Equal(t, "Updated description", retrieved.Description)
	assert.True(t, retrieved.Internal)
}

// TestZoneDAO_Get_Success tests successful zone retrieval.
func TestZoneDAO_Get_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()
	zone := createTestZone("get-test.com.", true)
	require.NoError(t, dao.Save(ctx, zone))

	retrieved, err := dao.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Equal(t, zone.ID, retrieved.ID)
	assert.Equal(t, zone.Name, retrieved.Name)
	assert.Equal(t, zone.Internal, retrieved.Internal)
}

// TestZoneDAO_Get_NotFound tests retrieval of non-existent zone.
func TestZoneDAO_Get_NotFound(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	_, err := dao.Get(ctx, 999999999)
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestZoneDAO_Delete_Success tests successful zone deletion.
func TestZoneDAO_Delete_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()
	zone := createTestZone("delete-test.com.", false)
	require.NoError(t, dao.Save(ctx, zone))

	// Verify zone exists
	_, err := dao.Get(ctx, zone.ID)
	require.NoError(t, err)

	// Delete zone
	require.NoError(t, dao.Delete(ctx, zone))

	// Verify zone is deleted (eventually, due to async delete in QuicBaaS)
	require.Eventually(t, func() bool {
		_, err := dao.Get(ctx, zone.ID)
		return err != nil
	}, 5*time.Second, 100*time.Millisecond, "zone should be deleted")
}

// TestZoneDAO_GetByName_Success tests retrieving zone by name.
func TestZoneDAO_GetByName_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Create unique zone name for this test
	uniqueName := "getbyname-" + time.Now().Format("20060102150405") + ".com."
	zone := createTestZone(uniqueName, false)
	require.NoError(t, dao.Save(ctx, zone))

	// Retrieve by name
	retrieved, err := dao.GetByName(ctx, uniqueName)
	require.NoError(t, err)
	assert.Equal(t, uniqueName, retrieved.Name)
	assert.Equal(t, zone.ID, retrieved.ID)
	assert.Equal(t, zone.TTL, retrieved.TTL)
}

// TestZoneDAO_GetByName_NotFound tests GetByName with non-existent zone.
func TestZoneDAO_GetByName_NotFound(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	_, err := dao.GetByName(ctx, "nonexistent-zone-12345.com.")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestZoneDAO_GetByName_FallbackScan tests that GetByName falls back to scan.
func TestZoneDAO_GetByName_FallbackScan(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Create multiple zones
	zone1 := createTestZone("scan-test1.com.", false)
	zone2 := createTestZone("scan-test2.com.", true)
	zone3 := createTestZone("scan-test3.com.", false)

	require.NoError(t, dao.Save(ctx, zone1))
	require.NoError(t, dao.Save(ctx, zone2))
	require.NoError(t, dao.Save(ctx, zone3))

	// Since QuicBaaS may not have secondary indexes configured,
	// GetByName should fall back to scanning and still find the zone
	retrieved, err := dao.GetByName(ctx, "scan-test2.com.")
	require.NoError(t, err)
	assert.Equal(t, "scan-test2.com.", retrieved.Name)
	assert.Equal(t, zone2.ID, retrieved.ID)
	assert.True(t, retrieved.Internal)
}

// TestZoneDAO_Count tests counting zones.
func TestZoneDAO_Count(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Initial count
	initialCount, err := dao.Count(ctx)
	require.NoError(t, err)

	// Add zones
	numZones := 3
	for i := 0; i < numZones; i++ {
		zone := createTestZone("count-test"+time.Now().Format("150405.000000")+".com.", false)
		require.NoError(t, dao.Save(ctx, zone))
		time.Sleep(time.Millisecond) // Ensure unique timestamp-based IDs
	}

	// Verify count increased
	newCount, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, initialCount+numZones, newCount)
}

// TestZoneDAO_RecordSetPersistence tests that zone records persist correctly.
func TestZoneDAO_RecordSetPersistence(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Create zone with various record types
	zone := &dnsEntities.Zone{
		Name:        "recordset-test.com.",
		TTL:         3600,
		Description: "Zone with multiple record types",
		Internal:    false,
		RecordSet: dnsEntities.RecordSet{
			SOARecord: dnsEntities.SOARecord{
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
			ARecords: []*dnsEntities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 300},
				{Name: "api", Value: "192.168.1.2", TTL: 300},
			},
			AAAARecords: []*dnsEntities.AAAARecord{
				{Name: "www", Value: "2001:db8::1", TTL: 300},
			},
			CNAMERecords: []*dnsEntities.CNAMERecord{
				{Name: "blog", Value: "www.recordset-test.com.", TTL: 300},
			},
			MXRecords: []*dnsEntities.MXRecord{
				{Name: "recordset-test.com.", Value: "mail.recordset-test.com.", Priority: 10, TTL: 3600},
			},
			TXTRecords: []*dnsEntities.TXTRecord{
				{Name: "recordset-test.com.", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			},
			NSRecords: []*dnsEntities.NSRecord{
				{Name: "recordset-test.com.", Value: "ns1.recordset-test.com.", TTL: 86400},
				{Name: "recordset-test.com.", Value: "ns2.recordset-test.com.", TTL: 86400},
			},
		},
	}

	require.NoError(t, dao.Save(ctx, zone))

	// Retrieve and verify all records
	retrieved, err := dao.Get(ctx, zone.ID)
	require.NoError(t, err)

	// Verify SOA record
	assert.Equal(t, zone.RecordSet.SOARecord.MName, retrieved.RecordSet.SOARecord.MName)
	assert.Equal(t, zone.RecordSet.SOARecord.RName, retrieved.RecordSet.SOARecord.RName)
	assert.Equal(t, zone.RecordSet.SOARecord.Serial, retrieved.RecordSet.SOARecord.Serial)

	// Verify A records
	assert.Len(t, retrieved.RecordSet.ARecords, 2)
	assert.Equal(t, "www", retrieved.RecordSet.ARecords[0].Name)
	assert.Equal(t, "192.168.1.1", retrieved.RecordSet.ARecords[0].Value)

	// Verify AAAA records
	assert.Len(t, retrieved.RecordSet.AAAARecords, 1)
	assert.Equal(t, "2001:db8::1", retrieved.RecordSet.AAAARecords[0].Value)

	// Verify CNAME records
	assert.Len(t, retrieved.RecordSet.CNAMERecords, 1)
	assert.Equal(t, "blog", retrieved.RecordSet.CNAMERecords[0].Name)

	// Verify MX records
	assert.Len(t, retrieved.RecordSet.MXRecords, 1)
	assert.Equal(t, uint16(10), retrieved.RecordSet.MXRecords[0].Priority)

	// Verify TXT records
	assert.Len(t, retrieved.RecordSet.TXTRecords, 1)
	assert.Contains(t, retrieved.RecordSet.TXTRecords[0].Value, "v=spf1")

	// Verify NS records
	assert.Len(t, retrieved.RecordSet.NSRecords, 2)
}

// TestZoneDAO_AddRemoveRecords tests adding and removing records from a zone.
func TestZoneDAO_AddRemoveRecords(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Create initial zone
	zone := createTestZone("modify-records.com.", false)
	require.NoError(t, dao.Save(ctx, zone))

	// Add new A record
	zone.AddARecord(&dnsEntities.ARecord{
		Name:  "new-host",
		Value: "192.168.1.200",
		TTL:   600,
	})
	require.NoError(t, dao.Save(ctx, zone))

	// Verify new record was added
	retrieved, err := dao.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.ARecords, 3) // 2 original + 1 new

	// Remove an A record
	zone.RemoveARecord("www.modify-records.com.")
	require.NoError(t, dao.Save(ctx, zone))

	// Verify record was removed
	retrieved, err = dao.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Len(t, retrieved.RecordSet.ARecords, 2) // 3 - 1 removed
}

// TestZoneDAO_InternalVsExternal tests internal vs external zone distinction.
func TestZoneDAO_InternalVsExternal(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Create internal zone
	internalZone := createTestZone("internal.local.", true)
	require.NoError(t, dao.Save(ctx, internalZone))

	// Create external zone
	externalZone := createTestZone("external.com.", false)
	require.NoError(t, dao.Save(ctx, externalZone))

	// Verify internal zone
	retrievedInternal, err := dao.Get(ctx, internalZone.ID)
	require.NoError(t, err)
	assert.True(t, retrievedInternal.Internal)

	// Verify external zone
	retrievedExternal, err := dao.Get(ctx, externalZone.ID)
	require.NoError(t, err)
	assert.False(t, retrievedExternal.Internal)
}

// TestZoneDAO_ConcurrentOperations tests concurrent zone operations.
func TestZoneDAO_ConcurrentOperations(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Concurrent writes
	numGoroutines := 5
	done := make(chan bool, numGoroutines)
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			zone := createTestZone(
				"concurrent-"+time.Now().Format("150405.000000000")+".com.",
				idx%2 == 0,
			)
			if err := dao.Save(ctx, zone); err != nil {
				errChan <- err
			}
			done <- true
		}(i)
		time.Sleep(time.Microsecond) // Small delay for unique timestamps
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Check for errors
	select {
	case err := <-errChan:
		t.Fatalf("concurrent operation failed: %v", err)
	default:
	}

	// Verify all zones were created
	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, numGoroutines)
}

// TestZoneDAO_DataPersistenceAcrossDAOInstances tests data persists across DAO instances.
func TestZoneDAO_DataPersistenceAcrossDAOInstances(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao1 := quicbaas.NewZoneDAO(client, logger)

	ctx := context.Background()

	// Create zone with first DAO
	zone := createTestZone("persistence-test.com.", true)
	require.NoError(t, dao1.Save(ctx, zone))

	// Create new DAO instance
	dao2 := quicbaas.NewZoneDAO(client, logger)

	// Retrieve with second DAO
	retrieved, err := dao2.Get(ctx, zone.ID)
	require.NoError(t, err)
	assert.Equal(t, zone.Name, retrieved.Name)
	assert.Equal(t, zone.Internal, retrieved.Internal)

	// GetByName with second DAO
	retrievedByName, err := dao2.GetByName(ctx, "persistence-test.com.")
	require.NoError(t, err)
	assert.Equal(t, zone.ID, retrievedByName.ID)
}
