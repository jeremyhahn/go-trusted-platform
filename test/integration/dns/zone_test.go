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

// Package dns provides integration tests for DNS zone CRUD operations.
// These tests verify end-to-end DNS zone functionality with real in-memory datastore.
// Run via: make integration-test-dns
package dns

import (
	"context"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestDatastore creates a mock QuicBaaS-backed datastore for integration testing.
func createTestDatastore(t *testing.T) *dns.Datastore {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()

	// Start the mock storage - required before any operations
	err := mockStorage.Start(context.Background())
	require.NoError(t, err, "failed to start mock storage")

	return dns.NewDatastore(mockStorage, logger)
}

// createTestService creates a DNS service for integration testing.
func createTestService(t *testing.T) *dns.Service {
	ds := createTestDatastore(t)

	svcParams := &dns.Params{
		TenantID: "integration-test", // Platform tenant for authorization
		Config: &dns.Config{
			AllowRegistration:         true,
			AllowExternalRegistration: true,
			AllowInternalRegistration: true,
			Logger:                    logging.DefaultLogger(),
		},
		Datastore: ds,
	}

	svc, err := dns.NewService(svcParams)
	require.NoError(t, err)

	return svc
}

// createTestZone creates a zone entity for testing.
func createTestZone(name string, internal bool) *entities.Zone {
	return &entities.Zone{
		ID:          util.NewID([]byte(name)),
		Name:        name,
		TenantID:    "integration-test", // Matches test service tenant
		TTL:         3600,
		Description: "Integration test zone for " + name,
		Internal:    internal,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       name,
				MName:      "ns1." + name,
				RName:      "hostmaster." + name,
				Serial:     2024010101,
				Refresh:    7200,
				Retry:      3600,
				Expire:     1209600,
				MinimumTTL: 86400,
				TTL:        3600,
			},
			NSRecords: []*entities.NSRecord{
				{Name: name, Value: "ns1." + name, TTL: 3600},
				{Name: name, Value: "ns2." + name, TTL: 3600},
			},
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.100", TTL: 300},
				{Name: "mail", Value: "192.168.1.101", TTL: 300},
			},
		},
	}
}

// TestZone_Create_Success tests successful zone creation.
func TestZone_Create_Success(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("example.com.", false)

	// Save the zone
	err := svc.Save(ctx, zone)
	require.NoError(t, err)

	// Verify zone can be retrieved
	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.Equal(t, zone.Name, retrieved.Name)
	assert.Equal(t, zone.TTL, retrieved.TTL)
	assert.Equal(t, zone.Description, retrieved.Description)
	assert.Equal(t, zone.Internal, retrieved.Internal)
	assert.Equal(t, zone.RecordSet.SOARecord.MName, retrieved.RecordSet.SOARecord.MName)
}

// TestZone_Create_InternalZone tests creating an internal zone.
func TestZone_Create_InternalZone(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("example.internal.", true)

	err := svc.Save(ctx, zone)
	require.NoError(t, err)

	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.True(t, retrieved.Internal)
	assert.Equal(t, "example.internal.", retrieved.Name)
}

// TestZone_Update_Success tests successful zone update.
func TestZone_Update_Success(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("update-test.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	// Update zone properties
	zone.TTL = 7200
	zone.Description = "Updated description for integration test"
	zone.Internal = true

	require.NoError(t, svc.Save(ctx, zone))

	// Verify update persisted
	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.Equal(t, uint32(7200), retrieved.TTL)
	assert.Equal(t, "Updated description for integration test", retrieved.Description)
	assert.True(t, retrieved.Internal)
}

// TestZone_Update_AddRecords tests adding records to an existing zone.
func TestZone_Update_AddRecords(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("add-records.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	initialARecordCount := len(zone.RecordSet.ARecords)

	// Add new A record
	zone.AddARecord(&entities.ARecord{
		Name:  "api",
		Value: "192.168.1.102",
		TTL:   300,
	})

	// Add new AAAA record
	zone.AddAAAARecord(&entities.AAAARecord{
		Name:  "www",
		Value: "2001:db8::1",
		TTL:   300,
	})

	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.ARecords, initialARecordCount+1)
	assert.Len(t, retrieved.RecordSet.AAAARecords, 1)
}

// TestZone_Update_RemoveRecords tests removing records from an existing zone.
func TestZone_Update_RemoveRecords(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("remove-records.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	initialCount := len(zone.RecordSet.ARecords)
	require.GreaterOrEqual(t, initialCount, 1, "zone should have at least one A record")

	// Remove an A record
	zone.RemoveARecord("www")
	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.Len(t, retrieved.RecordSet.ARecords, initialCount-1)
}

// TestZone_Delete_Success tests successful zone deletion.
func TestZone_Delete_Success(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("delete-test.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	// Verify zone exists
	_, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	// Delete the zone
	err = svc.Delete(ctx, zone)
	require.NoError(t, err)

	// Verify zone is deleted
	_, err = svc.Zone(ctx, zone.Name)
	assert.Error(t, err, "expected error when retrieving deleted zone")
}

// TestZone_Get_NotFound tests retrieving a non-existent zone.
func TestZone_Get_NotFound(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	_, err := svc.Zone(ctx, "nonexistent.com.")
	assert.Error(t, err)
}

// TestZone_Get_NormalizesName tests that zone retrieval normalizes names.
func TestZone_Get_NormalizesName(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("normalize-test.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	// Query without trailing dot
	retrieved, err := svc.Zone(ctx, "normalize-test.com")
	require.NoError(t, err)
	assert.Equal(t, "normalize-test.com.", retrieved.Name)
}

// TestZone_MultipleZones tests managing multiple zones concurrently.
func TestZone_MultipleZones(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zoneNames := []string{
		"zone1.example.com.",
		"zone2.example.com.",
		"zone3.example.com.",
		"internal.local.",
		"trusted.internal.",
	}

	// Create all zones
	for i, name := range zoneNames {
		zone := createTestZone(name, i >= 3) // Last two are internal
		require.NoError(t, svc.Save(ctx, zone), "failed to save zone %s", name)
	}

	// Verify all zones can be retrieved
	for i, name := range zoneNames {
		retrieved, err := svc.Zone(ctx, name)
		require.NoError(t, err, "failed to retrieve zone %s", name)
		assert.Equal(t, name, retrieved.Name)
		assert.Equal(t, i >= 3, retrieved.Internal, "zone %s internal flag mismatch", name)
	}
}

// TestZone_RecordSetPersistence tests that all record types persist correctly.
func TestZone_RecordSetPersistence(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zoneName := "recordset-persistence.com."
	zone := &entities.Zone{
		ID:          util.NewID([]byte(zoneName)),
		Name:        zoneName,
		TTL:         3600,
		Description: "Zone with all record types",
		Internal:    false,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       zoneName,
				MName:      "ns1." + zoneName,
				RName:      "hostmaster." + zoneName,
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
				{Name: "blog", Value: "www." + zoneName, TTL: 300},
			},
			MXRecords: []*entities.MXRecord{
				{Name: zoneName, Value: "mail." + zoneName, Priority: 10, TTL: 3600},
			},
			TXTRecords: []*entities.TXTRecord{
				{Name: zoneName, Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			},
			NSRecords: []*entities.NSRecord{
				{Name: zoneName, Value: "ns1." + zoneName, TTL: 86400},
				{Name: zoneName, Value: "ns2." + zoneName, TTL: 86400},
			},
			SRVRecords: []*entities.SRVRecord{
				{Name: "_ldap._tcp." + zoneName, Target: "ldap." + zoneName, Port: 389, Priority: 10, Weight: 100, TTL: 3600},
			},
		},
	}

	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)

	// Verify all record types persisted
	assert.Len(t, retrieved.RecordSet.ARecords, 2)
	assert.Len(t, retrieved.RecordSet.AAAARecords, 1)
	assert.Len(t, retrieved.RecordSet.CNAMERecords, 1)
	assert.Len(t, retrieved.RecordSet.MXRecords, 1)
	assert.Len(t, retrieved.RecordSet.TXTRecords, 1)
	assert.Len(t, retrieved.RecordSet.NSRecords, 2)
	assert.Len(t, retrieved.RecordSet.SRVRecords, 1)

	// Verify SOA record
	assert.Equal(t, "ns1."+zoneName, retrieved.RecordSet.SOARecord.MName)
	assert.Equal(t, uint32(2024010101), retrieved.RecordSet.SOARecord.Serial)
}

// TestZone_ConcurrentOperations tests concurrent zone operations.
func TestZone_ConcurrentOperations(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	numGoroutines := 10
	done := make(chan bool, numGoroutines)
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			zoneName := fmt.Sprintf("concurrent-%d.com.", idx)
			zone := createTestZone(zoneName, idx%2 == 0)
			if err := svc.Save(ctx, zone); err != nil {
				errChan <- err
			}

			// Verify we can retrieve it
			if _, err := svc.Zone(ctx, zoneName); err != nil {
				errChan <- err
			}
			done <- true
		}(i)
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
}

// TestZone_SOARecordUpdate tests updating SOA record fields.
func TestZone_SOARecordUpdate(t *testing.T) {
	svc := createTestService(t)
	ctx := context.Background()

	zone := createTestZone("soa-update.com.", false)
	require.NoError(t, svc.Save(ctx, zone))

	// Update SOA record
	zone.RecordSet.SOARecord.Serial = 2024010102
	zone.RecordSet.SOARecord.Refresh = 14400
	zone.RecordSet.SOARecord.Retry = 1800

	require.NoError(t, svc.Save(ctx, zone))

	retrieved, err := svc.Zone(ctx, zone.Name)
	require.NoError(t, err)

	assert.Equal(t, uint32(2024010102), retrieved.RecordSet.SOARecord.Serial)
	assert.Equal(t, uint32(14400), retrieved.RecordSet.SOARecord.Refresh)
	assert.Equal(t, uint32(1800), retrieved.RecordSet.SOARecord.Retry)
}
