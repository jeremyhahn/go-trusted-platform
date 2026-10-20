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

// Package dns provides multi-protocol integration tests for DNS services.
// These tests verify that DNS operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified DNSCommands interface.
//
// Run tests via:
//
//	make integration-test-dns
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package dns

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestDNSMultiProtocol runs the complete DNS test suite against all protocol adapters.
// Each adapter implements the DNSCommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestDNSMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement DNSCommands
	adapters := []DNSCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "dns", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testDNSProtocol(t, ctx, adapter)
		})
	}
}

// testDNSProtocol runs the complete DNS test suite against a single protocol adapter.
func testDNSProtocol(t *testing.T, ctx context.Context, cmd DNSCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("ZoneManagement", func(t *testing.T) {
		testZoneCreate(t, ctx, cmd, prefix)
		testZoneGet(t, ctx, cmd, prefix)
		testZoneUpdate(t, ctx, cmd, prefix)
		testZoneList(t, ctx, cmd, prefix)
		testZoneDelete(t, ctx, cmd, prefix)
	})

	t.Run("RecordManagement", func(t *testing.T) {
		testRecordAdd(t, ctx, cmd, prefix)
		testRecordGet(t, ctx, cmd, prefix)
		testRecordUpdate(t, ctx, cmd, prefix)
		testRecordList(t, ctx, cmd, prefix)
		testRecordDelete(t, ctx, cmd, prefix)
	})

	t.Run("RecordTypes", func(t *testing.T) {
		testRecordTypeA(t, ctx, cmd, prefix)
		testRecordTypeAAAA(t, ctx, cmd, prefix)
		testRecordTypeCNAME(t, ctx, cmd, prefix)
		testRecordTypeMX(t, ctx, cmd, prefix)
		testRecordTypeTXT(t, ctx, cmd, prefix)
		testRecordTypeSRV(t, ctx, cmd, prefix)
	})

	t.Run("Resolution", func(t *testing.T) {
		testResolve(t, ctx, cmd, prefix)
	})

	t.Run("TLSA", func(t *testing.T) {
		testTLSARecord(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// Zone Management Tests
// =============================================================================

func testZoneCreate(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateZoneWithDefaults", func(t *testing.T) {
		zoneName := fmt.Sprintf("%s-create-default.test.", prefix)
		opts := CreateZoneOptions{
			Name:        zoneName,
			TTL:         3600,
			Description: "Multi-protocol test zone with defaults",
			Internal:    false,
		}

		result, err := cmd.CreateZone(testCtx, opts)
		require.NoError(t, err, "CreateZone should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, zoneName, result.Name, "Zone name should match")
		assert.NotEmpty(t, result.ID, "Zone ID should not be empty")
		assert.Equal(t, uint32(3600), result.TTL, "TTL should match")
		assert.False(t, result.Internal, "Zone should not be internal")
	})

	t.Run("CreateZoneWithSOA", func(t *testing.T) {
		zoneName := fmt.Sprintf("%s-create-soa.test.", prefix)
		opts := CreateZoneOptions{
			Name:        zoneName,
			TTL:         7200,
			Description: "Multi-protocol test zone with SOA",
			Internal:    false,
			SOA: &SOARecordOptions{
				MName:      "ns1.test.",
				RName:      "admin.test.",
				Serial:     2025010101,
				Refresh:    3600,
				Retry:      600,
				Expire:     604800,
				MinimumTTL: 300,
			},
		}

		result, err := cmd.CreateZone(testCtx, opts)
		require.NoError(t, err, "CreateZone with SOA should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, zoneName, result.Name, "Zone name should match")
		assert.Equal(t, uint32(7200), result.TTL, "TTL should match")
	})

	t.Run("CreateInternalZone", func(t *testing.T) {
		zoneName := fmt.Sprintf("%s-create-internal.test.", prefix)
		opts := CreateZoneOptions{
			Name:        zoneName,
			TTL:         3600,
			Description: "Internal test zone",
			Internal:    true,
		}

		result, err := cmd.CreateZone(testCtx, opts)
		require.NoError(t, err, "CreateZone internal should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Internal, "Zone should be internal")
	})

	t.Run("CreateZoneEmptyNameFails", func(t *testing.T) {
		opts := CreateZoneOptions{
			Name: "",
			TTL:  3600,
		}

		_, err := cmd.CreateZone(testCtx, opts)
		require.Error(t, err, "CreateZone should fail with empty name")
	})
}

func testZoneGet(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a zone first
	zoneName := fmt.Sprintf("%s-get.test.", prefix)
	createOpts := CreateZoneOptions{
		Name:        zoneName,
		TTL:         3600,
		Description: "Zone for get test",
		Internal:    false,
		SOA: &SOARecordOptions{
			MName:      "ns1.test.",
			RName:      "admin.test.",
			Serial:     1,
			Refresh:    3600,
			Retry:      600,
			Expire:     604800,
			MinimumTTL: 300,
		},
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("GetExistingZone", func(t *testing.T) {
		result, err := cmd.GetZone(testCtx, zoneName)
		require.NoError(t, err, "GetZone should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, zoneName, result.Name, "Zone name should match")
		assert.Equal(t, "Zone for get test", result.Description, "Description should match")
		assert.Equal(t, uint32(3600), result.TTL, "TTL should match")
	})

	t.Run("GetZoneWithSOAInfo", func(t *testing.T) {
		result, err := cmd.GetZone(testCtx, zoneName)
		require.NoError(t, err, "GetZone should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.SOA, "SOA should not be nil")
		assert.Equal(t, "ns1.test.", result.SOA.MName, "SOA MName should match")
		assert.Equal(t, "admin.test.", result.SOA.RName, "SOA RName should match")
	})

	t.Run("GetNonexistentZoneFails", func(t *testing.T) {
		_, err := cmd.GetZone(testCtx, prefix+"-nonexistent.test.")
		require.Error(t, err, "GetZone should fail for nonexistent zone")
	})
}

func testZoneUpdate(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a zone first
	zoneName := fmt.Sprintf("%s-update.test.", prefix)
	createOpts := CreateZoneOptions{
		Name:        zoneName,
		TTL:         3600,
		Description: "Zone for update test",
		Internal:    false,
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("UpdateZoneTTL", func(t *testing.T) {
		updateOpts := UpdateZoneOptions{
			TTL:         7200,
			Description: "Zone for update test",
		}

		result, err := cmd.UpdateZone(testCtx, zoneName, updateOpts)
		if requireQUICUpdateZoneGap(t, cmd, err) {
			return
		}
		require.NoError(t, err, "UpdateZone should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, zoneName, result.Name, "Zone name should match")
		assert.Equal(t, uint32(7200), result.TTL, "TTL should be updated")
	})

	t.Run("UpdateZoneDescription", func(t *testing.T) {
		updateOpts := UpdateZoneOptions{
			TTL:         7200,
			Description: "Updated description",
		}

		result, err := cmd.UpdateZone(testCtx, zoneName, updateOpts)
		if requireQUICUpdateZoneGap(t, cmd, err) {
			return
		}
		require.NoError(t, err, "UpdateZone should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Verify with GetZone
		getResult, err := cmd.GetZone(testCtx, zoneName)
		require.NoError(t, err, "GetZone should succeed")
		assert.Equal(t, "Updated description", getResult.Description, "Description should be updated")
	})

	t.Run("UpdateNonexistentZoneFails", func(t *testing.T) {
		updateOpts := UpdateZoneOptions{
			TTL: 7200,
		}

		_, err := cmd.UpdateZone(testCtx, prefix+"-nonexistent.test.", updateOpts)
		if requireQUICUpdateZoneGap(t, cmd, err) {
			return
		}
		require.Error(t, err, "UpdateZone should fail for nonexistent zone")
	})
}

// requireQUICUpdateZoneGap records the declared QUIC UpdateZone gap: QUIC has
// no zone-update opcode (owner-queue 90; the docs/dns/api.md transport table reads MISSING), so
// the QUIC adapter refuses with ErrQUICDNSUnsupported. On QUIC it asserts that
// typed refusal and reports true; every other transport reports false and keeps
// the success assertions. When the opcode lands, drop this check so QUIC runs
// the success path too.
func requireQUICUpdateZoneGap(t *testing.T, cmd DNSCommands, err error) bool {
	t.Helper()
	if cmd.Name() != "QUIC" {
		return false
	}
	var unsupported ErrQUICDNSUnsupported
	require.ErrorAs(t, err, &unsupported, "QUIC UpdateZone is a declared gap (owner-queue 90)")
	assert.Equal(t, "UpdateZone", unsupported.Method, "declared method")
	return true
}

func testZoneList(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple zones for listing
	for i := 0; i < 3; i++ {
		zoneName := fmt.Sprintf("%s-list-%d.test.", prefix, i)
		opts := CreateZoneOptions{
			Name:        zoneName,
			TTL:         3600,
			Description: fmt.Sprintf("List test zone %d", i),
			Internal:    i%2 == 0, // Alternate internal/external
		}
		_, err := cmd.CreateZone(testCtx, opts)
		require.NoError(t, err, "Setup: CreateZone should succeed")
	}

	t.Run("ListAllZones", func(t *testing.T) {
		result, err := cmd.ListZones(testCtx, ListZonesOptions{Limit: 100})
		require.NoError(t, err, "ListZones should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Zones), 3, "Should have at least 3 zones")
	})

	t.Run("ListZonesWithPagination", func(t *testing.T) {
		result, err := cmd.ListZones(testCtx, ListZonesOptions{Limit: 2})
		require.NoError(t, err, "ListZones should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Zones)), int32(2), "Should respect limit")
	})

	t.Run("ListInternalZonesOnly", func(t *testing.T) {
		internal := true
		result, err := cmd.ListZones(testCtx, ListZonesOptions{
			Limit:    100,
			Internal: &internal,
		})
		require.NoError(t, err, "ListZones should succeed for internal zones")
		require.NotNil(t, result, "Result should not be nil")

		for _, zone := range result.Zones {
			assert.True(t, zone.Internal, "All zones should be internal")
		}
	})
}

func testZoneDelete(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a zone for deletion
	zoneName := fmt.Sprintf("%s-delete.test.", prefix)
	createOpts := CreateZoneOptions{
		Name:        zoneName,
		TTL:         3600,
		Description: "Zone for delete test",
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("DeleteExistingZone", func(t *testing.T) {
		result, err := cmd.DeleteZone(testCtx, zoneName)
		require.NoError(t, err, "DeleteZone should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, zoneName, result.Name, "Zone name should match")
		assert.True(t, result.Deleted, "Zone should be deleted")
	})

	t.Run("VerifyZoneIsDeleted", func(t *testing.T) {
		_, err := cmd.GetZone(testCtx, zoneName)
		require.Error(t, err, "GetZone should fail for deleted zone")
	})

	t.Run("DeleteNonexistentZoneFails", func(t *testing.T) {
		_, err := cmd.DeleteZone(testCtx, prefix+"-nonexistent-delete.test.")
		require.Error(t, err, "DeleteZone should fail for nonexistent zone")
	})
}

// =============================================================================
// Record Management Tests
// =============================================================================

func testRecordAdd(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a zone first
	zoneName := fmt.Sprintf("%s-record-add.test.", prefix)
	createOpts := CreateZoneOptions{
		Name: zoneName,
		TTL:  3600,
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("AddARecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "www." + zoneName,
			RecordType: "A",
			Value:      "192.168.1.100",
			TTL:        3600,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "www."+zoneName, result.Name, "Record name should match")
		assert.Equal(t, "A", result.RecordType, "Record type should be A")
		assert.Equal(t, "192.168.1.100", result.Value, "Value should match")
	})

	t.Run("AddMXRecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       zoneName,
			RecordType: "MX",
			Value:      "mail." + zoneName,
			TTL:        3600,
			Priority:   10,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord should succeed for MX")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "MX", result.RecordType, "Record type should be MX")
	})

	t.Run("AddRecordEmptyNameFails", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "",
			RecordType: "A",
			Value:      "192.168.1.100",
		}

		_, err := cmd.AddRecord(testCtx, opts)
		require.Error(t, err, "AddRecord should fail with empty name")
	})
}

func testRecordGet(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create zone and record
	zoneName := fmt.Sprintf("%s-record-get.test.", prefix)
	createOpts := CreateZoneOptions{
		Name: zoneName,
		TTL:  3600,
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	recordName := "api." + zoneName
	addOpts := AddRecordOptions{
		ZoneName:   zoneName,
		Name:       recordName,
		RecordType: "A",
		Value:      "192.168.1.200",
		TTL:        7200,
	}
	_, err = cmd.AddRecord(testCtx, addOpts)
	require.NoError(t, err, "Setup: AddRecord should succeed")

	t.Run("GetExistingRecord", func(t *testing.T) {
		result, err := cmd.GetRecord(testCtx, recordName, "A")
		require.NoError(t, err, "GetRecord should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, recordName, result.Name, "Record name should match")
		assert.Equal(t, "A", result.RecordType, "Record type should match")
		assert.Equal(t, "192.168.1.200", result.Value, "Value should match")
		assert.Equal(t, uint32(7200), result.TTL, "TTL should match")
	})

	t.Run("GetNonexistentRecordFails", func(t *testing.T) {
		_, err := cmd.GetRecord(testCtx, "nonexistent."+zoneName, "A")
		require.Error(t, err, "GetRecord should fail for nonexistent record")
	})

	t.Run("GetRecordWrongTypeFails", func(t *testing.T) {
		_, err := cmd.GetRecord(testCtx, recordName, "AAAA")
		require.Error(t, err, "GetRecord should fail for wrong type")
	})
}

func testRecordUpdate(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create zone and record
	zoneName := fmt.Sprintf("%s-record-update.test.", prefix)
	createOpts := CreateZoneOptions{
		Name: zoneName,
		TTL:  3600,
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	recordName := "db." + zoneName
	addOpts := AddRecordOptions{
		ZoneName:   zoneName,
		Name:       recordName,
		RecordType: "A",
		Value:      "10.0.0.1",
		TTL:        3600,
	}
	_, err = cmd.AddRecord(testCtx, addOpts)
	require.NoError(t, err, "Setup: AddRecord should succeed")

	t.Run("UpdateRecordValue", func(t *testing.T) {
		updateOpts := UpdateRecordOptions{
			ZoneName:   zoneName,
			Name:       recordName,
			RecordType: "A",
			Value:      "10.0.0.2",
			TTL:        3600,
		}

		result, err := cmd.UpdateRecord(testCtx, updateOpts)
		require.NoError(t, err, "UpdateRecord should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "10.0.0.2", result.Value, "Value should be updated")
	})

	t.Run("UpdateRecordTTL", func(t *testing.T) {
		updateOpts := UpdateRecordOptions{
			ZoneName:   zoneName,
			Name:       recordName,
			RecordType: "A",
			Value:      "10.0.0.2",
			TTL:        7200,
		}

		result, err := cmd.UpdateRecord(testCtx, updateOpts)
		require.NoError(t, err, "UpdateRecord should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, uint32(7200), result.TTL, "TTL should be updated")
	})

	t.Run("UpdateNonexistentRecordFails", func(t *testing.T) {
		updateOpts := UpdateRecordOptions{
			ZoneName:   zoneName,
			Name:       "nonexistent." + zoneName,
			RecordType: "A",
			Value:      "10.0.0.3",
			TTL:        3600,
		}

		_, err := cmd.UpdateRecord(testCtx, updateOpts)
		require.Error(t, err, "UpdateRecord should fail for nonexistent record")
	})
}

func testRecordList(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create zone with multiple records
	zoneName := fmt.Sprintf("%s-record-list.test.", prefix)
	createOpts := CreateZoneOptions{
		Name: zoneName,
		TTL:  3600,
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	// Add various records
	records := []AddRecordOptions{
		{ZoneName: zoneName, Name: "www." + zoneName, RecordType: "A", Value: "192.168.1.1", TTL: 3600},
		{ZoneName: zoneName, Name: "api." + zoneName, RecordType: "A", Value: "192.168.1.2", TTL: 3600},
		{ZoneName: zoneName, Name: zoneName, RecordType: "MX", Value: "mail." + zoneName, TTL: 3600, Priority: 10},
		{ZoneName: zoneName, Name: zoneName, RecordType: "TXT", Value: "v=spf1 include:_spf.test. ~all", TTL: 3600},
	}

	for _, rec := range records {
		_, err := cmd.AddRecord(testCtx, rec)
		require.NoError(t, err, "Setup: AddRecord should succeed")
	}

	t.Run("ListAllRecords", func(t *testing.T) {
		result, err := cmd.ListRecords(testCtx, zoneName, ListRecordsOptions{Limit: 100})
		require.NoError(t, err, "ListRecords should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Records), 4, "Should have at least 4 records")
	})

	t.Run("ListRecordsByType", func(t *testing.T) {
		result, err := cmd.ListRecords(testCtx, zoneName, ListRecordsOptions{
			RecordType: "A",
			Limit:      100,
		})
		require.NoError(t, err, "ListRecords should succeed for type filter")
		require.NotNil(t, result, "Result should not be nil")

		for _, rec := range result.Records {
			assert.Equal(t, "A", rec.RecordType, "All records should be type A")
		}
	})

	t.Run("ListRecordsWithPagination", func(t *testing.T) {
		result, err := cmd.ListRecords(testCtx, zoneName, ListRecordsOptions{Limit: 2})
		require.NoError(t, err, "ListRecords should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Records)), int32(2), "Should respect limit")
	})
}

func testRecordDelete(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create zone and record
	zoneName := fmt.Sprintf("%s-record-delete.test.", prefix)
	createOpts := CreateZoneOptions{
		Name: zoneName,
		TTL:  3600,
	}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	recordName := "delete-me." + zoneName
	addOpts := AddRecordOptions{
		ZoneName:   zoneName,
		Name:       recordName,
		RecordType: "A",
		Value:      "192.168.1.99",
		TTL:        3600,
	}
	_, err = cmd.AddRecord(testCtx, addOpts)
	require.NoError(t, err, "Setup: AddRecord should succeed")

	t.Run("DeleteExistingRecord", func(t *testing.T) {
		result, err := cmd.DeleteRecord(testCtx, recordName, "A")
		require.NoError(t, err, "DeleteRecord should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, recordName, result.Name, "Record name should match")
		assert.True(t, result.Deleted, "Record should be deleted")
	})

	t.Run("VerifyRecordIsDeleted", func(t *testing.T) {
		_, err := cmd.GetRecord(testCtx, recordName, "A")
		require.Error(t, err, "GetRecord should fail for deleted record")
	})

	t.Run("DeleteNonexistentRecordFails", func(t *testing.T) {
		_, err := cmd.DeleteRecord(testCtx, "nonexistent."+zoneName, "A")
		require.Error(t, err, "DeleteRecord should fail for nonexistent record")
	})
}

// =============================================================================
// Record Type Tests
// =============================================================================

func testRecordTypeA(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("%s-type-a.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("AddMultipleARecords", func(t *testing.T) {
		ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
		for i, ip := range ips {
			opts := AddRecordOptions{
				ZoneName:   zoneName,
				Name:       fmt.Sprintf("host%d.%s", i+1, zoneName),
				RecordType: "A",
				Value:      ip,
				TTL:        3600,
			}

			result, err := cmd.AddRecord(testCtx, opts)
			require.NoError(t, err, "AddRecord for A should succeed")
			assert.Equal(t, ip, result.Value, "IP should match")
		}
	})

	t.Run("InvalidIPv4Fails", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "invalid." + zoneName,
			RecordType: "A",
			Value:      "not-an-ip",
			TTL:        3600,
		}

		_, err := cmd.AddRecord(testCtx, opts)
		require.Error(t, err, "AddRecord should fail for invalid IPv4")
	})
}

func testRecordTypeAAAA(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("%s-type-aaaa.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("AddAAAARecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "ipv6." + zoneName,
			RecordType: "AAAA",
			Value:      "2001:db8::1",
			TTL:        3600,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord for AAAA should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "AAAA", result.RecordType, "Record type should be AAAA")
		assert.Equal(t, "2001:db8::1", result.Value, "IPv6 should match")
	})

	t.Run("InvalidIPv6Fails", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "invalid." + zoneName,
			RecordType: "AAAA",
			Value:      "192.168.1.1", // IPv4, not IPv6
			TTL:        3600,
		}

		_, err := cmd.AddRecord(testCtx, opts)
		require.Error(t, err, "AddRecord should fail for invalid IPv6")
	})
}

func testRecordTypeCNAME(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("%s-type-cname.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	// First add an A record to point to
	_, err = cmd.AddRecord(testCtx, AddRecordOptions{
		ZoneName:   zoneName,
		Name:       "server." + zoneName,
		RecordType: "A",
		Value:      "192.168.1.10",
		TTL:        3600,
	})
	require.NoError(t, err, "Setup: AddRecord for A should succeed")

	t.Run("AddCNAMERecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "alias." + zoneName,
			RecordType: "CNAME",
			Value:      "server." + zoneName,
			TTL:        3600,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord for CNAME should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "CNAME", result.RecordType, "Record type should be CNAME")
		assert.Equal(t, "server."+zoneName, result.Value, "Target should match")
	})
}

func testRecordTypeMX(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("%s-type-mx.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("AddMXRecordWithPriority", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       zoneName,
			RecordType: "MX",
			Value:      "mail1." + zoneName,
			TTL:        3600,
			Priority:   10,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord for MX should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "MX", result.RecordType, "Record type should be MX")
	})

	t.Run("AddMultipleMXWithDifferentPriorities", func(t *testing.T) {
		priorities := []uint16{20, 30}
		for i, priority := range priorities {
			opts := AddRecordOptions{
				ZoneName:   zoneName,
				Name:       zoneName,
				RecordType: "MX",
				Value:      fmt.Sprintf("mail%d.%s", i+2, zoneName),
				TTL:        3600,
				Priority:   priority,
			}

			result, err := cmd.AddRecord(testCtx, opts)
			require.NoError(t, err, "AddRecord for MX should succeed")
			assert.Equal(t, "MX", result.RecordType, "Record type should be MX")
		}
	})
}

func testRecordTypeTXT(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("%s-type-txt.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("AddSPFRecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       zoneName,
			RecordType: "TXT",
			Value:      "v=spf1 include:_spf.example.com ~all",
			TTL:        3600,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord for TXT/SPF should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "TXT", result.RecordType, "Record type should be TXT")
	})

	t.Run("AddDKIMRecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "selector._domainkey." + zoneName,
			RecordType: "TXT",
			Value:      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4...",
			TTL:        3600,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord for TXT/DKIM should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "TXT", result.RecordType, "Record type should be TXT")
	})

	t.Run("AddDMARCRecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "_dmarc." + zoneName,
			RecordType: "TXT",
			Value:      "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
			TTL:        3600,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord for TXT/DMARC should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "TXT", result.RecordType, "Record type should be TXT")
	})
}

func testRecordTypeSRV(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("%s-type-srv.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("AddSRVRecord", func(t *testing.T) {
		opts := AddRecordOptions{
			ZoneName:   zoneName,
			Name:       "_ldap._tcp." + zoneName,
			RecordType: "SRV",
			Value:      "ldap." + zoneName,
			TTL:        3600,
			Priority:   10,
			Weight:     5,
			Port:       389,
		}

		result, err := cmd.AddRecord(testCtx, opts)
		require.NoError(t, err, "AddRecord for SRV should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "SRV", result.RecordType, "Record type should be SRV")
	})

	t.Run("AddMultipleSRVForLoadBalancing", func(t *testing.T) {
		servers := []struct {
			weight uint16
			target string
		}{
			{10, "web1." + zoneName},
			{20, "web2." + zoneName},
			{30, "web3." + zoneName},
		}

		for _, srv := range servers {
			opts := AddRecordOptions{
				ZoneName:   zoneName,
				Name:       "_http._tcp." + zoneName,
				RecordType: "SRV",
				Value:      srv.target,
				TTL:        3600,
				Priority:   10,
				Weight:     srv.weight,
				Port:       80,
			}

			result, err := cmd.AddRecord(testCtx, opts)
			require.NoError(t, err, "AddRecord for SRV should succeed")
			assert.Equal(t, "SRV", result.RecordType, "Record type should be SRV")
		}
	})
}

// =============================================================================
// Resolution Tests
// =============================================================================

func testResolve(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create zone with records for resolution
	zoneName := fmt.Sprintf("%s-resolve.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	// Add records
	_, err = cmd.AddRecord(testCtx, AddRecordOptions{
		ZoneName:   zoneName,
		Name:       "resolve." + zoneName,
		RecordType: "A",
		Value:      "10.20.30.40",
		TTL:        3600,
	})
	require.NoError(t, err, "Setup: AddRecord should succeed")

	t.Run("ResolveARecord", func(t *testing.T) {
		result, err := cmd.Resolve(testCtx, "resolve."+zoneName, "A")
		require.NoError(t, err, "Resolve should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "resolve."+zoneName, result.Name, "Name should match")
		assert.Equal(t, "A", result.RecordType, "Type should be A")
		assert.Contains(t, result.Values, "10.20.30.40", "Values should contain IP")
		assert.Greater(t, result.TTL, uint32(0), "TTL should be positive")
	})

	t.Run("ResolveNonexistentRecord", func(t *testing.T) {
		_, err := cmd.Resolve(testCtx, "nonexistent."+zoneName, "A")
		require.Error(t, err, "Resolve should fail for nonexistent record")
	})
}

// =============================================================================
// TLSA/DANE Tests
// =============================================================================

func testTLSARecord(t *testing.T, ctx context.Context, cmd DNSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create zone for TLSA records
	zoneName := fmt.Sprintf("%s-tlsa.test.", prefix)
	createOpts := CreateZoneOptions{Name: zoneName, TTL: 3600}
	_, err := cmd.CreateZone(testCtx, createOpts)
	require.NoError(t, err, "Setup: CreateZone should succeed")

	t.Run("AddTLSARecordDANEEE", func(t *testing.T) {
		// DANE-EE: Usage=3, Selector=1, Matching=1 (SHA-256)
		opts := AddTLSARecordOptions{
			ZoneName:     zoneName,
			Name:         "_443._tcp." + zoneName,
			Usage:        3, // DANE-EE
			Selector:     1, // SPKI
			MatchingType: 1, // SHA-256
			Data:         "8f6c8e3a12b7e4d3c2f1a0b9e8d7c6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9",
			TTL:          3600,
		}

		result, err := cmd.AddTLSARecord(testCtx, opts)
		require.NoError(t, err, "AddTLSARecord should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "_443._tcp."+zoneName, result.Name, "TLSA name should match")
		assert.Equal(t, uint8(3), result.Usage, "Usage should be 3 (DANE-EE)")
		assert.Equal(t, uint8(1), result.Selector, "Selector should be 1 (SPKI)")
		assert.Equal(t, uint8(1), result.MatchingType, "MatchingType should be 1 (SHA-256)")
	})

	t.Run("AddTLSARecordDANETA", func(t *testing.T) {
		// DANE-TA: Usage=2, Selector=0, Matching=1 (SHA-256)
		opts := AddTLSARecordOptions{
			ZoneName:     zoneName,
			Name:         "_25._tcp." + zoneName,
			Usage:        2, // DANE-TA
			Selector:     0, // Full certificate
			MatchingType: 1, // SHA-256
			Data:         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			TTL:          3600,
		}

		result, err := cmd.AddTLSARecord(testCtx, opts)
		require.NoError(t, err, "AddTLSARecord should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, uint8(2), result.Usage, "Usage should be 2 (DANE-TA)")
		assert.Equal(t, uint8(0), result.Selector, "Selector should be 0 (Full cert)")
	})

	t.Run("AddTLSARecordSHA512", func(t *testing.T) {
		// Using SHA-512 matching
		opts := AddTLSARecordOptions{
			ZoneName:     zoneName,
			Name:         "_8443._tcp." + zoneName,
			Usage:        3, // DANE-EE
			Selector:     1, // SPKI
			MatchingType: 2, // SHA-512
			Data:         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
			TTL:          3600,
		}

		result, err := cmd.AddTLSARecord(testCtx, opts)
		require.NoError(t, err, "AddTLSARecord with SHA-512 should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, uint8(2), result.MatchingType, "MatchingType should be 2 (SHA-512)")
	})

	t.Run("AddTLSARecordInvalidUsageFails", func(t *testing.T) {
		opts := AddTLSARecordOptions{
			ZoneName:     zoneName,
			Name:         "_invalid._tcp." + zoneName,
			Usage:        5, // Invalid usage (valid: 0-3)
			Selector:     1,
			MatchingType: 1,
			Data:         "abcd1234",
			TTL:          3600,
		}

		_, err := cmd.AddTLSARecord(testCtx, opts)
		require.Error(t, err, "AddTLSARecord should fail for invalid usage")
	})
}
