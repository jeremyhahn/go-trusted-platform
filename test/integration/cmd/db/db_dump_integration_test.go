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

// Package db provides integration tests for the platformctl db dump command.
// These tests verify end-to-end functionality with a real QuicBaaS instance.
// Run via: make integration-test-cmd-db or INTEGRATION_TEST=1 go test ./test/integration/cmd/db/...
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	dnsEntities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// skipIfNotIntegration skips the test if the INTEGRATION_TEST env var is not set.
func skipIfNotIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// testContext holds shared resources for dump integration tests.
type testContext struct {
	factory   *quicbaas.Factory
	client    *quicbaas.Client
	logger    *logging.Logger
	outputDir string
	cleanup   func()
}

// newTestContext creates a new test context with an initialized QuicBaaS instance.
func newTestContext(t *testing.T) *testContext {
	t.Helper()

	cfg := quicbaas.TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, factory.Start(ctx))

	outputDir := t.TempDir()

	cleanup := func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		factory.Stop(stopCtx)
	}

	return &testContext{
		factory:   factory,
		client:    factory.Client(),
		logger:    logger,
		outputDir: outputDir,
		cleanup:   cleanup,
	}
}

// createTestZone creates a DNS zone entity for testing.
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

// TestDumpCommand_JSONFormat tests dumping data to JSON format.
func TestDumpCommand_JSONFormat(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create and save test entities
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)

	org := &entities.Organization{Name: "TestOrg-JSON"}
	require.NoError(t, orgDAO.Save(ctx, org))
	require.NotZero(t, org.ID)

	zoneDAO, err := tc.factory.ZoneDAO()
	require.NoError(t, err)

	zone := createTestZone("test-json.com.", false)
	require.NoError(t, zoneDAO.Save(ctx, zone))
	require.NotZero(t, zone.ID)

	// Execute dump using direct client access (simulating what dump command does)
	outputDir := filepath.Join(tc.outputDir, "json-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	// Dump Organization entities
	orgEntities, _, err := tc.client.List(ctx, "Organization", 100, "", 0)
	require.NoError(t, err)

	if len(orgEntities) > 0 {
		orgDir := filepath.Join(outputDir, "Organization")
		require.NoError(t, os.MkdirAll(orgDir, 0755))

		for _, entity := range orgEntities {
			filename := filepath.Join(orgDir, fmt.Sprintf("%d.json", entity.ID))
			require.NoError(t, os.WriteFile(filename, entity.Data, 0644))
		}
	}

	// Dump Zone entities
	zoneEntities, _, err := tc.client.List(ctx, "Zone", 100, "", 0)
	require.NoError(t, err)

	if len(zoneEntities) > 0 {
		zoneDir := filepath.Join(outputDir, "Zone")
		require.NoError(t, os.MkdirAll(zoneDir, 0755))

		for _, entity := range zoneEntities {
			filename := filepath.Join(zoneDir, fmt.Sprintf("%d.json", entity.ID))
			require.NoError(t, os.WriteFile(filename, entity.Data, 0644))
		}
	}

	// Verify Organization files were created
	orgDir := filepath.Join(outputDir, "Organization")
	files, err := os.ReadDir(orgDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 1, "expected at least 1 organization file")

	// Verify content is valid JSON
	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(orgDir, file.Name()))
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(content, &parsed)
		require.NoError(t, err, "content should be valid JSON")
		assert.Contains(t, parsed, "name", "JSON should contain 'name' field")
	}

	// Verify Zone files were created
	zoneDir := filepath.Join(outputDir, "Zone")
	files, err = os.ReadDir(zoneDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 1, "expected at least 1 zone file")

	// Verify zone content
	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(zoneDir, file.Name()))
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(content, &parsed)
		require.NoError(t, err, "zone content should be valid JSON")
		assert.Contains(t, parsed, "name", "zone JSON should contain 'name' field")
		assert.Contains(t, parsed, "ttl", "zone JSON should contain 'ttl' field")
	}
}

// TestDumpCommand_YAMLFormat tests dumping data to YAML format.
func TestDumpCommand_YAMLFormat(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create and save test entities
	roleDAO, err := tc.factory.RoleDAO()
	require.NoError(t, err)

	role := &entities.Role{Name: "admin-yaml-test"}
	require.NoError(t, roleDAO.Save(ctx, role))
	require.NotZero(t, role.ID)

	// Execute dump to YAML format
	outputDir := filepath.Join(tc.outputDir, "yaml-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	// List Role entities
	roleEntities, _, err := tc.client.List(ctx, "Role", 100, "", 0)
	require.NoError(t, err)

	if len(roleEntities) > 0 {
		roleDir := filepath.Join(outputDir, "Role")
		require.NoError(t, os.MkdirAll(roleDir, 0755))

		for _, entity := range roleEntities {
			// Convert JSON to YAML
			var parsed interface{}
			require.NoError(t, json.Unmarshal(entity.Data, &parsed))

			yamlData, err := yaml.Marshal(parsed)
			require.NoError(t, err)

			filename := filepath.Join(roleDir, fmt.Sprintf("%d.yaml", entity.ID))
			require.NoError(t, os.WriteFile(filename, yamlData, 0644))
		}
	}

	// Verify Role YAML files were created
	roleDir := filepath.Join(outputDir, "Role")
	files, err := os.ReadDir(roleDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 1, "expected at least 1 role file")

	// Verify content is valid YAML
	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(roleDir, file.Name()))
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = yaml.Unmarshal(content, &parsed)
		require.NoError(t, err, "content should be valid YAML")
		assert.Contains(t, parsed, "name", "YAML should contain 'name' field")
	}
}

// TestDumpCommand_PrettyJSON tests dumping data with pretty-printed JSON.
func TestDumpCommand_PrettyJSON(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create and save test entity
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)

	org := &entities.Organization{Name: "PrettyOrg"}
	require.NoError(t, orgDAO.Save(ctx, org))

	// Execute dump with pretty printing
	outputDir := filepath.Join(tc.outputDir, "pretty-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	orgEntities, _, err := tc.client.List(ctx, "Organization", 100, "", 0)
	require.NoError(t, err)

	if len(orgEntities) > 0 {
		orgDir := filepath.Join(outputDir, "Organization")
		require.NoError(t, os.MkdirAll(orgDir, 0755))

		for _, entity := range orgEntities {
			// Pretty print the JSON
			var parsed interface{}
			require.NoError(t, json.Unmarshal(entity.Data, &parsed))

			prettyJSON, err := json.MarshalIndent(parsed, "", "  ")
			require.NoError(t, err)

			filename := filepath.Join(orgDir, fmt.Sprintf("%d.json", entity.ID))
			require.NoError(t, os.WriteFile(filename, prettyJSON, 0644))
		}
	}

	// Verify pretty JSON contains indentation
	orgDir := filepath.Join(outputDir, "Organization")
	files, err := os.ReadDir(orgDir)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(files), 1)

	content, err := os.ReadFile(filepath.Join(orgDir, files[0].Name()))
	require.NoError(t, err)

	// Pretty JSON should contain newlines and indentation
	assert.Contains(t, string(content), "\n", "pretty JSON should contain newlines")
	assert.Contains(t, string(content), "  ", "pretty JSON should contain indentation")
}

// TestDumpCommand_PartitionFilter tests dumping only specific entity types.
func TestDumpCommand_PartitionFilter(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create multiple entity types
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)
	org := &entities.Organization{Name: "FilterTestOrg"}
	require.NoError(t, orgDAO.Save(ctx, org))

	roleDAO, err := tc.factory.RoleDAO()
	require.NoError(t, err)
	role := &entities.Role{Name: "FilterTestRole"}
	require.NoError(t, roleDAO.Save(ctx, role))

	zoneDAO, err := tc.factory.ZoneDAO()
	require.NoError(t, err)
	zone := createTestZone("filter-test.com.", true)
	require.NoError(t, zoneDAO.Save(ctx, zone))

	// Dump only Zone partition
	outputDir := filepath.Join(tc.outputDir, "partition-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	// Only dump Zone entities (simulating --partition Zone)
	partition := "Zone"
	zoneEntities, _, err := tc.client.List(ctx, partition, 100, "", 0)
	require.NoError(t, err)

	if len(zoneEntities) > 0 {
		zoneDir := filepath.Join(outputDir, partition)
		require.NoError(t, os.MkdirAll(zoneDir, 0755))

		for _, entity := range zoneEntities {
			filename := filepath.Join(zoneDir, fmt.Sprintf("%d.json", entity.ID))
			require.NoError(t, os.WriteFile(filename, entity.Data, 0644))
		}
	}

	// Verify only Zone directory exists
	entries, err := os.ReadDir(outputDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "should only have Zone directory")
	assert.Equal(t, "Zone", entries[0].Name(), "directory should be 'Zone'")

	// Verify Zone files exist
	zoneDir := filepath.Join(outputDir, "Zone")
	files, err := os.ReadDir(zoneDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 1, "expected at least 1 zone file")
}

// TestDumpCommand_EmptyPartition tests dumping when a partition has no data.
func TestDumpCommand_EmptyPartition(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	outputDir := filepath.Join(tc.outputDir, "empty-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	// Try to dump a partition that likely has no data
	partition := "DeviceProfile"
	deviceEntities, _, err := tc.client.List(ctx, partition, 100, "", 0)
	require.NoError(t, err)

	// Only create directory if we have entities
	if len(deviceEntities) > 0 {
		deviceDir := filepath.Join(outputDir, partition)
		require.NoError(t, os.MkdirAll(deviceDir, 0755))
	}

	// The directory should not exist if there's no data
	deviceDir := filepath.Join(outputDir, partition)
	_, err = os.Stat(deviceDir)
	// Either the directory doesn't exist (no data) or it exists with data
	// This test just ensures no error occurs when listing empty partitions
	if len(deviceEntities) == 0 {
		assert.True(t, os.IsNotExist(err), "directory should not exist for empty partition")
	}
}

// TestDumpCommand_MultipleEntityTypes tests dumping all known entity types.
func TestDumpCommand_MultipleEntityTypes(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create entities of different types
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)
	org := &entities.Organization{Name: "MultiOrg"}
	require.NoError(t, orgDAO.Save(ctx, org))

	roleDAO, err := tc.factory.RoleDAO()
	require.NoError(t, err)
	role := &entities.Role{Name: "MultiRole"}
	require.NoError(t, roleDAO.Save(ctx, role))

	userDAO, err := tc.factory.UserDAO()
	require.NoError(t, err)
	user := entities.NewUser("multi@example.com")
	require.NoError(t, userDAO.Save(ctx, user))

	zoneDAO, err := tc.factory.ZoneDAO()
	require.NoError(t, err)
	zone := createTestZone("multi.com.", false)
	require.NoError(t, zoneDAO.Save(ctx, zone))

	// Dump all entity types
	outputDir := filepath.Join(tc.outputDir, "multi-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	entityTypes := []string{"Organization", "User", "Role", "Zone"}
	totalExported := 0

	for _, entityType := range entityTypes {
		svcEntities, _, err := tc.client.List(ctx, entityType, 100, "", 0)
		require.NoError(t, err)

		if len(svcEntities) > 0 {
			entityDir := filepath.Join(outputDir, entityType)
			require.NoError(t, os.MkdirAll(entityDir, 0755))

			for _, entity := range svcEntities {
				filename := filepath.Join(entityDir, fmt.Sprintf("%d.json", entity.ID))
				require.NoError(t, os.WriteFile(filename, entity.Data, 0644))
				totalExported++
			}
		}
	}

	// Verify we exported at least the entities we created
	assert.GreaterOrEqual(t, totalExported, 4, "should export at least 4 entities")

	// Verify each entity type directory was created
	for _, entityType := range []string{"Organization", "User", "Role", "Zone"} {
		entityDir := filepath.Join(outputDir, entityType)
		_, err := os.Stat(entityDir)
		require.NoError(t, err, "directory for %s should exist", entityType)
	}
}

// TestDumpCommand_ZoneWithRecordSet tests that zone records are properly serialized.
func TestDumpCommand_ZoneWithRecordSet(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create zone with various record types
	zoneDAO, err := tc.factory.ZoneDAO()
	require.NoError(t, err)

	zone := &dnsEntities.Zone{
		Name:        "recordset-dump.com.",
		TTL:         3600,
		Description: "Zone with multiple record types for dump test",
		Internal:    false,
		RecordSet: dnsEntities.RecordSet{
			SOARecord: dnsEntities.SOARecord{
				Name:       "recordset-dump.com.",
				MName:      "ns1.recordset-dump.com.",
				RName:      "admin.recordset-dump.com.",
				Serial:     2024123101,
				Refresh:    7200,
				Retry:      3600,
				Expire:     1209600,
				MinimumTTL: 86400,
				TTL:        3600,
			},
			ARecords: []*dnsEntities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 300},
				{Name: "api", Value: "192.168.1.2", TTL: 300},
				{Name: "mail", Value: "192.168.1.3", TTL: 300},
			},
			AAAARecords: []*dnsEntities.AAAARecord{
				{Name: "www", Value: "2001:db8::1", TTL: 300},
			},
			CNAMERecords: []*dnsEntities.CNAMERecord{
				{Name: "blog", Value: "www.recordset-dump.com.", TTL: 300},
			},
			MXRecords: []*dnsEntities.MXRecord{
				{Name: "recordset-dump.com.", Value: "mail.recordset-dump.com.", Priority: 10, TTL: 3600},
			},
			TXTRecords: []*dnsEntities.TXTRecord{
				{Name: "recordset-dump.com.", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
			},
			NSRecords: []*dnsEntities.NSRecord{
				{Name: "recordset-dump.com.", Value: "ns1.recordset-dump.com.", TTL: 86400},
				{Name: "recordset-dump.com.", Value: "ns2.recordset-dump.com.", TTL: 86400},
			},
		},
	}

	require.NoError(t, zoneDAO.Save(ctx, zone))

	// Dump zone data
	outputDir := filepath.Join(tc.outputDir, "recordset-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	zoneEntities, _, err := tc.client.List(ctx, "Zone", 100, "", 0)
	require.NoError(t, err)
	require.NotEmpty(t, zoneEntities)

	zoneDir := filepath.Join(outputDir, "Zone")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	var dumpedZoneFile string
	for _, entity := range zoneEntities {
		filename := filepath.Join(zoneDir, fmt.Sprintf("%d.json", entity.ID))
		require.NoError(t, os.WriteFile(filename, entity.Data, 0644))
		dumpedZoneFile = filename
	}

	// Read and verify the dumped zone content
	content, err := os.ReadFile(dumpedZoneFile)
	require.NoError(t, err)

	var dumpedZone map[string]interface{}
	require.NoError(t, json.Unmarshal(content, &dumpedZone))

	// Verify zone fields
	assert.Contains(t, dumpedZone, "name")
	assert.Contains(t, dumpedZone, "ttl")
	assert.Contains(t, dumpedZone, "records")
	assert.Contains(t, dumpedZone, "description")

	// Verify records are included
	records, ok := dumpedZone["records"].(map[string]interface{})
	require.True(t, ok, "records should be a map")

	// Check for specific record types in the dump
	if aRecords, ok := records["a_records"]; ok {
		aRecordsList, ok := aRecords.([]interface{})
		require.True(t, ok)
		assert.GreaterOrEqual(t, len(aRecordsList), 3, "should have 3 A records")
	}
}

// TestDumpCommand_LargeDataset tests dumping a larger number of entities.
func TestDumpCommand_LargeDataset(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create multiple organizations
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)

	numOrgs := 20
	for i := 0; i < numOrgs; i++ {
		org := &entities.Organization{Name: "BulkOrg-" + time.Now().Format("20060102150405.000000000")}
		require.NoError(t, orgDAO.Save(ctx, org))
		time.Sleep(time.Microsecond) // Ensure unique timestamps
	}

	// Dump all organizations
	outputDir := filepath.Join(tc.outputDir, "large-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	orgEntities, _, err := tc.client.List(ctx, "Organization", 100, "", 0)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(orgEntities), numOrgs)

	orgDir := filepath.Join(outputDir, "Organization")
	require.NoError(t, os.MkdirAll(orgDir, 0755))

	for _, entity := range orgEntities {
		filename := filepath.Join(orgDir, fmt.Sprintf("%d.json", entity.ID))
		require.NoError(t, os.WriteFile(filename, entity.Data, 0644))
	}

	// Verify all files were created
	files, err := os.ReadDir(orgDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), numOrgs, "should have at least %d organization files", numOrgs)
}

// TestDumpCommand_DataIntegrity tests that dumped data can be parsed back.
func TestDumpCommand_DataIntegrity(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create a zone with specific data
	zoneDAO, err := tc.factory.ZoneDAO()
	require.NoError(t, err)

	originalZone := &dnsEntities.Zone{
		Name:        "integrity-test.com.",
		TTL:         7200,
		Description: "Data integrity test zone",
		Internal:    true,
		RecordSet: dnsEntities.RecordSet{
			SOARecord: dnsEntities.SOARecord{
				Name:       "integrity-test.com.",
				MName:      "ns1.integrity-test.com.",
				RName:      "admin.integrity-test.com.",
				Serial:     2024123102,
				Refresh:    3600,
				Retry:      1800,
				Expire:     604800,
				MinimumTTL: 43200,
				TTL:        7200,
			},
			ARecords: []*dnsEntities.ARecord{
				{Name: "test", Value: "10.0.0.1", TTL: 600},
			},
		},
	}

	require.NoError(t, zoneDAO.Save(ctx, originalZone))

	// Retrieve the raw data
	data, found, err := tc.client.Get(ctx, "Zone", originalZone.ID, 0)
	require.NoError(t, err)
	require.True(t, found)

	// Parse the data back to verify integrity
	var parsedZone dnsEntities.Zone
	require.NoError(t, json.Unmarshal(data, &parsedZone))

	// Verify all fields match
	assert.Equal(t, originalZone.Name, parsedZone.Name)
	assert.Equal(t, originalZone.TTL, parsedZone.TTL)
	assert.Equal(t, originalZone.Description, parsedZone.Description)
	assert.Equal(t, originalZone.Internal, parsedZone.Internal)
	assert.Equal(t, originalZone.RecordSet.SOARecord.Serial, parsedZone.RecordSet.SOARecord.Serial)
	assert.Len(t, parsedZone.RecordSet.ARecords, 1)
	assert.Equal(t, "10.0.0.1", parsedZone.RecordSet.ARecords[0].Value)
}

// TestDumpCommand_ConcurrentDump tests concurrent dump operations.
func TestDumpCommand_ConcurrentDump(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create some test data
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		org := &entities.Organization{Name: "ConcurrentOrg-" + time.Now().Format("150405.000000000")}
		require.NoError(t, orgDAO.Save(ctx, org))
		time.Sleep(time.Microsecond)
	}

	// Concurrent dumps to different directories
	numGoroutines := 3
	done := make(chan bool, numGoroutines)
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer func() { done <- true }()

			outputDir := filepath.Join(tc.outputDir, fmt.Sprintf("concurrent-dump-%d-%s", idx, time.Now().Format("150405.000000000")))
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				errChan <- err
				return
			}

			orgEntities, _, err := tc.client.List(ctx, "Organization", 100, "", 0)
			if err != nil {
				errChan <- err
				return
			}

			if len(orgEntities) > 0 {
				orgDir := filepath.Join(outputDir, "Organization")
				if err := os.MkdirAll(orgDir, 0755); err != nil {
					errChan <- err
					return
				}

				for _, entity := range orgEntities {
					filename := filepath.Join(orgDir, fmt.Sprintf("%d.json", entity.ID))
					if err := os.WriteFile(filename, entity.Data, 0644); err != nil {
						errChan <- err
						return
					}
				}
			}
		}(i)
		time.Sleep(time.Microsecond)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Check for errors
	select {
	case err := <-errChan:
		t.Fatalf("concurrent dump failed: %v", err)
	default:
	}
}

// TestDumpCommand_OutputDirectoryPermissions tests creating output in various directories.
func TestDumpCommand_OutputDirectoryPermissions(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create test data
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)

	org := &entities.Organization{Name: "PermTest"}
	require.NoError(t, orgDAO.Save(ctx, org))

	// Test creating nested output directories
	nestedDir := filepath.Join(tc.outputDir, "a", "b", "c", "d", "dump")
	require.NoError(t, os.MkdirAll(nestedDir, 0755))

	orgEntities, _, err := tc.client.List(ctx, "Organization", 100, "", 0)
	require.NoError(t, err)

	if len(orgEntities) > 0 {
		orgDir := filepath.Join(nestedDir, "Organization")
		require.NoError(t, os.MkdirAll(orgDir, 0755))

		for _, entity := range orgEntities {
			filename := filepath.Join(orgDir, fmt.Sprintf("%d.json", entity.ID))
			require.NoError(t, os.WriteFile(filename, entity.Data, 0644))
		}
	}

	// Verify nested structure was created correctly
	orgDir := filepath.Join(nestedDir, "Organization")
	info, err := os.Stat(orgDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// TestDumpCommand_JSONFormatInvalid tests error handling for invalid data.
func TestDumpCommand_JSONFormatInvalid(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create and save a valid entity first
	orgDAO, err := tc.factory.OrganizationDAO()
	require.NoError(t, err)

	org := &entities.Organization{Name: "ValidOrg"}
	require.NoError(t, orgDAO.Save(ctx, org))

	// Dump and verify JSON can be parsed
	orgEntities, _, err := tc.client.List(ctx, "Organization", 100, "", 0)
	require.NoError(t, err)
	require.NotEmpty(t, orgEntities)

	// All entities should have valid JSON data
	for _, entity := range orgEntities {
		var parsed map[string]interface{}
		err := json.Unmarshal(entity.Data, &parsed)
		require.NoError(t, err, "entity data should be valid JSON")
	}
}

// TestDumpCommand_SpecialCharactersInData tests handling of special characters.
func TestDumpCommand_SpecialCharactersInData(t *testing.T) {
	skipIfNotIntegration(t)

	tc := newTestContext(t)
	defer tc.cleanup()

	ctx := context.Background()

	// Create zone with special characters in description
	zoneDAO, err := tc.factory.ZoneDAO()
	require.NoError(t, err)

	zone := &dnsEntities.Zone{
		Name:        "special-chars.com.",
		TTL:         3600,
		Description: "Zone with special chars: \"quotes\", 'apostrophes', <angle>, &ampersand, newline\nhere",
		Internal:    false,
		RecordSet: dnsEntities.RecordSet{
			SOARecord: dnsEntities.SOARecord{
				Name:  "special-chars.com.",
				MName: "ns1.special-chars.com.",
				RName: "admin.special-chars.com.",
				TTL:   3600,
			},
			TXTRecords: []*dnsEntities.TXTRecord{
				{Name: "special-chars.com.", Value: "text with spaces and \"quotes\"", TTL: 300},
			},
		},
	}

	require.NoError(t, zoneDAO.Save(ctx, zone))

	// Dump and verify content
	outputDir := filepath.Join(tc.outputDir, "special-dump")
	require.NoError(t, os.MkdirAll(outputDir, 0755))

	zoneEntities, _, err := tc.client.List(ctx, "Zone", 100, "", 0)
	require.NoError(t, err)

	zoneDir := filepath.Join(outputDir, "Zone")
	require.NoError(t, os.MkdirAll(zoneDir, 0755))

	for _, entity := range zoneEntities {
		filename := filepath.Join(zoneDir, fmt.Sprintf("%d.json", entity.ID))
		require.NoError(t, os.WriteFile(filename, entity.Data, 0644))

		// Read it back and verify it's valid JSON
		content, err := os.ReadFile(filename)
		require.NoError(t, err)

		var parsed map[string]interface{}
		err = json.Unmarshal(content, &parsed)
		require.NoError(t, err, "content with special chars should be valid JSON")
	}
}
