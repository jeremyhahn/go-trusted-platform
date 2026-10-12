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

// Package datastore provides integration tests for the QuicBaaS DeviceProfileDAO implementation.
// These tests verify device profile-specific operations using real QuicBaaS with embedded PebbleDB.
// Run via: make integration-test-datastore or INTEGRATION_TEST=1 go test ./test/integration/datastore/...
package datastore

import (
	"context"
	"errors"
	"testing"
	"time"

	deviceEntities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestDeviceProfile creates a device profile entity for testing.
func createTestDeviceProfile(name, model string) *deviceEntities.DeviceProfile {
	return &deviceEntities.DeviceProfile{
		Name:     name,
		Model:    model,
		TenantID: "test-tenant",
		Role:     deviceEntities.DeviceRoleServer,
		Networks: map[string]*deviceEntities.NetworkPhaseConfig{
			deviceEntities.DefaultEnrollmentNetwork: {
				VLAN:       100,
				AuthMethod: deviceEntities.AuthMethodNone,
			},
			deviceEntities.DefaultPostEnrollmentNetwork: {
				VLAN:       200,
				AuthMethod: deviceEntities.AuthMethod802_1X,
			},
		},
	}
}

// createTestDeviceProfileWithMatchRules creates a device profile with match rules for testing.
func createTestDeviceProfileWithMatchRules(name, model, macPrefix, serialPrefix string) *deviceEntities.DeviceProfile {
	profile := createTestDeviceProfile(name, model)
	profile.MatchRules = &deviceEntities.ProfileMatchRules{
		MACPrefix:    macPrefix,
		SerialPrefix: serialPrefix,
		Model:        model,
	}
	return profile
}

// TestDeviceProfileDAO_Save_NewProfile tests saving a new device profile with auto-generated ID.
func TestDeviceProfileDAO_Save_NewProfile(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()
	uniqueName := uniqueID("profile-new")
	profile := createTestDeviceProfile(uniqueName, "Model-A")

	// ID should be 0 before save
	assert.Zero(t, profile.ID)

	err := dao.Save(ctx, profile)
	require.NoError(t, err)

	// ID should be auto-generated after save
	assert.NotZero(t, profile.ID)

	// Verify profile can be retrieved
	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
	assert.Equal(t, profile.TenantID, retrieved.TenantID)
	assert.Equal(t, profile.Role, retrieved.Role)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].VLAN, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].VLAN)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultPostEnrollmentNetwork].VLAN, retrieved.Networks[deviceEntities.DefaultPostEnrollmentNetwork].VLAN)
}

// TestDeviceProfileDAO_Save_UpdateProfile tests updating an existing device profile.
func TestDeviceProfileDAO_Save_UpdateProfile(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()
	uniqueName := uniqueID("profile-update")
	profile := createTestDeviceProfile(uniqueName, "Model-B")

	require.NoError(t, dao.Save(ctx, profile))
	originalID := profile.ID

	// Update profile
	profile.Model = "Model-B-Updated"
	profile.Role = deviceEntities.DeviceRoleGateway
	profile.TenantID = "updated-tenant"
	require.NoError(t, dao.Save(ctx, profile))

	// ID should remain the same
	assert.Equal(t, originalID, profile.ID)

	// Verify update persisted
	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, "Model-B-Updated", retrieved.Model)
	assert.Equal(t, deviceEntities.DeviceRoleGateway, retrieved.Role)
	assert.Equal(t, "updated-tenant", retrieved.TenantID)
}

// TestDeviceProfileDAO_Get_Success tests successful device profile retrieval.
func TestDeviceProfileDAO_Get_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()
	uniqueName := uniqueID("profile-get")
	profile := createTestDeviceProfile(uniqueName, "Model-C")
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
}

// TestDeviceProfileDAO_Get_NotFound tests retrieval of non-existent device profile.
func TestDeviceProfileDAO_Get_NotFound(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	_, err := dao.Get(ctx, 999999999)
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceProfileDAO_Delete_Success tests successful device profile deletion.
func TestDeviceProfileDAO_Delete_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()
	uniqueName := uniqueID("profile-delete")
	profile := createTestDeviceProfile(uniqueName, "Model-D")
	require.NoError(t, dao.Save(ctx, profile))

	// Verify profile exists
	_, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)

	// Delete profile
	require.NoError(t, dao.Delete(ctx, profile))

	// Verify profile is deleted (eventually, due to async delete in QuicBaaS)
	require.Eventually(t, func() bool {
		_, err := dao.Get(ctx, profile.ID)
		return err != nil
	}, 5*time.Second, 100*time.Millisecond, "profile should be deleted")
}

// TestDeviceProfileDAO_GetByModel_Success tests retrieving device profile by model name.
func TestDeviceProfileDAO_GetByModel_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create unique model for this test
	uniqueModel := uniqueID("MODEL")
	uniqueName := uniqueID("profile-model")
	profile := createTestDeviceProfile(uniqueName, uniqueModel)
	require.NoError(t, dao.Save(ctx, profile))

	// Retrieve by model
	retrieved, err := dao.GetByModel(ctx, uniqueModel)
	require.NoError(t, err)
	assert.Equal(t, uniqueModel, retrieved.Model)
	assert.Equal(t, profile.ID, retrieved.ID)
	assert.Equal(t, profile.Name, retrieved.Name)
}

// TestDeviceProfileDAO_GetByModel_NotFound tests GetByModel with non-existent model.
func TestDeviceProfileDAO_GetByModel_NotFound(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	_, err := dao.GetByModel(ctx, "NONEXISTENT-MODEL-12345")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceProfileDAO_FindByMACPrefix_Success tests finding profile by MAC prefix.
func TestDeviceProfileDAO_FindByMACPrefix_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with MAC prefix rule
	uniqueName := uniqueID("profile-mac")
	macPrefix := "52:54:00"
	profile := createTestDeviceProfileWithMatchRules(uniqueName, "Model-MAC", macPrefix, "")
	require.NoError(t, dao.Save(ctx, profile))

	// Find by full MAC address that matches the prefix
	fullMAC := "52:54:00:12:34:56"
	retrieved, err := dao.FindByMACPrefix(ctx, fullMAC)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
	assert.Equal(t, macPrefix, retrieved.MatchRules.MACPrefix)
}

// TestDeviceProfileDAO_FindByMACPrefix_CaseInsensitive tests case-insensitive MAC prefix matching.
func TestDeviceProfileDAO_FindByMACPrefix_CaseInsensitive(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with lowercase MAC prefix
	uniqueName := uniqueID("profile-mac-case")
	macPrefix := "aa:bb:cc"
	profile := createTestDeviceProfileWithMatchRules(uniqueName, "Model-MAC-Case", macPrefix, "")
	require.NoError(t, dao.Save(ctx, profile))

	// Find by uppercase MAC address
	upperMAC := "AA:BB:CC:DD:EE:FF"
	retrieved, err := dao.FindByMACPrefix(ctx, upperMAC)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)

	// Find by mixed case MAC address
	mixedMAC := "Aa:Bb:Cc:11:22:33"
	retrieved, err = dao.FindByMACPrefix(ctx, mixedMAC)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
}

// TestDeviceProfileDAO_FindByMACPrefix_NotFound tests FindByMACPrefix with no matching profile.
func TestDeviceProfileDAO_FindByMACPrefix_NotFound(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	_, err := dao.FindByMACPrefix(ctx, "ff:ff:ff:ff:ff:ff")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceProfileDAO_FindByMACPrefix_EmptyInput tests FindByMACPrefix with empty MAC address.
func TestDeviceProfileDAO_FindByMACPrefix_EmptyInput(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	_, err := dao.FindByMACPrefix(ctx, "")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceProfileDAO_FindBySerialPrefix_Success tests finding profile by serial prefix.
func TestDeviceProfileDAO_FindBySerialPrefix_Success(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with serial prefix rule
	uniqueName := uniqueID("profile-serial")
	serialPrefix := "SN-ABC"
	profile := createTestDeviceProfileWithMatchRules(uniqueName, "Model-Serial", "", serialPrefix)
	require.NoError(t, dao.Save(ctx, profile))

	// Find by full serial that matches the prefix
	fullSerial := "SN-ABC-12345"
	retrieved, err := dao.FindBySerialPrefix(ctx, fullSerial)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
	assert.Equal(t, serialPrefix, retrieved.MatchRules.SerialPrefix)
}

// TestDeviceProfileDAO_FindBySerialPrefix_CaseInsensitive tests case-insensitive serial prefix matching.
func TestDeviceProfileDAO_FindBySerialPrefix_CaseInsensitive(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with uppercase serial prefix
	uniqueName := uniqueID("profile-serial-case")
	serialPrefix := "XYZ-PREFIX"
	profile := createTestDeviceProfileWithMatchRules(uniqueName, "Model-Serial-Case", "", serialPrefix)
	require.NoError(t, dao.Save(ctx, profile))

	// Find by lowercase serial
	lowerSerial := "xyz-prefix-001"
	retrieved, err := dao.FindBySerialPrefix(ctx, lowerSerial)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)

	// Find by mixed case serial
	mixedSerial := "XyZ-PrEfIx-002"
	retrieved, err = dao.FindBySerialPrefix(ctx, mixedSerial)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
}

// TestDeviceProfileDAO_FindBySerialPrefix_NotFound tests FindBySerialPrefix with no matching profile.
func TestDeviceProfileDAO_FindBySerialPrefix_NotFound(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	_, err := dao.FindBySerialPrefix(ctx, "NONEXISTENT-SERIAL-12345")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceProfileDAO_FindBySerialPrefix_EmptyInput tests FindBySerialPrefix with empty serial.
func TestDeviceProfileDAO_FindBySerialPrefix_EmptyInput(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	_, err := dao.FindBySerialPrefix(ctx, "")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceProfileDAO_FindMatchingProfile_ByMAC tests FindMatchingProfile matching by MAC prefix.
func TestDeviceProfileDAO_FindMatchingProfile_ByMAC(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with MAC prefix rule
	uniqueName := uniqueID("profile-match-mac")
	profile := createTestDeviceProfileWithMatchRules(uniqueName, "Model-Match-MAC", "de:ad:be", "")
	require.NoError(t, dao.Save(ctx, profile))

	// Find by MAC prefix match
	retrieved, err := dao.FindMatchingProfile(ctx, "de:ad:be:ef:00:01", "", "")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
}

// TestDeviceProfileDAO_FindMatchingProfile_BySerial tests FindMatchingProfile matching by serial prefix.
func TestDeviceProfileDAO_FindMatchingProfile_BySerial(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with serial prefix rule
	uniqueName := uniqueID("profile-match-serial")
	profile := createTestDeviceProfileWithMatchRules(uniqueName, "Model-Match-Serial", "", "TPM-SN")
	require.NoError(t, dao.Save(ctx, profile))

	// Find by serial prefix match
	retrieved, err := dao.FindMatchingProfile(ctx, "", "tpm-sn-12345", "")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
}

// TestDeviceProfileDAO_FindMatchingProfile_ByModel tests FindMatchingProfile matching by model.
func TestDeviceProfileDAO_FindMatchingProfile_ByModel(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with model match rule
	uniqueModel := uniqueID("Model-Match-Model")
	uniqueName := uniqueID("profile-match-model")
	profile := createTestDeviceProfile(uniqueName, uniqueModel)
	profile.MatchRules = &deviceEntities.ProfileMatchRules{
		Model: uniqueModel,
	}
	require.NoError(t, dao.Save(ctx, profile))

	// Find by model match
	retrieved, err := dao.FindMatchingProfile(ctx, "", "", uniqueModel)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
}

// TestDeviceProfileDAO_FindMatchingProfile_MultipleCriteria tests FindMatchingProfile with multiple criteria.
func TestDeviceProfileDAO_FindMatchingProfile_MultipleCriteria(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with multiple match rules
	uniqueModel := uniqueID("Model-Multi")
	uniqueName := uniqueID("profile-match-multi")
	profile := createTestDeviceProfileWithMatchRules(uniqueName, uniqueModel, "ca:fe:ba", "MULTI-SN")
	require.NoError(t, dao.Save(ctx, profile))

	// Match by MAC prefix
	retrieved, err := dao.FindMatchingProfile(ctx, "ca:fe:ba:be:00:01", "", "")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)

	// Match by serial prefix
	retrieved, err = dao.FindMatchingProfile(ctx, "", "multi-sn-001", "")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)

	// Match by model
	retrieved, err = dao.FindMatchingProfile(ctx, "", "", uniqueModel)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)

	// Match by all criteria
	retrieved, err = dao.FindMatchingProfile(ctx, "ca:fe:ba:be:00:02", "multi-sn-002", uniqueModel)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
}

// TestDeviceProfileDAO_FindMatchingProfile_NotFound tests FindMatchingProfile with no matching profile.
func TestDeviceProfileDAO_FindMatchingProfile_NotFound(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	_, err := dao.FindMatchingProfile(ctx, "00:00:00:00:00:00", "NOMATCH-SN-12345", "NoMatchModel")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceProfileDAO_Count tests counting device profiles.
func TestDeviceProfileDAO_Count(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Initial count
	initialCount, err := dao.Count(ctx)
	require.NoError(t, err)

	// Add profiles
	numProfiles := 5
	for i := 0; i < numProfiles; i++ {
		uniqueName := uniqueID("profile-count")
		profile := createTestDeviceProfile(uniqueName, "Model-Count")
		require.NoError(t, dao.Save(ctx, profile))
	}

	// Verify count increased
	newCount, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, initialCount+numProfiles, newCount)
}

// TestDeviceProfileDAO_Page_FirstPage tests retrieving the first page of device profiles.
func TestDeviceProfileDAO_Page_FirstPage(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Add profiles
	numProfiles := 10
	for i := 0; i < numProfiles; i++ {
		uniqueName := uniqueID("profile-page")
		profile := createTestDeviceProfile(uniqueName, "Model-Page")
		require.NoError(t, dao.Save(ctx, profile))
	}

	// Get first page
	query := datastore.PageQuery{
		Page:     1,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)

	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 3, result.PageSize)
	assert.GreaterOrEqual(t, result.Total, numProfiles)
	assert.True(t, result.HasMore)
}

// TestDeviceProfileDAO_Page_MiddlePage tests retrieving a middle page of device profiles.
func TestDeviceProfileDAO_Page_MiddlePage(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Add profiles
	numProfiles := 10
	for i := 0; i < numProfiles; i++ {
		uniqueName := uniqueID("profile-middle")
		profile := createTestDeviceProfile(uniqueName, "Model-Middle")
		require.NoError(t, dao.Save(ctx, profile))
	}

	// Get second page
	query := datastore.PageQuery{
		Page:     2,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)

	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, 2, result.Page)
	assert.True(t, result.HasMore)
}

// TestDeviceProfileDAO_Page_EmptyResult tests requesting a page beyond available data.
func TestDeviceProfileDAO_Page_EmptyResult(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Add a few profiles
	for i := 0; i < 3; i++ {
		uniqueName := uniqueID("profile-empty")
		profile := createTestDeviceProfile(uniqueName, "Model-Empty")
		require.NoError(t, dao.Save(ctx, profile))
	}

	// Request page beyond data
	query := datastore.PageQuery{
		Page:     100,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)

	assert.Empty(t, result.Entities)
	assert.False(t, result.HasMore)
}

// TestDeviceProfileDAO_ConcurrentOperations tests concurrent device profile operations.
func TestDeviceProfileDAO_ConcurrentOperations(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Concurrent writes
	numGoroutines := 10
	done := make(chan bool, numGoroutines)
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			uniqueName := uniqueID("profile-concurrent")
			profile := createTestDeviceProfile(uniqueName, "Model-Concurrent")
			if err := dao.Save(ctx, profile); err != nil {
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

	// Verify all profiles were created
	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, numGoroutines)
}

// TestDeviceProfileDAO_ConcurrentReadsAndWrites tests concurrent read and write operations.
func TestDeviceProfileDAO_ConcurrentReadsAndWrites(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create initial profiles
	numInitial := 5
	var profileIDs []uint64
	for i := 0; i < numInitial; i++ {
		uniqueName := uniqueID("profile-rw-init")
		profile := createTestDeviceProfile(uniqueName, "Model-RW")
		require.NoError(t, dao.Save(ctx, profile))
		profileIDs = append(profileIDs, profile.ID)
	}

	// Concurrent reads and writes
	numGoroutines := 10
	done := make(chan bool, numGoroutines)
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			if idx%2 == 0 {
				// Read operation
				id := profileIDs[idx%len(profileIDs)]
				if _, err := dao.Get(ctx, id); err != nil {
					errChan <- err
				}
			} else {
				// Write operation
				uniqueName := uniqueID("profile-rw-write")
				profile := createTestDeviceProfile(uniqueName, "Model-RW-Write")
				if err := dao.Save(ctx, profile); err != nil {
					errChan <- err
				}
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
		t.Fatalf("concurrent read/write operation failed: %v", err)
	default:
	}
}

// TestDeviceProfileDAO_DataPersistenceAcrossDAOInstances tests data persists across DAO instances.
func TestDeviceProfileDAO_DataPersistenceAcrossDAOInstances(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao1 := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with first DAO
	uniqueName := uniqueID("profile-persistence")
	uniqueModel := uniqueID("Model-Persistence")
	profile := createTestDeviceProfileWithMatchRules(uniqueName, uniqueModel, "pe:rs:is", "PERSIST")
	require.NoError(t, dao1.Save(ctx, profile))

	// Create new DAO instance
	dao2 := quicbaas.NewDeviceProfileDAO(client, logger)

	// Retrieve with second DAO by ID
	retrieved, err := dao2.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
	assert.Equal(t, profile.MatchRules.MACPrefix, retrieved.MatchRules.MACPrefix)
	assert.Equal(t, profile.MatchRules.SerialPrefix, retrieved.MatchRules.SerialPrefix)

	// GetByModel with second DAO
	retrievedByModel, err := dao2.GetByModel(ctx, uniqueModel)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrievedByModel.ID)

	// FindByMACPrefix with second DAO
	retrievedByMAC, err := dao2.FindByMACPrefix(ctx, "pe:rs:is:te:nc:e0")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrievedByMAC.ID)

	// FindBySerialPrefix with second DAO
	retrievedBySerial, err := dao2.FindBySerialPrefix(ctx, "persist-001")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrievedBySerial.ID)
}

// TestDeviceProfileDAO_FullProfilePersistence tests that all profile fields persist correctly.
func TestDeviceProfileDAO_FullProfilePersistence(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile with all fields populated
	profile := &deviceEntities.DeviceProfile{
		Name:     uniqueID("full-profile"),
		Model:    uniqueID("Model-Full"),
		TenantID: "tenant-full",
		Role:     deviceEntities.DeviceRoleEdge,
		EventLog: []byte{0x01, 0x02, 0x03, 0x04},
		Networks: map[string]*deviceEntities.NetworkPhaseConfig{
			deviceEntities.DefaultEnrollmentNetwork: {
				VLAN:       100,
				AuthMethod: deviceEntities.AuthMethodNone,
				Gateway:    "192.168.1.1",
				DNS:        []string{"8.8.8.8", "8.8.4.4"},
				DHCPPool: &deviceEntities.DHCPPoolConfig{
					Network:    "192.168.1.0/24",
					RangeStart: "192.168.1.100",
					RangeEnd:   "192.168.1.200",
					LeaseTime:  3600,
				},
				ACLs: []deviceEntities.ACLConfig{
					{
						Priority: 10,
						Protocol: "tcp",
						SrcIP:    "any",
						DstIP:    "192.168.1.0/24",
						DstPort:  443,
						Action:   "allow",
					},
				},
			},
			deviceEntities.DefaultPostEnrollmentNetwork: {
				VLAN:       200,
				AuthMethod: deviceEntities.AuthMethod802_1X,
				Gateway:    "10.0.0.1",
				DNS:        []string{"10.0.0.53"},
			},
			deviceEntities.DefaultFailureNetwork: {
				VLAN:       999,
				AuthMethod: deviceEntities.AuthMethodNone,
			},
		},
		PlatformdConfig: &deviceEntities.PlatformdConfigRef{
			ConfigType: "reference",
			Reference:  "/etc/platformd/config.yaml",
			Version:    "1.0.0",
		},
		MatchRules: &deviceEntities.ProfileMatchRules{
			MACPrefix:    "fu:ll:pr",
			SerialPrefix: "FULL-SN",
			Model:        "Model-Full",
		},
	}

	require.NoError(t, dao.Save(ctx, profile))

	// Retrieve and verify all fields
	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)

	// Basic fields
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
	assert.Equal(t, profile.TenantID, retrieved.TenantID)
	assert.Equal(t, profile.Role, retrieved.Role)
	assert.Equal(t, profile.EventLog, retrieved.EventLog)

	// Provisioning network
	require.NotNil(t, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork])
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].VLAN, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].VLAN)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].AuthMethod, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].AuthMethod)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].Gateway, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].Gateway)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].DNS, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].DNS)

	// DHCP pool
	require.NotNil(t, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.Network, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.Network)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.RangeStart, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.RangeStart)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.RangeEnd, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.RangeEnd)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.LeaseTime, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].DHCPPool.LeaseTime)

	// ACLs
	require.Len(t, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].ACLs, 1)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].ACLs[0].Priority, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].ACLs[0].Priority)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].ACLs[0].Protocol, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].ACLs[0].Protocol)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultEnrollmentNetwork].ACLs[0].Action, retrieved.Networks[deviceEntities.DefaultEnrollmentNetwork].ACLs[0].Action)

	// Production network
	require.NotNil(t, retrieved.Networks[deviceEntities.DefaultPostEnrollmentNetwork])
	assert.Equal(t, profile.Networks[deviceEntities.DefaultPostEnrollmentNetwork].VLAN, retrieved.Networks[deviceEntities.DefaultPostEnrollmentNetwork].VLAN)
	assert.Equal(t, profile.Networks[deviceEntities.DefaultPostEnrollmentNetwork].AuthMethod, retrieved.Networks[deviceEntities.DefaultPostEnrollmentNetwork].AuthMethod)

	// Quarantine network
	require.NotNil(t, retrieved.Networks[deviceEntities.DefaultFailureNetwork])
	assert.Equal(t, profile.Networks[deviceEntities.DefaultFailureNetwork].VLAN, retrieved.Networks[deviceEntities.DefaultFailureNetwork].VLAN)

	// Platformd config
	require.NotNil(t, retrieved.PlatformdConfig)
	assert.Equal(t, profile.PlatformdConfig.ConfigType, retrieved.PlatformdConfig.ConfigType)
	assert.Equal(t, profile.PlatformdConfig.Reference, retrieved.PlatformdConfig.Reference)
	assert.Equal(t, profile.PlatformdConfig.Version, retrieved.PlatformdConfig.Version)

	// Match rules
	require.NotNil(t, retrieved.MatchRules)
	assert.Equal(t, profile.MatchRules.MACPrefix, retrieved.MatchRules.MACPrefix)
	assert.Equal(t, profile.MatchRules.SerialPrefix, retrieved.MatchRules.SerialPrefix)
	assert.Equal(t, profile.MatchRules.Model, retrieved.MatchRules.Model)
}

// TestDeviceProfileDAO_GetByModel_FallbackScan tests that GetByModel falls back to scan.
func TestDeviceProfileDAO_GetByModel_FallbackScan(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create multiple profiles with different models
	uniqueModel1 := uniqueID("MODEL-SCAN-1")
	uniqueModel2 := uniqueID("MODEL-SCAN-2")
	uniqueModel3 := uniqueID("MODEL-SCAN-3")

	profile1 := createTestDeviceProfile("profile-scan1", uniqueModel1)
	profile2 := createTestDeviceProfile("profile-scan2", uniqueModel2)
	profile3 := createTestDeviceProfile("profile-scan3", uniqueModel3)

	require.NoError(t, dao.Save(ctx, profile1))
	require.NoError(t, dao.Save(ctx, profile2))
	require.NoError(t, dao.Save(ctx, profile3))

	// Since QuicBaaS may not have secondary indexes configured,
	// GetByModel should fall back to scanning and still find the profile
	retrieved, err := dao.GetByModel(ctx, uniqueModel2)
	require.NoError(t, err)
	assert.Equal(t, uniqueModel2, retrieved.Model)
	assert.Equal(t, profile2.ID, retrieved.ID)
}

// TestDeviceProfileDAO_UpdateMatchRules tests updating match rules on an existing profile.
func TestDeviceProfileDAO_UpdateMatchRules(t *testing.T) {
	skipIfNotIntegration(t)

	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceProfileDAO(client, logger)

	ctx := context.Background()

	// Create profile without match rules
	uniqueName := uniqueID("profile-updaterules")
	profile := createTestDeviceProfile(uniqueName, "Model-UpdateRules")
	require.NoError(t, dao.Save(ctx, profile))
	require.Nil(t, profile.MatchRules)

	// Update with match rules
	profile.MatchRules = &deviceEntities.ProfileMatchRules{
		MACPrefix:    "up:da:te",
		SerialPrefix: "UPDATE-SN",
		Model:        "Model-UpdateRules",
	}
	require.NoError(t, dao.Save(ctx, profile))

	// Verify match rules were added
	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved.MatchRules)
	assert.Equal(t, "up:da:te", retrieved.MatchRules.MACPrefix)
	assert.Equal(t, "UPDATE-SN", retrieved.MatchRules.SerialPrefix)

	// Update match rules to different values
	profile.MatchRules.MACPrefix = "ne:w0:ma"
	profile.MatchRules.SerialPrefix = "NEW-SN"
	require.NoError(t, dao.Save(ctx, profile))

	// Verify match rules were updated
	retrieved, err = dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, "ne:w0:ma", retrieved.MatchRules.MACPrefix)
	assert.Equal(t, "NEW-SN", retrieved.MatchRules.SerialPrefix)

	// Verify we can find by new match rules
	foundByMAC, err := dao.FindByMACPrefix(ctx, "ne:w0:ma:c0:ff:ee")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, foundByMAC.ID)
}
