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

// Package datastore provides integration tests for the QuicBaaS DeviceDAO implementation.
// These tests verify device-specific operations using real QuicBaaS with embedded PebbleDB.
// Run via: make integration-test-datastore
package datastore

import (
	"context"
	"errors"
	"testing"
	"time"

	deviceEntities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestDevice creates a device entity for testing.
func createTestDevice(serial, model string) *deviceEntities.Device {
	return &deviceEntities.Device{
		Serial:     serial,
		Model:      model,
		AttestPub:  "test-attest-pub-key",
		EKCert:     "test-ek-cert",
		SigningPub: "test-signing-pub",
		HashAlgoId: 11, // SHA256
	}
}

// TestDeviceDAO_Save_NewDevice tests saving a new device with auto-generated ID.
func TestDeviceDAO_Save_NewDevice(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()
	device := createTestDevice("SN-001", "Model-A")

	// ID should be 0 before save
	assert.Zero(t, device.ID)

	err := dao.Save(ctx, device)
	require.NoError(t, err)

	// ID should be auto-generated after save
	assert.NotZero(t, device.ID)

	// Verify device can be retrieved
	retrieved, err := dao.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.Serial, retrieved.Serial)
	assert.Equal(t, device.Model, retrieved.Model)
	assert.Equal(t, device.AttestPub, retrieved.AttestPub)
	assert.Equal(t, device.EKCert, retrieved.EKCert)
	assert.Equal(t, device.SigningPub, retrieved.SigningPub)
	assert.Equal(t, device.HashAlgoId, retrieved.HashAlgoId)
}

// TestDeviceDAO_Save_UpdateDevice tests updating an existing device.
func TestDeviceDAO_Save_UpdateDevice(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()
	device := createTestDevice("SN-002", "Model-B")

	require.NoError(t, dao.Save(ctx, device))
	originalID := device.ID

	// Update device
	device.Model = "Model-B-Updated"
	device.SigningPub = "updated-signing-pub"
	require.NoError(t, dao.Save(ctx, device))

	// ID should remain the same
	assert.Equal(t, originalID, device.ID)

	// Verify update persisted
	retrieved, err := dao.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, "Model-B-Updated", retrieved.Model)
	assert.Equal(t, "updated-signing-pub", retrieved.SigningPub)
}

// TestDeviceDAO_Get_Success tests successful device retrieval.
func TestDeviceDAO_Get_Success(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()
	device := createTestDevice("SN-003", "Model-C")
	require.NoError(t, dao.Save(ctx, device))

	retrieved, err := dao.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrieved.ID)
	assert.Equal(t, device.Serial, retrieved.Serial)
	assert.Equal(t, device.Model, retrieved.Model)
}

// TestDeviceDAO_Get_NotFound tests retrieval of non-existent device.
func TestDeviceDAO_Get_NotFound(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	_, err := dao.Get(ctx, 999999999)
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceDAO_Delete_Success tests successful device deletion.
func TestDeviceDAO_Delete_Success(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()
	device := createTestDevice("SN-004", "Model-D")
	require.NoError(t, dao.Save(ctx, device))

	// Verify device exists
	_, err := dao.Get(ctx, device.ID)
	require.NoError(t, err)

	// Delete device
	require.NoError(t, dao.Delete(ctx, device))

	// Verify device is deleted (eventually, due to async delete in QuicBaaS)
	require.Eventually(t, func() bool {
		_, err := dao.Get(ctx, device.ID)
		return err != nil
	}, 5*time.Second, 100*time.Millisecond, "device should be deleted")
}

// TestDeviceDAO_FindBySerial_Success tests retrieving device by serial number.
func TestDeviceDAO_FindBySerial_Success(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	// Create unique serial for this test
	uniqueSerial := uniqueID("SERIAL")
	device := createTestDevice(uniqueSerial, "Model-E")
	require.NoError(t, dao.Save(ctx, device))

	// Retrieve by serial
	retrieved, err := dao.FindBySerial(ctx, uniqueSerial)
	require.NoError(t, err)
	assert.Equal(t, uniqueSerial, retrieved.Serial)
	assert.Equal(t, device.ID, retrieved.ID)
	assert.Equal(t, device.Model, retrieved.Model)
}

// TestDeviceDAO_FindBySerial_NotFound tests FindBySerial with non-existent serial.
func TestDeviceDAO_FindBySerial_NotFound(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	_, err := dao.FindBySerial(ctx, "NONEXISTENT-SERIAL-12345")
	require.Error(t, err)

	var notFoundErr quicbaas.ErrNotFoundByIndex
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestDeviceDAO_GetByModel_Success tests retrieving devices by model.
func TestDeviceDAO_GetByModel_Success(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	// Create unique model for this test
	uniqueModel := uniqueID("MODEL")

	// Create multiple devices with same model
	device1 := createTestDevice("SN-MODEL-1", uniqueModel)
	device2 := createTestDevice("SN-MODEL-2", uniqueModel)
	device3 := createTestDevice("SN-MODEL-3", uniqueModel)

	require.NoError(t, dao.Save(ctx, device1))
	require.NoError(t, dao.Save(ctx, device2))
	require.NoError(t, dao.Save(ctx, device3))

	// Retrieve all devices by model
	devices, err := dao.GetByModel(ctx, uniqueModel)
	require.NoError(t, err)
	assert.Len(t, devices, 3)

	// Verify all returned devices have the correct model
	for _, d := range devices {
		assert.Equal(t, uniqueModel, d.Model)
	}
}

// TestDeviceDAO_GetByModel_Empty tests GetByModel when no devices match.
func TestDeviceDAO_GetByModel_Empty(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	devices, err := dao.GetByModel(ctx, "NONEXISTENT-MODEL-12345")
	require.NoError(t, err)
	assert.Empty(t, devices)
}

// TestDeviceDAO_Count tests counting devices.
func TestDeviceDAO_Count(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	// Initial count
	initialCount, err := dao.Count(ctx)
	require.NoError(t, err)

	// Add devices
	numDevices := 5
	for i := 0; i < numDevices; i++ {
		device := createTestDevice(uniqueID("SN-COUNT"), "Model-Count")
		require.NoError(t, dao.Save(ctx, device))
	}

	// Verify count increased
	newCount, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, initialCount+numDevices, newCount)
}

// TestDeviceDAO_DataPersistence tests that device data persists correctly.
func TestDeviceDAO_DataPersistence(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	// Create device with all fields populated
	device := &deviceEntities.Device{
		Serial:     "SN-PERSIST-001",
		Model:      "Model-Persist",
		AttestPub:  "attest-pub-key-data",
		EKCert:     "ek-cert-pem-data",
		SigningPub: "signing-pub-key-data",
		HashAlgoId: 11, // SHA256
		EventLog:   []byte{0x01, 0x02, 0x03, 0x04},
	}

	require.NoError(t, dao.Save(ctx, device))

	// Create new DAO instance to verify persistence
	dao2 := quicbaas.NewDeviceDAO(client, logger)

	retrieved, err := dao2.Get(ctx, device.ID)
	require.NoError(t, err)

	assert.Equal(t, device.Serial, retrieved.Serial)
	assert.Equal(t, device.Model, retrieved.Model)
	assert.Equal(t, device.AttestPub, retrieved.AttestPub)
	assert.Equal(t, device.EKCert, retrieved.EKCert)
	assert.Equal(t, device.SigningPub, retrieved.SigningPub)
	assert.Equal(t, device.HashAlgoId, retrieved.HashAlgoId)
	assert.Equal(t, device.EventLog, retrieved.EventLog)
}

// TestDeviceDAO_ConcurrentOperations tests concurrent device operations.
func TestDeviceDAO_ConcurrentOperations(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	// Concurrent writes
	numGoroutines := 10
	done := make(chan bool, numGoroutines)
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			device := createTestDevice(
				uniqueID("SN-CONCURRENT"),
				"Model-Concurrent",
			)
			if err := dao.Save(ctx, device); err != nil {
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

	// Verify all devices were created
	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, numGoroutines)
}

// TestDeviceDAO_FindBySerial_FallbackScan tests that FindBySerial falls back to scan.
func TestDeviceDAO_FindBySerial_FallbackScan(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := quicbaas.NewDeviceDAO(client, logger)

	ctx := context.Background()

	// Create multiple devices
	device1 := createTestDevice("SN-SCAN-001", "Model-Scan")
	device2 := createTestDevice("SN-SCAN-002", "Model-Scan")
	device3 := createTestDevice("SN-SCAN-003", "Model-Scan")

	require.NoError(t, dao.Save(ctx, device1))
	require.NoError(t, dao.Save(ctx, device2))
	require.NoError(t, dao.Save(ctx, device3))

	// Since QuicBaaS may not have secondary indexes configured,
	// FindBySerial should fall back to scanning and still find the device
	retrieved, err := dao.FindBySerial(ctx, "SN-SCAN-002")
	require.NoError(t, err)
	assert.Equal(t, "SN-SCAN-002", retrieved.Serial)
	assert.Equal(t, device2.ID, retrieved.ID)
}
