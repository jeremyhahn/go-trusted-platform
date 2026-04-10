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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDatastore creates a datastore with started mock storage for testing
func testDatastore(t *testing.T) *Datastore {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger)
}

func TestNewDatastore(t *testing.T) {
	mockStorage := quicbaas.NewMockStorage()
	logger := logging.DefaultLogger()

	ds := NewDatastore(mockStorage, logger)
	require.NotNil(t, ds)
	assert.NotNil(t, ds.storage)
	assert.NotNil(t, ds.logger)
}

func TestDatastore_DeviceDAO(t *testing.T) {
	ctx := context.Background()
	ds := testDatastore(t)
	require.NotNil(t, ds)

	dao, err := ds.DeviceDAO()
	require.NoError(t, err)
	require.NotNil(t, dao)

	// Test that the DAO works
	device := &entities.Device{
		ID:     1,
		Model:  "TestTPM",
		Serial: "SN001",
	}

	err = dao.Save(ctx, device)
	assert.NoError(t, err)

	retrieved, err := dao.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrieved.ID)
	assert.Equal(t, device.Model, retrieved.Model)
	assert.Equal(t, device.Serial, retrieved.Serial)
}

func TestDatastore_ProfileDAO(t *testing.T) {
	ctx := context.Background()
	ds := testDatastore(t)
	require.NotNil(t, ds)

	dao, err := ds.ProfileDAO()
	require.NoError(t, err)
	require.NotNil(t, dao)

	// Test that the DAO works
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "TestProfile",
		Model: "TestModel",
	}

	err = dao.Save(ctx, profile)
	assert.NoError(t, err)

	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
}

func TestDatastore_MultipleDAOCreation(t *testing.T) {
	ctx := context.Background()
	ds := testDatastore(t)
	require.NotNil(t, ds)

	// Create multiple DAOs
	dao1, err := ds.DeviceDAO()
	require.NoError(t, err)
	require.NotNil(t, dao1)

	dao2, err := ds.DeviceDAO()
	require.NoError(t, err)
	require.NotNil(t, dao2)

	// Both DAOs should work independently
	device1 := &entities.Device{
		ID:     1,
		Model:  "TPM1",
		Serial: "SN1",
	}

	device2 := &entities.Device{
		ID:     2,
		Model:  "TPM2",
		Serial: "SN2",
	}

	err = dao1.Save(ctx, device1)
	require.NoError(t, err)

	err = dao2.Save(ctx, device2)
	require.NoError(t, err)

	// Retrieve from both DAOs
	retrieved1, err := dao1.Get(ctx, device1.ID)
	require.NoError(t, err)
	assert.Equal(t, device1.ID, retrieved1.ID)

	retrieved2, err := dao2.Get(ctx, device2.ID)
	require.NoError(t, err)
	assert.Equal(t, device2.ID, retrieved2.ID)
}

func TestDatastore_BothDAOTypes(t *testing.T) {
	ctx := context.Background()
	ds := testDatastore(t)
	require.NotNil(t, ds)

	// Create both types of DAOs
	deviceDAO, err := ds.DeviceDAO()
	require.NoError(t, err)
	require.NotNil(t, deviceDAO)

	profileDAO, err := ds.ProfileDAO()
	require.NoError(t, err)
	require.NotNil(t, profileDAO)

	// Test device DAO
	device := &entities.Device{
		ID:     1,
		Model:  "TestTPM",
		Serial: "SN001",
	}

	err = deviceDAO.Save(ctx, device)
	require.NoError(t, err)

	retrievedDevice, err := deviceDAO.Get(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retrievedDevice.ID)

	// Test profile DAO
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "TestProfile",
		Model: "TestModel",
	}

	err = profileDAO.Save(ctx, profile)
	require.NoError(t, err)

	retrievedProfile, err := profileDAO.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrievedProfile.ID)
}

func TestDatastore_DAOOperationsWithComplexDevice(t *testing.T) {
	ctx := context.Background()
	ds := testDatastore(t)
	require.NotNil(t, ds)

	dao, err := ds.DeviceDAO()
	require.NoError(t, err)

	largeEventLog := make([]byte, 512*1024) // 512KB
	for i := range largeEventLog {
		largeEventLog[i] = byte(i % 256)
	}

	device := &entities.Device{
		ID:         5000,
		AttestPub:  "complex-attest-public-key-data",
		EKCert:     "complex-endorsement-key-certificate",
		EventLog:   largeEventLog,
		HashAlgoId: 11,
		Model:      "ComplexTPM2000",
		Serial:     "SNCOMPLEX5000",
		SigningPub: "complex-signing-public-key-data",
	}

	err = dao.Save(ctx, device)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, device.ID)
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
