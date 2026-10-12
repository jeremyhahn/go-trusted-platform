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

func testProfileServiceDatastore(t *testing.T) *Datastore {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	// Start the mock storage - required before any operations
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger)
}

func testProfileServiceDatastoreWithMock(t *testing.T) (*Datastore, *quicbaas.MockStorage) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	return NewDatastore(mockStorage, logger), mockStorage
}

func TestNewProfileService(t *testing.T) {
	ds := testProfileServiceDatastore(t)

	service, err := NewProfileService(ds)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.NotNil(t, service.profileDAO)
	assert.NotNil(t, service)
}

func TestProfileService_Save(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:       1,
		Name:     "TestProfile",
		Model:    "TestModel",
		Role:     entities.DeviceRoleServer,
		EventLog: []byte("event-log-data"),
	}

	err = service.Save(ctx, profile)
	assert.NoError(t, err)
}

func TestProfileService_Save_WithZeroID(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   0, // Invalid ID
		Name: "TestProfile",
	}

	err = service.Save(ctx, profile)
	assert.Error(t, err)
	assert.ErrorAs(t, err, &ErrInvalidProfileID{})
}

func TestProfileService_Save_DAOError(t *testing.T) {
	ds, mockStorage := testProfileServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Inject an error into the storage
	mockStorage.PutError = errors.New("storage write failed")

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
	}

	err = service.Save(ctx, profile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save profile")
}

func TestProfileService_Get(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    100,
		Name:  "Profile100",
		Model: "Model100",
		Role:  entities.DeviceRoleClient,
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
	assert.Equal(t, profile.Role, retrieved.Role)
}

func TestProfileService_Get_WithZeroID(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	_, err = service.Get(ctx, 0)
	assert.Error(t, err)
	assert.ErrorAs(t, err, &ErrInvalidProfileID{})
}

func TestProfileService_Get_NotFound(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	_, err = service.Get(ctx, 9999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get profile")
}

func TestProfileService_Delete(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    200,
		Name:  "Profile200",
		Model: "Model200",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Verify it exists
	retrieved, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)

	// Delete it
	err = service.Delete(ctx, profile)
	assert.NoError(t, err)

	// Verify it's deleted
	_, err = service.Get(ctx, profile.ID)
	assert.Error(t, err)
}

func TestProfileService_Delete_WithNilProfile(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.Delete(ctx, nil)
	assert.Error(t, err)
	assert.ErrorAs(t, err, &ErrInvalidProfileID{})
}

func TestProfileService_Delete_WithZeroID(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID: 0,
	}

	err = service.Delete(ctx, profile)
	assert.Error(t, err)
	assert.ErrorAs(t, err, &ErrInvalidProfileID{})
}

func TestProfileService_Delete_DAOError(t *testing.T) {
	ds, mockStorage := testProfileServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
	}

	// Inject an error into the storage
	mockStorage.DeleteError = errors.New("storage delete failed")

	err = service.Delete(ctx, profile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete profile")
}

func TestProfileService_Update(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    300,
		Name:  "OriginalProfile",
		Model: "OriginalModel",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Update the profile
	profile.Name = "UpdatedProfile"
	profile.Model = "UpdatedModel"

	err = service.Update(ctx, profile)
	require.NoError(t, err)

	// Verify the update
	retrieved, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedProfile", retrieved.Name)
	assert.Equal(t, "UpdatedModel", retrieved.Model)
}

func TestProfileService_Update_WithNilProfile(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	err = service.Update(ctx, nil)
	assert.Error(t, err)
	assert.ErrorAs(t, err, &ErrInvalidProfileID{})
}

func TestProfileService_Update_WithZeroID(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID: 0,
	}

	err = service.Update(ctx, profile)
	assert.Error(t, err)
	assert.ErrorAs(t, err, &ErrInvalidProfileID{})
}

func TestProfileService_Update_NotFound(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    9999,
		Name:  "NonExistent",
		Model: "NonExistent",
	}

	err = service.Update(ctx, profile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get profile for update")
}

// TestProfileService_RejectsSharedProvisioningAndTrustedVLAN verifies the
// single service-layer enforcement point: a profile whose provisioning and
// trusted networks share a VLAN is rejected on Save and on Update with the
// typed error, and accepted once the VLANs differ.
func TestProfileService_RejectsSharedProvisioningAndTrustedVLAN(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:   7,
		Name: "SharedVLAN",
		Role: entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork:     {VLAN: 200},
			entities.DefaultPostEnrollmentNetwork: {VLAN: 200},
		},
	}

	var notDistinct ErrProfileVLANsNotDistinct
	err = service.Save(ctx, profile)
	require.ErrorAs(t, err, &notDistinct)
	require.Equal(t, uint16(200), notDistinct.VLAN)

	err = service.Update(ctx, profile)
	require.ErrorAs(t, err, &notDistinct)

	// Distinct VLANs are accepted.
	profile.Networks[entities.DefaultEnrollmentNetwork].VLAN = 998
	require.NoError(t, service.Save(ctx, profile))
	require.NoError(t, service.Update(ctx, profile))
}

func TestProfileService_Update_SaveError(t *testing.T) {
	ds, mockStorage := testProfileServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "OriginalProfile",
		Model: "OriginalModel",
	}

	// First save should succeed
	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Now inject put error for the update
	mockStorage.PutError = errors.New("storage write failed")

	profile.Name = "UpdatedProfile"
	err = service.Update(ctx, profile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update profile")
}

func TestProfileService_Count(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	initialCount, err := service.Count(ctx)
	require.NoError(t, err)

	profiles := []*entities.DeviceProfile{
		{ID: 1, Name: "Profile1", Model: "Model1"},
		{ID: 2, Name: "Profile2", Model: "Model2"},
		{ID: 3, Name: "Profile3", Model: "Model3"},
	}

	for _, profile := range profiles {
		err = service.Save(ctx, profile)
		require.NoError(t, err)
	}

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, initialCount+3, count)
}

func TestProfileService_Count_DAOError(t *testing.T) {
	ds, mockStorage := testProfileServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Inject an error into the storage
	mockStorage.ListError = errors.New("storage list failed")

	_, err = service.Count(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count profiles")
}

func TestProfileService_Page(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create test profiles
	for i := 1; i <= 10; i++ {
		profile := &entities.DeviceProfile{
			ID:    uint64(i),
			Name:  "Profile" + string(rune('0'+i)),
			Model: "Model" + string(rune('0'+i)),
		}
		err = service.Save(ctx, profile)
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

func TestProfileService_Page_DAOError(t *testing.T) {
	ds, mockStorage := testProfileServiceDatastoreWithMock(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Inject an error into the storage
	mockStorage.ListError = errors.New("storage list failed")

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  5,
		SortOrder: datastore.SORT_ASCENDING,
	}

	_, err = service.Page(ctx, pageQuery)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to page profiles")
}

func TestProfileService_FindMatchingProfile(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create profiles with different match rules
	profile1 := &entities.DeviceProfile{
		ID:    1,
		Name:  "ServerProfile",
		Model: "ServerModel",
		Role:  entities.DeviceRoleServer,
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	profile2 := &entities.DeviceProfile{
		ID:    2,
		Name:  "ClientProfile",
		Model: "ClientModel",
		Role:  entities.DeviceRoleClient,
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: "SN100",
		},
	}

	err = service.Save(ctx, profile1)
	require.NoError(t, err)

	err = service.Save(ctx, profile2)
	require.NoError(t, err)

	// Test MAC address matching
	matched, err := service.FindMatchingProfile(ctx, "52:54:00:ab:cd:ef", "SN999", "AnyModel")
	require.NoError(t, err)
	assert.Equal(t, profile1.ID, matched.ID)
	assert.Equal(t, "ServerProfile", matched.Name)

	// Test Serial number matching
	matched, err = service.FindMatchingProfile(ctx, "aa:bb:cc:dd:ee:ff", "SN100-XYZ", "AnyModel")
	require.NoError(t, err)
	assert.Equal(t, profile2.ID, matched.ID)
	assert.Equal(t, "ClientProfile", matched.Name)
}

func TestProfileService_FindMatchingProfile_NoMatch(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "ServerProfile",
		Model: "ServerModel",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// No matching profile - QuicBaaS returns ErrNotFoundByIndex for index lookups
	_, err = service.FindMatchingProfile(ctx, "aa:bb:cc:dd:ee:ff", "SN999", "AnyModel")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProfileService_FindByMACAddress(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create profile with MAC prefix
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "MACProfile",
		Model: "MACModel",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Test exact prefix match
	matched, err := service.FindByMACAddress(ctx, "52:54:00:ab:cd:ef")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, matched.ID)
	assert.Equal(t, "MACProfile", matched.Name)
}

func TestProfileService_FindByMACAddress_NoMatch(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create profile with different MAC prefix
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "MACProfile",
		Model: "MACModel",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Test non-matching MAC
	_, err = service.FindByMACAddress(ctx, "aa:bb:cc:dd:ee:ff")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find profile by MAC address")
}

func TestProfileService_FindByMACAddress_EmptyMAC(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Test with empty MAC address
	_, err = service.FindByMACAddress(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find profile by MAC address")
}

func TestProfileService_FindBySerial(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create profile with serial prefix
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "SerialProfile",
		Model: "SerialModel",
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: "SN100",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Test exact prefix match
	matched, err := service.FindBySerial(ctx, "SN100-XYZ-123")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, matched.ID)
	assert.Equal(t, "SerialProfile", matched.Name)
}

func TestProfileService_FindBySerial_NoMatch(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create profile with different serial prefix
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "SerialProfile",
		Model: "SerialModel",
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: "SN100",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Test non-matching serial
	_, err = service.FindBySerial(ctx, "SN999-ABC")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find profile by serial")
}

func TestProfileService_FindBySerial_EmptySerial(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Test with empty serial number
	_, err = service.FindBySerial(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find profile by serial")
}

func TestProfileService_WithNetworkConfig(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    400,
		Name:  "NetworkProfile",
		Model: "NetworkModel",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:     100,
				StaticIP: "192.168.1.10",
				Gateway:  "192.168.1.1",
				DNS:      []string{"8.8.8.8", "8.8.4.4"},
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "192.168.1.0/24",
					RangeStart: "192.168.1.100",
					RangeEnd:   "192.168.1.200",
					LeaseTime:  3600,
				},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     200,
				StaticIP: "10.0.0.10",
				Gateway:  "10.0.0.1",
			},
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.GetEnrollmentNetworkConfig())
	assert.Equal(t, uint16(100), retrieved.GetEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, "192.168.1.10", retrieved.GetEnrollmentNetworkConfig().StaticIP)
	assert.NotNil(t, retrieved.GetPostEnrollmentNetworkConfig())
	assert.Equal(t, uint16(200), retrieved.GetPostEnrollmentNetworkConfig().VLAN)
}

func TestProfileService_WithPlatformdConfig(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    500,
		Name:  "PlatformProfile",
		Model: "PlatformModel",
		PlatformdConfig: &entities.PlatformdConfigRef{
			ConfigType: "reference",
			Reference:  "/etc/platformd/config.yaml",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.PlatformdConfig)
	assert.Equal(t, "reference", retrieved.PlatformdConfig.ConfigType)
	assert.Equal(t, "/etc/platformd/config.yaml", retrieved.PlatformdConfig.Reference)
}

func TestProfileService_WithComplexMatchRules(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    600,
		Name:  "ComplexProfile",
		Model: "ComplexModel",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "52:54:00",
			SerialPrefix: "SN100",
			Model:        "TPM2000",
		},
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	// Test matching with MAC
	matched, err := service.FindMatchingProfile(ctx, "52:54:00:11:22:33", "SN999", "OtherModel")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, matched.ID)

	// Test matching with Serial
	matched, err = service.FindMatchingProfile(ctx, "aa:bb:cc:dd:ee:ff", "SN100-ABC", "OtherModel")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, matched.ID)

	// Test matching with Model
	matched, err = service.FindMatchingProfile(ctx, "aa:bb:cc:dd:ee:ff", "SN999", "TPM2000")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, matched.ID)
}

func TestProfileService_WithLargeEventLog(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	largeEventLog := make([]byte, 2*1024*1024) // 2MB
	for i := range largeEventLog {
		largeEventLog[i] = byte(i % 256)
	}

	profile := &entities.DeviceProfile{
		ID:       700,
		Name:     "LargeProfile",
		Model:    "LargeModel",
		EventLog: largeEventLog,
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.ID, retrieved.ID)
	assert.Len(t, retrieved.EventLog, 2*1024*1024)
}

func TestProfileService_WithDifferentRoles(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	roles := []entities.DeviceRole{
		entities.DeviceRoleServer,
		entities.DeviceRoleClient,
		entities.DeviceRoleWorkstation,
		entities.DeviceRoleEdge,
		entities.DeviceRoleIoT,
		entities.DeviceRoleGateway,
		entities.DeviceRoleLoadBalancer,
	}

	for i, role := range roles {
		profile := &entities.DeviceProfile{
			ID:    uint64(i + 1),
			Name:  "Profile" + role.String(),
			Model: "Model" + role.String(),
			Role:  role,
		}

		err = service.Save(ctx, profile)
		require.NoError(t, err)

		retrieved, err := service.Get(ctx, profile.ID)
		require.NoError(t, err)
		assert.Equal(t, role, retrieved.Role)
	}
}

func TestProfileService_Delete_NotFound(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID: 9999,
	}

	// QuicBaaS delete is idempotent - deleting non-existent records succeeds
	err = service.Delete(ctx, profile)
	assert.NoError(t, err)
}

func TestProfileService_Count_Empty(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	count, err := service.Count(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)
}

func TestProfileService_Page_Empty(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	pageQuery := datastore.PageQuery{
		Page:      1,
		PageSize:  10,
		SortOrder: datastore.SORT_ASCENDING,
	}

	result, err := service.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Entities), 0)
}

func TestProfileService_FindMatchingProfile_Empty(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// QuicBaaS returns ErrNotFoundByIndex for index lookups
	_, err = service.FindMatchingProfile(ctx, "aa:bb:cc:dd:ee:ff", "SN999", "AnyModel")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProfileService_Page_WithDifferentSortOrder(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create profiles
	for i := 1; i <= 5; i++ {
		profile := &entities.DeviceProfile{
			ID:    uint64(i),
			Name:  "Profile" + string(rune('0'+i)),
			Model: "Model" + string(rune('0'+i)),
		}
		err = service.Save(ctx, profile)
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

func TestProfileService_Delete_Success(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    1111,
		Name:  "DeleteProfile",
		Model: "DeleteModel",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	err = service.Delete(ctx, profile)
	assert.NoError(t, err)
}

func TestProfileService_Update_Success(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    1234,
		Name:  "OriginalName",
		Model: "OriginalModel",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	profile.Name = "UpdatedName"
	err = service.Update(ctx, profile)
	require.NoError(t, err)

	retrieved, err := service.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedName", retrieved.Name)
}

func TestProfileService_Count_AfterDeletion(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	profile := &entities.DeviceProfile{
		ID:    1500,
		Name:  "CountProfile",
		Model: "CountModel",
	}

	err = service.Save(ctx, profile)
	require.NoError(t, err)

	count1, err := service.Count(ctx)
	require.NoError(t, err)

	err = service.Delete(ctx, profile)
	require.NoError(t, err)

	count2, err := service.Count(ctx)
	require.NoError(t, err)

	assert.Equal(t, count1-1, count2)
}

func TestProfileService_Page_MultiPage(t *testing.T) {
	ds := testProfileServiceDatastore(t)
	ctx := context.Background()

	service, err := NewProfileService(ds)
	require.NoError(t, err)

	// Create 15 profiles
	for i := 1; i <= 15; i++ {
		profile := &entities.DeviceProfile{
			ID:    uint64(i + 3000),
			Name:  "PageProfile" + string(rune('0'+i)),
			Model: "PageModel" + string(rune('0'+i)),
		}
		err = service.Save(ctx, profile)
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

// TestProfileService_Update_PreservesPCRBaselineAndAssignment proves a
// request-shaped update (which can carry neither field) does not erase the
// baseline the verifier captured nor the assignment the assign flow
// recorded (#446). Dropping either restore line in Update must fail this.
func TestProfileService_Update_PreservesPCRBaselineAndAssignment(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	assigned := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID:   4460,
		Name: "workers",
		Role: entities.DeviceRoleWorker,
		PCRBaseline: &entities.PCRBaseline{
			Values:               map[int][]byte{0: {0xaa}, 7: {0xbb}},
			Source:               entities.BaselineSourceTOFU,
			RecordedAt:           recorded,
			RecordedFromDeviceID: 77,
		},
		Assigned:   true,
		AssignedAt: assigned,
	}))

	// The dashboard edit: identity fields only.
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 4460, Name: "workers-renamed", Role: entities.DeviceRoleWorker,
	}))

	stored, err := service.Get(ctx, 4460)
	require.NoError(t, err)
	assert.Equal(t, "workers-renamed", stored.Name, "the edit the caller asked for")
	require.NotNil(t, stored.PCRBaseline, "PCRBaseline erased by update")
	assert.Equal(t, entities.BaselineSourceTOFU, stored.PCRBaseline.Source)
	assert.Equal(t, []byte{0xbb}, stored.PCRBaseline.Values[7])
	assert.True(t, recorded.Equal(stored.PCRBaseline.RecordedAt))
	assert.Equal(t, uint64(77), stored.PCRBaseline.RecordedFromDeviceID)
	assert.True(t, stored.Assigned, "Assigned erased by update")
	assert.True(t, assigned.Equal(stored.AssignedAt), "AssignedAt erased by update")
}

// TestProfileService_Update_CallerBaselineStillWins pins the boundary of the
// restore: it fills an omission, it does not override a caller that supplied
// a baseline (the in-process verifier is such a caller when it captures TOFU).
func TestProfileService_Update_CallerBaselineStillWins(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID: 4461, Name: "p", Role: entities.DeviceRoleWorker,
		PCRBaseline: &entities.PCRBaseline{
			Values: map[int][]byte{0: {0x01}}, Source: entities.BaselineSourceTOFU, RecordedAt: time.Now().UTC(),
		},
	}))
	signed := &entities.PCRBaseline{
		Values: map[int][]byte{0: {0x02}}, Source: entities.BaselineSourceSigned, RecordedAt: time.Now().UTC(),
	}
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 4461, Name: "p", Role: entities.DeviceRoleWorker, PCRBaseline: signed,
	}))

	stored, err := service.Get(ctx, 4461)
	require.NoError(t, err)
	require.NotNil(t, stored.PCRBaseline)
	assert.Equal(t, entities.BaselineSourceSigned, stored.PCRBaseline.Source)
	assert.Equal(t, []byte{0x02}, stored.PCRBaseline.Values[0])
}

// TestProfileService_Update_UnassignedStaysUnassigned proves the Assigned
// restore only fires when the stored record was assigned: a profile that was
// never assigned is not invented into an assignment by an update.
func TestProfileService_Update_UnassignedStaysUnassigned(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{ID: 4462, Name: "p", Role: entities.DeviceRoleWorker}))
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{ID: 4462, Name: "q", Role: entities.DeviceRoleWorker}))

	stored, err := service.Get(ctx, 4462)
	require.NoError(t, err)
	assert.False(t, stored.Assigned)
	assert.True(t, stored.AssignedAt.IsZero())
	assert.Nil(t, stored.PCRBaseline)
}

// TestProfileService_Update_CallerAssignmentStillWins pins that the restore
// fills an omission only: an update that does carry an assignment is stored
// as sent, so the guard cannot be replaced by an unconditional copy.
func TestProfileService_Update_CallerAssignmentStillWins(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{ID: 4463, Name: "p", Role: entities.DeviceRoleWorker}))
	at := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 4463, Name: "p", Role: entities.DeviceRoleWorker, Assigned: true, AssignedAt: at,
	}))

	stored, err := service.Get(ctx, 4463)
	require.NoError(t, err)
	assert.True(t, stored.Assigned, "a caller-supplied assignment must be stored as sent")
	assert.True(t, at.Equal(stored.AssignedAt))
}

// TestProfileService_Update_PreservesTLSServerName pins the #430 rule: an
// update whose entity carries no TLSServerName (a console PUT rebuilt from a
// form that predates the field, or a client that never learned it) keeps the
// stored name the attestation collector verifies node certificates against.
// Dropping the restore from Update must fail this test.
func TestProfileService_Update_PreservesTLSServerName(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID: 4480, Name: "compute", Role: entities.DeviceRoleWorker,
		TLSServerName: "compute.example.internal",
	}))

	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 4480, Name: "compute-renamed", Role: entities.DeviceRoleWorker,
	}))

	stored, err := service.Get(ctx, 4480)
	require.NoError(t, err)
	assert.Equal(t, "compute-renamed", stored.Name, "the edit the caller asked for")
	assert.Equal(t, "compute.example.internal", stored.TLSServerName, "TLSServerName erased by update")
}

// TestProfileService_Update_CallerTLSServerNameStillWins pins the boundary of
// the restore: it fills an omission, it does not override a caller that
// supplied a new name.
func TestProfileService_Update_CallerTLSServerNameStillWins(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID: 4482, Name: "gw", Role: entities.DeviceRoleGateway,
		TLSServerName: "compute.example.internal",
	}))
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 4482, Name: "gw", Role: entities.DeviceRoleGateway,
		TLSServerName: "gw.example.internal",
	}))

	stored, err := service.Get(ctx, 4482)
	require.NoError(t, err)
	assert.Equal(t, "gw.example.internal", stored.TLSServerName)
}

// TestProfileService_Update_ClearTLSServerName pins the #462 clear path: the
// explicit option blanks the stored name, the very next update that omits it
// keeps it blank, and an update without the option still preserves a name
// set again afterwards.
func TestProfileService_Update_ClearTLSServerName(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID: 4483, Name: "compute", Role: entities.DeviceRoleWorker,
		TLSServerName: "compute.example.internal",
	}))
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 4483, Name: "compute", Role: entities.DeviceRoleWorker,
	}, ClearTLSServerName))

	stored, err := service.Get(ctx, 4483)
	require.NoError(t, err)
	assert.Empty(t, stored.TLSServerName, "the explicit clear must blank the name")

	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{
		ID: 4483, Name: "compute", Role: entities.DeviceRoleWorker, TLSServerName: "gw.example.internal",
	}))
	require.NoError(t, service.Update(ctx, &entities.DeviceProfile{ID: 4483, Name: "compute", Role: entities.DeviceRoleWorker}))
	stored, err = service.Get(ctx, 4483)
	require.NoError(t, err)
	assert.Equal(t, "gw.example.internal", stored.TLSServerName, "omission must still preserve after a clear")
}

// TestProfileService_Update_ClearTLSServerNameConflict pins that an update
// both naming a TLSServerName and clearing it is refused with the typed error
// and leaves the stored name untouched.
func TestProfileService_Update_ClearTLSServerNameConflict(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{
		ID: 4484, Name: "compute", Role: entities.DeviceRoleWorker,
		TLSServerName: "compute.example.internal",
	}))
	err = service.Update(ctx, &entities.DeviceProfile{
		ID: 4484, Name: "compute", Role: entities.DeviceRoleWorker, TLSServerName: "gw.example.internal",
	}, ClearTLSServerName)
	require.ErrorAs(t, err, &ErrTLSServerNameClearConflict{})

	stored, err := service.Get(ctx, 4484)
	require.NoError(t, err)
	assert.Equal(t, "compute.example.internal", stored.TLSServerName)
}

// TestApplyTLSServerName pins the tri-state every merge handler shares: an
// absent name keeps the profile's and asks for nothing, a value replaces it,
// and "" blanks it and asks the service for the explicit clear.
func TestApplyTLSServerName(t *testing.T) {
	name := func(s string) *string { return &s }
	tests := []struct {
		label    string
		in       *string
		wantName string
		wantOpts []ProfileUpdateOption
	}{
		{"omitted keeps", nil, "compute.example.internal", nil},
		{"value replaces", name("gw.example.internal"), "gw.example.internal", nil},
		{"empty clears", name(""), "", []ProfileUpdateOption{ClearTLSServerName}},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			profile := &entities.DeviceProfile{TLSServerName: "compute.example.internal"}
			opts := ApplyTLSServerName(profile, tt.in)
			assert.Equal(t, tt.wantName, profile.TLSServerName)
			assert.Equal(t, tt.wantOpts, opts)
		})
	}
}

// TestProfileService_FindProfileForDevice_BoundProfileWins pins the resolver's
// precedence (#463): a profile whose EKSerial equals the serial of the
// device's stored EK certificate wins over one whose match rules cover the
// device, and the same device with no EK certificate falls through to the
// match rules. Dropping the bound branch must fail this test.
func TestProfileService_FindProfileForDevice_BoundProfileWins(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()
	certPEM := newEKCertForTest(t, 4630001)

	// The installer-created shape: no match rules, then bound by assign.
	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{ID: 4631, Name: "node-05", Role: entities.DeviceRoleWorker, TLSServerName: "compute.example.internal"}))
	require.NoError(t, service.AssignToDeviceWithEK(ctx, 4631, "4630001", "", certPEM))
	// A rule-based profile that also covers the device.
	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{ID: 4632, Name: "x10-fleet", Role: entities.DeviceRoleWorker,
		MatchRules: &entities.ProfileMatchRules{Model: "SuperMicro X10"}}))

	dev := &entities.Device{ID: 970392025956353, Serial: "node-05-compute-01", Model: "SuperMicro X10", EKCert: certPEM}
	profile, err := service.FindProfileForDevice(ctx, dev)
	require.NoError(t, err)
	assert.Equal(t, uint64(4631), profile.ID, "the bound profile must win over a rule match")
	assert.Equal(t, "compute.example.internal", profile.TLSServerName)

	unbound := &entities.Device{ID: 971641861439490, Serial: "node-01-gw-01", Model: "SuperMicro X10"}
	profile, err = service.FindProfileForDevice(ctx, unbound)
	require.NoError(t, err)
	assert.Equal(t, uint64(4632), profile.ID, "with no EK identity the match rules decide")
}

// TestProfileService_FindProfileForDevice_NotFound pins the failure shapes:
// a nil device, and a device nothing is bound to and nothing matches — the
// fleet's state before assign (#463) — yield typed errors, never a guess.
func TestProfileService_FindProfileForDevice_NotFound(t *testing.T) {
	ds := testServiceDatastore(t)
	service, err := NewProfileService(ds)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = service.FindProfileForDevice(ctx, nil)
	assert.ErrorIs(t, err, ErrDeviceRequired{})

	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{ID: 4633, Name: "node-05", Role: entities.DeviceRoleWorker}))
	dev := &entities.Device{ID: 970392025956353, Serial: "node-05-compute-01", Model: "SuperMicro X10", EKCert: newEKCertForTest(t, 4630002)}
	_, err = service.FindProfileForDevice(ctx, dev)
	var none ErrNoProfileForDevice
	require.True(t, errors.As(err, &none), "got %v", err)
	assert.Equal(t, dev.ID, none.DeviceID)
	assert.Equal(t, "4630002", none.EKSerial)

	// An unparseable stored EK certificate yields no EK identity and falls
	// through to the match rules rather than failing the resolution.
	require.NoError(t, service.Save(ctx, &entities.DeviceProfile{ID: 4634, Name: "rules", Role: entities.DeviceRoleWorker,
		MatchRules: &entities.ProfileMatchRules{SerialPrefix: "NODE-01"}}))
	profile, err := service.FindProfileForDevice(ctx, &entities.Device{ID: 9, Serial: "node-01-gw-01", EKCert: "garbage"})
	require.NoError(t, err)
	assert.Equal(t, uint64(4634), profile.ID)
}
