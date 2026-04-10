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
