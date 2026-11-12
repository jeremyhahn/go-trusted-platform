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
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockDeviceProfileDAO(t *testing.T) (*DeviceProfileDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewDeviceProfileDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestDeviceProfileDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		Model: "TestModel",
	}
	err := dao.Save(ctx, profile)

	require.NoError(t, err)
	assert.NotZero(t, profile.ID)
	assert.Equal(t, 1, mock.Count(entityTypeDeviceProfile))
}

func TestDeviceProfileDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "TestModel",
	}
	err := dao.Save(ctx, profile)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), profile.ID)
}

func TestDeviceProfileDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	eventLog := []byte{0x00, 0x01, 0x02, 0x03}
	profile := &entities.DeviceProfile{
		ID:       12345,
		Model:    "TestModel",
		EventLog: eventLog,
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "TestModel", retrieved.Model)
	assert.Equal(t, eventLog, retrieved.EventLog)
}

func TestDeviceProfileDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestDeviceProfileDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 12345, Model: "TestModel"}
	require.NoError(t, dao.Save(ctx, profile))
	assert.Equal(t, 1, mock.Count(entityTypeDeviceProfile))

	err := dao.Delete(ctx, profile)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeDeviceProfile))
}

func TestDeviceProfileDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "InitialModel",
	}
	require.NoError(t, dao.Save(ctx, profile))

	profile.Model = "UpdatedModel"
	profile.EventLog = []byte{0xFF, 0xFE}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedModel", retrieved.Model)
	assert.Equal(t, []byte{0xFF, 0xFE}, retrieved.EventLog)
}

func TestDeviceProfileDAO_GetByModel_WithScan_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profiles := []*entities.DeviceProfile{
		{ID: 1, Model: "ModelA"},
		{ID: 2, Model: "ModelB"},
		{ID: 3, Model: "ModelC"},
	}
	for _, profile := range profiles {
		require.NoError(t, dao.Save(ctx, profile))
	}

	// Force scan by making Query return error
	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByModel(ctx, "ModelB")

	require.NoError(t, err)
	assert.Equal(t, "ModelB", retrieved.Model)
}

func TestDeviceProfileDAO_GetByModel_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 1, Model: "ModelA"}
	require.NoError(t, dao.Save(ctx, profile))

	mock.QueryError = errors.New("no index")

	_, err := dao.GetByModel(ctx, "NonexistentModel")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestDeviceProfileDAO_GetByModel_WithIndex_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "IndexedModel",
	}
	data, _ := json.Marshal(profile)
	mock.SetQueryResult(entityTypeDeviceProfile, "Model", []byte("IndexedModel"), []*service.Entity{{ID: 12345, Data: data}})

	retrieved, err := dao.GetByModel(ctx, "IndexedModel")

	require.NoError(t, err)
	assert.Equal(t, "IndexedModel", retrieved.Model)
}

func TestDeviceProfileDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestDeviceProfileDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.Count(ctx)
	require.Error(t, err)
}

func TestDeviceProfileDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestDeviceProfileDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestDeviceProfileDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	var allProfiles []*entities.DeviceProfile
	processor := func(result datastore.PageResult[*entities.DeviceProfile]) error {
		allProfiles = append(allProfiles, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allProfiles))
}

func TestDeviceProfileDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		profile := &entities.DeviceProfile{ID: uint64(i), Model: "Model"}
		require.NoError(t, dao.Save(ctx, profile))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.DeviceProfile]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestDeviceProfileDAO_WithLargeEventLog_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Create a large event log (4KB)
	largeEventLog := make([]byte, 4096)
	for i := range largeEventLog {
		largeEventLog[i] = byte(i % 256)
	}

	profile := &entities.DeviceProfile{
		ID:       12345,
		Model:    "LargeEventLogModel",
		EventLog: largeEventLog,
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, largeEventLog, retrieved.EventLog)
}

func TestDeviceProfileDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	profile := &entities.DeviceProfile{Model: "Test"}
	err := dao.Save(ctx, profile)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestDeviceProfileDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	profile := &entities.DeviceProfile{ID: 12345, Model: "Test"}
	data, _ := json.Marshal(profile)
	mock.SetData(entityTypeDeviceProfile, 12345, data)

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestDeviceProfileDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 12345, Model: "Test"}
	err := dao.Delete(ctx, profile)

	require.Error(t, err)
}

func TestDeviceProfileDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}

func TestDeviceProfileDAO_GetByModel_ListError_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.QueryError = errors.New("no index")
	mock.ListError = errors.New("list failed")

	ctx := context.Background()
	_, err := dao.GetByModel(ctx, "Model")

	require.Error(t, err)
}

func TestDeviceProfileDAO_EmptyEventLog_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:       12345,
		Model:    "EmptyEventLogModel",
		EventLog: []byte{},
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Empty(t, retrieved.EventLog)
}

func TestDeviceProfileDAO_NilEventLog_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    12345,
		Model: "NilEventLogModel",
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Nil(t, retrieved.EventLog)
}

func TestDeviceProfileDAO_FullProfileRoundTrip_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		Name:     "full-profile",
		Model:    "Model-Full",
		TenantID: "tenant-full",
		Role:     entities.DeviceRoleEdge,
		EventLog: []byte{0x01, 0x02, 0x03, 0x04},
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:       100,
				AuthMethod: entities.AuthMethodNone,
				Gateway:    "192.168.1.1",
				DNS:        []string{"8.8.8.8", "8.8.4.4"},
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "192.168.1.0/24",
					RangeStart: "192.168.1.100",
					RangeEnd:   "192.168.1.200",
					LeaseTime:  3600,
				},
				ACLs: []entities.ACLConfig{{
					Priority: 10,
					Protocol: "tcp",
					SrcIP:    "any",
					DstIP:    "192.168.1.0/24",
					DstPort:  443,
					Action:   "allow",
				}},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:       200,
				AuthMethod: entities.AuthMethod802_1X,
				Gateway:    "10.0.0.1",
				DNS:        []string{"10.0.0.53"},
			},
			entities.DefaultFailureNetwork: {
				VLAN:       999,
				AuthMethod: entities.AuthMethodNone,
			},
		},
		PlatformdConfig: &entities.PlatformdConfigRef{
			ConfigType: "reference",
			Reference:  "/etc/platformd/config.yaml",
			Version:    "1.0.0",
		},
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "fu:ll:pr",
			SerialPrefix: "FULL-SN",
			Model:        "Model-Full",
		},
	}
	assert.Zero(t, profile.ID)
	require.NoError(t, dao.Save(ctx, profile))
	assert.NotZero(t, profile.ID, "ID should be auto-generated")

	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
	assert.Equal(t, profile.TenantID, retrieved.TenantID)
	assert.Equal(t, profile.Role, retrieved.Role)
	assert.Equal(t, profile.EventLog, retrieved.EventLog)

	enrollment := retrieved.Networks[entities.DefaultEnrollmentNetwork]
	require.NotNil(t, enrollment)
	want := profile.Networks[entities.DefaultEnrollmentNetwork]
	assert.Equal(t, want.VLAN, enrollment.VLAN)
	assert.Equal(t, want.AuthMethod, enrollment.AuthMethod)
	assert.Equal(t, want.Gateway, enrollment.Gateway)
	assert.Equal(t, want.DNS, enrollment.DNS)
	require.NotNil(t, enrollment.DHCPPool)
	assert.Equal(t, *want.DHCPPool, *enrollment.DHCPPool)
	require.Len(t, enrollment.ACLs, 1)
	assert.Equal(t, want.ACLs[0], enrollment.ACLs[0])

	postEnrollment := retrieved.Networks[entities.DefaultPostEnrollmentNetwork]
	require.NotNil(t, postEnrollment)
	assert.Equal(t, uint16(200), postEnrollment.VLAN)
	assert.Equal(t, entities.AuthMethod802_1X, postEnrollment.AuthMethod)

	failure := retrieved.Networks[entities.DefaultFailureNetwork]
	require.NotNil(t, failure)
	assert.Equal(t, uint16(999), failure.VLAN)

	require.NotNil(t, retrieved.PlatformdConfig)
	assert.Equal(t, *profile.PlatformdConfig, *retrieved.PlatformdConfig)
	require.NotNil(t, retrieved.MatchRules)
	assert.Equal(t, *profile.MatchRules, *retrieved.MatchRules)
}

func TestDeviceProfileDAO_Update_RoleAndTenant_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		Name:     "profile-update",
		Model:    "Model-B",
		TenantID: "test-tenant",
		Role:     entities.DeviceRoleServer,
	}
	require.NoError(t, dao.Save(ctx, profile))
	originalID := profile.ID

	profile.Model = "Model-B-Updated"
	profile.Role = entities.DeviceRoleGateway
	profile.TenantID = "updated-tenant"
	require.NoError(t, dao.Save(ctx, profile))
	assert.Equal(t, originalID, profile.ID)

	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, "Model-B-Updated", retrieved.Model)
	assert.Equal(t, entities.DeviceRoleGateway, retrieved.Role)
	assert.Equal(t, "updated-tenant", retrieved.TenantID)
}

func TestDeviceProfileDAO_FindByMACPrefix_InputCaseIgnored_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:         1,
		Model:      "Model-MAC-Case",
		MatchRules: &entities.ProfileMatchRules{MACPrefix: "aa:bb:cc"},
	}
	require.NoError(t, dao.Save(ctx, profile))

	for _, mac := range []string{"AA:BB:CC:DD:EE:FF", "Aa:Bb:Cc:11:22:33"} {
		retrieved, err := dao.FindByMACPrefix(ctx, mac)
		require.NoError(t, err, mac)
		assert.Equal(t, profile.ID, retrieved.ID, mac)
	}
}

func TestDeviceProfileDAO_FindByDICEDeviceID_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	other := &entities.DeviceProfile{ID: 1, Model: "Model-No-DICE", EKSerial: "EK-1"}
	profile := &entities.DeviceProfile{
		ID:           2,
		Model:        "Model-DICE",
		DICEDeviceID: "00aabbccdd",
		GoldenFWHash: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	}
	require.NoError(t, dao.Save(ctx, other))
	require.NoError(t, dao.Save(ctx, profile))

	for _, id := range []string{"00aabbccdd", "00AABBCCDD"} {
		retrieved, err := dao.FindByDICEDeviceID(ctx, id)
		require.NoError(t, err, id)
		assert.Equal(t, profile.ID, retrieved.ID, id)
		assert.Equal(t, profile.GoldenFWHash, retrieved.GoldenFWHash, id)
	}

	for _, id := range []string{"00aabbccee", ""} {
		_, err := dao.FindByDICEDeviceID(ctx, id)
		var notFound ErrNotFoundByIndex
		require.ErrorAs(t, err, &notFound, id)
		assert.Equal(t, "DICEDeviceID", notFound.IndexField, id)
	}
}

func TestDeviceProfileDAO_FindMatchingProfile_AllCriteria_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		ID:    1,
		Model: "Model-Multi",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "ca:fe:ba",
			SerialPrefix: "MULTI-SN",
			Model:        "Model-Multi",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	lookups := []struct{ mac, serial, model string }{
		{"ca:fe:ba:be:00:01", "", ""},
		{"", "multi-sn-001", ""},
		{"", "", "Model-Multi"},
		{"ca:fe:ba:be:00:02", "multi-sn-002", "Model-Multi"},
	}
	for _, l := range lookups {
		retrieved, err := dao.FindMatchingProfile(ctx, l.mac, l.serial, l.model)
		require.NoError(t, err, l)
		assert.Equal(t, profile.ID, retrieved.ID, l)
	}
}

func TestDeviceProfileDAO_SecondInstanceLookups_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{
		Name:  "profile-persistence",
		Model: "Model-Persistence",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix:    "pe:rs:is",
			SerialPrefix: "PERSIST",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	// A DAO opened later over the same store resolves the profile by every lookup.
	dao2 := NewDeviceProfileDAO(mock, logging.DefaultLogger(), WithRequestTimeout(5*time.Second))

	retrieved, err := dao2.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, profile.Name, retrieved.Name)
	assert.Equal(t, profile.Model, retrieved.Model)
	require.NotNil(t, retrieved.MatchRules)
	assert.Equal(t, profile.MatchRules.MACPrefix, retrieved.MatchRules.MACPrefix)
	assert.Equal(t, profile.MatchRules.SerialPrefix, retrieved.MatchRules.SerialPrefix)

	byModel, err := dao2.GetByModel(ctx, "Model-Persistence")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, byModel.ID)

	byMAC, err := dao2.FindByMACPrefix(ctx, "pe:rs:is:te:nc:e0")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, byMAC.ID)

	bySerial, err := dao2.FindBySerialPrefix(ctx, "persist-001")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, bySerial.ID)
}

func TestDeviceProfileDAO_UpdateMatchRules_Mock(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &entities.DeviceProfile{Name: "profile-updaterules", Model: "Model-UpdateRules"}
	require.NoError(t, dao.Save(ctx, profile))

	profile.MatchRules = &entities.ProfileMatchRules{
		MACPrefix:    "up:da:te",
		SerialPrefix: "UPDATE-SN",
		Model:        "Model-UpdateRules",
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved.MatchRules)
	assert.Equal(t, "up:da:te", retrieved.MatchRules.MACPrefix)
	assert.Equal(t, "UPDATE-SN", retrieved.MatchRules.SerialPrefix)

	profile.MatchRules.MACPrefix = "ne:w0:ma"
	profile.MatchRules.SerialPrefix = "NEW-SN"
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err = dao.Get(ctx, profile.ID)
	require.NoError(t, err)
	assert.Equal(t, "ne:w0:ma", retrieved.MatchRules.MACPrefix)
	assert.Equal(t, "NEW-SN", retrieved.MatchRules.SerialPrefix)

	foundByMAC, err := dao.FindByMACPrefix(ctx, "ne:w0:ma:c0:ff:ee")
	require.NoError(t, err)
	assert.Equal(t, profile.ID, foundByMAC.ID)
}
