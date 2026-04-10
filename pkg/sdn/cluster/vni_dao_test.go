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

package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockVNIMappingDAO(t *testing.T) (*VNIMappingDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewVNIMappingDAO(mock, logger, WithVNIMappingRequestTimeout(5*time.Second))

	return dao, mock
}

func TestVNIMappingDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:         100,
		VLAN:        10,
		BridgeID:    "br-test",
		TenantID:    "tenant-1",
		Description: "Test mapping",
	}

	err := dao.Create(ctx, mapping)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), mapping.Version)
	assert.False(t, mapping.CreatedAt.IsZero())
	assert.False(t, mapping.UpdatedAt.IsZero())
}

func TestVNIMappingDAO_Create_NilMapping(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestVNIMappingDAO_Create_InvalidVNI_Zero(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:  0,
		VLAN: 10,
	}

	err := dao.Create(ctx, mapping)

	require.Error(t, err)
	var invalidVNIErr ErrInvalidVNI
	assert.ErrorAs(t, err, &invalidVNIErr)
}

func TestVNIMappingDAO_Create_InvalidVNI_TooLarge(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:  16777216, // Max is 16777215
		VLAN: 10,
	}

	err := dao.Create(ctx, mapping)

	require.Error(t, err)
	var invalidVNIErr ErrInvalidVNI
	assert.ErrorAs(t, err, &invalidVNIErr)
}

func TestVNIMappingDAO_Create_InvalidVLAN_Zero(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:  100,
		VLAN: 0,
	}

	err := dao.Create(ctx, mapping)

	require.Error(t, err)
	var invalidVLANErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidVLANErr)
}

func TestVNIMappingDAO_Create_InvalidVLAN_TooLarge(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:  100,
		VLAN: 4095, // Max is 4094
	}

	err := dao.Create(ctx, mapping)

	require.Error(t, err)
	var invalidVLANErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidVLANErr)
}

func TestVNIMappingDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}

	require.NoError(t, dao.Create(ctx, mapping))

	// Try to create again
	mapping2 := &VNIMappingState{
		VNI:      100,
		VLAN:     20,
		BridgeID: "br-test2",
	}
	err := dao.Create(ctx, mapping2)

	require.Error(t, err)
	var existsErr ErrVNIAlreadyMapped
	assert.ErrorAs(t, err, &existsErr)
}

func TestVNIMappingDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}

	err := dao.Create(ctx, mapping)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVNIMappingDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:         100,
		VLAN:        10,
		BridgeID:    "br-test",
		TenantID:    "tenant-1",
		Description: "Test mapping",
	}
	require.NoError(t, dao.Create(ctx, mapping))

	retrieved, err := dao.Get(ctx, 100)

	require.NoError(t, err)
	assert.Equal(t, uint32(100), retrieved.VNI)
	assert.Equal(t, uint16(10), retrieved.VLAN)
	assert.Equal(t, "br-test", retrieved.BridgeID)
	assert.Equal(t, "tenant-1", retrieved.TenantID)
	assert.Equal(t, "Test mapping", retrieved.Description)
}

func TestVNIMappingDAO_Get_InvalidVNI(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 0)

	require.Error(t, err)
	var invalidVNIErr ErrInvalidVNI
	assert.ErrorAs(t, err, &invalidVNIErr)
}

func TestVNIMappingDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 999)

	require.Error(t, err)
	var notFoundErr ErrVNIMappingNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVNIMappingDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 100)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVNIMappingDAO_GetByVLAN_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, mapping))

	retrieved, err := dao.GetByVLAN(ctx, 10)

	require.NoError(t, err)
	assert.Equal(t, uint32(100), retrieved.VNI)
	assert.Equal(t, uint16(10), retrieved.VLAN)
}

func TestVNIMappingDAO_GetByVLAN_NotFound(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByVLAN(ctx, 99)

	require.Error(t, err)
	var notFoundErr ErrVNIMappingNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVNIMappingDAO_GetByVLAN_InvalidVLAN(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByVLAN(ctx, 0)

	require.Error(t, err)
	var invalidVLANErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidVLANErr)
}

func TestVNIMappingDAO_GetByBridge_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mappings := []*VNIMappingState{
		{VNI: 100, VLAN: 10, BridgeID: "br-1"},
		{VNI: 200, VLAN: 20, BridgeID: "br-2"},
		{VNI: 300, VLAN: 30, BridgeID: "br-1"},
	}
	for _, m := range mappings {
		require.NoError(t, dao.Create(ctx, m))
	}

	br1Mappings, err := dao.GetByBridge(ctx, "br-1")

	require.NoError(t, err)
	assert.Len(t, br1Mappings, 2)
	for _, m := range br1Mappings {
		assert.Equal(t, "br-1", m.BridgeID)
	}
}

func TestVNIMappingDAO_GetByBridge_EmptyID(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByBridge(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVNIMappingDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:         100,
		VLAN:        10,
		BridgeID:    "br-test",
		Description: "Original",
	}
	require.NoError(t, dao.Create(ctx, mapping))

	updates := &VNIMappingState{
		VLAN:        20,
		BridgeID:    "br-test-2",
		Description: "Updated",
	}
	err := dao.Update(ctx, 100, updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, uint16(20), retrieved.VLAN)
	assert.Equal(t, "br-test-2", retrieved.BridgeID)
	assert.Equal(t, "Updated", retrieved.Description)
	assert.Equal(t, uint64(2), retrieved.Version)
	// VNI should be preserved
	assert.Equal(t, uint32(100), retrieved.VNI)
}

func TestVNIMappingDAO_Update_InvalidVNI(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &VNIMappingState{VLAN: 20}
	err := dao.Update(ctx, 0, updates, 1)

	require.Error(t, err)
	var invalidVNIErr ErrInvalidVNI
	assert.ErrorAs(t, err, &invalidVNIErr)
}

func TestVNIMappingDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, 100, nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestVNIMappingDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &VNIMappingState{VLAN: 20}
	err := dao.Update(ctx, 999, updates, 1)

	require.Error(t, err)
	var notFoundErr ErrVNIMappingNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVNIMappingDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, mapping))

	updates := &VNIMappingState{VLAN: 20}
	err := dao.Update(ctx, 100, updates, 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestVNIMappingDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, mapping))

	err := dao.Delete(ctx, 100, 1)

	require.NoError(t, err)

	// Verify it's deleted
	_, err = dao.Get(ctx, 100)
	var notFoundErr ErrVNIMappingNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVNIMappingDAO_Delete_InvalidVNI(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, 0, 1)

	require.Error(t, err)
	var invalidVNIErr ErrInvalidVNI
	assert.ErrorAs(t, err, &invalidVNIErr)
}

func TestVNIMappingDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, 999, 1)

	require.Error(t, err)
	var notFoundErr ErrVNIMappingNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVNIMappingDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, mapping))

	err := dao.Delete(ctx, 100, 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestVNIMappingDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mappings, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, mappings)
}

func TestVNIMappingDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		mapping := &VNIMappingState{
			VNI:      uint32(100 + i),
			VLAN:     uint16(10 + i),
			BridgeID: "br-test",
		}
		require.NoError(t, dao.Create(ctx, mapping))
	}

	mappings, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, mappings, 5)
}

func TestVNIMappingDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVNIMappingDAO_ListByTenant_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mappings := []*VNIMappingState{
		{VNI: 100, VLAN: 10, BridgeID: "br-1", TenantID: "tenant-1"},
		{VNI: 200, VLAN: 20, BridgeID: "br-2", TenantID: "tenant-2"},
		{VNI: 300, VLAN: 30, BridgeID: "br-3", TenantID: "tenant-1"},
	}
	for _, m := range mappings {
		require.NoError(t, dao.Create(ctx, m))
	}

	tenant1Mappings, err := dao.ListByTenant(ctx, "tenant-1")

	require.NoError(t, err)
	assert.Len(t, tenant1Mappings, 2)
	for _, m := range tenant1Mappings {
		assert.Equal(t, "tenant-1", m.TenantID)
	}
}

func TestVNIMappingDAO_ListByTenant_EmptyID(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.ListByTenant(ctx, "")

	require.Error(t, err)
	var invalidConfigErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfigErr)
}

func TestVNIMappingDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		mapping := &VNIMappingState{
			VNI:      uint32(100 + i),
			VLAN:     uint16(10 + i),
			BridgeID: "br-test",
		}
		require.NoError(t, dao.Create(ctx, mapping))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestVNIMappingDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, mapping))

	exists, err := dao.Exists(ctx, 100)

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestVNIMappingDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, 999)

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestVNIMappingDAO_Exists_InvalidVNI(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, 0)

	require.Error(t, err)
	var invalidVNIErr ErrInvalidVNI
	assert.ErrorAs(t, err, &invalidVNIErr)
}

func TestVNIMappingDAO_WithExternalIDs(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mapping := &VNIMappingState{
		VNI:      100,
		VLAN:     10,
		BridgeID: "br-test",
		ExternalIDs: map[string]string{
			"env":  "production",
			"team": "network",
		},
	}
	require.NoError(t, dao.Create(ctx, mapping))

	retrieved, err := dao.Get(ctx, 100)

	require.NoError(t, err)
	assert.Equal(t, "production", retrieved.ExternalIDs["env"])
	assert.Equal(t, "network", retrieved.ExternalIDs["team"])
}

func TestVNIMappingDAO_ValidVNIRange(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Test minimum valid VNI
	mappingMin := &VNIMappingState{
		VNI:      1,
		VLAN:     10,
		BridgeID: "br-test",
	}
	err := dao.Create(ctx, mappingMin)
	require.NoError(t, err)

	// Test maximum valid VNI
	mappingMax := &VNIMappingState{
		VNI:      16777215,
		VLAN:     20,
		BridgeID: "br-test",
	}
	err = dao.Create(ctx, mappingMax)
	require.NoError(t, err)

	// Verify both exist
	_, err = dao.Get(ctx, 1)
	require.NoError(t, err)

	_, err = dao.Get(ctx, 16777215)
	require.NoError(t, err)
}

func TestVNIMappingDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVNIMappingDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockVNIMappingDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, 100)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
