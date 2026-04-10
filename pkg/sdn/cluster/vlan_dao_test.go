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

func setupMockVLANDAO(t *testing.T) (*VLANDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewVLANDAO(mock, logger, WithVLANRequestTimeout(5*time.Second))

	return dao, mock
}

func TestVLANDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:          100,
		Name:        "production",
		Description: "Production network",
		Ports:       []string{"port-1", "port-2"},
	}

	err := dao.Create(ctx, vlan)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), vlan.Version)
	assert.False(t, vlan.CreatedAt.IsZero())
	assert.False(t, vlan.UpdatedAt.IsZero())
}

func TestVLANDAO_Create_NilVLAN(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestVLANDAO_Create_InvalidVLANID_Zero(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   0,
		Name: "invalid",
	}

	err := dao.Create(ctx, vlan)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_Create_InvalidVLANID_TooHigh(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   4095,
		Name: "invalid",
	}

	err := dao.Create(ctx, vlan)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_Create_ValidBoundaryIDs(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Test minimum valid VLAN ID
	vlan1 := &VLANState{ID: 1, Name: "vlan-1"}
	err := dao.Create(ctx, vlan1)
	require.NoError(t, err)

	// Test maximum valid VLAN ID
	vlan4094 := &VLANState{ID: 4094, Name: "vlan-4094"}
	err = dao.Create(ctx, vlan4094)
	require.NoError(t, err)
}

func TestVLANDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "production",
	}
	require.NoError(t, dao.Create(ctx, vlan))

	vlan2 := &VLANState{
		ID:   100,
		Name: "different-name",
	}
	err := dao.Create(ctx, vlan2)

	require.Error(t, err)
	var existsErr ErrVLANAlreadyExists
	assert.ErrorAs(t, err, &existsErr)
}

func TestVLANDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "production",
	}

	err := dao.Create(ctx, vlan)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVLANDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:          100,
		Name:        "production",
		Description: "Production network",
		Ports:       []string{"port-1", "port-2"},
		TrunkPorts:  []string{"port-trunk-1"},
		ExternalIDs: map[string]string{"tenant": "acme"},
	}
	require.NoError(t, dao.Create(ctx, vlan))

	retrieved, err := dao.Get(ctx, 100)

	require.NoError(t, err)
	assert.Equal(t, uint16(100), retrieved.ID)
	assert.Equal(t, "production", retrieved.Name)
	assert.Equal(t, "Production network", retrieved.Description)
	assert.Len(t, retrieved.Ports, 2)
	assert.Len(t, retrieved.TrunkPorts, 1)
	assert.Equal(t, "acme", retrieved.ExternalIDs["tenant"])
}

func TestVLANDAO_Get_InvalidVLANID_Zero(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 0)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_Get_InvalidVLANID_TooHigh(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 4095)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 999)

	require.Error(t, err)
	var notFoundErr ErrVLANNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVLANDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 100)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVLANDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:          100,
		Name:        "production",
		Description: "Original description",
	}
	require.NoError(t, dao.Create(ctx, vlan))

	updates := &VLANState{
		Name:        "production-updated",
		Description: "Updated description",
		Ports:       []string{"port-1", "port-2", "port-3"},
	}
	err := dao.Update(ctx, 100, updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, "production-updated", retrieved.Name)
	assert.Equal(t, "Updated description", retrieved.Description)
	assert.Len(t, retrieved.Ports, 3)
	assert.Equal(t, uint64(2), retrieved.Version)
}

func TestVLANDAO_Update_InvalidVLANID(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &VLANState{Name: "updated"}
	err := dao.Update(ctx, 0, updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, 100, nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestVLANDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &VLANState{Name: "updated"}
	err := dao.Update(ctx, 999, updates, 1)

	require.Error(t, err)
	var notFoundErr ErrVLANNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVLANDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "production",
	}
	require.NoError(t, dao.Create(ctx, vlan))

	updates := &VLANState{Name: "updated"}
	err := dao.Update(ctx, 100, updates, 99)

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestVLANDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "production",
	}
	require.NoError(t, dao.Create(ctx, vlan))

	err := dao.Delete(ctx, 100, 1)

	require.NoError(t, err)

	_, err = dao.Get(ctx, 100)
	var notFoundErr ErrVLANNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVLANDAO_Delete_InvalidVLANID(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, 0, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, 999, 1)

	require.Error(t, err)
	var notFoundErr ErrVLANNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVLANDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "production",
	}
	require.NoError(t, dao.Create(ctx, vlan))

	err := dao.Delete(ctx, 100, 99)

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestVLANDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlans, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, vlans)
}

func TestVLANDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := uint16(1); i <= 5; i++ {
		vlan := &VLANState{
			ID:   i * 100,
			Name: "vlan-" + string(rune('0'+i)),
		}
		require.NoError(t, dao.Create(ctx, vlan))
	}

	vlans, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, vlans, 5)
}

func TestVLANDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVLANDAO_ListByPort_AccessPorts(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlans := []*VLANState{
		{ID: 100, Name: "vlan-100", Ports: []string{"port-1", "port-2"}},
		{ID: 200, Name: "vlan-200", Ports: []string{"port-2", "port-3"}},
		{ID: 300, Name: "vlan-300", Ports: []string{"port-4"}},
	}
	for _, v := range vlans {
		require.NoError(t, dao.Create(ctx, v))
	}

	port2VLANs, err := dao.ListByPort(ctx, "port-2")

	require.NoError(t, err)
	assert.Len(t, port2VLANs, 2)
}

func TestVLANDAO_ListByPort_TrunkPorts(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlans := []*VLANState{
		{ID: 100, Name: "vlan-100", TrunkPorts: []string{"trunk-1", "trunk-2"}},
		{ID: 200, Name: "vlan-200", TrunkPorts: []string{"trunk-2", "trunk-3"}},
		{ID: 300, Name: "vlan-300", TrunkPorts: []string{"trunk-4"}},
	}
	for _, v := range vlans {
		require.NoError(t, dao.Create(ctx, v))
	}

	trunk2VLANs, err := dao.ListByPort(ctx, "trunk-2")

	require.NoError(t, err)
	assert.Len(t, trunk2VLANs, 2)
}

func TestVLANDAO_ListByPort_Mixed(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlans := []*VLANState{
		{ID: 100, Name: "vlan-100", Ports: []string{"port-1"}},
		{ID: 200, Name: "vlan-200", TrunkPorts: []string{"port-1"}},
	}
	for _, v := range vlans {
		require.NoError(t, dao.Create(ctx, v))
	}

	port1VLANs, err := dao.ListByPort(ctx, "port-1")

	require.NoError(t, err)
	assert.Len(t, port1VLANs, 2)
}

func TestVLANDAO_ListByPort_EmptyPortID(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.ListByPort(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := uint16(1); i <= 3; i++ {
		vlan := &VLANState{
			ID:   i * 100,
			Name: "vlan",
		}
		require.NoError(t, dao.Create(ctx, vlan))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestVLANDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "production",
	}
	require.NoError(t, dao.Create(ctx, vlan))

	exists, err := dao.Exists(ctx, 100)

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestVLANDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, 999)

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestVLANDAO_Exists_InvalidVLANID(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, 0)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVLANDAO_WithExternalIDs(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "production",
		ExternalIDs: map[string]string{
			"tenant":      "acme",
			"environment": "prod",
			"owner":       "network-team",
		},
	}
	require.NoError(t, dao.Create(ctx, vlan))

	retrieved, err := dao.Get(ctx, 100)

	require.NoError(t, err)
	assert.Equal(t, "acme", retrieved.ExternalIDs["tenant"])
	assert.Equal(t, "prod", retrieved.ExternalIDs["environment"])
	assert.Equal(t, "network-team", retrieved.ExternalIDs["owner"])
}

func TestVLANDAO_PreservesImmutableFieldsOnUpdate(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vlan := &VLANState{
		ID:   100,
		Name: "original",
	}
	require.NoError(t, dao.Create(ctx, vlan))

	original, err := dao.Get(ctx, 100)
	require.NoError(t, err)

	// Try to change ID in updates (should be ignored)
	updates := &VLANState{
		ID:   999, // This should be ignored
		Name: "updated",
	}
	err = dao.Update(ctx, 100, updates, 1)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 100)
	require.NoError(t, err)

	// ID should remain unchanged
	assert.Equal(t, uint16(100), retrieved.ID)
	assert.Equal(t, "updated", retrieved.Name)
	// CreatedAt should be preserved
	assert.Equal(t, original.CreatedAt, retrieved.CreatedAt)
	// Version should be incremented
	assert.Equal(t, uint64(2), retrieved.Version)
}

// Additional VLAN DAO tests for edge cases

func TestVLANDAO_ListByPort_Empty(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVLANDAO(mock, logger, WithVLANRequestTimeout(5*time.Second))

	ctx := context.Background()
	vlans, err := dao.ListByPort(ctx, "port-1")

	require.NoError(t, err)
	assert.Empty(t, vlans)
}

func TestVLANDAO_ListByPort_WithVLANs(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVLANDAO(mock, logger, WithVLANRequestTimeout(5*time.Second))

	ctx := context.Background()

	// Create VLANs with ports
	vlan1 := &VLANState{ID: 100, Name: "production", Ports: []string{"port-1", "port-2"}}
	vlan2 := &VLANState{ID: 200, Name: "development", Ports: []string{"port-1", "port-3"}}
	vlan3 := &VLANState{ID: 300, Name: "testing", Ports: []string{"port-3"}}
	require.NoError(t, dao.Create(ctx, vlan1))
	require.NoError(t, dao.Create(ctx, vlan2))
	require.NoError(t, dao.Create(ctx, vlan3))

	// List VLANs for port-1
	vlans, err := dao.ListByPort(ctx, "port-1")
	require.NoError(t, err)
	assert.Len(t, vlans, 2)

	// List VLANs for port-3
	vlans2, err := dao.ListByPort(ctx, "port-3")
	require.NoError(t, err)
	assert.Len(t, vlans2, 2)
}

func TestVLANDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVLANDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, 100)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVLANDAO_ListByPort_StorageError(t *testing.T) {
	dao, mock := setupMockVLANDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByPort(ctx, "port-1")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
