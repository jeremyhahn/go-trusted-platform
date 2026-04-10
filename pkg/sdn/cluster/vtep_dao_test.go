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
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockVTEPDAO(t *testing.T) (*VTEPDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewVTEPDAO(mock, logger, WithVTEPRequestTimeout(5*time.Second))

	return dao, mock
}

func TestVTEPDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:            "vtep-123",
		IP:            netip.MustParseAddr("10.0.0.1"),
		NodeID:        1,
		UnderlayIface: "eth0",
		UnderlayMTU:   1500,
		VXLANPort:     4789,
		Status:        VTEPStatusActive,
	}

	err := dao.Create(ctx, vtep)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), vtep.Version)
	assert.False(t, vtep.CreatedAt.IsZero())
	assert.False(t, vtep.UpdatedAt.IsZero())
}

func TestVTEPDAO_Create_NilVTEP(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestVTEPDAO_Create_EmptyID(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID: "",
		IP: netip.MustParseAddr("10.0.0.1"),
	}

	err := dao.Create(ctx, vtep)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVTEPDAO_Create_InvalidIP(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID: "vtep-123",
		IP: netip.Addr{}, // Invalid IP
	}

	err := dao.Create(ctx, vtep)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVTEPDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}

	require.NoError(t, dao.Create(ctx, vtep))

	// Try to create again
	vtep2 := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}
	err := dao.Create(ctx, vtep2)

	require.Error(t, err)
	var existsErr ErrVTEPAlreadyExists
	assert.ErrorAs(t, err, &existsErr)
}

func TestVTEPDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}

	err := dao.Create(ctx, vtep)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVTEPDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:            "vtep-123",
		IP:            netip.MustParseAddr("10.0.0.1"),
		NodeID:        1,
		UnderlayIface: "eth0",
		UnderlayMTU:   1500,
		VXLANPort:     4789,
		Status:        VTEPStatusActive,
	}
	require.NoError(t, dao.Create(ctx, vtep))

	retrieved, err := dao.Get(ctx, "vtep-123")

	require.NoError(t, err)
	assert.Equal(t, "vtep-123", retrieved.ID)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), retrieved.IP)
	assert.Equal(t, uint64(1), retrieved.NodeID)
	assert.Equal(t, "eth0", retrieved.UnderlayIface)
	assert.Equal(t, 1500, retrieved.UnderlayMTU)
	assert.Equal(t, uint16(4789), retrieved.VXLANPort)
	assert.Equal(t, VTEPStatusActive, retrieved.Status)
}

func TestVTEPDAO_Get_EmptyID(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVTEPDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "nonexistent")

	require.Error(t, err)
	var notFoundErr ErrVTEPNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVTEPDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, "vtep-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVTEPDAO_GetByIP_Success(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}
	require.NoError(t, dao.Create(ctx, vtep))

	retrieved, err := dao.GetByIP(ctx, netip.MustParseAddr("10.0.0.1"))

	require.NoError(t, err)
	assert.Equal(t, "vtep-123", retrieved.ID)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), retrieved.IP)
}

func TestVTEPDAO_GetByIP_NotFound(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByIP(ctx, netip.MustParseAddr("10.0.0.99"))

	require.Error(t, err)
	var notFoundErr ErrVTEPNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVTEPDAO_GetByIP_InvalidIP(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByIP(ctx, netip.Addr{})

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVTEPDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:            "vtep-123",
		IP:            netip.MustParseAddr("10.0.0.1"),
		NodeID:        1,
		UnderlayIface: "eth0",
		Status:        VTEPStatusActive,
	}
	require.NoError(t, dao.Create(ctx, vtep))

	updates := &VTEPState{
		IP:            netip.MustParseAddr("10.0.0.2"),
		UnderlayIface: "eth1",
		Status:        VTEPStatusDegraded,
	}
	err := dao.Update(ctx, "vtep-123", updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, "vtep-123")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), retrieved.IP)
	assert.Equal(t, "eth1", retrieved.UnderlayIface)
	assert.Equal(t, VTEPStatusDegraded, retrieved.Status)
	assert.Equal(t, uint64(2), retrieved.Version)
}

func TestVTEPDAO_Update_EmptyID(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &VTEPState{IP: netip.MustParseAddr("10.0.0.2")}
	err := dao.Update(ctx, "", updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVTEPDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, "vtep-123", nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestVTEPDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &VTEPState{IP: netip.MustParseAddr("10.0.0.2")}
	err := dao.Update(ctx, "nonexistent", updates, 1)

	require.Error(t, err)
	var notFoundErr ErrVTEPNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVTEPDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}
	require.NoError(t, dao.Create(ctx, vtep))

	updates := &VTEPState{IP: netip.MustParseAddr("10.0.0.2")}
	err := dao.Update(ctx, "vtep-123", updates, 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestVTEPDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}
	require.NoError(t, dao.Create(ctx, vtep))

	err := dao.Delete(ctx, "vtep-123", 1)

	require.NoError(t, err)

	// Verify it's deleted
	_, err = dao.Get(ctx, "vtep-123")
	var notFoundErr ErrVTEPNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVTEPDAO_Delete_EmptyID(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "", 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVTEPDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "nonexistent", 1)

	require.Error(t, err)
	var notFoundErr ErrVTEPNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestVTEPDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}
	require.NoError(t, dao.Create(ctx, vtep))

	err := dao.Delete(ctx, "vtep-123", 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestVTEPDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vteps, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, vteps)
}

func TestVTEPDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		vtep := &VTEPState{
			ID:     "vtep-" + string(rune('0'+i)),
			IP:     netip.MustParseAddr("10.0.0." + string(rune('0'+i))),
			NodeID: uint64(i),
		}
		require.NoError(t, dao.Create(ctx, vtep))
	}

	vteps, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, vteps, 5)
}

func TestVTEPDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVTEPDAO_ListByNode_Success(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vteps := []*VTEPState{
		{ID: "vtep-1", IP: netip.MustParseAddr("10.0.0.1"), NodeID: 1},
		{ID: "vtep-2", IP: netip.MustParseAddr("10.0.0.2"), NodeID: 2},
		{ID: "vtep-3", IP: netip.MustParseAddr("10.0.0.3"), NodeID: 1},
		{ID: "vtep-4", IP: netip.MustParseAddr("10.0.0.4"), NodeID: 2},
	}
	for _, v := range vteps {
		require.NoError(t, dao.Create(ctx, v))
	}

	node1VTEPs, err := dao.ListByNode(ctx, 1)

	require.NoError(t, err)
	assert.Len(t, node1VTEPs, 2)
	for _, v := range node1VTEPs {
		assert.Equal(t, uint64(1), v.NodeID)
	}
}

func TestVTEPDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		vtep := &VTEPState{
			ID:     "vtep-" + string(rune('0'+i)),
			IP:     netip.MustParseAddr("10.0.0." + string(rune('0'+i))),
			NodeID: uint64(i),
		}
		require.NoError(t, dao.Create(ctx, vtep))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestVTEPDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
	}
	require.NoError(t, dao.Create(ctx, vtep))

	exists, err := dao.Exists(ctx, "vtep-123")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestVTEPDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, "nonexistent")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestVTEPDAO_Exists_EmptyID(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestVTEPDAO_WithExternalIDs(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:     "vtep-123",
		IP:     netip.MustParseAddr("10.0.0.1"),
		NodeID: 1,
		ExternalIDs: map[string]string{
			"tenant":  "acme",
			"project": "network-lab",
		},
	}
	require.NoError(t, dao.Create(ctx, vtep))

	retrieved, err := dao.Get(ctx, "vtep-123")

	require.NoError(t, err)
	assert.Equal(t, "acme", retrieved.ExternalIDs["tenant"])
	assert.Equal(t, "network-lab", retrieved.ExternalIDs["project"])
}

func TestVTEPDAO_WithTunnels(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	vtep := &VTEPState{
		ID:      "vtep-123",
		IP:      netip.MustParseAddr("10.0.0.1"),
		NodeID:  1,
		Tunnels: []string{"tunnel-1", "tunnel-2", "tunnel-3"},
	}
	require.NoError(t, dao.Create(ctx, vtep))

	retrieved, err := dao.Get(ctx, "vtep-123")

	require.NoError(t, err)
	assert.Len(t, retrieved.Tunnels, 3)
	assert.Contains(t, retrieved.Tunnels, "tunnel-1")
	assert.Contains(t, retrieved.Tunnels, "tunnel-2")
	assert.Contains(t, retrieved.Tunnels, "tunnel-3")
}

func TestVTEPDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestVTEPDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockVTEPDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, "vtep-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
