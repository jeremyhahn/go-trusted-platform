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

func setupMockPortDAO(t *testing.T) (*PortDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewPortDAO(mock, logger, WithPortRequestTimeout(5*time.Second))

	return dao, mock
}

func TestPortDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
		Type:     "system",
		NodeID:   1,
	}

	err := dao.Create(ctx, port)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), port.Version)
	assert.False(t, port.CreatedAt.IsZero())
	assert.False(t, port.UpdatedAt.IsZero())
}

func TestPortDAO_Create_NilPort(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestPortDAO_Create_EmptyID(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:   "",
		Name: "eth0",
	}

	err := dao.Create(ctx, port)

	require.Error(t, err)
	var invalidIDErr ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestPortDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
	}

	require.NoError(t, dao.Create(ctx, port))

	port2 := &PortState{
		ID:       "port-123",
		Name:     "eth1",
		BridgeID: "br-test",
	}
	err := dao.Create(ctx, port2)

	require.Error(t, err)
	var existsErr ErrPortAlreadyExists
	assert.ErrorAs(t, err, &existsErr)
}

func TestPortDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
	}

	err := dao.Create(ctx, port)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestPortDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
		Type:     "internal",
		Tag:      100,
		VLANMode: "access",
		MAC:      "00:11:22:33:44:55",
		MTU:      9000,
	}
	require.NoError(t, dao.Create(ctx, port))

	retrieved, err := dao.Get(ctx, "port-123")

	require.NoError(t, err)
	assert.Equal(t, "port-123", retrieved.ID)
	assert.Equal(t, "eth0", retrieved.Name)
	assert.Equal(t, "br-test", retrieved.BridgeID)
	assert.Equal(t, "internal", retrieved.Type)
	assert.Equal(t, uint16(100), retrieved.Tag)
	assert.Equal(t, "access", retrieved.VLANMode)
	assert.Equal(t, "00:11:22:33:44:55", retrieved.MAC)
	assert.Equal(t, uint32(9000), retrieved.MTU)
}

func TestPortDAO_Get_EmptyID(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestPortDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "nonexistent")

	require.Error(t, err)
	var notFoundErr ErrPortNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestPortDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, "port-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestPortDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
		Tag:      100,
	}
	require.NoError(t, dao.Create(ctx, port))

	updates := &PortState{
		Name:     "eth0-updated",
		BridgeID: "br-test",
		Tag:      200,
		VLANMode: "trunk",
	}
	err := dao.Update(ctx, "port-123", updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, "port-123")
	require.NoError(t, err)
	assert.Equal(t, "eth0-updated", retrieved.Name)
	assert.Equal(t, uint16(200), retrieved.Tag)
	assert.Equal(t, "trunk", retrieved.VLANMode)
	assert.Equal(t, uint64(2), retrieved.Version)
}

func TestPortDAO_Update_EmptyID(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &PortState{Name: "updated"}
	err := dao.Update(ctx, "", updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestPortDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, "port-123", nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestPortDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &PortState{Name: "updated"}
	err := dao.Update(ctx, "nonexistent", updates, 1)

	require.Error(t, err)
	var notFoundErr ErrPortNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestPortDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, port))

	updates := &PortState{Name: "updated"}
	err := dao.Update(ctx, "port-123", updates, 99)

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestPortDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, port))

	err := dao.Delete(ctx, "port-123", 1)

	require.NoError(t, err)

	_, err = dao.Get(ctx, "port-123")
	var notFoundErr ErrPortNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestPortDAO_Delete_EmptyID(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "", 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestPortDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "nonexistent", 1)

	require.Error(t, err)
	var notFoundErr ErrPortNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestPortDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, port))

	err := dao.Delete(ctx, "port-123", 99)

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestPortDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	ports, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, ports)
}

func TestPortDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		port := &PortState{
			ID:       "port-" + string(rune('0'+i)),
			Name:     "eth" + string(rune('0'+i)),
			BridgeID: "br-test",
		}
		require.NoError(t, dao.Create(ctx, port))
	}

	ports, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, ports, 5)
}

func TestPortDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestPortDAO_ListByBridge_Success(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	ports := []*PortState{
		{ID: "port-1", Name: "eth0", BridgeID: "br-1"},
		{ID: "port-2", Name: "eth1", BridgeID: "br-2"},
		{ID: "port-3", Name: "eth2", BridgeID: "br-1"},
		{ID: "port-4", Name: "eth3", BridgeID: "br-2"},
	}
	for _, p := range ports {
		require.NoError(t, dao.Create(ctx, p))
	}

	br1Ports, err := dao.ListByBridge(ctx, "br-1")

	require.NoError(t, err)
	assert.Len(t, br1Ports, 2)
	for _, p := range br1Ports {
		assert.Equal(t, "br-1", p.BridgeID)
	}
}

func TestPortDAO_ListByBridge_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.ListByBridge(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestPortDAO_ListByNode_Success(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	ports := []*PortState{
		{ID: "port-1", Name: "eth0", BridgeID: "br-1", NodeID: 1},
		{ID: "port-2", Name: "eth1", BridgeID: "br-1", NodeID: 2},
		{ID: "port-3", Name: "eth2", BridgeID: "br-2", NodeID: 1},
	}
	for _, p := range ports {
		require.NoError(t, dao.Create(ctx, p))
	}

	node1Ports, err := dao.ListByNode(ctx, 1)

	require.NoError(t, err)
	assert.Len(t, node1Ports, 2)
	for _, p := range node1Ports {
		assert.Equal(t, uint64(1), p.NodeID)
	}
}

func TestPortDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		port := &PortState{
			ID:       "port-" + string(rune('0'+i)),
			Name:     "eth" + string(rune('0'+i)),
			BridgeID: "br-test",
		}
		require.NoError(t, dao.Create(ctx, port))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestPortDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
	}
	require.NoError(t, dao.Create(ctx, port))

	exists, err := dao.Exists(ctx, "port-123")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestPortDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, "nonexistent")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestPortDAO_Exists_EmptyID(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestPortDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, "port-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestPortDAO_WithTrunkPorts(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
		VLANMode: "trunk",
		Trunks:   []uint16{100, 200, 300},
	}
	require.NoError(t, dao.Create(ctx, port))

	retrieved, err := dao.Get(ctx, "port-123")

	require.NoError(t, err)
	assert.Equal(t, "trunk", retrieved.VLANMode)
	assert.Len(t, retrieved.Trunks, 3)
	assert.Contains(t, retrieved.Trunks, uint16(100))
	assert.Contains(t, retrieved.Trunks, uint16(200))
	assert.Contains(t, retrieved.Trunks, uint16(300))
}

func TestPortDAO_WithBondMode(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:          "port-123",
		Name:        "bond0",
		BridgeID:    "br-test",
		Type:        "bond",
		BondMode:    "balance-tcp",
		BondUpDelay: 1000,
	}
	require.NoError(t, dao.Create(ctx, port))

	retrieved, err := dao.Get(ctx, "port-123")

	require.NoError(t, err)
	assert.Equal(t, "bond", retrieved.Type)
	assert.Equal(t, "balance-tcp", retrieved.BondMode)
	assert.Equal(t, int64(1000), retrieved.BondUpDelay)
}

func TestPortDAO_WithStatistics(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	port := &PortState{
		ID:       "port-123",
		Name:     "eth0",
		BridgeID: "br-test",
		Statistics: map[string]int64{
			"rx_packets": 1000,
			"tx_packets": 500,
			"rx_bytes":   1000000,
			"tx_bytes":   500000,
		},
	}
	require.NoError(t, dao.Create(ctx, port))

	retrieved, err := dao.Get(ctx, "port-123")

	require.NoError(t, err)
	assert.Equal(t, int64(1000), retrieved.Statistics["rx_packets"])
	assert.Equal(t, int64(500), retrieved.Statistics["tx_packets"])
}

// Additional port DAO tests for edge cases

func TestPortDAO_ListByNode_Empty(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewPortDAO(mock, logger, WithPortRequestTimeout(5*time.Second))

	ctx := context.Background()
	ports, err := dao.ListByNode(ctx, 1)

	require.NoError(t, err)
	assert.Empty(t, ports)
}

func TestPortDAO_ListByNode_WithPorts(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewPortDAO(mock, logger, WithPortRequestTimeout(5*time.Second))

	ctx := context.Background()

	// Create ports for different nodes
	port1 := &PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1", NodeID: 1}
	port2 := &PortState{ID: "port-2", Name: "eth1", BridgeID: "br-1", NodeID: 1}
	port3 := &PortState{ID: "port-3", Name: "eth2", BridgeID: "br-2", NodeID: 2}
	require.NoError(t, dao.Create(ctx, port1))
	require.NoError(t, dao.Create(ctx, port2))
	require.NoError(t, dao.Create(ctx, port3))

	// List ports for node 1
	ports, err := dao.ListByNode(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, ports, 2)

	// List ports for node 2
	ports2, err := dao.ListByNode(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, ports2, 1)
}

func TestPortDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestPortDAO_ListByBridge_StorageError(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByBridge(ctx, "br-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestPortDAO_ListByNode_StorageError(t *testing.T) {
	dao, mock := setupMockPortDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByNode(ctx, 1)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
