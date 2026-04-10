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

func setupMockTunnelDAO(t *testing.T) (*TunnelDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger, WithTunnelRequestTimeout(5*time.Second))

	return dao, mock
}

func TestTunnelDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		LocalIP:    netip.MustParseAddr("10.0.0.1"),
		RemoteIP:   netip.MustParseAddr("10.0.0.2"),
		VNI:        100,
		OVSPort:    "vxlan-100",
		OFPort:     10,
		Status:     TunnelStatusUp,
		NodeID:     1,
	}

	err := dao.Create(ctx, tunnel)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), tunnel.Version)
	assert.False(t, tunnel.CreatedAt.IsZero())
	assert.False(t, tunnel.UpdatedAt.IsZero())
}

func TestTunnelDAO_Create_NilTunnel(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestTunnelDAO_Create_EmptyID(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
	}

	err := dao.Create(ctx, tunnel)

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_Create_MissingLocalVTEP(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "",
		RemoteVTEP: "vtep-2",
	}

	err := dao.Create(ctx, tunnel)

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_Create_MissingRemoteVTEP(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "",
	}

	err := dao.Create(ctx, tunnel)

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}

	require.NoError(t, dao.Create(ctx, tunnel))

	// Try to create again
	tunnel2 := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}
	err := dao.Create(ctx, tunnel2)

	require.Error(t, err)
	var existsErr ErrTunnelAlreadyExists
	assert.ErrorAs(t, err, &existsErr)
}

func TestTunnelDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}

	err := dao.Create(ctx, tunnel)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestTunnelDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		LocalIP:    netip.MustParseAddr("10.0.0.1"),
		RemoteIP:   netip.MustParseAddr("10.0.0.2"),
		VNI:        100,
		OVSPort:    "vxlan-100",
		OFPort:     10,
		Status:     TunnelStatusUp,
		NodeID:     1,
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	retrieved, err := dao.Get(ctx, "tunnel-123")

	require.NoError(t, err)
	assert.Equal(t, "tunnel-123", retrieved.ID)
	assert.Equal(t, "vtep-1", retrieved.LocalVTEP)
	assert.Equal(t, "vtep-2", retrieved.RemoteVTEP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), retrieved.LocalIP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), retrieved.RemoteIP)
	assert.Equal(t, uint32(100), retrieved.VNI)
	assert.Equal(t, "vxlan-100", retrieved.OVSPort)
	assert.Equal(t, int32(10), retrieved.OFPort)
	assert.Equal(t, TunnelStatusUp, retrieved.Status)
}

func TestTunnelDAO_Get_EmptyID(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "nonexistent")

	require.Error(t, err)
	var notFoundErr ErrTunnelNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestTunnelDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, "tunnel-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestTunnelDAO_GetByEndpoints_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		LocalIP:    netip.MustParseAddr("10.0.0.1"),
		RemoteIP:   netip.MustParseAddr("10.0.0.2"),
		VNI:        100,
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	retrieved, err := dao.GetByEndpoints(
		ctx,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		100,
	)

	require.NoError(t, err)
	assert.Equal(t, "tunnel-123", retrieved.ID)
}

func TestTunnelDAO_GetByEndpoints_NotFound(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByEndpoints(
		ctx,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.99"),
		100,
	)

	require.Error(t, err)
	var notFoundErr ErrTunnelNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestTunnelDAO_GetByEndpoints_InvalidLocalIP(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByEndpoints(
		ctx,
		netip.Addr{},
		netip.MustParseAddr("10.0.0.2"),
		100,
	)

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_GetByEndpoints_InvalidRemoteIP(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByEndpoints(
		ctx,
		netip.MustParseAddr("10.0.0.1"),
		netip.Addr{},
		100,
	)

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		LocalIP:    netip.MustParseAddr("10.0.0.1"),
		RemoteIP:   netip.MustParseAddr("10.0.0.2"),
		VNI:        100,
		Status:     TunnelStatusUp,
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	updates := &TunnelState{
		LocalIP:  netip.MustParseAddr("10.0.0.10"),
		RemoteIP: netip.MustParseAddr("10.0.0.20"),
		VNI:      200,
		Status:   TunnelStatusDown,
	}
	err := dao.Update(ctx, "tunnel-123", updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, "tunnel-123")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("10.0.0.10"), retrieved.LocalIP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.20"), retrieved.RemoteIP)
	assert.Equal(t, uint32(200), retrieved.VNI)
	assert.Equal(t, TunnelStatusDown, retrieved.Status)
	assert.Equal(t, uint64(2), retrieved.Version)
	// LocalVTEP and RemoteVTEP should be preserved
	assert.Equal(t, "vtep-1", retrieved.LocalVTEP)
	assert.Equal(t, "vtep-2", retrieved.RemoteVTEP)
}

func TestTunnelDAO_Update_EmptyID(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &TunnelState{VNI: 200}
	err := dao.Update(ctx, "", updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, "tunnel-123", nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestTunnelDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &TunnelState{VNI: 200}
	err := dao.Update(ctx, "nonexistent", updates, 1)

	require.Error(t, err)
	var notFoundErr ErrTunnelNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestTunnelDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	updates := &TunnelState{VNI: 200}
	err := dao.Update(ctx, "tunnel-123", updates, 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestTunnelDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	err := dao.Delete(ctx, "tunnel-123", 1)

	require.NoError(t, err)

	// Verify it's deleted
	_, err = dao.Get(ctx, "tunnel-123")
	var notFoundErr ErrTunnelNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestTunnelDAO_Delete_EmptyID(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "", 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "nonexistent", 1)

	require.Error(t, err)
	var notFoundErr ErrTunnelNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestTunnelDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	err := dao.Delete(ctx, "tunnel-123", 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestTunnelDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnels, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, tunnels)
}

func TestTunnelDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		tunnel := &TunnelState{
			ID:         "tunnel-" + string(rune('0'+i)),
			LocalVTEP:  "vtep-1",
			RemoteVTEP: "vtep-" + string(rune('0'+i+1)),
			VNI:        uint32(100 + i),
		}
		require.NoError(t, dao.Create(ctx, tunnel))
	}

	tunnels, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, tunnels, 5)
}

func TestTunnelDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestTunnelDAO_ListByVTEP_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnels := []*TunnelState{
		{ID: "tunnel-1", LocalVTEP: "vtep-1", RemoteVTEP: "vtep-2", VNI: 100},
		{ID: "tunnel-2", LocalVTEP: "vtep-2", RemoteVTEP: "vtep-3", VNI: 101},
		{ID: "tunnel-3", LocalVTEP: "vtep-1", RemoteVTEP: "vtep-3", VNI: 102},
		{ID: "tunnel-4", LocalVTEP: "vtep-3", RemoteVTEP: "vtep-1", VNI: 103},
	}
	for _, tun := range tunnels {
		require.NoError(t, dao.Create(ctx, tun))
	}

	vtep1Tunnels, err := dao.ListByVTEP(ctx, "vtep-1")

	require.NoError(t, err)
	assert.Len(t, vtep1Tunnels, 3) // vtep-1 is local or remote in 3 tunnels
}

func TestTunnelDAO_ListByVTEP_EmptyID(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.ListByVTEP(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_ListByVNI_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnels := []*TunnelState{
		{ID: "tunnel-1", LocalVTEP: "vtep-1", RemoteVTEP: "vtep-2", VNI: 100},
		{ID: "tunnel-2", LocalVTEP: "vtep-2", RemoteVTEP: "vtep-3", VNI: 200},
		{ID: "tunnel-3", LocalVTEP: "vtep-1", RemoteVTEP: "vtep-3", VNI: 100},
		{ID: "tunnel-4", LocalVTEP: "vtep-3", RemoteVTEP: "vtep-4", VNI: 300},
	}
	for _, tun := range tunnels {
		require.NoError(t, dao.Create(ctx, tun))
	}

	vni100Tunnels, err := dao.ListByVNI(ctx, 100)

	require.NoError(t, err)
	assert.Len(t, vni100Tunnels, 2)
	for _, tun := range vni100Tunnels {
		assert.Equal(t, uint32(100), tun.VNI)
	}
}

func TestTunnelDAO_ListByNode_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnels := []*TunnelState{
		{ID: "tunnel-1", LocalVTEP: "vtep-1", RemoteVTEP: "vtep-2", VNI: 100, NodeID: 1},
		{ID: "tunnel-2", LocalVTEP: "vtep-2", RemoteVTEP: "vtep-3", VNI: 101, NodeID: 2},
		{ID: "tunnel-3", LocalVTEP: "vtep-1", RemoteVTEP: "vtep-3", VNI: 102, NodeID: 1},
	}
	for _, tun := range tunnels {
		require.NoError(t, dao.Create(ctx, tun))
	}

	node1Tunnels, err := dao.ListByNode(ctx, 1)

	require.NoError(t, err)
	assert.Len(t, node1Tunnels, 2)
	for _, tun := range node1Tunnels {
		assert.Equal(t, uint64(1), tun.NodeID)
	}
}

func TestTunnelDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		tunnel := &TunnelState{
			ID:         "tunnel-" + string(rune('0'+i)),
			LocalVTEP:  "vtep-1",
			RemoteVTEP: "vtep-" + string(rune('0'+i+1)),
			VNI:        uint32(100 + i),
		}
		require.NoError(t, dao.Create(ctx, tunnel))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestTunnelDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	exists, err := dao.Exists(ctx, "tunnel-123")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestTunnelDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, "nonexistent")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestTunnelDAO_Exists_EmptyID(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidTunnelID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestTunnelDAO_WithStats(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	now := time.Now()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
		Stats: TunnelStats{
			BytesSent:   1000,
			BytesRecv:   2000,
			PacketsSent: 10,
			PacketsRecv: 20,
			LastUpdated: now,
		},
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	retrieved, err := dao.Get(ctx, "tunnel-123")

	require.NoError(t, err)
	assert.Equal(t, uint64(1000), retrieved.Stats.BytesSent)
	assert.Equal(t, uint64(2000), retrieved.Stats.BytesRecv)
	assert.Equal(t, uint64(10), retrieved.Stats.PacketsSent)
	assert.Equal(t, uint64(20), retrieved.Stats.PacketsRecv)
}

func TestTunnelDAO_WithExternalIDs(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tunnel := &TunnelState{
		ID:         "tunnel-123",
		LocalVTEP:  "vtep-1",
		RemoteVTEP: "vtep-2",
		VNI:        100,
		ExternalIDs: map[string]string{
			"tenant":  "acme",
			"project": "network-lab",
		},
	}
	require.NoError(t, dao.Create(ctx, tunnel))

	retrieved, err := dao.Get(ctx, "tunnel-123")

	require.NoError(t, err)
	assert.Equal(t, "acme", retrieved.ExternalIDs["tenant"])
	assert.Equal(t, "network-lab", retrieved.ExternalIDs["project"])
}

func TestTunnelDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestTunnelDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockTunnelDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, "tunnel-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
