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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockRemoteMACDAO(t *testing.T) (*RemoteMACDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger, WithRemoteMACRequestTimeout(5*time.Second))

	return dao, mock
}

func TestRemoteMACDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:          "mac-123",
		MAC:         mac,
		VNI:         100,
		RemoteVTEP:  "vtep-1",
		RemoteIP:    netip.MustParseAddr("10.0.0.1"),
		LearnedFrom: MACLearnSourceEVPN,
		NodeID:      1,
	}

	err := dao.Create(ctx, entry)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), entry.Version)
	assert.False(t, entry.LearnedAt.IsZero())
}

func TestRemoteMACDAO_Create_NilEntry(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestRemoteMACDAO_Create_EmptyID(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}

	err := dao.Create(ctx, entry)

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_Create_EmptyMAC(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        nil,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}

	err := dao.Create(ctx, entry)

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_Create_MissingRemoteVTEP(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "",
	}

	err := dao.Create(ctx, entry)

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}

	require.NoError(t, dao.Create(ctx, entry))

	// Try to create again
	entry2 := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}
	err := dao.Create(ctx, entry2)

	require.Error(t, err)
	var existsErr ErrRemoteMACAlreadyExists
	assert.ErrorAs(t, err, &existsErr)
}

func TestRemoteMACDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}

	err := dao.Create(ctx, entry)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:          "mac-123",
		MAC:         mac,
		VNI:         100,
		RemoteVTEP:  "vtep-1",
		RemoteIP:    netip.MustParseAddr("10.0.0.1"),
		LearnedFrom: MACLearnSourceEVPN,
		NodeID:      1,
	}
	require.NoError(t, dao.Create(ctx, entry))

	retrieved, err := dao.Get(ctx, "mac-123")

	require.NoError(t, err)
	assert.Equal(t, "mac-123", retrieved.ID)
	assert.Equal(t, "00:11:22:33:44:55", retrieved.MAC.String())
	assert.Equal(t, uint32(100), retrieved.VNI)
	assert.Equal(t, "vtep-1", retrieved.RemoteVTEP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), retrieved.RemoteIP)
	assert.Equal(t, MACLearnSourceEVPN, retrieved.LearnedFrom)
}

func TestRemoteMACDAO_Get_EmptyID(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "nonexistent")

	require.Error(t, err)
	var notFoundErr ErrRemoteMACNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRemoteMACDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, "mac-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_GetByMAC_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}
	require.NoError(t, dao.Create(ctx, entry))

	retrieved, err := dao.GetByMAC(ctx, mac, 100)

	require.NoError(t, err)
	assert.Equal(t, "mac-123", retrieved.ID)
	assert.Equal(t, "00:11:22:33:44:55", retrieved.MAC.String())
	assert.Equal(t, uint32(100), retrieved.VNI)
}

func TestRemoteMACDAO_GetByMAC_NotFound(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	_, err := dao.GetByMAC(ctx, mac, 100)

	require.Error(t, err)
	var notFoundErr ErrRemoteMACNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRemoteMACDAO_GetByMAC_EmptyMAC(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.GetByMAC(ctx, nil, 100)

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:          "mac-123",
		MAC:         mac,
		VNI:         100,
		RemoteVTEP:  "vtep-1",
		RemoteIP:    netip.MustParseAddr("10.0.0.1"),
		LearnedFrom: MACLearnSourceEVPN,
	}
	require.NoError(t, dao.Create(ctx, entry))

	updates := &RemoteMACState{
		RemoteVTEP:  "vtep-2",
		RemoteIP:    netip.MustParseAddr("10.0.0.2"),
		LearnedFrom: MACLearnSourceDataplane,
	}
	err := dao.Update(ctx, "mac-123", updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, "mac-123")
	require.NoError(t, err)
	assert.Equal(t, "vtep-2", retrieved.RemoteVTEP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), retrieved.RemoteIP)
	assert.Equal(t, MACLearnSourceDataplane, retrieved.LearnedFrom)
	assert.Equal(t, uint64(2), retrieved.Version)
	// MAC and VNI should be preserved
	assert.Equal(t, "00:11:22:33:44:55", retrieved.MAC.String())
	assert.Equal(t, uint32(100), retrieved.VNI)
}

func TestRemoteMACDAO_Update_EmptyID(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &RemoteMACState{RemoteVTEP: "vtep-2"}
	err := dao.Update(ctx, "", updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, "mac-123", nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestRemoteMACDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &RemoteMACState{RemoteVTEP: "vtep-2"}
	err := dao.Update(ctx, "nonexistent", updates, 1)

	require.Error(t, err)
	var notFoundErr ErrRemoteMACNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRemoteMACDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}
	require.NoError(t, dao.Create(ctx, entry))

	updates := &RemoteMACState{RemoteVTEP: "vtep-2"}
	err := dao.Update(ctx, "mac-123", updates, 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestRemoteMACDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}
	require.NoError(t, dao.Create(ctx, entry))

	err := dao.Delete(ctx, "mac-123", 1)

	require.NoError(t, err)

	// Verify it's deleted
	_, err = dao.Get(ctx, "mac-123")
	var notFoundErr ErrRemoteMACNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRemoteMACDAO_Delete_EmptyID(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "", 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "nonexistent", 1)

	require.Error(t, err)
	var notFoundErr ErrRemoteMACNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRemoteMACDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}
	require.NoError(t, dao.Create(ctx, entry))

	err := dao.Delete(ctx, "mac-123", 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestRemoteMACDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	entries, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestRemoteMACDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:5" + string(rune('0'+i)))
		entry := &RemoteMACState{
			ID:         "mac-" + string(rune('0'+i)),
			MAC:        mac,
			VNI:        uint32(100 + i),
			RemoteVTEP: "vtep-1",
		}
		require.NoError(t, dao.Create(ctx, entry))
	}

	entries, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, entries, 5)
}

func TestRemoteMACDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_ListByVNI_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")
	entries := []*RemoteMACState{
		{ID: "mac-1", MAC: mac1, VNI: 100, RemoteVTEP: "vtep-1"},
		{ID: "mac-2", MAC: mac2, VNI: 200, RemoteVTEP: "vtep-2"},
		{ID: "mac-3", MAC: mac3, VNI: 100, RemoteVTEP: "vtep-3"},
	}
	for _, e := range entries {
		require.NoError(t, dao.Create(ctx, e))
	}

	vni100Entries, err := dao.ListByVNI(ctx, 100)

	require.NoError(t, err)
	assert.Len(t, vni100Entries, 2)
	for _, e := range vni100Entries {
		assert.Equal(t, uint32(100), e.VNI)
	}
}

func TestRemoteMACDAO_ListByVTEP_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")
	entries := []*RemoteMACState{
		{ID: "mac-1", MAC: mac1, VNI: 100, RemoteVTEP: "vtep-1"},
		{ID: "mac-2", MAC: mac2, VNI: 200, RemoteVTEP: "vtep-2"},
		{ID: "mac-3", MAC: mac3, VNI: 300, RemoteVTEP: "vtep-1"},
	}
	for _, e := range entries {
		require.NoError(t, dao.Create(ctx, e))
	}

	vtep1Entries, err := dao.ListByVTEP(ctx, "vtep-1")

	require.NoError(t, err)
	assert.Len(t, vtep1Entries, 2)
	for _, e := range vtep1Entries {
		assert.Equal(t, "vtep-1", e.RemoteVTEP)
	}
}

func TestRemoteMACDAO_ListByVTEP_EmptyID(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.ListByVTEP(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidVTEPID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_ListByNode_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")
	entries := []*RemoteMACState{
		{ID: "mac-1", MAC: mac1, VNI: 100, RemoteVTEP: "vtep-1", NodeID: 1},
		{ID: "mac-2", MAC: mac2, VNI: 200, RemoteVTEP: "vtep-2", NodeID: 2},
		{ID: "mac-3", MAC: mac3, VNI: 300, RemoteVTEP: "vtep-3", NodeID: 1},
	}
	for _, e := range entries {
		require.NoError(t, dao.Create(ctx, e))
	}

	node1Entries, err := dao.ListByNode(ctx, 1)

	require.NoError(t, err)
	assert.Len(t, node1Entries, 2)
	for _, e := range node1Entries {
		assert.Equal(t, uint64(1), e.NodeID)
	}
}

func TestRemoteMACDAO_DeleteExpired_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")

	entries := []*RemoteMACState{
		{
			ID:         "mac-1",
			MAC:        mac1,
			VNI:        100,
			RemoteVTEP: "vtep-1",
			ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired
		},
		{
			ID:         "mac-2",
			MAC:        mac2,
			VNI:        200,
			RemoteVTEP: "vtep-2",
			ExpiresAt:  time.Now().Add(1 * time.Hour), // Not expired
		},
		{
			ID:         "mac-3",
			MAC:        mac3,
			VNI:        300,
			RemoteVTEP: "vtep-3",
			// No expiration - never expires
		},
	}
	for _, e := range entries {
		require.NoError(t, dao.Create(ctx, e))
	}

	deleted, err := dao.DeleteExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, 1, deleted)

	// Verify mac-1 is deleted
	_, err = dao.Get(ctx, "mac-1")
	var notFoundErr ErrRemoteMACNotFound
	assert.ErrorAs(t, err, &notFoundErr)

	// Verify mac-2 and mac-3 still exist
	_, err = dao.Get(ctx, "mac-2")
	require.NoError(t, err)

	_, err = dao.Get(ctx, "mac-3")
	require.NoError(t, err)
}

func TestRemoteMACDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		mac, _ := net.ParseMAC("00:11:22:33:44:5" + string(rune('0'+i)))
		entry := &RemoteMACState{
			ID:         "mac-" + string(rune('0'+i)),
			MAC:        mac,
			VNI:        uint32(100 + i),
			RemoteVTEP: "vtep-1",
		}
		require.NoError(t, dao.Create(ctx, entry))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestRemoteMACDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
	}
	require.NoError(t, dao.Create(ctx, entry))

	exists, err := dao.Exists(ctx, "mac-123")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestRemoteMACDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, "nonexistent")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestRemoteMACDAO_Exists_EmptyID(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidRemoteMACID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestRemoteMACDAO_WithExternalIDs(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ctx := context.Background()
	entry := &RemoteMACState{
		ID:         "mac-123",
		MAC:        mac,
		VNI:        100,
		RemoteVTEP: "vtep-1",
		ExternalIDs: map[string]string{
			"source":  "bgp",
			"cluster": "dc1",
		},
	}
	require.NoError(t, dao.Create(ctx, entry))

	retrieved, err := dao.Get(ctx, "mac-123")

	require.NoError(t, err)
	assert.Equal(t, "bgp", retrieved.ExternalIDs["source"])
	assert.Equal(t, "dc1", retrieved.ExternalIDs["cluster"])
}

func TestRemoteMACDAO_WithLearnSources(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	mac3, _ := net.ParseMAC("00:11:22:33:44:77")

	entries := []*RemoteMACState{
		{ID: "mac-1", MAC: mac1, VNI: 100, RemoteVTEP: "vtep-1", LearnedFrom: MACLearnSourceEVPN},
		{ID: "mac-2", MAC: mac2, VNI: 200, RemoteVTEP: "vtep-2", LearnedFrom: MACLearnSourceDataplane},
		{ID: "mac-3", MAC: mac3, VNI: 300, RemoteVTEP: "vtep-3", LearnedFrom: MACLearnSourceStatic},
	}
	for _, e := range entries {
		require.NoError(t, dao.Create(ctx, e))
	}

	e1, err := dao.Get(ctx, "mac-1")
	require.NoError(t, err)
	assert.Equal(t, MACLearnSourceEVPN, e1.LearnedFrom)

	e2, err := dao.Get(ctx, "mac-2")
	require.NoError(t, err)
	assert.Equal(t, MACLearnSourceDataplane, e2.LearnedFrom)

	e3, err := dao.Get(ctx, "mac-3")
	require.NoError(t, err)
	assert.Equal(t, MACLearnSourceStatic, e3.LearnedFrom)
}

func TestRemoteMACDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, "remotemac-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_ListByVNI_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByVNI(ctx, 100)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_ListByVTEP_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByVTEP(ctx, "vtep-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_ListByNode_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByNode(ctx, 1)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestRemoteMACDAO_DeleteExpired_StorageError(t *testing.T) {
	dao, mock := setupMockRemoteMACDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.DeleteExpired(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
