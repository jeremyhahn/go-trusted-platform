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

func setupMockBridgeDAO(t *testing.T) (*BridgeDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewBridgeDAO(mock, logger, WithBridgeRequestTimeout(5*time.Second))

	return dao, mock
}

func TestBridgeDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:           "br-test-123",
		Name:         "test-bridge",
		DatapathType: "system",
		NodeID:       1,
	}

	err := dao.Create(ctx, bridge)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), bridge.Version)
	assert.False(t, bridge.CreatedAt.IsZero())
	assert.False(t, bridge.UpdatedAt.IsZero())
}

func TestBridgeDAO_Create_NilBridge(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestBridgeDAO_Create_EmptyID(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "",
		Name: "test-bridge",
	}

	err := dao.Create(ctx, bridge)

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestBridgeDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge",
	}

	require.NoError(t, dao.Create(ctx, bridge))

	// Try to create again
	bridge2 := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge-2",
	}
	err := dao.Create(ctx, bridge2)

	require.Error(t, err)
	var existsErr ErrBridgeAlreadyExists
	assert.ErrorAs(t, err, &existsErr)
}

func TestBridgeDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge",
	}

	err := dao.Create(ctx, bridge)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestBridgeDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:           "br-test-123",
		Name:         "test-bridge",
		DatapathType: "system",
		NodeID:       1,
		STPEnabled:   true,
	}
	require.NoError(t, dao.Create(ctx, bridge))

	retrieved, err := dao.Get(ctx, "br-test-123")

	require.NoError(t, err)
	assert.Equal(t, "br-test-123", retrieved.ID)
	assert.Equal(t, "test-bridge", retrieved.Name)
	assert.Equal(t, "system", retrieved.DatapathType)
	assert.Equal(t, uint64(1), retrieved.NodeID)
	assert.True(t, retrieved.STPEnabled)
}

func TestBridgeDAO_Get_EmptyID(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestBridgeDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "nonexistent")

	require.Error(t, err)
	var notFoundErr ErrBridgeNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestBridgeDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, "br-test-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestBridgeDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:           "br-test-123",
		Name:         "test-bridge",
		DatapathType: "system",
		NodeID:       1,
	}
	require.NoError(t, dao.Create(ctx, bridge))

	updates := &BridgeState{
		Name:         "updated-bridge",
		DatapathType: "netdev",
		STPEnabled:   true,
	}
	err := dao.Update(ctx, "br-test-123", updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, "br-test-123")
	require.NoError(t, err)
	assert.Equal(t, "updated-bridge", retrieved.Name)
	assert.Equal(t, "netdev", retrieved.DatapathType)
	assert.True(t, retrieved.STPEnabled)
	assert.Equal(t, uint64(2), retrieved.Version)
}

func TestBridgeDAO_Update_EmptyID(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &BridgeState{Name: "updated"}
	err := dao.Update(ctx, "", updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestBridgeDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, "br-test-123", nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestBridgeDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &BridgeState{Name: "updated"}
	err := dao.Update(ctx, "nonexistent", updates, 1)

	require.Error(t, err)
	var notFoundErr ErrBridgeNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestBridgeDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge",
	}
	require.NoError(t, dao.Create(ctx, bridge))

	updates := &BridgeState{Name: "updated"}
	err := dao.Update(ctx, "br-test-123", updates, 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestBridgeDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge",
	}
	require.NoError(t, dao.Create(ctx, bridge))

	err := dao.Delete(ctx, "br-test-123", 1)

	require.NoError(t, err)

	// Verify it's deleted
	_, err = dao.Get(ctx, "br-test-123")
	var notFoundErr ErrBridgeNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestBridgeDAO_Delete_EmptyID(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "", 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestBridgeDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "nonexistent", 1)

	require.Error(t, err)
	var notFoundErr ErrBridgeNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestBridgeDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge",
	}
	require.NoError(t, dao.Create(ctx, bridge))

	err := dao.Delete(ctx, "br-test-123", 99) // Wrong version

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestBridgeDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridges, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, bridges)
}

func TestBridgeDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		bridge := &BridgeState{
			ID:   "br-test-" + string(rune('0'+i)),
			Name: "test-bridge",
		}
		require.NoError(t, dao.Create(ctx, bridge))
	}

	bridges, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, bridges, 5)
}

func TestBridgeDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestBridgeDAO_ListByNode_Success(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridges := []*BridgeState{
		{ID: "br-1", Name: "bridge1", NodeID: 1},
		{ID: "br-2", Name: "bridge2", NodeID: 2},
		{ID: "br-3", Name: "bridge3", NodeID: 1},
		{ID: "br-4", Name: "bridge4", NodeID: 2},
	}
	for _, b := range bridges {
		require.NoError(t, dao.Create(ctx, b))
	}

	node1Bridges, err := dao.ListByNode(ctx, 1)

	require.NoError(t, err)
	assert.Len(t, node1Bridges, 2)
	for _, b := range node1Bridges {
		assert.Equal(t, uint64(1), b.NodeID)
	}
}

func TestBridgeDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		bridge := &BridgeState{
			ID:   "br-test-" + string(rune('0'+i)),
			Name: "test-bridge",
		}
		require.NoError(t, dao.Create(ctx, bridge))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestBridgeDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge",
	}
	require.NoError(t, dao.Create(ctx, bridge))

	exists, err := dao.Exists(ctx, "br-test-123")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestBridgeDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, "nonexistent")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestBridgeDAO_Exists_EmptyID(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestBridgeDAO_WithExternalIDs(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:   "br-test-123",
		Name: "test-bridge",
		ExternalIDs: map[string]string{
			"tenant":  "acme",
			"project": "network-lab",
		},
	}
	require.NoError(t, dao.Create(ctx, bridge))

	retrieved, err := dao.Get(ctx, "br-test-123")

	require.NoError(t, err)
	assert.Equal(t, "acme", retrieved.ExternalIDs["tenant"])
	assert.Equal(t, "network-lab", retrieved.ExternalIDs["project"])
}

func TestBridgeDAO_WithControllers(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	bridge := &BridgeState{
		ID:            "br-test-123",
		Name:          "test-bridge",
		Controllers:   []string{"tcp:127.0.0.1:6653", "tcp:127.0.0.1:6654"},
		FlowProtocols: []string{"OpenFlow13", "OpenFlow15"},
		FailMode:      "secure",
	}
	require.NoError(t, dao.Create(ctx, bridge))

	retrieved, err := dao.Get(ctx, "br-test-123")

	require.NoError(t, err)
	assert.Len(t, retrieved.Controllers, 2)
	assert.Len(t, retrieved.FlowProtocols, 2)
	assert.Equal(t, "secure", retrieved.FailMode)
}

// Additional DAO tests for edge cases

func TestBridgeDAO_ListByNode_Empty(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewBridgeDAO(mock, logger, WithBridgeRequestTimeout(5*time.Second))

	ctx := context.Background()
	bridges, err := dao.ListByNode(ctx, 1)

	require.NoError(t, err)
	assert.Empty(t, bridges)
}

func TestBridgeDAO_ListByNode_WithBridges(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewBridgeDAO(mock, logger, WithBridgeRequestTimeout(5*time.Second))

	ctx := context.Background()

	// Create bridges for different nodes
	bridge1 := &BridgeState{ID: "br-1", Name: "bridge1", NodeID: 1}
	bridge2 := &BridgeState{ID: "br-2", Name: "bridge2", NodeID: 1}
	bridge3 := &BridgeState{ID: "br-3", Name: "bridge3", NodeID: 2}
	require.NoError(t, dao.Create(ctx, bridge1))
	require.NoError(t, dao.Create(ctx, bridge2))
	require.NoError(t, dao.Create(ctx, bridge3))

	// List bridges for node 1
	bridges, err := dao.ListByNode(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, bridges, 2)

	// List bridges for node 2
	bridges2, err := dao.ListByNode(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, bridges2, 1)
}

func TestBridgeDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestBridgeDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, "br-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestBridgeDAO_ListByNode_StorageError(t *testing.T) {
	dao, mock := setupMockBridgeDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByNode(ctx, 1)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
