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

func setupMockFlowDAO(t *testing.T) (*FlowDAO, *quicbaas.MockStorage) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger, WithFlowRequestTimeout(5*time.Second))

	return dao, mock
}

func TestFlowDAO_Create_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Table:    0,
		Priority: 100,
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}

	err := dao.Create(ctx, flow)

	require.NoError(t, err)
	assert.Equal(t, uint64(1), flow.Version)
	assert.False(t, flow.CreatedAt.IsZero())
	assert.False(t, flow.UpdatedAt.IsZero())
}

func TestFlowDAO_Create_NilFlow(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Create(ctx, nil)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestFlowDAO_Create_EmptyFlowID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "",
		BridgeID: "br-test",
	}

	err := dao.Create(ctx, flow)

	require.Error(t, err)
	var invalidIDErr ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Create_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "",
	}

	err := dao.Create(ctx, flow)

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Create_AlreadyExists(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Table:    0,
		Priority: 100,
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	flow2 := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Table:    1,
		Priority: 200,
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionDrop}},
	}
	err := dao.Create(ctx, flow2)

	require.Error(t, err)
	var existsErr ErrFlowAlreadyExists
	assert.ErrorAs(t, err, &existsErr)
}

func TestFlowDAO_Create_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}

	err := dao.Create(ctx, flow)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestFlowDAO_Get_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	inPort := uint32(1)
	ethType := uint16(0x0800)
	flow := &FlowState{
		ID:          "flow-123",
		BridgeID:    "br-test",
		Table:       0,
		Priority:    100,
		Cookie:      0xABCD,
		IdleTimeout: 30,
		HardTimeout: 300,
		Match: &FlowMatch{
			InPort:  &inPort,
			EthType: &ethType,
		},
		Actions: []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	retrieved, err := dao.Get(ctx, "br-test", "flow-123")

	require.NoError(t, err)
	assert.Equal(t, "flow-123", retrieved.ID)
	assert.Equal(t, "br-test", retrieved.BridgeID)
	assert.Equal(t, uint8(0), retrieved.Table)
	assert.Equal(t, uint16(100), retrieved.Priority)
	assert.Equal(t, uint64(0xABCD), retrieved.Cookie)
	assert.Equal(t, uint16(30), retrieved.IdleTimeout)
	assert.Equal(t, uint16(300), retrieved.HardTimeout)
	assert.NotNil(t, retrieved.Match)
	assert.Equal(t, uint32(1), *retrieved.Match.InPort)
}

func TestFlowDAO_Get_EmptyFlowID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "br-test", "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Get_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "", "flow-123")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Get_NotFound(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, "br-test", "nonexistent")

	require.Error(t, err)
	var notFoundErr ErrFlowNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestFlowDAO_Get_WrongBridge(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	// Try to get with wrong bridge ID
	_, err := dao.Get(ctx, "br-2", "flow-123")

	require.Error(t, err)
	var notFoundErr ErrFlowNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestFlowDAO_Get_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, "br-test", "flow-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestFlowDAO_Update_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Table:    0,
		Priority: 100,
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	updates := &FlowState{
		Table:    1,
		Priority: 200,
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionDrop}},
	}
	err := dao.Update(ctx, "br-test", "flow-123", updates, 1)

	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, "br-test", "flow-123")
	require.NoError(t, err)
	assert.Equal(t, uint8(1), retrieved.Table)
	assert.Equal(t, uint16(200), retrieved.Priority)
	assert.Equal(t, ActionDrop, retrieved.Actions[0].Type)
	assert.Equal(t, uint64(2), retrieved.Version)
}

func TestFlowDAO_Update_EmptyFlowID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &FlowState{Priority: 200}
	err := dao.Update(ctx, "br-test", "", updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Update_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &FlowState{Priority: 200}
	err := dao.Update(ctx, "", "flow-123", updates, 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Update_NilUpdates(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Update(ctx, "br-test", "flow-123", nil, 1)

	require.Error(t, err)
	var nilErr ErrNilEntity
	assert.ErrorAs(t, err, &nilErr)
}

func TestFlowDAO_Update_NotFound(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	updates := &FlowState{Priority: 200}
	err := dao.Update(ctx, "br-test", "nonexistent", updates, 1)

	require.Error(t, err)
	var notFoundErr ErrFlowNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestFlowDAO_Update_WrongBridge(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	updates := &FlowState{Priority: 200}
	err := dao.Update(ctx, "br-2", "flow-123", updates, 1)

	require.Error(t, err)
	var notFoundErr ErrFlowNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestFlowDAO_Update_VersionConflict(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	updates := &FlowState{Priority: 200}
	err := dao.Update(ctx, "br-test", "flow-123", updates, 99)

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
	assert.Equal(t, uint64(99), conflictErr.ExpectedVersion)
	assert.Equal(t, uint64(1), conflictErr.ActualVersion)
}

func TestFlowDAO_Delete_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	err := dao.Delete(ctx, "br-test", "flow-123", 1)

	require.NoError(t, err)

	_, err = dao.Get(ctx, "br-test", "flow-123")
	var notFoundErr ErrFlowNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestFlowDAO_Delete_EmptyFlowID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "br-test", "", 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Delete_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "", "flow-123", 1)

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Delete_NotFound(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	err := dao.Delete(ctx, "br-test", "nonexistent", 1)

	require.Error(t, err)
	var notFoundErr ErrFlowNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestFlowDAO_Delete_WrongBridge(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	err := dao.Delete(ctx, "br-2", "flow-123", 1)

	require.Error(t, err)
	var notFoundErr ErrFlowNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestFlowDAO_Delete_VersionConflict(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	err := dao.Delete(ctx, "br-test", "flow-123", 99)

	require.Error(t, err)
	var conflictErr ErrVersionConflict
	assert.ErrorAs(t, err, &conflictErr)
}

func TestFlowDAO_List_Empty(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flows, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, flows)
}

func TestFlowDAO_List_Multiple(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		flow := &FlowState{
			ID:       "flow-" + string(rune('0'+i)),
			BridgeID: "br-test",
			Match:    &FlowMatch{},
			Actions:  []*FlowAction{{Type: ActionNormal}},
		}
		require.NoError(t, dao.Create(ctx, flow))
	}

	flows, err := dao.List(ctx)

	require.NoError(t, err)
	assert.Len(t, flows, 5)
}

func TestFlowDAO_List_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.List(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestFlowDAO_ListByBridge_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flows := []*FlowState{
		{ID: "flow-1", BridgeID: "br-1", Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-2", BridgeID: "br-2", Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-3", BridgeID: "br-1", Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-4", BridgeID: "br-2", Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
	}
	for _, f := range flows {
		require.NoError(t, dao.Create(ctx, f))
	}

	br1Flows, err := dao.ListByBridge(ctx, "br-1")

	require.NoError(t, err)
	assert.Len(t, br1Flows, 2)
	for _, f := range br1Flows {
		assert.Equal(t, "br-1", f.BridgeID)
	}
}

func TestFlowDAO_ListByBridge_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.ListByBridge(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_ListByBridgeAndTable_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flows := []*FlowState{
		{ID: "flow-1", BridgeID: "br-1", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-2", BridgeID: "br-1", Table: 1, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-3", BridgeID: "br-1", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-4", BridgeID: "br-2", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
	}
	for _, f := range flows {
		require.NoError(t, dao.Create(ctx, f))
	}

	table0Flows, err := dao.ListByBridgeAndTable(ctx, "br-1", 0)

	require.NoError(t, err)
	assert.Len(t, table0Flows, 2)
	for _, f := range table0Flows {
		assert.Equal(t, "br-1", f.BridgeID)
		assert.Equal(t, uint8(0), f.Table)
	}
}

func TestFlowDAO_ListByBridgeAndTable_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.ListByBridgeAndTable(ctx, "", 0)

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Count_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		flow := &FlowState{
			ID:       "flow-" + string(rune('0'+i)),
			BridgeID: "br-test",
			Match:    &FlowMatch{},
			Actions:  []*FlowAction{{Type: ActionNormal}},
		}
		require.NoError(t, dao.Create(ctx, flow))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestFlowDAO_CountByBridge_Success(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flows := []*FlowState{
		{ID: "flow-1", BridgeID: "br-1", Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-2", BridgeID: "br-2", Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
		{ID: "flow-3", BridgeID: "br-1", Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}},
	}
	for _, f := range flows {
		require.NoError(t, dao.Create(ctx, f))
	}

	count, err := dao.CountByBridge(ctx, "br-1")

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestFlowDAO_CountByBridge_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.CountByBridge(ctx, "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Exists_True(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	exists, err := dao.Exists(ctx, "br-test", "flow-123")

	require.NoError(t, err)
	assert.True(t, exists)
}

func TestFlowDAO_Exists_False(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	exists, err := dao.Exists(ctx, "br-test", "nonexistent")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestFlowDAO_Exists_WrongBridge(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	exists, err := dao.Exists(ctx, "br-2", "flow-123")

	require.NoError(t, err)
	assert.False(t, exists)
}

func TestFlowDAO_Exists_EmptyFlowID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, "br-test", "")

	require.Error(t, err)
	var invalidIDErr ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_Exists_EmptyBridgeID(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Exists(ctx, "", "flow-123")

	require.Error(t, err)
	var invalidIDErr ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestFlowDAO_WithComplexMatch(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	inPort := uint32(1)
	ethType := uint16(0x0800)
	ipProto := uint8(6)
	tcpDst := uint16(80)

	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Table:    0,
		Priority: 100,
		Match: &FlowMatch{
			InPort:  &inPort,
			EthSrc:  "00:11:22:33:44:55",
			EthDst:  "66:77:88:99:aa:bb",
			EthType: &ethType,
			IPv4Src: "192.168.1.0/24",
			IPv4Dst: "10.0.0.1",
			IPProto: &ipProto,
			TCPDst:  &tcpDst,
		},
		Actions: []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, dao.Create(ctx, flow))

	retrieved, err := dao.Get(ctx, "br-test", "flow-123")

	require.NoError(t, err)
	assert.Equal(t, uint32(1), *retrieved.Match.InPort)
	assert.Equal(t, "00:11:22:33:44:55", retrieved.Match.EthSrc)
	assert.Equal(t, "66:77:88:99:aa:bb", retrieved.Match.EthDst)
	assert.Equal(t, uint16(0x0800), *retrieved.Match.EthType)
	assert.Equal(t, "192.168.1.0/24", retrieved.Match.IPv4Src)
	assert.Equal(t, "10.0.0.1", retrieved.Match.IPv4Dst)
	assert.Equal(t, uint8(6), *retrieved.Match.IPProto)
	assert.Equal(t, uint16(80), *retrieved.Match.TCPDst)
}

func TestFlowDAO_WithMultipleActions(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	outPort := uint32(2)
	vlanVid := uint16(100)
	table := uint8(1)

	flow := &FlowState{
		ID:       "flow-123",
		BridgeID: "br-test",
		Table:    0,
		Priority: 100,
		Match:    &FlowMatch{},
		Actions: []*FlowAction{
			{Type: ActionSetVLAN, VLANVid: &vlanVid},
			{Type: ActionOutput, Port: &outPort},
			{Type: ActionGotoTable, Table: &table},
		},
	}
	require.NoError(t, dao.Create(ctx, flow))

	retrieved, err := dao.Get(ctx, "br-test", "flow-123")

	require.NoError(t, err)
	assert.Len(t, retrieved.Actions, 3)
	assert.Equal(t, ActionSetVLAN, retrieved.Actions[0].Type)
	assert.Equal(t, uint16(100), *retrieved.Actions[0].VLANVid)
	assert.Equal(t, ActionOutput, retrieved.Actions[1].Type)
	assert.Equal(t, uint32(2), *retrieved.Actions[1].Port)
	assert.Equal(t, ActionGotoTable, retrieved.Actions[2].Type)
	assert.Equal(t, uint8(1), *retrieved.Actions[2].Table)
}

// Additional flow DAO tests for edge cases

func TestFlowDAO_ListByBridgeAndTable_Empty(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger, WithFlowRequestTimeout(5*time.Second))

	ctx := context.Background()
	flows, err := dao.ListByBridgeAndTable(ctx, "br-1", 0)

	require.NoError(t, err)
	assert.Empty(t, flows)
}

func TestFlowDAO_ListByBridgeAndTable_WithFlows(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger, WithFlowRequestTimeout(5*time.Second))

	ctx := context.Background()

	// Create flows for different tables
	flow1 := &FlowState{ID: "flow-1", BridgeID: "br-1", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}}
	flow2 := &FlowState{ID: "flow-2", BridgeID: "br-1", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}}
	flow3 := &FlowState{ID: "flow-3", BridgeID: "br-1", Table: 1, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}}
	require.NoError(t, dao.Create(ctx, flow1))
	require.NoError(t, dao.Create(ctx, flow2))
	require.NoError(t, dao.Create(ctx, flow3))

	// List flows for table 0
	flows, err := dao.ListByBridgeAndTable(ctx, "br-1", 0)
	require.NoError(t, err)
	assert.Len(t, flows, 2)

	// List flows for table 1
	flows2, err := dao.ListByBridgeAndTable(ctx, "br-1", 1)
	require.NoError(t, err)
	assert.Len(t, flows2, 1)
}

func TestFlowDAO_CountByBridge(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger, WithFlowRequestTimeout(5*time.Second))

	ctx := context.Background()

	// Create flows for different bridges
	flow1 := &FlowState{ID: "flow-1", BridgeID: "br-1", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}}
	flow2 := &FlowState{ID: "flow-2", BridgeID: "br-1", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}}
	flow3 := &FlowState{ID: "flow-3", BridgeID: "br-2", Table: 0, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionNormal}}}
	require.NoError(t, dao.Create(ctx, flow1))
	require.NoError(t, dao.Create(ctx, flow2))
	require.NoError(t, dao.Create(ctx, flow3))

	// Count flows for br-1
	count1, err := dao.CountByBridge(ctx, "br-1")
	require.NoError(t, err)
	assert.Equal(t, 2, count1)

	// Count flows for br-2
	count2, err := dao.CountByBridge(ctx, "br-2")
	require.NoError(t, err)
	assert.Equal(t, 1, count2)
}

func TestFlowDAO_Count_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestFlowDAO_Exists_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Exists(ctx, "br-test", "flow-123")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestFlowDAO_ListByBridge_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByBridge(ctx, "br-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestFlowDAO_ListByBridgeAndTable_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.ListByBridgeAndTable(ctx, "br-test", 0)

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestFlowDAO_CountByBridge_StorageError(t *testing.T) {
	dao, mock := setupMockFlowDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.CountByBridge(ctx, "br-test")

	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}
