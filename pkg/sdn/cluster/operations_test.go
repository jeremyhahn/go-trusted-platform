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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Bridge Operations Tests

func TestCreateBridgeOp_Type(t *testing.T) {
	op := NewCreateBridgeOp(&BridgeState{ID: "br-1", Name: "bridge1"}, 1)
	assert.Equal(t, OpTypeCreateBridge, op.Type())
}

func TestCreateBridgeOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewCreateBridgeOp(&BridgeState{ID: "br-1", Name: "bridge1"}, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestCreateBridgeOp_NodeID(t *testing.T) {
	op := NewCreateBridgeOp(&BridgeState{ID: "br-1", Name: "bridge1"}, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestCreateBridgeOp_Validate_Success(t *testing.T) {
	op := NewCreateBridgeOp(&BridgeState{ID: "br-1", Name: "bridge1"}, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestCreateBridgeOp_Validate_NilBridge(t *testing.T) {
	op := NewCreateBridgeOp(nil, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateBridgeOp_Validate_EmptyID(t *testing.T) {
	op := NewCreateBridgeOp(&BridgeState{ID: "", Name: "bridge1"}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidID)
}

func TestCreateBridgeOp_Validate_EmptyName(t *testing.T) {
	op := NewCreateBridgeOp(&BridgeState{ID: "br-1", Name: ""}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateBridgeOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	op := NewCreateBridgeOp(bridge, 1)

	err := op.Execute(context.Background(), sm)

	require.NoError(t, err)
	retrieved, err := sm.GetBridge(context.Background(), "br-1")
	require.NoError(t, err)
	assert.Equal(t, "bridge1", retrieved.Name)
}

func TestUpdateBridgeOp_Type(t *testing.T) {
	op := NewUpdateBridgeOp("br-1", &BridgeState{Name: "updated"}, 1, 1)
	assert.Equal(t, OpTypeUpdateBridge, op.Type())
}

func TestUpdateBridgeOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewUpdateBridgeOp("br-1", &BridgeState{Name: "updated"}, 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestUpdateBridgeOp_NodeID(t *testing.T) {
	op := NewUpdateBridgeOp("br-1", &BridgeState{Name: "updated"}, 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestUpdateBridgeOp_Validate_Success(t *testing.T) {
	op := NewUpdateBridgeOp("br-1", &BridgeState{Name: "updated"}, 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestUpdateBridgeOp_Validate_EmptyID(t *testing.T) {
	op := NewUpdateBridgeOp("", &BridgeState{Name: "updated"}, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidID)
}

func TestUpdateBridgeOp_Validate_NilUpdates(t *testing.T) {
	op := NewUpdateBridgeOp("br-1", nil, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestUpdateBridgeOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create initial bridge
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))

	// Update
	op := NewUpdateBridgeOp("br-1", &BridgeState{Name: "updated"}, 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	retrieved, err := sm.GetBridge(ctx, "br-1")
	require.NoError(t, err)
	assert.Equal(t, "updated", retrieved.Name)
}

func TestDeleteBridgeOp_Type(t *testing.T) {
	op := NewDeleteBridgeOp("br-1", 1, 1)
	assert.Equal(t, OpTypeDeleteBridge, op.Type())
}

func TestDeleteBridgeOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewDeleteBridgeOp("br-1", 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestDeleteBridgeOp_NodeID(t *testing.T) {
	op := NewDeleteBridgeOp("br-1", 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestDeleteBridgeOp_Validate_Success(t *testing.T) {
	op := NewDeleteBridgeOp("br-1", 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestDeleteBridgeOp_Validate_EmptyID(t *testing.T) {
	op := NewDeleteBridgeOp("", 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidBridgeID
	assert.ErrorAs(t, err, &invalidID)
}

func TestDeleteBridgeOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create initial bridge
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))

	// Delete
	op := NewDeleteBridgeOp("br-1", 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	_, err = sm.GetBridge(ctx, "br-1")
	var notFound ErrBridgeNotFound
	assert.ErrorAs(t, err, &notFound)
}

// Port Operations Tests

func TestCreatePortOp_Type(t *testing.T) {
	op := NewCreatePortOp(&PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}, 1)
	assert.Equal(t, OpTypeCreatePort, op.Type())
}

func TestCreatePortOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewCreatePortOp(&PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestCreatePortOp_NodeID(t *testing.T) {
	op := NewCreatePortOp(&PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestCreatePortOp_Validate_Success(t *testing.T) {
	op := NewCreatePortOp(&PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestCreatePortOp_Validate_NilPort(t *testing.T) {
	op := NewCreatePortOp(nil, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreatePortOp_Validate_EmptyID(t *testing.T) {
	op := NewCreatePortOp(&PortState{ID: "", Name: "eth0", BridgeID: "br-1"}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidID)
}

func TestCreatePortOp_Validate_EmptyName(t *testing.T) {
	op := NewCreatePortOp(&PortState{ID: "port-1", Name: "", BridgeID: "br-1"}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreatePortOp_Validate_EmptyBridgeID(t *testing.T) {
	op := NewCreatePortOp(&PortState{ID: "port-1", Name: "eth0", BridgeID: ""}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreatePortOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create bridge first
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))

	// Create port
	port := &PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}
	op := NewCreatePortOp(port, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	retrieved, err := sm.GetPort(ctx, "port-1")
	require.NoError(t, err)
	assert.Equal(t, "eth0", retrieved.Name)
}

func TestUpdatePortOp_Type(t *testing.T) {
	op := NewUpdatePortOp("port-1", &PortState{Name: "updated"}, 1, 1)
	assert.Equal(t, OpTypeUpdatePort, op.Type())
}

func TestUpdatePortOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewUpdatePortOp("port-1", &PortState{Name: "updated"}, 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestUpdatePortOp_NodeID(t *testing.T) {
	op := NewUpdatePortOp("port-1", &PortState{Name: "updated"}, 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestUpdatePortOp_Validate_Success(t *testing.T) {
	op := NewUpdatePortOp("port-1", &PortState{Name: "updated"}, 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestUpdatePortOp_Validate_EmptyID(t *testing.T) {
	op := NewUpdatePortOp("", &PortState{Name: "updated"}, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidID)
}

func TestUpdatePortOp_Validate_NilUpdates(t *testing.T) {
	op := NewUpdatePortOp("port-1", nil, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestUpdatePortOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create bridge and port
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))
	port := &PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}
	require.NoError(t, sm.CreatePort(ctx, port))

	// Update
	op := NewUpdatePortOp("port-1", &PortState{Name: "updated", BridgeID: "br-1"}, 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	retrieved, err := sm.GetPort(ctx, "port-1")
	require.NoError(t, err)
	assert.Equal(t, "updated", retrieved.Name)
}

func TestDeletePortOp_Type(t *testing.T) {
	op := NewDeletePortOp("port-1", 1, 1)
	assert.Equal(t, OpTypeDeletePort, op.Type())
}

func TestDeletePortOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewDeletePortOp("port-1", 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestDeletePortOp_NodeID(t *testing.T) {
	op := NewDeletePortOp("port-1", 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestDeletePortOp_Validate_Success(t *testing.T) {
	op := NewDeletePortOp("port-1", 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestDeletePortOp_Validate_EmptyID(t *testing.T) {
	op := NewDeletePortOp("", 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidPortID
	assert.ErrorAs(t, err, &invalidID)
}

func TestDeletePortOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create bridge and port
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))
	port := &PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}
	require.NoError(t, sm.CreatePort(ctx, port))

	// Delete
	op := NewDeletePortOp("port-1", 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	_, err = sm.GetPort(ctx, "port-1")
	var notFound ErrPortNotFound
	assert.ErrorAs(t, err, &notFound)
}

// Flow Operations Tests

func TestCreateFlowOp_Type(t *testing.T) {
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	op := NewCreateFlowOp(flow, 1)
	assert.Equal(t, OpTypeCreateFlow, op.Type())
}

func TestCreateFlowOp_Timestamp(t *testing.T) {
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	before := time.Now()
	op := NewCreateFlowOp(flow, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestCreateFlowOp_NodeID(t *testing.T) {
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	op := NewCreateFlowOp(flow, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestCreateFlowOp_Validate_Success(t *testing.T) {
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	op := NewCreateFlowOp(flow, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestCreateFlowOp_Validate_NilFlow(t *testing.T) {
	op := NewCreateFlowOp(nil, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateFlowOp_Validate_EmptyID(t *testing.T) {
	flow := &FlowState{
		ID:       "",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	op := NewCreateFlowOp(flow, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidID)
}

func TestCreateFlowOp_Validate_EmptyBridgeID(t *testing.T) {
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	op := NewCreateFlowOp(flow, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateFlowOp_Validate_NilMatch(t *testing.T) {
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    nil,
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	op := NewCreateFlowOp(flow, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateFlowOp_Validate_EmptyActions(t *testing.T) {
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{},
	}
	op := NewCreateFlowOp(flow, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateFlowOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create bridge first
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))

	// Create flow
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	op := NewCreateFlowOp(flow, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	retrieved, err := sm.GetFlow(ctx, "br-1", "flow-1")
	require.NoError(t, err)
	assert.Equal(t, "flow-1", retrieved.ID)
}

func TestUpdateFlowOp_Type(t *testing.T) {
	op := NewUpdateFlowOp("br-1", "flow-1", &FlowState{Priority: 100}, 1, 1)
	assert.Equal(t, OpTypeUpdateFlow, op.Type())
}

func TestUpdateFlowOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewUpdateFlowOp("br-1", "flow-1", &FlowState{Priority: 100}, 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestUpdateFlowOp_NodeID(t *testing.T) {
	op := NewUpdateFlowOp("br-1", "flow-1", &FlowState{Priority: 100}, 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestUpdateFlowOp_Validate_Success(t *testing.T) {
	op := NewUpdateFlowOp("br-1", "flow-1", &FlowState{Priority: 100}, 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestUpdateFlowOp_Validate_EmptyFlowID(t *testing.T) {
	op := NewUpdateFlowOp("br-1", "", &FlowState{Priority: 100}, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidID)
}

func TestUpdateFlowOp_Validate_EmptyBridgeID(t *testing.T) {
	op := NewUpdateFlowOp("", "flow-1", &FlowState{Priority: 100}, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestUpdateFlowOp_Validate_NilUpdates(t *testing.T) {
	op := NewUpdateFlowOp("br-1", "flow-1", nil, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestUpdateFlowOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create bridge and flow
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Priority: 50,
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, sm.CreateFlow(ctx, flow))

	// Update
	op := NewUpdateFlowOp("br-1", "flow-1", &FlowState{Priority: 100, Match: &FlowMatch{}, Actions: []*FlowAction{{Type: ActionDrop}}}, 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	retrieved, err := sm.GetFlow(ctx, "br-1", "flow-1")
	require.NoError(t, err)
	assert.Equal(t, uint16(100), retrieved.Priority)
}

func TestDeleteFlowOp_Type(t *testing.T) {
	op := NewDeleteFlowOp("br-1", "flow-1", 1, 1)
	assert.Equal(t, OpTypeDeleteFlow, op.Type())
}

func TestDeleteFlowOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewDeleteFlowOp("br-1", "flow-1", 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestDeleteFlowOp_NodeID(t *testing.T) {
	op := NewDeleteFlowOp("br-1", "flow-1", 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestDeleteFlowOp_Validate_Success(t *testing.T) {
	op := NewDeleteFlowOp("br-1", "flow-1", 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestDeleteFlowOp_Validate_EmptyFlowID(t *testing.T) {
	op := NewDeleteFlowOp("br-1", "", 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidFlowID
	assert.ErrorAs(t, err, &invalidID)
}

func TestDeleteFlowOp_Validate_EmptyBridgeID(t *testing.T) {
	op := NewDeleteFlowOp("", "flow-1", 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestDeleteFlowOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create bridge and flow
	bridge := &BridgeState{ID: "br-1", Name: "bridge1"}
	require.NoError(t, sm.CreateBridge(ctx, bridge))
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "br-1",
		Match:    &FlowMatch{},
		Actions:  []*FlowAction{{Type: ActionNormal}},
	}
	require.NoError(t, sm.CreateFlow(ctx, flow))

	// Delete
	op := NewDeleteFlowOp("br-1", "flow-1", 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	_, err = sm.GetFlow(ctx, "br-1", "flow-1")
	var notFound ErrFlowNotFound
	assert.ErrorAs(t, err, &notFound)
}

// VLAN Operations Tests

func TestCreateVLANOp_Type(t *testing.T) {
	op := NewCreateVLANOp(&VLANState{ID: 100, Name: "production"}, 1)
	assert.Equal(t, OpTypeCreateVLAN, op.Type())
}

func TestCreateVLANOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewCreateVLANOp(&VLANState{ID: 100, Name: "production"}, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestCreateVLANOp_NodeID(t *testing.T) {
	op := NewCreateVLANOp(&VLANState{ID: 100, Name: "production"}, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestCreateVLANOp_Validate_Success(t *testing.T) {
	op := NewCreateVLANOp(&VLANState{ID: 100, Name: "production"}, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestCreateVLANOp_Validate_NilVLAN(t *testing.T) {
	op := NewCreateVLANOp(nil, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateVLANOp_Validate_InvalidIDZero(t *testing.T) {
	op := NewCreateVLANOp(&VLANState{ID: 0, Name: "production"}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidID)
}

func TestCreateVLANOp_Validate_InvalidIDTooHigh(t *testing.T) {
	op := NewCreateVLANOp(&VLANState{ID: 4095, Name: "production"}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidID)
}

func TestCreateVLANOp_Validate_EmptyName(t *testing.T) {
	op := NewCreateVLANOp(&VLANState{ID: 100, Name: ""}, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestCreateVLANOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create VLAN
	vlan := &VLANState{ID: 100, Name: "production"}
	op := NewCreateVLANOp(vlan, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	retrieved, err := sm.GetVLAN(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, "production", retrieved.Name)
}

func TestUpdateVLANOp_Type(t *testing.T) {
	op := NewUpdateVLANOp(100, &VLANState{Name: "updated"}, 1, 1)
	assert.Equal(t, OpTypeUpdateVLAN, op.Type())
}

func TestUpdateVLANOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewUpdateVLANOp(100, &VLANState{Name: "updated"}, 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestUpdateVLANOp_NodeID(t *testing.T) {
	op := NewUpdateVLANOp(100, &VLANState{Name: "updated"}, 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestUpdateVLANOp_Validate_Success(t *testing.T) {
	op := NewUpdateVLANOp(100, &VLANState{Name: "updated"}, 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestUpdateVLANOp_Validate_InvalidIDZero(t *testing.T) {
	op := NewUpdateVLANOp(0, &VLANState{Name: "updated"}, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidID)
}

func TestUpdateVLANOp_Validate_InvalidIDTooHigh(t *testing.T) {
	op := NewUpdateVLANOp(4095, &VLANState{Name: "updated"}, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidID)
}

func TestUpdateVLANOp_Validate_NilUpdates(t *testing.T) {
	op := NewUpdateVLANOp(100, nil, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidOp ErrInvalidOperation
	assert.ErrorAs(t, err, &invalidOp)
}

func TestUpdateVLANOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create VLAN
	vlan := &VLANState{ID: 100, Name: "production"}
	require.NoError(t, sm.CreateVLAN(ctx, vlan))

	// Update
	op := NewUpdateVLANOp(100, &VLANState{Name: "updated"}, 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	retrieved, err := sm.GetVLAN(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, "updated", retrieved.Name)
}

func TestDeleteVLANOp_Type(t *testing.T) {
	op := NewDeleteVLANOp(100, 1, 1)
	assert.Equal(t, OpTypeDeleteVLAN, op.Type())
}

func TestDeleteVLANOp_Timestamp(t *testing.T) {
	before := time.Now()
	op := NewDeleteVLANOp(100, 1, 1)
	after := time.Now()

	assert.True(t, op.Timestamp().After(before) || op.Timestamp().Equal(before))
	assert.True(t, op.Timestamp().Before(after) || op.Timestamp().Equal(after))
}

func TestDeleteVLANOp_NodeID(t *testing.T) {
	op := NewDeleteVLANOp(100, 1, 42)
	assert.Equal(t, uint64(42), op.NodeID())
}

func TestDeleteVLANOp_Validate_Success(t *testing.T) {
	op := NewDeleteVLANOp(100, 1, 1)
	err := op.Validate()
	assert.NoError(t, err)
}

func TestDeleteVLANOp_Validate_InvalidIDZero(t *testing.T) {
	op := NewDeleteVLANOp(0, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidID)
}

func TestDeleteVLANOp_Validate_InvalidIDTooHigh(t *testing.T) {
	op := NewDeleteVLANOp(4095, 1, 1)
	err := op.Validate()

	require.Error(t, err)
	var invalidID ErrInvalidVLANID
	assert.ErrorAs(t, err, &invalidID)
}

func TestDeleteVLANOp_Execute(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	sm := NewQuicBaaSStateManager(mock, logging.DefaultLogger())
	ctx := context.Background()

	// Create VLAN
	vlan := &VLANState{ID: 100, Name: "production"}
	require.NoError(t, sm.CreateVLAN(ctx, vlan))

	// Delete
	op := NewDeleteVLANOp(100, 1, 1)
	err := op.Execute(ctx, sm)

	require.NoError(t, err)
	_, err = sm.GetVLAN(ctx, 100)
	var notFound ErrVLANNotFound
	assert.ErrorAs(t, err, &notFound)
}
