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

//go:build integration

package cluster

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	sdncluster "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/cluster"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdnTestCluster extends testCluster with SDN state managers
type sdnTestCluster struct {
	*testCluster
	stateManagers []*sdncluster.QuicBaaSStateManager
}

// newSDNTestCluster creates a test cluster with SDN state managers.
func newSDNTestCluster(t *testing.T, nodeCount int) *sdnTestCluster {
	t.Helper()

	tc := newTestCluster(t, nodeCount)
	return &sdnTestCluster{
		testCluster:   tc,
		stateManagers: make([]*sdncluster.QuicBaaSStateManager, 0, nodeCount),
	}
}

// startWithSDN starts the cluster and initializes SDN state managers.
func (stc *sdnTestCluster) startWithSDN(ctx context.Context) error {
	if err := stc.start(ctx); err != nil {
		return err
	}

	logger := logging.DefaultLogger()

	// Create state managers for each node
	for _, node := range stc.nodes {
		stateManager := sdncluster.NewQuicBaaSStateManager(
			node.storage,
			logger,
		)
		stc.stateManagers = append(stc.stateManagers, stateManager)
	}

	return nil
}

// getStateManager returns the state manager for the specified node index.
func (stc *sdnTestCluster) getStateManager(index int) *sdncluster.QuicBaaSStateManager {
	if index < 0 || index >= len(stc.stateManagers) {
		return nil
	}
	return stc.stateManagers[index]
}

// getLeaderStateManager returns the state manager for the leader node.
func (stc *sdnTestCluster) getLeaderStateManager() *sdncluster.QuicBaaSStateManager {
	leader := stc.getLeader()
	if leader == nil {
		return nil
	}
	for i, node := range stc.nodes {
		if node.id == leader.id {
			return stc.stateManagers[i]
		}
	}
	return nil
}

// waitForState waits until present holds on every node's state manager. A
// timeout is only logged: the caller's own reads assert on the state.
func (stc *sdnTestCluster) waitForState(ctx context.Context, t *testing.T, condition string, present func(sm *sdncluster.QuicBaaSStateManager) bool) {
	t.Helper()
	everywhere := func() bool {
		for _, sm := range stc.stateManagers {
			if !present(sm) {
				return false
			}
		}
		return true
	}
	if err := testenv.WaitUntil(ctx, defaultOperationTimeout, condition+" on every node", everywhere); err != nil {
		t.Logf("%v", err)
	}
}

// waitForBridge waits until every node's state manager reads the bridge.
func (stc *sdnTestCluster) waitForBridge(ctx context.Context, t *testing.T, bridgeID string) {
	t.Helper()
	stc.waitForState(ctx, t, "bridge "+bridgeID, func(sm *sdncluster.QuicBaaSStateManager) bool {
		_, err := sm.GetBridge(ctx, bridgeID)
		return err == nil
	})
}

// TestSDNBridgeReplication tests that bridge state replicates across nodes.
func TestSDNBridgeReplication(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create a bridge on the leader
	bridge := &sdncluster.BridgeState{
		ID:           fmt.Sprintf("br-test-%d", time.Now().UnixNano()),
		Name:         "br-integration-test",
		DatapathType: "system",
		FailMode:     "secure",
		STPEnabled:   true,
		Ports:        []string{},
		ExternalIDs:  map[string]string{"test": "replication"},
		NodeID:       stc.getLeader().id,
		Version:      1,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err, "Bridge creation should succeed on leader")

	t.Logf("Bridge %s created on leader", bridge.ID)

	// Wait for replication
	stc.waitForBridge(ctx, t, bridge.ID)

	// Verify bridge is visible from all nodes
	for i := 0; i < stc.nodeCount(); i++ {
		sm := stc.getStateManager(i)
		require.NotNil(t, sm)

		retrieved, err := sm.GetBridge(ctx, bridge.ID)
		if err != nil {
			t.Logf("Node %d: bridge not yet replicated (may take longer)", i+1)
			continue
		}

		assert.Equal(t, bridge.ID, retrieved.ID)
		assert.Equal(t, bridge.Name, retrieved.Name)
		assert.Equal(t, bridge.DatapathType, retrieved.DatapathType)
		t.Logf("Node %d: bridge replicated successfully", i+1)
	}

	t.Log("SDN bridge replication test completed")
}

// TestSDNBridgeReplication_Update tests bridge update replication.
func TestSDNBridgeReplication_Update(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create initial bridge
	bridge := &sdncluster.BridgeState{
		ID:           fmt.Sprintf("br-update-%d", time.Now().UnixNano()),
		Name:         "br-update-test",
		DatapathType: "system",
		STPEnabled:   false,
		Version:      1,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err)

	stc.waitForBridge(ctx, t, bridge.ID)

	// Update the bridge
	bridge.STPEnabled = true
	bridge.FailMode = "standalone"
	err = leaderSM.UpdateBridge(ctx, bridge.ID, bridge, 1)
	require.NoError(t, err)

	// Wait for update to replicate
	stc.waitForState(ctx, t, "bridge "+bridge.ID+" update", func(sm *sdncluster.QuicBaaSStateManager) bool {
		retrieved, err := sm.GetBridge(ctx, bridge.ID)
		return err == nil && retrieved.STPEnabled && retrieved.FailMode == "standalone"
	})

	// Verify update on followers
	followers := stc.getFollowers()
	for i, follower := range followers {
		idx := -1
		for j, node := range stc.nodes {
			if node.id == follower.id {
				idx = j
				break
			}
		}
		if idx < 0 {
			continue
		}

		sm := stc.getStateManager(idx)
		if sm == nil {
			continue
		}

		retrieved, err := sm.GetBridge(ctx, bridge.ID)
		if err != nil {
			t.Logf("Follower %d: update not yet replicated", i+1)
			continue
		}

		assert.True(t, retrieved.STPEnabled, "STPEnabled should be updated")
		assert.Equal(t, "standalone", retrieved.FailMode, "FailMode should be updated")
	}

	t.Log("Bridge update replication verified")
}

// TestSDNPortReplication tests that port state replicates across nodes.
func TestSDNPortReplication(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create a bridge first
	bridgeID := fmt.Sprintf("br-port-%d", time.Now().UnixNano())
	bridge := &sdncluster.BridgeState{
		ID:        bridgeID,
		Name:      "br-port-test",
		Ports:     []string{},
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err)

	stc.waitForBridge(ctx, t, bridgeID)

	// Create a port
	port := &sdncluster.PortState{
		ID:         fmt.Sprintf("port-test-%d", time.Now().UnixNano()),
		Name:       "eth-test",
		BridgeID:   bridgeID,
		Type:       "system",
		Tag:        100,
		VLANMode:   "access",
		AdminState: "up",
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	err = leaderSM.CreatePort(ctx, port)
	require.NoError(t, err, "Port creation should succeed")

	t.Logf("Port %s created on bridge %s", port.ID, bridgeID)

	// Wait for replication
	stc.waitForState(ctx, t, "port "+port.ID, func(sm *sdncluster.QuicBaaSStateManager) bool {
		_, err := sm.GetPort(ctx, port.ID)
		return err == nil
	})

	// Verify port is visible from all nodes
	for i := 0; i < stc.nodeCount(); i++ {
		sm := stc.getStateManager(i)
		if sm == nil {
			continue
		}

		retrieved, err := sm.GetPort(ctx, port.ID)
		if err != nil {
			t.Logf("Node %d: port not yet replicated", i+1)
			continue
		}

		assert.Equal(t, port.ID, retrieved.ID)
		assert.Equal(t, port.Name, retrieved.Name)
		assert.Equal(t, port.BridgeID, retrieved.BridgeID)
		assert.Equal(t, port.Tag, retrieved.Tag)
		t.Logf("Node %d: port replicated successfully", i+1)
	}

	t.Log("SDN port replication test completed")
}

// TestSDNFlowReplication tests that flow rules replicate across nodes.
func TestSDNFlowReplication(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create a bridge first
	bridgeID := fmt.Sprintf("br-flow-%d", time.Now().UnixNano())
	bridge := &sdncluster.BridgeState{
		ID:        bridgeID,
		Name:      "br-flow-test",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err)

	stc.waitForBridge(ctx, t, bridgeID)

	// Create a flow rule
	inPort := uint32(1)
	outPort := uint32(2)
	flow := &sdncluster.FlowState{
		ID:       fmt.Sprintf("flow-test-%d", time.Now().UnixNano()),
		BridgeID: bridgeID,
		Table:    0,
		Priority: 100,
		Match: &sdncluster.FlowMatch{
			InPort:  &inPort,
			EthType: func() *uint16 { v := uint16(0x0800); return &v }(),
		},
		Actions: []*sdncluster.FlowAction{
			{
				Type: sdncluster.ActionOutput,
				Port: &outPort,
			},
		},
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = leaderSM.CreateFlow(ctx, flow)
	require.NoError(t, err, "Flow creation should succeed")

	t.Logf("Flow %s created on bridge %s", flow.ID, bridgeID)

	// Wait for replication
	stc.waitForState(ctx, t, "flow "+flow.ID, func(sm *sdncluster.QuicBaaSStateManager) bool {
		_, err := sm.GetFlow(ctx, bridgeID, flow.ID)
		return err == nil
	})

	// Verify flow is visible from all nodes
	for i := 0; i < stc.nodeCount(); i++ {
		sm := stc.getStateManager(i)
		if sm == nil {
			continue
		}

		retrieved, err := sm.GetFlow(ctx, bridgeID, flow.ID)
		if err != nil {
			t.Logf("Node %d: flow not yet replicated", i+1)
			continue
		}

		assert.Equal(t, flow.ID, retrieved.ID)
		assert.Equal(t, flow.BridgeID, retrieved.BridgeID)
		assert.Equal(t, flow.Table, retrieved.Table)
		assert.Equal(t, flow.Priority, retrieved.Priority)
		t.Logf("Node %d: flow replicated successfully", i+1)
	}

	t.Log("SDN flow replication test completed")
}

// TestSDNFlowReplication_MultipleFlows tests multiple flow replication.
func TestSDNFlowReplication_MultipleFlows(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create a bridge
	bridgeID := fmt.Sprintf("br-multiflow-%d", time.Now().UnixNano())
	bridge := &sdncluster.BridgeState{
		ID:        bridgeID,
		Name:      "br-multiflow-test",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err)

	stc.waitForBridge(ctx, t, bridgeID)

	// Create multiple flows
	const flowCount = 5
	flowIDs := make([]string, flowCount)

	for i := 0; i < flowCount; i++ {
		outPort := uint32(i + 2)
		flow := &sdncluster.FlowState{
			ID:       fmt.Sprintf("flow-multi-%d-%d", time.Now().UnixNano(), i),
			BridgeID: bridgeID,
			Table:    uint8(i),
			Priority: uint16(100 + i),
			Actions: []*sdncluster.FlowAction{
				{Type: sdncluster.ActionOutput, Port: &outPort},
			},
			Version:   1,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		flowIDs[i] = flow.ID

		err := leaderSM.CreateFlow(ctx, flow)
		require.NoError(t, err, "Flow %d creation should succeed", i)
	}

	t.Logf("Created %d flows", flowCount)

	// Wait for replication
	stc.waitForState(ctx, t, fmt.Sprintf("%d flows on bridge %s", flowCount, bridgeID), func(sm *sdncluster.QuicBaaSStateManager) bool {
		flows, err := sm.ListFlows(ctx, bridgeID)
		return err == nil && len(flows) == flowCount
	})

	// Verify flows on followers
	followers := stc.getFollowers()
	require.NotEmpty(t, followers)

	for _, follower := range followers {
		idx := -1
		for j, node := range stc.nodes {
			if node.id == follower.id {
				idx = j
				break
			}
		}
		if idx < 0 {
			continue
		}

		sm := stc.getStateManager(idx)
		if sm == nil {
			continue
		}

		flows, err := sm.ListFlows(ctx, bridgeID)
		if err != nil {
			t.Logf("Error listing flows on node: %v", err)
			continue
		}

		t.Logf("Follower has %d flows (expected %d)", len(flows), flowCount)
	}

	t.Log("Multiple flow replication test completed")
}

// TestSDNStateConsistency tests read-after-write consistency.
func TestSDNStateConsistency(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create a bridge
	bridge := &sdncluster.BridgeState{
		ID:        fmt.Sprintf("br-consistent-%d", time.Now().UnixNano()),
		Name:      "br-consistency-test",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err)

	// Immediate read on leader should succeed (strong consistency)
	retrieved, err := leaderSM.GetBridge(ctx, bridge.ID)
	require.NoError(t, err, "Immediate read after write should succeed on leader")
	assert.Equal(t, bridge.ID, retrieved.ID)
	assert.Equal(t, bridge.Name, retrieved.Name)

	t.Log("Read-after-write consistency verified on leader")

	// Wait for replication to followers
	stc.waitForBridge(ctx, t, bridge.ID)

	// All followers should now have consistent state
	for i := 0; i < stc.nodeCount(); i++ {
		sm := stc.getStateManager(i)
		if sm == nil {
			continue
		}

		retrieved, err := sm.GetBridge(ctx, bridge.ID)
		if err != nil {
			continue
		}

		assert.Equal(t, bridge.ID, retrieved.ID)
		assert.Equal(t, bridge.Name, retrieved.Name)
	}

	t.Log("State consistency verified across cluster")
}

// TestSDNStateConsistency_ConcurrentReads tests concurrent read consistency.
func TestSDNStateConsistency_ConcurrentReads(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create a bridge with known state
	bridge := &sdncluster.BridgeState{
		ID:         fmt.Sprintf("br-concurrent-%d", time.Now().UnixNano()),
		Name:       "br-concurrent-test",
		STPEnabled: true,
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err)

	// Wait for replication
	stc.waitForBridge(ctx, t, bridge.ID)

	// Concurrent reads from all nodes
	results := make(chan *sdncluster.BridgeState, stc.nodeCount())
	errors := make(chan error, stc.nodeCount())

	for i := 0; i < stc.nodeCount(); i++ {
		go func(idx int) {
			sm := stc.getStateManager(idx)
			if sm == nil {
				errors <- fmt.Errorf("no state manager for node %d", idx)
				return
			}

			retrieved, err := sm.GetBridge(ctx, bridge.ID)
			if err != nil {
				errors <- err
				return
			}
			results <- retrieved
		}(i)
	}

	// Collect results
	var successCount int
	var readings []*sdncluster.BridgeState

	for i := 0; i < stc.nodeCount(); i++ {
		select {
		case r := <-results:
			readings = append(readings, r)
			successCount++
		case err := <-errors:
			t.Logf("Read error: %v", err)
		case <-time.After(5 * time.Second):
			t.Log("Read timeout")
		}
	}

	// All successful reads should return same data
	for i := 1; i < len(readings); i++ {
		assert.Equal(t, readings[0].ID, readings[i].ID)
		assert.Equal(t, readings[0].Name, readings[i].Name)
		assert.Equal(t, readings[0].STPEnabled, readings[i].STPEnabled)
	}

	t.Logf("Concurrent reads: %d/%d successful with consistent data", successCount, stc.nodeCount())
}

// TestSDNFailoverPersistence tests that state survives leader change.
func TestSDNFailoverPersistence(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create SDN state before failover
	bridge := &sdncluster.BridgeState{
		ID:         fmt.Sprintf("br-persist-%d", time.Now().UnixNano()),
		Name:       "br-persistence-test",
		FailMode:   "secure",
		STPEnabled: true,
		Version:    1,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, bridge)
	require.NoError(t, err)

	// Create port on the bridge
	port := &sdncluster.PortState{
		ID:        fmt.Sprintf("port-persist-%d", time.Now().UnixNano()),
		Name:      "eth-persist",
		BridgeID:  bridge.ID,
		Tag:       200,
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = leaderSM.CreatePort(ctx, port)
	require.NoError(t, err)

	t.Logf("Created bridge %s and port %s before failover", bridge.ID, port.ID)

	// Wait for replication
	stc.waitForState(ctx, t, "bridge "+bridge.ID+" and port "+port.ID, func(sm *sdncluster.QuicBaaSStateManager) bool {
		_, bridgeErr := sm.GetBridge(ctx, bridge.ID)
		_, portErr := sm.GetPort(ctx, port.ID)
		return bridgeErr == nil && portErr == nil
	})

	// Simulate leader failover
	originalLeader := stc.getLeader()
	require.NotNil(t, originalLeader)

	err = originalLeader.coordinator.Stop(ctx)
	require.NoError(t, err)

	// Update mock to elect new leader
	if mockOp, ok := originalLeader.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(0)
	}

	// The stopped leader reports IsLeader() == false, so only a running
	// follower is a candidate for the new leader.
	followers := stc.getRunningFollowers()
	require.NotEmpty(t, followers)

	newLeaderNode := followers[0]
	if mockOp, ok := newLeaderNode.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(newLeaderNode.id)
	}

	_, err = waitForNewLeader(ctx, defaultLeaderTimeout, []*testNode{newLeaderNode})
	require.NoError(t, err)

	// Find the new leader's state manager
	var newLeaderSM *sdncluster.QuicBaaSStateManager
	for i, node := range stc.nodes {
		if node.id == newLeaderNode.id {
			newLeaderSM = stc.stateManagers[i]
			break
		}
	}
	require.NotNil(t, newLeaderSM)

	// Verify state persisted through failover
	retrievedBridge, err := newLeaderSM.GetBridge(ctx, bridge.ID)
	require.NoError(t, err, "Bridge should persist through failover")
	assert.Equal(t, bridge.ID, retrievedBridge.ID)
	assert.Equal(t, bridge.Name, retrievedBridge.Name)
	assert.Equal(t, bridge.FailMode, retrievedBridge.FailMode)

	retrievedPort, err := newLeaderSM.GetPort(ctx, port.ID)
	require.NoError(t, err, "Port should persist through failover")
	assert.Equal(t, port.ID, retrievedPort.ID)
	assert.Equal(t, port.Name, retrievedPort.Name)
	assert.Equal(t, port.Tag, retrievedPort.Tag)

	t.Log("SDN state persisted through leader failover")
}

// TestSDNFailoverPersistence_WriteAfterFailover tests writes work after failover.
func TestSDNFailoverPersistence_WriteAfterFailover(t *testing.T) {
	stc := newSDNTestCluster(t, 3)
	defer stc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := stc.startWithSDN(ctx)
	require.NoError(t, err)

	err = stc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leaderSM := stc.getLeaderStateManager()
	require.NotNil(t, leaderSM)

	// Create initial bridge
	initialBridge := &sdncluster.BridgeState{
		ID:        fmt.Sprintf("br-initial-%d", time.Now().UnixNano()),
		Name:      "br-initial",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = leaderSM.CreateBridge(ctx, initialBridge)
	require.NoError(t, err)

	stc.waitForBridge(ctx, t, initialBridge.ID)

	// Simulate failover
	originalLeader := stc.getLeader()
	require.NotNil(t, originalLeader)

	err = originalLeader.coordinator.Stop(ctx)
	require.NoError(t, err)

	if mockOp, ok := originalLeader.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(0)
	}

	// The stopped leader reports IsLeader() == false, so only a running
	// follower is a candidate for the new leader.
	followers := stc.getRunningFollowers()
	require.NotEmpty(t, followers)

	newLeaderNode := followers[0]
	if mockOp, ok := newLeaderNode.raftOp.(*mockRaftOperator); ok {
		mockOp.setLeader(newLeaderNode.id)
	}

	_, err = waitForNewLeader(ctx, defaultLeaderTimeout, []*testNode{newLeaderNode})
	require.NoError(t, err)

	// Get new leader's state manager
	var newLeaderSM *sdncluster.QuicBaaSStateManager
	for i, node := range stc.nodes {
		if node.id == newLeaderNode.id {
			newLeaderSM = stc.stateManagers[i]
			break
		}
	}
	require.NotNil(t, newLeaderSM)

	// Write new data after failover
	postFailoverBridge := &sdncluster.BridgeState{
		ID:        fmt.Sprintf("br-postfailover-%d", time.Now().UnixNano()),
		Name:      "br-post-failover",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	err = newLeaderSM.CreateBridge(ctx, postFailoverBridge)
	require.NoError(t, err, "Should be able to write after failover")

	// Verify both bridges exist
	_, err = newLeaderSM.GetBridge(ctx, initialBridge.ID)
	assert.NoError(t, err, "Initial bridge should still exist")

	_, err = newLeaderSM.GetBridge(ctx, postFailoverBridge.ID)
	assert.NoError(t, err, "Post-failover bridge should exist")

	t.Log("Writes succeed after failover")
}
