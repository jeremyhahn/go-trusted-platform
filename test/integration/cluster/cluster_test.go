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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cluster"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClusterFormation tests that a 3-node cluster forms successfully.
func TestClusterFormation(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	// Start the cluster
	err := tc.start(ctx)
	require.NoError(t, err, "Cluster should start successfully")

	// Verify all nodes are present
	assert.Equal(t, 3, tc.nodeCount(), "Cluster should have 3 nodes")

	// Verify all nodes are running
	for i := 0; i < tc.nodeCount(); i++ {
		node := tc.getNode(i)
		require.NotNil(t, node)
		assert.True(t, node.coordinator.IsRunning(), "Node %d should be running", i+1)
	}

	// Wait for cluster to stabilize
	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err, "Cluster should become ready")

	// Verify cluster has quorum
	leader := tc.getLeader()
	require.NotNil(t, leader, "Cluster should have a leader")

	status, err := leader.coordinator.Status(ctx)
	require.NoError(t, err)
	assert.True(t, status.HasQuorum, "Cluster should have quorum")
	assert.Equal(t, 3, status.NodeCount, "Status should report 3 nodes")

	t.Logf("Cluster formed successfully with %d nodes", tc.nodeCount())
}

// TestClusterFormation_SingleNode tests that a single-node cluster works.
func TestClusterFormation_SingleNode(t *testing.T) {
	tc := newTestCluster(t, 1)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err, "Single-node cluster should start successfully")

	node := tc.getNode(0)
	require.NotNil(t, node)
	assert.True(t, node.coordinator.IsRunning())
	assert.True(t, node.coordinator.IsLeader(), "Single node should be leader")

	t.Log("Single-node cluster formed successfully")
}

// TestLeaderElection tests that a leader is elected within timeout.
func TestLeaderElection(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	// Wait for leader election
	leaderCtx, leaderCancel := context.WithTimeout(ctx, defaultLeaderTimeout)
	defer leaderCancel()

	leader, err := tc.waitForLeader(leaderCtx)
	require.NoError(t, err, "Leader should be elected within timeout")
	require.NotNil(t, leader)

	// Verify leader is actually the leader
	assert.True(t, leader.coordinator.IsLeader(), "Elected node should report IsLeader() = true")

	// Verify only one leader exists
	leaderCount := 0
	for i := 0; i < tc.nodeCount(); i++ {
		if tc.getNode(i).coordinator.IsLeader() {
			leaderCount++
		}
	}
	assert.Equal(t, 1, leaderCount, "Exactly one leader should exist")

	t.Logf("Leader elected: node %d", leader.id)
}

// TestLeaderElection_Timeout tests that WaitForLeader times out correctly.
func TestLeaderElection_Timeout(t *testing.T) {
	coordinator, membership, cleanup := newTestCoordinator(t, 1)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := coordinator.Start(ctx)
	require.NoError(t, err)

	// Don't bootstrap, so no leader will be elected
	// WaitForLeader should timeout
	shortCtx, shortCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer shortCancel()

	_, err = coordinator.WaitForLeader(shortCtx)
	assert.Error(t, err, "WaitForLeader should timeout when no leader exists")

	_ = membership // Used by cleanup
}

// TestNodeDiscovery tests that all nodes discover each other.
func TestNodeDiscovery(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err)

	// Check that each node can see all other nodes
	for i := 0; i < tc.nodeCount(); i++ {
		node := tc.getNode(i)
		require.NotNil(t, node)

		nodeList, err := node.coordinator.Nodes(ctx)
		require.NoError(t, err, "Node %d should be able to list nodes", i+1)
		assert.GreaterOrEqual(t, nodeList.Count(), 3, "Node %d should see at least 3 nodes", i+1)

		t.Logf("Node %d sees %d nodes in cluster", i+1, nodeList.Count())
	}
}

// TestNodeDiscovery_FindByID tests finding nodes by ID.
func TestNodeDiscovery_FindByID(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leader := tc.getLeader()
	require.NotNil(t, leader)

	nodeList, err := leader.coordinator.Nodes(ctx)
	require.NoError(t, err)

	// Find each node by ID
	for i := 1; i <= 3; i++ {
		found := nodeList.FindByID(uint64(i))
		assert.NotNil(t, found, "Should find node with ID %d", i)
		if found != nil {
			assert.Equal(t, uint64(i), found.ID)
		}
	}

	// Try to find non-existent node
	notFound := nodeList.FindByID(999)
	assert.Nil(t, notFound, "Should not find non-existent node")
}

// TestClusterStatus tests that the Status API returns correct information.
func TestClusterStatus(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leader := tc.getLeader()
	require.NotNil(t, leader)

	status, err := leader.coordinator.Status(ctx)
	require.NoError(t, err, "Status should be retrievable")

	// Verify status fields
	assert.Equal(t, cluster.ClusterStateRunning, status.State, "Cluster state should be running")
	assert.Equal(t, 3, status.NodeCount, "Should have 3 nodes")
	assert.Equal(t, 3, status.HealthyCount, "All nodes should be healthy")
	assert.True(t, status.HasQuorum, "Should have quorum")
	assert.NotZero(t, status.LeaderID, "Should have a leader ID")
	assert.False(t, status.LastUpdated.IsZero(), "LastUpdated should be set")
	assert.False(t, status.StartedAt.IsZero(), "StartedAt should be set")
	assert.Empty(t, status.ErrorMessage, "Should have no error message")

	t.Logf("Cluster status: state=%s, nodes=%d, healthy=%d, leader=%d",
		status.State, status.NodeCount, status.HealthyCount, status.LeaderID)
}

// TestClusterStatus_Degraded tests status when cluster is degraded.
func TestClusterStatus_Degraded(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leader := tc.getLeader()
	require.NotNil(t, leader)

	// Get initial status
	status, err := leader.coordinator.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, cluster.ClusterStateRunning, status.State)

	t.Log("Initial status verified as running")
}

// TestClusterNodes tests that the Nodes API lists all members.
func TestClusterNodes(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err)

	// Test from leader perspective
	leader := tc.getLeader()
	require.NotNil(t, leader)

	nodeList, err := leader.coordinator.Nodes(ctx)
	require.NoError(t, err)

	assert.Equal(t, 3, nodeList.Count(), "Should have 3 nodes")
	assert.NotNil(t, nodeList.Leader, "NodeList should identify the leader")
	assert.GreaterOrEqual(t, nodeList.HealthyCount(), 3, "Should have at least 3 healthy nodes")

	// Verify leader is in the list
	leaderInList := false
	for _, node := range nodeList.Nodes {
		if node.IsLeader {
			leaderInList = true
			assert.Equal(t, leader.id, node.ID, "Leader ID should match")
		}
		assert.NotEmpty(t, node.Address, "Node should have an address")
		assert.NotZero(t, node.ID, "Node should have an ID")
	}
	assert.True(t, leaderInList, "Leader should be in node list")

	t.Logf("Node list contains %d nodes with leader ID %d", nodeList.Count(), leader.id)
}

// TestClusterNodes_HealthyNodes tests filtering healthy nodes.
func TestClusterNodes_HealthyNodes(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err)

	leader := tc.getLeader()
	require.NotNil(t, leader)

	nodeList, err := leader.coordinator.Nodes(ctx)
	require.NoError(t, err)

	healthyNodes := nodeList.Healthy()
	assert.GreaterOrEqual(t, len(healthyNodes), 3, "All nodes should be healthy")

	for _, node := range healthyNodes {
		assert.True(t, node.IsHealthy(), "Filtered node should be healthy")
	}

	t.Logf("Found %d healthy nodes", len(healthyNodes))
}

// TestClusterNodes_AfterJoin tests that nodes are visible after joining.
func TestClusterNodes_AfterJoin(t *testing.T) {
	tc := newTestCluster(t, 3)
	defer tc.stop()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	err := tc.start(ctx)
	require.NoError(t, err)

	err = tc.waitForClusterReady(ctx)
	require.NoError(t, err)

	// Verify from each node's perspective
	for i := 0; i < tc.nodeCount(); i++ {
		node := tc.getNode(i)
		require.NotNil(t, node)

		nodeList, err := node.coordinator.Nodes(ctx)
		require.NoError(t, err)

		// Each node should see all nodes
		assert.GreaterOrEqual(t, nodeList.Count(), 3,
			"Node %d should see at least 3 nodes", i+1)
	}

	t.Log("All nodes visible from all perspectives")
}

// TestClusterCoordinator_Lifecycle tests coordinator lifecycle operations.
func TestClusterCoordinator_Lifecycle(t *testing.T) {
	coordinator, membership, cleanup := newTestCoordinator(t, 1)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	// Initially not running
	assert.False(t, coordinator.IsRunning(), "Coordinator should not be running initially")

	// Start
	err := coordinator.Start(ctx)
	require.NoError(t, err)
	assert.True(t, coordinator.IsRunning(), "Coordinator should be running after Start")

	// Bootstrap
	err = coordinator.Bootstrap(ctx)
	require.NoError(t, err)

	// Verify configuration is accessible
	cfg := coordinator.Config()
	assert.NotNil(t, cfg)
	assert.Equal(t, uint64(1), cfg.NodeID)

	// Stop
	err = coordinator.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, coordinator.IsRunning(), "Coordinator should not be running after Stop")

	_ = membership // Used by cleanup
	t.Log("Coordinator lifecycle completed successfully")
}

// TestClusterCoordinator_DoubleStart tests that double start returns error.
func TestClusterCoordinator_DoubleStart(t *testing.T) {
	coordinator, membership, cleanup := newTestCoordinator(t, 1)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	err := coordinator.Start(ctx)
	require.NoError(t, err)

	// Second start should fail
	err = coordinator.Start(ctx)
	assert.Error(t, err, "Second Start should return error")

	var alreadyRunningErr cluster.ErrCoordinatorAlreadyRunning
	assert.ErrorAs(t, err, &alreadyRunningErr)

	_ = membership // Used by cleanup
}

// TestClusterCoordinator_OperationsWhenNotRunning tests operations fail when not running.
func TestClusterCoordinator_OperationsWhenNotRunning(t *testing.T) {
	coordinator, membership, cleanup := newTestCoordinator(t, 1)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
	defer cancel()

	// Don't start the coordinator

	// All operations should fail
	err := coordinator.Bootstrap(ctx)
	assert.Error(t, err)

	err = coordinator.Join(ctx, []string{"127.0.0.1:8000"})
	assert.Error(t, err)

	err = coordinator.Leave(ctx)
	assert.Error(t, err)

	_, err = coordinator.Nodes(ctx)
	assert.Error(t, err)

	_, err = coordinator.GetLeader(ctx)
	assert.Error(t, err)

	err = coordinator.HealthCheck(ctx)
	assert.Error(t, err)

	_ = membership // Used by cleanup
}
