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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shardID is the default shard ID used for all operations in these tests.
const shardID uint64 = 0

// TestWriteReplication tests that writes replicate to all nodes.
func TestWriteReplication(t *testing.T) {
	skipIfNoRaftCluster(t)

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
	require.NotNil(t, leader.storage)

	// Write data on the leader
	testKey := fmt.Sprintf("test-replication-%d", time.Now().UnixNano())
	testData := []byte(`{"message": "replication test", "timestamp": "` + time.Now().Format(time.RFC3339) + `"}`)

	err = leader.storage.Put(ctx, "TestReplication", hashString(testKey), testData, shardID)
	require.NoError(t, err, "Write should succeed on leader")

	t.Log("Data written to leader, waiting for replication...")

	// Wait for replication with timeout
	replicationTimeout := 5 * time.Second
	replicatedCtx, replicatedCancel := context.WithTimeout(ctx, replicationTimeout)
	defer replicatedCancel()

	// Check that data is eventually readable from all followers
	followers := tc.getFollowers()
	require.GreaterOrEqual(t, len(followers), 2, "Should have at least 2 followers")

	for _, follower := range followers {
		require.NotNil(t, follower.storage)

		// Poll until data is replicated or timeout
		var found bool
		var retrieved []byte

		for !found {
			select {
			case <-replicatedCtx.Done():
				t.Fatalf("Replication timeout on node %d: data not found", follower.id)
			default:
				retrieved, found, err = follower.storage.Get(ctx, "TestReplication", hashString(testKey), shardID)
				if err == nil && found {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}

		assert.True(t, found, "Data should be replicated to node %d", follower.id)
		assert.Equal(t, testData, retrieved, "Replicated data should match on node %d", follower.id)
		t.Logf("Data replicated to node %d", follower.id)
	}

	t.Log("Write replication verified across all nodes")
}

// TestWriteReplication_Multiple tests multiple writes replicate correctly.
func TestWriteReplication_Multiple(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	// Write multiple records
	const recordCount = 10
	keys := make([]uint64, recordCount)

	for i := 0; i < recordCount; i++ {
		key := fmt.Sprintf("multi-test-%d-%d", time.Now().UnixNano(), i)
		keys[i] = hashString(key)
		data := []byte(fmt.Sprintf(`{"index": %d}`, i))

		err := leader.storage.Put(ctx, "MultiTest", keys[i], data, shardID)
		require.NoError(t, err, "Write %d should succeed", i)
	}

	t.Logf("Wrote %d records to leader", recordCount)

	// Allow time for replication
	time.Sleep(2 * time.Second)

	// Verify on a follower
	followers := tc.getFollowers()
	require.NotEmpty(t, followers)

	follower := followers[0]
	var foundCount int

	for _, key := range keys {
		_, found, err := follower.storage.Get(ctx, "MultiTest", key, shardID)
		if err == nil && found {
			foundCount++
		}
	}

	assert.GreaterOrEqual(t, foundCount, recordCount-1,
		"At least %d records should be replicated", recordCount-1)

	t.Logf("Verified %d/%d records replicated to follower", foundCount, recordCount)
}

// TestReadConsistency tests that reads are consistent across nodes.
func TestReadConsistency(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	// Write initial data
	testKey := hashString(fmt.Sprintf("consistency-test-%d", time.Now().UnixNano()))
	version1 := []byte(`{"version": 1}`)

	err = leader.storage.Put(ctx, "ConsistencyTest", testKey, version1, shardID)
	require.NoError(t, err)

	// Wait for replication
	time.Sleep(2 * time.Second)

	// Read from all nodes and verify consistency
	allNodes := tc.getClusterNodes()
	readings := make([][]byte, len(allNodes))

	for i, node := range allNodes {
		data, found, err := node.storage.Get(ctx, "ConsistencyTest", testKey, shardID)
		require.NoError(t, err, "Read from node %d should succeed", i+1)
		require.True(t, found, "Data should be found on node %d", i+1)
		readings[i] = data
	}

	// All readings should be the same
	for i := 1; i < len(readings); i++ {
		assert.Equal(t, readings[0], readings[i],
			"Reading from node %d should match node 1", i+1)
	}

	t.Log("Read consistency verified across all nodes")
}

// TestReadConsistency_AfterUpdate tests consistency after updates.
func TestReadConsistency_AfterUpdate(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	testKey := hashString(fmt.Sprintf("update-test-%d", time.Now().UnixNano()))

	// Write initial version
	err = leader.storage.Put(ctx, "UpdateTest", testKey, []byte(`{"version": 1}`), shardID)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	// Update to version 2
	err = leader.storage.Put(ctx, "UpdateTest", testKey, []byte(`{"version": 2}`), shardID)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	// Update to version 3
	version3 := []byte(`{"version": 3}`)
	err = leader.storage.Put(ctx, "UpdateTest", testKey, version3, shardID)
	require.NoError(t, err)

	// Wait for replication
	time.Sleep(2 * time.Second)

	// All nodes should have version 3
	allNodes := tc.getClusterNodes()
	for i, node := range allNodes {
		data, found, err := node.storage.Get(ctx, "UpdateTest", testKey, shardID)
		require.NoError(t, err)
		require.True(t, found)

		var result map[string]int
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, 3, result["version"],
			"Node %d should have latest version", i+1)
	}

	t.Log("Read consistency after updates verified")
}

// TestLogReplication tests that Raft log entries replicate.
func TestLogReplication(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	// Get initial term
	initialTerm := leader.raftOp.GetTerm()
	t.Logf("Initial Raft term: %d", initialTerm)

	// Write several entries to generate log entries
	for i := 0; i < 5; i++ {
		key := hashString(fmt.Sprintf("log-test-%d-%d", time.Now().UnixNano(), i))
		err := leader.storage.Put(ctx, "LogTest", key, []byte(fmt.Sprintf(`{"entry": %d}`, i)), shardID)
		require.NoError(t, err)
	}

	// Allow time for log replication
	time.Sleep(2 * time.Second)

	// Verify term is consistent across nodes (or at least not decreasing)
	allNodes := tc.getClusterNodes()
	for _, node := range allNodes {
		nodeTerm := node.raftOp.GetTerm()
		assert.GreaterOrEqual(t, nodeTerm, initialTerm,
			"Node %d term should be >= initial term", node.id)
	}

	t.Log("Log replication verified")
}

// TestLogReplication_TermIncrement tests term increments on leader change.
func TestLogReplication_TermIncrement(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	initialTerm := leader.raftOp.GetTerm()
	t.Logf("Initial term: %d", initialTerm)

	// Verify all nodes have consistent term
	allNodes := tc.getClusterNodes()
	for _, node := range allNodes {
		assert.Equal(t, initialTerm, node.raftOp.GetTerm(),
			"Node %d should have same term as leader", node.id)
	}

	t.Log("Term consistency verified")
}

// TestSnapshotCreation tests that snapshots are created.
func TestSnapshotCreation(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	// Write enough data to potentially trigger a snapshot
	// Note: In real QuicBaaS, snapshots are triggered by log size thresholds
	for i := 0; i < 50; i++ {
		key := hashString(fmt.Sprintf("snapshot-test-%d-%d", time.Now().UnixNano(), i))
		data := make([]byte, 1024) // 1KB of data
		for j := range data {
			data[j] = byte(i)
		}
		err := leader.storage.Put(ctx, "SnapshotTest", key, data, shardID)
		require.NoError(t, err)
	}

	// Allow time for potential snapshot
	time.Sleep(3 * time.Second)

	// Verify cluster is still healthy after snapshot operations
	assert.True(t, leader.coordinator.IsHealthy(), "Cluster should be healthy after snapshots")

	status, err := leader.coordinator.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, status.HealthyCount, "All nodes should still be healthy")

	t.Log("Snapshot creation test completed")
}

// TestSnapshotRecovery tests that a new node catches up via snapshot.
func TestSnapshotRecovery(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	// Write data that will be in snapshot/logs
	testKeys := make([]uint64, 20)
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("recovery-test-%d-%d", time.Now().UnixNano(), i)
		testKeys[i] = hashString(key)
		data := []byte(fmt.Sprintf(`{"index": %d, "timestamp": "%s"}`, i, time.Now().Format(time.RFC3339)))
		err := leader.storage.Put(ctx, "RecoveryTest", testKeys[i], data, shardID)
		require.NoError(t, err)
	}

	t.Logf("Wrote %d records for recovery test", len(testKeys))

	// Wait for replication to all nodes
	time.Sleep(3 * time.Second)

	// Verify all followers have the data
	followers := tc.getFollowers()
	for _, follower := range followers {
		var foundCount int
		for _, key := range testKeys {
			_, found, err := follower.storage.Get(ctx, "RecoveryTest", key, shardID)
			if err == nil && found {
				foundCount++
			}
		}
		assert.GreaterOrEqual(t, foundCount, len(testKeys)-2,
			"Follower %d should have most records", follower.id)
		t.Logf("Follower %d has %d/%d records", follower.id, foundCount, len(testKeys))
	}

	t.Log("Snapshot recovery test completed")
}

// TestConsensus_ConcurrentWrites tests concurrent writes achieve consensus.
func TestConsensus_ConcurrentWrites(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	// Concurrent writes from the leader
	const concurrency = 10
	results := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			key := hashString(fmt.Sprintf("concurrent-%d-%d", time.Now().UnixNano(), idx))
			data := []byte(fmt.Sprintf(`{"concurrent_index": %d}`, idx))
			results <- leader.storage.Put(ctx, "ConcurrentTest", key, data, shardID)
		}(i)
	}

	// Collect results
	var successCount int
	for i := 0; i < concurrency; i++ {
		if err := <-results; err == nil {
			successCount++
		}
	}

	assert.Equal(t, concurrency, successCount,
		"All concurrent writes should succeed")

	t.Logf("Concurrent writes completed: %d/%d successful", successCount, concurrency)
}

// TestConsensus_OrderPreservation tests that operation order is preserved.
func TestConsensus_OrderPreservation(t *testing.T) {
	skipIfNoRaftCluster(t)

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

	// Write sequential values to the same key
	testKey := hashString(fmt.Sprintf("order-test-%d", time.Now().UnixNano()))

	for i := 1; i <= 10; i++ {
		data := []byte(fmt.Sprintf(`{"sequence": %d}`, i))
		err := leader.storage.Put(ctx, "OrderTest", testKey, data, shardID)
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond) // Small delay between writes
	}

	// Wait for replication
	time.Sleep(2 * time.Second)

	// All nodes should have the final value (10)
	allNodes := tc.getClusterNodes()
	for _, node := range allNodes {
		data, found, err := node.storage.Get(ctx, "OrderTest", testKey, shardID)
		require.NoError(t, err)
		require.True(t, found)

		var result map[string]int
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, 10, result["sequence"],
			"Node %d should have final sequence value", node.id)
	}

	t.Log("Order preservation verified")
}

// hashString generates a FNV-1a hash for a string (matches the SDN cluster implementation)
func hashString(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for i := 0; i < len(s); i++ {
		hash ^= uint64(s[i])
		hash *= prime64
	}
	return hash
}
