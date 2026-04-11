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

// Package cluster provides integration tests for cluster operations.
// These tests require a real QuicBaaS instance and are run via:
//
//	make integration-test-cluster
//
// The tests verify end-to-end functionality with simulated Raft consensus.
// The mock cluster uses a shared storage layer that propagates writes to all
// nodes, simulating Raft replication behavior.

//go:build integration

package cluster

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cluster"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/require"
)

// Default timeouts for integration tests
const (
	defaultClusterTimeout     = 60 * time.Second
	defaultLeaderTimeout      = 30 * time.Second
	defaultOperationTimeout   = 10 * time.Second
	defaultHealthCheckTimeout = 5 * time.Second
	defaultNodeCount          = 3
	startupTimeout            = 60 * time.Second
	shutdownTimeout           = 10 * time.Second
)

// skipIfNotIntegration skips the test if the INTEGRATION_TEST env var is not set.
func skipIfNotIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// skipIfNoRaftCluster skips data replication tests that require a Raft cluster
// simulation. The mock cluster provides shared storage that simulates Raft
// replication by propagating writes to all nodes.
// Set RAFT_CLUSTER_TEST=1 to run these tests.
func skipIfNoRaftCluster(t *testing.T) {
	skipIfNotIntegration(t)
	if os.Getenv("RAFT_CLUSTER_TEST") == "" {
		t.Skip("Skipping Raft cluster test. Set RAFT_CLUSTER_TEST=1 to run with simulated Raft cluster.")
	}
}

// sharedStorage provides a thread-safe storage wrapper that propagates writes
// to all registered node storages, simulating Raft replication.
type sharedStorage struct {
	mu       sync.RWMutex
	primary  quicbaas.Storage            // Primary storage for the leader
	replicas map[uint64]quicbaas.Storage // Replica storages indexed by node ID
	factory  *quicbaas.Factory           // Factory for the primary storage
}

// newSharedStorage creates a shared storage instance with the primary factory.
func newSharedStorage(t *testing.T, logger *logging.Logger) *sharedStorage {
	t.Helper()

	cfg := quicbaas.MemoryTestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err, "Failed to create shared QuicBaaS factory")

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	err = factory.Start(ctx)
	require.NoError(t, err, "Failed to start shared QuicBaaS factory")

	storage := factory.Storage()
	require.NotNil(t, storage, "Shared factory storage is nil")

	return &sharedStorage{
		primary:  storage,
		replicas: make(map[uint64]quicbaas.Storage),
		factory:  factory,
	}
}

// registerReplica adds a replica storage for a node.
func (ss *sharedStorage) registerReplica(nodeID uint64, storage quicbaas.Storage) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.replicas[nodeID] = storage
}

// stop stops the shared storage factory.
func (ss *sharedStorage) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if ss.factory != nil {
		ss.factory.Stop(ctx)
	}
}

// replicatingStorage wraps a quicbaas.Storage and propagates writes to all
// replicas registered in the shared storage, simulating Raft replication.
// It implements the quicbaas.Storage interface by delegating to the local
// storage and replicating write operations.
type replicatingStorage struct {
	nodeID uint64
	local  quicbaas.Storage
	shared *sharedStorage
}

// Compile-time interface verification
var _ quicbaas.Storage = (*replicatingStorage)(nil)

// newReplicatingStorage creates a storage wrapper that replicates writes.
func newReplicatingStorage(nodeID uint64, local quicbaas.Storage, shared *sharedStorage) *replicatingStorage {
	return &replicatingStorage{
		nodeID: nodeID,
		local:  local,
		shared: shared,
	}
}

// Start initializes the storage backend (delegates to local).
func (rs *replicatingStorage) Start(ctx context.Context) error {
	return rs.local.Start(ctx)
}

// Stop gracefully shuts down the storage backend (delegates to local).
func (rs *replicatingStorage) Stop(ctx context.Context) error {
	return rs.local.Stop(ctx)
}

// IsStarted returns true if the storage is ready (delegates to local).
func (rs *replicatingStorage) IsStarted() bool {
	return rs.local.IsStarted()
}

// IsClosed returns true if the storage has been shut down (delegates to local).
func (rs *replicatingStorage) IsClosed() bool {
	return rs.local.IsClosed()
}

// Put stores data and replicates to all other nodes.
func (rs *replicatingStorage) Put(ctx context.Context, table string, key uint64, data []byte, shardID uint64) error {
	// Write to local storage first
	if err := rs.local.Put(ctx, table, key, data, shardID); err != nil {
		return err
	}

	// Replicate to all other nodes (simulating Raft replication)
	rs.shared.mu.RLock()
	defer rs.shared.mu.RUnlock()

	for id, replica := range rs.shared.replicas {
		if id != rs.nodeID {
			// Best-effort replication (like async Raft replication)
			replica.Put(ctx, table, key, data, shardID)
		}
	}

	return nil
}

// Get retrieves data from local storage.
func (rs *replicatingStorage) Get(ctx context.Context, table string, key uint64, shardID uint64) ([]byte, bool, error) {
	return rs.local.Get(ctx, table, key, shardID)
}

// Delete removes data and replicates deletion to all other nodes.
func (rs *replicatingStorage) Delete(ctx context.Context, table string, key uint64, shardID uint64) error {
	if err := rs.local.Delete(ctx, table, key, shardID); err != nil {
		return err
	}

	// Replicate deletion
	rs.shared.mu.RLock()
	defer rs.shared.mu.RUnlock()

	for id, replica := range rs.shared.replicas {
		if id != rs.nodeID {
			replica.Delete(ctx, table, key, shardID)
		}
	}

	return nil
}

// List retrieves entities with pagination (delegates to local).
func (rs *replicatingStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	return rs.local.List(ctx, entityType, pageSize, pageToken, shardID)
}

// Query searches for entities using secondary indexes (delegates to local).
func (rs *replicatingStorage) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	return rs.local.Query(ctx, entityType, indexField, value, shardID)
}

// testCluster represents a test cluster with multiple nodes
type testCluster struct {
	t             *testing.T
	nodes         []*testNode
	configs       []*cluster.Config
	logger        *logging.Logger
	basePort      int
	mu            sync.Mutex
	sharedState   *sharedClusterState // Shared Raft state for all nodes
	sharedStorage *sharedStorage      // Shared storage for replication simulation
}

// testNode represents a single node in the test cluster
type testNode struct {
	id          uint64
	config      *cluster.Config
	coordinator cluster.Coordinator
	membership  cluster.MembershipManager
	raftOp      cluster.RaftOperator
	factory     *quicbaas.Factory
	storage     quicbaas.Storage
	logger      *logging.Logger
}

// newTestCluster creates a new test cluster with the specified number of nodes.
// The cluster is not started automatically; call start() to begin.
func newTestCluster(t *testing.T, nodeCount int) *testCluster {
	t.Helper()

	logger := logging.DefaultLogger()

	tc := &testCluster{
		t:             t,
		nodes:         make([]*testNode, 0, nodeCount),
		configs:       make([]*cluster.Config, 0, nodeCount),
		logger:        logger,
		basePort:      15000 + (os.Getpid()%1000)*10,
		sharedState:   newSharedClusterState(), // Create shared state for all nodes
		sharedStorage: newSharedStorage(t, logger),
	}

	// Create configurations for each node
	for i := 0; i < nodeCount; i++ {
		nodeID := uint64(i + 1)
		listenAddr := fmt.Sprintf("127.0.0.1:%d", tc.basePort+i)

		cfg := cluster.NewConfig()
		cfg.NodeID = nodeID
		cfg.ListenAddress = listenAddr
		cfg.AdvertiseAddress = listenAddr
		cfg.DataDir = t.TempDir()

		tc.configs = append(tc.configs, cfg)
	}

	return tc
}

// start initializes and starts all nodes in the cluster.
// The first node bootstraps the cluster, and remaining nodes join.
func (tc *testCluster) start(ctx context.Context) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Create and start each node
	for i, cfg := range tc.configs {
		node, err := tc.createNode(cfg)
		if err != nil {
			return fmt.Errorf("failed to create node %d: %w", i, err)
		}
		tc.nodes = append(tc.nodes, node)
	}

	// Bootstrap the first node
	if len(tc.nodes) > 0 {
		if err := tc.nodes[0].coordinator.Start(ctx); err != nil {
			return fmt.Errorf("failed to start first node: %w", err)
		}

		if err := tc.nodes[0].coordinator.Bootstrap(ctx); err != nil {
			return fmt.Errorf("failed to bootstrap cluster: %w", err)
		}

		tc.t.Log("Cluster bootstrapped successfully on node 1")
	}

	// Join remaining nodes
	for i := 1; i < len(tc.nodes); i++ {
		if err := tc.nodes[i].coordinator.Start(ctx); err != nil {
			return fmt.Errorf("failed to start node %d: %w", i+1, err)
		}

		joinAddrs := []string{tc.configs[0].GetAdvertiseAddress()}
		if err := tc.nodes[i].coordinator.Join(ctx, joinAddrs); err != nil {
			return fmt.Errorf("failed to join node %d: %w", i+1, err)
		}

		tc.t.Logf("Node %d joined cluster successfully", i+1)
	}

	return nil
}

// createNode creates a single test node with the given configuration.
func (tc *testCluster) createNode(cfg *cluster.Config) (*testNode, error) {
	// Create QuicBaaS factory for this node using in-memory config
	quicbaasCfg := quicbaas.MemoryTestConfig(tc.t)
	quicbaasCfg.NodeID = cfg.NodeID

	factory, err := quicbaas.NewFactory(quicbaasCfg, tc.logger, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create quicbaas factory: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	if err := factory.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start quicbaas factory: %w", err)
	}

	localStorage := factory.Storage()
	if localStorage == nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stopCancel()
		factory.Stop(stopCtx)
		return nil, fmt.Errorf("quicbaas factory storage is nil after start")
	}

	// Register this node's storage with the shared storage for replication
	tc.sharedStorage.registerReplica(cfg.NodeID, localStorage)

	// Create replicating storage wrapper that propagates writes to all nodes
	replicatingStorage := newReplicatingStorage(cfg.NodeID, localStorage, tc.sharedStorage)

	// Create mock RaftOperator with shared state
	raftOp := newMockRaftOperator(cfg.NodeID, tc.sharedState)

	// Create membership manager
	membership, err := cluster.NewMembershipManager(cfg, raftOp, tc.logger)
	if err != nil {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stopCancel()
		factory.Stop(stopCtx)
		return nil, fmt.Errorf("failed to create membership manager: %w", err)
	}

	// Create coordinator
	coordinator, err := cluster.NewCoordinator(cfg, membership, tc.logger)
	if err != nil {
		membership.Close()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer stopCancel()
		factory.Stop(stopCtx)
		return nil, fmt.Errorf("failed to create coordinator: %w", err)
	}

	return &testNode{
		id:          cfg.NodeID,
		config:      cfg,
		coordinator: coordinator,
		membership:  membership,
		raftOp:      raftOp,
		factory:     factory,
		storage:     replicatingStorage,
		logger:      tc.logger,
	}, nil
}

// stop gracefully stops all nodes in the cluster.
func (tc *testCluster) stop() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), defaultClusterTimeout)
	defer cancel()

	// Stop nodes in reverse order (followers first)
	for i := len(tc.nodes) - 1; i >= 0; i-- {
		node := tc.nodes[i]
		if node.coordinator != nil {
			if err := node.coordinator.Stop(ctx); err != nil {
				tc.t.Logf("Warning: failed to stop coordinator for node %d: %v", node.id, err)
			}
		}
		if node.membership != nil {
			node.membership.Close()
		}
		if node.factory != nil {
			if err := node.factory.Stop(ctx); err != nil {
				tc.t.Logf("Warning: failed to stop factory for node %d: %v", node.id, err)
			}
		}
	}

	// Stop the shared storage
	if tc.sharedStorage != nil {
		tc.sharedStorage.stop()
	}

	tc.nodes = nil
}

// getNode returns the node at the specified index.
func (tc *testCluster) getNode(index int) *testNode {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if index < 0 || index >= len(tc.nodes) {
		return nil
	}
	return tc.nodes[index]
}

// getLeader returns the current leader node.
func (tc *testCluster) getLeader() *testNode {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for _, node := range tc.nodes {
		if node.coordinator.IsLeader() {
			return node
		}
	}
	return nil
}

// getFollowers returns all follower nodes.
func (tc *testCluster) getFollowers() []*testNode {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	followers := make([]*testNode, 0)
	for _, node := range tc.nodes {
		if !node.coordinator.IsLeader() {
			followers = append(followers, node)
		}
	}
	return followers
}

// waitForClusterReady waits until all nodes are healthy and a leader is elected.
func (tc *testCluster) waitForClusterReady(ctx context.Context) error {
	tc.t.Log("Waiting for cluster to become ready...")

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for cluster to become ready: %w", ctx.Err())
		case <-ticker.C:
			if tc.isClusterReady() {
				tc.t.Log("Cluster is ready")
				return nil
			}
		}
	}
}

// isClusterReady checks if all nodes are healthy and a leader exists.
func (tc *testCluster) isClusterReady() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if len(tc.nodes) == 0 {
		return false
	}

	hasLeader := false
	allHealthy := true

	for _, node := range tc.nodes {
		if node.coordinator == nil {
			return false
		}

		if !node.coordinator.IsHealthy() {
			allHealthy = false
		}

		if node.coordinator.IsLeader() {
			hasLeader = true
		}
	}

	return hasLeader && allHealthy
}

// waitForLeader waits until a leader is elected in the cluster.
func (tc *testCluster) waitForLeader(ctx context.Context) (*testNode, error) {
	tc.t.Log("Waiting for leader election...")

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for leader: %w", ctx.Err())
		case <-ticker.C:
			if leader := tc.getLeader(); leader != nil {
				tc.t.Logf("Leader elected: node %d", leader.id)
				return leader, nil
			}
		}
	}
}

// getClusterNodes returns the list of all nodes in the cluster.
func (tc *testCluster) getClusterNodes() []*testNode {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	nodes := make([]*testNode, len(tc.nodes))
	copy(nodes, tc.nodes)
	return nodes
}

// nodeCount returns the number of nodes in the cluster.
func (tc *testCluster) nodeCount() int {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return len(tc.nodes)
}

// sharedClusterState provides shared state across all mock Raft operators
// to simulate a real Raft cluster where all nodes see the same membership.
type sharedClusterState struct {
	mu       sync.RWMutex
	nodes    map[uint64]cluster.RaftMemberInfo
	leaderID uint64
	term     uint64
}

func newSharedClusterState() *sharedClusterState {
	return &sharedClusterState{
		nodes: make(map[uint64]cluster.RaftMemberInfo),
		term:  1,
	}
}

// mockRaftOperator implements RaftOperator for testing with shared state.
type mockRaftOperator struct {
	nodeID uint64
	state  *sharedClusterState // Shared state across all nodes
}

func newMockRaftOperator(nodeID uint64, state *sharedClusterState) *mockRaftOperator {
	return &mockRaftOperator{
		nodeID: nodeID,
		state:  state,
	}
}

func (m *mockRaftOperator) Bootstrap(ctx context.Context) error {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()

	m.state.nodes[m.nodeID] = cluster.RaftMemberInfo{
		ID:      m.nodeID,
		Address: fmt.Sprintf("127.0.0.1:%d", 15000+m.nodeID-1),
		Voter:   true,
	}
	m.state.leaderID = m.nodeID
	return nil
}

func (m *mockRaftOperator) AddVoter(ctx context.Context, id uint64, address string) error {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()

	m.state.nodes[id] = cluster.RaftMemberInfo{
		ID:      id,
		Address: address,
		Voter:   true,
	}
	return nil
}

func (m *mockRaftOperator) AddNonvoter(ctx context.Context, id uint64, address string) error {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()

	m.state.nodes[id] = cluster.RaftMemberInfo{
		ID:      id,
		Address: address,
		Voter:   false,
	}
	return nil
}

func (m *mockRaftOperator) RemoveServer(ctx context.Context, id uint64) error {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()

	delete(m.state.nodes, id)
	if m.state.leaderID == id {
		m.state.leaderID = 0
	}
	return nil
}

func (m *mockRaftOperator) GetLeader() (id uint64, address string, err error) {
	m.state.mu.RLock()
	defer m.state.mu.RUnlock()

	if m.state.leaderID == 0 {
		return 0, "", nil
	}

	if info, ok := m.state.nodes[m.state.leaderID]; ok {
		return m.state.leaderID, info.Address, nil
	}
	return 0, "", nil
}

func (m *mockRaftOperator) GetNodes() ([]cluster.RaftMemberInfo, error) {
	m.state.mu.RLock()
	defer m.state.mu.RUnlock()

	nodes := make([]cluster.RaftMemberInfo, 0, len(m.state.nodes))
	for _, info := range m.state.nodes {
		nodes = append(nodes, info)
	}
	return nodes, nil
}

func (m *mockRaftOperator) IsLeader() bool {
	m.state.mu.RLock()
	defer m.state.mu.RUnlock()
	return m.state.leaderID == m.nodeID
}

func (m *mockRaftOperator) GetState() cluster.RaftState {
	m.state.mu.RLock()
	defer m.state.mu.RUnlock()

	if m.state.leaderID == m.nodeID {
		return cluster.RaftStateLeader
	}
	return cluster.RaftStateFollower
}

func (m *mockRaftOperator) GetTerm() uint64 {
	m.state.mu.RLock()
	defer m.state.mu.RUnlock()
	return m.state.term
}

func (m *mockRaftOperator) setLeader(id uint64) {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	m.state.leaderID = id
}

func (m *mockRaftOperator) incrementTerm() {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	m.state.term++
}

// newClusterStorage creates a new QuicBaaS factory and storage for testing.
// Returns the storage interface and a cleanup function.
func newClusterStorage(t *testing.T) (quicbaas.Storage, func()) {
	t.Helper()

	cfg := quicbaas.MemoryTestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err, "Failed to create QuicBaaS factory")

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	err = factory.Start(ctx)
	require.NoError(t, err, "Failed to start QuicBaaS factory")

	storage := factory.Storage()
	require.NotNil(t, storage, "Factory storage is nil")

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := factory.Stop(ctx); err != nil {
			t.Logf("Warning: factory stop error: %v", err)
		}
	}

	return storage, cleanup
}

// newTestCoordinator creates a new coordinator for testing.
func newTestCoordinator(t *testing.T, nodeID uint64) (cluster.Coordinator, cluster.MembershipManager, func()) {
	t.Helper()

	cfg := cluster.NewConfig()
	cfg.NodeID = nodeID
	cfg.ListenAddress = fmt.Sprintf("127.0.0.1:%d", 15000+nodeID)
	cfg.AdvertiseAddress = cfg.ListenAddress
	cfg.DataDir = t.TempDir()

	logger := logging.DefaultLogger()

	_, cleanup := newClusterStorage(t)

	// Create shared state for this single-node test
	sharedState := newSharedClusterState()
	raftOp := newMockRaftOperator(nodeID, sharedState)

	membership, err := cluster.NewMembershipManager(cfg, raftOp, logger)
	require.NoError(t, err)

	coordinator, err := cluster.NewCoordinator(cfg, membership, logger)
	require.NoError(t, err)

	return coordinator, membership, func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
		defer cancel()
		coordinator.Stop(ctx)
		membership.Close()
		cleanup()
	}
}
