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
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// RaftOperator provides Raft cluster operations.
// This interface abstracts the underlying Raft implementation (e.g., QuicBaaS)
// to allow for testing and flexibility in the Raft backend.
type RaftOperator interface {
	// Bootstrap initializes a new Raft cluster with this node as the first member.
	Bootstrap(ctx context.Context) error

	// AddVoter adds a voting member to the Raft cluster.
	AddVoter(ctx context.Context, id uint64, address string) error

	// AddNonvoter adds a non-voting member to the Raft cluster.
	AddNonvoter(ctx context.Context, id uint64, address string) error

	// RemoveServer removes a server from the Raft cluster.
	RemoveServer(ctx context.Context, id uint64) error

	// GetLeader returns the current leader's ID and address.
	// Returns 0, "" if no leader is elected.
	GetLeader() (id uint64, address string, err error)

	// GetNodes returns all known nodes in the Raft cluster.
	GetNodes() ([]RaftMemberInfo, error)

	// IsLeader returns true if this node is the Raft leader.
	IsLeader() bool

	// GetState returns the current Raft state of this node.
	GetState() RaftState

	// GetTerm returns the current Raft term number.
	GetTerm() uint64
}

// RaftMemberInfo represents basic information about a node in the Raft cluster
// as returned by the RaftOperator. This is distinct from the RaftNode type in
// node.go which has more detailed health tracking information.
type RaftMemberInfo struct {
	ID      uint64
	Address string
	Voter   bool
}

// RaftState represents the Raft state of a node.
type RaftState int32

const (
	// RaftStateFollower indicates the node is a Raft follower.
	RaftStateFollower RaftState = iota
	// RaftStateCandidate indicates the node is a Raft candidate.
	RaftStateCandidate
	// RaftStateLeader indicates the node is the Raft leader.
	RaftStateLeader
	// RaftStateShutdown indicates the Raft node is shut down.
	RaftStateShutdown
)

// membershipManager implements MembershipManager using a RaftOperator.
// MembershipManager interface is defined in coordinator.go.
type membershipManager struct {
	config    *Config
	raftOp    RaftOperator
	logger    *logging.Logger
	localNode *Node

	// nodeCache caches known nodes for fast lookups.
	nodeCache     map[uint64]*Node
	nodeCacheMu   sync.RWMutex
	cacheExpiry   time.Time
	cacheDuration time.Duration

	// State tracking using atomics for lock-free reads.
	joined atomic.Bool
	closed atomic.Bool

	// leaderWaiters notifies goroutines waiting for leader election.
	leaderWaiters     []chan *Node
	leaderWaitersMu   sync.Mutex
	leaderCheckTicker *time.Ticker
	stopLeaderCheck   chan struct{}
}

// NewMembershipManager creates a new membership manager with the provided configuration.
// It implements the MembershipManager interface defined in coordinator.go.
func NewMembershipManager(config *Config, raftOp RaftOperator, logger *logging.Logger) (*membershipManager, error) {
	if config == nil {
		return nil, ErrInvalidConfig{
			Field:  "config",
			Reason: "configuration is required",
		}
	}

	if raftOp == nil {
		return nil, ErrInvalidConfig{
			Field:  "raftOp",
			Reason: "Raft operator is required",
		}
	}

	if logger == nil {
		return nil, ErrInvalidConfig{
			Field:  "logger",
			Reason: "logger is required",
		}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	localNode := &Node{
		ID:       config.NodeID,
		Address:  config.GetAdvertiseAddress(),
		State:    NodeStateUnknown,
		IsLeader: false,
		JoinTime: time.Time{},
		Metadata: make(map[string]string),
	}

	m := &membershipManager{
		config:          config,
		raftOp:          raftOp,
		logger:          logger,
		localNode:       localNode,
		nodeCache:       make(map[uint64]*Node),
		cacheDuration:   5 * time.Second,
		leaderWaiters:   make([]chan *Node, 0),
		stopLeaderCheck: make(chan struct{}),
	}

	// Start leader check routine for notifying waiters.
	m.leaderCheckTicker = time.NewTicker(100 * time.Millisecond)
	go m.leaderCheckLoop()

	logger.Debug("membership manager created",
		"node_id", config.NodeID,
		"address", config.GetAdvertiseAddress())

	return m, nil
}

// Bootstrap initializes a new cluster with this node as the first member.
func (m *membershipManager) Bootstrap(ctx context.Context) error {
	if m.closed.Load() {
		return ErrManagerClosed{}
	}

	if m.joined.Load() {
		return ErrAlreadyJoined{}
	}

	m.logger.Info("bootstrapping new cluster",
		"node_id", m.config.NodeID,
		"address", m.config.GetAdvertiseAddress())

	if err := m.raftOp.Bootstrap(ctx); err != nil {
		return ErrBootstrapFailed{
			Reason: "raft bootstrap failed",
			Cause:  err,
		}
	}

	m.joined.Store(true)
	m.localNode.JoinTime = time.Now()
	m.localNode.LastSeen = time.Now()
	m.localNode.State = NodeStateHealthy
	m.updateLocalNodeLeaderStatus()

	// Add ourselves to the cache.
	m.nodeCacheMu.Lock()
	m.nodeCache[m.localNode.ID] = m.localNode
	m.nodeCacheMu.Unlock()

	m.logger.Info("cluster bootstrapped successfully",
		"node_id", m.config.NodeID)

	return nil
}

// Join adds this node to an existing cluster.
func (m *membershipManager) Join(ctx context.Context, addresses []string) error {
	if m.closed.Load() {
		return ErrManagerClosed{}
	}

	if m.joined.Load() {
		return ErrAlreadyJoined{}
	}

	if len(addresses) == 0 {
		return ErrNoJoinAddresses{}
	}

	m.logger.Info("joining existing cluster",
		"node_id", m.config.NodeID,
		"join_addresses", addresses)

	// Try each join address until one succeeds.
	var lastErr error
	for _, addr := range addresses {
		if err := m.tryJoin(ctx, addr); err != nil {
			lastErr = err
			m.logger.Warn("join attempt failed",
				"address", addr,
				"error", err)
			continue
		}

		m.joined.Store(true)
		m.localNode.JoinTime = time.Now()
		m.localNode.LastSeen = time.Now()
		m.localNode.State = NodeStateHealthy
		m.updateLocalNodeLeaderStatus()

		// Add ourselves to the cache.
		m.nodeCacheMu.Lock()
		m.nodeCache[m.localNode.ID] = m.localNode
		m.nodeCacheMu.Unlock()

		m.logger.Info("joined cluster successfully",
			"node_id", m.config.NodeID,
			"via_address", addr)

		return nil
	}

	return ErrJoinFailed{
		NodeID:  m.config.NodeID,
		Address: addresses[0],
		Reason:  "all join addresses failed",
		Cause:   lastErr,
	}
}

// tryJoin attempts to join the cluster via a specific address.
// In a real implementation, this would make an RPC call to the target node
// to request being added to the cluster.
func (m *membershipManager) tryJoin(ctx context.Context, address string) error {
	// Validate address format.
	if address == "" {
		return ErrInvalidAddress{
			Address: address,
			Reason:  "address cannot be empty",
		}
	}

	// This is a placeholder for the actual join logic.
	// The real implementation would:
	// 1. Connect to the target node.
	// 2. Send a join request with our node ID and address.
	// 3. Wait for the leader to add us via AddVoter.
	// 4. Receive confirmation that we've been added.

	// For now, we add ourselves to the Raft cluster directly.
	// In a real implementation, this would be done via RPC to the leader.
	select {
	case <-ctx.Done():
		return ErrTimeout{Operation: "join"}
	default:
		// Add ourselves to the Raft cluster as a voter.
		// In a real implementation, this would be an RPC call to the leader
		// who would then call AddVoter on our behalf.
		if err := m.raftOp.AddVoter(ctx, m.config.NodeID, m.config.GetAdvertiseAddress()); err != nil {
			return ErrJoinFailed{
				NodeID:  m.config.NodeID,
				Address: address,
				Reason:  "failed to add voter",
				Cause:   err,
			}
		}
		return nil
	}
}

// Leave gracefully removes this node from the cluster.
func (m *membershipManager) Leave(ctx context.Context) error {
	if m.closed.Load() {
		return ErrManagerClosed{}
	}

	if !m.joined.Load() {
		return ErrNotJoined{}
	}

	m.logger.Info("leaving cluster",
		"node_id", m.config.NodeID)

	// If we're the leader, we need to transfer leadership first.
	// For simplicity, we just remove ourselves from the cluster.
	if err := m.raftOp.RemoveServer(ctx, m.config.NodeID); err != nil {
		return ErrLeaveFailed{
			NodeID: m.config.NodeID,
			Reason: "failed to remove from cluster",
			Cause:  err,
		}
	}

	m.joined.Store(false)
	m.localNode.State = NodeStateLeaving

	// Clear the cache.
	m.nodeCacheMu.Lock()
	m.nodeCache = make(map[uint64]*Node)
	m.nodeCacheMu.Unlock()

	m.logger.Info("left cluster successfully",
		"node_id", m.config.NodeID)

	return nil
}

// AddNode adds a new node to the cluster (leader only).
func (m *membershipManager) AddNode(ctx context.Context, nodeID uint64, address string) error {
	if m.closed.Load() {
		return ErrManagerClosed{}
	}

	if !m.joined.Load() {
		return ErrNotJoined{}
	}

	if !m.IsLeader() {
		leaderID, _, _ := m.raftOp.GetLeader()
		return ErrNodeNotLeader{
			NodeID:   m.config.NodeID,
			LeaderID: leaderID,
		}
	}

	if nodeID == 0 {
		return ErrInvalidConfig{
			Field:  "nodeID",
			Reason: "node ID must be greater than 0",
		}
	}

	if address == "" {
		return ErrInvalidAddress{
			Address: address,
			Reason:  "address cannot be empty",
		}
	}

	// Check if node already exists.
	m.nodeCacheMu.RLock()
	if _, exists := m.nodeCache[nodeID]; exists {
		m.nodeCacheMu.RUnlock()
		return ErrNodeAlreadyExists{NodeID: nodeID}
	}
	m.nodeCacheMu.RUnlock()

	m.logger.Info("adding node to cluster",
		"node_id", nodeID,
		"address", address)

	if err := m.raftOp.AddVoter(ctx, nodeID, address); err != nil {
		return ErrAddNodeFailed{
			NodeID:  nodeID,
			Address: address,
			Cause:   err,
		}
	}

	// Add to cache.
	newNode := &Node{
		ID:       nodeID,
		Address:  address,
		State:    NodeStateHealthy,
		IsLeader: false,
		LastSeen: time.Now(),
		JoinTime: time.Now(),
		Metadata: make(map[string]string),
	}

	m.nodeCacheMu.Lock()
	m.nodeCache[nodeID] = newNode
	m.nodeCacheMu.Unlock()

	m.logger.Info("node added successfully",
		"node_id", nodeID,
		"address", address)

	return nil
}

// RemoveNode removes a node from the cluster (leader only).
func (m *membershipManager) RemoveNode(ctx context.Context, nodeID uint64) error {
	if m.closed.Load() {
		return ErrManagerClosed{}
	}

	if !m.joined.Load() {
		return ErrNotJoined{}
	}

	if !m.IsLeader() {
		leaderID, _, _ := m.raftOp.GetLeader()
		return ErrNodeNotLeader{
			NodeID:   m.config.NodeID,
			LeaderID: leaderID,
		}
	}

	if nodeID == 0 {
		return ErrInvalidConfig{
			Field:  "nodeID",
			Reason: "node ID must be greater than 0",
		}
	}

	// Check if node exists.
	m.nodeCacheMu.RLock()
	_, exists := m.nodeCache[nodeID]
	m.nodeCacheMu.RUnlock()

	if !exists {
		// Refresh cache from Raft and check again.
		if err := m.refreshNodeCache(); err == nil {
			m.nodeCacheMu.RLock()
			_, exists = m.nodeCache[nodeID]
			m.nodeCacheMu.RUnlock()
		}

		if !exists {
			return ErrNodeNotFound{NodeID: nodeID}
		}
	}

	m.logger.Info("removing node from cluster",
		"node_id", nodeID)

	if err := m.raftOp.RemoveServer(ctx, nodeID); err != nil {
		return ErrRemoveNodeFailed{
			NodeID: nodeID,
			Cause:  err,
		}
	}

	// Remove from cache.
	m.nodeCacheMu.Lock()
	delete(m.nodeCache, nodeID)
	m.nodeCacheMu.Unlock()

	m.logger.Info("node removed successfully",
		"node_id", nodeID)

	return nil
}

// GetNodes returns all known cluster nodes.
// This implements the MembershipManager interface defined in types.go.
func (m *membershipManager) GetNodes(ctx context.Context) (NodeList, error) {
	if m.closed.Load() {
		return NodeList{}, ErrManagerClosed{}
	}

	if !m.joined.Load() {
		return NodeList{}, ErrNotJoined{}
	}

	// Check if cache is still valid.
	m.nodeCacheMu.RLock()
	cacheValid := time.Now().Before(m.cacheExpiry) && len(m.nodeCache) > 0
	m.nodeCacheMu.RUnlock()

	if !cacheValid {
		if err := m.refreshNodeCache(); err != nil {
			return NodeList{}, err
		}
	}

	// Build node list from cache.
	m.nodeCacheMu.RLock()
	defer m.nodeCacheMu.RUnlock()

	nodes := make([]*Node, 0, len(m.nodeCache))
	var leader *Node

	for _, node := range m.nodeCache {
		nodeCopy := node.Clone()
		nodes = append(nodes, nodeCopy)
		if node.IsLeader {
			leader = nodeCopy
		}
	}

	return NodeList{
		Nodes:  nodes,
		Leader: leader,
		Term:   m.raftOp.GetTerm(),
	}, nil
}

// refreshNodeCache updates the node cache from the Raft cluster state.
func (m *membershipManager) refreshNodeCache() error {
	raftNodes, err := m.raftOp.GetNodes()
	if err != nil {
		return ErrClusterUnavailable{Reason: err.Error()}
	}

	leaderID, leaderAddr, _ := m.raftOp.GetLeader()

	m.nodeCacheMu.Lock()
	defer m.nodeCacheMu.Unlock()

	// Update existing nodes and add new ones.
	seenIDs := make(map[uint64]bool)

	for _, rn := range raftNodes {
		seenIDs[rn.ID] = true

		isLeader := rn.ID == leaderID

		if existing, ok := m.nodeCache[rn.ID]; ok {
			// Update existing node.
			existing.LastSeen = time.Now()
			existing.IsLeader = isLeader
			if isLeader && leaderAddr != "" {
				existing.Address = leaderAddr
			}
		} else {
			// Add new node.
			addr := rn.Address
			if isLeader && leaderAddr != "" {
				addr = leaderAddr
			}

			m.nodeCache[rn.ID] = &Node{
				ID:       rn.ID,
				Address:  addr,
				State:    NodeStateHealthy,
				IsLeader: isLeader,
				LastSeen: time.Now(),
				Metadata: make(map[string]string),
			}
		}
	}

	// Mark nodes not in Raft as having left.
	for id, node := range m.nodeCache {
		if !seenIDs[id] && node.State != NodeStateLeaving {
			// Only mark as leaving if the node isn't the local node that just joined.
			if id != m.config.NodeID {
				node.State = NodeStateLeaving
			}
		}
	}

	// Update local node's leader status.
	if local, ok := m.nodeCache[m.config.NodeID]; ok {
		local.IsLeader = leaderID == m.config.NodeID
		m.localNode.IsLeader = local.IsLeader
	}

	m.cacheExpiry = time.Now().Add(m.cacheDuration)

	return nil
}

// InvalidateCache forces the next GetNodes call to refresh from Raft state.
func (m *membershipManager) InvalidateCache() {
	m.nodeCacheMu.Lock()
	defer m.nodeCacheMu.Unlock()
	m.cacheExpiry = time.Time{} // Zero time ensures cache is invalid
}

// GetLeader returns the current leader node.
func (m *membershipManager) GetLeader(ctx context.Context) (*Node, error) {
	if m.closed.Load() {
		return nil, ErrManagerClosed{}
	}

	if !m.joined.Load() {
		return nil, ErrNotJoined{}
	}

	leaderID, leaderAddr, err := m.raftOp.GetLeader()
	if err != nil {
		return nil, ErrClusterUnavailable{Reason: err.Error()}
	}

	if leaderID == 0 {
		return nil, ErrNoLeader{}
	}

	// Try to get from cache first.
	m.nodeCacheMu.RLock()
	if leader, ok := m.nodeCache[leaderID]; ok {
		m.nodeCacheMu.RUnlock()
		return leader, nil
	}
	m.nodeCacheMu.RUnlock()

	// Not in cache, create a minimal node.
	return &Node{
		ID:       leaderID,
		Address:  leaderAddr,
		State:    NodeStateHealthy,
		IsLeader: true,
		LastSeen: time.Now(),
	}, nil
}

// IsLeader returns true if this node is the leader.
func (m *membershipManager) IsLeader() bool {
	if m.closed.Load() || !m.joined.Load() {
		return false
	}
	return m.raftOp.IsLeader()
}

// GetTerm returns the current Raft term number.
func (m *membershipManager) GetTerm() uint64 {
	if m.closed.Load() || !m.joined.Load() {
		return 0
	}
	return m.raftOp.GetTerm()
}

// WaitForLeader waits for a leader to be elected.
func (m *membershipManager) WaitForLeader(ctx context.Context) (*Node, error) {
	if m.closed.Load() {
		return nil, ErrManagerClosed{}
	}

	if !m.joined.Load() {
		return nil, ErrNotJoined{}
	}

	// Check if we already have a leader.
	if leader, err := m.GetLeader(ctx); err == nil && leader != nil {
		return leader, nil
	}

	// Create a channel to wait for leader notification.
	waiterCh := make(chan *Node, 1)

	m.leaderWaitersMu.Lock()
	m.leaderWaiters = append(m.leaderWaiters, waiterCh)
	m.leaderWaitersMu.Unlock()

	// Clean up the waiter channel when we're done.
	defer func() {
		m.leaderWaitersMu.Lock()
		for i, ch := range m.leaderWaiters {
			if ch == waiterCh {
				m.leaderWaiters = append(m.leaderWaiters[:i], m.leaderWaiters[i+1:]...)
				break
			}
		}
		m.leaderWaitersMu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return nil, ErrLeadershipTimeout{}
	case leader := <-waiterCh:
		return leader, nil
	}
}

// leaderCheckLoop periodically checks for a leader and notifies waiters.
func (m *membershipManager) leaderCheckLoop() {
	for {
		select {
		case <-m.stopLeaderCheck:
			return
		case <-m.leaderCheckTicker.C:
			if m.closed.Load() || !m.joined.Load() {
				continue
			}

			leaderID, leaderAddr, err := m.raftOp.GetLeader()
			if err != nil || leaderID == 0 {
				continue
			}

			// Update local node leader status.
			m.updateLocalNodeLeaderStatus()

			// Notify any waiters.
			m.leaderWaitersMu.Lock()
			if len(m.leaderWaiters) > 0 {
				leader := &Node{
					ID:       leaderID,
					Address:  leaderAddr,
					State:    NodeStateHealthy,
					IsLeader: true,
					LastSeen: time.Now(),
				}

				for _, ch := range m.leaderWaiters {
					select {
					case ch <- leader:
					default:
						// Channel already has a value or is full.
					}
				}
				m.leaderWaiters = m.leaderWaiters[:0]
			}
			m.leaderWaitersMu.Unlock()
		}
	}
}

// updateLocalNodeLeaderStatus updates the local node's leader status based on Raft state.
func (m *membershipManager) updateLocalNodeLeaderStatus() {
	m.localNode.IsLeader = m.raftOp.IsLeader()
}

// LocalNode returns information about the local node.
func (m *membershipManager) LocalNode() *Node {
	return m.localNode
}

// Close shuts down the membership manager.
func (m *membershipManager) Close() error {
	if m.closed.Swap(true) {
		// Already closed.
		return nil
	}

	m.logger.Debug("closing membership manager",
		"node_id", m.config.NodeID)

	// Stop the leader check loop.
	close(m.stopLeaderCheck)
	m.leaderCheckTicker.Stop()

	// Notify all waiters that we're closing.
	m.leaderWaitersMu.Lock()
	for _, ch := range m.leaderWaiters {
		close(ch)
	}
	m.leaderWaiters = nil
	m.leaderWaitersMu.Unlock()

	// Clear the cache.
	m.nodeCacheMu.Lock()
	m.nodeCache = nil
	m.nodeCacheMu.Unlock()

	return nil
}

// Ensure membershipManager implements MembershipManager.
var _ MembershipManager = (*membershipManager)(nil)
