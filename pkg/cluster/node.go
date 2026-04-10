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
	"sort"
	"sync"
	"time"
)

// ExtendedNodeState represents the extended health state of a cluster node.
// This type provides additional health-specific states beyond NodeState.
type ExtendedNodeState string

const (
	// ExtNodeStateUnknown indicates the node state is unknown.
	ExtNodeStateUnknown ExtendedNodeState = "unknown"

	// ExtNodeStateHealthy indicates the node is healthy and responsive.
	ExtNodeStateHealthy ExtendedNodeState = "healthy"

	// ExtNodeStateUnhealthy indicates the node is unhealthy but reachable.
	ExtNodeStateUnhealthy ExtendedNodeState = "unhealthy"

	// ExtNodeStateUnreachable indicates the node cannot be reached.
	ExtNodeStateUnreachable ExtendedNodeState = "unreachable"

	// ExtNodeStateLeaving indicates the node is gracefully leaving the cluster.
	ExtNodeStateLeaving ExtendedNodeState = "leaving"
)

// validExtendedNodeStates contains all valid extended node state values for quick lookup.
var validExtendedNodeStates = map[ExtendedNodeState]struct{}{
	ExtNodeStateUnknown:     {},
	ExtNodeStateHealthy:     {},
	ExtNodeStateUnhealthy:   {},
	ExtNodeStateUnreachable: {},
	ExtNodeStateLeaving:     {},
}

// String returns the string representation of the extended node state.
func (s ExtendedNodeState) String() string {
	return string(s)
}

// IsValid checks if the extended node state is a valid state value.
func (s ExtendedNodeState) IsValid() bool {
	_, exists := validExtendedNodeStates[s]
	return exists
}

// ToNodeState converts ExtendedNodeState to the base NodeState type.
func (s ExtendedNodeState) ToNodeState() NodeState {
	switch s {
	case ExtNodeStateHealthy:
		return NodeStateHealthy
	case ExtNodeStateUnhealthy:
		return NodeStateUnhealthy
	case ExtNodeStateLeaving:
		return NodeStateLeaving
	default:
		return NodeStateUnknown
	}
}

// ParseExtendedNodeState parses a string into an ExtendedNodeState value.
// Returns an error if the string does not represent a valid state.
func ParseExtendedNodeState(s string) (ExtendedNodeState, error) {
	state := ExtendedNodeState(s)
	if !state.IsValid() {
		return "", ErrInvalidNodeState{State: NodeState(-1)}
	}
	return state, nil
}

// AllExtendedNodeStates returns all valid extended node states.
func AllExtendedNodeStates() []ExtendedNodeState {
	return []ExtendedNodeState{
		ExtNodeStateUnknown,
		ExtNodeStateHealthy,
		ExtNodeStateUnhealthy,
		ExtNodeStateUnreachable,
		ExtNodeStateLeaving,
	}
}

// ExtendedNode represents a member node in the cluster with additional health
// and timing information beyond the base Node type defined in types.go.
type ExtendedNode struct {
	// ID is the unique identifier for this node in the cluster.
	ID uint64

	// Address is the client-facing address for this node (e.g., "192.168.1.10:8080").
	Address string

	// RaftAddress is the Raft consensus address for this node (e.g., "192.168.1.10:9000").
	RaftAddress string

	// State is the current extended health state of this node.
	State ExtendedNodeState

	// IsLeader indicates whether this node is the current Raft leader.
	IsLeader bool

	// LastSeen is the timestamp when this node was last seen or responded to health checks.
	LastSeen time.Time

	// JoinTime is the timestamp when this node joined the cluster.
	JoinTime time.Time
}

// Uptime returns the duration since the node joined the cluster.
func (n *ExtendedNode) Uptime() time.Duration {
	if n.JoinTime.IsZero() {
		return 0
	}
	return time.Since(n.JoinTime)
}

// IsHealthy returns true if the node is in a healthy state and has been seen
// within the health check timeout period.
func (n *ExtendedNode) IsHealthy() bool {
	if n.State != ExtNodeStateHealthy {
		return false
	}

	// Node must have been seen within the last 30 seconds to be considered healthy
	healthCheckTimeout := 30 * time.Second
	return time.Since(n.LastSeen) < healthCheckTimeout
}

// Clone returns a deep copy of the node.
func (n *ExtendedNode) Clone() *ExtendedNode {
	if n == nil {
		return nil
	}
	return &ExtendedNode{
		ID:          n.ID,
		Address:     n.Address,
		RaftAddress: n.RaftAddress,
		State:       n.State,
		IsLeader:    n.IsLeader,
		LastSeen:    n.LastSeen,
		JoinTime:    n.JoinTime,
	}
}

// ToBaseNode converts ExtendedNode to the base Node type defined in types.go.
func (n *ExtendedNode) ToBaseNode() *Node {
	if n == nil {
		return nil
	}

	return &Node{
		ID:          n.ID,
		Address:     n.Address,
		RaftAddress: n.RaftAddress,
		IsLeader:    n.IsLeader,
		State:       n.State.ToNodeState(),
		LastSeen:    n.LastSeen,
		JoinTime:    n.JoinTime,
		Metadata:    make(map[string]string),
	}
}

// ExtendedNodeList is a collection of extended cluster nodes with helper methods.
type ExtendedNodeList []ExtendedNode

// Leader returns the current leader node, or nil if no leader is found.
func (nl ExtendedNodeList) Leader() *ExtendedNode {
	for i := range nl {
		if nl[i].IsLeader {
			return &nl[i]
		}
	}
	return nil
}

// Followers returns all nodes that are not the leader.
func (nl ExtendedNodeList) Followers() []ExtendedNode {
	followers := make([]ExtendedNode, 0, len(nl))
	for _, node := range nl {
		if !node.IsLeader {
			followers = append(followers, node)
		}
	}
	return followers
}

// Healthy returns all nodes in a healthy state.
func (nl ExtendedNodeList) Healthy() []ExtendedNode {
	healthy := make([]ExtendedNode, 0, len(nl))
	for _, node := range nl {
		if node.IsHealthy() {
			healthy = append(healthy, node)
		}
	}
	return healthy
}

// Count returns the total number of nodes in the list.
func (nl ExtendedNodeList) Count() int {
	return len(nl)
}

// ByID returns the node with the given ID, or nil if not found.
func (nl ExtendedNodeList) ByID(id uint64) *ExtendedNode {
	for i := range nl {
		if nl[i].ID == id {
			return &nl[i]
		}
	}
	return nil
}

// ByAddress returns the node with the given client address, or nil if not found.
func (nl ExtendedNodeList) ByAddress(address string) *ExtendedNode {
	for i := range nl {
		if nl[i].Address == address {
			return &nl[i]
		}
	}
	return nil
}

// ByRaftAddress returns the node with the given Raft address, or nil if not found.
func (nl ExtendedNodeList) ByRaftAddress(address string) *ExtendedNode {
	for i := range nl {
		if nl[i].RaftAddress == address {
			return &nl[i]
		}
	}
	return nil
}

// SortByID returns a new ExtendedNodeList sorted by node ID in ascending order.
func (nl ExtendedNodeList) SortByID() ExtendedNodeList {
	sorted := make(ExtendedNodeList, len(nl))
	copy(sorted, nl)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	return sorted
}

// SortByJoinTime returns a new ExtendedNodeList sorted by join time (oldest first).
func (nl ExtendedNodeList) SortByJoinTime() ExtendedNodeList {
	sorted := make(ExtendedNodeList, len(nl))
	copy(sorted, nl)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].JoinTime.Before(sorted[j].JoinTime)
	})
	return sorted
}

// Filter returns a new ExtendedNodeList containing only nodes that match the predicate.
func (nl ExtendedNodeList) Filter(predicate func(*ExtendedNode) bool) ExtendedNodeList {
	filtered := make(ExtendedNodeList, 0)
	for i := range nl {
		if predicate(&nl[i]) {
			filtered = append(filtered, nl[i])
		}
	}
	return filtered
}

// ExtendedNodeRegistry provides thread-safe management of extended cluster node information.
type ExtendedNodeRegistry struct {
	mu    sync.RWMutex
	nodes map[uint64]*ExtendedNode
}

// NewExtendedNodeRegistry creates a new empty extended node registry.
func NewExtendedNodeRegistry() *ExtendedNodeRegistry {
	return &ExtendedNodeRegistry{
		nodes: make(map[uint64]*ExtendedNode),
	}
}

// Add adds or updates a node in the registry.
func (r *ExtendedNodeRegistry) Add(node *ExtendedNode) error {
	if node == nil {
		return ErrNilNode{}
	}
	if node.ID == 0 {
		return ErrInvalidNodeID{ID: node.ID}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.nodes[node.ID] = node.Clone()
	return nil
}

// Remove removes a node from the registry.
func (r *ExtendedNodeRegistry) Remove(nodeID uint64) error {
	if nodeID == 0 {
		return ErrInvalidNodeID{ID: nodeID}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.nodes[nodeID]; !exists {
		return ErrNodeNotFound{NodeID: nodeID}
	}

	delete(r.nodes, nodeID)
	return nil
}

// Get returns a copy of the node with the given ID.
func (r *ExtendedNodeRegistry) Get(nodeID uint64) (*ExtendedNode, error) {
	if nodeID == 0 {
		return nil, ErrInvalidNodeID{ID: nodeID}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	node, exists := r.nodes[nodeID]
	if !exists {
		return nil, ErrNodeNotFound{NodeID: nodeID}
	}

	return node.Clone(), nil
}

// List returns all nodes as an ExtendedNodeList.
func (r *ExtendedNodeRegistry) List() ExtendedNodeList {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make(ExtendedNodeList, 0, len(r.nodes))
	for _, node := range r.nodes {
		list = append(list, *node.Clone())
	}
	return list
}

// UpdateState updates the state of a specific node.
func (r *ExtendedNodeRegistry) UpdateState(nodeID uint64, state ExtendedNodeState) error {
	if nodeID == 0 {
		return ErrInvalidNodeID{ID: nodeID}
	}
	if !state.IsValid() {
		return ErrInvalidNodeState{State: state.ToNodeState()}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	node, exists := r.nodes[nodeID]
	if !exists {
		return ErrNodeNotFound{NodeID: nodeID}
	}

	node.State = state
	node.LastSeen = time.Now()
	return nil
}

// SetLeader marks the specified node as leader and clears the leader flag on all other nodes.
func (r *ExtendedNodeRegistry) SetLeader(nodeID uint64) error {
	if nodeID == 0 {
		return ErrInvalidNodeID{ID: nodeID}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear all leader flags first
	for _, node := range r.nodes {
		node.IsLeader = false
	}

	// Set the new leader
	node, exists := r.nodes[nodeID]
	if !exists {
		return ErrNodeNotFound{NodeID: nodeID}
	}

	node.IsLeader = true
	return nil
}

// ClearLeader clears the leader flag on all nodes.
func (r *ExtendedNodeRegistry) ClearLeader() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, node := range r.nodes {
		node.IsLeader = false
	}
}

// Count returns the number of nodes in the registry.
func (r *ExtendedNodeRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.nodes)
}

// HealthyCount returns the number of healthy nodes in the registry.
func (r *ExtendedNodeRegistry) HealthyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, node := range r.nodes {
		if node.IsHealthy() {
			count++
		}
	}
	return count
}

// UpdateLastSeen updates the last seen timestamp for a node.
func (r *ExtendedNodeRegistry) UpdateLastSeen(nodeID uint64) error {
	if nodeID == 0 {
		return ErrInvalidNodeID{ID: nodeID}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	node, exists := r.nodes[nodeID]
	if !exists {
		return ErrNodeNotFound{NodeID: nodeID}
	}

	node.LastSeen = time.Now()
	return nil
}

// GetLeader returns the current leader node, or an error if no leader exists.
func (r *ExtendedNodeRegistry) GetLeader() (*ExtendedNode, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, node := range r.nodes {
		if node.IsLeader {
			return node.Clone(), nil
		}
	}
	return nil, ErrNoLeader{}
}
