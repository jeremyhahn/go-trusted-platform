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
	"time"
)

// NodeState represents the health state of a cluster node.
type NodeState int32

const (
	// NodeStateUnknown indicates the node state is unknown.
	NodeStateUnknown NodeState = iota
	// NodeStateHealthy indicates the node is healthy and responsive.
	NodeStateHealthy
	// NodeStateUnhealthy indicates the node is unhealthy or unresponsive.
	NodeStateUnhealthy
	// NodeStateSuspect indicates the node may be failing.
	NodeStateSuspect
	// NodeStateLeaving indicates the node has left the cluster.
	NodeStateLeaving
)

// String returns the string representation of the node state.
func (s NodeState) String() string {
	switch s {
	case NodeStateHealthy:
		return "healthy"
	case NodeStateUnhealthy:
		return "unhealthy"
	case NodeStateSuspect:
		return "suspect"
	case NodeStateLeaving:
		return "leaving"
	default:
		return "unknown"
	}
}

// Node represents a cluster node for the Coordinator and MembershipManager interfaces.
type Node struct {
	// ID is the unique identifier for this node.
	ID uint64 `json:"id" yaml:"id"`

	// Address is the network address for cluster communication.
	Address string `json:"address" yaml:"address"`

	// RaftAddress is the address used for Raft consensus communication.
	RaftAddress string `json:"raft_address,omitempty" yaml:"raft_address,omitempty"`

	// IsLeader indicates whether this node is the current leader.
	IsLeader bool `json:"is_leader" yaml:"is_leader"`

	// State is the current health state of the node.
	State NodeState `json:"state" yaml:"state"`

	// LastSeen is the last time this node was seen.
	LastSeen time.Time `json:"last_seen" yaml:"last_seen"`

	// JoinTime is when this node joined the cluster.
	JoinTime time.Time `json:"join_time" yaml:"join_time"`

	// Metadata contains optional node metadata.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// IsHealthy returns true if this node is in a healthy state.
func (n *Node) IsHealthy() bool {
	return n.State == NodeStateHealthy
}

// Clone returns a deep copy of the node.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	clone := &Node{
		ID:          n.ID,
		Address:     n.Address,
		RaftAddress: n.RaftAddress,
		IsLeader:    n.IsLeader,
		State:       n.State,
		LastSeen:    n.LastSeen,
		JoinTime:    n.JoinTime,
	}
	if n.Metadata != nil {
		clone.Metadata = make(map[string]string, len(n.Metadata))
		for k, v := range n.Metadata {
			clone.Metadata[k] = v
		}
	}
	return clone
}

// NodeList represents a list of cluster nodes.
type NodeList struct {
	// Nodes is the list of nodes in the cluster.
	Nodes []*Node

	// Leader is the current leader node, if any.
	Leader *Node

	// Term is the current Raft term.
	Term uint64
}

// Count returns the number of nodes in the list.
func (nl *NodeList) Count() int {
	return len(nl.Nodes)
}

// HealthyCount returns the number of healthy nodes.
func (nl *NodeList) HealthyCount() int {
	count := 0
	for _, n := range nl.Nodes {
		if n.IsHealthy() {
			count++
		}
	}
	return count
}

// FindByID finds a node by its ID.
func (nl *NodeList) FindByID(id uint64) *Node {
	for _, n := range nl.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

// Healthy returns all healthy nodes.
func (nl *NodeList) Healthy() []*Node {
	healthy := make([]*Node, 0, len(nl.Nodes))
	for _, n := range nl.Nodes {
		if n.IsHealthy() {
			healthy = append(healthy, n)
		}
	}
	return healthy
}

// MembershipManager defines the interface for cluster membership management.
// This interface abstracts the underlying membership and consensus implementation.
type MembershipManager interface {
	// Bootstrap initializes a new cluster with this node as the first member.
	Bootstrap(ctx context.Context) error

	// Join adds this node to an existing cluster.
	Join(ctx context.Context, addresses []string) error

	// Leave gracefully removes this node from the cluster.
	Leave(ctx context.Context) error

	// AddNode adds a new node to the cluster (leader only).
	AddNode(ctx context.Context, nodeID uint64, address string) error

	// RemoveNode removes a node from the cluster (leader only).
	RemoveNode(ctx context.Context, nodeID uint64) error

	// GetNodes returns all known cluster nodes.
	GetNodes(ctx context.Context) (NodeList, error)

	// InvalidateCache forces the next GetNodes call to refresh from Raft state.
	InvalidateCache()

	// GetLeader returns the current leader node.
	GetLeader(ctx context.Context) (*Node, error)

	// IsLeader returns true if this node is the leader.
	IsLeader() bool

	// WaitForLeader waits for a leader to be elected.
	WaitForLeader(ctx context.Context) (*Node, error)

	// LocalNode returns information about the local node.
	LocalNode() *Node

	// GetTerm returns the current Raft term number.
	GetTerm() uint64

	// Close shuts down the membership manager.
	Close() error
}
