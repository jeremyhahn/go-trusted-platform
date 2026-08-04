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

import "time"

// NodeRole represents the Raft role of a node.
type NodeRole string

const (
	NodeRoleLeader    NodeRole = "leader"
	NodeRoleFollower  NodeRole = "follower"
	NodeRoleCandidate NodeRole = "candidate"
	NodeRoleObserver  NodeRole = "observer"
	NodeRoleUnknown   NodeRole = "unknown"
)

// NodeState represents the health state of a node.
type NodeState string

const (
	NodeStateActive      NodeState = "active"
	NodeStateJoining     NodeState = "joining"
	NodeStateLeaving     NodeState = "leaving"
	NodeStateLeft        NodeState = "left"
	NodeStateFailed      NodeState = "failed"
	NodeStateUnreachable NodeState = "unreachable"
	NodeStateUnknown     NodeState = "unknown"
)

// ClusterState represents the overall cluster health.
type ClusterState string

const (
	ClusterStateHealthy   ClusterState = "healthy"
	ClusterStateUnhealthy ClusterState = "unhealthy"
	ClusterStateUnknown   ClusterState = "unknown"
)

// StatusResponse contains cluster status information.
type StatusResponse struct {
	ClusterID     string       `json:"cluster_id" yaml:"cluster_id"`
	LeaderID      string       `json:"leader_id" yaml:"leader_id"`
	LeaderAddr    string       `json:"leader_addr" yaml:"leader_addr"`
	Term          uint64       `json:"term" yaml:"term"`
	TotalNodes    uint32       `json:"total_nodes" yaml:"total_nodes"`
	HealthyNodes  uint32       `json:"healthy_nodes" yaml:"healthy_nodes"`
	State         ClusterState `json:"state" yaml:"state"`
	LocalNodeID   string       `json:"local_node_id" yaml:"local_node_id"`
	LocalRole     NodeRole     `json:"local_role" yaml:"local_role"`
	LastHeartbeat *time.Time   `json:"last_heartbeat,omitempty" yaml:"last_heartbeat,omitempty"`
	Timestamp     time.Time    `json:"timestamp" yaml:"timestamp"`
}

// NodeInfo contains information about a cluster node.
type NodeInfo struct {
	ID            string     `json:"id" yaml:"id"`
	Address       string     `json:"address" yaml:"address"`
	Port          uint32     `json:"port" yaml:"port"`
	Role          NodeRole   `json:"role" yaml:"role"`
	State         NodeState  `json:"state" yaml:"state"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty" yaml:"last_heartbeat,omitempty"`
	JoinedAt      *time.Time `json:"joined_at,omitempty" yaml:"joined_at,omitempty"`
}

// ListNodesResponse contains the list of cluster nodes.
type ListNodesResponse struct {
	Nodes []*NodeInfo `json:"nodes" yaml:"nodes"`
	Total uint32      `json:"total" yaml:"total"`
}

// BootstrapResponse contains the result of bootstrapping a cluster.
type BootstrapResponse struct {
	ClusterID string `json:"cluster_id" yaml:"cluster_id"`
	NodeID    string `json:"node_id" yaml:"node_id"`
	Message   string `json:"message" yaml:"message"`
}

// JoinResponse contains the result of joining a cluster.
type JoinResponse struct {
	ClusterID  string `json:"cluster_id" yaml:"cluster_id"`
	NodeID     string `json:"node_id" yaml:"node_id"`
	LeaderID   string `json:"leader_id" yaml:"leader_id"`
	LeaderAddr string `json:"leader_addr" yaml:"leader_addr"`
	Message    string `json:"message" yaml:"message"`
}

// LeaveResponse contains the result of leaving a cluster.
type LeaveResponse struct {
	Message string `json:"message" yaml:"message"`
}
