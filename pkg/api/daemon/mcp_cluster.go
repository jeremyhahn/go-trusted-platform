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

package daemon

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// MCP Cluster bridge
// =============================================================================
//
// The platform_cluster_* MCP tools call the gRPC ClusterService servicer the
// daemon registers, which serves every transport from the daemon's
// ClusterServicer: an MCP platform_cluster_status runs the exact code path of
// a gRPC GetStatus.
//
// That servicer answers Unavailable today: no ClusterServicer is wired in ANY
// build. A build-tagged implementation exists (`-tags cluster`) but nothing
// constructs it or injects it via Daemon.SetClusterService, so the tag does
// not change what any transport answers. See #334.

// ErrClusterNotConfigured indicates that no cluster service is wired into a
// daemon surface. Callers should treat this the same way the gRPC
// ClusterService treats a missing servicer.
type ErrClusterNotConfigured struct{}

// Error returns a human-readable description of the error.
func (ErrClusterNotConfigured) Error() string {
	return "cluster service not configured"
}

// GRPCStatus classifies the error as Unavailable, the class the gRPC
// ClusterService answers with while no servicer is set.
func (e ErrClusterNotConfigured) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// =============================================================================
// Service interface
// =============================================================================

// ClusterStatusInfo is the protocol-agnostic snapshot of cluster state the
// ClusterServicer reports. It mirrors the *cluster.ClusterStatus shape used
// by the build-tagged ClusterService while keeping this file free of any
// dependency on pkg/cluster (which is only compiled with -tags cluster).
type ClusterStatusInfo struct {
	State        string    `json:"state"`
	NodeCount    int       `json:"node_count"`
	HealthyCount int       `json:"healthy_count"`
	LeaderID     uint64    `json:"leader_id"`
	Term         uint64    `json:"term"`
	HasQuorum    bool      `json:"has_quorum"`
	LastUpdated  time.Time `json:"last_updated"`
	StartedAt    time.Time `json:"started_at"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// ClusterNodeInfo is the protocol-agnostic projection of a cluster member
// surfaced by ListNodes. Mirrors *cluster.Node minus build-tagged types.
type ClusterNodeInfo struct {
	ID          uint64            `json:"id"`
	Address     string            `json:"address"`
	RaftAddress string            `json:"raft_address,omitempty"`
	IsLeader    bool              `json:"is_leader"`
	State       string            `json:"state"`
	LastSeen    time.Time         `json:"last_seen"`
	JoinTime    time.Time         `json:"join_time"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ClusterNodesInfo bundles a slice of cluster members with the current
// leader (if known) and Raft term.
type ClusterNodesInfo struct {
	Nodes  []ClusterNodeInfo `json:"nodes"`
	Leader *ClusterNodeInfo  `json:"leader,omitempty"`
	Term   uint64            `json:"term"`
}

// ClusterServicer defines the cluster service operations the gRPC
// ClusterService delegates to. The interface is tag-agnostic so the daemon
// can hold a ClusterServicer without pulling in pkg/cluster when building
// without -tags cluster. The build-tagged adapter wires
// *cluster.ClusterService to satisfy this interface.
type ClusterServicer interface {
	// Bootstrap initializes a new cluster with this node as the first
	// member. Should only be called once on the first node in a new
	// cluster.
	Bootstrap(ctx context.Context) error

	// Join adds this node to an existing cluster by dialing one or more
	// seed addresses.
	Join(ctx context.Context, addresses []string) error

	// Leave gracefully removes this node from the cluster, transferring
	// leadership if necessary.
	Leave(ctx context.Context) error

	// Status returns the current cluster status (state, leader, term,
	// quorum).
	Status(ctx context.Context) (*ClusterStatusInfo, error)

	// Nodes returns all nodes in the cluster with their current state.
	Nodes(ctx context.Context) (*ClusterNodesInfo, error)

	// IsLeader returns true if this node is the current cluster leader.
	IsLeader() bool

	// NodeID returns this node's identifier in the cluster.
	NodeID() uint64
}

// SetClusterServer wires the ClusterService servicer the platform_cluster_*
// MCP tools call. The daemon passes the same servicer it registers on gRPC,
// so each tool answers and refuses exactly as its gRPC method does.
func (p *MCPServiceProvider) SetClusterServer(server platformv1.ClusterServiceServer) {
	p.clusterServer = server
}

// ClusterServiceServer implements mcp.ClusterProvider. It returns nil while
// no cluster service is wired, and the cluster tools then refuse with
// ErrClusterNotConfigured.
func (p *MCPServiceProvider) ClusterServiceServer() platformv1.ClusterServiceServer {
	return p.clusterServer
}
