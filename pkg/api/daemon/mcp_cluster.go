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

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
)

// =============================================================================
// MCP Cluster bridge
// =============================================================================
//
// MCPServiceProvider implements mcp.ClusterProvider by delegating to the same
// ClusterServicer that powers the gRPC ClusterService. This keeps the MCP
// and gRPC surfaces in lockstep: AI/LLM clients calling
// platform_cluster_status hit the exact same code path as a gRPC GetStatus
// RPC.
//
// That parity is currently a contract, not a behaviour: no ClusterServicer
// is wired in ANY build, so every MCP cluster tool returns
// ErrClusterNotConfigured and the gRPC surface returns codes.Unimplemented.
// A build-tagged implementation exists (`-tags cluster`) but nothing
// constructs it or injects it via Daemon.SetClusterService, so the tag does
// not change what either surface answers. See #334.

// ErrClusterNotConfigured indicates that no cluster servicer is wired into
// the MCPServiceProvider. Callers should treat this the same way the gRPC
// ClusterService treats a missing coordinator (FailedPrecondition /
// Unimplemented).
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

// ErrClusterPeerAddressRequired indicates that a join operation was issued
// without any seed peer addresses to dial.
type ErrClusterPeerAddressRequired struct{}

// Error returns a human-readable description of the error.
func (ErrClusterPeerAddressRequired) Error() string {
	return "cluster: at least one seed_address is required to join"
}

// GRPCStatus classifies the error as InvalidArgument, as gRPC Join does.
func (e ErrClusterPeerAddressRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrClusterServicerFailed is a cluster servicer failure answered over MCP.
// It keeps the servicer's error and carries the class the gRPC
// ClusterService answers the same failure with.
type ErrClusterServicerFailed struct {
	Cause error
}

func (e ErrClusterServicerFailed) Error() string {
	return e.Cause.Error()
}

func (e ErrClusterServicerFailed) Unwrap() error {
	return e.Cause
}

// GRPCStatus classifies the failure as grpcapi.ClusterErrorStatus does.
func (e ErrClusterServicerFailed) GRPCStatus() *status.Status {
	return status.Convert(grpcapi.ClusterErrorStatus(e.Cause))
}

// =============================================================================
// Service interface
// =============================================================================

// ClusterStatusInfo is the protocol-agnostic snapshot of cluster state the
// MCP bridge surfaces. It mirrors the *cluster.ClusterStatus shape used by
// the build-tagged ClusterService while keeping mcp_cluster.go free of any
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

// ClusterServicer defines the cluster service operations the MCP bridge
// (and gRPC service) delegate to. The interface is tag-agnostic so the
// daemon can hold a *ClusterServicer field without pulling in pkg/cluster
// when building without -tags cluster. The build-tagged adapter wires
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

// SetClusterService injects the cluster service after construction. The
// daemon wires the same ClusterServicer that powers the gRPC
// ClusterServiceServer so the MCP and gRPC surfaces stay in lockstep.
func (p *MCPServiceProvider) SetClusterService(svc ClusterServicer) {
	p.clusterService = svc
}

// =============================================================================
// Lifecycle operations
// =============================================================================

// ClusterBootstrap initializes a new cluster with this node as the leader.
func (p *MCPServiceProvider) ClusterBootstrap(ctx context.Context, clusterName string) (interface{}, error) {
	if p.clusterService == nil {
		return nil, ErrClusterNotConfigured{}
	}
	if err := p.clusterService.Bootstrap(ctx); err != nil {
		return nil, ErrClusterServicerFailed{Cause: err}
	}
	st, err := p.clusterService.Status(ctx)
	if err != nil {
		return nil, ErrClusterServicerFailed{Cause: err}
	}
	return clusterBootstrapResultJSON(clusterName, p.clusterService.NodeID(), st), nil
}

// ClusterJoin adds this node to an existing cluster.
func (p *MCPServiceProvider) ClusterJoin(ctx context.Context, seedAddresses []string) (interface{}, error) {
	if p.clusterService == nil {
		return nil, ErrClusterNotConfigured{}
	}
	if len(seedAddresses) == 0 {
		return nil, ErrClusterPeerAddressRequired{}
	}
	if err := p.clusterService.Join(ctx, seedAddresses); err != nil {
		return nil, ErrClusterServicerFailed{Cause: err}
	}
	st, err := p.clusterService.Status(ctx)
	if err != nil {
		return nil, ErrClusterServicerFailed{Cause: err}
	}
	return clusterJoinResultJSON(p.clusterService.NodeID(), seedAddresses, st), nil
}

// ClusterLeave gracefully removes this node from the cluster.
func (p *MCPServiceProvider) ClusterLeave(ctx context.Context) (interface{}, error) {
	if p.clusterService == nil {
		return nil, ErrClusterNotConfigured{}
	}
	nodeID := p.clusterService.NodeID()
	if err := p.clusterService.Leave(ctx); err != nil {
		return nil, ErrClusterServicerFailed{Cause: err}
	}
	return map[string]interface{}{
		"node_id": nodeID,
		"left":    true,
	}, nil
}

// =============================================================================
// Status / inspection
// =============================================================================

// ClusterStatus returns the current cluster status. When includeNodes is
// true the response also enumerates all known nodes.
func (p *MCPServiceProvider) ClusterStatus(ctx context.Context, includeNodes bool) (interface{}, error) {
	if p.clusterService == nil {
		return nil, ErrClusterNotConfigured{}
	}
	st, err := p.clusterService.Status(ctx)
	if err != nil {
		return nil, ErrClusterServicerFailed{Cause: err}
	}

	out := map[string]interface{}{
		"cluster":   clusterStatusJSON(st),
		"node_id":   p.clusterService.NodeID(),
		"is_leader": p.clusterService.IsLeader(),
		"timestamp": time.Now().UTC(),
	}

	if includeNodes {
		nodes, nodesErr := p.clusterService.Nodes(ctx)
		if nodesErr != nil {
			return nil, ErrClusterServicerFailed{Cause: nodesErr}
		}
		out["nodes"] = clusterNodesJSON(nodes)
		if nodes != nil && nodes.Leader != nil {
			out["leader"] = clusterNodeJSON(*nodes.Leader)
		}
	}
	return out, nil
}

// ClusterListNodes returns all nodes in the cluster.
func (p *MCPServiceProvider) ClusterListNodes(ctx context.Context) (interface{}, error) {
	if p.clusterService == nil {
		return nil, ErrClusterNotConfigured{}
	}
	nodes, err := p.clusterService.Nodes(ctx)
	if err != nil {
		return nil, ErrClusterServicerFailed{Cause: err}
	}
	out := map[string]interface{}{
		"nodes": clusterNodesJSON(nodes),
		"total": clusterNodeCount(nodes),
	}
	if nodes != nil {
		out["term"] = nodes.Term
		if nodes.Leader != nil {
			out["leader"] = clusterNodeJSON(*nodes.Leader)
		}
	}
	return out, nil
}

// =============================================================================
// JSON projections
// =============================================================================

// clusterStatusJSON projects ClusterStatusInfo into a JSON-friendly map.
// Mirrors the proto ClusterInfo shape so MCP clients see fields the gRPC
// clients already know.
func clusterStatusJSON(st *ClusterStatusInfo) map[string]interface{} {
	if st == nil {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{
		"state":         st.State,
		"node_count":    st.NodeCount,
		"healthy_count": st.HealthyCount,
		"leader_id":     st.LeaderID,
		"term":          st.Term,
		"has_quorum":    st.HasQuorum,
		"last_updated":  st.LastUpdated,
		"started_at":    st.StartedAt,
	}
	if st.ErrorMessage != "" {
		out["error_message"] = st.ErrorMessage
	}
	return out
}

// clusterNodeJSON projects a ClusterNodeInfo into a JSON-friendly map.
func clusterNodeJSON(node ClusterNodeInfo) map[string]interface{} {
	out := map[string]interface{}{
		"id":        node.ID,
		"address":   node.Address,
		"is_leader": node.IsLeader,
		"state":     node.State,
		"last_seen": node.LastSeen,
		"join_time": node.JoinTime,
	}
	if node.RaftAddress != "" {
		out["raft_address"] = node.RaftAddress
	}
	if len(node.Metadata) > 0 {
		out["metadata"] = node.Metadata
	}
	return out
}

// clusterNodesJSON projects a slice of nodes into JSON-friendly maps.
func clusterNodesJSON(nodes *ClusterNodesInfo) []map[string]interface{} {
	if nodes == nil {
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, len(nodes.Nodes))
	for i, n := range nodes.Nodes {
		out[i] = clusterNodeJSON(n)
	}
	return out
}

// clusterNodeCount returns the number of nodes in a (possibly nil) list.
func clusterNodeCount(nodes *ClusterNodesInfo) int {
	if nodes == nil {
		return 0
	}
	return len(nodes.Nodes)
}

// clusterBootstrapResultJSON formats a Bootstrap result combining the
// supplied cluster name with the post-bootstrap status snapshot.
func clusterBootstrapResultJSON(clusterName string, nodeID uint64, st *ClusterStatusInfo) map[string]interface{} {
	out := map[string]interface{}{
		"node_id":   nodeID,
		"cluster":   clusterStatusJSON(st),
		"bootstrap": true,
	}
	if clusterName != "" {
		out["cluster_name"] = clusterName
	}
	return out
}

// clusterJoinResultJSON formats a Join result combining the supplied seed
// addresses with the post-join status snapshot.
func clusterJoinResultJSON(nodeID uint64, addresses []string, st *ClusterStatusInfo) map[string]interface{} {
	return map[string]interface{}{
		"node_id":        nodeID,
		"seed_addresses": addresses,
		"cluster":        clusterStatusJSON(st),
		"joined":         true,
	}
}
