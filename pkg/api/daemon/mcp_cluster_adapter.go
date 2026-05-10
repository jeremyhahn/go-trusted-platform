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

//go:build cluster

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cluster"
)

// =============================================================================
// Cluster service adapter (build-tagged)
// =============================================================================
//
// clusterServiceAdapter bridges the build-tagged *ClusterService (which
// owns a real cluster.Coordinator) to the tag-agnostic ClusterServicer
// interface consumed by the MCP cluster tools. This preserves the
// MCP/gRPC parity contract: both surfaces delegate to the same
// underlying coordinator.
//
// The adapter is only compiled when the daemon is built with
// `-tags cluster`. Without the tag, the daemon's clusterService field
// stays nil and MCP cluster tools surface ErrClusterNotConfigured.

// clusterCore is the minimal subset of *ClusterService the adapter
// depends on. Defining it as an interface (rather than wrapping the
// concrete *ClusterService directly) keeps the adapter unit-testable
// without standing up a real Raft coordinator. *ClusterService
// satisfies clusterCore implicitly via its method set.
type clusterCore interface {
	Bootstrap(ctx context.Context) error
	Join(ctx context.Context, addresses []string) error
	Leave(ctx context.Context) error
	Status(ctx context.Context) (*cluster.ClusterStatus, error)
	Nodes(ctx context.Context) (cluster.NodeList, error)
	IsLeader() bool
	NodeID() uint64
}

// clusterServiceAdapter wraps a clusterCore (typically *ClusterService)
// to satisfy the tag-agnostic ClusterServicer interface.
type clusterServiceAdapter struct {
	svc clusterCore
}

// NewClusterServiceAdapter wraps a *ClusterService so it can be passed
// into MCPServiceProvider via SetClusterService. Returns nil if svc is
// nil so callers can pass through optional services without checks.
func NewClusterServiceAdapter(svc *ClusterService) ClusterServicer {
	if svc == nil {
		return nil
	}
	return newClusterServiceAdapter(svc)
}

// newClusterServiceAdapter is the internal constructor used by tests to
// inject a fake clusterCore. The public NewClusterServiceAdapter is a
// thin wrapper that pins the input type to *ClusterService.
func newClusterServiceAdapter(svc clusterCore) ClusterServicer {
	if svc == nil {
		return nil
	}
	return &clusterServiceAdapter{svc: svc}
}

// Bootstrap delegates to the wrapped clusterCore.
func (a *clusterServiceAdapter) Bootstrap(ctx context.Context) error {
	return a.svc.Bootstrap(ctx)
}

// Join delegates to the wrapped clusterCore.
func (a *clusterServiceAdapter) Join(ctx context.Context, addresses []string) error {
	return a.svc.Join(ctx, addresses)
}

// Leave delegates to the wrapped clusterCore.
func (a *clusterServiceAdapter) Leave(ctx context.Context) error {
	return a.svc.Leave(ctx)
}

// Status delegates to the wrapped clusterCore and projects the
// cluster.ClusterStatus into the tag-agnostic ClusterStatusInfo.
func (a *clusterServiceAdapter) Status(ctx context.Context) (*ClusterStatusInfo, error) {
	st, err := a.svc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return clusterStatusInfoFromDomain(st), nil
}

// Nodes delegates to the wrapped clusterCore and projects the
// cluster.NodeList into a tag-agnostic ClusterNodesInfo.
func (a *clusterServiceAdapter) Nodes(ctx context.Context) (*ClusterNodesInfo, error) {
	list, err := a.svc.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	return clusterNodesInfoFromDomain(list), nil
}

// IsLeader delegates to the wrapped clusterCore.
func (a *clusterServiceAdapter) IsLeader() bool {
	return a.svc.IsLeader()
}

// NodeID delegates to the wrapped clusterCore.
func (a *clusterServiceAdapter) NodeID() uint64 {
	return a.svc.NodeID()
}

// =============================================================================
// Domain projections
// =============================================================================

// clusterStatusInfoFromDomain projects a *cluster.ClusterStatus into a
// ClusterStatusInfo. Returns nil when the input is nil so the MCP layer
// can fall through to its empty-status branch.
func clusterStatusInfoFromDomain(st *cluster.ClusterStatus) *ClusterStatusInfo {
	if st == nil {
		return nil
	}
	return &ClusterStatusInfo{
		State:        string(st.State),
		NodeCount:    st.NodeCount,
		HealthyCount: st.HealthyCount,
		LeaderID:     st.LeaderID,
		Term:         st.Term,
		HasQuorum:    st.HasQuorum,
		LastUpdated:  st.LastUpdated,
		StartedAt:    st.StartedAt,
		ErrorMessage: st.ErrorMessage,
	}
}

// clusterNodesInfoFromDomain projects a cluster.NodeList into a
// ClusterNodesInfo, copying nodes into the tag-agnostic shape.
func clusterNodesInfoFromDomain(list cluster.NodeList) *ClusterNodesInfo {
	out := &ClusterNodesInfo{
		Term:  list.Term,
		Nodes: make([]ClusterNodeInfo, 0, len(list.Nodes)),
	}
	for _, n := range list.Nodes {
		if n == nil {
			continue
		}
		out.Nodes = append(out.Nodes, clusterNodeInfoFromDomain(n))
	}
	if list.Leader != nil {
		leader := clusterNodeInfoFromDomain(list.Leader)
		out.Leader = &leader
	}
	return out
}

// clusterNodeInfoFromDomain projects a *cluster.Node into a
// ClusterNodeInfo.
func clusterNodeInfoFromDomain(n *cluster.Node) ClusterNodeInfo {
	return ClusterNodeInfo{
		ID:          n.ID,
		Address:     n.Address,
		RaftAddress: n.RaftAddress,
		IsLeader:    n.IsLeader,
		State:       n.State.String(),
		LastSeen:    n.LastSeen,
		JoinTime:    n.JoinTime,
		Metadata:    n.Metadata,
	}
}
