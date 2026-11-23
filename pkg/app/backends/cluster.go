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

package backends

import (
	"context"
	"sort"
	"time"

	quicbaasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// clusterLeaderShardID is the shard whose leader the platform reports as the
// cluster leader.
const clusterLeaderShardID uint64 = 1

// ClusterSurface is the part of the embedded go-quicbaas service the cluster
// backend reads. The embedded service facade (quicbaasservice.QuicBaaS, from
// (*app.App).QuicBaaSService) satisfies it.
type ClusterSurface interface {
	ClusterStatus(ctx context.Context, req *quicbaasservice.ClusterStatusRequest) (*quicbaasservice.ClusterStatusResponse, error)
	GetLeader(ctx context.Context, req *quicbaasservice.GetLeaderRequest) (*quicbaasservice.GetLeaderResponse, error)
}

var _ ClusterSurface = (quicbaasservice.QuicBaaS)(nil)

// clusterBackend is the daemon.ClusterServicer over the Raft cluster the
// embedded go-quicbaas server already runs in-process. That server's
// ClusterStatus reports Raft membership, not liveness, so node health is
// reported as unknown until the SDK exposes liveness.
type clusterBackend struct {
	svc         ClusterSurface
	nodeID      uint64
	raftAddress string
}

// NewClusterBackend returns the cluster servicer over svc for the node
// nodeID. A nil svc yields a nil servicer, which the daemon treats as "not
// configured".
func NewClusterBackend(svc ClusterSurface, nodeID uint64, raftAddress string) daemon.ClusterServicer {
	if svc == nil {
		return nil
	}
	return &clusterBackend{svc: svc, nodeID: nodeID, raftAddress: raftAddress}
}

// PlatformClusterBackend returns the cluster servicer of a running platform
// over its embedded go-quicbaas service, or nil when the platform runs no
// embedded service.
func PlatformClusterBackend(a *app.App) daemon.ClusterServicer {
	if a == nil {
		return nil
	}
	svc := a.QuicBaaSService()
	if svc == nil {
		return nil
	}
	var nodeID uint64
	var raftAddress string
	if cfg := a.QuicBaaSConfig; cfg != nil {
		nodeID, raftAddress = cfg.NodeID, cfg.RaftAddress
	}
	return NewClusterBackend(svc, nodeID, raftAddress)
}

// clusterStatus reads the embedded cluster status, mapping an SDK error to
// ErrClusterOperationFailed for op.
func (b *clusterBackend) clusterStatus(ctx context.Context, op string) (*quicbaasservice.ClusterStatusResponse, error) {
	resp, err := b.svc.ClusterStatus(ctx, &quicbaasservice.ClusterStatusRequest{IncludeDetails: true})
	if err != nil {
		return nil, grpcapi.ErrClusterOperationFailed{Operation: op, Reason: err.Error()}
	}
	if resp == nil {
		resp = &quicbaasservice.ClusterStatusResponse{}
	}
	return resp, nil
}

// clusterLeaderID is the leader of shard 1, or of the first shard when there
// is no shard 1; zero when there is no leader.
func clusterLeaderID(resp *quicbaasservice.ClusterStatusResponse) uint64 {
	var first *quicbaasservice.ShardInfo
	for _, shard := range resp.Shards {
		if shard == nil {
			continue
		}
		if shard.ShardID == clusterLeaderShardID {
			return shard.LeaderID
		}
		if first == nil {
			first = shard
		}
	}
	if first != nil {
		return first.LeaderID
	}
	return 0
}

// Status reports the cluster state the embedded server sees. The embedded
// go-quicbaas ClusterStatus reports Raft membership, not liveness: it marks
// every configured member Healthy, a stopped follower included. So no member
// is counted healthy (HealthyCount stays 0) and a cluster with a known leader
// reads "unknown" until the SDK exposes liveness; "degraded" means no leader,
// "uninitialized" no members.
func (b *clusterBackend) Status(ctx context.Context) (*daemon.ClusterStatusInfo, error) {
	resp, err := b.clusterStatus(ctx, "status")
	if err != nil {
		return nil, err
	}
	leaderID := clusterLeaderID(resp)
	info := &daemon.ClusterStatusInfo{
		LeaderID:    leaderID,
		HasQuorum:   leaderID != 0,
		LastUpdated: time.Unix(0, resp.Timestamp),
	}
	for _, n := range resp.Nodes {
		if n != nil {
			info.NodeCount++
		}
	}
	switch {
	case info.NodeCount == 0:
		info.State = "uninitialized"
	case leaderID == 0:
		info.State = "degraded"
	default:
		info.State = "unknown"
	}
	return info, nil
}

// Nodes lists the cluster members sorted by ID, with the leader marked.
// Every node State is "unknown": the embedded go-quicbaas ClusterStatus
// reports Raft membership, not liveness, so its HealthStatus is not a
// measured verdict until the SDK exposes liveness.
func (b *clusterBackend) Nodes(ctx context.Context) (*daemon.ClusterNodesInfo, error) {
	resp, err := b.clusterStatus(ctx, "nodes")
	if err != nil {
		return nil, err
	}
	leaderID := clusterLeaderID(resp)
	nodes := make([]daemon.ClusterNodeInfo, 0, len(resp.Nodes))
	for _, n := range resp.Nodes {
		if n == nil {
			continue
		}
		nodes = append(nodes, daemon.ClusterNodeInfo{
			ID:          n.NodeID,
			Address:     n.Address,
			RaftAddress: n.Address,
			IsLeader:    leaderID != 0 && n.NodeID == leaderID,
			State:       "unknown",
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	out := &daemon.ClusterNodesInfo{Nodes: nodes}
	for i := range nodes {
		if nodes[i].IsLeader {
			leader := nodes[i]
			out.Leader = &leader
			break
		}
	}
	return out, nil
}

// IsLeader reports whether this node leads shard 1. Leadership comes from
// the same ClusterStatus topology Status and Nodes use: this node leads only
// when it is a listed member and the shard 1 leader. A standalone service
// (no members, whose GetLeader answers a synthetic leader 1) is never leader.
func (b *clusterBackend) IsLeader() bool {
	if b.nodeID == 0 {
		return false
	}
	resp, err := b.clusterStatus(context.Background(), "leader")
	if err != nil {
		return false
	}
	leader := clusterLeaderID(resp)
	if leader == 0 || leader != b.nodeID {
		return false
	}
	for _, n := range resp.Nodes {
		if n != nil && n.NodeID == b.nodeID {
			return true
		}
	}
	return false
}

// NodeID returns this node's configured Raft node ID.
func (b *clusterBackend) NodeID() uint64 {
	return b.nodeID
}

// Bootstrap reports whether the cluster is already formed. Raft forms when
// the embedded go-quicbaas server starts in cluster mode from the quicbaas
// config; bootstrapping a node that started standalone at runtime needs a
// go-quicbaas call this SDK version does not have. A cluster with a leader
// answers ErrClusterAlreadyInitialized, one without ErrClusterNotInitialized.
func (b *clusterBackend) Bootstrap(ctx context.Context) error {
	resp, err := b.clusterStatus(ctx, "bootstrap")
	if err != nil {
		return err
	}
	if clusterLeaderID(resp) != 0 {
		return grpcapi.ErrClusterAlreadyInitialized{}
	}
	return grpcapi.ErrClusterNotInitialized{}
}

// Join answers Unavailable: runtime membership (AddNode on the leader) is the
// next slice of the cluster row.
func (b *clusterBackend) Join(context.Context, []string) error {
	return grpcapi.ErrClusterServiceUnavailable{}
}

// Leave answers Unavailable: runtime membership (RemoveNode) is the next
// slice of the cluster row.
func (b *clusterBackend) Leave(context.Context) error {
	return grpcapi.ErrClusterServiceUnavailable{}
}
