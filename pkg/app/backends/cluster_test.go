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
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	quicbaasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// fakeClusterSurface is a ClusterSurface returning canned answers and
// counting the calls made to it.
type fakeClusterSurface struct {
	status     *quicbaasservice.ClusterStatusResponse
	statusErr  error
	leader     *quicbaasservice.GetLeaderResponse
	leaderErr  error
	removeErr  error
	removeResp *quicbaasservice.RemoveNodeResponse

	statusCalls int
	leaderCalls int
	leaderReq   *quicbaasservice.GetLeaderRequest
	removeReqs  []quicbaasservice.RemoveNodeRequest
}

func (f *fakeClusterSurface) ClusterStatus(_ context.Context, _ *quicbaasservice.ClusterStatusRequest) (*quicbaasservice.ClusterStatusResponse, error) {
	f.statusCalls++
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if f.status == nil {
		return &quicbaasservice.ClusterStatusResponse{}, nil
	}
	return f.status, nil
}

func (f *fakeClusterSurface) GetLeader(_ context.Context, req *quicbaasservice.GetLeaderRequest) (*quicbaasservice.GetLeaderResponse, error) {
	f.leaderCalls++
	f.leaderReq = req
	if f.leaderErr != nil {
		return nil, f.leaderErr
	}
	if f.leader == nil {
		return &quicbaasservice.GetLeaderResponse{}, nil
	}
	return f.leader, nil
}

func (f *fakeClusterSurface) RemoveNode(_ context.Context, req *quicbaasservice.RemoveNodeRequest) (*quicbaasservice.RemoveNodeResponse, error) {
	f.removeReqs = append(f.removeReqs, *req)
	if f.removeErr != nil {
		return nil, f.removeErr
	}
	if f.removeResp != nil {
		return f.removeResp, nil
	}
	return &quicbaasservice.RemoveNodeResponse{Success: true}, nil
}

const clusterTestTimestamp int64 = 1_700_000_000_123_456_789

// threeNodeStatus is three nodes (IDs 3, 1, 2), node 2 unhealthy, shard 1
// led by node 1.
func threeNodeStatus() *quicbaasservice.ClusterStatusResponse {
	return &quicbaasservice.ClusterStatusResponse{
		Nodes: []*quicbaasservice.NodeInfo{
			{NodeID: 3, Address: "10.0.0.3:7000", HealthStatus: quicbaasservice.HealthStatusHealthy},
			{NodeID: 1, Address: "10.0.0.1:7000", IsLeader: true, HealthStatus: quicbaasservice.HealthStatusHealthy},
			{NodeID: 2, Address: "10.0.0.2:7000", HealthStatus: quicbaasservice.HealthStatusUnhealthy},
		},
		Shards:    []*quicbaasservice.ShardInfo{{ShardID: 1, LeaderID: 1, Replicas: []uint64{1, 2, 3}}},
		Timestamp: clusterTestTimestamp,
	}
}

// twoShardStatus is a three-node cluster running two shards: shard 3 is
// replicated on nodes 2 and 3 and led by node 3, shard 1 is replicated on
// every node and led by node 1. The shards are listed out of order so a test
// can tell Leave sorts them.
func twoShardStatus() *quicbaasservice.ClusterStatusResponse {
	return &quicbaasservice.ClusterStatusResponse{
		Nodes: []*quicbaasservice.NodeInfo{
			{NodeID: 1, Address: "192.0.2.1:7000"},
			{NodeID: 2, Address: "192.0.2.2:7000"},
			{NodeID: 3, Address: "192.0.2.3:7000"},
		},
		Shards: []*quicbaasservice.ShardInfo{
			{ShardID: 3, LeaderID: 3, Replicas: []uint64{2, 3}},
			{ShardID: 1, LeaderID: 1, Replicas: []uint64{1, 2, 3}},
		},
		Timestamp: clusterTestTimestamp,
	}
}

func TestClusterBackend_Status(t *testing.T) {
	ctx := context.Background()

	// allHealthy is what the pinned go-quicbaas ClusterStatus always
	// returns: every Raft member marked Healthy, whether it is up or not.
	allHealthy := func() *quicbaasservice.ClusterStatusResponse {
		resp := threeNodeStatus()
		for _, n := range resp.Nodes {
			n.HealthStatus = quicbaasservice.HealthStatusHealthy
		}
		return resp
	}

	t.Run("membership is not health", func(t *testing.T) {
		st, err := NewClusterBackend(&fakeClusterSurface{status: allHealthy()}, 1, "").Status(ctx)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.State != "unknown" || st.NodeCount != 3 || st.HealthyCount != 0 || st.LeaderID != 1 || !st.HasQuorum {
			t.Errorf("status = %+v, want unknown, 3 nodes, 0 healthy, leader 1, quorum", st)
		}
		if want := time.Unix(0, clusterTestTimestamp); !st.LastUpdated.Equal(want) {
			t.Errorf("LastUpdated = %v, want %v", st.LastUpdated, want)
		}
	})

	t.Run("no leader", func(t *testing.T) {
		resp := allHealthy()
		resp.Shards[0].LeaderID = 0
		st, err := NewClusterBackend(&fakeClusterSurface{status: resp}, 1, "").Status(ctx)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.State != "degraded" || st.HealthyCount != 0 || st.HasQuorum {
			t.Errorf("status = %+v, want degraded, 0 healthy, no quorum", st)
		}
	})

	t.Run("uninitialized", func(t *testing.T) {
		st, err := NewClusterBackend(&fakeClusterSurface{}, 1, "").Status(ctx)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.State != "uninitialized" || st.HasQuorum {
			t.Errorf("status = %+v, want uninitialized without quorum", st)
		}
	})
}

func TestClusterBackend_Nodes(t *testing.T) {
	b := NewClusterBackend(&fakeClusterSurface{status: threeNodeStatus()}, 1, "")
	nodes, err := b.Nodes(context.Background())
	if err != nil {
		t.Fatalf("Nodes: %v", err)
	}
	if len(nodes.Nodes) != 3 {
		t.Fatalf("got %d nodes, want 3", len(nodes.Nodes))
	}
	// Node 2 is Unhealthy in the fixture: a reported HealthStatus is Raft
	// membership, not a measured verdict, so every node reads unknown.
	wantStates := map[uint64]string{1: "unknown", 2: "unknown", 3: "unknown"}
	for i, n := range nodes.Nodes {
		if n.ID != uint64(i+1) {
			t.Errorf("node[%d].ID = %d, want %d (sorted by ID)", i, n.ID, i+1)
		}
		if n.IsLeader != (n.ID == 1) {
			t.Errorf("node %d IsLeader = %v", n.ID, n.IsLeader)
		}
		if n.State != wantStates[n.ID] {
			t.Errorf("node %d State = %q, want %q", n.ID, n.State, wantStates[n.ID])
		}
		if n.Address == "" || n.RaftAddress != n.Address {
			t.Errorf("node %d Address %q RaftAddress %q, want both the NodeInfo address", n.ID, n.Address, n.RaftAddress)
		}
	}
	if nodes.Leader == nil || nodes.Leader.ID != 1 {
		t.Errorf("Leader = %+v, want node 1", nodes.Leader)
	}
}

// TestClusterBackend_TopologyIsNotHealth pins that a ClusterStatus marking
// every member Healthy (as the pinned go-quicbaas one always does, even for a
// stopped follower) never reaches the daemon as a healthy node or a running
// cluster.
func TestClusterBackend_TopologyIsNotHealth(t *testing.T) {
	ctx := context.Background()
	resp := threeNodeStatus()
	for _, n := range resp.Nodes {
		n.HealthStatus = quicbaasservice.HealthStatusHealthy
	}
	b := NewClusterBackend(&fakeClusterSurface{status: resp}, 1, "")
	st, err := b.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State == "running" {
		t.Errorf("Status State = %q from topology alone, want not running", st.State)
	}
	nodes, err := b.Nodes(ctx)
	if err != nil {
		t.Fatalf("Nodes: %v", err)
	}
	for _, n := range nodes.Nodes {
		if n.State == "healthy" {
			t.Errorf("node %d State = %q from topology alone, want not healthy", n.ID, n.State)
		}
	}
}

func TestClusterBackend_LeaderAndNodeID(t *testing.T) {
	leaderOne := &fakeClusterSurface{status: threeNodeStatus()}
	b := NewClusterBackend(leaderOne, 1, "")
	if !b.IsLeader() {
		t.Error("IsLeader = false for listed node 1 leading shard 1")
	}
	if leaderOne.leaderCalls != 0 {
		t.Errorf("GetLeader calls = %d, want 0 (leadership comes from ClusterStatus)", leaderOne.leaderCalls)
	}
	if b.NodeID() != 1 {
		t.Errorf("NodeID = %d, want 1", b.NodeID())
	}

	if NewClusterBackend(&fakeClusterSurface{status: threeNodeStatus()}, 2, "").IsLeader() {
		t.Error("IsLeader = true for node 2 when shard 1 leader is 1")
	}
	if NewClusterBackend(&fakeClusterSurface{statusErr: errors.New("no status")}, 1, "").IsLeader() {
		t.Error("IsLeader = true on a ClusterStatus error")
	}
	if NewClusterBackend(&fakeClusterSurface{status: threeNodeStatus()}, 0, "").IsLeader() {
		t.Error("IsLeader = true with node ID 0")
	}
}

// TestClusterBackend_StandaloneIsNotLeader pins the standalone service's
// answer pair: the go-qrdb LocalBackend reports an empty topology through
// ClusterStatus but always answers leader 1 from GetLeader. This node must
// not report itself leader when no Raft cluster exists.
func TestClusterBackend_StandaloneIsNotLeader(t *testing.T) {
	standalone := &fakeClusterSurface{leader: &quicbaasservice.GetLeaderResponse{ShardID: 1, LeaderID: 1}}
	b := NewClusterBackend(standalone, 1, "")
	if b.IsLeader() {
		t.Error("IsLeader = true for a standalone service with no members")
	}
	st, err := b.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != "uninitialized" {
		t.Errorf("Status State = %q, want uninitialized", st.State)
	}
	nodes, err := b.Nodes(context.Background())
	if err != nil {
		t.Fatalf("Nodes: %v", err)
	}
	if len(nodes.Nodes) != 0 {
		t.Errorf("Nodes = %+v, want none for a standalone service", nodes.Nodes)
	}
	if nodes.Leader != nil {
		t.Errorf("Leader = %+v, want nil for a standalone service", nodes.Leader)
	}

	t.Run("leader not a listed member", func(t *testing.T) {
		resp := threeNodeStatus()
		resp.Shards[0].LeaderID = 7
		if NewClusterBackend(&fakeClusterSurface{status: resp}, 7, "").IsLeader() {
			t.Error("IsLeader = true for node 7 that leads shard 1 but is not in Nodes")
		}
	})
}

func TestClusterBackend_Bootstrap(t *testing.T) {
	ctx := context.Background()

	err := NewClusterBackend(&fakeClusterSurface{status: threeNodeStatus()}, 1, "").Bootstrap(ctx)
	var already grpcapi.ErrClusterAlreadyInitialized
	if !errors.As(err, &already) {
		t.Errorf("Bootstrap with a leader = %v, want ErrClusterAlreadyInitialized", err)
	}

	err = NewClusterBackend(&fakeClusterSurface{}, 1, "").Bootstrap(ctx)
	var notInit grpcapi.ErrClusterNotInitialized
	if !errors.As(err, &notInit) {
		t.Errorf("Bootstrap without a leader = %v, want ErrClusterNotInitialized", err)
	}
}

func TestClusterBackend_JoinNotWired(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClusterSurface{status: twoShardStatus()}
	b := NewClusterBackend(fake, 1, "")

	var unavailable grpcapi.ErrClusterServiceUnavailable
	if err := b.Join(ctx, []string{"192.0.2.9:7000"}); !errors.As(err, &unavailable) {
		t.Errorf("Join = %v, want ErrClusterServiceUnavailable", err)
	}
	if fake.statusCalls != 0 || fake.leaderCalls != 0 || len(fake.removeReqs) != 0 {
		t.Errorf("Join made SDK calls: status %d, leader %d, remove %d", fake.statusCalls, fake.leaderCalls, len(fake.removeReqs))
	}
}

func TestClusterBackend_LeaveIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   uint64
	}{
		{"leader of shard 1", 1},
		{"follower", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeClusterSurface{status: twoShardStatus()}
			b := NewClusterBackend(fake, tc.id, "")

			err := b.Leave(context.Background())
			var unavailable grpcapi.ErrClusterServiceUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("Leave = %v, want ErrClusterServiceUnavailable", err)
			}
			if got := status.Code(grpcapi.ClusterErrorStatus(err)); got != codes.Unavailable {
				t.Errorf("Leave status code = %v, want %v", got, codes.Unavailable)
			}
			if fake.statusCalls != 0 || len(fake.removeReqs) != 0 {
				t.Errorf("Leave made SDK calls: status %d, remove %d", fake.statusCalls, len(fake.removeReqs))
			}
		})
	}
}

func TestClusterBackend_LeaveRemovesThisNodeFromEachShard(t *testing.T) {
	fake := &fakeClusterSurface{status: twoShardStatus()}
	b := NewClusterBackend(fake, 2, "")

	if err := b.Leave(context.Background()); err != nil {
		t.Fatalf("Leave = %v, want nil", err)
	}
	want := []quicbaasservice.RemoveNodeRequest{{ShardID: 1, NodeID: 2}, {ShardID: 3, NodeID: 2}}
	if !reflect.DeepEqual(fake.removeReqs, want) {
		t.Errorf("RemoveNode requests = %+v, want %+v", fake.removeReqs, want)
	}
}

func TestClusterBackend_LeaveOnlyShardsItReplicates(t *testing.T) {
	st := twoShardStatus()
	st.Shards[1].LeaderID = 3
	fake := &fakeClusterSurface{status: st}
	b := NewClusterBackend(fake, 1, "")

	if err := b.Leave(context.Background()); err != nil {
		t.Fatalf("Leave = %v, want nil", err)
	}
	want := []quicbaasservice.RemoveNodeRequest{{ShardID: 1, NodeID: 1}}
	if !reflect.DeepEqual(fake.removeReqs, want) {
		t.Errorf("RemoveNode requests = %+v, want %+v", fake.removeReqs, want)
	}
}

func TestClusterBackend_LeaveRefusesALeader(t *testing.T) {
	// Node 1 leads shard 1; node 3 leads shard 3 only and is a follower of
	// shard 1. Either way nothing is removed.
	for _, nodeID := range []uint64{1, 3} {
		fake := &fakeClusterSurface{status: twoShardStatus()}
		b := NewClusterBackend(fake, nodeID, "")

		var leader grpcapi.ErrCannotLeaveAsLeader
		if err := b.Leave(context.Background()); !errors.As(err, &leader) {
			t.Errorf("node %d: Leave = %v, want ErrCannotLeaveAsLeader", nodeID, err)
		}
		if len(fake.removeReqs) != 0 {
			t.Errorf("node %d: a refused leave removed %+v", nodeID, fake.removeReqs)
		}
	}
}

func TestClusterBackend_LeaveRefusesANonMember(t *testing.T) {
	fake := &fakeClusterSurface{status: twoShardStatus()}
	b := NewClusterBackend(fake, 7, "")

	var notMember grpcapi.ErrNodeNotInCluster
	if err := b.Leave(context.Background()); !errors.As(err, &notMember) {
		t.Errorf("Leave = %v, want ErrNodeNotInCluster", err)
	}
	if len(fake.removeReqs) != 0 {
		t.Errorf("a non-member leave removed %+v", fake.removeReqs)
	}
}

func TestClusterBackend_LeaveWithoutANodeID(t *testing.T) {
	fake := &fakeClusterSurface{status: twoShardStatus()}
	b := NewClusterBackend(fake, 0, "")

	var notInit grpcapi.ErrClusterNotInitialized
	if err := b.Leave(context.Background()); !errors.As(err, &notInit) {
		t.Errorf("Leave = %v, want ErrClusterNotInitialized", err)
	}
	if fake.statusCalls != 0 || len(fake.removeReqs) != 0 {
		t.Errorf("Leave with no node ID made SDK calls: status %d, remove %d", fake.statusCalls, len(fake.removeReqs))
	}
}

func TestClusterBackend_LeaveSDKFailure(t *testing.T) {
	cases := map[string]struct {
		fake *fakeClusterSurface
		text string
	}{
		"error": {
			fake: &fakeClusterSurface{status: twoShardStatus(), removeErr: errors.New("raft: remove member timed out")},
			text: "raft: remove member timed out",
		},
		"not successful": {
			fake: &fakeClusterSurface{status: twoShardStatus(), removeResp: &quicbaasservice.RemoveNodeResponse{Success: false, Message: "proposal dropped"}},
			text: "proposal dropped",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b := NewClusterBackend(tc.fake, 2, "")
			var failed grpcapi.ErrClusterOperationFailed
			if err := b.Leave(context.Background()); !errors.As(err, &failed) {
				t.Fatalf("Leave = %v, want ErrClusterOperationFailed", err)
			}
			if failed.Operation != "leave" || !strings.Contains(failed.Reason, tc.text) || !strings.Contains(failed.Reason, "shard 1") {
				t.Errorf("Leave error = %+v, want Operation leave naming shard 1 and %q", failed, tc.text)
			}
			if len(tc.fake.removeReqs) != 1 {
				t.Errorf("Leave went on after a failed RemoveNode: %+v", tc.fake.removeReqs)
			}
		})
	}
}

func TestClusterBackend_LeaveStatusFailure(t *testing.T) {
	fake := &fakeClusterSurface{statusErr: errors.New("raft: shard 1 unavailable")}
	b := NewClusterBackend(fake, 2, "")

	var failed grpcapi.ErrClusterOperationFailed
	if err := b.Leave(context.Background()); !errors.As(err, &failed) || failed.Operation != "leave" {
		t.Errorf("Leave = %v, want ErrClusterOperationFailed for leave", err)
	}
	if len(fake.removeReqs) != 0 {
		t.Errorf("Leave removed %+v after a status failure", fake.removeReqs)
	}
}

func TestClusterBackend_LeaveStatusCodes(t *testing.T) {
	cases := []struct {
		name   string
		fake   *fakeClusterSurface
		nodeID uint64
		want   codes.Code
	}{
		{"leader", &fakeClusterSurface{status: twoShardStatus()}, 1, codes.FailedPrecondition},
		{"no node ID", &fakeClusterSurface{status: twoShardStatus()}, 0, codes.FailedPrecondition},
		{"non-member", &fakeClusterSurface{status: twoShardStatus()}, 7, codes.NotFound},
		{"sdk failure", &fakeClusterSurface{status: twoShardStatus(), removeErr: errors.New("raft: remove member timed out")}, 2, codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewClusterBackend(tc.fake, tc.nodeID, "")
			if got := status.Code(grpcapi.ClusterErrorStatus(b.Leave(context.Background()))); got != tc.want {
				t.Errorf("Leave status code = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClusterBackend_SDKErrors(t *testing.T) {
	ctx := context.Background()
	sdkErr := errors.New("raft: shard 1 unavailable")
	b := NewClusterBackend(&fakeClusterSurface{statusErr: sdkErr}, 1, "")

	calls := map[string]func() error{
		"status":    func() error { _, err := b.Status(ctx); return err },
		"nodes":     func() error { _, err := b.Nodes(ctx); return err },
		"bootstrap": func() error { return b.Bootstrap(ctx) },
	}
	for op, call := range calls {
		t.Run(op, func(t *testing.T) {
			var failed grpcapi.ErrClusterOperationFailed
			err := call()
			if !errors.As(err, &failed) {
				t.Fatalf("%s error = %v, want ErrClusterOperationFailed", op, err)
			}
			if failed.Operation != op || !strings.Contains(failed.Reason, sdkErr.Error()) {
				t.Errorf("%s error = %+v, want Operation %q with the SDK error text", op, failed, op)
			}
		})
	}
}

func TestClusterBackend_NilSurface(t *testing.T) {
	if b := NewClusterBackend(nil, 1, ""); b != nil {
		t.Errorf("NewClusterBackend(nil) = %#v, want an untyped nil", b)
	}
}

func TestPlatformClusterBackend_NoEmbeddedService(t *testing.T) {
	if b := PlatformClusterBackend(nil); b != nil {
		t.Errorf("PlatformClusterBackend(nil) = %#v, want nil", b)
	}
	if b := PlatformClusterBackend(&app.App{}); b != nil {
		t.Errorf("PlatformClusterBackend(no service) = %#v, want nil", b)
	}
}
