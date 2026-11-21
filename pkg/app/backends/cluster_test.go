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
	"strings"
	"testing"
	"time"

	quicbaasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// fakeClusterSurface is a ClusterSurface returning canned answers and
// counting the calls made to it.
type fakeClusterSurface struct {
	status    *quicbaasservice.ClusterStatusResponse
	statusErr error
	leader    *quicbaasservice.GetLeaderResponse
	leaderErr error

	statusCalls int
	leaderCalls int
	leaderReq   *quicbaasservice.GetLeaderRequest
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
	leaderOne := &fakeClusterSurface{leader: &quicbaasservice.GetLeaderResponse{ShardID: 1, LeaderID: 1}}
	b := NewClusterBackend(leaderOne, 1, "")
	if !b.IsLeader() {
		t.Error("IsLeader = false with LeaderID 1 and node ID 1")
	}
	if leaderOne.leaderReq == nil || leaderOne.leaderReq.ShardID != 1 {
		t.Errorf("GetLeader request = %+v, want ShardID 1", leaderOne.leaderReq)
	}
	if b.NodeID() != 1 {
		t.Errorf("NodeID = %d, want 1", b.NodeID())
	}

	if NewClusterBackend(&fakeClusterSurface{leader: &quicbaasservice.GetLeaderResponse{ShardID: 1, LeaderID: 2}}, 1, "").IsLeader() {
		t.Error("IsLeader = true with LeaderID 2")
	}
	if NewClusterBackend(&fakeClusterSurface{leaderErr: errors.New("no leader")}, 1, "").IsLeader() {
		t.Error("IsLeader = true on a GetLeader error")
	}
	if NewClusterBackend(&fakeClusterSurface{leader: &quicbaasservice.GetLeaderResponse{ShardID: 1}}, 0, "").IsLeader() {
		t.Error("IsLeader = true with node ID 0 and LeaderID 0")
	}
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

func TestClusterBackend_JoinLeaveNotWired(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClusterSurface{status: threeNodeStatus()}
	b := NewClusterBackend(fake, 1, "")

	var unavailable grpcapi.ErrClusterServiceUnavailable
	if err := b.Join(ctx, []string{"10.0.0.9:7000"}); !errors.As(err, &unavailable) {
		t.Errorf("Join = %v, want ErrClusterServiceUnavailable", err)
	}
	if err := b.Leave(ctx); !errors.As(err, &unavailable) {
		t.Errorf("Leave = %v, want ErrClusterServiceUnavailable", err)
	}
	if fake.statusCalls != 0 || fake.leaderCalls != 0 {
		t.Errorf("Join/Leave made SDK calls: status %d, leader %d", fake.statusCalls, fake.leaderCalls)
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
