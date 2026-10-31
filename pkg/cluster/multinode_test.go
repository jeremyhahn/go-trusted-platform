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
	"fmt"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// sharedRaftState is one Raft group seen by every node of a multi-node test
// cluster: the voter set, the leader and the term.
type sharedRaftState struct {
	mu       sync.Mutex
	members  map[uint64]string
	leaderID uint64
	term     uint64
}

func newSharedRaftState() *sharedRaftState {
	return &sharedRaftState{members: make(map[uint64]string), term: 1}
}

// setLeader elects id, as a Raft election would after the leader is lost.
func (s *sharedRaftState) setLeader(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaderID = id
}

// incrementTerm starts a new term, as a Raft election does.
func (s *sharedRaftState) incrementTerm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.term++
}

func (s *sharedRaftState) leader() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leaderID
}

// sharedRaftOperator is one node's RaftOperator over a sharedRaftState.
type sharedRaftOperator struct {
	state   *sharedRaftState
	id      uint64
	address string
}

func (o *sharedRaftOperator) Bootstrap(ctx context.Context) error {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	o.state.members[o.id] = o.address
	o.state.leaderID = o.id
	return nil
}

func (o *sharedRaftOperator) AddVoter(ctx context.Context, id uint64, address string) error {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	o.state.members[id] = address
	return nil
}

func (o *sharedRaftOperator) AddNonvoter(ctx context.Context, id uint64, address string) error {
	return o.AddVoter(ctx, id, address)
}

func (o *sharedRaftOperator) RemoveServer(ctx context.Context, id uint64) error {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	delete(o.state.members, id)
	if o.state.leaderID == id {
		o.state.leaderID = 0
	}
	return nil
}

func (o *sharedRaftOperator) GetLeader() (uint64, string, error) {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.state.leaderID, o.state.members[o.state.leaderID], nil
}

func (o *sharedRaftOperator) GetNodes() ([]RaftMemberInfo, error) {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	nodes := make([]RaftMemberInfo, 0, len(o.state.members))
	for id, addr := range o.state.members {
		nodes = append(nodes, RaftMemberInfo{ID: id, Address: addr, Voter: true})
	}
	return nodes, nil
}

func (o *sharedRaftOperator) IsLeader() bool {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.state.leaderID == o.id
}

func (o *sharedRaftOperator) GetState() RaftState {
	if o.IsLeader() {
		return RaftStateLeader
	}
	return RaftStateFollower
}

func (o *sharedRaftOperator) GetTerm() uint64 {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.state.term
}

// testNode is one member of a multi-node test cluster: a real coordinator
// over a real membership manager.
type testNode struct {
	id          uint64
	address     string
	coordinator Coordinator
	membership  *membershipManager
}

// newTestCluster starts size nodes over one shared Raft group. Node 1
// bootstraps and every other node joins through it, so node 1 leads. The
// nodes are stopped and closed when the test ends.
func newTestCluster(t *testing.T, size int) ([]*testNode, *sharedRaftState) {
	t.Helper()
	ctx := t.Context()
	state := newSharedRaftState()
	nodes := make([]*testNode, 0, size)

	for i := 1; i <= size; i++ {
		config := NewConfig()
		config.NodeID = uint64(i)
		config.ListenAddress = fmt.Sprintf("127.0.0.1:%d", 7000+i)
		config.DataDir = t.TempDir()

		raftOp := &sharedRaftOperator{state: state, id: config.NodeID, address: config.ListenAddress}
		membership, err := NewMembershipManager(config, raftOp, logging.DefaultLogger())
		if err != nil {
			t.Fatalf("NewMembershipManager(node %d) error = %v", i, err)
		}
		coordinator, err := NewCoordinator(config, membership, logging.DefaultLogger())
		if err != nil {
			t.Fatalf("NewCoordinator(node %d) error = %v", i, err)
		}
		node := &testNode{id: config.NodeID, address: config.ListenAddress, coordinator: coordinator, membership: membership}
		t.Cleanup(func() {
			if node.coordinator.IsRunning() {
				if err := node.coordinator.Stop(context.Background()); err != nil {
					t.Errorf("Stop(node %d) error = %v", node.id, err)
				}
			}
			if err := node.membership.Close(); err != nil {
				t.Errorf("Close(node %d) error = %v", node.id, err)
			}
		})

		if err := coordinator.Start(ctx); err != nil {
			t.Fatalf("Start(node %d) error = %v", i, err)
		}
		if i == 1 {
			err = coordinator.Bootstrap(ctx)
		} else {
			err = coordinator.Join(ctx, []string{nodes[0].address})
		}
		if err != nil {
			t.Fatalf("Bootstrap/Join(node %d) error = %v", i, err)
		}
		nodes = append(nodes, node)
	}
	return nodes, state
}

// mustStatus returns the node's cluster status, failing the test on error.
func mustStatus(t *testing.T, node *testNode) *ClusterStatus {
	t.Helper()
	status, err := node.coordinator.Status(t.Context())
	if err != nil {
		t.Fatalf("Status(node %d) error = %v", node.id, err)
	}
	return status
}

// mustStop stops the node's coordinator, which leaves the Raft group.
func mustStop(t *testing.T, node *testNode) {
	t.Helper()
	if err := node.coordinator.Stop(t.Context()); err != nil {
		t.Fatalf("Stop(node %d) error = %v", node.id, err)
	}
}

func TestMultiNode_Formation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, _ := newTestCluster(t, 3)

		leaders := 0
		for _, node := range nodes {
			if !node.coordinator.IsRunning() {
				t.Errorf("node %d IsRunning() = false", node.id)
			}
			if node.coordinator.IsLeader() {
				leaders++
			}

			status := mustStatus(t, node)
			if status.State != ClusterStateRunning {
				t.Errorf("node %d State = %v, want %v", node.id, status.State, ClusterStateRunning)
			}
			if status.NodeCount != 3 || status.HealthyCount != 3 {
				t.Errorf("node %d NodeCount/HealthyCount = %d/%d, want 3/3", node.id, status.NodeCount, status.HealthyCount)
			}
			if !status.HasQuorum {
				t.Errorf("node %d HasQuorum = false, want true", node.id)
			}
			if status.LeaderID != 1 {
				t.Errorf("node %d LeaderID = %d, want 1", node.id, status.LeaderID)
			}
			if status.StartedAt.IsZero() || status.LastUpdated.IsZero() {
				t.Errorf("node %d StartedAt/LastUpdated not set", node.id)
			}
			if status.ErrorMessage != "" {
				t.Errorf("node %d ErrorMessage = %q, want empty", node.id, status.ErrorMessage)
			}
			if !node.coordinator.IsHealthy() {
				t.Errorf("node %d IsHealthy() = false", node.id)
			}
		}
		if leaders != 1 {
			t.Errorf("leaders = %d, want exactly 1", leaders)
		}
	})
}

func TestMultiNode_EveryNodeDiscoversEveryMember(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, _ := newTestCluster(t, 3)

		for _, node := range nodes {
			list, err := node.coordinator.Nodes(t.Context())
			if err != nil {
				t.Fatalf("Nodes(node %d) error = %v", node.id, err)
			}
			if list.Count() != 3 || len(list.Healthy()) != 3 {
				t.Errorf("node %d sees %d nodes, %d healthy, want 3 and 3", node.id, list.Count(), len(list.Healthy()))
			}
			if list.Leader == nil || list.Leader.ID != 1 {
				t.Errorf("node %d Leader = %+v, want node 1", node.id, list.Leader)
			}
			for _, want := range nodes {
				member := list.FindByID(want.id)
				if member == nil {
					t.Errorf("node %d does not see node %d", node.id, want.id)
					continue
				}
				if member.Address != want.address {
					t.Errorf("node %d sees node %d at %q, want %q", node.id, want.id, member.Address, want.address)
				}
				if member.IsLeader != (want.id == 1) {
					t.Errorf("node %d sees node %d IsLeader = %v", node.id, want.id, member.IsLeader)
				}
			}
			if list.FindByID(999) != nil {
				t.Errorf("node %d FindByID(999) found a node", node.id)
			}
		}
	})
}

func TestMultiNode_FollowerLossKeepsQuorum(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, _ := newTestCluster(t, 3)
		leader := nodes[0]
		mustStatus(t, leader)

		mustStop(t, nodes[2])

		status := mustStatus(t, leader)
		if status.State != ClusterStateRunning || !status.HasQuorum {
			t.Errorf("leader State/HasQuorum = %v/%v, want running with quorum", status.State, status.HasQuorum)
		}
		if status.NodeCount != 3 || status.HealthyCount != 2 {
			t.Errorf("leader NodeCount/HealthyCount = %d/%d, want 3/2", status.NodeCount, status.HealthyCount)
		}
		if !leader.coordinator.IsRunning() || !leader.coordinator.IsLeader() {
			t.Error("leader stopped leading after a follower left")
		}
	})
}

func TestMultiNode_TwoOfFiveLostKeepsQuorum(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, _ := newTestCluster(t, 5)
		leader := nodes[0]
		mustStatus(t, leader)

		mustStop(t, nodes[3])
		mustStop(t, nodes[4])

		status := mustStatus(t, leader)
		if !status.HasQuorum || status.HealthyCount != 3 {
			t.Errorf("leader HasQuorum/HealthyCount = %v/%d, want true/3", status.HasQuorum, status.HealthyCount)
		}
		if !leader.coordinator.IsRunning() || !leader.coordinator.IsLeader() {
			t.Error("leader stopped leading after two of five nodes left")
		}
	})
}

func TestMultiNode_MajorityLossDegrades(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, _ := newTestCluster(t, 3)
		leader := nodes[0]
		mustStatus(t, leader)

		mustStop(t, nodes[1])
		mustStop(t, nodes[2])

		status := mustStatus(t, leader)
		if status.State != ClusterStateDegraded || status.HasQuorum {
			t.Errorf("leader State/HasQuorum = %v/%v, want degraded without quorum", status.State, status.HasQuorum)
		}
		if want := "insufficient healthy nodes: 1/2 required"; status.ErrorMessage != want {
			t.Errorf("leader ErrorMessage = %q, want %q", status.ErrorMessage, want)
		}
		if leader.coordinator.IsHealthy() {
			t.Error("leader IsHealthy() = true without quorum")
		}
	})
}

func TestMultiNode_RestartedNodeRejoins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, _ := newTestCluster(t, 3)
		leader, restarted := nodes[0], nodes[2]
		mustStatus(t, leader)

		mustStop(t, restarted)
		if err := restarted.coordinator.Start(t.Context()); err != nil {
			t.Fatalf("Start() after Stop error = %v", err)
		}
		if err := restarted.coordinator.Join(t.Context(), []string{leader.address}); err != nil {
			t.Fatalf("Join() after restart error = %v", err)
		}

		status := mustStatus(t, restarted)
		if status.NodeCount != 3 || status.HealthyCount != 3 || !status.HasQuorum {
			t.Errorf("restarted NodeCount/HealthyCount/HasQuorum = %d/%d/%v, want 3/3/true",
				status.NodeCount, status.HealthyCount, status.HasQuorum)
		}
		if status.LeaderID != leader.id {
			t.Errorf("restarted LeaderID = %d, want %d", status.LeaderID, leader.id)
		}

		list, err := leader.coordinator.Nodes(t.Context())
		if err != nil {
			t.Fatalf("Nodes(leader) error = %v", err)
		}
		if list.Count() != 3 || list.FindByID(restarted.id) == nil {
			t.Errorf("leader sees %d nodes, restarted node present = %v", list.Count(), list.FindByID(restarted.id) != nil)
		}
	})
}

func TestMultiNode_LeaderFailover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, state := newTestCluster(t, 3)
		oldLeader, successor := nodes[0], nodes[1]

		mustStop(t, oldLeader)
		if got := state.leader(); got != 0 {
			t.Fatalf("raft leader after the leader left = %d, want none", got)
		}
		if successor.coordinator.IsLeader() {
			t.Fatal("successor leads before an election")
		}

		type result struct {
			leader *Node
			err    error
		}
		waited := make(chan result, 1)
		go func() {
			leader, err := successor.coordinator.WaitForLeader(t.Context())
			waited <- result{leader, err}
		}()
		// The waiter is registered and blocked before the election.
		synctest.Wait()

		state.setLeader(successor.id)
		state.incrementTerm()

		// The membership leader-check tick delivers the new leader.
		got := <-waited
		synctest.Wait()
		if got.err != nil {
			t.Fatalf("WaitForLeader() error = %v", got.err)
		}
		if got.leader.ID != successor.id {
			t.Errorf("WaitForLeader() = node %d, want node %d", got.leader.ID, successor.id)
		}
		if !successor.coordinator.IsLeader() {
			t.Error("successor IsLeader() = false after the election")
		}

		status := mustStatus(t, successor)
		if status.LeaderID != successor.id || !status.HasQuorum {
			t.Errorf("successor LeaderID/HasQuorum = %d/%v, want %d/true", status.LeaderID, status.HasQuorum, successor.id)
		}
		list, err := nodes[2].coordinator.Nodes(t.Context())
		if err != nil {
			t.Fatalf("Nodes(node 3) error = %v", err)
		}
		if list.Term != 2 {
			t.Errorf("Term = %d, want 2", list.Term)
		}
		leader, err := nodes[2].coordinator.GetLeader(t.Context())
		if err != nil {
			t.Fatalf("GetLeader(node 3) error = %v", err)
		}
		if leader.ID != successor.id {
			t.Errorf("node 3 GetLeader() = node %d, want node %d", leader.ID, successor.id)
		}
	})
}
