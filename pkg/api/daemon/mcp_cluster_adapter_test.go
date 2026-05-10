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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cluster"
)

// =============================================================================
// Test fakes
// =============================================================================

// fakeClusterCore implements clusterCore so the adapter can be tested
// without spinning up a real Raft coordinator.
type fakeClusterCore struct {
	bootstrapCalled int
	joinCalled      int
	joinAddresses   []string
	leaveCalled     int

	bootstrapErr error
	joinErr      error
	leaveErr     error

	statusVal *cluster.ClusterStatus
	statusErr error

	nodesVal cluster.NodeList
	nodesErr error

	leader bool
	nodeID uint64
}

func (f *fakeClusterCore) Bootstrap(ctx context.Context) error {
	f.bootstrapCalled++
	return f.bootstrapErr
}

func (f *fakeClusterCore) Join(ctx context.Context, addresses []string) error {
	f.joinCalled++
	f.joinAddresses = append([]string(nil), addresses...)
	return f.joinErr
}

func (f *fakeClusterCore) Leave(ctx context.Context) error {
	f.leaveCalled++
	return f.leaveErr
}

func (f *fakeClusterCore) Status(ctx context.Context) (*cluster.ClusterStatus, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.statusVal, nil
}

func (f *fakeClusterCore) Nodes(ctx context.Context) (cluster.NodeList, error) {
	if f.nodesErr != nil {
		return cluster.NodeList{}, f.nodesErr
	}
	return f.nodesVal, nil
}

func (f *fakeClusterCore) IsLeader() bool { return f.leader }
func (f *fakeClusterCore) NodeID() uint64 { return f.nodeID }

// =============================================================================
// Tests: NewClusterServiceAdapter
// =============================================================================

func TestNewClusterServiceAdapter_NilReturnsNil(t *testing.T) {
	if got := NewClusterServiceAdapter(nil); got != nil {
		t.Errorf("expected nil for nil input, got %T", got)
	}
}

func TestNewClusterServiceAdapter_InternalNilReturnsNil(t *testing.T) {
	if got := newClusterServiceAdapter(nil); got != nil {
		t.Errorf("expected nil for nil input, got %T", got)
	}
}

// =============================================================================
// Tests: adapter delegation
// =============================================================================

func TestClusterServiceAdapter_Bootstrap(t *testing.T) {
	core := &fakeClusterCore{}
	a := newClusterServiceAdapter(core)
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if core.bootstrapCalled != 1 {
		t.Errorf("Bootstrap calls = %d, want 1", core.bootstrapCalled)
	}
}

func TestClusterServiceAdapter_BootstrapPropagatesError(t *testing.T) {
	want := errors.New("boom")
	core := &fakeClusterCore{bootstrapErr: want}
	a := newClusterServiceAdapter(core)
	if err := a.Bootstrap(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}
}

func TestClusterServiceAdapter_Join(t *testing.T) {
	core := &fakeClusterCore{}
	a := newClusterServiceAdapter(core)
	if err := a.Join(context.Background(), []string{"a:1", "b:2"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if core.joinCalled != 1 {
		t.Errorf("Join calls = %d, want 1", core.joinCalled)
	}
	if len(core.joinAddresses) != 2 || core.joinAddresses[0] != "a:1" {
		t.Errorf("Join addresses = %v, want [a:1 b:2]", core.joinAddresses)
	}
}

func TestClusterServiceAdapter_JoinPropagatesError(t *testing.T) {
	want := errors.New("boom")
	core := &fakeClusterCore{joinErr: want}
	a := newClusterServiceAdapter(core)
	if err := a.Join(context.Background(), []string{"x:1"}); !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}
}

func TestClusterServiceAdapter_Leave(t *testing.T) {
	core := &fakeClusterCore{}
	a := newClusterServiceAdapter(core)
	if err := a.Leave(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if core.leaveCalled != 1 {
		t.Errorf("Leave calls = %d, want 1", core.leaveCalled)
	}
}

func TestClusterServiceAdapter_LeavePropagatesError(t *testing.T) {
	want := errors.New("boom")
	core := &fakeClusterCore{leaveErr: want}
	a := newClusterServiceAdapter(core)
	if err := a.Leave(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}
}

func TestClusterServiceAdapter_Status(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	core := &fakeClusterCore{
		statusVal: &cluster.ClusterStatus{
			State:        cluster.ClusterStateRunning,
			NodeCount:    3,
			HealthyCount: 3,
			LeaderID:     1,
			Term:         5,
			HasQuorum:    true,
			LastUpdated:  now,
			StartedAt:    now.Add(-time.Hour),
			ErrorMessage: "",
		},
	}
	a := newClusterServiceAdapter(core)

	got, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil status")
	}
	if got.State != string(cluster.ClusterStateRunning) {
		t.Errorf("State = %q, want %q", got.State, cluster.ClusterStateRunning)
	}
	if got.NodeCount != 3 {
		t.Errorf("NodeCount = %d, want 3", got.NodeCount)
	}
	if !got.HasQuorum {
		t.Errorf("HasQuorum should be true")
	}
}

func TestClusterServiceAdapter_StatusPropagatesError(t *testing.T) {
	want := errors.New("boom")
	core := &fakeClusterCore{statusErr: want}
	a := newClusterServiceAdapter(core)
	if _, err := a.Status(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}
}

func TestClusterServiceAdapter_StatusNil(t *testing.T) {
	core := &fakeClusterCore{statusVal: nil}
	a := newClusterServiceAdapter(core)
	got, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil ClusterStatusInfo for nil domain status, got %v", got)
	}
}

func TestClusterServiceAdapter_Nodes(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	leader := &cluster.Node{
		ID:          1,
		Address:     "10.0.0.1:7001",
		RaftAddress: "10.0.0.1:7000",
		IsLeader:    true,
		State:       cluster.NodeStateHealthy,
		LastSeen:    now,
		JoinTime:    now.Add(-time.Hour),
		Metadata:    map[string]string{"role": "leader"},
	}
	follower := &cluster.Node{
		ID:       2,
		Address:  "10.0.0.2:7001",
		IsLeader: false,
		State:    cluster.NodeStateHealthy,
		LastSeen: now,
		JoinTime: now.Add(-time.Hour),
	}
	core := &fakeClusterCore{
		nodesVal: cluster.NodeList{
			Nodes:  []*cluster.Node{leader, nil, follower}, // includes a nil to exercise skip
			Leader: leader,
			Term:   5,
		},
	}
	a := newClusterServiceAdapter(core)

	got, err := a.Nodes(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.Term != 5 {
		t.Errorf("Term = %d, want 5", got.Term)
	}
	if len(got.Nodes) != 2 {
		t.Errorf("Nodes len = %d, want 2 (nil should be skipped)", len(got.Nodes))
	}
	if got.Leader == nil || got.Leader.ID != 1 {
		t.Errorf("Leader projection mismatch: %+v", got.Leader)
	}
	if got.Nodes[0].State != "healthy" {
		t.Errorf("State projection mismatch: %q", got.Nodes[0].State)
	}
	if got.Nodes[0].Metadata["role"] != "leader" {
		t.Errorf("Metadata projection mismatch: %v", got.Nodes[0].Metadata)
	}
}

func TestClusterServiceAdapter_NodesPropagatesError(t *testing.T) {
	want := errors.New("boom")
	core := &fakeClusterCore{nodesErr: want}
	a := newClusterServiceAdapter(core)
	if _, err := a.Nodes(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected error %v, got %v", want, err)
	}
}

func TestClusterServiceAdapter_NodesNoLeader(t *testing.T) {
	core := &fakeClusterCore{
		nodesVal: cluster.NodeList{
			Nodes: []*cluster.Node{},
			Term:  1,
		},
	}
	a := newClusterServiceAdapter(core)

	got, err := a.Nodes(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Leader != nil {
		t.Errorf("expected nil Leader, got %+v", got.Leader)
	}
}

func TestClusterServiceAdapter_IsLeader(t *testing.T) {
	core := &fakeClusterCore{leader: true}
	a := newClusterServiceAdapter(core)
	if !a.IsLeader() {
		t.Error("IsLeader = false, want true")
	}
}

func TestClusterServiceAdapter_NodeID(t *testing.T) {
	core := &fakeClusterCore{nodeID: 42}
	a := newClusterServiceAdapter(core)
	if got := a.NodeID(); got != 42 {
		t.Errorf("NodeID = %d, want 42", got)
	}
}

// =============================================================================
// Tests: domain projections
// =============================================================================

func TestClusterStatusInfoFromDomain_Nil(t *testing.T) {
	if got := clusterStatusInfoFromDomain(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestClusterStatusInfoFromDomain_AllFields(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	st := &cluster.ClusterStatus{
		State:        cluster.ClusterStateDegraded,
		NodeCount:    5,
		HealthyCount: 3,
		LeaderID:     7,
		Term:         9,
		HasQuorum:    false,
		LastUpdated:  now,
		StartedAt:    now.Add(-time.Hour),
		ErrorMessage: "raft: split brain",
	}
	got := clusterStatusInfoFromDomain(st)
	if got.State != string(cluster.ClusterStateDegraded) {
		t.Errorf("State = %q, want %q", got.State, cluster.ClusterStateDegraded)
	}
	if got.NodeCount != 5 {
		t.Errorf("NodeCount = %d, want 5", got.NodeCount)
	}
	if got.HealthyCount != 3 {
		t.Errorf("HealthyCount = %d, want 3", got.HealthyCount)
	}
	if got.LeaderID != 7 {
		t.Errorf("LeaderID = %d, want 7", got.LeaderID)
	}
	if got.Term != 9 {
		t.Errorf("Term = %d, want 9", got.Term)
	}
	if got.HasQuorum {
		t.Errorf("HasQuorum should be false")
	}
	if got.ErrorMessage != "raft: split brain" {
		t.Errorf("ErrorMessage = %q, want raft: split brain", got.ErrorMessage)
	}
}

func TestClusterNodeInfoFromDomain_PassesAllFields(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	n := &cluster.Node{
		ID:          11,
		Address:     "x:1",
		RaftAddress: "x:7000",
		IsLeader:    true,
		State:       cluster.NodeStateSuspect,
		LastSeen:    now,
		JoinTime:    now.Add(-time.Hour),
		Metadata:    map[string]string{"k": "v"},
	}
	got := clusterNodeInfoFromDomain(n)
	if got.ID != 11 {
		t.Errorf("ID = %d, want 11", got.ID)
	}
	if got.Address != "x:1" {
		t.Errorf("Address = %q, want x:1", got.Address)
	}
	if got.RaftAddress != "x:7000" {
		t.Errorf("RaftAddress = %q, want x:7000", got.RaftAddress)
	}
	if !got.IsLeader {
		t.Error("IsLeader should be true")
	}
	if got.State != "suspect" {
		t.Errorf("State = %q, want suspect", got.State)
	}
	if got.Metadata["k"] != "v" {
		t.Errorf("Metadata mismatch: %v", got.Metadata)
	}
}

func TestClusterNodesInfoFromDomain_EmptyList(t *testing.T) {
	got := clusterNodesInfoFromDomain(cluster.NodeList{})
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if len(got.Nodes) != 0 {
		t.Errorf("Nodes len = %d, want 0", len(got.Nodes))
	}
	if got.Leader != nil {
		t.Errorf("Leader should be nil for empty list")
	}
}

func TestClusterNodesInfoFromDomain_SkipsNilNodes(t *testing.T) {
	got := clusterNodesInfoFromDomain(cluster.NodeList{
		Nodes: []*cluster.Node{nil, {ID: 1, State: cluster.NodeStateHealthy}, nil},
		Term:  3,
	})
	if len(got.Nodes) != 1 {
		t.Errorf("Nodes len = %d, want 1 (nils dropped)", len(got.Nodes))
	}
	if got.Term != 3 {
		t.Errorf("Term = %d, want 3", got.Term)
	}
}
