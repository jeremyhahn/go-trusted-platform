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
	"errors"
	"testing"
	"time"
)

// =============================================================================
// Test fakes
// =============================================================================

// fakeClusterServicer is a hand-rolled ClusterServicer that records calls
// and returns canned data. Hand-rolling beats a mocking framework here:
// the surface is tiny (7 methods) and tests stay readable.
type fakeClusterServicer struct {
	bootstrapCalled int
	joinCalled      int
	joinAddresses   []string
	leaveCalled     int

	statusInfo  *ClusterStatusInfo
	statusErr   error
	statusCalls int

	nodes     *ClusterNodesInfo
	nodesErr  error
	nodeCalls int

	bootstrapErr error
	joinErr      error
	leaveErr     error

	leader bool
	nodeID uint64
}

func (f *fakeClusterServicer) Bootstrap(ctx context.Context) error {
	f.bootstrapCalled++
	return f.bootstrapErr
}

func (f *fakeClusterServicer) Join(ctx context.Context, addresses []string) error {
	f.joinCalled++
	f.joinAddresses = append([]string(nil), addresses...)
	return f.joinErr
}

func (f *fakeClusterServicer) Leave(ctx context.Context) error {
	f.leaveCalled++
	return f.leaveErr
}

func (f *fakeClusterServicer) Status(ctx context.Context) (*ClusterStatusInfo, error) {
	f.statusCalls++
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.statusInfo, nil
}

func (f *fakeClusterServicer) Nodes(ctx context.Context) (*ClusterNodesInfo, error) {
	f.nodeCalls++
	if f.nodesErr != nil {
		return nil, f.nodesErr
	}
	return f.nodes, nil
}

func (f *fakeClusterServicer) IsLeader() bool { return f.leader }
func (f *fakeClusterServicer) NodeID() uint64 { return f.nodeID }

// newProviderWithCluster wires a fake servicer into a fresh
// MCPServiceProvider via the public setter (which is itself part of the
// surface under test).
func newProviderWithCluster(svc ClusterServicer) *MCPServiceProvider {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	p.SetClusterService(svc)
	return p
}

// stockStatus returns a canned ClusterStatusInfo for the happy path.
func stockStatus() *ClusterStatusInfo {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	return &ClusterStatusInfo{
		State:        "healthy",
		NodeCount:    3,
		HealthyCount: 3,
		LeaderID:     1,
		Term:         5,
		HasQuorum:    true,
		LastUpdated:  now,
		StartedAt:    now.Add(-time.Hour),
	}
}

// stockNodes returns a canned ClusterNodesInfo with a leader node.
func stockNodes() *ClusterNodesInfo {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	leader := ClusterNodeInfo{
		ID:          1,
		Address:     "10.0.0.1:7001",
		RaftAddress: "10.0.0.1:7000",
		IsLeader:    true,
		State:       "healthy",
		LastSeen:    now,
		JoinTime:    now.Add(-time.Hour),
		Metadata:    map[string]string{"role": "leader"},
	}
	follower := ClusterNodeInfo{
		ID:       2,
		Address:  "10.0.0.2:7001",
		IsLeader: false,
		State:    "healthy",
		LastSeen: now,
		JoinTime: now.Add(-time.Hour),
	}
	return &ClusterNodesInfo{
		Nodes:  []ClusterNodeInfo{leader, follower},
		Leader: &leader,
		Term:   5,
	}
}

// =============================================================================
// Tests: errors
// =============================================================================

func TestErrClusterNotConfigured_Error(t *testing.T) {
	if got := (ErrClusterNotConfigured{}).Error(); got != "cluster service not configured" {
		t.Errorf("unexpected message: %q", got)
	}
}

func TestErrClusterPeerAddressRequired_Error(t *testing.T) {
	got := (ErrClusterPeerAddressRequired{}).Error()
	if got == "" {
		t.Fatal("expected non-empty error message")
	}
}

// =============================================================================
// Tests: ClusterBootstrap
// =============================================================================

func TestClusterBootstrap_NoServicer(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	_, err := p.ClusterBootstrap(context.Background(), "alpha")
	if !errors.As(err, new(ErrClusterNotConfigured)) {
		t.Fatalf("expected ErrClusterNotConfigured, got %v", err)
	}
}

func TestClusterBootstrap_HappyPath(t *testing.T) {
	fake := &fakeClusterServicer{
		statusInfo: stockStatus(),
		nodeID:     1,
		leader:     true,
	}
	p := newProviderWithCluster(fake)

	result, err := p.ClusterBootstrap(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.bootstrapCalled != 1 {
		t.Errorf("Bootstrap call count = %d, want 1", fake.bootstrapCalled)
	}
	if fake.statusCalls != 1 {
		t.Errorf("Status call count = %d, want 1", fake.statusCalls)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if m["bootstrap"] != true {
		t.Errorf("bootstrap field = %v, want true", m["bootstrap"])
	}
	if m["cluster_name"] != "alpha" {
		t.Errorf("cluster_name = %v, want alpha", m["cluster_name"])
	}
	if m["node_id"] != uint64(1) {
		t.Errorf("node_id = %v, want 1", m["node_id"])
	}
}

func TestClusterBootstrap_WithoutName_OmitsField(t *testing.T) {
	fake := &fakeClusterServicer{statusInfo: stockStatus()}
	p := newProviderWithCluster(fake)

	result, err := p.ClusterBootstrap(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if _, ok := m["cluster_name"]; ok {
		t.Errorf("expected cluster_name to be omitted when empty")
	}
}

func TestClusterBootstrap_BootstrapError(t *testing.T) {
	want := errors.New("boom: raft")
	fake := &fakeClusterServicer{bootstrapErr: want}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterBootstrap(context.Background(), "alpha")
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped error %v, got %v", want, err)
	}
	if fake.statusCalls != 0 {
		t.Errorf("Status should not be called after bootstrap fails")
	}
}

func TestClusterBootstrap_StatusError(t *testing.T) {
	want := errors.New("boom: status")
	fake := &fakeClusterServicer{statusErr: want}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterBootstrap(context.Background(), "alpha")
	if !errors.Is(err, want) {
		t.Fatalf("expected status error, got %v", err)
	}
}

// =============================================================================
// Tests: ClusterJoin
// =============================================================================

func TestClusterJoin_NoServicer(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	_, err := p.ClusterJoin(context.Background(), []string{"x:1"})
	if !errors.As(err, new(ErrClusterNotConfigured)) {
		t.Fatalf("expected ErrClusterNotConfigured, got %v", err)
	}
}

func TestClusterJoin_NoAddresses(t *testing.T) {
	fake := &fakeClusterServicer{}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterJoin(context.Background(), nil)
	if !errors.As(err, new(ErrClusterPeerAddressRequired)) {
		t.Fatalf("expected ErrClusterPeerAddressRequired, got %v", err)
	}
	if fake.joinCalled != 0 {
		t.Errorf("Join must not be called with no addresses")
	}
}

func TestClusterJoin_HappyPath(t *testing.T) {
	fake := &fakeClusterServicer{
		statusInfo: stockStatus(),
		nodeID:     2,
	}
	p := newProviderWithCluster(fake)

	addrs := []string{"10.0.0.1:7001", "10.0.0.2:7001"}
	result, err := p.ClusterJoin(context.Background(), addrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.joinCalled != 1 {
		t.Errorf("Join call count = %d, want 1", fake.joinCalled)
	}
	if len(fake.joinAddresses) != 2 {
		t.Errorf("Join addresses = %v, want %v", fake.joinAddresses, addrs)
	}
	m := result.(map[string]interface{})
	if m["joined"] != true {
		t.Errorf("joined = %v, want true", m["joined"])
	}
}

func TestClusterJoin_PropagatesError(t *testing.T) {
	want := errors.New("boom: dial")
	fake := &fakeClusterServicer{joinErr: want}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterJoin(context.Background(), []string{"x:1"})
	if !errors.Is(err, want) {
		t.Fatalf("expected join error, got %v", err)
	}
}

// =============================================================================
// Tests: ClusterLeave
// =============================================================================

func TestClusterLeave_NoServicer(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	_, err := p.ClusterLeave(context.Background())
	if !errors.As(err, new(ErrClusterNotConfigured)) {
		t.Fatalf("expected ErrClusterNotConfigured, got %v", err)
	}
}

func TestClusterLeave_HappyPath(t *testing.T) {
	fake := &fakeClusterServicer{nodeID: 7}
	p := newProviderWithCluster(fake)

	result, err := p.ClusterLeave(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.leaveCalled != 1 {
		t.Errorf("Leave call count = %d, want 1", fake.leaveCalled)
	}
	m := result.(map[string]interface{})
	if m["left"] != true {
		t.Errorf("left = %v, want true", m["left"])
	}
	if m["node_id"] != uint64(7) {
		t.Errorf("node_id = %v, want 7", m["node_id"])
	}
}

func TestClusterLeave_PropagatesError(t *testing.T) {
	want := errors.New("boom: leave")
	fake := &fakeClusterServicer{leaveErr: want}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterLeave(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("expected leave error, got %v", err)
	}
}

// =============================================================================
// Tests: ClusterStatus
// =============================================================================

func TestClusterStatus_NoServicer(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	_, err := p.ClusterStatus(context.Background(), false)
	if !errors.As(err, new(ErrClusterNotConfigured)) {
		t.Fatalf("expected ErrClusterNotConfigured, got %v", err)
	}
}

func TestClusterStatus_WithoutNodes(t *testing.T) {
	fake := &fakeClusterServicer{
		statusInfo: stockStatus(),
		nodeID:     1,
		leader:     true,
	}
	p := newProviderWithCluster(fake)

	result, err := p.ClusterStatus(context.Background(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.nodeCalls != 0 {
		t.Errorf("Nodes should not be called when include_nodes=false")
	}
	m := result.(map[string]interface{})
	if m["is_leader"] != true {
		t.Errorf("is_leader = %v, want true", m["is_leader"])
	}
	if m["node_id"] != uint64(1) {
		t.Errorf("node_id = %v, want 1", m["node_id"])
	}
	if _, ok := m["nodes"]; ok {
		t.Errorf("nodes should be omitted when include_nodes=false")
	}
	cluster := m["cluster"].(map[string]interface{})
	if cluster["state"] != "healthy" {
		t.Errorf("cluster.state = %v, want healthy", cluster["state"])
	}
}

func TestClusterStatus_WithNodes(t *testing.T) {
	fake := &fakeClusterServicer{
		statusInfo: stockStatus(),
		nodes:      stockNodes(),
		nodeID:     1,
		leader:     true,
	}
	p := newProviderWithCluster(fake)

	result, err := p.ClusterStatus(context.Background(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.nodeCalls != 1 {
		t.Errorf("Nodes call count = %d, want 1", fake.nodeCalls)
	}
	m := result.(map[string]interface{})
	nodes := m["nodes"].([]map[string]interface{})
	if len(nodes) != 2 {
		t.Errorf("nodes len = %d, want 2", len(nodes))
	}
	leader := m["leader"].(map[string]interface{})
	if leader["id"] != uint64(1) {
		t.Errorf("leader.id = %v, want 1", leader["id"])
	}
}

func TestClusterStatus_StatusError(t *testing.T) {
	want := errors.New("boom: status")
	fake := &fakeClusterServicer{statusErr: want}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterStatus(context.Background(), false)
	if !errors.Is(err, want) {
		t.Fatalf("expected status error, got %v", err)
	}
}

func TestClusterStatus_NodesError(t *testing.T) {
	want := errors.New("boom: nodes")
	fake := &fakeClusterServicer{
		statusInfo: stockStatus(),
		nodesErr:   want,
	}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterStatus(context.Background(), true)
	if !errors.Is(err, want) {
		t.Fatalf("expected nodes error, got %v", err)
	}
}

// =============================================================================
// Tests: ClusterListNodes
// =============================================================================

func TestClusterListNodes_NoServicer(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	_, err := p.ClusterListNodes(context.Background())
	if !errors.As(err, new(ErrClusterNotConfigured)) {
		t.Fatalf("expected ErrClusterNotConfigured, got %v", err)
	}
}

func TestClusterListNodes_HappyPath(t *testing.T) {
	fake := &fakeClusterServicer{nodes: stockNodes()}
	p := newProviderWithCluster(fake)

	result, err := p.ClusterListNodes(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["total"] != 2 {
		t.Errorf("total = %v, want 2", m["total"])
	}
	if m["term"] != uint64(5) {
		t.Errorf("term = %v, want 5", m["term"])
	}
	leader := m["leader"].(map[string]interface{})
	if leader["id"] != uint64(1) {
		t.Errorf("leader.id = %v, want 1", leader["id"])
	}
	nodes := m["nodes"].([]map[string]interface{})
	if len(nodes) != 2 {
		t.Errorf("nodes len = %d, want 2", len(nodes))
	}
}

func TestClusterListNodes_NilNodes(t *testing.T) {
	fake := &fakeClusterServicer{nodes: nil}
	p := newProviderWithCluster(fake)

	result, err := p.ClusterListNodes(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.(map[string]interface{})
	if m["total"] != 0 {
		t.Errorf("total = %v, want 0", m["total"])
	}
	if _, ok := m["leader"]; ok {
		t.Errorf("leader should be omitted when nodes is nil")
	}
}

func TestClusterListNodes_PropagatesError(t *testing.T) {
	want := errors.New("boom: list")
	fake := &fakeClusterServicer{nodesErr: want}
	p := newProviderWithCluster(fake)

	_, err := p.ClusterListNodes(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("expected list error, got %v", err)
	}
}

// =============================================================================
// Tests: JSON projection helpers
// =============================================================================

func TestClusterStatusJSON_NilStatus(t *testing.T) {
	got := clusterStatusJSON(nil)
	if got == nil {
		t.Fatal("expected non-nil empty map for nil status")
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestClusterStatusJSON_OmitsEmptyError(t *testing.T) {
	got := clusterStatusJSON(stockStatus())
	if _, ok := got["error_message"]; ok {
		t.Errorf("error_message should be omitted when empty")
	}
}

func TestClusterStatusJSON_IncludesError(t *testing.T) {
	st := stockStatus()
	st.ErrorMessage = "raft: split"
	got := clusterStatusJSON(st)
	if got["error_message"] != "raft: split" {
		t.Errorf("error_message = %v, want raft: split", got["error_message"])
	}
}

func TestClusterNodeJSON_OmitsEmptyOptionals(t *testing.T) {
	n := ClusterNodeInfo{ID: 1, Address: "x:1", State: "healthy"}
	got := clusterNodeJSON(n)
	if _, ok := got["raft_address"]; ok {
		t.Errorf("raft_address should be omitted when empty")
	}
	if _, ok := got["metadata"]; ok {
		t.Errorf("metadata should be omitted when empty")
	}
}

func TestClusterNodeJSON_IncludesOptionals(t *testing.T) {
	n := ClusterNodeInfo{
		ID:          1,
		Address:     "x:1",
		RaftAddress: "x:7000",
		State:       "healthy",
		Metadata:    map[string]string{"k": "v"},
	}
	got := clusterNodeJSON(n)
	if got["raft_address"] != "x:7000" {
		t.Errorf("raft_address = %v, want x:7000", got["raft_address"])
	}
	if got["metadata"] == nil {
		t.Errorf("metadata should be present")
	}
}

func TestClusterNodesJSON_NilReturnsEmptySlice(t *testing.T) {
	got := clusterNodesJSON(nil)
	if got == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(got))
	}
}

func TestClusterNodeCount_Nil(t *testing.T) {
	if got := clusterNodeCount(nil); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestClusterNodeCount_Populated(t *testing.T) {
	if got := clusterNodeCount(stockNodes()); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestClusterBootstrapResultJSON_OmitsEmptyName(t *testing.T) {
	got := clusterBootstrapResultJSON("", 1, stockStatus())
	if _, ok := got["cluster_name"]; ok {
		t.Errorf("cluster_name should be omitted when empty")
	}
}

func TestClusterBootstrapResultJSON_IncludesName(t *testing.T) {
	got := clusterBootstrapResultJSON("alpha", 1, stockStatus())
	if got["cluster_name"] != "alpha" {
		t.Errorf("cluster_name = %v, want alpha", got["cluster_name"])
	}
}

func TestClusterJoinResultJSON_KeepsAddresses(t *testing.T) {
	addrs := []string{"a:1", "b:2"}
	got := clusterJoinResultJSON(2, addrs, stockStatus())
	out := got["seed_addresses"].([]string)
	if len(out) != 2 || out[0] != "a:1" {
		t.Errorf("seed_addresses = %v, want %v", out, addrs)
	}
}

// =============================================================================
// Tests: SetClusterService
// =============================================================================

func TestSetClusterService_InjectsServicer(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	if p.clusterService != nil {
		t.Fatal("expected nil clusterService at construction")
	}
	fake := &fakeClusterServicer{}
	p.SetClusterService(fake)
	if p.clusterService != fake {
		t.Fatalf("clusterService not injected: got %v, want %v", p.clusterService, fake)
	}
}

func TestSetClusterService_AcceptsNil(t *testing.T) {
	fake := &fakeClusterServicer{}
	p := newProviderWithCluster(fake)
	p.SetClusterService(nil)
	if p.clusterService != nil {
		t.Errorf("expected nil after SetClusterService(nil), got %v", p.clusterService)
	}
}

// TestNewMCPServiceProvider_WiresClusterService verifies the constructor
// pulls ClusterService out of the config. Without this wiring, callers
// would have to remember to invoke SetClusterService after construction.
func TestNewMCPServiceProvider_WiresClusterService(t *testing.T) {
	fake := &fakeClusterServicer{}
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{ClusterService: fake})
	if p.clusterService != fake {
		t.Errorf("constructor should wire ClusterService config, got %v", p.clusterService)
	}
}
