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
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewCommand(getFlags)
	if cmd == nil {
		t.Fatal("expected command to be created")
	}

	if cmd.Use != "cluster" {
		t.Errorf("expected Use to be 'cluster', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected Short description to be set")
	}

	if cmd.Long == "" {
		t.Error("expected Long description to be set")
	}

	// Check that all subcommands are registered
	expectedSubcommands := []string{"bootstrap", "join", "leave", "status", "nodes"}
	subcommands := cmd.Commands()

	if len(subcommands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(subcommands))
	}

	subcommandNames := make(map[string]bool)
	for _, sub := range subcommands {
		subcommandNames[sub.Use] = true
	}

	for _, expected := range expectedSubcommands {
		if !subcommandNames[expected] {
			t.Errorf("expected subcommand %q to be registered", expected)
		}
	}
}

func TestNewBootstrapCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewBootstrapCommand(getFlags)
	if cmd == nil {
		t.Fatal("expected command to be created")
	}

	if cmd.Use != "bootstrap" {
		t.Errorf("expected Use to be 'bootstrap', got %q", cmd.Use)
	}

	// Check required flags exist
	nodeIDFlag := cmd.Flags().Lookup("node-id")
	if nodeIDFlag == nil {
		t.Error("expected node-id flag to be defined")
	}

	listenAddrFlag := cmd.Flags().Lookup("listen-addr")
	if listenAddrFlag == nil {
		t.Error("expected listen-addr flag to be defined")
	}

	advertiseAddrFlag := cmd.Flags().Lookup("advertise-addr")
	if advertiseAddrFlag == nil {
		t.Error("expected advertise-addr flag to be defined")
	}

	dataDirFlag := cmd.Flags().Lookup("data-dir")
	if dataDirFlag == nil {
		t.Error("expected data-dir flag to be defined")
	}
}

func TestNewJoinCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewJoinCommand(getFlags)
	if cmd == nil {
		t.Fatal("expected command to be created")
	}

	if cmd.Use != "join" {
		t.Errorf("expected Use to be 'join', got %q", cmd.Use)
	}

	// Check required flags exist
	nodeIDFlag := cmd.Flags().Lookup("node-id")
	if nodeIDFlag == nil {
		t.Error("expected node-id flag to be defined")
	}

	listenAddrFlag := cmd.Flags().Lookup("listen-addr")
	if listenAddrFlag == nil {
		t.Error("expected listen-addr flag to be defined")
	}

	joinFlag := cmd.Flags().Lookup("join")
	if joinFlag == nil {
		t.Error("expected join flag to be defined")
	}

	advertiseAddrFlag := cmd.Flags().Lookup("advertise-addr")
	if advertiseAddrFlag == nil {
		t.Error("expected advertise-addr flag to be defined")
	}
}

func TestNewLeaveCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewLeaveCommand(getFlags)
	if cmd == nil {
		t.Fatal("expected command to be created")
	}

	if cmd.Use != "leave" {
		t.Errorf("expected Use to be 'leave', got %q", cmd.Use)
	}

	// Check force flag exists
	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Error("expected force flag to be defined")
	}
}

func TestNewStatusCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewStatusCommand(getFlags)
	if cmd == nil {
		t.Fatal("expected command to be created")
	}

	if cmd.Use != "status" {
		t.Errorf("expected Use to be 'status', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected Short description to be set")
	}

	if cmd.Long == "" {
		t.Error("expected Long description to be set")
	}
}

func TestNewNodesCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewNodesCommand(getFlags)
	if cmd == nil {
		t.Fatal("expected command to be created")
	}

	if cmd.Use != "nodes" {
		t.Errorf("expected Use to be 'nodes', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected Short description to be set")
	}

	if cmd.Long == "" {
		t.Error("expected Long description to be set")
	}
}

func TestBootstrapValidation_MissingNodeID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	// Test with empty node ID
	err := runBootstrapValidation("", "10.0.0.1:7946", "", "")
	if err == nil {
		t.Error("expected error for missing node ID")
	}
	if _, ok := err.(ErrMissingNodeID); !ok {
		t.Errorf("expected ErrMissingNodeID, got %T", err)
	}

	_ = flags // suppress unused variable warning
}

func TestBootstrapValidation_MissingListenAddr(t *testing.T) {
	err := runBootstrapValidation("node-1", "", "", "")
	if err == nil {
		t.Error("expected error for missing listen address")
	}
	if _, ok := err.(ErrMissingListenAddr); !ok {
		t.Errorf("expected ErrMissingListenAddr, got %T", err)
	}
}

func TestBootstrapValidation_InvalidListenAddr(t *testing.T) {
	err := runBootstrapValidation("node-1", "invalid-address", "", "")
	if err == nil {
		t.Error("expected error for invalid listen address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}

func TestBootstrapValidation_InvalidAdvertiseAddr(t *testing.T) {
	err := runBootstrapValidation("node-1", "10.0.0.1:7946", "invalid", "")
	if err == nil {
		t.Error("expected error for invalid advertise address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}

func TestBootstrapValidation_Valid(t *testing.T) {
	err := runBootstrapValidation("node-1", "10.0.0.1:7946", "", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestJoinValidation_MissingNodeID(t *testing.T) {
	err := runJoinValidation("", "10.0.0.1:7946", "", "10.0.0.2:7946")
	if err == nil {
		t.Error("expected error for missing node ID")
	}
	if _, ok := err.(ErrMissingNodeID); !ok {
		t.Errorf("expected ErrMissingNodeID, got %T", err)
	}
}

func TestJoinValidation_MissingListenAddr(t *testing.T) {
	err := runJoinValidation("node-1", "", "", "10.0.0.2:7946")
	if err == nil {
		t.Error("expected error for missing listen address")
	}
	if _, ok := err.(ErrMissingListenAddr); !ok {
		t.Errorf("expected ErrMissingListenAddr, got %T", err)
	}
}

func TestJoinValidation_MissingJoinAddrs(t *testing.T) {
	err := runJoinValidation("node-1", "10.0.0.1:7946", "", "")
	if err == nil {
		t.Error("expected error for missing join addresses")
	}
	if _, ok := err.(ErrMissingJoinAddrs); !ok {
		t.Errorf("expected ErrMissingJoinAddrs, got %T", err)
	}
}

func TestJoinValidation_InvalidListenAddr(t *testing.T) {
	err := runJoinValidation("node-1", "invalid", "", "10.0.0.2:7946")
	if err == nil {
		t.Error("expected error for invalid listen address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}

func TestJoinValidation_InvalidJoinAddr(t *testing.T) {
	err := runJoinValidation("node-1", "10.0.0.1:7946", "", "invalid")
	if err == nil {
		t.Error("expected error for invalid join address")
	}
	if _, ok := err.(ErrInvalidJoinAddr); !ok {
		t.Errorf("expected ErrInvalidJoinAddr, got %T", err)
	}
}

func TestJoinValidation_Valid(t *testing.T) {
	err := runJoinValidation("node-1", "10.0.0.1:7946", "", "10.0.0.2:7946,10.0.0.3:7946")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// runBootstrapValidation performs validation only (no gRPC call)
func runBootstrapValidation(nodeID, listenAddr, advertiseAddr, dataDir string) error {
	if nodeID == "" {
		return ErrMissingNodeID{}
	}
	if listenAddr == "" {
		return ErrMissingListenAddr{}
	}
	if err := validateAddress(listenAddr); err != nil {
		return ErrInvalidListenAddr{Addr: listenAddr, Reason: err.Error()}
	}
	if advertiseAddr != "" {
		if err := validateAddress(advertiseAddr); err != nil {
			return ErrInvalidListenAddr{Addr: advertiseAddr, Reason: err.Error()}
		}
	}
	return nil
}

// runJoinValidation performs validation only (no gRPC call)
func runJoinValidation(nodeID, listenAddr, advertiseAddr, joinAddrs string) error {
	if nodeID == "" {
		return ErrMissingNodeID{}
	}
	if listenAddr == "" {
		return ErrMissingListenAddr{}
	}
	if joinAddrs == "" {
		return ErrMissingJoinAddrs{}
	}
	if err := validateAddress(listenAddr); err != nil {
		return ErrInvalidListenAddr{Addr: listenAddr, Reason: err.Error()}
	}
	if advertiseAddr != "" {
		if err := validateAddress(advertiseAddr); err != nil {
			return ErrInvalidListenAddr{Addr: advertiseAddr, Reason: err.Error()}
		}
	}
	addrs := parseAddressList(joinAddrs)
	if len(addrs) == 0 {
		return ErrMissingJoinAddrs{}
	}
	if err := validateAddressList(addrs); err != nil {
		return err
	}
	return nil
}

func TestBootstrapResult_Success(t *testing.T) {
	result := &BootstrapResult{
		ClusterID:  "cluster-123",
		NodeID:     "node-1",
		ListenAddr: "10.0.0.1:7946",
		DataDir:    "/var/lib/raft",
		Success:    true,
		Message:    "Cluster bootstrap initiated successfully",
	}

	if result.ClusterID != "cluster-123" {
		t.Errorf("expected ClusterID to be 'cluster-123', got %q", result.ClusterID)
	}
	if result.NodeID != "node-1" {
		t.Errorf("expected NodeID to be 'node-1', got %q", result.NodeID)
	}
	if !result.Success {
		t.Error("expected Success to be true")
	}
}

func TestBootstrapResult_Failure(t *testing.T) {
	result := &BootstrapResult{
		ClusterID:  "",
		NodeID:     "node-1",
		ListenAddr: "10.0.0.1:7946",
		Success:    false,
		Message:    "Failed to bootstrap cluster",
	}

	if result.Success {
		t.Error("expected Success to be false")
	}
	if result.Message == "" {
		t.Error("expected Message to be set")
	}
}

func TestJoinResult_Success(t *testing.T) {
	result := &JoinResult{
		NodeID:     "node-2",
		ClusterID:  "cluster-123",
		LeaderID:   "node-1",
		LeaderAddr: "10.0.0.1:7946",
		JoinedFrom: []string{"10.0.0.1:7946", "10.0.0.3:7946"},
		Success:    true,
		Message:    "Successfully joined cluster",
	}

	if result.NodeID != "node-2" {
		t.Errorf("expected NodeID to be 'node-2', got %q", result.NodeID)
	}
	if len(result.JoinedFrom) != 2 {
		t.Errorf("expected 2 seed nodes, got %d", len(result.JoinedFrom))
	}
	if !result.Success {
		t.Error("expected Success to be true")
	}
}

func TestJoinResult_Failure(t *testing.T) {
	result := &JoinResult{
		NodeID:  "node-2",
		Success: false,
		Message: "Failed to join cluster: connection refused",
	}

	if result.Success {
		t.Error("expected Success to be false")
	}
	if result.ClusterID != "" {
		t.Error("expected ClusterID to be empty on failure")
	}
}

func TestLeaveResult_GracefulLeave(t *testing.T) {
	result := &LeaveResult{
		NodeID:  "node-2",
		Force:   false,
		Success: true,
		Message: "Successfully left cluster",
	}

	if result.Force {
		t.Error("expected Force to be false")
	}
	if !result.Success {
		t.Error("expected Success to be true")
	}
}

func TestLeaveResult_ForceLeave(t *testing.T) {
	result := &LeaveResult{
		NodeID:  "node-2",
		Force:   true,
		Success: true,
		Message: "Force left cluster (immediate)",
	}

	if !result.Force {
		t.Error("expected Force to be true")
	}
	if !result.Success {
		t.Error("expected Success to be true")
	}
}

func TestClusterStatusSummary_Healthy(t *testing.T) {
	status := &ClusterStatusSummary{
		ClusterID:    "cluster-123",
		NodeID:       "node-1",
		RaftState:    string(RaftStateLeader),
		LeaderID:     "node-1",
		LeaderAddr:   "10.0.0.1:7946",
		Term:         42,
		CommitIndex:  1234,
		AppliedIndex: 1234,
		NodeCount:    3,
		VoterCount:   3,
		Healthy:      true,
		Timestamp:    "2025-01-15T10:30:00Z",
	}

	if !status.Healthy {
		t.Error("expected Healthy to be true")
	}
	if status.RaftState != string(RaftStateLeader) {
		t.Errorf("expected RaftState to be 'leader', got %q", status.RaftState)
	}
	if status.Term != 42 {
		t.Errorf("expected Term to be 42, got %d", status.Term)
	}
	if status.CommitIndex != status.AppliedIndex {
		t.Error("expected CommitIndex to equal AppliedIndex for healthy cluster")
	}
}

func TestClusterStatusSummary_Degraded(t *testing.T) {
	status := &ClusterStatusSummary{
		ClusterID:    "cluster-123",
		NodeID:       "node-2",
		RaftState:    string(RaftStateFollower),
		LeaderID:     "",
		LeaderAddr:   "",
		Term:         43,
		CommitIndex:  1234,
		AppliedIndex: 1230,
		NodeCount:    2,
		VoterCount:   3,
		Healthy:      false,
		Timestamp:    "2025-01-15T10:30:00Z",
	}

	if status.Healthy {
		t.Error("expected Healthy to be false")
	}
	if status.LeaderID != "" {
		t.Error("expected no leader in degraded cluster")
	}
}

func TestNodeInfo_LeaderNode(t *testing.T) {
	node := &NodeInfo{
		NodeID:    "node-1",
		Address:   "10.0.0.1:7946",
		State:     string(NodeStateAlive),
		RaftState: string(RaftStateLeader),
		IsVoter:   true,
		IsLeader:  true,
		LastSeen:  "2025-01-15T10:30:00Z",
		Uptime:    "3d5h",
	}

	if !node.IsLeader {
		t.Error("expected IsLeader to be true")
	}
	if !node.IsVoter {
		t.Error("expected IsVoter to be true")
	}
	if node.RaftState != string(RaftStateLeader) {
		t.Errorf("expected RaftState to be 'leader', got %q", node.RaftState)
	}
}

func TestNodeInfo_FollowerNode(t *testing.T) {
	node := &NodeInfo{
		NodeID:    "node-2",
		Address:   "10.0.0.2:7946",
		State:     string(NodeStateAlive),
		RaftState: string(RaftStateFollower),
		IsVoter:   true,
		IsLeader:  false,
		LastSeen:  "2025-01-15T10:30:00Z",
		Uptime:    "2d10h",
	}

	if node.IsLeader {
		t.Error("expected IsLeader to be false")
	}
	if node.RaftState != string(RaftStateFollower) {
		t.Errorf("expected RaftState to be 'follower', got %q", node.RaftState)
	}
}

func TestNodeInfo_NonVoterNode(t *testing.T) {
	node := &NodeInfo{
		NodeID:    "node-4",
		Address:   "10.0.0.4:7946",
		State:     string(NodeStateAlive),
		RaftState: string(RaftStateFollower),
		IsVoter:   false,
		IsLeader:  false,
		LastSeen:  "2025-01-15T10:30:00Z",
		Uptime:    "1h",
	}

	if node.IsVoter {
		t.Error("expected IsVoter to be false")
	}
}

func TestNodeInfo_DeadNode(t *testing.T) {
	node := &NodeInfo{
		NodeID:    "node-3",
		Address:   "10.0.0.3:7946",
		State:     string(NodeStateDead),
		RaftState: string(RaftStateUnknown),
		IsVoter:   true,
		IsLeader:  false,
		LastSeen:  "2025-01-15T09:30:00Z",
		Uptime:    "N/A",
	}

	if node.State != string(NodeStateDead) {
		t.Errorf("expected State to be 'dead', got %q", node.State)
	}
	if node.RaftState != string(RaftStateUnknown) {
		t.Errorf("expected RaftState to be 'unknown', got %q", node.RaftState)
	}
}

func TestNodeListResponse(t *testing.T) {
	nodes := []*NodeInfo{
		{NodeID: "node-1", IsLeader: true, IsVoter: true},
		{NodeID: "node-2", IsLeader: false, IsVoter: true},
		{NodeID: "node-3", IsLeader: false, IsVoter: true},
	}

	response := &NodeListResponse{
		Nodes:      nodes,
		TotalCount: 3,
		VoterCount: 3,
		LeaderID:   "node-1",
	}

	if response.TotalCount != 3 {
		t.Errorf("expected TotalCount to be 3, got %d", response.TotalCount)
	}
	if response.VoterCount != 3 {
		t.Errorf("expected VoterCount to be 3, got %d", response.VoterCount)
	}
	if response.LeaderID != "node-1" {
		t.Errorf("expected LeaderID to be 'node-1', got %q", response.LeaderID)
	}
	if len(response.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(response.Nodes))
	}
}

func TestNodeListResponse_EmptyCluster(t *testing.T) {
	response := &NodeListResponse{
		Nodes:      []*NodeInfo{},
		TotalCount: 0,
		VoterCount: 0,
		LeaderID:   "",
	}

	if response.TotalCount != 0 {
		t.Errorf("expected TotalCount to be 0, got %d", response.TotalCount)
	}
	if response.LeaderID != "" {
		t.Error("expected LeaderID to be empty")
	}
	if len(response.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(response.Nodes))
	}
}

func TestRaftStateConstants(t *testing.T) {
	tests := []struct {
		state    RaftState
		expected string
	}{
		{RaftStateFollower, "follower"},
		{RaftStateCandidate, "candidate"},
		{RaftStateLeader, "leader"},
		{RaftStateShutdown, "shutdown"},
		{RaftStateUnknown, "unknown"},
	}

	for _, tc := range tests {
		if string(tc.state) != tc.expected {
			t.Errorf("expected RaftState %q, got %q", tc.expected, string(tc.state))
		}
	}
}

func TestNodeStateConstants(t *testing.T) {
	tests := []struct {
		state    NodeState
		expected string
	}{
		{NodeStateAlive, "alive"},
		{NodeStateSuspect, "suspect"},
		{NodeStateDead, "dead"},
		{NodeStateLeft, "left"},
		{NodeStateUnknown, "unknown"},
	}

	for _, tc := range tests {
		if string(tc.state) != tc.expected {
			t.Errorf("expected NodeState %q, got %q", tc.expected, string(tc.state))
		}
	}

}

// mockClusterService implements ClusterServiceServer for testing
type mockClusterService struct {
	platformv1.UnimplementedClusterServiceServer
}

// Bootstrap implements the Bootstrap RPC
func (m *mockClusterService) Bootstrap(ctx context.Context, req *platformv1.BootstrapClusterRequest) (*platformv1.BootstrapClusterResponse, error) {
	return &platformv1.BootstrapClusterResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Cluster bootstrap initiated successfully",
		},
		Cluster: &platformv1.ClusterInfo{
			Id:            "cluster-test-123",
			Name:          req.GetClusterName(),
			State:         platformv1.ClusterState_CLUSTER_STATE_HEALTHY,
			LeaderId:      req.GetNodeName(),
			LeaderAddress: req.GetAdvertiseAddress(),
			TotalNodes:    1,
			HealthyNodes:  1,
			Term:          1,
			CreatedAt:     timestamppb.Now(),
		},
		Node: &platformv1.ClusterNode{
			Id:      req.GetNodeName(),
			Name:    req.GetNodeName(),
			Address: req.GetAdvertiseAddress(),
			Port:    req.GetAdvertisePort(),
			Role:    platformv1.NodeRole_NODE_ROLE_LEADER,
			State:   platformv1.NodeState_NODE_STATE_ACTIVE,
			Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		},
	}, nil
}

// Join implements the Join RPC
func (m *mockClusterService) Join(ctx context.Context, req *platformv1.JoinClusterRequest) (*platformv1.JoinClusterResponse, error) {
	return &platformv1.JoinClusterResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Successfully joined cluster",
		},
		Cluster: &platformv1.ClusterInfo{
			Id:            "cluster-test-123",
			Name:          "test-cluster",
			State:         platformv1.ClusterState_CLUSTER_STATE_HEALTHY,
			LeaderId:      "leader-1",
			LeaderAddress: "10.0.0.1",
			TotalNodes:    2,
			HealthyNodes:  2,
			Term:          1,
		},
		Node: &platformv1.ClusterNode{
			Id:      req.GetNodeName(),
			Name:    req.GetNodeName(),
			Address: req.GetAdvertiseAddress(),
			Port:    req.GetAdvertisePort(),
			Role:    platformv1.NodeRole_NODE_ROLE_FOLLOWER,
			State:   platformv1.NodeState_NODE_STATE_ACTIVE,
			Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		},
	}, nil
}

// Leave implements the Leave RPC
func (m *mockClusterService) Leave(ctx context.Context, req *platformv1.LeaveClusterRequest) (*platformv1.LeaveClusterResponse, error) {
	msg := "Successfully left cluster"
	if req.GetForce() {
		msg = "Force left cluster (immediate)"
	}
	return &platformv1.LeaveClusterResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: msg,
		},
	}, nil
}

// GetStatus implements the GetStatus RPC
func (m *mockClusterService) GetStatus(ctx context.Context, req *platformv1.GetClusterStatusRequest) (*platformv1.GetClusterStatusResponse, error) {
	now := timestamppb.Now()
	return &platformv1.GetClusterStatusResponse{
		Cluster: &platformv1.ClusterInfo{
			Id:            "cluster-test-123",
			Name:          "test-cluster",
			State:         platformv1.ClusterState_CLUSTER_STATE_HEALTHY,
			LeaderId:      "node-1",
			LeaderAddress: "10.0.0.1",
			TotalNodes:    3,
			HealthyNodes:  3,
			Term:          42,
		},
		LocalNode: &platformv1.ClusterNode{
			Id:            "node-1",
			Name:          "node-1",
			Address:       "10.0.0.1",
			Port:          7946,
			Role:          platformv1.NodeRole_NODE_ROLE_LEADER,
			State:         platformv1.NodeState_NODE_STATE_ACTIVE,
			Health:        platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			LastHeartbeat: now,
		},
		Timestamp: now,
	}, nil
}

// ListNodes implements the ListNodes RPC
func (m *mockClusterService) ListNodes(ctx context.Context, req *platformv1.ListClusterNodesRequest) (*platformv1.ListClusterNodesResponse, error) {
	now := timestamppb.Now()
	return &platformv1.ListClusterNodesResponse{
		Nodes: []*platformv1.ClusterNode{
			{
				Id:            "node-1",
				Name:          "node-1",
				Address:       "10.0.0.1",
				Port:          7946,
				Role:          platformv1.NodeRole_NODE_ROLE_LEADER,
				State:         platformv1.NodeState_NODE_STATE_ACTIVE,
				Health:        platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
				JoinedAt:      timestamppb.New(time.Now().Add(-72 * time.Hour)),
				LastHeartbeat: now,
			},
			{
				Id:            "node-2",
				Name:          "node-2",
				Address:       "10.0.0.2",
				Port:          7946,
				Role:          platformv1.NodeRole_NODE_ROLE_FOLLOWER,
				State:         platformv1.NodeState_NODE_STATE_ACTIVE,
				Health:        platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
				JoinedAt:      timestamppb.New(time.Now().Add(-48 * time.Hour)),
				LastHeartbeat: now,
			},
			{
				Id:            "node-3",
				Name:          "node-3",
				Address:       "10.0.0.3",
				Port:          7946,
				Role:          platformv1.NodeRole_NODE_ROLE_FOLLOWER,
				State:         platformv1.NodeState_NODE_STATE_ACTIVE,
				Health:        platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
				JoinedAt:      timestamppb.New(time.Now().Add(-24 * time.Hour)),
				LastHeartbeat: now,
			},
		},
		Total: 3,
	}, nil
}

// startTestGRPCServer starts a gRPC server on a Unix socket for testing
func startTestGRPCServer(t *testing.T, socketPath string) (*grpc.Server, func()) {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on Unix socket: %v", err)
	}

	server := grpc.NewServer()

	// Register the mock ClusterService
	platformv1.RegisterClusterServiceServer(server, &mockClusterService{})

	go func() {
		if err := server.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Logf("gRPC server error: %v", err)
		}
	}()

	// Give the server time to start
	time.Sleep(10 * time.Millisecond)

	cleanup := func() {
		server.GracefulStop()
		listener.Close()
	}

	return server, cleanup
}

// setupTestServer creates a test gRPC server for testing run* functions
func setupTestServer(t *testing.T) (string, *grpc.Server, func()) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	server, cleanup := startTestGRPCServer(t, socketPath)

	return socketPath, server, cleanup
}

// createTestFlags creates test flags with a working context
func createTestFlags(socketPath string, format cli.OutputFormat) *cli.CommonFlags {
	testCtx := &cli.Context{
		Name: "test",
		Type: cli.ContextTypeLocal,
		Local: &cli.LocalContext{
			SocketPath: socketPath,
		},
	}

	return &cli.CommonFlags{
		OutputFormat: format,
		NoColor:      true,
		GetConfig: func() (*cli.Config, error) {
			return cli.DefaultConfig(), nil
		},
		GetContext: func() (*cli.Context, error) {
			return testCtx, nil
		},
	}
}

// Test runBootstrap with valid inputs
func TestRunBootstrap_TableOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runBootstrap(flags, "node-1", "10.0.0.1:7946", "", "/var/lib/raft")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunBootstrap_JSONOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatJSON)

	err := runBootstrap(flags, "node-1", "10.0.0.1:7946", "", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunBootstrap_YAMLOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatYAML)

	err := runBootstrap(flags, "node-1", "10.0.0.1:7946", "10.0.0.1:7946", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunBootstrap_InvalidOutputFormat(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormat("invalid"))

	err := runBootstrap(flags, "node-1", "10.0.0.1:7946", "", "")
	if err == nil {
		t.Error("expected error for invalid output format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestRunBootstrap_MissingNodeID(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runBootstrap(flags, "", "10.0.0.1:7946", "", "")
	if err == nil {
		t.Error("expected error for missing node ID")
	}
	if _, ok := err.(ErrMissingNodeID); !ok {
		t.Errorf("expected ErrMissingNodeID, got %T", err)
	}
}

func TestRunBootstrap_MissingListenAddr(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runBootstrap(flags, "node-1", "", "", "")
	if err == nil {
		t.Error("expected error for missing listen address")
	}
	if _, ok := err.(ErrMissingListenAddr); !ok {
		t.Errorf("expected ErrMissingListenAddr, got %T", err)
	}
}

func TestRunBootstrap_InvalidListenAddr(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runBootstrap(flags, "node-1", "invalid", "", "")
	if err == nil {
		t.Error("expected error for invalid listen address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}

func TestRunBootstrap_InvalidAdvertiseAddr(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runBootstrap(flags, "node-1", "10.0.0.1:7946", "invalid", "")
	if err == nil {
		t.Error("expected error for invalid advertise address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}

func TestRunBootstrap_ContextError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
		GetConfig: func() (*cli.Config, error) {
			return cli.DefaultConfig(), nil
		},
		GetContext: func() (*cli.Context, error) {
			return nil, cli.ErrContextNotFound{Context: "nonexistent"}
		},
	}

	err := runBootstrap(flags, "node-1", "10.0.0.1:7946", "", "")
	if err == nil {
		t.Error("expected error for context failure")
	}
}

// Test runJoin
func TestRunJoin_TableOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", "10.0.0.1:7946")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunJoin_JSONOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatJSON)

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", "10.0.0.1:7946,10.0.0.3:7946")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunJoin_YAMLOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatYAML)

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "10.0.0.2:7946", "10.0.0.1:7946")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunJoin_InvalidOutputFormat(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormat("invalid"))

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", "10.0.0.1:7946")
	if err == nil {
		t.Error("expected error for invalid output format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestRunJoin_MissingNodeID(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "", "10.0.0.2:7946", "", "10.0.0.1:7946")
	if err == nil {
		t.Error("expected error for missing node ID")
	}
	if _, ok := err.(ErrMissingNodeID); !ok {
		t.Errorf("expected ErrMissingNodeID, got %T", err)
	}
}

func TestRunJoin_MissingListenAddr(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "node-2", "", "", "10.0.0.1:7946")
	if err == nil {
		t.Error("expected error for missing listen address")
	}
	if _, ok := err.(ErrMissingListenAddr); !ok {
		t.Errorf("expected ErrMissingListenAddr, got %T", err)
	}
}

func TestRunJoin_MissingJoinAddrs(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", "")
	if err == nil {
		t.Error("expected error for missing join addresses")
	}
	if _, ok := err.(ErrMissingJoinAddrs); !ok {
		t.Errorf("expected ErrMissingJoinAddrs, got %T", err)
	}
}

func TestRunJoin_InvalidListenAddr(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "node-2", "invalid", "", "10.0.0.1:7946")
	if err == nil {
		t.Error("expected error for invalid listen address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}

func TestRunJoin_InvalidAdvertiseAddr(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "invalid", "10.0.0.1:7946")
	if err == nil {
		t.Error("expected error for invalid advertise address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}

func TestRunJoin_InvalidJoinAddr(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", "invalid")
	if err == nil {
		t.Error("expected error for invalid join address")
	}
	if _, ok := err.(ErrInvalidJoinAddr); !ok {
		t.Errorf("expected ErrInvalidJoinAddr, got %T", err)
	}
}

func TestRunJoin_EmptyJoinAddrsList(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", ",,,")
	if err == nil {
		t.Error("expected error for empty join addresses list")
	}
	if _, ok := err.(ErrMissingJoinAddrs); !ok {
		t.Errorf("expected ErrMissingJoinAddrs, got %T", err)
	}
}

func TestRunJoin_ContextError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
		GetConfig: func() (*cli.Config, error) {
			return cli.DefaultConfig(), nil
		},
		GetContext: func() (*cli.Context, error) {
			return nil, cli.ErrContextNotFound{Context: "nonexistent"}
		},
	}

	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", "10.0.0.1:7946")
	if err == nil {
		t.Error("expected error for context failure")
	}
}

// Test runLeave
func TestRunLeave_TableOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runLeave(flags, "", false, 30)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunLeave_ForceLeave(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runLeave(flags, "", true, 30)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunLeave_JSONOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatJSON)

	err := runLeave(flags, "", false, 30)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunLeave_YAMLOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatYAML)

	err := runLeave(flags, "", false, 30)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunLeave_InvalidOutputFormat(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormat("invalid"))

	err := runLeave(flags, "", false, 30)
	if err == nil {
		t.Error("expected error for invalid output format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestRunLeave_ContextError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
		GetConfig: func() (*cli.Config, error) {
			return cli.DefaultConfig(), nil
		},
		GetContext: func() (*cli.Context, error) {
			return nil, cli.ErrContextNotFound{Context: "nonexistent"}
		},
	}

	err := runLeave(flags, "", false, 30)
	if err == nil {
		t.Error("expected error for context failure")
	}
}

// Test runStatus
func TestRunStatus_TableOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runStatus(flags, false)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunStatus_JSONOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatJSON)

	err := runStatus(flags, false)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunStatus_YAMLOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatYAML)

	err := runStatus(flags, false)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunStatus_InvalidOutputFormat(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormat("invalid"))

	err := runStatus(flags, false)
	if err == nil {
		t.Error("expected error for invalid output format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestRunStatus_ContextError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
		GetConfig: func() (*cli.Config, error) {
			return cli.DefaultConfig(), nil
		},
		GetContext: func() (*cli.Context, error) {
			return nil, cli.ErrContextNotFound{Context: "nonexistent"}
		},
	}

	err := runStatus(flags, false)
	if err == nil {
		t.Error("expected error for context failure")
	}
}

// Test runNodes
func TestRunNodes_TableOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	err := runNodes(flags)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunNodes_JSONOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatJSON)

	err := runNodes(flags)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunNodes_YAMLOutput(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatYAML)

	err := runNodes(flags)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunNodes_InvalidOutputFormat(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormat("invalid"))

	err := runNodes(flags)
	if err == nil {
		t.Error("expected error for invalid output format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestRunNodes_ContextError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
		GetConfig: func() (*cli.Config, error) {
			return cli.DefaultConfig(), nil
		},
		GetContext: func() (*cli.Context, error) {
			return nil, cli.ErrContextNotFound{Context: "nonexistent"}
		},
	}

	err := runNodes(flags)
	if err == nil {
		t.Error("expected error for context failure")
	}
}

// Test print functions with success and failure results
func TestPrintBootstrapResult_Success(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &BootstrapResult{
		ClusterID:  "cluster-123",
		NodeID:     "node-1",
		ListenAddr: "10.0.0.1:7946",
		DataDir:    "/var/lib/raft",
		Success:    true,
		Message:    "Cluster bootstrap initiated successfully",
	}

	err := printBootstrapResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintBootstrapResult_Failure(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &BootstrapResult{
		ClusterID:  "",
		NodeID:     "node-1",
		ListenAddr: "10.0.0.1:7946",
		DataDir:    "",
		Success:    false,
		Message:    "Bootstrap failed: already bootstrapped",
	}

	err := printBootstrapResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintBootstrapResult_WithDataDir(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &BootstrapResult{
		ClusterID:  "cluster-123",
		NodeID:     "node-1",
		ListenAddr: "10.0.0.1:7946",
		DataDir:    "/var/lib/raft",
		Success:    true,
		Message:    "Cluster bootstrap initiated successfully",
	}

	err := printBootstrapResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintBootstrapResult_WithoutDataDir(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &BootstrapResult{
		ClusterID:  "cluster-123",
		NodeID:     "node-1",
		ListenAddr: "10.0.0.1:7946",
		DataDir:    "",
		Success:    true,
		Message:    "Cluster bootstrap initiated successfully",
	}

	err := printBootstrapResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintJoinResult_Success(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &JoinResult{
		NodeID:     "node-2",
		ClusterID:  "cluster-123",
		LeaderID:   "node-1",
		LeaderAddr: "10.0.0.1:7946",
		JoinedFrom: []string{"10.0.0.1:7946", "10.0.0.3:7946"},
		Success:    true,
		Message:    "Successfully joined cluster",
	}

	err := printJoinResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintJoinResult_Failure(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &JoinResult{
		NodeID:     "node-2",
		ClusterID:  "",
		LeaderID:   "",
		LeaderAddr: "",
		JoinedFrom: nil,
		Success:    false,
		Message:    "Failed to join cluster: connection refused",
	}

	err := printJoinResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintJoinResult_SingleSeedNode(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &JoinResult{
		NodeID:     "node-2",
		ClusterID:  "cluster-123",
		LeaderID:   "node-1",
		LeaderAddr: "10.0.0.1:7946",
		JoinedFrom: []string{"10.0.0.1:7946"},
		Success:    true,
		Message:    "Successfully joined cluster",
	}

	err := printJoinResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintJoinResult_NoSeedNodes(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &JoinResult{
		NodeID:     "node-2",
		ClusterID:  "cluster-123",
		LeaderID:   "node-1",
		LeaderAddr: "10.0.0.1:7946",
		JoinedFrom: nil,
		Success:    true,
		Message:    "Successfully joined cluster",
	}

	err := printJoinResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintJoinResult_MultipleSeedNodes(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &JoinResult{
		NodeID:     "node-4",
		ClusterID:  "cluster-123",
		LeaderID:   "node-1",
		LeaderAddr: "10.0.0.1:7946",
		JoinedFrom: []string{"10.0.0.1:7946", "10.0.0.2:7946", "10.0.0.3:7946"},
		Success:    true,
		Message:    "Successfully joined cluster",
	}

	err := printJoinResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintLeaveResult_Success(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &LeaveResult{
		NodeID:  "node-2",
		Force:   false,
		Success: true,
		Message: "Successfully left cluster",
	}

	err := printLeaveResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintLeaveResult_Failure(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &LeaveResult{
		NodeID:  "node-2",
		Force:   false,
		Success: false,
		Message: "Failed to leave cluster: node not in cluster",
	}

	err := printLeaveResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintLeaveResult_ForceLeave(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	result := &LeaveResult{
		NodeID:  "node-2",
		Force:   true,
		Success: true,
		Message: "Force left cluster (immediate)",
	}

	err := printLeaveResult(printer, result)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintClusterStatus_Healthy(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	status := &ClusterStatusSummary{
		ClusterID:    "cluster-123",
		NodeID:       "node-1",
		RaftState:    string(RaftStateLeader),
		LeaderID:     "node-1",
		LeaderAddr:   "10.0.0.1:7946",
		Term:         42,
		CommitIndex:  1234,
		AppliedIndex: 1234,
		LastContact:  "2025-01-15T10:30:00Z",
		NodeCount:    3,
		VoterCount:   3,
		Healthy:      true,
		Timestamp:    "2025-01-15T10:30:00Z",
	}

	err := printClusterStatus(printer, status)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintClusterStatus_Unhealthy(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	status := &ClusterStatusSummary{
		ClusterID:    "cluster-123",
		NodeID:       "node-2",
		RaftState:    string(RaftStateFollower),
		LeaderID:     "",
		LeaderAddr:   "",
		Term:         43,
		CommitIndex:  1234,
		AppliedIndex: 1230,
		LastContact:  "N/A",
		NodeCount:    2,
		VoterCount:   3,
		Healthy:      false,
		Timestamp:    "2025-01-15T10:30:00Z",
	}

	err := printClusterStatus(printer, status)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_WithNodes(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes: []*NodeInfo{
			{
				NodeID:    "node-1",
				Address:   "10.0.0.1:7946",
				State:     string(NodeStateAlive),
				RaftState: string(RaftStateLeader),
				IsVoter:   true,
				IsLeader:  true,
				Uptime:    "3d5h",
			},
			{
				NodeID:    "node-2",
				Address:   "10.0.0.2:7946",
				State:     string(NodeStateAlive),
				RaftState: string(RaftStateFollower),
				IsVoter:   true,
				IsLeader:  false,
				Uptime:    "2d10h",
			},
		},
		TotalCount: 2,
		VoterCount: 2,
		LeaderID:   "node-1",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_EmptyCluster(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes:      []*NodeInfo{},
		TotalCount: 0,
		VoterCount: 0,
		LeaderID:   "",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_NilNodes(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes:      nil,
		TotalCount: 0,
		VoterCount: 0,
		LeaderID:   "",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_LongNodeID(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes: []*NodeInfo{
			{
				NodeID:    "550e8400-e29b-41d4-a716-446655440000",
				Address:   "10.0.0.1:7946",
				State:     string(NodeStateAlive),
				RaftState: string(RaftStateLeader),
				IsVoter:   true,
				IsLeader:  true,
				Uptime:    "3d5h",
			},
		},
		TotalCount: 1,
		VoterCount: 1,
		LeaderID:   "550e8400-e29b-41d4-a716-446655440000",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_NonVoterNode(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes: []*NodeInfo{
			{
				NodeID:    "node-1",
				Address:   "10.0.0.1:7946",
				State:     string(NodeStateAlive),
				RaftState: string(RaftStateLeader),
				IsVoter:   true,
				IsLeader:  true,
				Uptime:    "3d5h",
			},
			{
				NodeID:    "node-observer",
				Address:   "10.0.0.4:7946",
				State:     string(NodeStateAlive),
				RaftState: string(RaftStateFollower),
				IsVoter:   false,
				IsLeader:  false,
				Uptime:    "1h",
			},
		},
		TotalCount: 2,
		VoterCount: 1,
		LeaderID:   "node-1",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_DeadNode(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes: []*NodeInfo{
			{
				NodeID:    "node-1",
				Address:   "10.0.0.1:7946",
				State:     string(NodeStateAlive),
				RaftState: string(RaftStateLeader),
				IsVoter:   true,
				IsLeader:  true,
				Uptime:    "3d5h",
			},
			{
				NodeID:    "node-dead",
				Address:   "10.0.0.3:7946",
				State:     string(NodeStateDead),
				RaftState: string(RaftStateUnknown),
				IsVoter:   true,
				IsLeader:  false,
				Uptime:    "N/A",
			},
		},
		TotalCount: 2,
		VoterCount: 2,
		LeaderID:   "node-1",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_SuspectNode(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes: []*NodeInfo{
			{
				NodeID:    "node-suspect",
				Address:   "10.0.0.2:7946",
				State:     string(NodeStateSuspect),
				RaftState: string(RaftStateFollower),
				IsVoter:   true,
				IsLeader:  false,
				Uptime:    "2h",
			},
		},
		TotalCount: 1,
		VoterCount: 1,
		LeaderID:   "",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_LeftNode(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes: []*NodeInfo{
			{
				NodeID:    "node-left",
				Address:   "10.0.0.5:7946",
				State:     string(NodeStateLeft),
				RaftState: string(RaftStateShutdown),
				IsVoter:   false,
				IsLeader:  false,
				Uptime:    "N/A",
			},
		},
		TotalCount: 1,
		VoterCount: 0,
		LeaderID:   "",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestPrintNodesTable_CandidateNode(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	response := &NodeListResponse{
		Nodes: []*NodeInfo{
			{
				NodeID:    "node-candidate",
				Address:   "10.0.0.2:7946",
				State:     string(NodeStateAlive),
				RaftState: string(RaftStateCandidate),
				IsVoter:   true,
				IsLeader:  false,
				Uptime:    "1h",
			},
		},
		TotalCount: 1,
		VoterCount: 1,
		LeaderID:   "",
	}

	err := printNodesTable(printer, response)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// Test Bootstrap command validation through RunE
func TestBootstrapCommand_RunE_Valid(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	testCtx := &cli.Context{
		Name: "test",
		Type: cli.ContextTypeLocal,
		Local: &cli.LocalContext{
			SocketPath: socketPath,
		},
	}

	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			NoColor:      true,
			GetConfig: func() (*cli.Config, error) {
				return cli.DefaultConfig(), nil
			},
			GetContext: func() (*cli.Context, error) {
				return testCtx, nil
			},
		}
	}

	cmd := NewBootstrapCommand(getFlags)
	cmd.Flags().Set("node-id", "node-1")
	cmd.Flags().Set("listen-addr", "10.0.0.1:7946")

	err := cmd.RunE(cmd, []string{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// Test Join command validation through RunE
func TestJoinCommand_RunE_Valid(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	testCtx := &cli.Context{
		Name: "test",
		Type: cli.ContextTypeLocal,
		Local: &cli.LocalContext{
			SocketPath: socketPath,
		},
	}

	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			NoColor:      true,
			GetConfig: func() (*cli.Config, error) {
				return cli.DefaultConfig(), nil
			},
			GetContext: func() (*cli.Context, error) {
				return testCtx, nil
			},
		}
	}

	cmd := NewJoinCommand(getFlags)
	cmd.Flags().Set("node-id", "node-2")
	cmd.Flags().Set("listen-addr", "10.0.0.2:7946")
	cmd.Flags().Set("join", "10.0.0.1:7946")

	err := cmd.RunE(cmd, []string{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// Test Leave command through RunE
func TestLeaveCommand_RunE(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	testCtx := &cli.Context{
		Name: "test",
		Type: cli.ContextTypeLocal,
		Local: &cli.LocalContext{
			SocketPath: socketPath,
		},
	}

	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			NoColor:      true,
			GetConfig: func() (*cli.Config, error) {
				return cli.DefaultConfig(), nil
			},
			GetContext: func() (*cli.Context, error) {
				return testCtx, nil
			},
		}
	}

	cmd := NewLeaveCommand(getFlags)

	err := cmd.RunE(cmd, []string{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// Test Status command through RunE
func TestStatusCommand_RunE(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	testCtx := &cli.Context{
		Name: "test",
		Type: cli.ContextTypeLocal,
		Local: &cli.LocalContext{
			SocketPath: socketPath,
		},
	}

	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			NoColor:      true,
			GetConfig: func() (*cli.Config, error) {
				return cli.DefaultConfig(), nil
			},
			GetContext: func() (*cli.Context, error) {
				return testCtx, nil
			},
		}
	}

	cmd := NewStatusCommand(getFlags)

	err := cmd.RunE(cmd, []string{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// Test Nodes command through RunE
func TestNodesCommand_RunE(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	testCtx := &cli.Context{
		Name: "test",
		Type: cli.ContextTypeLocal,
		Local: &cli.LocalContext{
			SocketPath: socketPath,
		},
	}

	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			NoColor:      true,
			GetConfig: func() (*cli.Config, error) {
				return cli.DefaultConfig(), nil
			},
			GetContext: func() (*cli.Context, error) {
				return testCtx, nil
			},
		}
	}

	cmd := NewNodesCommand(getFlags)

	err := cmd.RunE(cmd, []string{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// Test advertise address defaulting to listen address
func TestRunBootstrap_AdvertiseAddrDefault(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	// When advertise address is empty, it should default to listen address
	err := runBootstrap(flags, "node-1", "10.0.0.1:7946", "", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRunJoin_AdvertiseAddrDefault(t *testing.T) {
	socketPath, _, cleanup := setupTestServer(t)
	defer cleanup()

	flags := createTestFlags(socketPath, cli.OutputFormatTable)

	// When advertise address is empty, it should default to listen address
	err := runJoin(flags, "node-2", "10.0.0.2:7946", "", "10.0.0.1:7946")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// Test valid IPv6 addresses
func TestBootstrapValidation_IPv6Address(t *testing.T) {
	err := runBootstrapValidation("node-1", "[::1]:7946", "", "")
	if err != nil {
		t.Errorf("expected no error for IPv6 address, got %v", err)
	}
}

func TestBootstrapValidation_ValidAdvertiseAddr(t *testing.T) {
	err := runBootstrapValidation("node-1", "10.0.0.1:7946", "10.0.0.1:7946", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestJoinValidation_IPv6Address(t *testing.T) {
	err := runJoinValidation("node-1", "[::1]:7946", "", "[::2]:7946")
	if err != nil {
		t.Errorf("expected no error for IPv6 address, got %v", err)
	}
}

func TestJoinValidation_ValidAdvertiseAddr(t *testing.T) {
	err := runJoinValidation("node-1", "10.0.0.1:7946", "10.0.0.1:7946", "10.0.0.2:7946")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestJoinValidation_MultipleValidJoinAddrs(t *testing.T) {
	err := runJoinValidation("node-1", "10.0.0.1:7946", "", "10.0.0.2:7946,10.0.0.3:7946,10.0.0.4:7946")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestJoinValidation_InvalidAdvertiseAddr(t *testing.T) {
	err := runJoinValidation("node-1", "10.0.0.1:7946", "invalid", "10.0.0.2:7946")
	if err == nil {
		t.Error("expected error for invalid advertise address")
	}
	if _, ok := err.(ErrInvalidListenAddr); !ok {
		t.Errorf("expected ErrInvalidListenAddr, got %T", err)
	}
}
