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

	// The listener is already bound: a dial queues in its backlog until
	// Serve accepts it, so no start-up wait is needed.
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
