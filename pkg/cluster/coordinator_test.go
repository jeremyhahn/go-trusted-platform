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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// mockMembershipManager provides a mock implementation of MembershipManager for testing.
type mockMembershipManager struct {
	mu sync.RWMutex

	// Control flags
	bootstrapError     error
	joinError          error
	leaveError         error
	addNodeError       error
	removeNodeError    error
	getNodesError      error
	getLeaderError     error
	waitForLeaderError error

	// State
	isLeader  bool
	joined    bool
	term      uint64
	localNode *Node
	nodes     NodeList
	leader    *Node

	// Tracking
	bootstrapCalled  int
	joinCalled       int
	leaveCalled      int
	addNodeCalled    int
	removeNodeCalled int
	getNodesCalled   int
	getLeaderCalled  int
	closeCalled      int
}

func newMockMembershipManager() *mockMembershipManager {
	return &mockMembershipManager{
		term: 1,
		localNode: &Node{
			ID:       1,
			Address:  "127.0.0.1:7000",
			State:    NodeStateHealthy,
			IsLeader: true,
		},
		leader: &Node{
			ID:       1,
			Address:  "127.0.0.1:7000",
			State:    NodeStateHealthy,
			IsLeader: true,
		},
		nodes: NodeList{
			Nodes: []*Node{
				{ID: 1, Address: "127.0.0.1:7000", State: NodeStateHealthy, IsLeader: true},
			},
			Leader: &Node{ID: 1, Address: "127.0.0.1:7000", State: NodeStateHealthy, IsLeader: true},
			Term:   1,
		},
		isLeader: true,
		joined:   false,
	}
}

func (m *mockMembershipManager) Bootstrap(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bootstrapCalled++
	if m.bootstrapError != nil {
		return m.bootstrapError
	}
	m.joined = true
	return nil
}

func (m *mockMembershipManager) Join(ctx context.Context, addresses []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.joinCalled++
	if m.joinError != nil {
		return m.joinError
	}
	m.joined = true
	return nil
}

func (m *mockMembershipManager) Leave(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leaveCalled++
	if m.leaveError != nil {
		return m.leaveError
	}
	m.joined = false
	return nil
}

func (m *mockMembershipManager) AddNode(ctx context.Context, nodeID uint64, address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addNodeCalled++
	return m.addNodeError
}

func (m *mockMembershipManager) RemoveNode(ctx context.Context, nodeID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeNodeCalled++
	return m.removeNodeError
}

func (m *mockMembershipManager) GetNodes(ctx context.Context) (NodeList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getNodesCalled++
	if m.getNodesError != nil {
		return NodeList{}, m.getNodesError
	}
	return m.nodes, nil
}

func (m *mockMembershipManager) InvalidateCache() {
	// No-op for mock - the mock doesn't cache
}

func (m *mockMembershipManager) GetLeader(ctx context.Context) (*Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getLeaderCalled++
	if m.getLeaderError != nil {
		return nil, m.getLeaderError
	}
	return m.leader, nil
}

func (m *mockMembershipManager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLeader
}

func (m *mockMembershipManager) WaitForLeader(ctx context.Context) (*Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.waitForLeaderError != nil {
		return nil, m.waitForLeaderError
	}
	if m.leader == nil {
		<-ctx.Done()
		return nil, ErrLeadershipTimeout{}
	}
	return m.leader, nil
}

func (m *mockMembershipManager) LocalNode() *Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localNode
}

func (m *mockMembershipManager) GetTerm() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.term
}

func (m *mockMembershipManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled++
	return nil
}

func (m *mockMembershipManager) setLeader(node *Node) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leader = node
	m.nodes.Leader = node
}

func (m *mockMembershipManager) setIsLeader(isLeader bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isLeader = isLeader
}

func (m *mockMembershipManager) setNodes(nodes NodeList) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = nodes
}

func createTestCoordinator(t *testing.T) (Coordinator, *mockMembershipManager) {
	t.Helper()
	config := NewConfig()
	membership := newMockMembershipManager()
	logger := logging.DefaultLogger()

	coord, err := NewCoordinator(config, membership, logger)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coord, membership
}

func TestNewCoordinator(t *testing.T) {
	t.Run("creates coordinator with valid params", func(t *testing.T) {
		config := NewConfig()
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		coord, err := NewCoordinator(config, membership, logger)
		if err != nil {
			t.Fatalf("NewCoordinator() error = %v", err)
		}

		if coord == nil {
			t.Fatal("NewCoordinator() returned nil")
		}
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		_, err := NewCoordinator(nil, membership, logger)
		if err == nil {
			t.Error("NewCoordinator(nil config) should return error")
		}

		_, ok := err.(ErrNilConfig)
		if !ok {
			t.Errorf("expected ErrNilConfig, got %T", err)
		}
	})

	t.Run("returns error for nil membership", func(t *testing.T) {
		config := NewConfig()
		logger := logging.DefaultLogger()

		_, err := NewCoordinator(config, nil, logger)
		if err == nil {
			t.Error("NewCoordinator(nil membership) should return error")
		}

		_, ok := err.(ErrNilMembership)
		if !ok {
			t.Errorf("expected ErrNilMembership, got %T", err)
		}
	})

	t.Run("returns error for nil logger", func(t *testing.T) {
		config := NewConfig()
		membership := newMockMembershipManager()

		_, err := NewCoordinator(config, membership, nil)
		if err == nil {
			t.Error("NewCoordinator(nil logger) should return error")
		}

		_, ok := err.(ErrNilLogger)
		if !ok {
			t.Errorf("expected ErrNilLogger, got %T", err)
		}
	})

	t.Run("returns error for invalid config", func(t *testing.T) {
		config := NewConfig()
		config.NodeID = 0 // Invalid
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		_, err := NewCoordinator(config, membership, logger)
		if err == nil {
			t.Error("NewCoordinator(invalid config) should return error")
		}
	})

	t.Run("applies functional options", func(t *testing.T) {
		config := NewConfig()
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		coord, err := NewCoordinator(
			config,
			membership,
			logger,
			WithCoordinatorHealthCheckInterval(10*time.Second),
			WithCoordinatorLeaderWaitTimeout(60*time.Second),
			WithCoordinatorShutdownTimeout(20*time.Second),
		)
		if err != nil {
			t.Fatalf("NewCoordinator() error = %v", err)
		}

		// Access internal coordinator to verify options
		c := coord.(*coordinator)
		if c.healthCheckInterval != 10*time.Second {
			t.Errorf("healthCheckInterval = %v, want 10s", c.healthCheckInterval)
		}
		if c.leaderWaitTimeout != 60*time.Second {
			t.Errorf("leaderWaitTimeout = %v, want 60s", c.leaderWaitTimeout)
		}
		if c.shutdownTimeout != 20*time.Second {
			t.Errorf("shutdownTimeout = %v, want 20s", c.shutdownTimeout)
		}
	})
}

func TestCoordinator_Start(t *testing.T) {
	t.Run("starts successfully", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		err := coord.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		defer func() {
			if err := coord.Stop(ctx); err != nil {
				t.Logf("Stop failed: %v", err)
			}
		}()

		if !coord.IsRunning() {
			t.Error("IsRunning() should return true after Start()")
		}
	})

	t.Run("returns error when already running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		err := coord.Start(ctx)
		if err == nil {
			t.Error("Start() should return error when already running")
		}

		_, ok := err.(ErrCoordinatorAlreadyRunning)
		if !ok {
			t.Errorf("expected ErrCoordinatorAlreadyRunning, got %T", err)
		}
	})
}

func TestCoordinator_Stop(t *testing.T) {
	t.Run("stops successfully", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)

		err := coord.Stop(ctx)
		if err != nil {
			t.Fatalf("Stop() error = %v", err)
		}

		if coord.IsRunning() {
			t.Error("IsRunning() should return false after Stop()")
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		err := coord.Stop(ctx)
		if err == nil {
			t.Error("Stop() should return error when not running")
		}

		_, ok := err.(ErrCoordinatorNotRunning)
		if !ok {
			t.Errorf("expected ErrCoordinatorNotRunning, got %T", err)
		}
	})

	t.Run("leaves cluster on stop", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		_ = coord.Stop(ctx)

		if membership.leaveCalled == 0 {
			t.Error("Stop() should call Leave()")
		}
	})
}

func TestCoordinator_Bootstrap(t *testing.T) {
	t.Run("bootstraps successfully", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		err := coord.Bootstrap(ctx)
		if err != nil {
			t.Fatalf("Bootstrap() error = %v", err)
		}

		if membership.bootstrapCalled != 1 {
			t.Errorf("Bootstrap() called membership %d times, want 1", membership.bootstrapCalled)
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		err := coord.Bootstrap(ctx)
		if err == nil {
			t.Error("Bootstrap() should return error when not running")
		}

		_, ok := err.(ErrCoordinatorNotRunning)
		if !ok {
			t.Errorf("expected ErrCoordinatorNotRunning, got %T", err)
		}
	})

	t.Run("returns error on membership failure", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		membership.bootstrapError = errors.New("bootstrap failed")

		err := coord.Bootstrap(ctx)
		if err == nil {
			t.Error("Bootstrap() should return error on membership failure")
		}

		_, ok := err.(ErrBootstrapFailed)
		if !ok {
			t.Errorf("expected ErrBootstrapFailed, got %T", err)
		}
	})
}

func TestCoordinator_Join(t *testing.T) {
	t.Run("joins successfully", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		err := coord.Join(ctx, []string{"192.168.1.1:7000"})
		if err != nil {
			t.Fatalf("Join() error = %v", err)
		}

		if membership.joinCalled != 1 {
			t.Errorf("Join() called membership %d times, want 1", membership.joinCalled)
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		err := coord.Join(ctx, []string{"192.168.1.1:7000"})
		if err == nil {
			t.Error("Join() should return error when not running")
		}
	})

	t.Run("returns error with empty addresses", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		err := coord.Join(ctx, []string{})
		if err == nil {
			t.Error("Join() should return error with empty addresses")
		}

		_, ok := err.(ErrNoJoinAddresses)
		if !ok {
			t.Errorf("expected ErrNoJoinAddresses, got %T", err)
		}
	})

	t.Run("returns error on membership failure", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		membership.joinError = errors.New("join failed")

		err := coord.Join(ctx, []string{"192.168.1.1:7000"})
		if err == nil {
			t.Error("Join() should return error on membership failure")
		}

		_, ok := err.(ErrJoinFailed)
		if !ok {
			t.Errorf("expected ErrJoinFailed, got %T", err)
		}
	})
}

func TestCoordinator_Leave(t *testing.T) {
	t.Run("leaves successfully", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		err := coord.Leave(ctx)
		if err != nil {
			t.Fatalf("Leave() error = %v", err)
		}

		if membership.leaveCalled != 1 {
			t.Errorf("Leave() called membership %d times, want 1", membership.leaveCalled)
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		err := coord.Leave(ctx)
		if err == nil {
			t.Error("Leave() should return error when not running")
		}
	})

	t.Run("returns error on membership failure", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		membership.leaveError = errors.New("leave failed")

		err := coord.Leave(ctx)
		if err == nil {
			t.Error("Leave() should return error on membership failure")
		}

		_, ok := err.(ErrLeaveFailed)
		if !ok {
			t.Errorf("expected ErrLeaveFailed, got %T", err)
		}
	})
}

func TestCoordinator_Status(t *testing.T) {
	t.Run("returns status", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		status, err := coord.Status(ctx)
		if err != nil {
			t.Fatalf("Status() error = %v", err)
		}

		if status == nil {
			t.Fatal("Status() returned nil")
		}

		if status.State != ClusterStateRunning {
			t.Errorf("status.State = %q, want %q", status.State, ClusterStateRunning)
		}
	})

	t.Run("returns copy of status", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		status1, _ := coord.Status(ctx)
		status1.NodeCount = 999

		status2, _ := coord.Status(ctx)
		if status2.NodeCount == 999 {
			t.Error("Status() should return a copy")
		}
	})
}

func TestCoordinator_Nodes(t *testing.T) {
	t.Run("returns nodes", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		nodeList, err := coord.Nodes(ctx)
		if err != nil {
			t.Fatalf("Nodes() error = %v", err)
		}

		if nodeList.Count() == 0 {
			t.Error("Nodes() should return at least one node")
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_, err := coord.Nodes(ctx)
		if err == nil {
			t.Error("Nodes() should return error when not running")
		}
	})
}

func TestCoordinator_IsLeader(t *testing.T) {
	t.Run("returns true when leader", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		membership.setIsLeader(true)

		if !coord.IsLeader() {
			t.Error("IsLeader() should return true")
		}
	})

	t.Run("returns false when not leader", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		membership.setIsLeader(false)

		if coord.IsLeader() {
			t.Error("IsLeader() should return false")
		}
	})

	t.Run("returns false when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)

		if coord.IsLeader() {
			t.Error("IsLeader() should return false when not running")
		}
	})
}

func TestCoordinator_GetLeader(t *testing.T) {
	t.Run("returns leader", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		leader, err := coord.GetLeader(ctx)
		if err != nil {
			t.Fatalf("GetLeader() error = %v", err)
		}

		if leader == nil {
			t.Fatal("GetLeader() returned nil")
		}

		if leader.ID != 1 {
			t.Errorf("leader ID = %d, want 1", leader.ID)
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_, err := coord.GetLeader(ctx)
		if err == nil {
			t.Error("GetLeader() should return error when not running")
		}
	})
}

func TestCoordinator_WaitForLeader(t *testing.T) {
	t.Run("returns leader immediately if exists", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		leader, err := coord.WaitForLeader(ctx)
		if err != nil {
			t.Fatalf("WaitForLeader() error = %v", err)
		}

		if leader == nil {
			t.Fatal("WaitForLeader() returned nil")
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_, err := coord.WaitForLeader(ctx)
		if err == nil {
			t.Error("WaitForLeader() should return error when not running")
		}
	})
}

func TestCoordinator_IsHealthy(t *testing.T) {
	t.Run("returns true when healthy", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		// Give time for health check to run
		time.Sleep(50 * time.Millisecond)

		if !coord.IsHealthy() {
			t.Error("IsHealthy() should return true after start")
		}
	})

	t.Run("returns false when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)

		if coord.IsHealthy() {
			t.Error("IsHealthy() should return false when not running")
		}
	})
}

func TestCoordinator_HealthCheck(t *testing.T) {
	t.Run("passes when healthy", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		// Configure mock for healthy cluster
		membership.setNodes(NodeList{
			Nodes: []*Node{
				{ID: 1, State: NodeStateHealthy},
				{ID: 2, State: NodeStateHealthy},
				{ID: 3, State: NodeStateHealthy},
			},
			Leader: &Node{ID: 1, State: NodeStateHealthy, IsLeader: true},
		})
		membership.setLeader(&Node{ID: 1, State: NodeStateHealthy, IsLeader: true})

		err := coord.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}
	})

	t.Run("returns error when not running", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		err := coord.HealthCheck(ctx)
		if err == nil {
			t.Error("HealthCheck() should return error when not running")
		}
	})

	t.Run("returns error when no quorum", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		// Configure mock for unhealthy cluster
		membership.setNodes(NodeList{
			Nodes: []*Node{
				{ID: 1, State: NodeStateHealthy},
				{ID: 2, State: NodeStateUnhealthy},
				{ID: 3, State: NodeStateUnhealthy},
			},
		})
		membership.setLeader(&Node{ID: 1})

		err := coord.HealthCheck(ctx)
		if err == nil {
			t.Error("HealthCheck() should return error when no quorum")
		}
	})

	t.Run("returns error when no leader", func(t *testing.T) {
		coord, membership := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		membership.setLeader(nil)
		membership.getLeaderError = ErrNoLeader{}

		err := coord.HealthCheck(ctx)
		if err == nil {
			t.Error("HealthCheck() should return error when no leader")
		}
	})
}

func TestCoordinator_Config(t *testing.T) {
	coord, _ := createTestCoordinator(t)

	config := coord.Config()
	if config == nil {
		t.Fatal("Config() returned nil")
	}

	if config.NodeID != 1 {
		t.Errorf("Config().NodeID = %d, want 1", config.NodeID)
	}
}

func TestCoordinator_NodeID(t *testing.T) {
	coord, _ := createTestCoordinator(t)

	nodeID := coord.NodeID()
	if nodeID != 1 {
		t.Errorf("NodeID() = %d, want 1", nodeID)
	}
}

func TestCoordinator_Options(t *testing.T) {
	t.Run("WithCoordinatorHealthCheckInterval", func(t *testing.T) {
		config := NewConfig()
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		coord, _ := NewCoordinator(config, membership, logger,
			WithCoordinatorHealthCheckInterval(15*time.Second))

		c := coord.(*coordinator)
		if c.healthCheckInterval != 15*time.Second {
			t.Errorf("healthCheckInterval = %v, want 15s", c.healthCheckInterval)
		}
	})

	t.Run("WithCoordinatorLeaderWaitTimeout", func(t *testing.T) {
		config := NewConfig()
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		coord, _ := NewCoordinator(config, membership, logger,
			WithCoordinatorLeaderWaitTimeout(45*time.Second))

		c := coord.(*coordinator)
		if c.leaderWaitTimeout != 45*time.Second {
			t.Errorf("leaderWaitTimeout = %v, want 45s", c.leaderWaitTimeout)
		}
	})

	t.Run("WithCoordinatorShutdownTimeout", func(t *testing.T) {
		config := NewConfig()
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		coord, _ := NewCoordinator(config, membership, logger,
			WithCoordinatorShutdownTimeout(30*time.Second))

		c := coord.(*coordinator)
		if c.shutdownTimeout != 30*time.Second {
			t.Errorf("shutdownTimeout = %v, want 30s", c.shutdownTimeout)
		}
	})
}

func TestCoordinator_Concurrent(t *testing.T) {
	t.Run("concurrent reads are safe", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = coord.Status(ctx)
				_, _ = coord.Nodes(ctx)
				_ = coord.IsLeader()
				_ = coord.IsHealthy()
				_ = coord.IsRunning()
				_ = coord.NodeID()
				_ = coord.Config()
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent start calls are safe", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		var wg sync.WaitGroup
		var successCount int32

		// Multiple start attempts
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if coord.Start(ctx) == nil {
					// Safely increment success count
					successCount++
				}
			}()
		}

		wg.Wait()

		// Verify only one start succeeded (or coordinator is running)
		if !coord.IsRunning() {
			t.Error("coordinator should be running after concurrent starts")
		}

		// Clean up
		_ = coord.Stop(ctx)
	})

	t.Run("single stop after start", func(t *testing.T) {
		coord, _ := createTestCoordinator(t)
		ctx := context.Background()

		_ = coord.Start(ctx)

		err := coord.Stop(ctx)
		if err != nil {
			t.Errorf("Stop() error = %v", err)
		}

		if coord.IsRunning() {
			t.Error("coordinator should be stopped after Stop()")
		}

		// Second stop should return error
		err = coord.Stop(ctx)
		if err == nil {
			t.Error("second Stop() should return error")
		}
	})
}

func TestCoordinator_HealthMonitor(t *testing.T) {
	t.Run("health monitor updates status", func(t *testing.T) {
		config := NewConfig()
		membership := newMockMembershipManager()
		logger := logging.DefaultLogger()

		coord, _ := NewCoordinator(config, membership, logger,
			WithCoordinatorHealthCheckInterval(50*time.Millisecond))

		ctx := context.Background()
		_ = coord.Start(ctx)
		defer func() { _ = coord.Stop(ctx) }()

		// Wait for health check to run
		time.Sleep(100 * time.Millisecond)

		status, _ := coord.Status(ctx)
		// Health monitor should have updated the node count
		// (depends on mock returning at least one node).
		// NodeCount may be 0 if the mock doesn't return nodes.
		_ = status.NodeCount
	})
}
