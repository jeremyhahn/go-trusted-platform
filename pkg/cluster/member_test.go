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
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// mockRaftOperator provides a mock implementation of RaftOperator for testing.
type mockRaftOperator struct {
	mu sync.RWMutex

	// Control flags
	bootstrapError   error
	addVoterError    error
	addNonvoterError error
	removeError      error
	getLeaderError   error
	getNodesError    error

	// State
	isLeader   bool
	leaderID   uint64
	leaderAddr string
	term       uint64
	state      RaftState
	nodes      []RaftMemberInfo

	// Tracking
	bootstrapCalled int
	addVoterCalled  int
	removeCalled    int
}

func newMockRaftOperator() *mockRaftOperator {
	return &mockRaftOperator{
		leaderID:   1,
		leaderAddr: "127.0.0.1:7000",
		term:       1,
		state:      RaftStateFollower,
		nodes:      []RaftMemberInfo{},
	}
}

func (m *mockRaftOperator) Bootstrap(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bootstrapCalled++
	if m.bootstrapError != nil {
		return m.bootstrapError
	}
	m.isLeader = true
	m.leaderID = 1
	return nil
}

func (m *mockRaftOperator) AddVoter(ctx context.Context, id uint64, address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addVoterCalled++
	if m.addVoterError != nil {
		return m.addVoterError
	}
	m.nodes = append(m.nodes, RaftMemberInfo{ID: id, Address: address, Voter: true})
	return nil
}

func (m *mockRaftOperator) AddNonvoter(ctx context.Context, id uint64, address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addNonvoterError != nil {
		return m.addNonvoterError
	}
	m.nodes = append(m.nodes, RaftMemberInfo{ID: id, Address: address, Voter: false})
	return nil
}

func (m *mockRaftOperator) RemoveServer(ctx context.Context, id uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeCalled++
	if m.removeError != nil {
		return m.removeError
	}
	// Remove node from list
	for i, n := range m.nodes {
		if n.ID == id {
			m.nodes = append(m.nodes[:i], m.nodes[i+1:]...)
			break
		}
	}
	return nil
}

func (m *mockRaftOperator) GetLeader() (id uint64, address string, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getLeaderError != nil {
		return 0, "", m.getLeaderError
	}
	return m.leaderID, m.leaderAddr, nil
}

func (m *mockRaftOperator) GetNodes() ([]RaftMemberInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.getNodesError != nil {
		return nil, m.getNodesError
	}
	return m.nodes, nil
}

func (m *mockRaftOperator) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLeader
}

func (m *mockRaftOperator) GetState() RaftState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *mockRaftOperator) GetTerm() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.term
}

func (m *mockRaftOperator) setLeader(id uint64, addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leaderID = id
	m.leaderAddr = addr
}

func (m *mockRaftOperator) setIsLeader(isLeader bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isLeader = isLeader
}

func (m *mockRaftOperator) setNodes(nodes []RaftMemberInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = nodes
}

func createTestMembershipManager(t *testing.T) (*membershipManager, *mockRaftOperator) {
	t.Helper()
	config := NewConfig()
	raftOp := newMockRaftOperator()
	logger := logging.DefaultLogger()

	mm, err := NewMembershipManager(config, raftOp, logger)
	if err != nil {
		t.Fatalf("NewMembershipManager() error = %v", err)
	}

	return mm, raftOp
}

func TestNewMembershipManager(t *testing.T) {
	t.Run("creates manager with valid config", func(t *testing.T) {
		config := NewConfig()
		raftOp := newMockRaftOperator()
		logger := logging.DefaultLogger()

		mm, err := NewMembershipManager(config, raftOp, logger)
		if err != nil {
			t.Fatalf("NewMembershipManager() error = %v", err)
		}

		if mm == nil {
			t.Fatal("NewMembershipManager() returned nil")
		}

		// Clean up
		_ = mm.Close()
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		raftOp := newMockRaftOperator()
		logger := logging.DefaultLogger()

		_, err := NewMembershipManager(nil, raftOp, logger)
		if err == nil {
			t.Error("NewMembershipManager(nil config) should return error")
		}
	})

	t.Run("returns error for nil raft operator", func(t *testing.T) {
		config := NewConfig()
		logger := logging.DefaultLogger()

		_, err := NewMembershipManager(config, nil, logger)
		if err == nil {
			t.Error("NewMembershipManager(nil raftOp) should return error")
		}
	})

	t.Run("returns error for nil logger", func(t *testing.T) {
		config := NewConfig()
		raftOp := newMockRaftOperator()

		_, err := NewMembershipManager(config, raftOp, nil)
		if err == nil {
			t.Error("NewMembershipManager(nil logger) should return error")
		}
	})

	t.Run("returns error for invalid config", func(t *testing.T) {
		config := NewConfig()
		config.NodeID = 0 // Invalid
		raftOp := newMockRaftOperator()
		logger := logging.DefaultLogger()

		_, err := NewMembershipManager(config, raftOp, logger)
		if err == nil {
			t.Error("NewMembershipManager(invalid config) should return error")
		}
	})
}

func TestMembershipManager_Bootstrap(t *testing.T) {
	t.Run("bootstraps successfully", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		err := mm.Bootstrap(ctx)
		if err != nil {
			t.Fatalf("Bootstrap() error = %v", err)
		}

		if raftOp.bootstrapCalled != 1 {
			t.Errorf("Bootstrap() called Raft %d times, want 1", raftOp.bootstrapCalled)
		}

		if !mm.joined.Load() {
			t.Error("joined flag should be set after bootstrap")
		}

		if mm.localNode.State != NodeStateHealthy {
			t.Errorf("local node state = %v, want %v", mm.localNode.State, NodeStateHealthy)
		}
	})

	t.Run("returns error when already joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)

		err := mm.Bootstrap(ctx)
		if err == nil {
			t.Error("Bootstrap() should return error when already joined")
		}

		_, ok := err.(ErrAlreadyJoined)
		if !ok {
			t.Errorf("expected ErrAlreadyJoined, got %T", err)
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		err := mm.Bootstrap(ctx)
		if err == nil {
			t.Error("Bootstrap() should return error when closed")
		}

		_, ok := err.(ErrManagerClosed)
		if !ok {
			t.Errorf("expected ErrManagerClosed, got %T", err)
		}
	})

	t.Run("returns error on raft failure", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		raftOp.bootstrapError = errors.New("raft error")

		err := mm.Bootstrap(ctx)
		if err == nil {
			t.Error("Bootstrap() should return error on raft failure")
		}

		_, ok := err.(ErrBootstrapFailed)
		if !ok {
			t.Errorf("expected ErrBootstrapFailed, got %T", err)
		}
	})
}

func TestMembershipManager_Join(t *testing.T) {
	t.Run("joins successfully", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		err := mm.Join(ctx, []string{"192.168.1.1:7000"})
		if err != nil {
			t.Fatalf("Join() error = %v", err)
		}

		if !mm.joined.Load() {
			t.Error("joined flag should be set after join")
		}
	})

	t.Run("returns error when already joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Join(ctx, []string{"192.168.1.1:7000"})

		err := mm.Join(ctx, []string{"192.168.1.2:7000"})
		if err == nil {
			t.Error("Join() should return error when already joined")
		}

		_, ok := err.(ErrAlreadyJoined)
		if !ok {
			t.Errorf("expected ErrAlreadyJoined, got %T", err)
		}
	})

	t.Run("returns error with empty addresses", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		err := mm.Join(ctx, []string{})
		if err == nil {
			t.Error("Join() should return error with empty addresses")
		}

		_, ok := err.(ErrNoJoinAddresses)
		if !ok {
			t.Errorf("expected ErrNoJoinAddresses, got %T", err)
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		err := mm.Join(ctx, []string{"192.168.1.1:7000"})
		if err == nil {
			t.Error("Join() should return error when closed")
		}
	})
}

func TestMembershipManager_Leave(t *testing.T) {
	t.Run("leaves successfully", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)

		err := mm.Leave(ctx)
		if err != nil {
			t.Fatalf("Leave() error = %v", err)
		}

		if raftOp.removeCalled != 1 {
			t.Errorf("RemoveServer() called %d times, want 1", raftOp.removeCalled)
		}

		if mm.joined.Load() {
			t.Error("joined flag should be cleared after leave")
		}
	})

	t.Run("returns error when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		err := mm.Leave(ctx)
		if err == nil {
			t.Error("Leave() should return error when not joined")
		}

		_, ok := err.(ErrNotJoined)
		if !ok {
			t.Errorf("expected ErrNotJoined, got %T", err)
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		err := mm.Leave(ctx)
		if err == nil {
			t.Error("Leave() should return error when closed")
		}
	})

	t.Run("returns error on raft failure", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.removeError = errors.New("raft error")

		err := mm.Leave(ctx)
		if err == nil {
			t.Error("Leave() should return error on raft failure")
		}

		_, ok := err.(ErrLeaveFailed)
		if !ok {
			t.Errorf("expected ErrLeaveFailed, got %T", err)
		}
	})
}

func TestMembershipManager_AddNode(t *testing.T) {
	t.Run("adds node successfully", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)

		err := mm.AddNode(ctx, 2, "192.168.1.2:7000")
		if err != nil {
			t.Fatalf("AddNode() error = %v", err)
		}

		if raftOp.addVoterCalled != 1 {
			t.Errorf("AddVoter() called %d times, want 1", raftOp.addVoterCalled)
		}
	})

	t.Run("returns error when not leader", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(false)

		err := mm.AddNode(ctx, 2, "192.168.1.2:7000")
		if err == nil {
			t.Error("AddNode() should return error when not leader")
		}

		_, ok := err.(ErrNodeNotLeader)
		if !ok {
			t.Errorf("expected ErrNodeNotLeader, got %T", err)
		}
	})

	t.Run("returns error when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		err := mm.AddNode(ctx, 2, "192.168.1.2:7000")
		if err == nil {
			t.Error("AddNode() should return error when not joined")
		}
	})

	t.Run("returns error for zero node ID", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)

		err := mm.AddNode(ctx, 0, "192.168.1.2:7000")
		if err == nil {
			t.Error("AddNode() should return error for zero node ID")
		}
	})

	t.Run("returns error for empty address", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)

		err := mm.AddNode(ctx, 2, "")
		if err == nil {
			t.Error("AddNode() should return error for empty address")
		}
	})

	t.Run("returns error when node already exists", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)

		_ = mm.AddNode(ctx, 2, "192.168.1.2:7000")

		err := mm.AddNode(ctx, 2, "192.168.1.2:7000")
		if err == nil {
			t.Error("AddNode() should return error when node already exists")
		}

		_, ok := err.(ErrNodeAlreadyExists)
		if !ok {
			t.Errorf("expected ErrNodeAlreadyExists, got %T", err)
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		err := mm.AddNode(ctx, 2, "192.168.1.2:7000")
		if err == nil {
			t.Error("AddNode() should return error when closed")
		}
	})
}

func TestMembershipManager_RemoveNode(t *testing.T) {
	t.Run("removes node successfully", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)
		_ = mm.AddNode(ctx, 2, "192.168.1.2:7000")

		err := mm.RemoveNode(ctx, 2)
		if err != nil {
			t.Fatalf("RemoveNode() error = %v", err)
		}

		if raftOp.removeCalled != 1 {
			t.Errorf("RemoveServer() called %d times, want 1", raftOp.removeCalled)
		}
	})

	t.Run("returns error when not leader", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(false)

		err := mm.RemoveNode(ctx, 2)
		if err == nil {
			t.Error("RemoveNode() should return error when not leader")
		}
	})

	t.Run("returns error when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		err := mm.RemoveNode(ctx, 2)
		if err == nil {
			t.Error("RemoveNode() should return error when not joined")
		}
	})

	t.Run("returns error for zero node ID", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)

		err := mm.RemoveNode(ctx, 0)
		if err == nil {
			t.Error("RemoveNode() should return error for zero node ID")
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		err := mm.RemoveNode(ctx, 2)
		if err == nil {
			t.Error("RemoveNode() should return error when closed")
		}
	})
}

func TestMembershipManager_GetNodes(t *testing.T) {
	t.Run("returns nodes successfully", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		raftOp.setNodes([]RaftMemberInfo{
			{ID: 1, Address: "addr1", Voter: true},
			{ID: 2, Address: "addr2", Voter: true},
		})

		_ = mm.Bootstrap(ctx)

		nodeList, err := mm.GetNodes(ctx)
		if err != nil {
			t.Fatalf("GetNodes() error = %v", err)
		}

		if nodeList.Count() < 1 {
			t.Error("GetNodes() should return at least the local node")
		}
	})

	t.Run("returns error when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_, err := mm.GetNodes(ctx)
		if err == nil {
			t.Error("GetNodes() should return error when not joined")
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		_, err := mm.GetNodes(ctx)
		if err == nil {
			t.Error("GetNodes() should return error when closed")
		}
	})
}

func TestMembershipManager_GetLeader(t *testing.T) {
	t.Run("returns leader successfully", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setLeader(1, "127.0.0.1:7000")

		leader, err := mm.GetLeader(ctx)
		if err != nil {
			t.Fatalf("GetLeader() error = %v", err)
		}

		if leader.ID != 1 {
			t.Errorf("leader ID = %d, want 1", leader.ID)
		}
	})

	t.Run("returns error when no leader", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setLeader(0, "")

		_, err := mm.GetLeader(ctx)
		if err == nil {
			t.Error("GetLeader() should return error when no leader")
		}

		_, ok := err.(ErrNoLeader)
		if !ok {
			t.Errorf("expected ErrNoLeader, got %T", err)
		}
	})

	t.Run("returns error when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_, err := mm.GetLeader(ctx)
		if err == nil {
			t.Error("GetLeader() should return error when not joined")
		}
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		_, err := mm.GetLeader(ctx)
		if err == nil {
			t.Error("GetLeader() should return error when closed")
		}
	})
}

func TestMembershipManager_IsLeader(t *testing.T) {
	t.Run("returns true when leader", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)

		if !mm.IsLeader() {
			t.Error("IsLeader() should return true")
		}
	})

	t.Run("returns false when not leader", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(false)

		if mm.IsLeader() {
			t.Error("IsLeader() should return false")
		}
	})

	t.Run("returns false when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()

		if mm.IsLeader() {
			t.Error("IsLeader() should return false when closed")
		}
	})

	t.Run("returns false when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()

		if mm.IsLeader() {
			t.Error("IsLeader() should return false when not joined")
		}
	})
}

func TestMembershipManager_WaitForLeader(t *testing.T) {
	t.Run("returns immediately when leader exists", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setLeader(1, "127.0.0.1:7000")

		leader, err := mm.WaitForLeader(ctx)
		if err != nil {
			t.Fatalf("WaitForLeader() error = %v", err)
		}

		if leader.ID != 1 {
			t.Errorf("leader ID = %d, want 1", leader.ID)
		}
	})

	t.Run("waits for leader to be elected", func(t *testing.T) {
		// The leader check loop runs on a ticker; inside a synctest bubble it
		// reads the fake clock, which advances only when every goroutine is
		// blocked, so the test never waits on the wall clock.
		synctest.Test(t, func(t *testing.T) {
			mm, raftOp := createTestMembershipManager(t)
			defer func() {
				if err := mm.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			}()
			ctx := context.Background()

			if err := mm.Bootstrap(ctx); err != nil {
				t.Fatalf("Bootstrap() error = %v", err)
			}
			raftOp.setLeader(0, "") // No leader initially

			done := make(chan struct{})
			var leader *Node
			var waitErr error

			go func() {
				leader, waitErr = mm.WaitForLeader(ctx)
				close(done)
			}()

			// Wait until the waiter is registered and blocked
			synctest.Wait()
			select {
			case <-done:
				t.Fatalf("WaitForLeader() returned (%v, %v) before a leader was elected", leader, waitErr)
			default:
			}

			// Elect a leader; the next leader check tick wakes the waiter
			raftOp.setLeader(1, "127.0.0.1:7000")
			<-done

			if waitErr != nil {
				t.Fatalf("WaitForLeader() error = %v", waitErr)
			}
			if leader == nil || leader.ID != 1 {
				t.Errorf("leader = %+v, want ID 1", leader)
			}
		})
	})

	t.Run("returns error on context cancellation", func(t *testing.T) {
		// The deadline and the leader check ticks run on synctest time (#284).
		synctest.Test(t, func(t *testing.T) {
			mm, raftOp := createTestMembershipManager(t)
			defer func() { _ = mm.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			_ = mm.Bootstrap(ctx)
			raftOp.setLeader(0, "") // No leader

			_, err := mm.WaitForLeader(ctx)
			if err == nil {
				t.Error("WaitForLeader() should return error on context cancellation")
			}

			_, ok := err.(ErrLeadershipTimeout)
			if !ok {
				t.Errorf("expected ErrLeadershipTimeout, got %T", err)
			}
		})
	})

	t.Run("returns error when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()
		ctx := context.Background()

		_, err := mm.WaitForLeader(ctx)
		if err == nil {
			t.Error("WaitForLeader() should return error when closed")
		}
	})

	t.Run("returns error when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_, err := mm.WaitForLeader(ctx)
		if err == nil {
			t.Error("WaitForLeader() should return error when not joined")
		}
	})
}

func TestMembershipManager_LocalNode(t *testing.T) {
	mm, _ := createTestMembershipManager(t)
	defer func() { _ = mm.Close() }()

	localNode := mm.LocalNode()
	if localNode == nil {
		t.Fatal("LocalNode() returned nil")
	}

	if localNode.ID != 1 { // Default config NodeID
		t.Errorf("LocalNode ID = %d, want 1", localNode.ID)
	}
}

func TestMembershipManager_GetTerm(t *testing.T) {
	t.Run("returns term when joined", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.term = 5

		term := mm.GetTerm()
		if term != 5 {
			t.Errorf("GetTerm() = %d, want 5", term)
		}
	})

	t.Run("returns zero when not joined", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()

		term := mm.GetTerm()
		if term != 0 {
			t.Errorf("GetTerm() = %d, want 0 when not joined", term)
		}
	})

	t.Run("returns zero when closed", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)
		_ = mm.Close()

		term := mm.GetTerm()
		if term != 0 {
			t.Errorf("GetTerm() = %d, want 0 when closed", term)
		}
	})
}

func TestMembershipManager_Close(t *testing.T) {
	t.Run("closes successfully", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)

		err := mm.Close()
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}

		if !mm.closed.Load() {
			t.Error("closed flag should be set after Close()")
		}
	})

	t.Run("multiple close calls are safe", func(t *testing.T) {
		mm, _ := createTestMembershipManager(t)

		err1 := mm.Close()
		err2 := mm.Close()

		if err1 != nil || err2 != nil {
			t.Errorf("Close() errors = %v, %v", err1, err2)
		}
	})
}

func TestMembershipManager_Concurrent(t *testing.T) {
	t.Run("concurrent operations are safe", func(t *testing.T) {
		mm, raftOp := createTestMembershipManager(t)
		defer func() { _ = mm.Close() }()
		ctx := context.Background()

		_ = mm.Bootstrap(ctx)
		raftOp.setIsLeader(true)
		raftOp.setNodes([]RaftMemberInfo{
			{ID: 1, Address: "addr1", Voter: true},
		})

		var wg sync.WaitGroup
		var addCounter atomic.Int32

		// Concurrent reads
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = mm.GetNodes(ctx)
				_, _ = mm.GetLeader(ctx)
				_ = mm.IsLeader()
				_ = mm.GetTerm()
				_ = mm.LocalNode()
			}()
		}

		// Concurrent adds
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				nodeID := uint64(100 + idx)
				err := mm.AddNode(ctx, nodeID, "addr")
				if err == nil {
					addCounter.Add(1)
				}
			}(i)
		}

		wg.Wait()
	})
}

func TestMembershipManager_ImplementsInterface(t *testing.T) {
	// Verify that membershipManager implements MembershipManager interface
	var _ MembershipManager = (*membershipManager)(nil)
}
