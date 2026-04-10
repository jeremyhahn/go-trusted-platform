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
	"sync"
	"testing"
	"time"
)

func TestRaftClusterState_String(t *testing.T) {
	tests := []struct {
		state RaftClusterState
		want  string
	}{
		{RaftStateUninitialized, "uninitialized"},
		{RaftStateBootstrapping, "bootstrapping"},
		{RaftStateJoining, "joining"},
		{RaftStateFollowerRole, "follower"},
		{RaftStateCandidateRole, "candidate"},
		{RaftStateLeaderRole, "leader"},
		{RaftStateLeavingCluster, "leaving"},
		{RaftStateShutdownComplete, "shutdown"},
		{RaftClusterState("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("RaftClusterState.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRaftClusterState_IsValid(t *testing.T) {
	tests := []struct {
		state RaftClusterState
		want  bool
	}{
		{RaftStateUninitialized, true},
		{RaftStateBootstrapping, true},
		{RaftStateJoining, true},
		{RaftStateFollowerRole, true},
		{RaftStateCandidateRole, true},
		{RaftStateLeaderRole, true},
		{RaftStateLeavingCluster, true},
		{RaftStateShutdownComplete, true},
		{RaftClusterState("invalid"), false},
		{RaftClusterState(""), false},
		{RaftClusterState("random"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsValid(); got != tt.want {
				t.Errorf("RaftClusterState(%q).IsValid() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestRaftClusterState_IsTerminal(t *testing.T) {
	tests := []struct {
		state RaftClusterState
		want  bool
	}{
		{RaftStateUninitialized, false},
		{RaftStateBootstrapping, false},
		{RaftStateJoining, false},
		{RaftStateFollowerRole, false},
		{RaftStateCandidateRole, false},
		{RaftStateLeaderRole, false},
		{RaftStateLeavingCluster, false},
		{RaftStateShutdownComplete, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsTerminal(); got != tt.want {
				t.Errorf("RaftClusterState(%q).IsTerminal() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestRaftClusterState_IsOperational(t *testing.T) {
	tests := []struct {
		state RaftClusterState
		want  bool
	}{
		{RaftStateUninitialized, false},
		{RaftStateBootstrapping, false},
		{RaftStateJoining, false},
		{RaftStateFollowerRole, true},
		{RaftStateCandidateRole, true},
		{RaftStateLeaderRole, true},
		{RaftStateLeavingCluster, false},
		{RaftStateShutdownComplete, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsOperational(); got != tt.want {
				t.Errorf("RaftClusterState(%q).IsOperational() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestRaftClusterState_IsTransitioning(t *testing.T) {
	tests := []struct {
		state RaftClusterState
		want  bool
	}{
		{RaftStateUninitialized, false},
		{RaftStateBootstrapping, true},
		{RaftStateJoining, true},
		{RaftStateFollowerRole, false},
		{RaftStateCandidateRole, false},
		{RaftStateLeaderRole, false},
		{RaftStateLeavingCluster, true},
		{RaftStateShutdownComplete, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsTransitioning(); got != tt.want {
				t.Errorf("RaftClusterState(%q).IsTransitioning() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestRaftClusterState_IsRaftRole(t *testing.T) {
	tests := []struct {
		state RaftClusterState
		want  bool
	}{
		{RaftStateUninitialized, false},
		{RaftStateBootstrapping, false},
		{RaftStateJoining, false},
		{RaftStateFollowerRole, true},
		{RaftStateCandidateRole, true},
		{RaftStateLeaderRole, true},
		{RaftStateLeavingCluster, false},
		{RaftStateShutdownComplete, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsRaftRole(); got != tt.want {
				t.Errorf("RaftClusterState(%q).IsRaftRole() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestRaftClusterState_CanTransitionTo(t *testing.T) {
	tests := []struct {
		from RaftClusterState
		to   RaftClusterState
		want bool
	}{
		// Same state transitions (idempotency)
		{RaftStateUninitialized, RaftStateUninitialized, true},
		{RaftStateFollowerRole, RaftStateFollowerRole, true},
		{RaftStateLeaderRole, RaftStateLeaderRole, true},

		// From Uninitialized
		{RaftStateUninitialized, RaftStateBootstrapping, true},
		{RaftStateUninitialized, RaftStateJoining, true},
		{RaftStateUninitialized, RaftStateShutdownComplete, true},
		{RaftStateUninitialized, RaftStateFollowerRole, false},
		{RaftStateUninitialized, RaftStateLeaderRole, false},

		// From Bootstrapping
		{RaftStateBootstrapping, RaftStateLeaderRole, true},
		{RaftStateBootstrapping, RaftStateFollowerRole, true},
		{RaftStateBootstrapping, RaftStateShutdownComplete, true},
		{RaftStateBootstrapping, RaftStateJoining, false},

		// From Joining
		{RaftStateJoining, RaftStateFollowerRole, true},
		{RaftStateJoining, RaftStateShutdownComplete, true},
		{RaftStateJoining, RaftStateLeaderRole, false},

		// From Follower
		{RaftStateFollowerRole, RaftStateCandidateRole, true},
		{RaftStateFollowerRole, RaftStateLeavingCluster, true},
		{RaftStateFollowerRole, RaftStateShutdownComplete, true},
		{RaftStateFollowerRole, RaftStateLeaderRole, false},
		{RaftStateFollowerRole, RaftStateBootstrapping, false},

		// From Candidate
		{RaftStateCandidateRole, RaftStateLeaderRole, true},
		{RaftStateCandidateRole, RaftStateFollowerRole, true},
		{RaftStateCandidateRole, RaftStateLeavingCluster, true},
		{RaftStateCandidateRole, RaftStateShutdownComplete, true},
		{RaftStateCandidateRole, RaftStateBootstrapping, false},

		// From Leader
		{RaftStateLeaderRole, RaftStateFollowerRole, true},
		{RaftStateLeaderRole, RaftStateLeavingCluster, true},
		{RaftStateLeaderRole, RaftStateShutdownComplete, true},
		{RaftStateLeaderRole, RaftStateCandidateRole, false},
		{RaftStateLeaderRole, RaftStateBootstrapping, false},

		// From Leaving
		{RaftStateLeavingCluster, RaftStateShutdownComplete, true},
		{RaftStateLeavingCluster, RaftStateFollowerRole, false},
		{RaftStateLeavingCluster, RaftStateLeaderRole, false},

		// From Shutdown (terminal)
		{RaftStateShutdownComplete, RaftStateUninitialized, false},
		{RaftStateShutdownComplete, RaftStateFollowerRole, false},
		{RaftStateShutdownComplete, RaftStateLeaderRole, false},

		// Invalid state
		{RaftClusterState("invalid"), RaftStateFollowerRole, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.from)+"->"+string(tt.to), func(t *testing.T) {
			if got := tt.from.CanTransitionTo(tt.to); got != tt.want {
				t.Errorf("RaftClusterState(%q).CanTransitionTo(%q) = %v, want %v", tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestParseRaftClusterState(t *testing.T) {
	tests := []struct {
		input   string
		want    RaftClusterState
		wantErr bool
	}{
		{"uninitialized", RaftStateUninitialized, false},
		{"bootstrapping", RaftStateBootstrapping, false},
		{"joining", RaftStateJoining, false},
		{"follower", RaftStateFollowerRole, false},
		{"candidate", RaftStateCandidateRole, false},
		{"leader", RaftStateLeaderRole, false},
		{"leaving", RaftStateLeavingCluster, false},
		{"shutdown", RaftStateShutdownComplete, false},
		{"invalid", RaftClusterState(""), true},
		{"", RaftClusterState(""), true},
		{"FOLLOWER", RaftClusterState(""), true}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseRaftClusterState(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRaftClusterState(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseRaftClusterState(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAllRaftClusterStates(t *testing.T) {
	states := AllRaftClusterStates()

	expectedCount := 8
	if len(states) != expectedCount {
		t.Errorf("AllRaftClusterStates() returned %d states, want %d", len(states), expectedCount)
	}

	// Verify all returned states are valid
	for _, state := range states {
		if !state.IsValid() {
			t.Errorf("AllRaftClusterStates() returned invalid state: %q", state)
		}
	}

	// Verify expected states are present
	expectedStates := []RaftClusterState{
		RaftStateUninitialized,
		RaftStateBootstrapping,
		RaftStateJoining,
		RaftStateFollowerRole,
		RaftStateCandidateRole,
		RaftStateLeaderRole,
		RaftStateLeavingCluster,
		RaftStateShutdownComplete,
	}

	for _, expected := range expectedStates {
		found := false
		for _, state := range states {
			if state == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllRaftClusterStates() missing expected state: %q", expected)
		}
	}
}

func TestRaftClusterStatus_Uptime(t *testing.T) {
	t.Run("returns duration since start time", func(t *testing.T) {
		startTime := time.Now().Add(-1 * time.Hour)
		status := RaftClusterStatus{
			State:     RaftStateFollowerRole,
			StartTime: startTime,
		}

		uptime := status.Uptime()

		// Allow some tolerance for test execution time
		if uptime < 59*time.Minute || uptime > 61*time.Minute {
			t.Errorf("Uptime() = %v, expected approximately 1 hour", uptime)
		}
	})

	t.Run("returns zero for zero start time", func(t *testing.T) {
		status := RaftClusterStatus{
			State:     RaftStateFollowerRole,
			StartTime: time.Time{},
		}

		uptime := status.Uptime()
		if uptime != 0 {
			t.Errorf("Uptime() = %v, want 0 for zero start time", uptime)
		}
	})
}

func TestRaftClusterStatus_IsHealthy(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		state         RaftClusterState
		lastHeartbeat time.Time
		want          bool
	}{
		{
			name:          "leader is healthy when operational",
			state:         RaftStateLeaderRole,
			lastHeartbeat: now.Add(-1 * time.Minute),
			want:          true,
		},
		{
			name:          "leader is healthy even without recent heartbeat",
			state:         RaftStateLeaderRole,
			lastHeartbeat: now.Add(-1 * time.Hour),
			want:          true,
		},
		{
			name:          "follower is healthy with recent heartbeat",
			state:         RaftStateFollowerRole,
			lastHeartbeat: now.Add(-10 * time.Second),
			want:          true,
		},
		{
			name:          "follower is unhealthy without recent heartbeat",
			state:         RaftStateFollowerRole,
			lastHeartbeat: now.Add(-1 * time.Minute),
			want:          false,
		},
		{
			name:          "candidate is healthy with recent heartbeat",
			state:         RaftStateCandidateRole,
			lastHeartbeat: now.Add(-10 * time.Second),
			want:          true,
		},
		{
			name:          "non-operational state is unhealthy",
			state:         RaftStateBootstrapping,
			lastHeartbeat: now,
			want:          false,
		},
		{
			name:          "uninitialized is unhealthy",
			state:         RaftStateUninitialized,
			lastHeartbeat: now,
			want:          false,
		},
		{
			name:          "shutdown is unhealthy",
			state:         RaftStateShutdownComplete,
			lastHeartbeat: now,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := RaftClusterStatus{
				State:         tt.state,
				LastHeartbeat: tt.lastHeartbeat,
			}

			if got := status.IsHealthy(); got != tt.want {
				t.Errorf("RaftClusterStatus.IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRaftStateManager(t *testing.T) {
	sm := NewRaftStateManager()

	if sm == nil {
		t.Fatal("NewRaftStateManager() returned nil")
	}

	state := sm.GetState()
	if state != RaftStateUninitialized {
		t.Errorf("initial state = %q, want %q", state, RaftStateUninitialized)
	}

	status := sm.GetStatus()
	if status.State != RaftStateUninitialized {
		t.Errorf("initial status state = %q, want %q", status.State, RaftStateUninitialized)
	}

	if status.StartTime.IsZero() {
		t.Error("initial start time should be set")
	}
}

func TestRaftStateManager_GetState(t *testing.T) {
	sm := NewRaftStateManager()

	state := sm.GetState()
	if state != RaftStateUninitialized {
		t.Errorf("GetState() = %q, want %q", state, RaftStateUninitialized)
	}
}

func TestRaftStateManager_SetState(t *testing.T) {
	t.Run("valid transition succeeds", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		err := sm.SetState(ctx, RaftStateBootstrapping)
		if err != nil {
			t.Fatalf("SetState() error = %v", err)
		}

		if state := sm.GetState(); state != RaftStateBootstrapping {
			t.Errorf("GetState() = %q, want %q", state, RaftStateBootstrapping)
		}
	})

	t.Run("invalid transition fails", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		err := sm.SetState(ctx, RaftStateFollowerRole)
		if err == nil {
			t.Error("SetState() expected error for invalid transition")
		}

		_, ok := err.(ErrInvalidStateTransition)
		if !ok {
			t.Errorf("expected ErrInvalidStateTransition, got %T", err)
		}
	})

	t.Run("invalid state fails", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		err := sm.SetState(ctx, RaftClusterState("invalid"))
		if err == nil {
			t.Error("SetState() expected error for invalid state")
		}
	})

	t.Run("cancelled context fails", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := sm.SetState(ctx, RaftStateBootstrapping)
		if err == nil {
			t.Error("SetState() expected error for cancelled context")
		}

		_, ok := err.(ErrContextCancelled)
		if !ok {
			t.Errorf("expected ErrContextCancelled, got %T", err)
		}
	})

	t.Run("updates status state", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		_ = sm.SetState(ctx, RaftStateBootstrapping)
		_ = sm.SetState(ctx, RaftStateLeaderRole)

		status := sm.GetStatus()
		if status.State != RaftStateLeaderRole {
			t.Errorf("status state = %q, want %q", status.State, RaftStateLeaderRole)
		}
	})
}

func TestRaftStateManager_GetStatus(t *testing.T) {
	sm := NewRaftStateManager()

	status := sm.GetStatus()

	if status.State != RaftStateUninitialized {
		t.Errorf("status.State = %q, want %q", status.State, RaftStateUninitialized)
	}

	if status.StartTime.IsZero() {
		t.Error("status.StartTime should be set")
	}
}

func TestRaftStateManager_UpdateStatus(t *testing.T) {
	t.Run("updates status fields", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		err := sm.UpdateStatus(ctx, func(s *RaftClusterStatus) {
			s.NodeID = 42
			s.LeaderID = 1
			s.Term = 5
			s.NodeCount = 3
			s.HealthyCount = 3
		})

		if err != nil {
			t.Fatalf("UpdateStatus() error = %v", err)
		}

		status := sm.GetStatus()
		if status.NodeID != 42 {
			t.Errorf("status.NodeID = %d, want 42", status.NodeID)
		}
		if status.LeaderID != 1 {
			t.Errorf("status.LeaderID = %d, want 1", status.LeaderID)
		}
		if status.Term != 5 {
			t.Errorf("status.Term = %d, want 5", status.Term)
		}
	})

	t.Run("cancelled context fails", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := sm.UpdateStatus(ctx, func(s *RaftClusterStatus) {
			s.NodeID = 42
		})

		if err == nil {
			t.Error("UpdateStatus() expected error for cancelled context")
		}
	})

	t.Run("maintains state consistency", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		// Set state first
		_ = sm.SetState(ctx, RaftStateBootstrapping)

		// Update status should not change the state
		_ = sm.UpdateStatus(ctx, func(s *RaftClusterStatus) {
			s.State = RaftStateLeaderRole // Try to change state
		})

		// State should remain consistent with SetState
		status := sm.GetStatus()
		if status.State != RaftStateBootstrapping {
			t.Errorf("status.State = %q, want %q (state should be preserved)", status.State, RaftStateBootstrapping)
		}
	})
}

func TestRaftStateManager_WaitForState(t *testing.T) {
	t.Run("returns immediately if already in state", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		err := sm.WaitForState(ctx, RaftStateUninitialized)
		if err != nil {
			t.Errorf("WaitForState() error = %v", err)
		}
	})

	t.Run("waits for state transition", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		done := make(chan error, 1)
		go func() {
			done <- sm.WaitForState(ctx, RaftStateBootstrapping)
		}()

		// Give the waiter time to register
		time.Sleep(10 * time.Millisecond)

		// Transition to the target state
		_ = sm.SetState(ctx, RaftStateBootstrapping)

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("WaitForState() error = %v", err)
			}
		case <-time.After(1 * time.Second):
			t.Error("WaitForState() timed out")
		}
	})

	t.Run("returns error on context cancellation", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() {
			done <- sm.WaitForState(ctx, RaftStateLeaderRole)
		}()

		// Give the waiter time to register
		time.Sleep(10 * time.Millisecond)

		cancel()

		select {
		case err := <-done:
			if err == nil {
				t.Error("WaitForState() expected error on cancellation")
			}
			_, ok := err.(ErrContextCancelled)
			if !ok {
				t.Errorf("expected ErrContextCancelled, got %T", err)
			}
		case <-time.After(1 * time.Second):
			t.Error("WaitForState() timed out waiting for cancellation")
		}
	})
}

func TestRaftStateManager_OnStateChange(t *testing.T) {
	t.Run("callback is invoked on state change", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		var callbackFrom, callbackTo RaftClusterState
		called := make(chan struct{}, 1)

		_ = sm.OnStateChange(func(from, to RaftClusterState) {
			callbackFrom = from
			callbackTo = to
			called <- struct{}{}
		})

		_ = sm.SetState(ctx, RaftStateBootstrapping)

		select {
		case <-called:
			if callbackFrom != RaftStateUninitialized {
				t.Errorf("callback from = %q, want %q", callbackFrom, RaftStateUninitialized)
			}
			if callbackTo != RaftStateBootstrapping {
				t.Errorf("callback to = %q, want %q", callbackTo, RaftStateBootstrapping)
			}
		case <-time.After(1 * time.Second):
			t.Error("callback was not invoked")
		}
	})

	t.Run("unregister prevents future callbacks", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		callCount := 0
		unregister := sm.OnStateChange(func(from, to RaftClusterState) {
			callCount++
		})

		_ = sm.SetState(ctx, RaftStateBootstrapping)
		if callCount != 1 {
			t.Errorf("callback count = %d, want 1", callCount)
		}

		unregister()

		_ = sm.SetState(ctx, RaftStateLeaderRole)
		if callCount != 1 {
			t.Errorf("callback count after unregister = %d, want 1", callCount)
		}
	})

	t.Run("multiple callbacks are invoked", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		callCount1 := 0
		callCount2 := 0

		sm.OnStateChange(func(from, to RaftClusterState) {
			callCount1++
		})

		sm.OnStateChange(func(from, to RaftClusterState) {
			callCount2++
		})

		_ = sm.SetState(ctx, RaftStateBootstrapping)

		if callCount1 != 1 {
			t.Errorf("callback1 count = %d, want 1", callCount1)
		}
		if callCount2 != 1 {
			t.Errorf("callback2 count = %d, want 1", callCount2)
		}
	})
}

func TestRaftStateManager_Concurrent(t *testing.T) {
	t.Run("concurrent state reads are safe", func(t *testing.T) {
		sm := NewRaftStateManager()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sm.GetState()
				_ = sm.GetStatus()
			}()
		}
		wg.Wait()
	})

	t.Run("concurrent state updates are safe", func(t *testing.T) {
		sm := NewRaftStateManager()
		ctx := context.Background()

		var wg sync.WaitGroup

		// Multiple goroutines updating status
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_ = sm.UpdateStatus(ctx, func(s *RaftClusterStatus) {
					s.NodeCount = idx
				})
			}(i)
		}

		// Multiple goroutines reading
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sm.GetState()
				_ = sm.GetStatus()
			}()
		}

		wg.Wait()
	})

	t.Run("concurrent callback registration is safe", func(t *testing.T) {
		sm := NewRaftStateManager()

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				unregister := sm.OnStateChange(func(from, to RaftClusterState) {})
				unregister()
			}()
		}
		wg.Wait()
	})
}
