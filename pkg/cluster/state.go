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
	"sync/atomic"
	"time"
)

// RaftClusterState represents the Raft-specific lifecycle state of a cluster node.
// This type provides extended state values beyond the base ClusterState defined
// in coordinator.go for more granular Raft state tracking.
type RaftClusterState string

const (
	// RaftStateUninitialized indicates the cluster has not yet been bootstrapped.
	RaftStateUninitialized RaftClusterState = "uninitialized"

	// RaftStateBootstrapping indicates the cluster is being initialized.
	RaftStateBootstrapping RaftClusterState = "bootstrapping"

	// RaftStateJoining indicates the node is joining an existing cluster.
	RaftStateJoining RaftClusterState = "joining"

	// RaftStateFollowerRole indicates the node is a Raft follower.
	RaftStateFollowerRole RaftClusterState = "follower"

	// RaftStateCandidateRole indicates the node is running for leader election.
	RaftStateCandidateRole RaftClusterState = "candidate"

	// RaftStateLeaderRole indicates the node is the Raft leader.
	RaftStateLeaderRole RaftClusterState = "leader"

	// RaftStateLeavingCluster indicates the node is gracefully leaving the cluster.
	RaftStateLeavingCluster RaftClusterState = "leaving"

	// RaftStateShutdownComplete indicates the node has shut down.
	RaftStateShutdownComplete RaftClusterState = "shutdown"
)

// validRaftClusterStates contains all valid Raft cluster state values for quick lookup.
var validRaftClusterStates = map[RaftClusterState]struct{}{
	RaftStateUninitialized:    {},
	RaftStateBootstrapping:    {},
	RaftStateJoining:          {},
	RaftStateFollowerRole:     {},
	RaftStateCandidateRole:    {},
	RaftStateLeaderRole:       {},
	RaftStateLeavingCluster:   {},
	RaftStateShutdownComplete: {},
}

// validRaftClusterTransitions defines allowed state transitions for Raft cluster lifecycle.
var validRaftClusterTransitions = map[RaftClusterState][]RaftClusterState{
	RaftStateUninitialized: {
		RaftStateBootstrapping,    // Node starts cluster bootstrap
		RaftStateJoining,          // Node joins existing cluster
		RaftStateShutdownComplete, // Node shuts down before initialization
	},
	RaftStateBootstrapping: {
		RaftStateLeaderRole,       // Successfully bootstrapped as leader
		RaftStateFollowerRole,     // Bootstrapped but another node became leader
		RaftStateShutdownComplete, // Bootstrap failed or cancelled
	},
	RaftStateJoining: {
		RaftStateFollowerRole,     // Successfully joined as follower
		RaftStateShutdownComplete, // Join failed or cancelled
	},
	RaftStateFollowerRole: {
		RaftStateCandidateRole,    // Follower starts election
		RaftStateLeavingCluster,   // Follower initiates graceful leave
		RaftStateShutdownComplete, // Follower shuts down
	},
	RaftStateCandidateRole: {
		RaftStateLeaderRole,       // Won election
		RaftStateFollowerRole,     // Lost election or stepped down
		RaftStateLeavingCluster,   // Candidate initiates graceful leave
		RaftStateShutdownComplete, // Candidate shuts down
	},
	RaftStateLeaderRole: {
		RaftStateFollowerRole,     // Leader steps down
		RaftStateLeavingCluster,   // Leader initiates graceful leave
		RaftStateShutdownComplete, // Leader shuts down
	},
	RaftStateLeavingCluster: {
		RaftStateShutdownComplete, // Leave completed
	},
	RaftStateShutdownComplete: {
		// Terminal state - no transitions allowed
	},
}

// String returns the string representation of the Raft cluster state.
func (s RaftClusterState) String() string {
	return string(s)
}

// IsValid checks if the Raft cluster state is a valid state value.
func (s RaftClusterState) IsValid() bool {
	_, exists := validRaftClusterStates[s]
	return exists
}

// IsTerminal checks if the state is a terminal state with no further transitions.
func (s RaftClusterState) IsTerminal() bool {
	return s == RaftStateShutdownComplete
}

// IsOperational checks if the node is in an operational state capable of
// participating in cluster operations.
func (s RaftClusterState) IsOperational() bool {
	return s == RaftStateFollowerRole || s == RaftStateCandidateRole || s == RaftStateLeaderRole
}

// IsTransitioning checks if the node is in a transitional state.
func (s RaftClusterState) IsTransitioning() bool {
	return s == RaftStateBootstrapping || s == RaftStateJoining || s == RaftStateLeavingCluster
}

// IsRaftRole checks if the state represents a Raft role.
func (s RaftClusterState) IsRaftRole() bool {
	return s == RaftStateFollowerRole || s == RaftStateCandidateRole || s == RaftStateLeaderRole
}

// CanTransitionTo checks if transitioning from the current state to the
// target state is allowed.
func (s RaftClusterState) CanTransitionTo(target RaftClusterState) bool {
	// Same-state transitions are allowed for idempotency
	if s == target {
		return true
	}

	allowed, exists := validRaftClusterTransitions[s]
	if !exists {
		return false
	}

	for _, valid := range allowed {
		if valid == target {
			return true
		}
	}

	return false
}

// ParseRaftClusterState parses a string into a RaftClusterState value.
// Returns an error if the string does not represent a valid state.
func ParseRaftClusterState(s string) (RaftClusterState, error) {
	state := RaftClusterState(s)
	if !state.IsValid() {
		return "", ErrInvalidClusterState{State: ClusterState(state)}
	}
	return state, nil
}

// AllRaftClusterStates returns all valid Raft cluster states.
func AllRaftClusterStates() []RaftClusterState {
	return []RaftClusterState{
		RaftStateUninitialized,
		RaftStateBootstrapping,
		RaftStateJoining,
		RaftStateFollowerRole,
		RaftStateCandidateRole,
		RaftStateLeaderRole,
		RaftStateLeavingCluster,
		RaftStateShutdownComplete,
	}
}

// RaftClusterStatus represents the current status of a Raft cluster node including
// consensus information and health metrics.
type RaftClusterStatus struct {
	// State is the current Raft cluster state of this node.
	State RaftClusterState

	// NodeID is the unique identifier for this node in the cluster.
	NodeID uint64

	// LeaderID is the node ID of the current Raft leader.
	// Zero if no leader is known.
	LeaderID uint64

	// Term is the current Raft term number.
	Term uint64

	// CommitIndex is the highest log entry known to be committed.
	CommitIndex uint64

	// AppliedIndex is the highest log entry applied to the state machine.
	AppliedIndex uint64

	// NodeCount is the total number of nodes in the cluster.
	NodeCount int

	// HealthyCount is the number of healthy nodes in the cluster.
	HealthyCount int

	// LastHeartbeat is the timestamp of the last received heartbeat.
	LastHeartbeat time.Time

	// StartTime is when this node started.
	StartTime time.Time
}

// Uptime returns the duration since the node started.
func (s *RaftClusterStatus) Uptime() time.Duration {
	if s.StartTime.IsZero() {
		return 0
	}
	return time.Since(s.StartTime)
}

// IsHealthy returns true if the cluster node is considered healthy.
// A node is healthy if it is operational and has received a heartbeat
// within the last 30 seconds.
func (s *RaftClusterStatus) IsHealthy() bool {
	if !s.State.IsOperational() {
		return false
	}

	// Leader nodes are always considered healthy if operational
	if s.State == RaftStateLeaderRole {
		return true
	}

	// Followers and candidates must have recent heartbeat
	heartbeatTimeout := 30 * time.Second
	return time.Since(s.LastHeartbeat) < heartbeatTimeout
}

// RaftStateManager defines the interface for managing Raft cluster state transitions.
type RaftStateManager interface {
	// GetState returns the current Raft cluster state.
	GetState() RaftClusterState

	// SetState transitions to a new state if the transition is valid.
	// Returns an error if the transition is not allowed.
	SetState(ctx context.Context, state RaftClusterState) error

	// GetStatus returns the current Raft cluster status.
	GetStatus() RaftClusterStatus

	// UpdateStatus atomically updates the Raft cluster status fields.
	// The update function receives the current status and returns the modified status.
	UpdateStatus(ctx context.Context, update func(*RaftClusterStatus)) error

	// WaitForState blocks until the cluster reaches the specified state or context is cancelled.
	WaitForState(ctx context.Context, target RaftClusterState) error

	// OnStateChange registers a callback to be invoked when state changes.
	// Returns a function that can be called to unregister the callback.
	OnStateChange(callback RaftStateChangeCallback) (unregister func())
}

// RaftStateChangeCallback is a function invoked when Raft cluster state changes.
type RaftStateChangeCallback func(from, to RaftClusterState)

// raftStateManager provides a thread-safe implementation of RaftStateManager
// using atomic operations where possible.
type raftStateManager struct {
	state  atomic.Value // RaftClusterState
	status atomic.Value // RaftClusterStatus

	// mu protects callbacks and status updates that require consistency
	mu        sync.RWMutex
	callbacks map[uint64]RaftStateChangeCallback
	nextID    uint64

	// waiters is used for WaitForState coordination
	waiters sync.Map // map[RaftClusterState][]chan struct{}
}

// NewRaftStateManager creates a new RaftStateManager with the initial state set to Uninitialized.
func NewRaftStateManager() RaftStateManager {
	sm := &raftStateManager{
		callbacks: make(map[uint64]RaftStateChangeCallback),
	}
	sm.state.Store(RaftStateUninitialized)
	sm.status.Store(RaftClusterStatus{
		State:     RaftStateUninitialized,
		StartTime: time.Now(),
	})
	return sm
}

// GetState returns the current Raft cluster state.
func (sm *raftStateManager) GetState() RaftClusterState {
	return sm.state.Load().(RaftClusterState)
}

// SetState transitions to a new state if the transition is valid.
func (sm *raftStateManager) SetState(ctx context.Context, newState RaftClusterState) error {
	if ctx.Err() != nil {
		return ErrContextCancelled{Err: ctx.Err()}
	}

	if !newState.IsValid() {
		return ErrInvalidClusterState{State: ClusterState(newState)}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	currentState := sm.state.Load().(RaftClusterState)

	if !currentState.CanTransitionTo(newState) {
		return ErrInvalidStateTransition{From: ClusterState(currentState), To: ClusterState(newState)}
	}

	// Update state atomically
	sm.state.Store(newState)

	// Update status with new state
	status := sm.status.Load().(RaftClusterStatus)
	status.State = newState
	sm.status.Store(status)

	// Notify waiters for this state
	sm.notifyWaiters(newState)

	// Invoke callbacks
	for _, cb := range sm.callbacks {
		cb(currentState, newState)
	}

	return nil
}

// GetStatus returns the current Raft cluster status.
func (sm *raftStateManager) GetStatus() RaftClusterStatus {
	return sm.status.Load().(RaftClusterStatus)
}

// UpdateStatus atomically updates the Raft cluster status fields.
func (sm *raftStateManager) UpdateStatus(ctx context.Context, update func(*RaftClusterStatus)) error {
	if ctx.Err() != nil {
		return ErrContextCancelled{Err: ctx.Err()}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	status := sm.status.Load().(RaftClusterStatus)
	update(&status)
	// Ensure state consistency
	status.State = sm.state.Load().(RaftClusterState)
	sm.status.Store(status)

	return nil
}

// WaitForState blocks until the cluster reaches the specified state or context is cancelled.
func (sm *raftStateManager) WaitForState(ctx context.Context, target RaftClusterState) error {
	// Check if already in target state
	if sm.GetState() == target {
		return nil
	}

	// Create a channel to wait on
	ch := make(chan struct{}, 1)

	// Register the waiter
	sm.mu.Lock()
	key := target
	actual, loaded := sm.waiters.Load(key)
	var waiters []chan struct{}
	if loaded {
		waiters = actual.([]chan struct{})
	}
	waiters = append(waiters, ch)
	sm.waiters.Store(key, waiters)
	sm.mu.Unlock()

	// Wait for state change or context cancellation
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ErrContextCancelled{Err: ctx.Err()}
	}
}

// OnStateChange registers a callback to be invoked when state changes.
func (sm *raftStateManager) OnStateChange(callback RaftStateChangeCallback) (unregister func()) {
	sm.mu.Lock()
	id := sm.nextID
	sm.nextID++
	sm.callbacks[id] = callback
	sm.mu.Unlock()

	return func() {
		sm.mu.Lock()
		delete(sm.callbacks, id)
		sm.mu.Unlock()
	}
}

// notifyWaiters notifies all goroutines waiting for the given state.
// Must be called with mu held.
func (sm *raftStateManager) notifyWaiters(state RaftClusterState) {
	if value, ok := sm.waiters.Load(state); ok {
		waiters := value.([]chan struct{})
		for _, ch := range waiters {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		sm.waiters.Delete(state)
	}
}
