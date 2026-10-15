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

package compute

import (
	"fmt"
	"sync"
	"time"
)

// InstanceState represents the lifecycle state of a compute instance
type InstanceState string

const (
	// StateUnknown represents an unknown or uninitialized state
	StateUnknown InstanceState = "unknown"

	// StateCreating represents an instance being created
	StateCreating InstanceState = "creating"

	// StateStopped represents a stopped instance
	StateStopped InstanceState = "stopped"

	// StateStarting represents an instance in the process of starting
	StateStarting InstanceState = "starting"

	// StateRunning represents a running instance
	StateRunning InstanceState = "running"

	// StateStopping represents an instance in the process of stopping
	StateStopping InstanceState = "stopping"

	// StateError represents an instance in an error state
	StateError InstanceState = "error"

	// StateDeleting represents an instance being deleted
	StateDeleting InstanceState = "deleting"

	// StateSuspended represents a VM whose vCPUs are paused in memory; it
	// resumes where it stopped
	StateSuspended InstanceState = "suspended"
)

// String returns the string representation of InstanceState
func (s InstanceState) String() string {
	return string(s)
}

// IsValid checks if the InstanceState is valid
func (s InstanceState) IsValid() bool {
	switch s {
	case StateUnknown, StateCreating, StateStopped, StateStarting,
		StateRunning, StateStopping, StateError, StateDeleting, StateSuspended:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if the state is terminal (no further transitions expected)
func (s InstanceState) IsTerminal() bool {
	return s == StateError || s == StateDeleting
}

// CanTransitionTo checks if the current state can transition to the target state
func (s InstanceState) CanTransitionTo(target InstanceState) bool {
	// An instance in error can still be deleted; nothing else leaves a
	// terminal state.
	if s == StateError && target == StateDeleting {
		return true
	}
	if s.IsTerminal() {
		return false
	}

	// Valid state transitions
	validTransitions := map[InstanceState][]InstanceState{
		StateUnknown:   {StateCreating, StateError},
		StateCreating:  {StateStopped, StateError},
		StateStopped:   {StateStarting, StateDeleting, StateError},
		StateStarting:  {StateRunning, StateError},
		StateRunning:   {StateStopping, StateSuspended, StateError},
		StateSuspended: {StateRunning, StateStopping, StateError},
		StateStopping:  {StateStopped, StateError},
		StateError:     {}, // Terminal state
		StateDeleting:  {}, // Terminal state
	}

	allowed, exists := validTransitions[s]
	if !exists {
		return false
	}

	for _, allowedState := range allowed {
		if allowedState == target {
			return true
		}
	}

	return false
}

// LifecycleManager manages instance state transitions
type LifecycleManager struct {
	mu         sync.RWMutex
	states     map[string]InstanceState
	timestamps map[string]time.Time
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager() *LifecycleManager {
	return &LifecycleManager{
		states:     make(map[string]InstanceState),
		timestamps: make(map[string]time.Time),
	}
}

// SetState sets the state for an instance
func (lm *LifecycleManager) SetState(instanceID string, state InstanceState) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if !state.IsValid() {
		return &SentinelCauseError{Sentinel: ErrInvalidState, Cause: &MessageError{Msg: string(state)}}
	}

	// Check if transition is valid
	currentState, exists := lm.states[instanceID]
	if exists && !currentState.CanTransitionTo(state) {
		return &SentinelCauseError{Sentinel: ErrInvalidState, Cause: &MessageError{Msg: fmt.Sprintf("cannot transition from %s to %s", currentState, state)}}
	}

	lm.states[instanceID] = state
	lm.timestamps[instanceID] = time.Now()

	return nil
}

// GetState returns the current state of an instance
func (lm *LifecycleManager) GetState(instanceID string) (InstanceState, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if instanceID == "" {
		return StateUnknown, ErrInvalidInstanceID
	}

	state, exists := lm.states[instanceID]
	if !exists {
		return StateUnknown, ErrInstanceNotFound
	}

	return state, nil
}

// GetStateTimestamp returns when the instance last changed state
func (lm *LifecycleManager) GetStateTimestamp(instanceID string) (time.Time, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if instanceID == "" {
		return time.Time{}, ErrInvalidInstanceID
	}

	ts, exists := lm.timestamps[instanceID]
	if !exists {
		return time.Time{}, ErrInstanceNotFound
	}

	return ts, nil
}

// DeleteInstance removes an instance from the lifecycle manager
func (lm *LifecycleManager) DeleteInstance(instanceID string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if _, exists := lm.states[instanceID]; !exists {
		return ErrInstanceNotFound
	}

	delete(lm.states, instanceID)
	delete(lm.timestamps, instanceID)

	return nil
}

// ListInstances returns all instance IDs and their states
func (lm *LifecycleManager) ListInstances() map[string]InstanceState {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	result := make(map[string]InstanceState, len(lm.states))
	for id, state := range lm.states {
		result[id] = state
	}

	return result
}

// WaitForState waits for an instance to reach a specific state or timeout
func (lm *LifecycleManager) WaitForState(instanceID string, targetState InstanceState, timeout time.Duration) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if !targetState.IsValid() {
		return &SentinelCauseError{Sentinel: ErrInvalidState, Cause: &MessageError{Msg: string(targetState)}}
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeoutCh := time.After(timeout)

	for {
		select {
		case <-ticker.C:
			state, err := lm.GetState(instanceID)
			if err != nil {
				return err
			}
			if state == targetState {
				return nil
			}
			if state == StateError {
				return &SentinelCauseError{Sentinel: ErrInvalidState, Cause: &MessageError{Msg: fmt.Sprintf("instance entered error state while waiting for %s", targetState)}}
			}
		case <-timeoutCh:
			return ErrTimeout
		}
	}
}
