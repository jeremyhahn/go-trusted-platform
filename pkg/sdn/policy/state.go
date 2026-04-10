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

package policy

import (
	"sync"
	"time"
)

// PortStateMachine manages port authentication state transitions
type PortStateMachine struct {
	mu    sync.RWMutex
	ports map[string]*PortInfo
}

// NewPortStateMachine creates a new port state machine
func NewPortStateMachine() *PortStateMachine {
	return &PortStateMachine{
		ports: make(map[string]*PortInfo),
	}
}

// GetState returns the current state of a port
func (sm *PortStateMachine) GetState(portID string) (PortState, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	info, exists := sm.ports[portID]
	if !exists {
		return PortStateUnconnected, ErrPortNotFound
	}

	return info.State, nil
}

// SetState transitions a port to a new state
func (sm *PortStateMachine) SetState(portID string, state PortState) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	info, exists := sm.ports[portID]
	if !exists {
		// Create new port entry with unconnected state
		info = &PortInfo{
			PortID:          portID,
			State:           PortStateUnconnected,
			LastStateChange: time.Now(),
		}
		sm.ports[portID] = info
	}

	// Validate state transition
	if err := sm.validateTransition(info.State, state); err != nil {
		return err
	}

	info.State = state
	info.LastStateChange = time.Now()

	return nil
}

// GetInfo returns detailed information about a port
func (sm *PortStateMachine) GetInfo(portID string) (*PortInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	info, exists := sm.ports[portID]
	if !exists {
		return nil, ErrPortNotFound
	}

	// Return a copy to prevent external modifications
	infoCopy := *info
	if info.Policy != nil {
		policyCopy := *info.Policy
		infoCopy.Policy = &policyCopy
	}

	return &infoCopy, nil
}

// SetPolicy sets the policy for a port
func (sm *PortStateMachine) SetPolicy(portID string, policy *PortPolicy) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	info, exists := sm.ports[portID]
	if !exists {
		info = &PortInfo{
			PortID:          portID,
			State:           PortStateUnconnected,
			LastStateChange: time.Now(),
		}
		sm.ports[portID] = info
	}

	info.Policy = policy

	return nil
}

// RemovePort removes a port from the state machine
func (sm *PortStateMachine) RemovePort(portID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.ports[portID]; !exists {
		return ErrPortNotFound
	}

	delete(sm.ports, portID)

	return nil
}

// ListPorts returns all port IDs
func (sm *PortStateMachine) ListPorts() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ports := make([]string, 0, len(sm.ports))
	for portID := range sm.ports {
		ports = append(ports, portID)
	}

	return ports
}

// IncrementAuthAttempts increments the authentication attempt counter
func (sm *PortStateMachine) IncrementAuthAttempts(portID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	info, exists := sm.ports[portID]
	if !exists {
		return ErrPortNotFound
	}

	info.AuthAttempts++
	info.LastAuthAttempt = time.Now()

	return nil
}

// RecordError records an error for a port
func (sm *PortStateMachine) RecordError(portID string, err error) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	info, exists := sm.ports[portID]
	if !exists {
		return ErrPortNotFound
	}

	info.ErrorCount++
	if err != nil {
		info.LastError = err.Error()
	}

	return nil
}

// validateTransition validates if a state transition is allowed
func (sm *PortStateMachine) validateTransition(current, next PortState) error {
	// Define valid state transitions
	validTransitions := map[PortState][]PortState{
		PortStateUnconnected: {
			PortStateProvisioning,
			PortStateBlocked,
		},
		PortStateProvisioning: {
			PortStateEnrolled, // NEW: After enrollment, before activation
			PortStateUnauthorized,
			PortStateAuthenticating,
			PortStateAuthorized,
			PortStateBlocked,
		},
		PortStateEnrolled: { // NEW: Add this section
			PortStateAuthorized,   // After client activates
			PortStateProvisioning, // Re-enroll
			PortStateBlocked,      // If blocked
		},
		PortStateUnauthorized: {
			PortStateAuthenticating,
			PortStateProvisioning, // Allow re-provisioning
			PortStateBlocked,
		},
		PortStateAuthenticating: {
			PortStateAuthorized,
			PortStateUnauthorized,
			PortStateBlocked,
		},
		PortStateAuthorized: {
			PortStateUnauthorized,
			PortStateQuarantined, // Can be quarantined for scanning
			PortStateBlocked,
		},
		PortStateQuarantined: {
			PortStateAuthorized,   // After successful remediation
			PortStateBlocked,      // If remediation fails
			PortStateProvisioning, // Re-enroll
		},
		PortStateBlocked: {
			PortStateUnconnected,  // Admin reset
			PortStateProvisioning, // Admin allows re-enrollment
		},
	}

	// Allow same-state transitions (for idempotency)
	if current == next {
		return nil
	}

	allowed := validTransitions[current]
	for _, s := range allowed {
		if s == next {
			return nil
		}
	}

	return ErrInvalidState
}
