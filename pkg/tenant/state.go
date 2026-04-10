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

package tenant

// State represents the lifecycle state of a tenant.
type State string

const (
	// StateCreated indicates the tenant has been created but not yet activated.
	StateCreated State = "created"

	// StateActive indicates the tenant is fully operational.
	StateActive State = "active"

	// StateSuspended indicates the tenant is temporarily suspended.
	StateSuspended State = "suspended"

	// StateDeleting indicates the tenant is being deleted.
	StateDeleting State = "deleting"

	// StateDeleted indicates the tenant has been deleted.
	StateDeleted State = "deleted"
)

// ValidTransitions defines the allowed state transitions for tenant lifecycle.
// The map key is the current state and the value is a list of valid target states.
var ValidTransitions = map[State][]State{
	StateCreated: {
		StateActive,   // Tenant is activated after initial setup
		StateDeleting, // Tenant can be deleted before activation
	},
	StateActive: {
		StateSuspended, // Tenant can be suspended for various reasons
		StateDeleting,  // Tenant can be deleted when active
	},
	StateSuspended: {
		StateActive,   // Tenant can be reactivated
		StateDeleting, // Tenant can be deleted while suspended
	},
	StateDeleting: {
		StateDeleted, // Deletion completes
	},
	StateDeleted: {
		// No transitions allowed from deleted state
	},
}

// validStates contains all valid state values for quick lookup.
var validStates = map[State]struct{}{
	StateCreated:   {},
	StateActive:    {},
	StateSuspended: {},
	StateDeleting:  {},
	StateDeleted:   {},
}

// CanTransitionTo checks if transitioning from the current state to the target state is allowed.
func (s State) CanTransitionTo(target State) bool {
	// Same-state transitions are allowed for idempotency
	if s == target {
		return true
	}

	allowed, exists := ValidTransitions[s]
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

// String returns the string representation of the state.
func (s State) String() string {
	return string(s)
}

// IsValid checks if the state is a valid tenant state.
func (s State) IsValid() bool {
	_, exists := validStates[s]
	return exists
}

// IsTerminal checks if the state is a terminal state (no further transitions).
func (s State) IsTerminal() bool {
	return s == StateDeleted
}

// IsOperational checks if the tenant is in an operational state.
func (s State) IsOperational() bool {
	return s == StateActive
}

// AllowsResourceCreation checks if resources can be created in this state.
func (s State) AllowsResourceCreation() bool {
	return s == StateActive
}

// AllowsResourceDeletion checks if resources can be deleted in this state.
func (s State) AllowsResourceDeletion() bool {
	return s == StateActive || s == StateDeleting
}

// ParseState parses a string into a State value.
// Returns an error if the string does not represent a valid state.
func ParseState(s string) (State, error) {
	state := State(s)
	if !state.IsValid() {
		return "", ErrInvalidState{Current: state}
	}
	return state, nil
}

// AllStates returns all valid tenant states.
func AllStates() []State {
	return []State{
		StateCreated,
		StateActive,
		StateSuspended,
		StateDeleting,
		StateDeleted,
	}
}

// TransitionableStates returns states that can be transitioned from.
func TransitionableStates() []State {
	return []State{
		StateCreated,
		StateActive,
		StateSuspended,
		StateDeleting,
	}
}
