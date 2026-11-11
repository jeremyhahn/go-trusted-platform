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

import (
	"errors"
	"testing"
)

func TestState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected string
	}{
		{"created", StateCreated, "created"},
		{"active", StateActive, "active"},
		{"suspended", StateSuspended, "suspended"},
		{"deleting", StateDeleting, "deleting"},
		{"deleted", StateDeleted, "deleted"},
		{"custom state", State("custom"), "custom"},
		{"empty state", State(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("State.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestState_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected bool
	}{
		{"created is valid", StateCreated, true},
		{"active is valid", StateActive, true},
		{"suspended is valid", StateSuspended, true},
		{"deleting is valid", StateDeleting, true},
		{"deleted is valid", StateDeleted, true},
		{"unknown is invalid", State("unknown"), false},
		{"empty is invalid", State(""), false},
		{"random is invalid", State("random-state"), false},
		{"uppercase is invalid", State("ACTIVE"), false},
		{"mixed case is invalid", State("Active"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsValid(); got != tt.expected {
				t.Errorf("State.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestState_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected bool
	}{
		{"deleted is terminal", StateDeleted, true},
		{"created is not terminal", StateCreated, false},
		{"active is not terminal", StateActive, false},
		{"suspended is not terminal", StateSuspended, false},
		{"deleting is not terminal", StateDeleting, false},
		{"unknown is not terminal", State("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsTerminal(); got != tt.expected {
				t.Errorf("State.IsTerminal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestState_IsOperational(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected bool
	}{
		{"active is operational", StateActive, true},
		{"created is not operational", StateCreated, false},
		{"suspended is not operational", StateSuspended, false},
		{"deleting is not operational", StateDeleting, false},
		{"deleted is not operational", StateDeleted, false},
		{"unknown is not operational", State("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsOperational(); got != tt.expected {
				t.Errorf("State.IsOperational() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestState_AllowsResourceCreation(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected bool
	}{
		{"active allows creation", StateActive, true},
		{"created does not allow creation", StateCreated, false},
		{"suspended does not allow creation", StateSuspended, false},
		{"deleting does not allow creation", StateDeleting, false},
		{"deleted does not allow creation", StateDeleted, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.AllowsResourceCreation(); got != tt.expected {
				t.Errorf("State.AllowsResourceCreation() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestState_AllowsResourceDeletion(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected bool
	}{
		{"active allows deletion", StateActive, true},
		{"deleting allows deletion", StateDeleting, true},
		{"created does not allow deletion", StateCreated, false},
		{"suspended does not allow deletion", StateSuspended, false},
		{"deleted does not allow deletion", StateDeleted, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.AllowsResourceDeletion(); got != tt.expected {
				t.Errorf("State.AllowsResourceDeletion() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestState_CanTransitionTo_ValidTransitions(t *testing.T) {
	tests := []struct {
		name   string
		from   State
		to     State
		expect bool
	}{
		// Same state transitions (idempotency)
		{"created to created", StateCreated, StateCreated, true},
		{"active to active", StateActive, StateActive, true},
		{"suspended to suspended", StateSuspended, StateSuspended, true},
		{"deleting to deleting", StateDeleting, StateDeleting, true},
		{"deleted to deleted", StateDeleted, StateDeleted, true},

		// Valid transitions from created
		{"created to active", StateCreated, StateActive, true},
		{"created to deleting", StateCreated, StateDeleting, true},

		// Valid transitions from active
		{"active to suspended", StateActive, StateSuspended, true},
		{"active to deleting", StateActive, StateDeleting, true},

		// Valid transitions from suspended
		{"suspended to active", StateSuspended, StateActive, true},
		{"suspended to deleting", StateSuspended, StateDeleting, true},

		// Valid transitions from deleting
		{"deleting to deleted", StateDeleting, StateDeleted, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.from.CanTransitionTo(tt.to); got != tt.expect {
				t.Errorf("State(%s).CanTransitionTo(%s) = %v, want %v", tt.from, tt.to, got, tt.expect)
			}
		})
	}
}

func TestState_CanTransitionTo_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name   string
		from   State
		to     State
		expect bool
	}{
		// Invalid transitions from created
		{"created to suspended", StateCreated, StateSuspended, false},
		{"created to deleted", StateCreated, StateDeleted, false},

		// Invalid transitions from active
		{"active to created", StateActive, StateCreated, false},
		{"active to deleted", StateActive, StateDeleted, false},

		// Invalid transitions from suspended
		{"suspended to created", StateSuspended, StateCreated, false},
		{"suspended to deleted", StateSuspended, StateDeleted, false},

		// Invalid transitions from deleting
		{"deleting to created", StateDeleting, StateCreated, false},
		{"deleting to active", StateDeleting, StateActive, false},
		{"deleting to suspended", StateDeleting, StateSuspended, false},

		// Invalid transitions from deleted (terminal state)
		{"deleted to created", StateDeleted, StateCreated, false},
		{"deleted to active", StateDeleted, StateActive, false},
		{"deleted to suspended", StateDeleted, StateSuspended, false},
		{"deleted to deleting", StateDeleted, StateDeleting, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.from.CanTransitionTo(tt.to); got != tt.expect {
				t.Errorf("State(%s).CanTransitionTo(%s) = %v, want %v", tt.from, tt.to, got, tt.expect)
			}
		})
	}
}

func TestState_CanTransitionTo_UnknownState(t *testing.T) {
	unknown := State("unknown")

	// Unknown state cannot transition to anything
	for _, target := range AllStates() {
		if unknown.CanTransitionTo(target) {
			t.Errorf("Unknown state should not be able to transition to %s", target)
		}
	}

	// Valid states cannot transition to unknown state
	for _, from := range AllStates() {
		if from.CanTransitionTo(unknown) {
			t.Errorf("State %s should not be able to transition to unknown state", from)
		}
	}
}

func TestParseState_ValidStates(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected State
	}{
		{"parse created", "created", StateCreated},
		{"parse active", "active", StateActive},
		{"parse suspended", "suspended", StateSuspended},
		{"parse deleting", "deleting", StateDeleting},
		{"parse deleted", "deleted", StateDeleted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseState(tt.input)
			if err != nil {
				t.Errorf("ParseState(%q) returned unexpected error: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("ParseState(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseState_InvalidStates(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"unknown", "unknown"},
		{"uppercase", "ACTIVE"},
		{"mixed case", "Active"},
		{"whitespace", " active "},
		{"random", "random-state"},
		{"numeric", "123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseState(tt.input)
			if err == nil {
				t.Errorf("ParseState(%q) expected error, got state %q", tt.input, got)
			}

			var invalidStateErr ErrInvalidState
			if !errors.As(err, &invalidStateErr) {
				t.Errorf("ParseState(%q) error should be ErrInvalidState, got %T", tt.input, err)
			}
		})
	}
}

func TestAllStates(t *testing.T) {
	states := AllStates()

	// Should return all 5 states
	if len(states) != 5 {
		t.Errorf("AllStates() returned %d states, want 5", len(states))
	}

	// Check that all expected states are present
	expectedStates := map[State]bool{
		StateCreated:   false,
		StateActive:    false,
		StateSuspended: false,
		StateDeleting:  false,
		StateDeleted:   false,
	}

	for _, s := range states {
		if _, exists := expectedStates[s]; !exists {
			t.Errorf("AllStates() returned unexpected state: %s", s)
		}
		expectedStates[s] = true
	}

	for state, found := range expectedStates {
		if !found {
			t.Errorf("AllStates() missing state: %s", state)
		}
	}
}

func TestTransitionableStates(t *testing.T) {
	states := TransitionableStates()

	// Should return 4 states (all except deleted)
	if len(states) != 4 {
		t.Errorf("TransitionableStates() returned %d states, want 4", len(states))
	}

	// Check that all expected states are present
	expectedStates := map[State]bool{
		StateCreated:   false,
		StateActive:    false,
		StateSuspended: false,
		StateDeleting:  false,
	}

	for _, s := range states {
		if _, exists := expectedStates[s]; !exists {
			t.Errorf("TransitionableStates() returned unexpected state: %s", s)
		}
		expectedStates[s] = true
	}

	for state, found := range expectedStates {
		if !found {
			t.Errorf("TransitionableStates() missing state: %s", state)
		}
	}

	// Deleted should NOT be in the list
	for _, s := range states {
		if s == StateDeleted {
			t.Error("TransitionableStates() should not include StateDeleted")
		}
	}
}

func TestValidTransitions_Completeness(t *testing.T) {
	// Verify that ValidTransitions map has entries for all states
	for _, state := range AllStates() {
		if _, exists := ValidTransitions[state]; !exists {
			// This is okay for deleted state which has no valid transitions
			if state != StateDeleted {
				t.Errorf("ValidTransitions missing entry for state: %s", state)
			}
		}
	}
}

func TestValidTransitions_NoSelfReferences(t *testing.T) {
	// Verify that ValidTransitions does not include self-transitions
	// (those are handled by CanTransitionTo separately)
	for from, targets := range ValidTransitions {
		for _, to := range targets {
			if from == to {
				t.Errorf("ValidTransitions[%s] should not include %s (self-transition)", from, to)
			}
		}
	}
}

func TestValidTransitions_AllTargetsAreValid(t *testing.T) {
	// Verify that all target states in ValidTransitions are valid states
	for from, targets := range ValidTransitions {
		for _, to := range targets {
			if !to.IsValid() {
				t.Errorf("ValidTransitions[%s] contains invalid state: %s", from, to)
			}
		}
	}
}
