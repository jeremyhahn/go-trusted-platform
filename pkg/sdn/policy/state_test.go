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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPortStateMachine(t *testing.T) {
	sm := NewPortStateMachine()
	assert.NotNil(t, sm)
	assert.NotNil(t, sm.ports)
}

func TestPortStateMachine_SetState(t *testing.T) {
	sm := NewPortStateMachine()

	tests := []struct {
		name        string
		portID      string
		state       PortState
		expectError bool
		errorType   error
	}{
		{
			name:        "Valid state transition - Unconnected (initial)",
			portID:      "port1",
			state:       PortStateProvisioning,
			expectError: false,
		},
		{
			name:        "Empty port ID",
			portID:      "",
			state:       PortStateUnauthorized,
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sm.SetState(tt.portID, tt.state)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)

				// Verify state was set
				state, err := sm.GetState(tt.portID)
				assert.NoError(t, err)
				assert.Equal(t, tt.state, state)
			}
		})
	}
}

func TestPortStateMachine_GetState(t *testing.T) {
	sm := NewPortStateMachine()

	t.Run("Port not found", func(t *testing.T) {
		state, err := sm.GetState("nonexistent")
		assert.ErrorIs(t, err, ErrPortNotFound)
		assert.Equal(t, PortStateUnconnected, state)
	})

	t.Run("Port exists", func(t *testing.T) {
		// Follow proper state machine flow: unconnected -> provisioning -> authorized
		require.NoError(t, sm.SetState("port1", PortStateProvisioning))
		require.NoError(t, sm.SetState("port1", PortStateAuthorized))

		state, err := sm.GetState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateAuthorized, state)
	})
}

func TestPortStateMachine_StateTransitions(t *testing.T) {
	tests := []struct {
		name        string
		fromState   PortState
		toState     PortState
		expectError bool
	}{
		// Unconnected transitions
		{
			name:        "Unconnected to Provisioning",
			fromState:   PortStateUnconnected,
			toState:     PortStateProvisioning,
			expectError: false,
		},
		{
			name:        "Unconnected to Blocked",
			fromState:   PortStateUnconnected,
			toState:     PortStateBlocked,
			expectError: false,
		},
		{
			name:        "Unconnected to Unauthorized (invalid)",
			fromState:   PortStateUnconnected,
			toState:     PortStateUnauthorized,
			expectError: true,
		},
		// Provisioning transitions
		{
			name:        "Provisioning to Unauthorized",
			fromState:   PortStateProvisioning,
			toState:     PortStateUnauthorized,
			expectError: false,
		},
		{
			name:        "Provisioning to Authenticating",
			fromState:   PortStateProvisioning,
			toState:     PortStateAuthenticating,
			expectError: false,
		},
		{
			name:        "Provisioning to Authorized (direct)",
			fromState:   PortStateProvisioning,
			toState:     PortStateAuthorized,
			expectError: false,
		},
		{
			name:        "Provisioning to Blocked",
			fromState:   PortStateProvisioning,
			toState:     PortStateBlocked,
			expectError: false,
		},
		{
			name:        "Provisioning to Quarantined (invalid)",
			fromState:   PortStateProvisioning,
			toState:     PortStateQuarantined,
			expectError: true,
		},
		// Unauthorized transitions
		{
			name:        "Unauthorized to Authenticating",
			fromState:   PortStateUnauthorized,
			toState:     PortStateAuthenticating,
			expectError: false,
		},
		{
			name:        "Unauthorized to Provisioning (re-provision)",
			fromState:   PortStateUnauthorized,
			toState:     PortStateProvisioning,
			expectError: false,
		},
		{
			name:        "Unauthorized to Blocked",
			fromState:   PortStateUnauthorized,
			toState:     PortStateBlocked,
			expectError: false,
		},
		{
			name:        "Unauthorized to Authorized (invalid - must authenticate)",
			fromState:   PortStateUnauthorized,
			toState:     PortStateAuthorized,
			expectError: true,
		},
		// Authenticating transitions
		{
			name:        "Authenticating to Authorized",
			fromState:   PortStateAuthenticating,
			toState:     PortStateAuthorized,
			expectError: false,
		},
		{
			name:        "Authenticating to Unauthorized",
			fromState:   PortStateAuthenticating,
			toState:     PortStateUnauthorized,
			expectError: false,
		},
		{
			name:        "Authenticating to Blocked",
			fromState:   PortStateAuthenticating,
			toState:     PortStateBlocked,
			expectError: false,
		},
		{
			name:        "Authenticating to Provisioning (invalid)",
			fromState:   PortStateAuthenticating,
			toState:     PortStateProvisioning,
			expectError: true,
		},
		// Authorized transitions
		{
			name:        "Authorized to Unauthorized",
			fromState:   PortStateAuthorized,
			toState:     PortStateUnauthorized,
			expectError: false,
		},
		{
			name:        "Authorized to Quarantined",
			fromState:   PortStateAuthorized,
			toState:     PortStateQuarantined,
			expectError: false,
		},
		{
			name:        "Authorized to Blocked",
			fromState:   PortStateAuthorized,
			toState:     PortStateBlocked,
			expectError: false,
		},
		{
			name:        "Authorized to Provisioning (invalid)",
			fromState:   PortStateAuthorized,
			toState:     PortStateProvisioning,
			expectError: true,
		},
		// Quarantined transitions
		{
			name:        "Quarantined to Authorized (after remediation)",
			fromState:   PortStateQuarantined,
			toState:     PortStateAuthorized,
			expectError: false,
		},
		{
			name:        "Quarantined to Blocked (remediation failed)",
			fromState:   PortStateQuarantined,
			toState:     PortStateBlocked,
			expectError: false,
		},
		{
			name:        "Quarantined to Provisioning (re-enroll)",
			fromState:   PortStateQuarantined,
			toState:     PortStateProvisioning,
			expectError: false,
		},
		{
			name:        "Quarantined to Unauthorized (invalid)",
			fromState:   PortStateQuarantined,
			toState:     PortStateUnauthorized,
			expectError: true,
		},
		// Blocked transitions
		{
			name:        "Blocked to Unconnected (admin reset)",
			fromState:   PortStateBlocked,
			toState:     PortStateUnconnected,
			expectError: false,
		},
		{
			name:        "Blocked to Provisioning (admin allows re-enrollment)",
			fromState:   PortStateBlocked,
			toState:     PortStateProvisioning,
			expectError: false,
		},
		{
			name:        "Blocked to Authorized (invalid)",
			fromState:   PortStateBlocked,
			toState:     PortStateAuthorized,
			expectError: true,
		},
		// Same-state transitions (idempotency)
		{
			name:        "Unconnected to Unconnected",
			fromState:   PortStateUnconnected,
			toState:     PortStateUnconnected,
			expectError: false,
		},
		{
			name:        "Provisioning to Provisioning",
			fromState:   PortStateProvisioning,
			toState:     PortStateProvisioning,
			expectError: false,
		},
		{
			name:        "Authorized to Authorized",
			fromState:   PortStateAuthorized,
			toState:     PortStateAuthorized,
			expectError: false,
		},
		{
			name:        "Quarantined to Quarantined",
			fromState:   PortStateQuarantined,
			toState:     PortStateQuarantined,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewPortStateMachine()
			portID := "test-port"

			// Set up the port to reach the fromState through valid transitions
			setupPortState(t, sm, portID, tt.fromState)

			// Attempt transition
			err := sm.SetState(portID, tt.toState)

			if tt.expectError {
				assert.ErrorIs(t, err, ErrInvalidState)
			} else {
				assert.NoError(t, err)

				state, err := sm.GetState(portID)
				assert.NoError(t, err)
				assert.Equal(t, tt.toState, state)
			}
		})
	}
}

func TestPortStateMachine_CompleteWorkflows(t *testing.T) {
	tests := []struct {
		name       string
		workflow   []PortState
		shouldFail bool
	}{
		{
			name: "Standard enrollment flow",
			workflow: []PortState{
				PortStateProvisioning,
				PortStateAuthenticating,
				PortStateAuthorized,
			},
			shouldFail: false,
		},
		{
			name: "Direct provisioning to authorized",
			workflow: []PortState{
				PortStateProvisioning,
				PortStateAuthorized,
			},
			shouldFail: false,
		},
		{
			name: "Quarantine and recovery",
			workflow: []PortState{
				PortStateProvisioning,
				PortStateAuthorized,
				PortStateQuarantined,
				PortStateAuthorized,
			},
			shouldFail: false,
		},
		{
			name: "Failed authentication and re-provisioning",
			workflow: []PortState{
				PortStateProvisioning,
				PortStateUnauthorized,
				PortStateProvisioning,
				PortStateAuthorized,
			},
			shouldFail: false,
		},
		{
			name: "Blocked and re-enrollment",
			workflow: []PortState{
				PortStateProvisioning,
				PortStateBlocked,
				PortStateProvisioning,
				PortStateAuthorized,
			},
			shouldFail: false,
		},
		{
			name: "Admin reset from blocked",
			workflow: []PortState{
				PortStateProvisioning,
				PortStateBlocked,
				PortStateUnconnected,
				PortStateProvisioning,
			},
			shouldFail: false,
		},
		{
			name: "Invalid: Skip provisioning",
			workflow: []PortState{
				PortStateUnauthorized,
			},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewPortStateMachine()
			portID := "workflow-port"

			var err error
			for i, state := range tt.workflow {
				err = sm.SetState(portID, state)
				if err != nil {
					if !tt.shouldFail {
						t.Fatalf("Step %d failed unexpectedly: %v", i, err)
					}
					return
				}
			}

			if tt.shouldFail {
				t.Fatal("Workflow should have failed but didn't")
			}

			// Verify final state
			finalState, err := sm.GetState(portID)
			assert.NoError(t, err)
			assert.Equal(t, tt.workflow[len(tt.workflow)-1], finalState)
		})
	}
}

func TestPortStateMachine_GetInfo(t *testing.T) {
	sm := NewPortStateMachine()

	t.Run("Port not found", func(t *testing.T) {
		_, err := sm.GetInfo("nonexistent")
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("Port exists", func(t *testing.T) {
		portID := "port1"
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
		require.NoError(t, sm.SetState(portID, PortStateAuthorized))

		info, err := sm.GetInfo(portID)
		assert.NoError(t, err)
		assert.NotNil(t, info)
		assert.Equal(t, portID, info.PortID)
		assert.Equal(t, PortStateAuthorized, info.State)
		assert.False(t, info.LastStateChange.IsZero())
	})
}

func TestPortStateMachine_SetPolicy(t *testing.T) {
	sm := NewPortStateMachine()

	t.Run("Invalid port ID", func(t *testing.T) {
		err := sm.SetPolicy("", &PortPolicy{})
		assert.ErrorIs(t, err, ErrInvalidPortID)
	})

	t.Run("New port with policy", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		err := sm.SetPolicy("port1", policy)
		assert.NoError(t, err)

		info, err := sm.GetInfo("port1")
		assert.NoError(t, err)
		assert.NotNil(t, info.Policy)
		assert.Equal(t, "tenant-1", info.Policy.TenantID)
		assert.Equal(t, uint16(100), info.Policy.VLAN)
	})

	t.Run("Update existing port policy", func(t *testing.T) {
		policy1 := &PortPolicy{TenantID: "tenant-1", VLAN: 100}
		policy2 := &PortPolicy{TenantID: "tenant-2", VLAN: 200}

		require.NoError(t, sm.SetPolicy("port2", policy1))
		require.NoError(t, sm.SetPolicy("port2", policy2))

		info, err := sm.GetInfo("port2")
		assert.NoError(t, err)
		assert.Equal(t, "tenant-2", info.Policy.TenantID)
		assert.Equal(t, uint16(200), info.Policy.VLAN)
	})
}

func TestPortStateMachine_RemovePort(t *testing.T) {
	sm := NewPortStateMachine()

	t.Run("Port not found", func(t *testing.T) {
		err := sm.RemovePort("nonexistent")
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("Remove existing port", func(t *testing.T) {
		portID := "port1"
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
		require.NoError(t, sm.SetState(portID, PortStateAuthorized))

		err := sm.RemovePort(portID)
		assert.NoError(t, err)

		_, err = sm.GetState(portID)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestPortStateMachine_ListPorts(t *testing.T) {
	sm := NewPortStateMachine()

	t.Run("Empty list", func(t *testing.T) {
		ports := sm.ListPorts()
		assert.Empty(t, ports)
	})

	t.Run("Multiple ports", func(t *testing.T) {
		// port1: provisioning
		require.NoError(t, sm.SetState("port1", PortStateProvisioning))
		// port2: authorized
		require.NoError(t, sm.SetState("port2", PortStateProvisioning))
		require.NoError(t, sm.SetState("port2", PortStateAuthorized))
		// port3: blocked
		require.NoError(t, sm.SetState("port3", PortStateBlocked))

		ports := sm.ListPorts()
		assert.Len(t, ports, 3)
		assert.Contains(t, ports, "port1")
		assert.Contains(t, ports, "port2")
		assert.Contains(t, ports, "port3")
	})
}

func TestPortStateMachine_IncrementAuthAttempts(t *testing.T) {
	sm := NewPortStateMachine()

	t.Run("Port not found", func(t *testing.T) {
		err := sm.IncrementAuthAttempts("nonexistent")
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("Increment attempts", func(t *testing.T) {
		portID := "port1"
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
		require.NoError(t, sm.SetState(portID, PortStateAuthenticating))

		require.NoError(t, sm.IncrementAuthAttempts(portID))
		require.NoError(t, sm.IncrementAuthAttempts(portID))

		info, err := sm.GetInfo(portID)
		assert.NoError(t, err)
		assert.Equal(t, 2, info.AuthAttempts)
		assert.False(t, info.LastAuthAttempt.IsZero())
	})
}

func TestPortStateMachine_RecordError(t *testing.T) {
	sm := NewPortStateMachine()

	t.Run("Port not found", func(t *testing.T) {
		err := sm.RecordError("nonexistent", ErrInvalidPolicy)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("Record error", func(t *testing.T) {
		portID := "port1"
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))

		testErr := ErrInvalidCertificate
		require.NoError(t, sm.RecordError(portID, testErr))

		info, err := sm.GetInfo(portID)
		assert.NoError(t, err)
		assert.Equal(t, 1, info.ErrorCount)
		assert.Equal(t, testErr.Error(), info.LastError)
	})

	t.Run("Record nil error", func(t *testing.T) {
		portID := "port2"
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))

		require.NoError(t, sm.RecordError(portID, nil))

		info, err := sm.GetInfo(portID)
		assert.NoError(t, err)
		assert.Equal(t, 1, info.ErrorCount)
	})
}

func TestPortStateMachine_Concurrency(t *testing.T) {
	sm := NewPortStateMachine()
	portID := "concurrent-port"

	// Initialize port
	require.NoError(t, sm.SetState(portID, PortStateProvisioning))

	// Both goroutines are released together by closing start, so their
	// operations run concurrently; the race detector checks the locking by
	// happens-before, which needs no pacing between operations.
	start := make(chan struct{})
	errs := make(chan error, 2)

	// Concurrent state changes: Authenticating <-> Unauthorized is valid in
	// both directions, so every write must succeed.
	go func() {
		<-start
		next := PortStateAuthenticating
		for i := 0; i < 100; i++ {
			if err := sm.SetState(portID, next); err != nil {
				errs <- err
				return
			}
			if next == PortStateAuthenticating {
				next = PortStateUnauthorized
			} else {
				next = PortStateAuthenticating
			}
		}
		errs <- nil
	}()

	// Concurrent reads
	go func() {
		<-start
		for i := 0; i < 100; i++ {
			if _, err := sm.GetState(portID); err != nil {
				errs <- err
				return
			}
			if _, err := sm.GetInfo(portID); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()

	close(start)
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)

	// The 100th write leaves the port Unauthorized
	state, err := sm.GetState(portID)
	require.NoError(t, err)
	assert.Equal(t, PortStateUnauthorized, state)
}

// setupPortState sets up a port to reach the target state through valid transitions
func setupPortState(t *testing.T, sm *PortStateMachine, portID string, targetState PortState) {
	t.Helper()

	switch targetState {
	case PortStateUnconnected:
		// Ports start in unconnected state, but we can also reach it from blocked
		// For testing, we'll use the blocked -> unconnected path if needed
		// But since new ports start unconnected, we can just create it
		require.NoError(t, sm.SetState(portID, PortStateBlocked))
		require.NoError(t, sm.SetState(portID, PortStateUnconnected))
	case PortStateProvisioning:
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
	case PortStateUnauthorized:
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
		require.NoError(t, sm.SetState(portID, PortStateUnauthorized))
	case PortStateAuthenticating:
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
		require.NoError(t, sm.SetState(portID, PortStateAuthenticating))
	case PortStateAuthorized:
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
		require.NoError(t, sm.SetState(portID, PortStateAuthorized))
	case PortStateQuarantined:
		require.NoError(t, sm.SetState(portID, PortStateProvisioning))
		require.NoError(t, sm.SetState(portID, PortStateAuthorized))
		require.NoError(t, sm.SetState(portID, PortStateQuarantined))
	case PortStateBlocked:
		require.NoError(t, sm.SetState(portID, PortStateBlocked))
	}
}
