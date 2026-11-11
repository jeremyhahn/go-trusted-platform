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
)

func TestPortStateString(t *testing.T) {
	tests := []struct {
		name     string
		state    PortState
		expected string
	}{
		{
			name:     "Unconnected",
			state:    PortStateUnconnected,
			expected: "unconnected",
		},
		{
			name:     "Provisioning",
			state:    PortStateProvisioning,
			expected: "provisioning",
		},
		{
			name:     "Enrolled",
			state:    PortStateEnrolled,
			expected: "enrolled",
		},
		{
			name:     "Unauthorized",
			state:    PortStateUnauthorized,
			expected: "unauthorized",
		},
		{
			name:     "Authenticating",
			state:    PortStateAuthenticating,
			expected: "authenticating",
		},
		{
			name:     "Authorized",
			state:    PortStateAuthorized,
			expected: "authorized",
		},
		{
			name:     "Quarantined",
			state:    PortStateQuarantined,
			expected: "quarantined",
		},
		{
			name:     "Blocked",
			state:    PortStateBlocked,
			expected: "blocked",
		},
		{
			name:     "Unknown",
			state:    PortState(999),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.state.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPortStateValues(t *testing.T) {
	// Ensure iota values are as expected
	assert.Equal(t, PortState(0), PortStateUnconnected)
	assert.Equal(t, PortState(1), PortStateProvisioning)
	assert.Equal(t, PortState(2), PortStateEnrolled)
	assert.Equal(t, PortState(3), PortStateUnauthorized)
	assert.Equal(t, PortState(4), PortStateAuthenticating)
	assert.Equal(t, PortState(5), PortStateAuthorized)
	assert.Equal(t, PortState(6), PortStateQuarantined)
	assert.Equal(t, PortState(7), PortStateBlocked)
}

func TestPortStateOrder(t *testing.T) {
	// Verify the logical progression of states
	assert.True(t, PortStateUnconnected < PortStateProvisioning)
	assert.True(t, PortStateProvisioning < PortStateEnrolled)
	assert.True(t, PortStateEnrolled < PortStateUnauthorized)
	assert.True(t, PortStateUnauthorized < PortStateAuthenticating)
	assert.True(t, PortStateAuthenticating < PortStateAuthorized)
	assert.True(t, PortStateAuthorized < PortStateQuarantined)
	assert.True(t, PortStateQuarantined < PortStateBlocked)
}

func TestFlowActionType(t *testing.T) {
	assert.Equal(t, FlowActionType("allow"), FlowActionAllow)
	assert.Equal(t, FlowActionType("deny"), FlowActionDeny)
	assert.Equal(t, FlowActionType("forward"), FlowActionForward)
	assert.Equal(t, FlowActionType("normal"), FlowActionNormal)
}

func TestPortInfoWithNewStates(t *testing.T) {
	tests := []struct {
		name          string
		state         PortState
		expectedState PortState
	}{
		{
			name:          "Unconnected state",
			state:         PortStateUnconnected,
			expectedState: PortStateUnconnected,
		},
		{
			name:          "Provisioning state",
			state:         PortStateProvisioning,
			expectedState: PortStateProvisioning,
		},
		{
			name:          "Enrolled state",
			state:         PortStateEnrolled,
			expectedState: PortStateEnrolled,
		},
		{
			name:          "Quarantined state",
			state:         PortStateQuarantined,
			expectedState: PortStateQuarantined,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &PortInfo{
				PortID: "test-port",
				State:  tt.state,
			}
			assert.Equal(t, tt.expectedState, info.State)
		})
	}
}
