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

func TestPortPolicyStructure(t *testing.T) {
	policy := &PortPolicy{
		TenantID: "tenant-123",
		VLAN:     100,
		ACLs:     []ACLRule{},
		Metadata: make(map[string]string),
	}

	assert.Equal(t, "tenant-123", policy.TenantID)
	assert.Equal(t, uint16(100), policy.VLAN)
	assert.NotNil(t, policy.ACLs)
	assert.NotNil(t, policy.Metadata)
}

func TestACLRuleStructure(t *testing.T) {
	acl := ACLRule{
		Priority:    100,
		Description: "Test rule",
		Match: FlowMatch{
			InPort:  "eth0",
			IPProto: 6,
			TCPDst:  443,
		},
		Action: FlowAction{
			Type: FlowActionAllow,
		},
	}

	assert.Equal(t, 100, acl.Priority)
	assert.Equal(t, "Test rule", acl.Description)
	assert.Equal(t, "eth0", acl.Match.InPort)
	assert.Equal(t, uint8(6), acl.Match.IPProto)
	assert.Equal(t, uint16(443), acl.Match.TCPDst)
	assert.Equal(t, FlowActionAllow, acl.Action.Type)
}

func TestFlowMatchStructure(t *testing.T) {
	match := FlowMatch{
		InPort:  "port1",
		EthSrc:  "00:11:22:33:44:55",
		EthDst:  "66:77:88:99:aa:bb",
		EthType: 0x0800,
		VLANVid: 100,
		IPProto: 6,
		IPv4Src: "10.0.0.1/24",
		IPv4Dst: "10.0.0.2/24",
		TCPSrc:  8080,
		TCPDst:  443,
	}

	assert.Equal(t, "port1", match.InPort)
	assert.Equal(t, "00:11:22:33:44:55", match.EthSrc)
	assert.Equal(t, "66:77:88:99:aa:bb", match.EthDst)
	assert.Equal(t, uint16(0x0800), match.EthType)
	assert.Equal(t, uint16(100), match.VLANVid)
	assert.Equal(t, uint8(6), match.IPProto)
	assert.Equal(t, "10.0.0.1/24", match.IPv4Src)
	assert.Equal(t, "10.0.0.2/24", match.IPv4Dst)
	assert.Equal(t, uint16(8080), match.TCPSrc)
	assert.Equal(t, uint16(443), match.TCPDst)
}

func TestFlowActionStructure(t *testing.T) {
	action := FlowAction{
		Type:    FlowActionForward,
		Output:  "port2",
		SetVLAN: 200,
		Params:  map[string]string{"key": "value"},
	}

	assert.Equal(t, FlowActionForward, action.Type)
	assert.Equal(t, "port2", action.Output)
	assert.Equal(t, uint16(200), action.SetVLAN)
	assert.Equal(t, "value", action.Params["key"])
}

func TestPortInfoStructure(t *testing.T) {
	info := &PortInfo{
		PortID:       "port1",
		State:        PortStateAuthorized,
		AuthAttempts: 3,
		ErrorCount:   1,
		LastError:    "test error",
	}

	assert.Equal(t, "port1", info.PortID)
	assert.Equal(t, PortStateAuthorized, info.State)
	assert.Equal(t, 3, info.AuthAttempts)
	assert.Equal(t, 1, info.ErrorCount)
	assert.Equal(t, "test error", info.LastError)
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
