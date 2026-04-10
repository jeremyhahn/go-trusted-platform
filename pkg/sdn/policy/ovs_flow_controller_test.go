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
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockOVSClient is a mock implementation of the OVS client
type MockOVSClient struct {
	mock.Mock
}

func (m *MockOVSClient) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	args := m.Called(ctx, bridgeName, flow)
	return args.Error(0)
}

func (m *MockOVSClient) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	args := m.Called(ctx, bridgeName, match)
	return args.Error(0)
}

func (m *MockOVSClient) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	args := m.Called(ctx, bridgeName)
	if flows := args.Get(0); flows != nil {
		return flows.([]*ovs.Flow), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockOVSClient) SetPortVLAN(ctx context.Context, portName string, tag int64) error {
	args := m.Called(ctx, portName, tag)
	return args.Error(0)
}

func (m *MockOVSClient) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	args := m.Called(ctx, portName, state)
	return args.Error(0)
}

func (m *MockOVSClient) GetOFPort(ctx context.Context, portName string) (int32, error) {
	args := m.Called(ctx, portName)
	return args.Get(0).(int32), args.Error(1)
}

func TestNewOVSFlowController(t *testing.T) {
	tests := []struct {
		name        string
		client      *ovs.Client
		expectError bool
		errorType   error
	}{
		{
			name:        "nil client returns error",
			client:      nil,
			expectError: true,
			errorType:   ErrInvalidClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, err := NewOVSFlowController(tt.client)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, controller)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, controller)
			}
		})
	}
}

func TestOVSFlowController_InstallFlow(t *testing.T) {
	// Note: Tests that require OVS client interaction are tested via integration tests
	// Unit tests here only cover validation logic that doesn't require client

	t.Run("empty bridge name returns error", func(t *testing.T) {
		controller := &OVSFlowController{
			client:  nil, // validation happens before client use
			timeout: 1 * time.Second,
		}

		err := controller.InstallFlow("", 1000, "in_port=1", "output:2")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})
}

func TestOVSFlowController_DeleteFlow(t *testing.T) {
	tests := []struct {
		name        string
		bridgeName  string
		match       string
		expectError bool
		errorType   error
	}{
		{
			name:        "empty bridge name returns error",
			bridgeName:  "",
			match:       "in_port=1",
			expectError: true,
			errorType:   ErrInvalidBridgeName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &OVSFlowController{
				client:  nil,
				timeout: 1 * time.Second,
			}

			err := controller.DeleteFlow(tt.bridgeName, tt.match)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				// Would be nil in real implementation with valid client
				assert.Error(t, err) // Panics with nil client
			}
		})
	}
}

func TestOVSFlowController_DeleteFlowsByPort(t *testing.T) {
	tests := []struct {
		name        string
		bridgeName  string
		portID      string
		expectError bool
		errorType   error
	}{
		{
			name:        "empty bridge name returns error",
			bridgeName:  "",
			portID:      "eth0",
			expectError: true,
			errorType:   ErrInvalidBridgeName,
		},
		{
			name:        "empty port ID returns error",
			bridgeName:  "br0",
			portID:      "",
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &OVSFlowController{
				client:  nil,
				timeout: 1 * time.Second,
			}

			err := controller.DeleteFlowsByPort(tt.bridgeName, tt.portID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			}
		})
	}
}

func TestOVSFlowController_ListFlows(t *testing.T) {
	tests := []struct {
		name        string
		bridgeName  string
		expectError bool
		errorType   error
	}{
		{
			name:        "empty bridge name returns error",
			bridgeName:  "",
			expectError: true,
			errorType:   ErrInvalidBridgeName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &OVSFlowController{
				client:  nil,
				timeout: 1 * time.Second,
			}

			flows, err := controller.ListFlows(tt.bridgeName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, flows)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			}
		})
	}
}

func TestOVSFlowController_SetPortVLAN(t *testing.T) {
	tests := []struct {
		name        string
		portName    string
		vlan        int64
		expectError bool
		errorType   error
	}{
		{
			name:        "empty port name returns error",
			portName:    "",
			vlan:        100,
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
		{
			name:        "negative VLAN returns error",
			portName:    "eth0",
			vlan:        -1,
			expectError: true,
			errorType:   ErrInvalidVLAN,
		},
		{
			name:        "VLAN too large returns error",
			portName:    "eth0",
			vlan:        4096,
			expectError: true,
			errorType:   ErrInvalidVLAN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &OVSFlowController{
				client:  nil,
				timeout: 1 * time.Second,
			}

			ctx := context.Background()
			err := controller.SetPortVLAN(ctx, tt.portName, tt.vlan)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			}
		})
	}
}

func TestOVSFlowController_SetPortState(t *testing.T) {
	tests := []struct {
		name        string
		portName    string
		state       ovs.PortState
		expectError bool
		errorType   error
	}{
		{
			name:        "empty port name returns error",
			portName:    "",
			state:       ovs.PortStateUp,
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &OVSFlowController{
				client:  nil,
				timeout: 1 * time.Second,
			}

			ctx := context.Background()
			err := controller.SetPortState(ctx, tt.portName, tt.state)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			}
		})
	}
}

func TestOVSFlowController_GetOFPort(t *testing.T) {
	tests := []struct {
		name        string
		portName    string
		expectError bool
		errorType   error
	}{
		{
			name:        "empty port name returns error",
			portName:    "",
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &OVSFlowController{
				client:  nil,
				timeout: 1 * time.Second,
			}

			ctx := context.Background()
			port, err := controller.GetOFPort(ctx, tt.portName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, int32(0), port)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			}
		})
	}
}

func TestOVSFlowController_SetTimeout(t *testing.T) {
	controller := &OVSFlowController{
		timeout: 30 * time.Second,
	}

	newTimeout := 60 * time.Second
	controller.SetTimeout(newTimeout)

	assert.Equal(t, newTimeout, controller.timeout)
}

func TestFormatFlow(t *testing.T) {
	tests := []struct {
		name     string
		flow     *ovs.Flow
		expected string
	}{
		{
			name: "flow with all fields",
			flow: &ovs.Flow{
				Table:       0,
				Priority:    1000,
				Match:       "in_port=1",
				Actions:     "output:2",
				Cookie:      "0x123",
				Duration:    60,
				IdleAge:     30,
				PacketCount: 100,
				ByteCount:   10000,
			},
			expected: "table=0,priority=1000,in_port=1,cookie=0x123,duration=60s,idle_age=30s,n_packets=100,n_bytes=10000,actions=output:2",
		},
		{
			name: "flow with minimal fields",
			flow: &ovs.Flow{
				Table:    0,
				Priority: 500,
				Actions:  "drop",
			},
			expected: "table=0,priority=500,actions=drop",
		},
		{
			name: "flow with match and actions only",
			flow: &ovs.Flow{
				Table:    1,
				Priority: 2000,
				Match:    "dl_type=0x0800,nw_dst=192.168.1.0/24",
				Actions:  "mod_vlan_vid:100,normal",
			},
			expected: "table=1,priority=2000,dl_type=0x0800,nw_dst=192.168.1.0/24,actions=mod_vlan_vid:100,normal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatFlow(tt.flow)
			assert.Equal(t, tt.expected, result)
		})
	}
}
