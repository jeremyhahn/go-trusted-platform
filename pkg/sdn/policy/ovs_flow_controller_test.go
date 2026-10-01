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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
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

func TestOVSFlowController_InstallFlows(t *testing.T) {
	t.Run("empty bridge name returns error", func(t *testing.T) {
		controller := &OVSFlowController{
			client:  nil, // validation happens before client use
			timeout: 1 * time.Second,
		}

		err := controller.InstallFlows("", []zoneflows.FlowRule{
			{Priority: 1000, Match: "in_port=1", Actions: "output:2"},
		})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("empty batch is a no-op", func(t *testing.T) {
		controller := &OVSFlowController{
			client:  nil, // never reached for an empty batch
			timeout: 1 * time.Second,
		}

		assert.NoError(t, controller.InstallFlows("br0", nil))
		assert.NoError(t, controller.InstallFlows("br0", []zoneflows.FlowRule{}))
	})
}

// portUpdateRecorder is an ovsClient that records UpdatePort calls.
type portUpdateRecorder struct {
	updates map[string]interface{}
	err     error
}

func (r *portUpdateRecorder) AddFlow(context.Context, string, *ovs.FlowMod) error       { return nil }
func (r *portUpdateRecorder) AddFlows(context.Context, string, []*ovs.FlowMod) error    { return nil }
func (r *portUpdateRecorder) DeleteFlow(context.Context, string, string) error          { return nil }
func (r *portUpdateRecorder) ListFlows(context.Context, string) ([]*ovs.Flow, error)    { return nil, nil }
func (r *portUpdateRecorder) SetPortState(context.Context, string, ovs.PortState) error { return nil }
func (r *portUpdateRecorder) GetOFPort(context.Context, string) (int32, error)          { return 1, nil }
func (r *portUpdateRecorder) UpdatePort(_ context.Context, _ string, u map[string]interface{}) error {
	r.updates = u
	return r.err
}

// TestOVSFlowController_SetPortTrunk_Native writes a native-untagged trunk.
func TestOVSFlowController_SetPortTrunk_Native(t *testing.T) {
	rec := &portUpdateRecorder{}
	c := &OVSFlowController{client: rec}
	assert.NoError(t, c.SetPortTrunk(context.Background(), "eth0", []uint16{401, 405}, 405))
	assert.Equal(t, "native-untagged", rec.updates["vlan_mode"])
	assert.Equal(t, int64(405), rec.updates["tag"])
	assert.Equal(t, ovs.Set{Set: []interface{}{int64(401), int64(405)}}, rec.updates["trunks"])
}

// TestOVSFlowController_SetPortTrunk_TaggedOnly clears the tag.
func TestOVSFlowController_SetPortTrunk_TaggedOnly(t *testing.T) {
	rec := &portUpdateRecorder{}
	c := &OVSFlowController{client: rec}
	assert.NoError(t, c.SetPortTrunk(context.Background(), "gw0", []uint16{400, 401}, 0))
	assert.Equal(t, "trunk", rec.updates["vlan_mode"])
	assert.Equal(t, ovs.Set{Set: []interface{}{}}, rec.updates["tag"])
}

// TestOVSFlowController_SetPortTrunk_Errors refuses bad input and wraps a
// client failure.
func TestOVSFlowController_SetPortTrunk_Errors(t *testing.T) {
	ctx := context.Background()
	c := &OVSFlowController{client: &portUpdateRecorder{}}
	assert.ErrorIs(t, c.SetPortTrunk(ctx, "", []uint16{401}, 0), ErrInvalidPortID)
	assert.ErrorIs(t, c.SetPortTrunk(ctx, "eth0", nil, 0), ErrInvalidVLAN)
	assert.ErrorIs(t, c.SetPortTrunk(ctx, "eth0", []uint16{0}, 0), ErrInvalidVLAN)
	assert.ErrorIs(t, c.SetPortTrunk(ctx, "eth0", []uint16{401}, 4095), ErrInvalidVLAN)

	failing := &OVSFlowController{client: &portUpdateRecorder{err: assert.AnError}}
	err := failing.SetPortTrunk(ctx, "eth0", []uint16{401}, 0)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Contains(t, err.Error(), "set trunk")
}

// TestOVSFlowController_SetPortVLAN_ClearsTrunk makes a clean access port.
func TestOVSFlowController_SetPortVLAN_ClearsTrunk(t *testing.T) {
	rec := &portUpdateRecorder{}
	c := &OVSFlowController{client: rec}
	assert.NoError(t, c.SetPortVLAN(context.Background(), "eth0", 404))
	assert.Equal(t, "access", rec.updates["vlan_mode"])
	assert.Equal(t, int64(404), rec.updates["tag"])
	assert.Equal(t, ovs.Set{Set: []interface{}{}}, rec.updates["trunks"])

	failing := &OVSFlowController{client: &portUpdateRecorder{err: assert.AnError}}
	assert.ErrorIs(t, failing.SetPortVLAN(context.Background(), "eth0", 404), assert.AnError)
}
