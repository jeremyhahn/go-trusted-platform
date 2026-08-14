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
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockOVSFlowController is a mock for testing engine enhanced functions
type MockOVSFlowController struct {
	flows        map[string][]FlowRule
	portVLANs    map[string]int64
	portStates   map[string]ovs.PortState
	ofPorts      map[string]int32
	installError error
	deleteError  error
	vlanError    error
	stateError   error
	ofPortError  error
}

func NewMockOVSFlowController() *MockOVSFlowController {
	return &MockOVSFlowController{
		flows:      make(map[string][]FlowRule),
		portVLANs:  make(map[string]int64),
		portStates: make(map[string]ovs.PortState),
		ofPorts:    make(map[string]int32),
	}
}

func (m *MockOVSFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	if m.installError != nil {
		return m.installError
	}

	rule := FlowRule{
		Priority: priority,
		Match:    match,
		Actions:  actions,
	}

	m.flows[bridgeName] = append(m.flows[bridgeName], rule)
	return nil
}

func (m *MockOVSFlowController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	for _, rule := range rules {
		if err := m.InstallFlow(bridgeName, rule.Priority, rule.Match, rule.Actions); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockOVSFlowController) DeleteFlow(bridgeName string, match string) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	// Remove matching flows
	if flows, ok := m.flows[bridgeName]; ok {
		newFlows := []FlowRule{}
		for _, flow := range flows {
			if flow.Match != match {
				newFlows = append(newFlows, flow)
			}
		}
		m.flows[bridgeName] = newFlows
	}

	return nil
}

func (m *MockOVSFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	// Remove all flows for the port
	delete(m.flows, bridgeName)
	return nil
}

func (m *MockOVSFlowController) ListFlows(bridgeName string) ([]string, error) {
	flows, ok := m.flows[bridgeName]
	if !ok {
		return []string{}, nil
	}

	result := make([]string, len(flows))
	for i, flow := range flows {
		result[i] = flow.String()
	}
	return result, nil
}

func (m *MockOVSFlowController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	if m.vlanError != nil {
		return m.vlanError
	}

	m.portVLANs[portName] = vlan
	return nil
}

func (m *MockOVSFlowController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	if m.stateError != nil {
		return m.stateError
	}

	m.portStates[portName] = state
	return nil
}

func (m *MockOVSFlowController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	if m.ofPortError != nil {
		return 0, m.ofPortError
	}

	if port, ok := m.ofPorts[portName]; ok {
		return port, nil
	}

	return 0, ErrPortNotFound
}

func TestEngine_SetPortVLAN(t *testing.T) {
	mockController := NewMockOVSFlowController()

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		portID      string
		vlan        uint16
		setupMock   func()
		expectError bool
		errorType   error
	}{
		{
			name:   "set valid VLAN",
			portID: "eth0",
			vlan:   100,
			setupMock: func() {
				mockController.vlanError = nil
			},
			expectError: false,
		},
		{
			name:        "empty port ID returns error",
			portID:      "",
			vlan:        100,
			setupMock:   func() {},
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
		{
			name:        "VLAN 0 returns error",
			portID:      "eth0",
			vlan:        0,
			setupMock:   func() {},
			expectError: true,
			errorType:   ErrInvalidVLAN,
		},
		{
			name:        "VLAN too large returns error",
			portID:      "eth0",
			vlan:        4095,
			setupMock:   func() {},
			expectError: true,
			errorType:   ErrInvalidVLAN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := engine.SetPortVLAN(tt.portID, tt.vlan)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, int64(tt.vlan), mockController.portVLANs[tt.portID])
			}
		})
	}
}

func TestEngine_GetPortVLAN(t *testing.T) {
	mockController := NewMockOVSFlowController()

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	// Setup a port with policy
	portID := "eth0"
	policy := &PortPolicy{
		TenantID: "tenant1",
		VLAN:     200,
	}

	// Transition port through states to authorized
	err = engine.SetPortState(portID, PortStateProvisioning)
	require.NoError(t, err)

	err = engine.ApplyPolicy(portID, policy)
	require.NoError(t, err)

	tests := []struct {
		name         string
		portID       string
		expectedVLAN uint16
		expectError  bool
		errorType    error
	}{
		{
			name:         "get VLAN for port with policy",
			portID:       portID,
			expectedVLAN: 200,
			expectError:  false,
		},
		{
			name:        "empty port ID returns error",
			portID:      "",
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
		{
			name:        "non-existent port returns error",
			portID:      "nonexistent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vlan, err := engine.GetPortVLAN(tt.portID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedVLAN, vlan)
			}
		})
	}
}

func TestEngine_BlockPort(t *testing.T) {
	mockController := NewMockOVSFlowController()

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		portID      string
		setupMock   func()
		expectError bool
		errorType   error
	}{
		{
			name:   "block port successfully",
			portID: "eth0",
			setupMock: func() {
				mockController.installError = nil
				mockController.stateError = nil
			},
			expectError: false,
		},
		{
			name:        "empty port ID returns error",
			portID:      "",
			setupMock:   func() {},
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := engine.BlockPort(tt.portID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)

				// Verify port state
				state, err := engine.GetPortState(tt.portID)
				assert.NoError(t, err)
				assert.Equal(t, PortStateBlocked, state)

				// Verify OVSDB state was set
				assert.Equal(t, ovs.PortStateDown, mockController.portStates[tt.portID])

				// Verify blocking flows were installed
				flows := mockController.flows["br0"]
				assert.NotEmpty(t, flows)
			}
		})
	}
}

func TestEngine_UnblockPort(t *testing.T) {
	mockController := NewMockOVSFlowController()

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	// First block a port
	portID := "eth0"
	err = engine.BlockPort(portID)
	require.NoError(t, err)

	tests := []struct {
		name        string
		portID      string
		setupMock   func()
		expectError bool
		errorType   error
	}{
		{
			name:   "unblock port successfully",
			portID: portID,
			setupMock: func() {
				mockController.deleteError = nil
				mockController.stateError = nil
			},
			expectError: false,
		},
		{
			name:        "empty port ID returns error",
			portID:      "",
			setupMock:   func() {},
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := engine.UnblockPort(tt.portID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)

				// Verify port state changed to unauthorized
				state, err := engine.GetPortState(tt.portID)
				assert.NoError(t, err)
				assert.Equal(t, PortStateProvisioning, state)

				// Verify OVSDB state was set to up
				assert.Equal(t, ovs.PortStateUp, mockController.portStates[tt.portID])
			}
		})
	}
}

func TestEngine_GetOFPort(t *testing.T) {
	mockController := NewMockOVSFlowController()
	mockController.ofPorts["eth0"] = 5

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	tests := []struct {
		name           string
		portID         string
		expectedOFPort int32
		expectError    bool
		errorType      error
	}{
		{
			name:           "get OF port successfully",
			portID:         "eth0",
			expectedOFPort: 5,
			expectError:    false,
		},
		{
			name:        "empty port ID returns error",
			portID:      "",
			expectError: true,
			errorType:   ErrInvalidPortID,
		},
		{
			name:        "non-existent port returns error",
			portID:      "nonexistent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ofPort, err := engine.GetOFPort(tt.portID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedOFPort, ofPort)
			}
		})
	}
}

func TestEngine_BlockPort_WithFlowInstallError(t *testing.T) {
	mockController := NewMockOVSFlowController()
	mockController.installError = assert.AnError

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	err = engine.BlockPort("eth0")
	assert.Error(t, err)

	// Port state should not be changed if flow installation fails
	_, err = engine.GetPortState("eth0")
	assert.Error(t, err) // Port doesn't exist in state machine
}

func TestEngine_UnblockPort_WithFlowDeleteError(t *testing.T) {
	mockController := NewMockOVSFlowController()

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	// Block port first
	err = engine.BlockPort("eth0")
	require.NoError(t, err)

	// Set error for delete operation
	mockController.deleteError = assert.AnError

	err = engine.UnblockPort("eth0")
	assert.Error(t, err)

	// Port should still be blocked
	state, err := engine.GetPortState("eth0")
	require.NoError(t, err)
	assert.Equal(t, PortStateBlocked, state)
}
