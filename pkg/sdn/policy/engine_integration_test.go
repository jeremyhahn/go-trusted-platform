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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockOVSPortController mocks the OVSPortController interface
type MockOVSPortController struct {
	mock.Mock
}

func (m *MockOVSPortController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	args := m.Called(bridgeName, priority, match, actions)
	return args.Error(0)
}

func (m *MockOVSPortController) DeleteFlow(bridgeName string, match string) error {
	args := m.Called(bridgeName, match)
	return args.Error(0)
}

func (m *MockOVSPortController) DeleteFlowsByPort(bridgeName string, portID string) error {
	args := m.Called(bridgeName, portID)
	return args.Error(0)
}

func (m *MockOVSPortController) ListFlows(bridgeName string) ([]string, error) {
	args := m.Called(bridgeName)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockOVSPortController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	args := m.Called(ctx, portName, vlan)
	return args.Error(0)
}

func (m *MockOVSPortController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	args := m.Called(ctx, portName, state)
	return args.Error(0)
}

func (m *MockOVSPortController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	args := m.Called(ctx, portName)
	return args.Get(0).(int32), args.Error(1)
}

// TestNewEngine_WithOVSPortController tests engine creation with OVSPortController
func TestNewEngine_WithOVSPortController(t *testing.T) {
	mockController := new(MockOVSPortController)

	config := Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)
	assert.NotNil(t, engine)
	assert.Equal(t, "br0", engine.bridgeName)
	assert.NotNil(t, engine.portController)
}

// TestNewEngine_FlowControllerImplementsOVSPortController tests auto-detection
func TestNewEngine_FlowControllerImplementsOVSPortController(t *testing.T) {
	mockController := new(MockOVSPortController)

	config := Config{
		BridgeName:     "br0",
		FlowController: mockController,
		// PortController is nil - should auto-detect from FlowController
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)
	assert.NotNil(t, engine)
	assert.NotNil(t, engine.portController)
}

// TestNewEngine_MissingPortController tests error when port controller is not available
func TestNewEngine_MissingPortController(t *testing.T) {
	// Create a mock that only implements FlowController (not OVSPortController)
	mockFlowController := new(MockFlowController)

	config := Config{
		BridgeName:     "br0",
		FlowController: mockFlowController,
		// PortController is nil and FlowController doesn't implement OVSPortController
	}

	_, err := NewEngine(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port controller is required")
}

// TestSetPortVLAN tests VLAN setting via OVSDB
func TestSetPortVLAN(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		portID    string
		vlan      uint16
		setupMock func()
		wantErr   bool
		errMsg    string
	}{
		{
			name:   "valid VLAN",
			portID: "port1",
			vlan:   100,
			setupMock: func() {
				mockController.On("SetPortVLAN", mock.Anything, "port1", int64(100)).
					Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name:      "empty port ID",
			portID:    "",
			vlan:      100,
			setupMock: func() {},
			wantErr:   true,
			errMsg:    "invalid port ID",
		},
		{
			name:      "invalid VLAN - too low",
			portID:    "port1",
			vlan:      0,
			setupMock: func() {},
			wantErr:   true,
			errMsg:    "invalid VLAN ID",
		},
		{
			name:      "invalid VLAN - too high",
			portID:    "port1",
			vlan:      4095,
			setupMock: func() {},
			wantErr:   true,
			errMsg:    "invalid VLAN ID",
		},
		{
			name:   "OVSDB error",
			portID: "port1",
			vlan:   100,
			setupMock: func() {
				mockController.On("SetPortVLAN", mock.Anything, "port1", int64(100)).
					Return(errors.New("OVSDB connection failed")).Once()
			},
			wantErr: true,
			errMsg:  "failed to set port VLAN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := engine.SetPortVLAN(tt.portID, tt.vlan)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}

	mockController.AssertExpectations(t)
}

// TestApplyPolicy_WithVLAN tests policy application with VLAN configuration
func TestApplyPolicy_WithVLAN(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	policy := &PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		ACLs:     []ACLRule{},
	}

	// Setup expectations
	mockController.On("SetPortVLAN", mock.Anything, "port1", int64(100)).
		Return(nil).Once()
	mockController.On("InstallFlow", "br0", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Times(2) // VLAN rule + default allow rule

	err = engine.ApplyPolicy("port1", policy)
	assert.NoError(t, err)

	// Verify state
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, state)

	// Verify policy
	retrievedPolicy, err := engine.GetPolicy("port1")
	assert.NoError(t, err)
	assert.Equal(t, policy.TenantID, retrievedPolicy.TenantID)
	assert.Equal(t, policy.VLAN, retrievedPolicy.VLAN)

	mockController.AssertExpectations(t)
}

// TestApplyPolicy_VLANFailure tests rollback when VLAN configuration fails
func TestApplyPolicy_VLANFailure(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	policy := &PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		ACLs:     []ACLRule{},
	}

	// Setup expectations - VLAN setting fails
	mockController.On("SetPortVLAN", mock.Anything, "port1", int64(100)).
		Return(errors.New("OVSDB error")).Once()

	err = engine.ApplyPolicy("port1", policy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set port VLAN")

	// Verify state was rolled back
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateUnauthorized, state)

	// Verify no policy is stored
	_, err = engine.GetPolicy("port1")
	assert.Error(t, err)
	assert.Equal(t, ErrPolicyNotFound, err)

	mockController.AssertExpectations(t)
}

// TestRemovePolicy_ClearsVLAN tests that RemovePolicy clears VLAN assignment
func TestRemovePolicy_ClearsVLAN(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	// First apply a policy with VLAN
	policy := &PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		ACLs:     []ACLRule{},
	}

	mockController.On("SetPortVLAN", mock.Anything, "port1", int64(100)).
		Return(nil).Once()
	mockController.On("InstallFlow", "br0", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Times(2)

	err = engine.ApplyPolicy("port1", policy)
	require.NoError(t, err)

	// Now remove the policy
	mockController.On("DeleteFlowsByPort", "br0", "port1").Return(nil).Once()
	mockController.On("SetPortVLAN", mock.Anything, "port1", int64(0)).
		Return(nil).Once()

	err = engine.RemovePolicy("port1")
	assert.NoError(t, err)

	// Verify state
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateUnauthorized, state)

	mockController.AssertExpectations(t)
}

// TestSetPortState_Blocked tests port blocking with both flows and OVSDB state
func TestSetPortState_Blocked(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	// Setup expectations for blocking
	mockController.On("InstallFlow", "br0", mock.Anything, "in_port=port1", "drop").
		Return(nil).Once()
	mockController.On("SetPortState", mock.Anything, "port1", ovs.PortStateDown).
		Return(nil).Once()

	err = engine.SetPortState("port1", PortStateBlocked)
	assert.NoError(t, err)

	// Verify state
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateBlocked, state)

	mockController.AssertExpectations(t)
}

// TestSetPortState_Blocked_OVSDBFailure tests that blocking still works if OVSDB fails
func TestSetPortState_Blocked_OVSDBFailure(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	// Setup expectations - flow install succeeds, OVSDB state change fails
	mockController.On("InstallFlow", "br0", mock.Anything, "in_port=port1", "drop").
		Return(nil).Once()
	mockController.On("SetPortState", mock.Anything, "port1", ovs.PortStateDown).
		Return(errors.New("OVSDB error")).Once()

	// Should still succeed because DROP rules are primary mechanism
	err = engine.SetPortState("port1", PortStateBlocked)
	assert.NoError(t, err)

	mockController.AssertExpectations(t)
}

// TestApplyPolicy_CompleteFlow tests the complete flow with all operations
func TestApplyPolicy_CompleteFlow(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	policy := &PortPolicy{
		TenantID: "tenant1",
		VLAN:     200,
		ACLs: []ACLRule{
			{
				Priority: 100,
				Match: FlowMatch{
					IPv4Dst: "10.0.0.0/24",
				},
				Action: FlowAction{
					Type: FlowActionAllow,
				},
			},
		},
	}

	// Setup expectations
	mockController.On("SetPortVLAN", mock.Anything, "port1", int64(200)).
		Return(nil).Once()
	mockController.On("InstallFlow", "br0", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Times(2) // VLAN rule + ACL rule

	err = engine.ApplyPolicy("port1", policy)
	assert.NoError(t, err)

	// Verify complete state
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, state)

	info, err := engine.GetPortInfo("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, info.State)
	assert.NotNil(t, info.Policy)
	assert.Equal(t, uint16(200), info.Policy.VLAN)

	mockController.AssertExpectations(t)
}

// TestOnCertificateExpired tests certificate expiry handling
func TestOnCertificateExpired(t *testing.T) {
	mockController := new(MockOVSPortController)

	engine, err := NewEngine(Config{
		BridgeName:     "br0",
		FlowController: mockController,
		PortController: mockController,
	})
	require.NoError(t, err)

	// First set up a port with a policy
	policy := &PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		ACLs:     []ACLRule{},
	}

	mockController.On("SetPortVLAN", mock.Anything, "port1", int64(100)).
		Return(nil).Once()
	mockController.On("InstallFlow", "br0", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Times(2)

	err = engine.ApplyPolicy("port1", policy)
	require.NoError(t, err)

	// Now handle certificate expiry
	mockController.On("DeleteFlowsByPort", "br0", "port1").Return(nil).Once()
	mockController.On("InstallFlow", "br0", mock.Anything, "in_port=port1", "drop").
		Return(nil).Once()
	mockController.On("SetPortState", mock.Anything, "port1", ovs.PortStateDown).
		Return(nil).Once()

	err = engine.OnCertificateExpired("port1")
	assert.NoError(t, err)

	// Verify port is blocked
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateBlocked, state)

	mockController.AssertExpectations(t)
}

// MockFlowController only implements FlowController (not OVSPortController)
type MockFlowController struct {
	mock.Mock
}

func (m *MockFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	args := m.Called(bridgeName, priority, match, actions)
	return args.Error(0)
}

func (m *MockFlowController) DeleteFlow(bridgeName string, match string) error {
	args := m.Called(bridgeName, match)
	return args.Error(0)
}

func (m *MockFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	args := m.Called(bridgeName, portID)
	return args.Error(0)
}

func (m *MockFlowController) ListFlows(bridgeName string) ([]string, error) {
	args := m.Called(bridgeName)
	return args.Get(0).([]string), args.Error(1)
}

// MockPolicyExtractor for testing certificate-based authentication
type MockPolicyExtractor struct {
	mock.Mock
}

func (m *MockPolicyExtractor) ExtractPolicy(cert *x509.Certificate) (*PortPolicy, error) {
	args := m.Called(cert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PortPolicy), args.Error(1)
}

func (m *MockPolicyExtractor) ExtractTenantID(cert *x509.Certificate) (string, error) {
	args := m.Called(cert)
	return args.String(0), args.Error(1)
}

func (m *MockPolicyExtractor) ExtractVLAN(cert *x509.Certificate) (uint16, error) {
	args := m.Called(cert)
	return args.Get(0).(uint16), args.Error(1)
}

func (m *MockPolicyExtractor) ExtractACLs(cert *x509.Certificate) ([]ACLRule, error) {
	args := m.Called(cert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]ACLRule), args.Error(1)
}

// TestAuthenticatePort_Success tests successful certificate-based authentication
func TestAuthenticatePort_Success(t *testing.T) {
	mockController := new(MockOVSPortController)
	mockExtractor := new(MockPolicyExtractor)

	engine, err := NewEngine(Config{
		BridgeName:      "br0",
		FlowController:  mockController,
		PortController:  mockController,
		PolicyExtractor: mockExtractor,
	})
	require.NoError(t, err)

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "device1",
		},
	}

	policy := &PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		ACLs:     []ACLRule{},
	}

	// Setup expectations
	mockExtractor.On("ExtractPolicy", cert).Return(policy, nil).Once()
	mockController.On("SetPortVLAN", mock.Anything, "port1", int64(100)).
		Return(nil).Once()
	mockController.On("InstallFlow", "br0", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Times(2)

	err = engine.AuthenticatePort("port1", cert)
	assert.NoError(t, err)

	// Verify state
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, state)

	mockController.AssertExpectations(t)
	mockExtractor.AssertExpectations(t)
}

// TestAuthenticatePort_PolicyExtractionFailure tests policy extraction failure
func TestAuthenticatePort_PolicyExtractionFailure(t *testing.T) {
	mockController := new(MockOVSPortController)
	mockExtractor := new(MockPolicyExtractor)

	engine, err := NewEngine(Config{
		BridgeName:      "br0",
		FlowController:  mockController,
		PortController:  mockController,
		PolicyExtractor: mockExtractor,
	})
	require.NoError(t, err)

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "device1",
		},
	}

	// Setup expectations - policy extraction fails
	mockExtractor.On("ExtractPolicy", cert).
		Return((*PortPolicy)(nil), errors.New("missing tenant ID")).Once()

	err = engine.AuthenticatePort("port1", cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "policy extraction failed")

	// Verify state is unauthorized
	state, err := engine.GetPortState("port1")
	assert.NoError(t, err)
	assert.Equal(t, PortStateUnauthorized, state)

	mockController.AssertExpectations(t)
	mockExtractor.AssertExpectations(t)
}
