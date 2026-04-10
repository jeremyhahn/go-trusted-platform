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

package compute

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// mockPolicyEngine implements policy.PolicyEngine for testing
type mockPolicyEngine struct {
	portStates   map[string]policy.PortState
	portPolicies map[string]*policy.PortPolicy
}

func newMockPolicyEngine() *mockPolicyEngine {
	return &mockPolicyEngine{
		portStates:   make(map[string]policy.PortState),
		portPolicies: make(map[string]*policy.PortPolicy),
	}
}

func (m *mockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	m.portStates[portID] = state
	return nil
}

func (m *mockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	state, ok := m.portStates[portID]
	if !ok {
		return policy.PortStateUnconnected, nil
	}
	return state, nil
}

func (m *mockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	state, _ := m.GetPortState(portID)
	portPolicy, _ := m.GetPolicy(portID)
	return &policy.PortInfo{
		PortID: portID,
		State:  state,
		Policy: portPolicy,
	}, nil
}

func (m *mockPolicyEngine) ApplyPolicy(portID string, portPolicy *policy.PortPolicy) error {
	m.portPolicies[portID] = portPolicy
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *mockPolicyEngine) RemovePolicy(portID string) error {
	delete(m.portPolicies, portID)
	delete(m.portStates, portID)
	return nil
}

func (m *mockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	portPolicy, ok := m.portPolicies[portID]
	if !ok {
		return nil, nil
	}
	return portPolicy, nil
}

func (m *mockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	return nil
}

func (m *mockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	portPolicy, ok := m.portPolicies[portID]
	if !ok {
		return 0, nil
	}
	return portPolicy.VLAN, nil
}

func (m *mockPolicyEngine) BlockPort(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mockPolicyEngine) UnblockPort(portID string) error {
	m.portStates[portID] = policy.PortStateUnconnected
	return nil
}

func (m *mockPolicyEngine) GetOFPort(portID string) (int32, error) {
	return 1, nil
}

func (m *mockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	m.portStates[portID] = policy.PortStateAuthenticating
	return nil
}

func (m *mockPolicyEngine) OnCertificateExpired(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mockPolicyEngine) OnCertificateRevoked(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}

func TestSetProvisioningState(t *testing.T) {
	tests := []struct {
		name      string
		config    *PortAuthConfig
		wantState policy.PortState
		wantErr   bool
	}{
		{
			name: "successful provisioning state",
			config: &PortAuthConfig{
				PortID:       "test-port",
				BridgeName:   "trusted0",
				MACAddress:   "00:11:22:33:44:55",
				PolicyEngine: newMockPolicyEngine(),
			},
			wantState: policy.PortStateProvisioning,
			wantErr:   false,
		},
		{
			name:      "nil config",
			config:    nil,
			wantState: policy.PortStateUnconnected,
			wantErr:   true,
		},
		{
			name: "empty port ID",
			config: &PortAuthConfig{
				PortID:       "",
				BridgeName:   "trusted0",
				PolicyEngine: newMockPolicyEngine(),
			},
			wantState: policy.PortStateUnconnected,
			wantErr:   true,
		},
		{
			name: "nil policy engine",
			config: &PortAuthConfig{
				PortID:       "test-port",
				BridgeName:   "trusted0",
				PolicyEngine: nil,
			},
			wantState: policy.PortStateUnconnected,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetProvisioningState(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetProvisioningState() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.config != nil && tt.config.PolicyEngine != nil {
				state, err := tt.config.PolicyEngine.GetPortState(tt.config.PortID)
				if err != nil {
					t.Errorf("GetPortState() error = %v", err)
					return
				}
				if state != tt.wantState {
					t.Errorf("GetPortState() = %v, want %v", state, tt.wantState)
				}
			}
		})
	}
}

func TestActivatePort(t *testing.T) {
	tests := []struct {
		name       string
		config     *PortAuthConfig
		portPolicy *policy.PortPolicy
		wantState  policy.PortState
		wantErr    bool
	}{
		{
			name: "successful activation",
			config: &PortAuthConfig{
				PortID:       "test-port",
				BridgeName:   "trusted0",
				MACAddress:   "00:11:22:33:44:55",
				PolicyEngine: newMockPolicyEngine(),
			},
			portPolicy: &policy.PortPolicy{
				TenantID: "tenant1",
				VLAN:     100,
			},
			wantState: policy.PortStateAuthorized,
			wantErr:   false,
		},
		{
			name:   "nil config",
			config: nil,
			portPolicy: &policy.PortPolicy{
				TenantID: "tenant1",
				VLAN:     100,
			},
			wantState: policy.PortStateUnconnected,
			wantErr:   true,
		},
		{
			name: "nil port policy",
			config: &PortAuthConfig{
				PortID:       "test-port",
				BridgeName:   "trusted0",
				PolicyEngine: newMockPolicyEngine(),
			},
			portPolicy: nil,
			wantState:  policy.PortStateUnconnected,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ActivatePort(tt.config, tt.portPolicy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ActivatePort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.config != nil && tt.config.PolicyEngine != nil {
				state, err := tt.config.PolicyEngine.GetPortState(tt.config.PortID)
				if err != nil {
					t.Errorf("GetPortState() error = %v", err)
					return
				}
				if state != tt.wantState {
					t.Errorf("GetPortState() = %v, want %v", state, tt.wantState)
				}

				// Verify policy was applied
				appliedPolicy, err := tt.config.PolicyEngine.GetPolicy(tt.config.PortID)
				if err != nil {
					t.Errorf("GetPolicy() error = %v", err)
					return
				}
				if appliedPolicy == nil {
					t.Error("GetPolicy() returned nil, expected policy")
					return
				}
				if appliedPolicy.VLAN != tt.portPolicy.VLAN {
					t.Errorf("GetPolicy().VLAN = %v, want %v", appliedPolicy.VLAN, tt.portPolicy.VLAN)
				}
			}
		})
	}
}

func TestGetPortState(t *testing.T) {
	mockEngine := newMockPolicyEngine()
	mockEngine.SetPortState("test-port", policy.PortStateProvisioning)

	tests := []struct {
		name      string
		config    *PortAuthConfig
		wantState policy.PortState
		wantErr   bool
	}{
		{
			name: "get existing state",
			config: &PortAuthConfig{
				PortID:       "test-port",
				BridgeName:   "trusted0",
				PolicyEngine: mockEngine,
			},
			wantState: policy.PortStateProvisioning,
			wantErr:   false,
		},
		{
			name:      "nil config",
			config:    nil,
			wantState: policy.PortStateUnconnected,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := GetPortState(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPortState() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if state != tt.wantState {
				t.Errorf("GetPortState() = %v, want %v", state, tt.wantState)
			}
		})
	}
}

func TestRemovePortAuth(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *PortAuthConfig
		wantErr bool
	}{
		{
			name: "successful removal",
			setup: func() *PortAuthConfig {
				mockEngine := newMockPolicyEngine()
				mockEngine.SetPortState("test-port", policy.PortStateAuthorized)
				mockEngine.ApplyPolicy("test-port", &policy.PortPolicy{
					TenantID: "tenant1",
					VLAN:     100,
				})
				return &PortAuthConfig{
					PortID:       "test-port",
					BridgeName:   "trusted0",
					PolicyEngine: mockEngine,
				}
			},
			wantErr: false,
		},
		{
			name: "nil config",
			setup: func() *PortAuthConfig {
				return nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setup()
			err := RemovePortAuth(config)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemovePortAuth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && config != nil && config.PolicyEngine != nil {
				// Verify policy was removed
				portPolicy, err := config.PolicyEngine.GetPolicy(config.PortID)
				if err != nil {
					t.Errorf("GetPolicy() error = %v", err)
					return
				}
				if portPolicy != nil {
					t.Error("GetPolicy() returned policy, expected nil after removal")
				}
			}
		})
	}
}

func TestPortAuthWorkflow(t *testing.T) {
	// Test the complete workflow: provisioning -> enrolled -> authorized
	mockEngine := newMockPolicyEngine()
	config := &PortAuthConfig{
		PortID:       "test-port",
		BridgeName:   "trusted0",
		MACAddress:   "00:11:22:33:44:55",
		PolicyEngine: mockEngine,
	}

	// Step 1: Set provisioning state
	if err := SetProvisioningState(config); err != nil {
		t.Fatalf("SetProvisioningState() error = %v", err)
	}

	state, err := GetPortState(config)
	if err != nil {
		t.Fatalf("GetPortState() error = %v", err)
	}
	if state != policy.PortStateProvisioning {
		t.Errorf("After provisioning, state = %v, want %v", state, policy.PortStateProvisioning)
	}

	// Step 2: Simulate enrollment (would be done by enrollment hook)
	mockEngine.SetPortState("test-port", policy.PortStateEnrolled)

	state, err = GetPortState(config)
	if err != nil {
		t.Fatalf("GetPortState() error = %v", err)
	}
	if state != policy.PortStateEnrolled {
		t.Errorf("After enrollment, state = %v, want %v", state, policy.PortStateEnrolled)
	}

	// Step 3: Activate with production policy
	portPolicy := &policy.PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		ACLs:     []policy.ACLRule{},
	}

	if err := ActivatePort(config, portPolicy); err != nil {
		t.Fatalf("ActivatePort() error = %v", err)
	}

	state, err = GetPortState(config)
	if err != nil {
		t.Fatalf("GetPortState() error = %v", err)
	}
	if state != policy.PortStateAuthorized {
		t.Errorf("After activation, state = %v, want %v", state, policy.PortStateAuthorized)
	}

	// Verify policy
	appliedPolicy, err := mockEngine.GetPolicy("test-port")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if appliedPolicy == nil {
		t.Fatal("GetPolicy() returned nil")
	}
	if appliedPolicy.VLAN != 100 {
		t.Errorf("Policy VLAN = %v, want %v", appliedPolicy.VLAN, 100)
	}

	// Step 4: Remove authentication
	if err := RemovePortAuth(config); err != nil {
		t.Fatalf("RemovePortAuth() error = %v", err)
	}

	// Verify policy removed
	removedPolicy, err := mockEngine.GetPolicy("test-port")
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if removedPolicy != nil {
		t.Error("Policy should be nil after removal")
	}
}
