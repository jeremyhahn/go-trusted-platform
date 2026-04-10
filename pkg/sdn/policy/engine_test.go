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
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock FlowController for testing
type mockFlowController struct {
	mu           sync.Mutex
	flows        map[string][]mockFlow
	installError error
	deleteError  error
}

type mockFlow struct {
	priority int
	match    string
	actions  string
}

func newMockFlowController() *mockFlowController {
	return &mockFlowController{
		flows: make(map[string][]mockFlow),
	}
}

func (m *mockFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.installError != nil {
		return m.installError
	}

	m.flows[bridgeName] = append(m.flows[bridgeName], mockFlow{
		priority: priority,
		match:    match,
		actions:  actions,
	})

	return nil
}

func (m *mockFlowController) DeleteFlow(bridgeName string, match string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteError != nil {
		return m.deleteError
	}

	// Simple mock implementation
	delete(m.flows, bridgeName)
	return nil
}

func (m *mockFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteError != nil {
		return m.deleteError
	}

	// Remove flows matching the port
	if flows, exists := m.flows[bridgeName]; exists {
		filtered := []mockFlow{}
		for _, flow := range flows {
			// Simple check - doesn't contain the port ID
			if flow.match == "" || len(flow.match) == 0 {
				continue
			}
			filtered = append(filtered, flow)
		}
		m.flows[bridgeName] = filtered
	}

	return nil
}

func (m *mockFlowController) ListFlows(bridgeName string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	flows := m.flows[bridgeName]
	result := make([]string, len(flows))
	for i, flow := range flows {
		result[i] = flow.match + " -> " + flow.actions
	}
	return result, nil
}

// OVSPortController interface implementation

func (m *mockFlowController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	return nil
}

func (m *mockFlowController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	return nil
}

func (m *mockFlowController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	return 1, nil
}

func (m *mockFlowController) GetFlowCount(bridgeName string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.flows[bridgeName])
}

func TestNewEngine(t *testing.T) {
	flowController := newMockFlowController()

	t.Run("Valid config", func(t *testing.T) {
		config := Config{
			BridgeName:     "br0",
			FlowController: flowController,
		}

		engine, err := NewEngine(config)
		assert.NoError(t, err)
		assert.NotNil(t, engine)
		assert.Equal(t, "br0", engine.bridgeName)
	})

	t.Run("Missing bridge name", func(t *testing.T) {
		config := Config{
			FlowController: flowController,
		}

		_, err := NewEngine(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bridge name")
	})

	t.Run("Missing flow controller", func(t *testing.T) {
		config := Config{
			BridgeName: "br0",
		}

		_, err := NewEngine(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "flow controller")
	})

	t.Run("With monitoring enabled", func(t *testing.T) {
		config := Config{
			BridgeName:       "br0",
			FlowController:   flowController,
			EnableMonitoring: true,
		}

		engine, err := NewEngine(config)
		assert.NoError(t, err)
		assert.NotNil(t, engine.monitor)
	})
}

func TestEngine_SetPortState(t *testing.T) {
	t.Run("Set unauthorized from provisioning", func(t *testing.T) {
		engine := createTestEngine(t)
		portID := "port1"

		// Transition from unconnected -> provisioning first
		err := engine.SetPortState(portID, PortStateProvisioning)
		require.NoError(t, err)

		// Then transition to unauthorized
		err = engine.SetPortState(portID, PortStateUnauthorized)
		assert.NoError(t, err)

		state, err := engine.GetPortState(portID)
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)
	})

	t.Run("Set authenticating from provisioning", func(t *testing.T) {
		engine := createTestEngine(t)
		portID := "port2"

		// Transition from unconnected -> provisioning first
		err := engine.SetPortState(portID, PortStateProvisioning)
		require.NoError(t, err)

		// Then transition to authenticating
		err = engine.SetPortState(portID, PortStateAuthenticating)
		assert.NoError(t, err)

		state, err := engine.GetPortState(portID)
		assert.NoError(t, err)
		assert.Equal(t, PortStateAuthenticating, state)
	})

	t.Run("Set blocked from unconnected", func(t *testing.T) {
		engine := createTestEngine(t)
		portID := "port3"

		// Blocked is valid from unconnected, no setup needed
		err := engine.SetPortState(portID, PortStateBlocked)
		assert.NoError(t, err)

		state, err := engine.GetPortState(portID)
		assert.NoError(t, err)
		assert.Equal(t, PortStateBlocked, state)
	})

	t.Run("Empty port ID", func(t *testing.T) {
		engine := createTestEngine(t)

		err := engine.SetPortState("", PortStateUnauthorized)
		assert.ErrorIs(t, err, ErrInvalidPortID)
	})
}

func TestEngine_ApplyPolicy(t *testing.T) {
	engine := createTestEngine(t)

	t.Run("Valid policy", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
			ACLs:     []ACLRule{},
		}

		err := engine.ApplyPolicy("port1", policy)
		assert.NoError(t, err)

		// Verify state changed to authorized
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateAuthorized, state)

		// Verify policy was stored
		retrievedPolicy, err := engine.GetPolicy("port1")
		assert.NoError(t, err)
		assert.Equal(t, policy.TenantID, retrievedPolicy.TenantID)
		assert.Equal(t, policy.VLAN, retrievedPolicy.VLAN)
	})

	t.Run("Invalid port ID", func(t *testing.T) {
		err := engine.ApplyPolicy("", &PortPolicy{})
		assert.ErrorIs(t, err, ErrInvalidPortID)
	})

	t.Run("Nil policy", func(t *testing.T) {
		err := engine.ApplyPolicy("port1", nil)
		assert.ErrorIs(t, err, ErrInvalidPolicy)
	})

	t.Run("Missing tenant ID", func(t *testing.T) {
		policy := &PortPolicy{
			VLAN: 100,
		}

		err := engine.ApplyPolicy("port2", policy)
		assert.ErrorIs(t, err, ErrMissingTenantID)
	})

	t.Run("Invalid VLAN", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     0,
		}

		err := engine.ApplyPolicy("port3", policy)
		assert.ErrorIs(t, err, ErrInvalidVLAN)
	})

	t.Run("VLAN too high", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     5000,
		}

		err := engine.ApplyPolicy("port4", policy)
		assert.ErrorIs(t, err, ErrInvalidVLAN)
	})

	t.Run("Invalid ACL priority", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
			ACLs: []ACLRule{
				{
					Priority: -1,
				},
			},
		}

		err := engine.ApplyPolicy("port5", policy)
		assert.ErrorIs(t, err, ErrInvalidACL)
	})
}

func TestEngine_RemovePolicy(t *testing.T) {
	engine := createTestEngine(t)

	t.Run("Remove existing policy", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		require.NoError(t, engine.ApplyPolicy("port1", policy))

		err := engine.RemovePolicy("port1")
		assert.NoError(t, err)

		// Verify state changed to unauthorized
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)

		// Verify policy was removed
		_, err = engine.GetPolicy("port1")
		assert.ErrorIs(t, err, ErrPolicyNotFound)
	})

	t.Run("Invalid port ID", func(t *testing.T) {
		err := engine.RemovePolicy("")
		assert.ErrorIs(t, err, ErrInvalidPortID)
	})
}

func TestEngine_GetPolicy(t *testing.T) {
	engine := createTestEngine(t)

	t.Run("Policy not found", func(t *testing.T) {
		_, err := engine.GetPolicy("nonexistent")
		assert.Error(t, err)
	})

	t.Run("Get existing policy", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		require.NoError(t, engine.ApplyPolicy("port1", policy))

		retrievedPolicy, err := engine.GetPolicy("port1")
		assert.NoError(t, err)
		assert.Equal(t, policy.TenantID, retrievedPolicy.TenantID)
		assert.Equal(t, policy.VLAN, retrievedPolicy.VLAN)
	})
}

func TestEngine_AuthenticatePort(t *testing.T) {
	t.Run("Valid certificate", func(t *testing.T) {
		engine := createTestEngine(t)

		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization:       []string{"tenant-1"},
				OrganizationalUnit: []string{"vlan=100"},
			},
		})

		err := engine.AuthenticatePort("port1", cert)
		assert.NoError(t, err)

		// Verify port is authorized
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateAuthorized, state)

		// Verify policy was extracted and applied
		policy, err := engine.GetPolicy("port1")
		assert.NoError(t, err)
		assert.Equal(t, "tenant-1", policy.TenantID)
		assert.Equal(t, uint16(100), policy.VLAN)
	})

	t.Run("Invalid port ID", func(t *testing.T) {
		engine := createTestEngine(t)

		cert := createTestCertificate(t, x509.Certificate{})
		err := engine.AuthenticatePort("", cert)
		assert.ErrorIs(t, err, ErrInvalidPortID)
	})

	t.Run("Nil certificate", func(t *testing.T) {
		engine := createTestEngine(t)

		err := engine.AuthenticatePort("port1", nil)
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})

	t.Run("Certificate missing VLAN", func(t *testing.T) {
		engine := createTestEngine(t)

		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"tenant-1"},
			},
		})

		err := engine.AuthenticatePort("port2", cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy extraction failed")

		// Verify port is unauthorized
		state, err := engine.GetPortState("port2")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)
	})
}

func TestEngine_OnCertificateExpired(t *testing.T) {
	engine := createTestEngine(t)

	t.Run("Expire authorized port", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		require.NoError(t, engine.ApplyPolicy("port1", policy))

		err := engine.OnCertificateExpired("port1")
		assert.NoError(t, err)

		// Verify port is blocked
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateBlocked, state)
	})
}

func TestEngine_OnCertificateRevoked(t *testing.T) {
	engine := createTestEngine(t)

	t.Run("Revoke authorized port", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		require.NoError(t, engine.ApplyPolicy("port1", policy))

		err := engine.OnCertificateRevoked("port1")
		assert.NoError(t, err)

		// Verify port is blocked
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateBlocked, state)
	})
}

func TestEngine_GetPortInfo(t *testing.T) {
	engine := createTestEngine(t)

	t.Run("Port not found", func(t *testing.T) {
		_, err := engine.GetPortInfo("nonexistent")
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("Get port info", func(t *testing.T) {
		// Follow proper state machine flow: unconnected -> provisioning -> authenticating -> authorized
		require.NoError(t, engine.SetPortState("port1", PortStateProvisioning))
		require.NoError(t, engine.SetPortState("port1", PortStateAuthenticating))
		require.NoError(t, engine.SetPortState("port1", PortStateAuthorized))

		info, err := engine.GetPortInfo("port1")
		assert.NoError(t, err)
		assert.NotNil(t, info)
		assert.Equal(t, "port1", info.PortID)
		assert.Equal(t, PortStateAuthorized, info.State)
	})
}

func TestEngine_GetMonitor(t *testing.T) {
	t.Run("Without monitoring", func(t *testing.T) {
		engine := createTestEngine(t)
		monitor := engine.GetMonitor()
		assert.Nil(t, monitor)
	})

	t.Run("With monitoring", func(t *testing.T) {
		config := Config{
			BridgeName:       "br0",
			FlowController:   newMockFlowController(),
			EnableMonitoring: true,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		monitor := engine.GetMonitor()
		assert.NotNil(t, monitor)
	})
}

func TestEngine_FlowInstallation(t *testing.T) {
	controller := newMockFlowController()
	config := Config{
		BridgeName:     "br0",
		FlowController: controller,
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)

	t.Run("Install flows on policy application", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
			ACLs: []ACLRule{
				{
					Priority: 100,
					Match:    FlowMatch{},
					Action:   FlowAction{Type: FlowActionAllow},
				},
			},
		}

		initialCount := controller.GetFlowCount("br0")
		err := engine.ApplyPolicy("port1", policy)
		assert.NoError(t, err)

		// Verify flows were installed
		finalCount := controller.GetFlowCount("br0")
		assert.Greater(t, finalCount, initialCount)
	})

	t.Run("Remove flows on policy removal", func(t *testing.T) {
		policy := &PortPolicy{
			TenantID: "tenant-2",
			VLAN:     200,
		}

		require.NoError(t, engine.ApplyPolicy("port2", policy))

		err := engine.RemovePolicy("port2")
		assert.NoError(t, err)

		// Flows should be removed (mock just clears for simplicity)
	})
}

func TestEngine_ConcurrentOperations(t *testing.T) {
	engine := createTestEngine(t)

	var wg sync.WaitGroup
	numPorts := 10

	// Concurrent policy applications
	for i := 0; i < numPorts; i++ {
		wg.Add(1)
		go func(portNum int) {
			defer wg.Done()

			portID := fmt.Sprintf("port%d", portNum)
			policy := &PortPolicy{
				TenantID: fmt.Sprintf("tenant-%d", portNum),
				VLAN:     uint16(100 + portNum),
			}

			err := engine.ApplyPolicy(portID, policy)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify all policies were applied
	for i := 0; i < numPorts; i++ {
		portID := fmt.Sprintf("port%d", i)
		policy, err := engine.GetPolicy(portID)
		assert.NoError(t, err)
		assert.NotNil(t, policy)
	}
}

// Helper function to create test engine
func createTestEngine(t *testing.T) *Engine {
	t.Helper()

	config := Config{
		BridgeName:     "br0",
		FlowController: newMockFlowController(),
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)

	return engine
}
