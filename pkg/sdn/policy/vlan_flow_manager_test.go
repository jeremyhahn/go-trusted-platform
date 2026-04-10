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
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vlanMockFlowController implements FlowController for VLAN flow manager testing
type vlanMockFlowController struct {
	mu              sync.Mutex
	flows           map[string][]vlanMockFlow
	installErr      error
	deleteErr       error
	deleteByPortErr error
}

type vlanMockFlow struct {
	priority int
	match    string
	actions  string
}

func newVLANMockFlowController() *vlanMockFlowController {
	return &vlanMockFlowController{
		flows: make(map[string][]vlanMockFlow),
	}
}

func (m *vlanMockFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.installErr != nil {
		return m.installErr
	}

	m.flows[bridgeName] = append(m.flows[bridgeName], vlanMockFlow{
		priority: priority,
		match:    match,
		actions:  actions,
	})
	return nil
}

func (m *vlanMockFlowController) DeleteFlow(bridgeName string, match string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteErr != nil {
		return m.deleteErr
	}

	flows, ok := m.flows[bridgeName]
	if !ok {
		return nil
	}

	newFlows := make([]vlanMockFlow, 0)
	for _, flow := range flows {
		if flow.match != match {
			newFlows = append(newFlows, flow)
		}
	}
	m.flows[bridgeName] = newFlows
	return nil
}

func (m *vlanMockFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteByPortErr != nil {
		return m.deleteByPortErr
	}

	delete(m.flows, bridgeName)
	return nil
}

func (m *vlanMockFlowController) ListFlows(bridgeName string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	flows, ok := m.flows[bridgeName]
	if !ok {
		return nil, nil
	}

	result := make([]string, len(flows))
	for i, flow := range flows {
		result[i] = fmt.Sprintf("priority=%d,%s,actions=%s", flow.priority, flow.match, flow.actions)
	}
	return result, nil
}

func (m *vlanMockFlowController) getFlowCount(bridgeName string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.flows[bridgeName])
}

func TestNewVLANFlowManager(t *testing.T) {
	t.Run("success with defaults", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)

		assert.Equal(t, "br0", manager.bridgeName)
		assert.Equal(t, DefaultProvisioningVLAN, manager.provisioningVLAN)
		assert.Equal(t, DefaultQuarantineVLAN, manager.quarantineVLAN)
		assert.NotNil(t, manager.provisioningGenerator)
		assert.NotNil(t, manager.quarantineGenerator)
		assert.NotNil(t, manager.ruleGenerator)
		assert.NotNil(t, manager.portVLANMap)
	})

	t.Run("success with custom VLANs", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:       "br0",
			FlowController:   mockController,
			ProvisioningVLAN: 100,
			QuarantineVLAN:   200,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)

		assert.Equal(t, uint16(100), manager.provisioningVLAN)
		assert.Equal(t, uint16(200), manager.quarantineVLAN)
	})

	t.Run("success with custom logger", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		logger := slog.Default()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
			Logger:         logger,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, logger, manager.logger)
	})

	t.Run("error missing bridge name", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.Error(t, err)
		assert.Nil(t, manager)
		assert.Contains(t, err.Error(), "bridge name is required")
	})

	t.Run("error missing flow controller", func(t *testing.T) {
		config := VLANFlowManagerConfig{
			BridgeName: "br0",
		}

		manager, err := NewVLANFlowManager(config)
		require.Error(t, err)
		assert.Nil(t, manager)
		assert.Contains(t, err.Error(), "flow controller is required")
	})
}

func TestApplyProvisioningFlows(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyProvisioningFlows("eth0", "00:11:22:33:44:55")
		require.NoError(t, err)

		// Verify flows were installed
		assert.Greater(t, mockController.getFlowCount("br0"), 0)

		// Verify VLAN tracking
		vlan, err := manager.GetPortVLAN("eth0")
		require.NoError(t, err)
		assert.Equal(t, DefaultProvisioningVLAN, vlan)
	})

	t.Run("error invalid port ID", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyProvisioningFlows("", "00:11:22:33:44:55")
		require.Error(t, err)
		assert.Equal(t, ErrInvalidPortID, err)
	})

	t.Run("error flow installation fails", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		mockController.installErr = fmt.Errorf("installation failed")

		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyProvisioningFlows("eth0", "00:11:22:33:44:55")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowInstallFailed)
	})

	t.Run("replaces existing flows", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		// Apply flows first time
		err = manager.ApplyProvisioningFlows("eth0", "00:11:22:33:44:55")
		require.NoError(t, err)

		// Apply flows second time (should replace)
		err = manager.ApplyProvisioningFlows("eth0", "00:11:22:33:44:55")
		require.NoError(t, err)

		// Verify VLAN is still tracked
		vlan, err := manager.GetPortVLAN("eth0")
		require.NoError(t, err)
		assert.Equal(t, DefaultProvisioningVLAN, vlan)
	})
}

func TestApplyProductionFlows(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 100,
				},
			},
		}

		err = manager.ApplyProductionFlows("eth0", profile)
		require.NoError(t, err)

		// Verify flows were installed
		assert.Greater(t, mockController.getFlowCount("br0"), 0)

		// Verify VLAN tracking
		vlan, err := manager.GetPortVLAN("eth0")
		require.NoError(t, err)
		assert.Equal(t, uint16(100), vlan)
	})

	t.Run("success with ACLs", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 100,
					ACLs: []entities.ACLConfig{
						{
							Priority: 100,
							Protocol: "tcp",
							SrcIP:    "10.0.0.0/24",
							DstIP:    "192.168.1.0/24",
							DstPort:  443,
							Action:   "allow",
						},
					},
				},
			},
		}

		err = manager.ApplyProductionFlows("eth0", profile)
		require.NoError(t, err)

		// Verify flows were installed
		assert.Greater(t, mockController.getFlowCount("br0"), 0)
	})

	t.Run("error invalid port ID", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		profile := &entities.DeviceProfile{
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 100,
				},
			},
		}

		err = manager.ApplyProductionFlows("", profile)
		require.Error(t, err)
		assert.Equal(t, ErrInvalidPortID, err)
	})

	t.Run("error nil profile", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyProductionFlows("eth0", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device profile is required")
	})

	t.Run("error missing production network", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
		}

		err = manager.ApplyProductionFlows("eth0", profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "production network configuration is required")
	})

	t.Run("error zero production VLAN", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 0,
				},
			},
		}

		err = manager.ApplyProductionFlows("eth0", profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "production VLAN not configured")
	})

	t.Run("error flow installation fails", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		mockController.installErr = fmt.Errorf("installation failed")

		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 100,
				},
			},
		}

		err = manager.ApplyProductionFlows("eth0", profile)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowInstallFailed)
	})
}

func TestApplyQuarantineFlows(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyQuarantineFlows("eth0", "00:11:22:33:44:55")
		require.NoError(t, err)

		// Verify flows were installed
		assert.Greater(t, mockController.getFlowCount("br0"), 0)

		// Verify VLAN tracking
		vlan, err := manager.GetPortVLAN("eth0")
		require.NoError(t, err)
		assert.Equal(t, DefaultQuarantineVLAN, vlan)
	})

	t.Run("error invalid port ID", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyQuarantineFlows("", "00:11:22:33:44:55")
		require.Error(t, err)
		assert.Equal(t, ErrInvalidPortID, err)
	})

	t.Run("error flow installation fails", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		mockController.installErr = fmt.Errorf("installation failed")

		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyQuarantineFlows("eth0", "00:11:22:33:44:55")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowInstallFailed)
	})
}

func TestRemoveFlows(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		// Apply flows first
		err = manager.ApplyProvisioningFlows("eth0", "00:11:22:33:44:55")
		require.NoError(t, err)

		// Remove flows
		err = manager.RemoveFlows("eth0")
		require.NoError(t, err)

		// Verify VLAN tracking is removed
		_, err = manager.GetPortVLAN("eth0")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port not found")
	})

	t.Run("error invalid port ID", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.RemoveFlows("")
		require.Error(t, err)
		assert.Equal(t, ErrInvalidPortID, err)
	})

	t.Run("error deletion fails", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		mockController.deleteByPortErr = fmt.Errorf("deletion failed")

		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.RemoveFlows("eth0")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to remove flows")
	})
}

func TestGetPortVLAN(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		err = manager.ApplyProvisioningFlows("eth0", "00:11:22:33:44:55")
		require.NoError(t, err)

		vlan, err := manager.GetPortVLAN("eth0")
		require.NoError(t, err)
		assert.Equal(t, DefaultProvisioningVLAN, vlan)
	})

	t.Run("error port not found", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		_, err = manager.GetPortVLAN("eth0")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "port not found")
	})
}

func TestVLANLifecycle(t *testing.T) {
	t.Run("provisioning to production to quarantine", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		config := VLANFlowManagerConfig{
			BridgeName:     "br0",
			FlowController: mockController,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)

		portID := "eth0"
		portMAC := "00:11:22:33:44:55"

		// 1. Start in provisioning
		err = manager.ApplyProvisioningFlows(portID, portMAC)
		require.NoError(t, err)

		vlan, err := manager.GetPortVLAN(portID)
		require.NoError(t, err)
		assert.Equal(t, DefaultProvisioningVLAN, vlan)

		// 2. Transition to production
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 100,
				},
			},
		}

		err = manager.ApplyProductionFlows(portID, profile)
		require.NoError(t, err)

		vlan, err = manager.GetPortVLAN(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(100), vlan)

		// 3. Move to quarantine
		err = manager.ApplyQuarantineFlows(portID, portMAC)
		require.NoError(t, err)

		vlan, err = manager.GetPortVLAN(portID)
		require.NoError(t, err)
		assert.Equal(t, DefaultQuarantineVLAN, vlan)
	})
}

func TestConvertACLConfig(t *testing.T) {
	mockController := newVLANMockFlowController()
	config := VLANFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: mockController,
	}

	manager, err := NewVLANFlowManager(config)
	require.NoError(t, err)

	t.Run("tcp rule", func(t *testing.T) {
		acl := entities.ACLConfig{
			Priority: 100,
			Protocol: "tcp",
			SrcIP:    "10.0.0.1",
			DstIP:    "192.168.1.1",
			SrcPort:  8080,
			DstPort:  443,
			Action:   "allow",
		}

		rule := manager.convertACLConfig(acl)
		assert.Equal(t, 100, rule.Priority)
		assert.Equal(t, EtherTypeIPv4, rule.Match.EthType)
		assert.Equal(t, ProtoTCP, rule.Match.IPProto)
		assert.Equal(t, uint16(8080), rule.Match.TCPSrc)
		assert.Equal(t, uint16(443), rule.Match.TCPDst)
		assert.Equal(t, "10.0.0.1", rule.Match.IPv4Src)
		assert.Equal(t, "192.168.1.1", rule.Match.IPv4Dst)
		assert.Equal(t, FlowActionAllow, rule.Action.Type)
	})

	t.Run("udp rule", func(t *testing.T) {
		acl := entities.ACLConfig{
			Priority: 200,
			Protocol: "udp",
			DstPort:  53,
			Action:   "allow",
		}

		rule := manager.convertACLConfig(acl)
		assert.Equal(t, 200, rule.Priority)
		assert.Equal(t, EtherTypeIPv4, rule.Match.EthType)
		assert.Equal(t, ProtoUDP, rule.Match.IPProto)
		assert.Equal(t, uint16(53), rule.Match.UDPDst)
		assert.Equal(t, FlowActionAllow, rule.Action.Type)
	})

	t.Run("icmp rule", func(t *testing.T) {
		acl := entities.ACLConfig{
			Priority: 300,
			Protocol: "icmp",
			Action:   "deny",
		}

		rule := manager.convertACLConfig(acl)
		assert.Equal(t, 300, rule.Priority)
		assert.Equal(t, EtherTypeIPv4, rule.Match.EthType)
		assert.Equal(t, ProtoICMP, rule.Match.IPProto)
		assert.Equal(t, FlowActionDeny, rule.Action.Type)
	})

	t.Run("any protocol rule", func(t *testing.T) {
		acl := entities.ACLConfig{
			Priority: 400,
			Protocol: "any",
			Action:   "allow",
		}

		rule := manager.convertACLConfig(acl)
		assert.Equal(t, 400, rule.Priority)
		assert.Equal(t, EtherTypeIPv4, rule.Match.EthType)
		assert.Equal(t, FlowActionAllow, rule.Action.Type)
	})
}

func TestGetVLANs(t *testing.T) {
	mockController := newVLANMockFlowController()
	config := VLANFlowManagerConfig{
		BridgeName:       "br0",
		FlowController:   mockController,
		ProvisioningVLAN: 100,
		QuarantineVLAN:   200,
	}

	manager, err := NewVLANFlowManager(config)
	require.NoError(t, err)

	assert.Equal(t, uint16(100), manager.GetProvisioningVLAN())
	assert.Equal(t, uint16(200), manager.GetQuarantineVLAN())
}

func TestConcurrentAccess(t *testing.T) {
	mockController := newVLANMockFlowController()
	config := VLANFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: mockController,
	}

	manager, err := NewVLANFlowManager(config)
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent provisioning flow applications
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			portID := fmt.Sprintf("eth%d", id)
			err := manager.ApplyProvisioningFlows(portID, "00:11:22:33:44:55")
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify all ports are tracked
	for i := 0; i < numGoroutines; i++ {
		portID := fmt.Sprintf("eth%d", i)
		vlan, err := manager.GetPortVLAN(portID)
		assert.NoError(t, err)
		assert.Equal(t, DefaultProvisioningVLAN, vlan)
	}
}
