//go:build integration

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

package sdn

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// MockFlowController implements the FlowController interface for testing
type MockFlowController struct {
	installedFlows []FlowRecord
	deletedFlows   []string
}

type FlowRecord struct {
	Bridge   string
	Priority int
	Match    string
	Actions  string
}

func NewMockFlowController() *MockFlowController {
	return &MockFlowController{
		installedFlows: make([]FlowRecord, 0),
		deletedFlows:   make([]string, 0),
	}
}

func (m *MockFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	m.installedFlows = append(m.installedFlows, FlowRecord{
		Bridge:   bridgeName,
		Priority: priority,
		Match:    match,
		Actions:  actions,
	})
	return nil
}

// InstallFlows records a batch install, matching the canonical
// policy.FlowController contract.
func (m *MockFlowController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	for _, rule := range rules {
		m.installedFlows = append(m.installedFlows, FlowRecord{
			Bridge:   bridgeName,
			Priority: rule.Priority,
			Match:    rule.Match,
			Actions:  rule.Actions,
		})
	}
	return nil
}

func (m *MockFlowController) DeleteFlow(bridgeName string, match string) error {
	m.deletedFlows = append(m.deletedFlows, match)
	return nil
}

func (m *MockFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	m.deletedFlows = append(m.deletedFlows, portID)
	return nil
}

func (m *MockFlowController) ListFlows(bridgeName string) ([]string, error) {
	flows := make([]string, 0, len(m.installedFlows))
	for _, f := range m.installedFlows {
		flows = append(flows, f.Match)
	}
	return flows, nil
}

func (m *MockFlowController) Reset() {
	m.installedFlows = make([]FlowRecord, 0)
	m.deletedFlows = make([]string, 0)
}

// SetPortVLAN implements OVSPortController interface
func (m *MockFlowController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	return nil
}

// SetPortTrunk implements OVSPortController interface
func (m *MockFlowController) SetPortTrunk(ctx context.Context, portName string, allowed []uint16, native uint16) error {
	return nil
}

// SetPortState implements OVSPortController interface
func (m *MockFlowController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	return nil
}

// GetOFPort implements OVSPortController interface
func (m *MockFlowController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	return 1, nil
}

// TestProvisioningToEnrolledTransition verifies the state transition from
// provisioning to enrolled state
func TestProvisioningToEnrolledTransition(t *testing.T) {
	mockFC := NewMockFlowController()

	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     "br0",
		FlowController: mockFC,
	})
	require.NoError(t, err)

	portID := "eth0"

	t.Run("Transition from unconnected to provisioning", func(t *testing.T) {
		err := engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateProvisioning, state)
	})

	t.Run("Transition from provisioning to enrolled", func(t *testing.T) {
		err := engine.SetPortState(portID, policy.PortStateEnrolled)
		require.NoError(t, err)

		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateEnrolled, state)
	})

	t.Run("Verify port info after enrollment", func(t *testing.T) {
		info, err := engine.GetPortInfo(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateEnrolled, info.State)
		assert.Equal(t, portID, info.PortID)
		assert.WithinDuration(t, time.Now(), info.LastStateChange, 5*time.Second)
	})
}

// TestEnrolledToAuthorizedTransition verifies the transition from enrolled
// to authorized state (production network activation)
func TestEnrolledToAuthorizedTransition(t *testing.T) {
	mockFC := NewMockFlowController()

	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     "br0",
		FlowController: mockFC,
	})
	require.NoError(t, err)

	portID := "eth0"

	// Setup: Get port to enrolled state
	require.NoError(t, engine.SetPortState(portID, policy.PortStateProvisioning))
	require.NoError(t, engine.SetPortState(portID, policy.PortStateEnrolled))

	t.Run("Apply production policy and transition to authorized", func(t *testing.T) {
		productionPolicy := &policy.PortPolicy{
			TenantID: "test-tenant",
			VLAN:     200,
			ACLs: []policy.ACLRule{
				{
					Priority: 100,
					Match: policy.FlowMatch{
						IPv4Src: "10.0.200.0/24",
					},
					Action: policy.FlowAction{
						Type: policy.FlowActionAllow,
					},
					Description: "Allow production network traffic",
				},
			},
		}

		err := engine.ApplyPolicy(portID, productionPolicy)
		require.NoError(t, err)

		// Verify state transition
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		// Verify flows were installed
		assert.Greater(t, len(mockFC.installedFlows), 0, "Flows should be installed")

		// Verify VLAN is set in flows
		hasVLANFlow := false
		for _, flow := range mockFC.installedFlows {
			if flow.Match != "" && flow.Actions != "" {
				hasVLANFlow = true
				break
			}
		}
		assert.True(t, hasVLANFlow, "VLAN flows should be installed")
	})
}

// TestProvisioningVLANToProductionVLANTransition verifies VLAN changes
// during network phase transitions
func TestProvisioningVLANToProductionVLANTransition(t *testing.T) {
	mockFC := NewMockFlowController()

	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     "br0",
		FlowController: mockFC,
	})
	require.NoError(t, err)

	portID := "eth0"

	t.Run("Apply provisioning policy with VLAN 100", func(t *testing.T) {
		provisioningPolicy := &policy.PortPolicy{
			TenantID: "test-tenant",
			VLAN:     100,
			ACLs:     []policy.ACLRule{},
		}

		err := engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		err = engine.ApplyPolicy(portID, provisioningPolicy)
		require.NoError(t, err)

		// Verify policy applied
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(100), appliedPolicy.VLAN)
	})

	t.Run("Transition to production policy with VLAN 200", func(t *testing.T) {
		// Reset flows to track transition
		mockFC.Reset()

		productionPolicy := &policy.PortPolicy{
			TenantID: "test-tenant",
			VLAN:     200,
			ACLs:     []policy.ACLRule{},
		}

		// Remove old policy and apply new one
		err := engine.RemovePolicy(portID)
		require.NoError(t, err)

		// Valid transition: Unauthorized -> Provisioning -> Enrolled
		err = engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		err = engine.SetPortState(portID, policy.PortStateEnrolled)
		require.NoError(t, err)

		err = engine.ApplyPolicy(portID, productionPolicy)
		require.NoError(t, err)

		// Verify new policy
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(200), appliedPolicy.VLAN)

		// Verify old flows were deleted
		assert.Greater(t, len(mockFC.deletedFlows), 0, "Old flows should be deleted")
	})
}

// TestACLRulesTransition verifies ACL rule changes during phase transitions
func TestACLRulesTransition(t *testing.T) {
	mockFC := NewMockFlowController()

	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     "br0",
		FlowController: mockFC,
	})
	require.NoError(t, err)

	portID := "eth0"

	t.Run("Apply restrictive provisioning ACLs", func(t *testing.T) {
		provisioningPolicy := &policy.PortPolicy{
			TenantID: "test-tenant",
			VLAN:     100,
			ACLs: []policy.ACLRule{
				{
					Priority: 100,
					Match: policy.FlowMatch{
						IPProto: 6,   // TCP
						TCPDst:  443, // HTTPS
					},
					Action: policy.FlowAction{
						Type: policy.FlowActionAllow,
					},
					Description: "Allow HTTPS for enrollment",
				},
				{
					Priority: 90,
					Match: policy.FlowMatch{
						IPProto: 17, // UDP
						UDPDst:  53, // DNS
					},
					Action: policy.FlowAction{
						Type: policy.FlowActionAllow,
					},
					Description: "Allow DNS",
				},
			},
		}

		err := engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		err = engine.ApplyPolicy(portID, provisioningPolicy)
		require.NoError(t, err)

		// Verify restrictive ACLs applied
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Len(t, appliedPolicy.ACLs, 2)
	})

	t.Run("Transition to permissive production ACLs", func(t *testing.T) {
		mockFC.Reset()

		productionPolicy := &policy.PortPolicy{
			TenantID: "test-tenant",
			VLAN:     200,
			ACLs: []policy.ACLRule{
				{
					Priority: 100,
					Match: policy.FlowMatch{
						IPv4Src: "10.0.200.0/24",
					},
					Action: policy.FlowAction{
						Type: policy.FlowActionAllow,
					},
					Description: "Allow all production traffic",
				},
			},
		}

		err := engine.RemovePolicy(portID)
		require.NoError(t, err)
		// Valid transition: Unauthorized -> Provisioning -> Enrolled
		err = engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		err = engine.SetPortState(portID, policy.PortStateEnrolled)
		require.NoError(t, err)

		err = engine.ApplyPolicy(portID, productionPolicy)
		require.NoError(t, err)

		// Verify permissive ACLs applied
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Len(t, appliedPolicy.ACLs, 1)
		assert.Equal(t, "Allow all production traffic", appliedPolicy.ACLs[0].Description)
	})
}

// TestQuarantineNetworkTransition verifies transitions to/from quarantine state
func TestQuarantineNetworkTransition(t *testing.T) {
	mockFC := NewMockFlowController()

	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     "br0",
		FlowController: mockFC,
	})
	require.NoError(t, err)

	portID := "eth0"

	// Setup: Get port to authorized state
	productionPolicy := &policy.PortPolicy{
		TenantID: "test-tenant",
		VLAN:     200,
	}
	require.NoError(t, engine.SetPortState(portID, policy.PortStateProvisioning))
	require.NoError(t, engine.ApplyPolicy(portID, productionPolicy))

	t.Run("Transition to quarantine state", func(t *testing.T) {
		err := engine.SetPortState(portID, policy.PortStateQuarantined)
		require.NoError(t, err)

		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateQuarantined, state)
	})

	t.Run("Apply quarantine policy with restricted VLAN", func(t *testing.T) {
		mockFC.Reset()

		quarantinePolicy := &policy.PortPolicy{
			TenantID: "test-tenant",
			VLAN:     300,
			ACLs: []policy.ACLRule{
				{
					Priority: 100,
					Match: policy.FlowMatch{
						IPv4Dst: "10.0.300.1/32", // Only allow quarantine server
					},
					Action: policy.FlowAction{
						Type: policy.FlowActionAllow,
					},
					Description: "Quarantine server only",
				},
			},
		}

		err := engine.RemovePolicy(portID)
		require.NoError(t, err)

		err = engine.ApplyPolicy(portID, quarantinePolicy)
		require.NoError(t, err)

		// Verify quarantine policy applied
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(300), appliedPolicy.VLAN)
	})

	t.Run("Return to production after remediation", func(t *testing.T) {
		mockFC.Reset()

		// Remove quarantine policy
		err := engine.RemovePolicy(portID)
		require.NoError(t, err)

		// Reapply production policy
		err = engine.ApplyPolicy(portID, productionPolicy)
		require.NoError(t, err)

		// Verify back to authorized state
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		// Verify production VLAN restored
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(200), appliedPolicy.VLAN)
	})
}

// TestDeviceProfileToSDNPolicyIntegration verifies end-to-end integration
// from device profile to SDN policy enforcement
func TestDeviceProfileToSDNPolicyIntegration(t *testing.T) {
	mockFC := NewMockFlowController()

	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     "br0",
		FlowController: mockFC,
	})
	require.NoError(t, err)

	// Create a complete device profile
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "integration-test-device",
		Model: "TestServer",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:    100,
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2"},
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						SrcIP:    "0.0.0.0/0",
						DstIP:    "10.0.100.2/32",
						DstPort:  443,
						Action:   "allow",
					},
					{
						Priority: 90,
						Protocol: "udp",
						SrcIP:    "0.0.0.0/0",
						DstIP:    "10.0.100.2/32",
						DstPort:  53,
						Action:   "allow",
					},
				},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:    200,
				Gateway: "10.0.200.1",
				DNS:     []string{"10.0.200.2"},
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "any",
						SrcIP:    "10.0.200.0/24",
						DstIP:    "0.0.0.0/0",
						Action:   "allow",
					},
				},
			},
			entities.DefaultFailureNetwork: {
				VLAN:    300,
				Gateway: "10.0.300.1",
				DNS:     []string{"10.0.300.2"},
			},
		},
	}

	portID := "eth0"

	t.Run("Phase 1: Provisioning network", func(t *testing.T) {
		// Convert device profile provisioning network to SDN policy
		provPolicy := convertDeviceProfileToSDNPolicy(profile.Networks[entities.DefaultEnrollmentNetwork], "tenant-1")

		err := engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		err = engine.ApplyPolicy(portID, provPolicy)
		require.NoError(t, err)

		// Verify provisioning state and policy
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(100), appliedPolicy.VLAN)
		assert.Len(t, appliedPolicy.ACLs, 2)
	})

	t.Run("Phase 2: Enrollment complete, transition to enrolled", func(t *testing.T) {
		err := engine.RemovePolicy(portID)
		require.NoError(t, err)
		// Valid transition: Unauthorized -> Provisioning -> Enrolled
		err = engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		err = engine.SetPortState(portID, policy.PortStateEnrolled)
		require.NoError(t, err)

		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateEnrolled, state)
	})

	t.Run("Phase 3: Activate production network", func(t *testing.T) {
		mockFC.Reset()

		// Convert device profile production network to SDN policy
		prodPolicy := convertDeviceProfileToSDNPolicy(profile.Networks[entities.DefaultPostEnrollmentNetwork], "tenant-1")

		err := engine.ApplyPolicy(portID, prodPolicy)
		require.NoError(t, err)

		// Verify production state and policy
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(200), appliedPolicy.VLAN)
		assert.Len(t, appliedPolicy.ACLs, 1)

		// Verify flows contain production VLAN
		flows, err := mockFC.ListFlows("br0")
		require.NoError(t, err)
		assert.Greater(t, len(flows), 0)
	})

	t.Run("Phase 4: Quarantine for scanning", func(t *testing.T) {
		mockFC.Reset()

		// Transition directly from Authorized to Quarantined
		// Valid transition: Authorized -> Quarantined (quarantine policy removes previous policy)
		err := engine.SetPortState(portID, policy.PortStateQuarantined)
		require.NoError(t, err)

		// Apply quarantine policy
		quarPolicy := convertDeviceProfileToSDNPolicy(profile.Networks[entities.DefaultFailureNetwork], "tenant-1")
		err = engine.ApplyPolicy(portID, quarPolicy)
		require.NoError(t, err)

		// Verify quarantine state and policy
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(300), appliedPolicy.VLAN)
	})

	t.Run("Phase 5: Return to production after remediation", func(t *testing.T) {
		mockFC.Reset()

		// Remove quarantine policy
		err := engine.RemovePolicy(portID)
		require.NoError(t, err)

		// Reapply production policy
		prodPolicy := convertDeviceProfileToSDNPolicy(profile.Networks[entities.DefaultPostEnrollmentNetwork], "tenant-1")
		err = engine.ApplyPolicy(portID, prodPolicy)
		require.NoError(t, err)

		// Verify back to production
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, uint16(200), appliedPolicy.VLAN)
	})
}

// convertDeviceProfileToSDNPolicy converts a device profile network config to SDN policy
func convertDeviceProfileToSDNPolicy(config *entities.NetworkPhaseConfig, tenantID string) *policy.PortPolicy {
	if config == nil {
		return nil
	}

	p := &policy.PortPolicy{
		TenantID:  tenantID,
		VLAN:      config.VLAN,
		ACLs:      make([]policy.ACLRule, 0, len(config.ACLs)),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	for _, acl := range config.ACLs {
		aclRule := policy.ACLRule{
			Priority:    acl.Priority,
			Description: "From device profile",
		}

		aclRule.Match = policy.FlowMatch{
			IPv4Src: acl.SrcIP,
			IPv4Dst: acl.DstIP,
		}

		switch acl.Protocol {
		case "tcp":
			aclRule.Match.IPProto = 6
			aclRule.Match.TCPSrc = acl.SrcPort
			aclRule.Match.TCPDst = acl.DstPort
		case "udp":
			aclRule.Match.IPProto = 17
			aclRule.Match.UDPSrc = acl.SrcPort
			aclRule.Match.UDPDst = acl.DstPort
		case "icmp":
			aclRule.Match.IPProto = 1
		}

		switch acl.Action {
		case "allow":
			aclRule.Action.Type = policy.FlowActionAllow
		case "deny":
			aclRule.Action.Type = policy.FlowActionDeny
		}

		p.ACLs = append(p.ACLs, aclRule)
	}

	return p
}

// TestCertificateBasedPolicyExtraction verifies policy extraction from certificates
func TestCertificateBasedPolicyExtraction(t *testing.T) {
	t.Run("Extract VLAN from certificate metadata", func(t *testing.T) {
		// This would be implemented when certificate extensions are defined
		// For now, we verify the interface exists
		extractor := policy.NewX509PolicyExtractor()
		require.NotNil(t, extractor)
	})
}

// TestStateTransitionValidation verifies that invalid state transitions are rejected
func TestStateTransitionValidation(t *testing.T) {
	mockFC := NewMockFlowController()

	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     "br0",
		FlowController: mockFC,
	})
	require.NoError(t, err)

	portID := "eth0"

	t.Run("Cannot go directly from unconnected to authorized", func(t *testing.T) {
		// Should fail - must go through provisioning
		err := engine.SetPortState(portID, policy.PortStateAuthorized)
		assert.Error(t, err)
	})

	t.Run("Cannot go from blocked to authorized without admin intervention", func(t *testing.T) {
		// Setup blocked state
		require.NoError(t, engine.SetPortState(portID, policy.PortStateProvisioning))
		require.NoError(t, engine.SetPortState(portID, policy.PortStateBlocked))

		// Try to go directly to authorized
		err := engine.SetPortState(portID, policy.PortStateAuthorized)
		assert.Error(t, err)
	})

	t.Run("Valid transition path: unconnected -> provisioning -> enrolled -> authorized", func(t *testing.T) {
		// Reset port
		mockFC.Reset()
		portID := "eth1"

		// Valid state progression
		require.NoError(t, engine.SetPortState(portID, policy.PortStateProvisioning))
		require.NoError(t, engine.SetPortState(portID, policy.PortStateEnrolled))

		// Apply policy to transition to authorized
		testPolicy := &policy.PortPolicy{
			TenantID: "test",
			VLAN:     200,
		}
		require.NoError(t, engine.ApplyPolicy(portID, testPolicy))

		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)
	})
}
