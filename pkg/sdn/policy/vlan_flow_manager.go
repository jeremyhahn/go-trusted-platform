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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

const (
	// Default VLAN IDs
	DefaultProvisioningVLAN = uint16(998)
	DefaultQuarantineVLAN   = uint16(666)
)

// VLANFlowManagerConfig configures the VLAN flow manager
type VLANFlowManagerConfig struct {
	// BridgeName is the OVS bridge to manage
	BridgeName string

	// FlowController manages OpenFlow rules
	FlowController FlowController

	// Logger for the VLAN flow manager (uses slog.Default() if nil)
	Logger *slog.Logger

	// ProvisioningVLAN is the VLAN ID for provisioning (default: 998)
	ProvisioningVLAN uint16

	// QuarantineVLAN is the VLAN ID for quarantine (default: 666)
	QuarantineVLAN uint16

	// ProvisioningConfig configures the provisioning flow generator
	ProvisioningConfig *ProvisioningFlowConfig

	// QuarantineConfig configures the quarantine flow generator
	QuarantineConfig *QuarantineFlowConfig
}

// VLANFlowManager manages VLAN-based network segmentation for device lifecycle
type VLANFlowManager struct {
	mu                    sync.RWMutex
	logger                *slog.Logger
	bridgeName            string
	flowController        FlowController
	provisioningVLAN      uint16
	quarantineVLAN        uint16
	provisioningGenerator *ProvisioningFlowGenerator
	quarantineGenerator   *QuarantineFlowGenerator
	ruleGenerator         *RuleGenerator
	portVLANMap           map[string]uint16 // tracks current VLAN for each port
}

// NewVLANFlowManager creates a new VLAN flow manager
func NewVLANFlowManager(config VLANFlowManagerConfig) (*VLANFlowManager, error) {
	if config.BridgeName == "" {
		return nil, fmt.Errorf("bridge name is required")
	}

	if config.FlowController == nil {
		return nil, fmt.Errorf("flow controller is required")
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Set default VLANs if not specified
	provisioningVLAN := config.ProvisioningVLAN
	if provisioningVLAN == 0 {
		provisioningVLAN = DefaultProvisioningVLAN
	}

	quarantineVLAN := config.QuarantineVLAN
	if quarantineVLAN == 0 {
		quarantineVLAN = DefaultQuarantineVLAN
	}

	// Initialize provisioning config with defaults
	provisioningConfig := config.ProvisioningConfig
	if provisioningConfig == nil {
		provisioningConfig = &ProvisioningFlowConfig{
			ProvisioningVLAN: provisioningVLAN,
		}
	} else if provisioningConfig.ProvisioningVLAN == 0 {
		provisioningConfig.ProvisioningVLAN = provisioningVLAN
	}

	// Initialize quarantine config with defaults
	quarantineConfig := config.QuarantineConfig
	if quarantineConfig == nil {
		quarantineConfig = &QuarantineFlowConfig{
			QuarantineVLAN: quarantineVLAN,
		}
	} else if quarantineConfig.QuarantineVLAN == 0 {
		quarantineConfig.QuarantineVLAN = quarantineVLAN
	}

	return &VLANFlowManager{
		logger:                logger,
		bridgeName:            config.BridgeName,
		flowController:        config.FlowController,
		provisioningVLAN:      provisioningVLAN,
		quarantineVLAN:        quarantineVLAN,
		provisioningGenerator: NewProvisioningFlowGenerator(provisioningConfig),
		quarantineGenerator:   NewQuarantineFlowGenerator(quarantineConfig),
		ruleGenerator:         NewRuleGenerator(),
		portVLANMap:           make(map[string]uint16),
	}, nil
}

// ApplyProvisioningFlows applies provisioning VLAN flows to a new port
// This allows the device to get DHCP, DNS, and access to ACME server for enrollment
func (m *VLANFlowManager) ApplyProvisioningFlows(portID string, portMAC string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("applying provisioning flows",
		slog.String("port_id", portID),
		slog.String("port_mac", portMAC),
		slog.Uint64("vlan", uint64(m.provisioningVLAN)))

	// Remove any existing flows for this port
	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, portID); err != nil {
		m.logger.Warn("failed to delete existing flows",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	// Generate provisioning flows
	flows := m.provisioningGenerator.GenerateFlows(portID, portMAC)

	// Install flows
	for _, flow := range flows {
		if err := m.flowController.InstallFlow(
			m.bridgeName,
			flow.Priority,
			flow.Match,
			flow.Actions,
		); err != nil {
			m.logger.Error("failed to install provisioning flow",
				slog.String("port_id", portID),
				slog.String("error", err.Error()),
				slog.String("match", flow.Match),
				slog.String("actions", flow.Actions))
			return fmt.Errorf("%w: %v", ErrFlowInstallFailed, err)
		}
	}

	// Track current VLAN
	m.portVLANMap[portID] = m.provisioningVLAN

	m.logger.Info("provisioning flows applied successfully",
		slog.String("port_id", portID),
		slog.Int("flow_count", len(flows)))

	return nil
}

// ApplyProductionFlows transitions a port to production VLAN after enrollment
// The VLAN is extracted from the device profile
func (m *VLANFlowManager) ApplyProductionFlows(portID string, profile *entities.DeviceProfile) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	if profile == nil {
		return fmt.Errorf("device profile is required")
	}

	prodNet := profile.GetPostEnrollmentNetworkConfig()
	if prodNet == nil {
		return fmt.Errorf("production network configuration is required in device profile")
	}

	productionVLAN := prodNet.VLAN
	if productionVLAN == 0 {
		return fmt.Errorf("production VLAN not configured in device profile")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("applying production flows",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(productionVLAN)),
		slog.String("profile", profile.Name))

	// Remove existing flows
	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, portID); err != nil {
		m.logger.Warn("failed to delete existing flows",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	// Create production policy from device profile
	policy := m.createProductionPolicy(portID, profile)

	// Generate authorization rules for production
	rules, err := m.ruleGenerator.GenerateAuthorizationRules(portID, policy)
	if err != nil {
		return fmt.Errorf("failed to generate production rules: %w", err)
	}

	// Install flows
	for _, rule := range rules {
		if err := m.flowController.InstallFlow(
			m.bridgeName,
			rule.Priority,
			rule.Match,
			rule.Actions,
		); err != nil {
			m.logger.Error("failed to install production flow",
				slog.String("port_id", portID),
				slog.String("error", err.Error()),
				slog.String("match", rule.Match),
				slog.String("actions", rule.Actions))
			return fmt.Errorf("%w: %v", ErrFlowInstallFailed, err)
		}
	}

	// Track current VLAN
	m.portVLANMap[portID] = productionVLAN

	m.logger.Info("production flows applied successfully",
		slog.String("port_id", portID),
		slog.Uint64("vlan", uint64(productionVLAN)),
		slog.Int("flow_count", len(rules)))

	return nil
}

// ApplyQuarantineFlows applies quarantine VLAN flows when a certificate is revoked
// This isolates the device in a restricted network for security scanning
func (m *VLANFlowManager) ApplyQuarantineFlows(portID string, portMAC string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("applying quarantine flows",
		slog.String("port_id", portID),
		slog.String("port_mac", portMAC),
		slog.Uint64("vlan", uint64(m.quarantineVLAN)))

	// Remove existing flows
	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, portID); err != nil {
		m.logger.Warn("failed to delete existing flows",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	// Generate quarantine flows
	flows := m.quarantineGenerator.GenerateFlows(portID, portMAC)

	// Install flows
	for _, flow := range flows {
		if err := m.flowController.InstallFlow(
			m.bridgeName,
			flow.Priority,
			flow.Match,
			flow.Actions,
		); err != nil {
			m.logger.Error("failed to install quarantine flow",
				slog.String("port_id", portID),
				slog.String("error", err.Error()),
				slog.String("match", flow.Match),
				slog.String("actions", flow.Actions))
			return fmt.Errorf("%w: %v", ErrFlowInstallFailed, err)
		}
	}

	// Track current VLAN
	m.portVLANMap[portID] = m.quarantineVLAN

	m.logger.Info("quarantine flows applied successfully",
		slog.String("port_id", portID),
		slog.Int("flow_count", len(flows)))

	return nil
}

// RemoveFlows removes all flows for a port
func (m *VLANFlowManager) RemoveFlows(portID string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("removing flows",
		slog.String("port_id", portID))

	if err := m.flowController.DeleteFlowsByPort(m.bridgeName, portID); err != nil {
		return fmt.Errorf("failed to remove flows: %w", err)
	}

	// Remove from tracking map
	delete(m.portVLANMap, portID)

	m.logger.Info("flows removed successfully",
		slog.String("port_id", portID))

	return nil
}

// GetPortVLAN returns the current VLAN for a port
func (m *VLANFlowManager) GetPortVLAN(portID string) (uint16, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vlan, ok := m.portVLANMap[portID]
	if !ok {
		return 0, fmt.Errorf("port not found: %s", portID)
	}

	return vlan, nil
}

// createProductionPolicy creates a PortPolicy from a device profile
func (m *VLANFlowManager) createProductionPolicy(portID string, profile *entities.DeviceProfile) *PortPolicy {
	prodNet := profile.GetPostEnrollmentNetworkConfig()
	policy := &PortPolicy{
		TenantID: fmt.Sprintf("profile-%d", profile.ID),
		VLAN:     prodNet.VLAN,
		ACLs:     make([]ACLRule, 0),
	}

	// Convert profile ACLs to policy ACLs
	if prodNet.ACLs != nil {
		for _, acl := range prodNet.ACLs {
			policyACL := m.convertACLConfig(acl)
			policy.ACLs = append(policy.ACLs, policyACL)
		}
	}

	// If no ACLs specified, use default allow-all
	if len(policy.ACLs) == 0 {
		policy.ACLs = append(policy.ACLs, ACLRule{
			Priority: 100,
			Match: FlowMatch{
				InPort: portID,
			},
			Action: FlowAction{
				Type: FlowActionNormal,
			},
			Description: "Default allow all traffic",
		})
	}

	return policy
}

// convertACLConfig converts a device profile ACLConfig to a policy ACLRule
func (m *VLANFlowManager) convertACLConfig(acl entities.ACLConfig) ACLRule {
	rule := ACLRule{
		Priority:    acl.Priority,
		Description: fmt.Sprintf("%s %s -> %s", acl.Protocol, acl.SrcIP, acl.DstIP),
	}

	// Build match criteria
	match := FlowMatch{}

	// Set protocol
	switch acl.Protocol {
	case "tcp":
		match.EthType = EtherTypeIPv4
		match.IPProto = ProtoTCP
		if acl.SrcPort > 0 {
			match.TCPSrc = acl.SrcPort
		}
		if acl.DstPort > 0 {
			match.TCPDst = acl.DstPort
		}
	case "udp":
		match.EthType = EtherTypeIPv4
		match.IPProto = ProtoUDP
		if acl.SrcPort > 0 {
			match.UDPSrc = acl.SrcPort
		}
		if acl.DstPort > 0 {
			match.UDPDst = acl.DstPort
		}
	case "icmp":
		match.EthType = EtherTypeIPv4
		match.IPProto = ProtoICMP
	case "any":
		match.EthType = EtherTypeIPv4
	}

	// Set IP addresses
	if acl.SrcIP != "" {
		match.IPv4Src = acl.SrcIP
	}
	if acl.DstIP != "" {
		match.IPv4Dst = acl.DstIP
	}

	rule.Match = match

	// Set action
	switch acl.Action {
	case "allow":
		rule.Action = FlowAction{
			Type: FlowActionAllow,
		}
	case "deny":
		rule.Action = FlowAction{
			Type: FlowActionDeny,
		}
	default:
		rule.Action = FlowAction{
			Type: FlowActionDeny,
		}
	}

	return rule
}

// GetProvisioningVLAN returns the provisioning VLAN ID
func (m *VLANFlowManager) GetProvisioningVLAN() uint16 {
	return m.provisioningVLAN
}

// GetQuarantineVLAN returns the quarantine VLAN ID
func (m *VLANFlowManager) GetQuarantineVLAN() uint16 {
	return m.quarantineVLAN
}
