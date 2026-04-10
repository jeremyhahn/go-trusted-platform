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

package container

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Protocol constants for OpenFlow rules.
const (
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
	ProtocolICMP uint8 = 1
)

// Ethernet type constants.
const (
	EthTypeIPv4 uint16 = 0x0800
	EthTypeIPv6 uint16 = 0x86DD
	EthTypeARP  uint16 = 0x0806
)

// Default OpenFlow settings.
const (
	DefaultFlowTable     = 0
	DefaultFlowPriority  = 100
	SecurityFlowTable    = 10
	SecurityBasePriority = 200
)

// Security group rule direction constants.
const (
	DirectionIngress = "ingress"
	DirectionEgress  = "egress"
)

// NetworkManagerConfig contains configuration for the SDNNetworkManager.
type NetworkManagerConfig struct {
	// OVSBridge is the default OVS bridge name.
	OVSBridge string

	// OpenFlowController is the OpenFlow controller address (e.g., "tcp:127.0.0.1:6653").
	OpenFlowController string

	// DefaultVLAN is the default VLAN ID for containers.
	DefaultVLAN uint16

	// FlowTableBase is the starting OpenFlow table for container flows.
	FlowTableBase int

	// FlowPriorityBase is the base priority for container flows.
	FlowPriorityBase int

	// PortNamePrefix is the prefix for container OVS port names.
	PortNamePrefix string

	// CleanupOnTeardown removes all flows and ports on teardown.
	CleanupOnTeardown bool

	// ConnectionTimeout is the timeout for OVS/OpenFlow connections.
	ConnectionTimeout time.Duration
}

// Validate validates the NetworkManagerConfig.
func (c *NetworkManagerConfig) Validate() error {
	if c.OVSBridge == "" {
		return ErrNetworkSetupFailed
	}

	if c.DefaultVLAN > 4094 {
		return ErrVLANConfigFailed
	}

	if c.FlowTableBase < 0 || c.FlowTableBase > 254 {
		c.FlowTableBase = DefaultFlowTable
	}

	if c.FlowPriorityBase <= 0 || c.FlowPriorityBase > 65535 {
		c.FlowPriorityBase = DefaultFlowPriority
	}

	if c.PortNamePrefix == "" {
		c.PortNamePrefix = "ctr-"
	}

	if c.ConnectionTimeout <= 0 {
		c.ConnectionTimeout = 30 * time.Second
	}

	return nil
}

// GetPortPrefix returns the port name prefix with default fallback.
func (c *NetworkManagerConfig) GetPortPrefix() string {
	if c.PortNamePrefix == "" {
		return "ctr-"
	}
	return c.PortNamePrefix
}

// ContainerNetworkInfo contains network information for a container.
type ContainerNetworkInfo struct {
	// ContainerID is the container identifier.
	ContainerID string

	// PortName is the OVS port name.
	PortName string

	// OFPort is the OpenFlow port number.
	OFPort int32

	// VLANID is the assigned VLAN ID.
	VLANID uint16

	// IPAddress is the container's IP address.
	IPAddress string

	// MACAddress is the container's MAC address.
	MACAddress string

	// Gateway is the network gateway.
	Gateway string

	// SecurityGroups contains the names of applied security groups.
	SecurityGroups []string

	// FlowCount is the number of installed OpenFlow rules.
	FlowCount int

	// Mode is the network mode (sdn, bridge, host, none).
	Mode NetworkMode

	// BridgeName is the OVS bridge name.
	BridgeName string

	// CreatedAt is when the network was configured.
	CreatedAt time.Time

	// UpdatedAt is when the network was last updated.
	UpdatedAt time.Time
}

// SecurityGroup defines a security group for container traffic control.
type SecurityGroup struct {
	// Name is the security group name.
	Name string

	// Description describes the security group.
	Description string

	// Rules are the security group rules.
	Rules []SecurityGroupRule

	// Priority is the base priority for this security group's flows.
	Priority int

	// Table is the OpenFlow table for this security group.
	Table int
}

// Validate validates the SecurityGroup.
func (sg *SecurityGroup) Validate() error {
	if sg.Name == "" {
		return ErrNetworkSetupFailed
	}

	for i := range sg.Rules {
		if err := sg.Rules[i].Validate(); err != nil {
			return err
		}
	}

	return nil
}

// SecurityGroupRule defines a single security group rule.
type SecurityGroupRule struct {
	// Direction is "ingress" or "egress".
	Direction string

	// Protocol is the IP protocol (tcp, udp, icmp, or numeric).
	Protocol string

	// Port is the single port to match.
	Port uint16

	// PortRangeStart is the start of a port range (inclusive).
	PortRangeStart uint16

	// PortRangeEnd is the end of a port range (inclusive).
	PortRangeEnd uint16

	// RemoteIP is the remote IP address or CIDR to match.
	RemoteIP string

	// RemoteGroup is another security group to allow traffic from.
	RemoteGroup string

	// Action is the action (allow, drop).
	Action string

	// Description describes this rule.
	Description string
}

// Validate validates the SecurityGroupRule.
func (r *SecurityGroupRule) Validate() error {
	if r.Direction != DirectionIngress && r.Direction != DirectionEgress {
		return ErrNetworkSetupFailed
	}

	if r.Action == "" {
		r.Action = "allow"
	}

	if r.Action != "allow" && r.Action != "drop" {
		return ErrNetworkSetupFailed
	}

	// Validate port range
	if r.PortRangeStart > 0 && r.PortRangeEnd > 0 {
		if r.PortRangeStart > r.PortRangeEnd {
			return ErrNetworkSetupFailed
		}
	}

	return nil
}

// OVSClient defines the interface for OVS operations.
// This interface allows for mocking in tests.
type OVSClient interface {
	// Connect establishes connection to OVS.
	Connect(ctx context.Context) error

	// Disconnect closes the connection.
	Disconnect() error

	// IsConnected returns true if connected.
	IsConnected() bool

	// AddPort adds a port to a bridge.
	AddPort(ctx context.Context, bridgeName, portName string) error

	// DeletePort removes a port from a bridge.
	DeletePort(ctx context.Context, bridgeName, portName string) error

	// SetPortVLAN sets the VLAN tag on a port.
	SetPortVLAN(ctx context.Context, portName string, vlanID uint16) error

	// GetOFPort returns the OpenFlow port number for a port.
	GetOFPort(ctx context.Context, portName string) (int32, error)

	// AddFlow adds an OpenFlow rule.
	AddFlow(ctx context.Context, bridgeName string, flow *OVSFlow) error

	// DeleteFlow deletes OpenFlow rules matching the criteria.
	DeleteFlow(ctx context.Context, bridgeName string, match string) error

	// DeleteFlowsByPort deletes all flows for a specific port.
	DeleteFlowsByPort(ctx context.Context, bridgeName string, portName string, ofPort int32) error
}

// OVSFlow represents an OpenFlow rule for OVS.
type OVSFlow struct {
	// Table is the OpenFlow table.
	Table int

	// Priority is the rule priority.
	Priority int

	// Match is the match criteria string.
	Match string

	// Actions is the actions string.
	Actions string

	// Cookie identifies this flow.
	Cookie string

	// IdleTimeout is the idle timeout in seconds.
	IdleTimeout int

	// HardTimeout is the hard timeout in seconds.
	HardTimeout int
}

// OpenFlowController defines the interface for OpenFlow management.
// This interface allows for mocking in tests.
type OpenFlowController interface {
	// AddFlow installs an OpenFlow rule.
	AddFlow(ctx context.Context, flow *InternalOpenFlowRule) error

	// DeleteFlow removes an OpenFlow rule.
	DeleteFlow(ctx context.Context, flow *InternalOpenFlowRule) error

	// DeleteFlowsByPort removes all flows for a port.
	DeleteFlowsByPort(ctx context.Context, portName string, ofPort int32) error

	// ModifyFlow modifies an existing flow.
	ModifyFlow(ctx context.Context, flow *InternalOpenFlowRule) error

	// ListFlows returns all flows matching criteria.
	ListFlows(ctx context.Context, match *InternalOpenFlowMatch) ([]*InternalOpenFlowRule, error)
}

// InternalOpenFlowRule represents an OpenFlow rule in internal format.
// This is distinct from the config-level OpenFlowRule.
type InternalOpenFlowRule struct {
	// Match is the match criteria.
	Match *InternalOpenFlowMatch

	// Actions are the actions to take.
	Actions []InternalOpenFlowAction

	// Priority is the rule priority.
	Priority int

	// Table is the OpenFlow table.
	Table int

	// Cookie identifies this rule.
	Cookie uint64

	// IdleTimeout in seconds.
	IdleTimeout int

	// HardTimeout in seconds.
	HardTimeout int
}

// InternalOpenFlowMatch represents OpenFlow match criteria.
type InternalOpenFlowMatch struct {
	// InPort is the input port number.
	InPort int32

	// DLType is the Ethernet type (e.g., 0x0800 for IPv4).
	DLType uint16

	// NWProto is the IP protocol number.
	NWProto uint8

	// TPSrc is the source transport port.
	TPSrc uint16

	// TPDst is the destination transport port.
	TPDst uint16

	// NWSrc is the source IP address or CIDR.
	NWSrc string

	// NWDst is the destination IP address or CIDR.
	NWDst string

	// DLSrc is the source MAC address.
	DLSrc string

	// DLDst is the destination MAC address.
	DLDst string

	// VLANID is the VLAN ID to match.
	VLANID uint16
}

// ToMatchString converts the match to an OVS match string.
func (m *InternalOpenFlowMatch) ToMatchString() string {
	var parts []string

	if m.InPort > 0 {
		parts = append(parts, fmt.Sprintf("in_port=%d", m.InPort))
	}
	if m.DLType > 0 {
		parts = append(parts, fmt.Sprintf("dl_type=0x%04x", m.DLType))
	}
	if m.NWProto > 0 {
		parts = append(parts, fmt.Sprintf("nw_proto=%d", m.NWProto))
	}
	if m.TPSrc > 0 {
		parts = append(parts, fmt.Sprintf("tp_src=%d", m.TPSrc))
	}
	if m.TPDst > 0 {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", m.TPDst))
	}
	if m.NWSrc != "" {
		parts = append(parts, fmt.Sprintf("nw_src=%s", m.NWSrc))
	}
	if m.NWDst != "" {
		parts = append(parts, fmt.Sprintf("nw_dst=%s", m.NWDst))
	}
	if m.DLSrc != "" {
		parts = append(parts, fmt.Sprintf("dl_src=%s", m.DLSrc))
	}
	if m.DLDst != "" {
		parts = append(parts, fmt.Sprintf("dl_dst=%s", m.DLDst))
	}
	if m.VLANID > 0 {
		parts = append(parts, fmt.Sprintf("dl_vlan=%d", m.VLANID))
	}

	return strings.Join(parts, ",")
}

// InternalOpenFlowActionType defines the type of OpenFlow action.
type InternalOpenFlowActionType int

const (
	// InternalActionAllow allows the packet (output NORMAL).
	InternalActionAllow InternalOpenFlowActionType = iota

	// InternalActionDrop drops the packet (no output).
	InternalActionDrop

	// InternalActionOutput outputs to a specific port.
	InternalActionOutput

	// InternalActionGoto goes to another table.
	InternalActionGoto

	// InternalActionSetVLAN sets the VLAN tag.
	InternalActionSetVLAN

	// InternalActionStripVLAN removes the VLAN tag.
	InternalActionStripVLAN
)

// InternalOpenFlowAction represents an OpenFlow action.
type InternalOpenFlowAction struct {
	// Type is the action type.
	Type InternalOpenFlowActionType

	// Port is the output port for output actions.
	Port int32

	// Table is the destination table for goto actions.
	Table int

	// VLAN is the VLAN ID for set VLAN actions.
	VLAN uint16
}

// ToActionString converts the action to an OVS action string.
func (a *InternalOpenFlowAction) ToActionString() string {
	switch a.Type {
	case InternalActionAllow:
		return "NORMAL"
	case InternalActionDrop:
		return "drop"
	case InternalActionOutput:
		return fmt.Sprintf("output:%d", a.Port)
	case InternalActionGoto:
		return fmt.Sprintf("resubmit(,%d)", a.Table)
	case InternalActionSetVLAN:
		return fmt.Sprintf("mod_vlan_vid:%d", a.VLAN)
	case InternalActionStripVLAN:
		return "strip_vlan"
	default:
		return ""
	}
}

// SecurityGroupManager translates security groups to OpenFlow rules.
type SecurityGroupManager interface {
	// GetSecurityGroup retrieves a security group by name.
	GetSecurityGroup(ctx context.Context, name string) (*SecurityGroup, error)

	// SecurityGroupToFlows converts a security group to OpenFlow rules.
	SecurityGroupToFlows(sg *SecurityGroup, portName string, ofPort int32, vlanID uint16) []*InternalOpenFlowRule
}

// SDNNetworkManager manages SDN/OVS/OpenFlow networking for containers.
// It implements the NetworkManager interface defined in lifecycle.go.
type SDNNetworkManager struct {
	config NetworkManagerConfig
	ovs    OVSClient
	ofCtrl OpenFlowController
	sgMgr  SecurityGroupManager

	// Container network state
	containers map[string]*ContainerNetworkInfo
	mu         sync.RWMutex

	// Lifecycle
	closed   atomic.Bool
	closedMu sync.RWMutex
}

// NewSDNNetworkManager creates a new SDNNetworkManager.
func NewSDNNetworkManager(config NetworkManagerConfig, ovs OVSClient, ofCtrl OpenFlowController, sgMgr SecurityGroupManager) (*SDNNetworkManager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid network manager config: %w", err)
	}

	if ovs == nil {
		return nil, ErrOVSConnectionFailed
	}

	nm := &SDNNetworkManager{
		config:     config,
		ovs:        ovs,
		ofCtrl:     ofCtrl,
		sgMgr:      sgMgr,
		containers: make(map[string]*ContainerNetworkInfo),
	}

	return nm, nil
}

// SetupContainerNetwork configures network for a container.
// For SDN mode: creates OVS port, sets VLAN, installs OpenFlow rules.
// For bridge/host/none: delegates to Podman (returns nil).
// This method implements the NetworkManager interface.
func (nm *SDNNetworkManager) SetupContainerNetwork(ctx context.Context, containerID string, cfg *ContainerNetworkConfig) error {
	if nm.closed.Load() {
		return ErrOrchestratorClosed
	}

	if containerID == "" {
		return ErrInvalidContainerID
	}

	if cfg == nil {
		return ErrInvalidNetworkMode
	}

	// For non-SDN modes, return nil and let Podman handle it
	mode := cfg.GetNetworkMode()
	if mode != NetworkModeSDN {
		return nm.setupNonSDNNetwork(ctx, containerID, mode)
	}

	// Validate SDN config
	if cfg.SDN == nil {
		return ErrInvalidNetworkMode
	}

	if err := cfg.SDN.Validate(); err != nil {
		return err
	}

	_, err := nm.setupSDNNetwork(ctx, containerID, cfg.SDN)
	return err
}

// SetupContainerNetworkWithInfo configures network and returns detailed info.
// This is an extended version that returns ContainerNetworkInfo.
func (nm *SDNNetworkManager) SetupContainerNetworkWithInfo(ctx context.Context, containerID string, cfg *ContainerNetworkConfig) (*ContainerNetworkInfo, error) {
	if nm.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if containerID == "" {
		return nil, ErrInvalidContainerID
	}

	if cfg == nil {
		return nil, ErrInvalidNetworkMode
	}

	// For non-SDN modes, return minimal info and let Podman handle it
	mode := cfg.GetNetworkMode()
	if mode != NetworkModeSDN {
		if err := nm.setupNonSDNNetwork(ctx, containerID, mode); err != nil {
			return nil, err
		}
		nm.mu.RLock()
		info := nm.containers[containerID]
		nm.mu.RUnlock()
		if info != nil {
			infoCopy := *info
			return &infoCopy, nil
		}
		return nil, nil
	}

	// Validate SDN config
	if cfg.SDN == nil {
		return nil, ErrInvalidNetworkMode
	}

	if err := cfg.SDN.Validate(); err != nil {
		return nil, err
	}

	return nm.setupSDNNetwork(ctx, containerID, cfg.SDN)
}

// setupNonSDNNetwork handles bridge/host/none network modes.
func (nm *SDNNetworkManager) setupNonSDNNetwork(ctx context.Context, containerID string, mode NetworkMode) error {
	info := &ContainerNetworkInfo{
		ContainerID: containerID,
		Mode:        mode,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	nm.mu.Lock()
	nm.containers[containerID] = info
	nm.mu.Unlock()

	return nil
}

// setupSDNNetwork handles SDN/OVS/OpenFlow network configuration.
func (nm *SDNNetworkManager) setupSDNNetwork(ctx context.Context, containerID string, cfg *SDNConfig) (*ContainerNetworkInfo, error) {
	// Generate port name
	portName := cfg.OVSPort
	if portName == "" {
		portName = nm.generatePortName(containerID)
	}

	bridgeName := cfg.Bridge
	if bridgeName == "" {
		bridgeName = nm.config.OVSBridge
	}

	// Ensure OVS is connected
	if !nm.ovs.IsConnected() {
		if err := nm.ovs.Connect(ctx); err != nil {
			return nil, fmt.Errorf("%w: failed to connect to OVS: %v", ErrOVSConnectionFailed, err)
		}
	}

	// Create OVS port
	if err := nm.ovs.AddPort(ctx, bridgeName, portName); err != nil {
		return nil, fmt.Errorf("%w: failed to add OVS port %s: %v", ErrNetworkSetupFailed, portName, err)
	}

	// Set VLAN tag
	vlanID := cfg.VLANID
	if vlanID == 0 {
		vlanID = nm.config.DefaultVLAN
	}

	if vlanID > 0 {
		if err := nm.ovs.SetPortVLAN(ctx, portName, vlanID); err != nil {
			// Cleanup port on failure
			nm.ovs.DeletePort(ctx, bridgeName, portName)
			return nil, fmt.Errorf("%w: failed to set VLAN %d on port %s: %v", ErrVLANConfigFailed, vlanID, portName, err)
		}
	}

	// Get OpenFlow port number
	ofPort, err := nm.ovs.GetOFPort(ctx, portName)
	if err != nil {
		nm.ovs.DeletePort(ctx, bridgeName, portName)
		return nil, fmt.Errorf("%w: failed to get OpenFlow port: %v", ErrNetworkSetupFailed, err)
	}

	info := &ContainerNetworkInfo{
		ContainerID:    containerID,
		PortName:       portName,
		OFPort:         ofPort,
		VLANID:         vlanID,
		IPAddress:      cfg.IPAddress,
		MACAddress:     cfg.MACAddress,
		SecurityGroups: cfg.SecurityGroups,
		Mode:           NetworkModeSDN,
		BridgeName:     bridgeName,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Install custom OpenFlow rules
	flowCount := 0
	for _, rule := range cfg.OpenFlowRules {
		if err := nm.installConfigRule(ctx, bridgeName, ofPort, vlanID, &rule); err != nil {
			// Log error but continue - partial flows are better than none
			continue
		}
		flowCount++
	}

	// Apply security groups
	for _, sgName := range cfg.SecurityGroups {
		count, err := nm.applySecurityGroupFlows(ctx, containerID, sgName, portName, ofPort, vlanID)
		if err != nil {
			// Log error but continue
			continue
		}
		flowCount += count
	}

	info.FlowCount = flowCount

	// Store container network info
	nm.mu.Lock()
	nm.containers[containerID] = info
	nm.mu.Unlock()

	return info, nil
}

// TeardownContainerNetwork removes network configuration for a container.
// This method implements the NetworkManager interface.
func (nm *SDNNetworkManager) TeardownContainerNetwork(ctx context.Context, containerID string) error {
	if nm.closed.Load() {
		return ErrOrchestratorClosed
	}

	return nm.teardownContainerNetworkInternal(ctx, containerID)
}

// teardownContainerNetworkInternal is the internal teardown that doesn't check closed state.
// This is used by Close() to cleanup containers even after setting closed=true.
func (nm *SDNNetworkManager) teardownContainerNetworkInternal(ctx context.Context, containerID string) error {
	if containerID == "" {
		return ErrInvalidContainerID
	}

	nm.mu.Lock()
	info, exists := nm.containers[containerID]
	if exists {
		delete(nm.containers, containerID)
	}
	nm.mu.Unlock()

	if !exists {
		return ErrContainerNotFound
	}

	// For non-SDN modes, nothing to clean up
	if info.Mode != NetworkModeSDN {
		return nil
	}

	// Remove OpenFlow rules for this container
	if nm.ofCtrl != nil && info.OFPort > 0 {
		// Best-effort cleanup: log but continue on error
		_ = nm.ofCtrl.DeleteFlowsByPort(ctx, info.PortName, info.OFPort)
	}

	// Also delete via OVS client if available
	if nm.ovs != nil && nm.ovs.IsConnected() && info.OFPort > 0 {
		nm.ovs.DeleteFlowsByPort(ctx, info.BridgeName, info.PortName, info.OFPort)
	}

	// Remove OVS port
	if nm.ovs != nil && nm.ovs.IsConnected() && info.PortName != "" {
		if err := nm.ovs.DeletePort(ctx, info.BridgeName, info.PortName); err != nil {
			return fmt.Errorf("%w: failed to delete OVS port %s: %v", ErrNetworkTeardownFailed, info.PortName, err)
		}
	}

	return nil
}

// ApplySecurityGroup applies a security group to a container.
func (nm *SDNNetworkManager) ApplySecurityGroup(ctx context.Context, containerID, sgName string) error {
	if nm.closed.Load() {
		return ErrOrchestratorClosed
	}

	if containerID == "" {
		return ErrInvalidContainerID
	}

	if sgName == "" {
		return ErrNetworkSetupFailed
	}

	nm.mu.Lock()
	info, exists := nm.containers[containerID]
	nm.mu.Unlock()

	if !exists {
		return ErrContainerNotFound
	}

	if info.Mode != NetworkModeSDN {
		// Security groups only apply to SDN mode
		return nil
	}

	// Check if already applied
	for _, existing := range info.SecurityGroups {
		if existing == sgName {
			return nil
		}
	}

	// Apply security group flows
	count, err := nm.applySecurityGroupFlows(ctx, containerID, sgName, info.PortName, info.OFPort, info.VLANID)
	if err != nil {
		return err
	}

	// Update container info
	nm.mu.Lock()
	if info, exists := nm.containers[containerID]; exists {
		info.SecurityGroups = append(info.SecurityGroups, sgName)
		info.FlowCount += count
		info.UpdatedAt = time.Now()
	}
	nm.mu.Unlock()

	return nil
}

// RemoveSecurityGroup removes a security group from a container.
func (nm *SDNNetworkManager) RemoveSecurityGroup(ctx context.Context, containerID, sgName string) error {
	if nm.closed.Load() {
		return ErrOrchestratorClosed
	}

	if containerID == "" {
		return ErrInvalidContainerID
	}

	if sgName == "" {
		return ErrNetworkSetupFailed
	}

	nm.mu.Lock()
	info, exists := nm.containers[containerID]
	nm.mu.Unlock()

	if !exists {
		return ErrContainerNotFound
	}

	if info.Mode != NetworkModeSDN {
		return nil
	}

	// Find and remove the security group
	found := false
	newSGs := make([]string, 0, len(info.SecurityGroups))
	for _, sg := range info.SecurityGroups {
		if sg == sgName {
			found = true
		} else {
			newSGs = append(newSGs, sg)
		}
	}

	if !found {
		return nil
	}

	// Delete security group flows
	if err := nm.removeSecurityGroupFlows(ctx, containerID, sgName, info.PortName, info.OFPort); err != nil {
		return err
	}

	// Update container info
	nm.mu.Lock()
	if info, exists := nm.containers[containerID]; exists {
		info.SecurityGroups = newSGs
		info.UpdatedAt = time.Now()
	}
	nm.mu.Unlock()

	return nil
}

// GetContainerNetworkInfo retrieves network information for a container.
func (nm *SDNNetworkManager) GetContainerNetworkInfo(ctx context.Context, containerID string) (*ContainerNetworkInfo, error) {
	if nm.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if containerID == "" {
		return nil, ErrInvalidContainerID
	}

	nm.mu.RLock()
	info, exists := nm.containers[containerID]
	nm.mu.RUnlock()

	if !exists {
		return nil, ErrContainerNotFound
	}

	// Return a copy
	infoCopy := *info
	infoCopy.SecurityGroups = make([]string, len(info.SecurityGroups))
	copy(infoCopy.SecurityGroups, info.SecurityGroups)

	return &infoCopy, nil
}

// ListContainerNetworks returns network info for all containers.
func (nm *SDNNetworkManager) ListContainerNetworks(ctx context.Context) ([]*ContainerNetworkInfo, error) {
	if nm.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	nm.mu.RLock()
	defer nm.mu.RUnlock()

	result := make([]*ContainerNetworkInfo, 0, len(nm.containers))
	for _, info := range nm.containers {
		infoCopy := *info
		infoCopy.SecurityGroups = make([]string, len(info.SecurityGroups))
		copy(infoCopy.SecurityGroups, info.SecurityGroups)
		result = append(result, &infoCopy)
	}

	return result, nil
}

// Close closes the network manager and releases resources.
func (nm *SDNNetworkManager) Close() error {
	nm.closedMu.Lock()
	defer nm.closedMu.Unlock()

	if nm.closed.Load() {
		return nil
	}

	// Cleanup all container networks if configured (before setting closed)
	if nm.config.CleanupOnTeardown {
		ctx, cancel := context.WithTimeout(context.Background(), nm.config.ConnectionTimeout)
		defer cancel()

		nm.mu.Lock()
		containerIDs := make([]string, 0, len(nm.containers))
		for id := range nm.containers {
			containerIDs = append(containerIDs, id)
		}
		nm.mu.Unlock()

		for _, id := range containerIDs {
			nm.teardownContainerNetworkInternal(ctx, id)
		}
	}

	nm.closed.Store(true)
	return nil
}

// generatePortName generates an OVS port name for a container.
func (nm *SDNNetworkManager) generatePortName(containerID string) string {
	// Use first 12 characters of container ID for brevity
	shortID := containerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	return nm.config.GetPortPrefix() + shortID
}

// installConfigRule installs an OpenFlow rule from configuration.
func (nm *SDNNetworkManager) installConfigRule(ctx context.Context, bridgeName string, ofPort int32, vlanID uint16, rule *OpenFlowRule) error {
	if nm.ovs == nil {
		return ErrOVSConnectionFailed
	}

	// Convert config rule to OVS flow
	match := nm.buildMatchString(ofPort, vlanID, &rule.Match)
	actions := nm.buildActionsString(rule.Actions)

	flow := &OVSFlow{
		Table:    rule.Table,
		Priority: rule.Priority,
		Match:    match,
		Actions:  actions,
	}

	return nm.ovs.AddFlow(ctx, bridgeName, flow)
}

// buildMatchString builds an OVS match string from OpenFlowMatch.
func (nm *SDNNetworkManager) buildMatchString(ofPort int32, vlanID uint16, match *OpenFlowMatch) string {
	var parts []string

	// Add port match if specified, otherwise use container's port
	if match.InPort != "" {
		parts = append(parts, fmt.Sprintf("in_port=%s", match.InPort))
	} else if ofPort > 0 {
		parts = append(parts, fmt.Sprintf("in_port=%d", ofPort))
	}

	// Add VLAN match
	if vlanID > 0 {
		parts = append(parts, fmt.Sprintf("dl_vlan=%d", vlanID))
	}

	// Add Ethernet type
	if match.DLType > 0 {
		parts = append(parts, fmt.Sprintf("dl_type=0x%04x", match.DLType))
	}

	// Add IP protocol
	if match.NWProto > 0 {
		parts = append(parts, fmt.Sprintf("nw_proto=%d", match.NWProto))
	}

	// Add transport ports
	if match.TPSrc > 0 {
		parts = append(parts, fmt.Sprintf("tp_src=%d", match.TPSrc))
	}
	if match.TPDst > 0 {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", match.TPDst))
	}

	// Add IP addresses
	if match.NWSrc != "" {
		parts = append(parts, fmt.Sprintf("nw_src=%s", match.NWSrc))
	}
	if match.NWDst != "" {
		parts = append(parts, fmt.Sprintf("nw_dst=%s", match.NWDst))
	}

	// Add MAC addresses
	if match.DLSrc != "" {
		parts = append(parts, fmt.Sprintf("dl_src=%s", match.DLSrc))
	}
	if match.DLDst != "" {
		parts = append(parts, fmt.Sprintf("dl_dst=%s", match.DLDst))
	}

	return strings.Join(parts, ",")
}

// buildActionsString builds an OVS actions string from config actions.
func (nm *SDNNetworkManager) buildActionsString(actions []OpenFlowAction) string {
	if len(actions) == 0 {
		return "NORMAL"
	}

	var parts []string
	for _, action := range actions {
		switch action.Type {
		case ActionAllow:
			parts = append(parts, "NORMAL")
		case ActionDrop:
			parts = append(parts, "drop")
		case ActionForward:
			if action.Port != "" {
				parts = append(parts, fmt.Sprintf("output:%s", action.Port))
			}
		case ActionGoto:
			parts = append(parts, fmt.Sprintf("resubmit(,%d)", action.Table))
		}
	}

	if len(parts) == 0 {
		return "NORMAL"
	}

	return strings.Join(parts, ",")
}

// applySecurityGroupFlows applies security group rules as OpenFlow flows.
func (nm *SDNNetworkManager) applySecurityGroupFlows(ctx context.Context, containerID, sgName, portName string, ofPort int32, vlanID uint16) (int, error) {
	if nm.sgMgr == nil {
		return 0, nil
	}

	sg, err := nm.sgMgr.GetSecurityGroup(ctx, sgName)
	if err != nil {
		return 0, fmt.Errorf("failed to get security group %s: %w", sgName, err)
	}

	flows := nm.sgMgr.SecurityGroupToFlows(sg, portName, ofPort, vlanID)
	if len(flows) == 0 {
		return 0, nil
	}

	installed := 0
	for _, flow := range flows {
		if nm.ofCtrl != nil {
			if err := nm.ofCtrl.AddFlow(ctx, flow); err != nil {
				continue
			}
		} else if nm.ovs != nil {
			// Fall back to OVS client
			ovsFlow := nm.internalFlowToOVS(flow)
			nm.mu.RLock()
			info := nm.containers[containerID]
			nm.mu.RUnlock()
			bridgeName := nm.config.OVSBridge
			if info != nil && info.BridgeName != "" {
				bridgeName = info.BridgeName
			}
			if err := nm.ovs.AddFlow(ctx, bridgeName, ovsFlow); err != nil {
				continue
			}
		}
		installed++
	}

	return installed, nil
}

// removeSecurityGroupFlows removes security group flows for a container.
func (nm *SDNNetworkManager) removeSecurityGroupFlows(ctx context.Context, containerID, sgName, portName string, ofPort int32) error {
	if nm.sgMgr == nil {
		return nil
	}

	// Get security group to know which flows to remove
	sg, err := nm.sgMgr.GetSecurityGroup(ctx, sgName)
	if err != nil {
		// If we can't get the security group, try to delete by port
		if nm.ofCtrl != nil {
			return nm.ofCtrl.DeleteFlowsByPort(ctx, portName, ofPort)
		}
		return nil
	}

	// Get bridge name
	nm.mu.RLock()
	info := nm.containers[containerID]
	nm.mu.RUnlock()

	bridgeName := nm.config.OVSBridge
	if info != nil && info.BridgeName != "" {
		bridgeName = info.BridgeName
	}

	// Delete flows matching this security group's rules
	for _, rule := range sg.Rules {
		match := nm.buildSecurityRuleMatch(ofPort, 0, &rule)
		if nm.ovs != nil {
			nm.ovs.DeleteFlow(ctx, bridgeName, match)
		}
	}

	return nil
}

// buildSecurityRuleMatch builds a match string for a security group rule.
func (nm *SDNNetworkManager) buildSecurityRuleMatch(ofPort int32, vlanID uint16, rule *SecurityGroupRule) string {
	var parts []string

	// Add port match based on direction
	if rule.Direction == DirectionIngress {
		// For ingress, match traffic going TO the container
		// (This would typically be done at the bridge level)
	} else {
		// For egress, match traffic FROM the container
		if ofPort > 0 {
			parts = append(parts, fmt.Sprintf("in_port=%d", ofPort))
		}
	}

	// Add VLAN if specified
	if vlanID > 0 {
		parts = append(parts, fmt.Sprintf("dl_vlan=%d", vlanID))
	}

	// Add IP type for protocol matching
	if rule.Protocol != "" {
		parts = append(parts, "dl_type=0x0800")

		// Add protocol
		proto := nm.parseProtocol(rule.Protocol)
		if proto > 0 {
			parts = append(parts, fmt.Sprintf("nw_proto=%d", proto))
		}

		// Add port
		if rule.Port > 0 {
			if rule.Direction == DirectionIngress {
				parts = append(parts, fmt.Sprintf("tp_dst=%d", rule.Port))
			} else {
				parts = append(parts, fmt.Sprintf("tp_src=%d", rule.Port))
			}
		}
	}

	// Add remote IP
	if rule.RemoteIP != "" {
		if rule.Direction == DirectionIngress {
			parts = append(parts, fmt.Sprintf("nw_src=%s", rule.RemoteIP))
		} else {
			parts = append(parts, fmt.Sprintf("nw_dst=%s", rule.RemoteIP))
		}
	}

	return strings.Join(parts, ",")
}

// parseProtocol parses a protocol string to a protocol number.
func (nm *SDNNetworkManager) parseProtocol(proto string) uint8 {
	switch strings.ToLower(proto) {
	case "tcp":
		return ProtocolTCP
	case "udp":
		return ProtocolUDP
	case "icmp":
		return ProtocolICMP
	default:
		// Try to parse as number
		if n, err := strconv.ParseUint(proto, 10, 8); err == nil {
			return uint8(n)
		}
		return 0
	}
}

// internalFlowToOVS converts an internal flow to OVS format.
func (nm *SDNNetworkManager) internalFlowToOVS(flow *InternalOpenFlowRule) *OVSFlow {
	var match string
	if flow.Match != nil {
		match = flow.Match.ToMatchString()
	}

	var actionParts []string
	for _, action := range flow.Actions {
		if s := action.ToActionString(); s != "" {
			actionParts = append(actionParts, s)
		}
	}
	actions := strings.Join(actionParts, ",")
	if actions == "" {
		actions = "NORMAL"
	}

	return &OVSFlow{
		Table:       flow.Table,
		Priority:    flow.Priority,
		Match:       match,
		Actions:     actions,
		Cookie:      fmt.Sprintf("0x%x", flow.Cookie),
		IdleTimeout: flow.IdleTimeout,
		HardTimeout: flow.HardTimeout,
	}
}

// DefaultSecurityGroupManager provides a default implementation of SecurityGroupManager.
type DefaultSecurityGroupManager struct {
	groups map[string]*SecurityGroup
	mu     sync.RWMutex
}

// NewDefaultSecurityGroupManager creates a new DefaultSecurityGroupManager.
func NewDefaultSecurityGroupManager() *DefaultSecurityGroupManager {
	return &DefaultSecurityGroupManager{
		groups: make(map[string]*SecurityGroup),
	}
}

// RegisterSecurityGroup registers a security group.
func (m *DefaultSecurityGroupManager) RegisterSecurityGroup(sg *SecurityGroup) error {
	if sg == nil || sg.Name == "" {
		return ErrNetworkSetupFailed
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.groups[sg.Name] = sg
	return nil
}

// GetSecurityGroup retrieves a security group by name.
func (m *DefaultSecurityGroupManager) GetSecurityGroup(ctx context.Context, name string) (*SecurityGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sg, exists := m.groups[name]
	if !exists {
		return nil, ErrContainerNotFound
	}

	return sg, nil
}

// SecurityGroupToFlows converts a security group to OpenFlow rules.
func (m *DefaultSecurityGroupManager) SecurityGroupToFlows(sg *SecurityGroup, portName string, ofPort int32, vlanID uint16) []*InternalOpenFlowRule {
	if sg == nil {
		return nil
	}

	var flows []*InternalOpenFlowRule
	basePriority := sg.Priority
	if basePriority <= 0 {
		basePriority = SecurityBasePriority
	}

	table := sg.Table
	if table <= 0 {
		table = SecurityFlowTable
	}

	for i, rule := range sg.Rules {
		flow := m.ruleToFlow(&rule, ofPort, vlanID, basePriority+i, table)
		if flow != nil {
			flows = append(flows, flow)
		}
	}

	return flows
}

// ruleToFlow converts a single security group rule to an OpenFlow rule.
func (m *DefaultSecurityGroupManager) ruleToFlow(rule *SecurityGroupRule, ofPort int32, vlanID uint16, priority, table int) *InternalOpenFlowRule {
	match := &InternalOpenFlowMatch{}

	// Set VLAN match
	if vlanID > 0 {
		match.VLANID = vlanID
	}

	// Set direction-specific matches
	if rule.Direction == DirectionEgress {
		// Egress: match traffic from container
		match.InPort = ofPort
	}

	// Set Ethernet type for IP protocols
	if rule.Protocol != "" {
		match.DLType = EthTypeIPv4

		// Set protocol
		switch strings.ToLower(rule.Protocol) {
		case "tcp":
			match.NWProto = ProtocolTCP
		case "udp":
			match.NWProto = ProtocolUDP
		case "icmp":
			match.NWProto = ProtocolICMP
		default:
			if n, err := strconv.ParseUint(rule.Protocol, 10, 8); err == nil {
				match.NWProto = uint8(n)
			}
		}

		// Set port match
		if rule.Port > 0 {
			if rule.Direction == DirectionIngress {
				match.TPDst = rule.Port
			} else {
				match.TPSrc = rule.Port
			}
		}
	}

	// Set remote IP
	if rule.RemoteIP != "" {
		// Validate IP/CIDR format
		if _, _, err := net.ParseCIDR(rule.RemoteIP); err != nil {
			if ip := net.ParseIP(rule.RemoteIP); ip == nil {
				return nil // Invalid IP
			}
		}

		if rule.Direction == DirectionIngress {
			match.NWSrc = rule.RemoteIP
		} else {
			match.NWDst = rule.RemoteIP
		}
	}

	// Build actions
	var actions []InternalOpenFlowAction
	switch rule.Action {
	case "drop":
		actions = append(actions, InternalOpenFlowAction{Type: InternalActionDrop})
	default:
		actions = append(actions, InternalOpenFlowAction{Type: InternalActionAllow})
	}

	return &InternalOpenFlowRule{
		Match:    match,
		Actions:  actions,
		Priority: priority,
		Table:    table,
	}
}
