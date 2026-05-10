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

// BridgeType represents the type of an SDN bridge.
type BridgeType string

const (
	// BridgeTypeUnspecified indicates no bridge type is set.
	BridgeTypeUnspecified BridgeType = "UNSPECIFIED"
	// BridgeTypeOVS indicates an Open vSwitch bridge.
	BridgeTypeOVS BridgeType = "ovs"
	// BridgeTypeLinux indicates a Linux bridge.
	BridgeTypeLinux BridgeType = "linux"
	// BridgeTypeVXLAN indicates a VXLAN bridge.
	BridgeTypeVXLAN BridgeType = "vxlan"
)

// PortType represents the type of a port on an SDN bridge.
type PortType string

const (
	// PortTypeUnspecified indicates no port type is set.
	PortTypeUnspecified PortType = "UNSPECIFIED"
	// PortTypeInternal indicates an internal port.
	PortTypeInternal PortType = "internal"
	// PortTypePhysical indicates a physical port.
	PortTypePhysical PortType = "physical"
	// PortTypeTap indicates a tap port.
	PortTypeTap PortType = "tap"
	// PortTypeVeth indicates a veth port.
	PortTypeVeth PortType = "veth"
	// PortTypeVXLAN indicates a VXLAN port.
	PortTypeVXLAN PortType = "vxlan"
	// PortTypeGRE indicates a GRE port.
	PortTypeGRE PortType = "gre"
)

// FlowActionType represents the type of an OpenFlow action.
type FlowActionType string

const (
	// FlowActionUnspecified indicates no action type is set.
	FlowActionUnspecified FlowActionType = "UNSPECIFIED"
	// FlowActionOutput indicates an output action.
	FlowActionOutput FlowActionType = "output"
	// FlowActionDrop indicates a drop action.
	FlowActionDrop FlowActionType = "drop"
	// FlowActionSetVLAN indicates a set VLAN action.
	FlowActionSetVLAN FlowActionType = "set_vlan"
	// FlowActionStripVLAN indicates a strip VLAN action.
	FlowActionStripVLAN FlowActionType = "strip_vlan"
	// FlowActionSetField indicates a set field action.
	FlowActionSetField FlowActionType = "set_field"
	// FlowActionGotoTable indicates a goto table action.
	FlowActionGotoTable FlowActionType = "goto_table"
	// FlowActionController indicates a controller action.
	FlowActionController FlowActionType = "controller"
)

// FlowTable represents an OpenFlow table number.
type FlowTable int

const (
	// FlowTableUnspecified indicates no table is set.
	FlowTableUnspecified FlowTable = -1
	// FlowTable0 is table 0.
	FlowTable0 FlowTable = 0
	// FlowTable1 is table 1.
	FlowTable1 FlowTable = 1
	// FlowTable2 is table 2.
	FlowTable2 FlowTable = 2
	// FlowTable3 is table 3.
	FlowTable3 FlowTable = 3
	// FlowTableDrop is the drop table (255).
	FlowTableDrop FlowTable = 255
)

// PolicyType represents the type of a network policy.
type PolicyType string

const (
	// PolicyTypeUnspecified indicates no policy type is set.
	PolicyTypeUnspecified PolicyType = "UNSPECIFIED"
	// PolicyTypeACL indicates an access control list policy.
	PolicyTypeACL PolicyType = "acl"
	// PolicyTypeQoS indicates a quality of service policy.
	PolicyTypeQoS PolicyType = "qos"
	// PolicyTypeNAT indicates a network address translation policy.
	PolicyTypeNAT PolicyType = "nat"
	// PolicyTypeFirewall indicates a firewall policy.
	PolicyTypeFirewall PolicyType = "firewall"
	// PolicyTypeRouting indicates a routing policy.
	PolicyTypeRouting PolicyType = "routing"
)

// PolicyTargetType represents the type of a policy target.
type PolicyTargetType string

const (
	// PolicyTargetTypeUnspecified indicates no target type.
	PolicyTargetTypeUnspecified PolicyTargetType = "UNSPECIFIED"
	// PolicyTargetTypeBridge indicates a bridge target.
	PolicyTargetTypeBridge PolicyTargetType = "bridge"
	// PolicyTargetTypePort indicates a port target.
	PolicyTargetTypePort PolicyTargetType = "port"
)

// BridgeConfig contains the configuration for creating a bridge.
type BridgeConfig struct {
	// Name is the bridge name.
	Name string `json:"name" yaml:"name"`
	// Type is the bridge type.
	Type BridgeType `json:"type" yaml:"type"`
	// DatapathID is the datapath identifier.
	DatapathID string `json:"datapath_id,omitempty" yaml:"datapath_id,omitempty"`
	// STPEnabled indicates whether STP is enabled.
	STPEnabled bool `json:"stp_enabled" yaml:"stp_enabled"`
	// MTU is the maximum transmission unit.
	MTU uint32 `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	// Options are additional key-value options.
	Options map[string]string `json:"options,omitempty" yaml:"options,omitempty"`
	// Labels are key-value metadata labels.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// PortConfig contains the configuration for adding a port.
type PortConfig struct {
	// Name is the port name.
	Name string `json:"name" yaml:"name"`
	// Type is the port type.
	Type PortType `json:"type" yaml:"type"`
	// VLAN is the VLAN tag for access ports.
	VLAN uint32 `json:"vlan,omitempty" yaml:"vlan,omitempty"`
	// MACAddress is the MAC address.
	MACAddress string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`
	// MTU is the maximum transmission unit.
	MTU uint32 `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	// Options are additional key-value options.
	Options map[string]string `json:"options,omitempty" yaml:"options,omitempty"`
	// Labels are key-value metadata labels.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// FlowMatch contains match criteria for an OpenFlow rule.
type FlowMatch struct {
	// InPort matches on the input port.
	InPort string `json:"in_port,omitempty" yaml:"in_port,omitempty"`
	// EthSrc matches on source MAC address.
	EthSrc string `json:"eth_src,omitempty" yaml:"eth_src,omitempty"`
	// EthDst matches on destination MAC address.
	EthDst string `json:"eth_dst,omitempty" yaml:"eth_dst,omitempty"`
	// EthType matches on ethertype.
	EthType uint32 `json:"eth_type,omitempty" yaml:"eth_type,omitempty"`
	// IPSrc matches on source IP address.
	IPSrc string `json:"ip_src,omitempty" yaml:"ip_src,omitempty"`
	// IPDst matches on destination IP address.
	IPDst string `json:"ip_dst,omitempty" yaml:"ip_dst,omitempty"`
}

// FlowAction represents an OpenFlow action.
type FlowAction struct {
	// Type is the action type.
	Type FlowActionType `json:"type" yaml:"type"`
	// Port is the output port for the action.
	Port string `json:"port,omitempty" yaml:"port,omitempty"`
}

// FlowConfig contains the configuration for adding a flow rule.
type FlowConfig struct {
	// BridgeID is the bridge to add the flow to.
	BridgeID string `json:"bridge_id" yaml:"bridge_id"`
	// Table is the flow table number.
	Table FlowTable `json:"table" yaml:"table"`
	// Priority is the flow priority.
	Priority uint32 `json:"priority" yaml:"priority"`
	// Match contains the match criteria.
	Match *FlowMatch `json:"match,omitempty" yaml:"match,omitempty"`
	// Actions are the flow actions.
	Actions []*FlowAction `json:"actions,omitempty" yaml:"actions,omitempty"`
	// Metadata are key-value metadata entries.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// VLANConfig contains the configuration for creating a VLAN.
type VLANConfig struct {
	// VlanID is the VLAN ID (1-4094).
	VlanID uint32 `json:"vlan_id" yaml:"vlan_id"`
	// Name is the VLAN name.
	Name string `json:"name" yaml:"name"`
	// BridgeID is the bridge to associate with.
	BridgeID string `json:"bridge_id,omitempty" yaml:"bridge_id,omitempty"`
	// Labels are key-value metadata labels.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

// PolicyTarget describes a target for a network policy.
type PolicyTarget struct {
	// Type is the target type (bridge, port).
	Type PolicyTargetType `json:"type" yaml:"type"`
	// ID is the target identifier.
	ID string `json:"id" yaml:"id"`
}

// PolicyConfig contains the configuration for applying a network policy.
type PolicyConfig struct {
	// Name is the policy name.
	Name string `json:"name" yaml:"name"`
	// Description is the policy description.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Type is the policy type.
	Type PolicyType `json:"type" yaml:"type"`
	// Priority is the policy priority.
	Priority int32 `json:"priority" yaml:"priority"`
	// Enabled indicates whether the policy is enabled.
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Targets are the policy targets.
	Targets []*PolicyTarget `json:"targets,omitempty" yaml:"targets,omitempty"`
}

// LabelSelector provides label-based filtering for list operations.
type LabelSelector struct {
	// MatchLabels are the labels to match.
	MatchLabels map[string]string `json:"match_labels,omitempty" yaml:"match_labels,omitempty"`
}

// VNIConfig contains the configuration for creating a VNI.
type VNIConfig struct {
	// VNI is the VXLAN Network Identifier.
	VNI uint32 `json:"vni" yaml:"vni"`
	// VLAN is the VLAN to map.
	VLAN uint32 `json:"vlan" yaml:"vlan"`
	// Name is the optional name for the VNI.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}
