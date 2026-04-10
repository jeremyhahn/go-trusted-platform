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

package cluster

import (
	"time"
)

// BridgeState represents a bridge configuration in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/bridges/{id}
type BridgeState struct {
	// ID is the unique identifier for this bridge (UUID from OVS)
	ID string `json:"id"`

	// Name is the bridge name
	Name string `json:"name"`

	// DatapathType specifies the datapath type (system, netdev)
	DatapathType string `json:"datapath_type"`

	// DatapathID is the OpenFlow datapath identifier
	DatapathID string `json:"datapath_id,omitempty"`

	// Ports contains the IDs of ports attached to this bridge
	Ports []string `json:"ports"`

	// FailMode specifies the failure mode (standalone, secure)
	FailMode string `json:"fail_mode,omitempty"`

	// FlowProtocols lists enabled OpenFlow protocol versions
	FlowProtocols []string `json:"flow_protocols,omitempty"`

	// Controllers lists OpenFlow controller addresses
	Controllers []string `json:"controllers,omitempty"`

	// STPEnabled indicates if Spanning Tree Protocol is enabled
	STPEnabled bool `json:"stp_enabled"`

	// RSTPEnabled indicates if Rapid Spanning Tree Protocol is enabled
	RSTPEnabled bool `json:"rstp_enabled"`

	// McastSnoopingEnabled indicates if multicast snooping is enabled
	McastSnoopingEnabled bool `json:"mcast_snooping_enabled"`

	// ExternalIDs are user-defined metadata tags
	ExternalIDs map[string]string `json:"external_ids,omitempty"`

	// OtherConfig contains additional configuration options
	OtherConfig map[string]string `json:"other_config,omitempty"`

	// Status contains runtime status information
	Status map[string]string `json:"status,omitempty"`

	// NodeID is the cluster node that owns this bridge
	NodeID uint64 `json:"node_id"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this bridge was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the entity ID for QuicBaaS storage (hash of bridge ID)
func (b *BridgeState) EntityID() uint64 {
	return hashString(b.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use ID-based hashing instead
func (b *BridgeState) SetEntityID(id uint64) {
	// No-op: entity ID is derived from bridge ID
}

// PortState represents a port configuration in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/ports/{id}
type PortState struct {
	// ID is the unique identifier for this port (UUID from OVS)
	ID string `json:"id"`

	// Name is the port name
	Name string `json:"name"`

	// BridgeID is the ID of the bridge this port is attached to
	BridgeID string `json:"bridge_id"`

	// Interfaces contains the IDs of interfaces in this port
	Interfaces []string `json:"interfaces"`

	// Tag is the VLAN tag (0 = trunk port, >0 = access port)
	Tag uint16 `json:"tag"`

	// Trunks lists VLAN IDs allowed on trunk ports
	Trunks []uint16 `json:"trunks,omitempty"`

	// VLANMode specifies VLAN mode (trunk, access, native-tagged, native-untagged)
	VLANMode string `json:"vlan_mode,omitempty"`

	// Type specifies the port type (internal, system, tap, vxlan, gre, etc)
	Type string `json:"type"`

	// MAC is the MAC address of the port
	MAC string `json:"mac,omitempty"`

	// MTU is the maximum transmission unit
	MTU uint32 `json:"mtu,omitempty"`

	// OFPort is the OpenFlow port number
	OFPort int32 `json:"ofport,omitempty"`

	// AdminState is the administrative state (up, down)
	AdminState string `json:"admin_state,omitempty"`

	// LinkState is the link state (up, down)
	LinkState string `json:"link_state,omitempty"`

	// BondMode specifies bonding mode for bonded ports
	BondMode string `json:"bond_mode,omitempty"`

	// BondUpDelay is the bond up delay in milliseconds
	BondUpDelay int64 `json:"bond_up_delay,omitempty"`

	// QoS is the ID of the QoS configuration
	QoS string `json:"qos,omitempty"`

	// ExternalIDs are user-defined metadata tags
	ExternalIDs map[string]string `json:"external_ids,omitempty"`

	// OtherConfig contains additional configuration options
	OtherConfig map[string]string `json:"other_config,omitempty"`

	// Statistics contains port statistics
	Statistics map[string]int64 `json:"statistics,omitempty"`

	// NodeID is the cluster node that owns this port
	NodeID uint64 `json:"node_id"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this port was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the entity ID for QuicBaaS storage (hash of port ID)
func (p *PortState) EntityID() uint64 {
	return hashString(p.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use ID-based hashing instead
func (p *PortState) SetEntityID(id uint64) {
	// No-op: entity ID is derived from port ID
}

// FlowState represents an OpenFlow rule in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/flows/{bridge}/{id}
type FlowState struct {
	// ID is the unique identifier for this flow
	ID string `json:"id"`

	// BridgeID is the ID of the bridge this flow is installed on
	BridgeID string `json:"bridge_id"`

	// Table is the OpenFlow table number
	Table uint8 `json:"table"`

	// Priority determines rule precedence (higher = more specific)
	Priority uint16 `json:"priority"`

	// Cookie is an opaque identifier set by the controller
	Cookie uint64 `json:"cookie,omitempty"`

	// IdleTimeout is seconds before flow expires due to inactivity (0 = no timeout)
	IdleTimeout uint16 `json:"idle_timeout"`

	// HardTimeout is seconds before flow expires regardless of activity (0 = no timeout)
	HardTimeout uint16 `json:"hard_timeout"`

	// Match contains the match criteria
	Match *FlowMatch `json:"match"`

	// Actions contains the actions to execute on match
	Actions []*FlowAction `json:"actions"`

	// Flags contains OpenFlow flags (send_flow_rem, check_overlap, etc)
	Flags []string `json:"flags,omitempty"`

	// PacketCount is the number of packets matched
	PacketCount uint64 `json:"packet_count"`

	// ByteCount is the number of bytes matched
	ByteCount uint64 `json:"byte_count"`

	// DurationSec is the flow duration in seconds
	DurationSec uint32 `json:"duration_sec"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this flow was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at"`

	// LastSeenAt is the timestamp when this flow last matched a packet
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
}

// EntityID returns the entity ID for QuicBaaS storage (hash of flow ID)
func (f *FlowState) EntityID() uint64 {
	return hashString(f.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use ID-based hashing instead
func (f *FlowState) SetEntityID(id uint64) {
	// No-op: entity ID is derived from flow ID
}

// FlowMatch contains the match criteria for an OpenFlow rule
type FlowMatch struct {
	// InPort matches the input port
	InPort *uint32 `json:"in_port,omitempty"`

	// EthSrc matches the Ethernet source address
	EthSrc string `json:"eth_src,omitempty"`

	// EthDst matches the Ethernet destination address
	EthDst string `json:"eth_dst,omitempty"`

	// EthType matches the Ethernet type
	EthType *uint16 `json:"eth_type,omitempty"`

	// VLANVid matches the VLAN ID
	VLANVid *uint16 `json:"vlan_vid,omitempty"`

	// VLANPcp matches the VLAN priority
	VLANPcp *uint8 `json:"vlan_pcp,omitempty"`

	// IPv4Src matches the IPv4 source address (CIDR notation)
	IPv4Src string `json:"ipv4_src,omitempty"`

	// IPv4Dst matches the IPv4 destination address (CIDR notation)
	IPv4Dst string `json:"ipv4_dst,omitempty"`

	// IPProto matches the IP protocol number
	IPProto *uint8 `json:"ip_proto,omitempty"`

	// TCPSrc matches the TCP source port
	TCPSrc *uint16 `json:"tcp_src,omitempty"`

	// TCPDst matches the TCP destination port
	TCPDst *uint16 `json:"tcp_dst,omitempty"`

	// UDPSrc matches the UDP source port
	UDPSrc *uint16 `json:"udp_src,omitempty"`

	// UDPDst matches the UDP destination port
	UDPDst *uint16 `json:"udp_dst,omitempty"`

	// ICMPType matches the ICMP type
	ICMPType *uint8 `json:"icmp_type,omitempty"`

	// ICMPCode matches the ICMP code
	ICMPCode *uint8 `json:"icmp_code,omitempty"`

	// ARPOp matches the ARP operation
	ARPOp *uint16 `json:"arp_op,omitempty"`

	// ARPSpa matches the ARP source protocol address
	ARPSpa string `json:"arp_spa,omitempty"`

	// ARPTpa matches the ARP target protocol address
	ARPTpa string `json:"arp_tpa,omitempty"`
}

// FlowAction represents an action to execute when a flow matches
type FlowAction struct {
	// Type specifies the action type
	Type FlowActionType `json:"type"`

	// Output port for OUTPUT action
	Port *uint32 `json:"port,omitempty"`

	// VLAN ID for SET_VLAN action
	VLANVid *uint16 `json:"vlan_vid,omitempty"`

	// VLAN priority for SET_VLAN_PCP action
	VLANPcp *uint8 `json:"vlan_pcp,omitempty"`

	// MAC address for SET_ETH_SRC/SET_ETH_DST actions
	MAC string `json:"mac,omitempty"`

	// IP address for SET_IPV4_SRC/SET_IPV4_DST actions
	IPv4 string `json:"ipv4,omitempty"`

	// Port number for SET_TCP_SRC/SET_TCP_DST/SET_UDP_SRC/SET_UDP_DST actions
	L4Port *uint16 `json:"l4_port,omitempty"`

	// Table for GOTO_TABLE action
	Table *uint8 `json:"table,omitempty"`

	// Group ID for GROUP action
	GroupID *uint32 `json:"group_id,omitempty"`

	// Meter ID for METER action
	MeterID *uint32 `json:"meter_id,omitempty"`
}

// FlowActionType specifies the type of flow action
type FlowActionType string

const (
	// ActionOutput forwards packet to specified port
	ActionOutput FlowActionType = "output"

	// ActionDrop drops the packet
	ActionDrop FlowActionType = "drop"

	// ActionNormal forwards using normal L2/L3 switching
	ActionNormal FlowActionType = "normal"

	// ActionFlood forwards to all ports except input
	ActionFlood FlowActionType = "flood"

	// ActionAll forwards to all ports including input
	ActionAll FlowActionType = "all"

	// ActionController sends packet to controller
	ActionController FlowActionType = "controller"

	// ActionLocal sends packet to local port
	ActionLocal FlowActionType = "local"

	// ActionInPort sends packet back to input port
	ActionInPort FlowActionType = "in_port"

	// ActionSetVLAN sets the VLAN ID
	ActionSetVLAN FlowActionType = "set_vlan"

	// ActionStripVLAN removes the VLAN tag
	ActionStripVLAN FlowActionType = "strip_vlan"

	// ActionSetVLANPcp sets the VLAN priority
	ActionSetVLANPcp FlowActionType = "set_vlan_pcp"

	// ActionSetEthSrc sets the Ethernet source address
	ActionSetEthSrc FlowActionType = "set_eth_src"

	// ActionSetEthDst sets the Ethernet destination address
	ActionSetEthDst FlowActionType = "set_eth_dst"

	// ActionSetIPv4Src sets the IPv4 source address
	ActionSetIPv4Src FlowActionType = "set_ipv4_src"

	// ActionSetIPv4Dst sets the IPv4 destination address
	ActionSetIPv4Dst FlowActionType = "set_ipv4_dst"

	// ActionSetTCPSrc sets the TCP source port
	ActionSetTCPSrc FlowActionType = "set_tcp_src"

	// ActionSetTCPDst sets the TCP destination port
	ActionSetTCPDst FlowActionType = "set_tcp_dst"

	// ActionSetUDPSrc sets the UDP source port
	ActionSetUDPSrc FlowActionType = "set_udp_src"

	// ActionSetUDPDst sets the UDP destination port
	ActionSetUDPDst FlowActionType = "set_udp_dst"

	// ActionGotoTable transfers to another flow table
	ActionGotoTable FlowActionType = "goto_table"

	// ActionGroup applies a group action
	ActionGroup FlowActionType = "group"

	// ActionMeter applies a meter
	ActionMeter FlowActionType = "meter"
)

// VLANState represents a VLAN configuration in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/vlans/{id}
type VLANState struct {
	// ID is the VLAN ID (1-4094)
	ID uint16 `json:"id"`

	// Name is the VLAN name
	Name string `json:"name"`

	// Description provides a human-readable description
	Description string `json:"description,omitempty"`

	// Ports contains the IDs of ports assigned to this VLAN
	Ports []string `json:"ports"`

	// TrunkPorts contains the IDs of trunk ports carrying this VLAN
	TrunkPorts []string `json:"trunk_ports,omitempty"`

	// ExternalIDs are user-defined metadata tags
	ExternalIDs map[string]string `json:"external_ids,omitempty"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this VLAN was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the entity ID for QuicBaaS storage (VLAN ID as uint64)
func (v *VLANState) EntityID() uint64 {
	return uint64(v.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use VLAN ID directly
func (v *VLANState) SetEntityID(id uint64) {
	// No-op: entity ID is the VLAN ID
}

// hashString generates a uint64 hash from a string for use as entity ID
func hashString(s string) uint64 {
	// Simple FNV-1a hash algorithm
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for i := 0; i < len(s); i++ {
		hash ^= uint64(s[i])
		hash *= prime64
	}
	return hash
}
