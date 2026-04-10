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

package bridge

import (
	"context"
	"time"
)

// BridgeStatus represents the operational status of a tenant bridge
type BridgeStatus string

const (
	// StatusPending indicates the bridge is being created
	StatusPending BridgeStatus = "pending"

	// StatusActive indicates the bridge is operational
	StatusActive BridgeStatus = "active"

	// StatusError indicates the bridge is in an error state
	StatusError BridgeStatus = "error"

	// StatusDeleting indicates the bridge is being deleted
	StatusDeleting BridgeStatus = "deleting"

	// StatusSuspended indicates the bridge is suspended
	StatusSuspended BridgeStatus = "suspended"
)

// VLANRange represents a range of VLANs allocated to a tenant
type VLANRange struct {
	Start uint16
	End   uint16
}

// IsValid checks if the VLAN range is valid
func (v VLANRange) IsValid() bool {
	return v.Start > 0 && v.End > 0 && v.Start <= v.End && v.End <= 4094
}

// Contains checks if a VLAN ID is within the range
func (v VLANRange) Contains(vlan uint16) bool {
	return vlan >= v.Start && vlan <= v.End
}

// Size returns the number of VLANs in the range
func (v VLANRange) Size() int {
	if !v.IsValid() {
		return 0
	}
	return int(v.End - v.Start + 1)
}

// TenantBridge represents a tenant's OVS bridge
type TenantBridge struct {
	// Name is the OVS bridge name (br-tenant-{tenantName})
	Name string

	// TenantID is the unique identifier of the tenant
	TenantID string

	// TenantName is the human-readable tenant name
	TenantName string

	// Datapath specifies the OVS datapath type (system, netdev, etc.)
	Datapath string

	// VLANRange is the VLAN range allocated to this tenant
	VLANRange VLANRange

	// CreatedAt is the timestamp when the bridge was created
	CreatedAt time.Time

	// UpdatedAt is the timestamp when the bridge was last updated
	UpdatedAt time.Time

	// Status is the operational status of the bridge
	Status BridgeStatus

	// PortCount is the number of ports on the bridge
	PortCount int

	// FlowCount is the number of OpenFlow rules installed
	FlowCount int

	// UUID is the OVS bridge UUID
	UUID string

	// ErrorMessage contains the error message if status is error
	ErrorMessage string
}

// BridgeInfo contains basic bridge information from OVS
type BridgeInfo struct {
	Name         string
	UUID         string
	DatapathType string
	Ports        []string
	Status       map[string]string
}

// BridgeOption is a functional option for bridge creation
type BridgeOption func(*bridgeOptions)

type bridgeOptions struct {
	datapathType string
	failMode     string
	protocols    []string
	externalIDs  map[string]string
	otherConfig  map[string]string
}

// WithDatapathType sets the datapath type for the bridge
func WithDatapathType(datapathType string) BridgeOption {
	return func(o *bridgeOptions) {
		o.datapathType = datapathType
	}
}

// WithFailMode sets the fail mode for the bridge
func WithFailMode(failMode string) BridgeOption {
	return func(o *bridgeOptions) {
		o.failMode = failMode
	}
}

// WithProtocols sets the OpenFlow protocols for the bridge
func WithProtocols(protocols []string) BridgeOption {
	return func(o *bridgeOptions) {
		o.protocols = protocols
	}
}

// WithExternalIDs sets external IDs for the bridge
func WithExternalIDs(ids map[string]string) BridgeOption {
	return func(o *bridgeOptions) {
		o.externalIDs = ids
	}
}

// WithOtherConfig sets other config for the bridge
func WithOtherConfig(config map[string]string) BridgeOption {
	return func(o *bridgeOptions) {
		o.otherConfig = config
	}
}

// OVSClient interface abstracts OVS operations for bridge management
type OVSClient interface {
	// CreateBridge creates a new OVS bridge
	CreateBridge(ctx context.Context, name string) error

	// DeleteBridge deletes an OVS bridge
	DeleteBridge(ctx context.Context, name string) error

	// GetBridge retrieves bridge information
	GetBridge(ctx context.Context, name string) (*BridgeInfo, error)

	// ListBridges returns all bridge names
	ListBridges(ctx context.Context) ([]string, error)

	// SetBridgeDatapath sets the datapath type for a bridge
	SetBridgeDatapath(ctx context.Context, name string, datapathType string) error

	// SetBridgeFailMode sets the fail mode for a bridge
	SetBridgeFailMode(ctx context.Context, name string, failMode string) error

	// SetBridgeProtocols sets the OpenFlow protocols for a bridge
	SetBridgeProtocols(ctx context.Context, name string, protocols []string) error

	// AddPort adds a port to a bridge
	AddPort(ctx context.Context, bridgeName, portName string) error

	// DeletePort removes a port from a bridge
	DeletePort(ctx context.Context, bridgeName, portName string) error

	// ListPorts returns all ports on a bridge
	ListPorts(ctx context.Context, bridgeName string) ([]string, error)

	// SetPortVLAN sets the VLAN tag for a port
	SetPortVLAN(ctx context.Context, portName string, tag uint16) error
}

// OpenFlowClient interface abstracts OpenFlow operations for flow management
type OpenFlowClient interface {
	// AddFlow adds an OpenFlow rule to a bridge
	AddFlow(ctx context.Context, bridge string, flow *Flow) error

	// DeleteFlows deletes OpenFlow rules matching the criteria
	DeleteFlows(ctx context.Context, bridge string, match *FlowMatch) error

	// GetFlows retrieves all flows from a bridge
	GetFlows(ctx context.Context, bridge string) ([]*Flow, error)

	// DeleteAllFlows removes all flows from a bridge
	DeleteAllFlows(ctx context.Context, bridge string) error
}

// Flow represents an OpenFlow rule
type Flow struct {
	// Table is the flow table number
	Table uint8

	// Priority is the flow priority (higher = more important)
	Priority uint16

	// Match specifies the matching criteria
	Match FlowMatch

	// Actions specifies the actions to perform
	Actions []Action

	// Cookie is an opaque identifier for the flow
	Cookie uint64

	// IdleTimeout is the idle timeout in seconds (0 = no timeout)
	IdleTimeout uint16

	// HardTimeout is the hard timeout in seconds (0 = no timeout)
	HardTimeout uint16
}

// FlowMatch represents OpenFlow match criteria
type FlowMatch struct {
	// InPort matches the input port
	InPort *uint32

	// VLAN matches the VLAN ID
	VLAN *uint16

	// EthSrc matches the source MAC address
	EthSrc *string

	// EthDst matches the destination MAC address
	EthDst *string

	// EthType matches the Ethernet type
	EthType *uint16

	// IPProto matches the IP protocol
	IPProto *uint8

	// IPv4Src matches the source IPv4 address
	IPv4Src *string

	// IPv4Dst matches the destination IPv4 address
	IPv4Dst *string

	// TCPSrc matches the TCP source port
	TCPSrc *uint16

	// TCPDst matches the TCP destination port
	TCPDst *uint16

	// UDPSrc matches the UDP source port
	UDPSrc *uint16

	// UDPDst matches the UDP destination port
	UDPDst *uint16
}

// IsEmpty returns true if no match criteria are specified
func (m FlowMatch) IsEmpty() bool {
	return m.InPort == nil && m.VLAN == nil && m.EthSrc == nil &&
		m.EthDst == nil && m.EthType == nil && m.IPProto == nil &&
		m.IPv4Src == nil && m.IPv4Dst == nil && m.TCPSrc == nil &&
		m.TCPDst == nil && m.UDPSrc == nil && m.UDPDst == nil
}

// ActionType represents the type of OpenFlow action
type ActionType string

const (
	// ActionOutput outputs the packet to a port
	ActionOutput ActionType = "output"

	// ActionDrop drops the packet
	ActionDrop ActionType = "drop"

	// ActionSetVLAN sets the VLAN ID
	ActionSetVLAN ActionType = "set_vlan"

	// ActionPopVLAN removes the VLAN tag
	ActionPopVLAN ActionType = "pop_vlan"

	// ActionPushVLAN adds a VLAN tag
	ActionPushVLAN ActionType = "push_vlan"

	// ActionGotoTable jumps to another table
	ActionGotoTable ActionType = "goto_table"

	// ActionSetField sets a field value
	ActionSetField ActionType = "set_field"

	// ActionNormal performs normal L2/L3 forwarding
	ActionNormal ActionType = "normal"

	// ActionFlood floods to all ports except input
	ActionFlood ActionType = "flood"

	// ActionController sends to controller
	ActionController ActionType = "controller"
)

// Action represents an OpenFlow action
type Action struct {
	// Type is the action type
	Type ActionType

	// Port is the output port (for ActionOutput)
	Port uint32

	// VLAN is the VLAN ID (for ActionSetVLAN, ActionPushVLAN)
	VLAN uint16

	// Table is the destination table (for ActionGotoTable)
	Table uint8

	// Field is the field name (for ActionSetField)
	Field string

	// Value is the field value (for ActionSetField)
	Value string
}

// Special port numbers for OpenFlow
const (
	// PortMax is the maximum physical port number
	PortMax uint32 = 0xffffff00

	// PortInPort outputs to the input port
	PortInPort uint32 = 0xfffffff8

	// PortTable submits to first flow table
	PortTable uint32 = 0xfffffff9

	// PortNormal performs normal L2/L3 forwarding
	PortNormal uint32 = 0xfffffffa

	// PortFlood floods to all ports except input
	PortFlood uint32 = 0xfffffffb

	// PortAll outputs to all ports except input
	PortAll uint32 = 0xfffffffc

	// PortController sends to controller
	PortController uint32 = 0xfffffffd

	// PortLocal is the local port
	PortLocal uint32 = 0xfffffffe

	// PortAny matches any port
	PortAny uint32 = 0xffffffff
)

// Common Ethernet types
const (
	EthTypeIPv4 uint16 = 0x0800
	EthTypeARP  uint16 = 0x0806
	EthTypeVLAN uint16 = 0x8100
	EthTypeIPv6 uint16 = 0x86DD
)

// Common IP protocols
const (
	IPProtoICMP uint8 = 1
	IPProtoTCP  uint8 = 6
	IPProtoUDP  uint8 = 17
)

// Flow table numbers for tenant bridges
const (
	// TableIngress is the ingress classification table
	TableIngress uint8 = 0

	// TableVLANValidation is the VLAN validation table
	TableVLANValidation uint8 = 1

	// TableForwarding is the forwarding table
	TableForwarding uint8 = 2

	// TableEgress is the egress processing table
	TableEgress uint8 = 3
)

// LifecycleEvent represents a tenant lifecycle event
type LifecycleEvent string

const (
	// EventCreate is triggered when a tenant is created
	EventCreate LifecycleEvent = "create"

	// EventActivate is triggered when a tenant becomes active
	EventActivate LifecycleEvent = "activate"

	// EventSuspend is triggered when a tenant is suspended
	EventSuspend LifecycleEvent = "suspend"

	// EventResume is triggered when a tenant is resumed
	EventResume LifecycleEvent = "resume"

	// EventDelete is triggered when a tenant is deleted
	EventDelete LifecycleEvent = "delete"
)
