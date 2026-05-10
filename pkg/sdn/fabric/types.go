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

package fabric

// FabricMode defines the operating mode of the physical switch fabric.
type FabricMode string

const (
	// ModeVLAN uses traditional VLAN-based segmentation.
	ModeVLAN FabricMode = "vlan"

	// ModeEVPN uses EVPN-VXLAN overlay with VTEP and VNI mappings.
	ModeEVPN FabricMode = "evpn"
)

// SegmentRole classifies the purpose of a network segment for port
// lifecycle operations.
type SegmentRole string

const (
	// RoleProvisioning is used for PXE boot and initial node setup.
	RoleProvisioning SegmentRole = "provisioning"

	// RoleQuarantine is used for isolating untrusted or failed nodes.
	RoleQuarantine SegmentRole = "quarantine"

	// RoleNone indicates no special role; used for production segments.
	RoleNone SegmentRole = ""
)

// PortRef identifies a specific switch port, optionally associated with
// a LAG group.
type PortRef struct {
	// SwitchID identifies the switch this port belongs to.
	SwitchID string `yaml:"switch-id" json:"switch_id" mapstructure:"switch-id"`

	// Port is the interface name (e.g., "Ethernet1/1").
	Port string `yaml:"port" json:"port" mapstructure:"port"`

	// LAGID optionally associates this port with a LAG group.
	LAGID string `yaml:"lag-id,omitempty" json:"lag_id,omitempty" mapstructure:"lag-id"`
}

// Validate checks that the port reference has all required fields.
func (p PortRef) Validate() error {
	if p.SwitchID == "" {
		return ErrInvalidPortRef{Reason: "switch-id is required"}
	}
	if p.Port == "" {
		return ErrInvalidPortRef{Reason: "port is required"}
	}
	return nil
}

// Segment is the resolved runtime representation of a segment, including
// the computed VNI when operating in EVPN mode.
type Segment struct {
	// Name is the unique segment name.
	Name string

	// VLAN is the 802.1Q VLAN identifier.
	VLAN uint16

	// VNI is the VXLAN Network Identifier, computed from the EVPN VNI base
	// plus the VLAN ID. Zero in VLAN-only mode.
	VNI uint32

	// CIDR is the IP network prefix for this segment.
	CIDR string

	// Gateway is the default gateway IP address.
	Gateway string

	// DNS holds the DNS server addresses for the segment.
	DNS []string

	// DHCP controls whether DHCP is served on this segment.
	DHCP bool

	// Role classifies the segment for port lifecycle operations.
	Role SegmentRole
}

// SwitchStatus represents the health state of a fabric switch.
type SwitchStatus struct {
	// ID is the switch identifier from configuration.
	ID string `json:"id"`

	// Connected indicates whether the driver has an active connection.
	Connected bool `json:"connected"`

	// Vendor is the switch vendor string.
	Vendor string `json:"vendor"`

	// Model is the switch model string.
	Model string `json:"model"`

	// MgmtIP is the management IP address.
	MgmtIP string `json:"mgmt_ip"`
}
