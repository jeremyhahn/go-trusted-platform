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
	"net"
	"net/netip"
	"time"
)

// VTEPStatus represents the operational status of a VTEP.
type VTEPStatus uint8

const (
	// VTEPStatusUnknown indicates the VTEP status is unknown.
	VTEPStatusUnknown VTEPStatus = iota

	// VTEPStatusActive indicates the VTEP is operational.
	VTEPStatusActive

	// VTEPStatusDegraded indicates the VTEP is partially operational.
	VTEPStatusDegraded

	// VTEPStatusDown indicates the VTEP is not operational.
	VTEPStatusDown
)

// String returns the string representation of the VTEP status.
func (s VTEPStatus) String() string {
	switch s {
	case VTEPStatusActive:
		return "active"
	case VTEPStatusDegraded:
		return "degraded"
	case VTEPStatusDown:
		return "down"
	default:
		return "unknown"
	}
}

// TunnelStatus represents the operational status of a VXLAN tunnel.
type TunnelStatus uint8

const (
	// TunnelStatusUnknown indicates the tunnel status is unknown.
	TunnelStatusUnknown TunnelStatus = iota

	// TunnelStatusUp indicates the tunnel is operational.
	TunnelStatusUp

	// TunnelStatusDown indicates the tunnel is not operational.
	TunnelStatusDown

	// TunnelStatusError indicates the tunnel has an error.
	TunnelStatusError
)

// String returns the string representation of the tunnel status.
func (s TunnelStatus) String() string {
	switch s {
	case TunnelStatusUp:
		return "up"
	case TunnelStatusDown:
		return "down"
	case TunnelStatusError:
		return "error"
	default:
		return "unknown"
	}
}

// VTEPState represents a VXLAN Tunnel Endpoint in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/vteps/{id}
type VTEPState struct {
	// ID is the unique identifier for this VTEP (hash of IP)
	ID string `json:"id"`

	// NodeID is the cluster node that owns this VTEP
	NodeID uint64 `json:"node_id"`

	// IP is the VTEP IP address
	IP netip.Addr `json:"ip"`

	// UnderlayIface is the physical interface name for the underlay network
	UnderlayIface string `json:"underlay_iface"`

	// UnderlayMTU is the MTU of the underlay interface
	UnderlayMTU int `json:"underlay_mtu"`

	// VXLANPort is the UDP port for VXLAN traffic
	VXLANPort uint16 `json:"vxlan_port"`

	// Status is the operational status of the VTEP
	Status VTEPStatus `json:"status"`

	// Tunnels contains the IDs of tunnels originating from this VTEP
	Tunnels []string `json:"tunnels"`

	// ExternalIDs are user-defined metadata tags
	ExternalIDs map[string]string `json:"external_ids,omitempty"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this VTEP was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the entity ID for QuicBaaS storage (hash of VTEP ID)
func (v *VTEPState) EntityID() uint64 {
	return hashString(v.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use ID-based hashing instead
func (v *VTEPState) SetEntityID(id uint64) {
	// No-op: entity ID is derived from VTEP ID
}

// TunnelStats contains traffic statistics for a tunnel.
type TunnelStats struct {
	// BytesSent is the number of bytes sent through the tunnel
	BytesSent uint64 `json:"bytes_sent"`

	// BytesRecv is the number of bytes received through the tunnel
	BytesRecv uint64 `json:"bytes_recv"`

	// PacketsSent is the number of packets sent through the tunnel
	PacketsSent uint64 `json:"packets_sent"`

	// PacketsRecv is the number of packets received through the tunnel
	PacketsRecv uint64 `json:"packets_recv"`

	// LastUpdated is the timestamp of the last statistics update
	LastUpdated time.Time `json:"last_updated"`
}

// TunnelState represents a VXLAN tunnel between two VTEPs in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/tunnels/{id}
type TunnelState struct {
	// ID is the unique identifier for this tunnel
	ID string `json:"id"`

	// LocalVTEP is the ID of the local VTEP
	LocalVTEP string `json:"local_vtep"`

	// RemoteVTEP is the ID of the remote VTEP
	RemoteVTEP string `json:"remote_vtep"`

	// LocalIP is the local tunnel endpoint IP address
	LocalIP netip.Addr `json:"local_ip"`

	// RemoteIP is the remote tunnel endpoint IP address
	RemoteIP netip.Addr `json:"remote_ip"`

	// VNI is the VXLAN Network Identifier
	VNI uint32 `json:"vni"`

	// OVSPort is the OVS port name for this tunnel
	OVSPort string `json:"ovs_port"`

	// OFPort is the OpenFlow port number
	OFPort int32 `json:"of_port"`

	// Status is the operational status of the tunnel
	Status TunnelStatus `json:"status"`

	// NodeID is the cluster node that owns this tunnel
	NodeID uint64 `json:"node_id"`

	// ExternalIDs are user-defined metadata tags
	ExternalIDs map[string]string `json:"external_ids,omitempty"`

	// Stats contains traffic statistics
	Stats TunnelStats `json:"stats"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this tunnel was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the entity ID for QuicBaaS storage (hash of tunnel ID)
func (t *TunnelState) EntityID() uint64 {
	return hashString(t.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use ID-based hashing instead
func (t *TunnelState) SetEntityID(id uint64) {
	// No-op: entity ID is derived from tunnel ID
}

// VNIMappingState represents a VNI to VLAN mapping in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/vni-mappings/{vni}
type VNIMappingState struct {
	// VNI is the VXLAN Network Identifier (primary key)
	VNI uint32 `json:"vni"`

	// VLAN is the local VLAN ID mapped to this VNI
	VLAN uint16 `json:"vlan"`

	// BridgeID is the ID of the associated bridge
	BridgeID string `json:"bridge_id"`

	// TenantID is an optional tenant identifier for isolation
	TenantID string `json:"tenant_id,omitempty"`

	// Description provides a human-readable description
	Description string `json:"description,omitempty"`

	// ExternalIDs are user-defined metadata tags
	ExternalIDs map[string]string `json:"external_ids,omitempty"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// CreatedAt is the timestamp when this mapping was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the entity ID for QuicBaaS storage (VNI as uint64)
func (m *VNIMappingState) EntityID() uint64 {
	return uint64(m.VNI)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use VNI directly
func (m *VNIMappingState) SetEntityID(id uint64) {
	// No-op: entity ID is the VNI
}

// MACLearnSource indicates how a MAC address was learned.
type MACLearnSource string

const (
	// MACLearnSourceEVPN indicates the MAC was learned via EVPN.
	MACLearnSourceEVPN MACLearnSource = "evpn"

	// MACLearnSourceDataplane indicates the MAC was learned from the dataplane.
	MACLearnSourceDataplane MACLearnSource = "dataplane"

	// MACLearnSourceStatic indicates the MAC was statically configured.
	MACLearnSourceStatic MACLearnSource = "static"
)

// RemoteMACState represents a MAC address learned from a remote VTEP in the cluster-replicated state.
// This type is stored in QuicBaaS at path: /sdn/remote-macs/{id}
type RemoteMACState struct {
	// ID is the unique identifier (hash of MAC+VNI)
	ID string `json:"id"`

	// MAC is the hardware address
	MAC net.HardwareAddr `json:"mac"`

	// VNI is the VXLAN Network Identifier
	VNI uint32 `json:"vni"`

	// RemoteVTEP is the ID of the remote VTEP
	RemoteVTEP string `json:"remote_vtep"`

	// RemoteIP is the IP address of the remote VTEP
	RemoteIP netip.Addr `json:"remote_ip"`

	// LearnedFrom indicates the source of the MAC learning
	LearnedFrom MACLearnSource `json:"learned_from"`

	// NodeID is the cluster node that owns this entry
	NodeID uint64 `json:"node_id"`

	// ExternalIDs are user-defined metadata tags
	ExternalIDs map[string]string `json:"external_ids,omitempty"`

	// Version is used for optimistic locking and conflict detection
	Version uint64 `json:"version"`

	// LearnedAt is the timestamp when this MAC was learned
	LearnedAt time.Time `json:"learned_at"`

	// ExpiresAt is the timestamp when this entry expires (zero = never)
	ExpiresAt time.Time `json:"expires_at"`
}

// EntityID returns the entity ID for QuicBaaS storage (hash of remote MAC ID)
func (r *RemoteMACState) EntityID() uint64 {
	return hashString(r.ID)
}

// SetEntityID is required by the GenericDAO interface but is a no-op
// as we use ID-based hashing instead
func (r *RemoteMACState) SetEntityID(id uint64) {
	// No-op: entity ID is derived from remote MAC ID
}

// IsExpired returns true if the remote MAC entry has expired.
func (r *RemoteMACState) IsExpired() bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(r.ExpiresAt)
}
