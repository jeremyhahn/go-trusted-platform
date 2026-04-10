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

// Package vxlan provides VXLAN tunnel management for SDN overlay networking.
// It handles VTEP lifecycle management, VNI-to-VLAN mapping, and tunnel
// operations for multi-host VXLAN networking.
package vxlan

import (
	"net"
	"net/netip"
	"time"
)

// VNI represents a VXLAN Network Identifier.
// VNIs are 24-bit identifiers with valid range 1-16777215.
type VNI uint32

// MinVNI is the minimum valid VNI value.
const MinVNI VNI = 1

// MaxVNI is the maximum valid VNI value (2^24 - 1).
const MaxVNI VNI = 16777215

// DefaultVXLANPort is the standard IANA-assigned UDP port for VXLAN.
const DefaultVXLANPort uint16 = 4789

// DefaultBaseVNI is the default base VNI for VLAN-to-VNI mapping.
const DefaultBaseVNI VNI = 1000000

// MinimumMTU is the minimum MTU required for VXLAN encapsulation.
// VXLAN adds 50 bytes of overhead (14 outer Eth + 20 IP + 8 UDP + 8 VXLAN).
const MinimumMTU = 1550

// VXLANOverhead is the number of bytes added by VXLAN encapsulation.
const VXLANOverhead = 50

// Valid returns true if the VNI is within the valid range.
func (v VNI) Valid() bool {
	return v >= MinVNI && v <= MaxVNI
}

// Uint32 returns the VNI as a uint32.
func (v VNI) Uint32() uint32 {
	return uint32(v)
}

// VTEPConfig holds VTEP (VXLAN Tunnel Endpoint) configuration.
type VTEPConfig struct {
	// LocalIP is the local VTEP IP address used for VXLAN tunnels.
	LocalIP netip.Addr

	// UnderlayIface is the physical interface name for underlay traffic.
	UnderlayIface string

	// UnderlayMTU is the MTU of the underlay network.
	// Should be at least MinimumMTU (1550) for VXLAN to work.
	// Recommended: 9000 for jumbo frames.
	UnderlayMTU int

	// VXLANPort is the UDP destination port for VXLAN traffic.
	// Default: 4789 (IANA standard).
	VXLANPort uint16
}

// Validate checks if the VTEPConfig is valid.
func (c *VTEPConfig) Validate() error {
	if !c.LocalIP.IsValid() {
		return ErrInvalidVTEPIP
	}
	if c.LocalIP.IsUnspecified() {
		return ErrInvalidVTEPIP
	}
	if c.UnderlayIface == "" {
		return ErrUnderlayNotReady
	}
	if c.UnderlayMTU < MinimumMTU {
		return ErrMTUTooSmall
	}
	if c.VXLANPort == 0 {
		return ErrInvalidVXLANPort
	}
	return nil
}

// EffectiveMTU returns the effective MTU for overlay traffic
// after accounting for VXLAN encapsulation overhead.
func (c *VTEPConfig) EffectiveMTU() int {
	return c.UnderlayMTU - VXLANOverhead
}

// TunnelStatus represents the operational state of a VXLAN tunnel.
type TunnelStatus uint8

const (
	// TunnelStatusUnknown indicates the tunnel state is unknown.
	TunnelStatusUnknown TunnelStatus = iota

	// TunnelStatusUp indicates the tunnel is operational.
	TunnelStatusUp

	// TunnelStatusDown indicates the tunnel is not operational.
	TunnelStatusDown

	// TunnelStatusError indicates the tunnel is in an error state.
	TunnelStatusError
)

// String returns a human-readable representation of the tunnel status.
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

// TunnelState represents a VXLAN tunnel to a remote VTEP.
type TunnelState struct {
	// ID is a unique identifier for this tunnel.
	// Format: "{local_vtep}-{remote_vtep}-{vni}"
	ID string

	// LocalVTEP is the local tunnel endpoint IP address.
	LocalVTEP netip.Addr

	// RemoteVTEP is the remote tunnel endpoint IP address.
	RemoteVTEP netip.Addr

	// VNI is the VXLAN Network Identifier for this tunnel.
	VNI VNI

	// OVSPort is the OVS port name for this tunnel.
	// Format: "vxlan-{hash}" or "vxlan-{last_octet}-{vni}"
	OVSPort string

	// OFPort is the OpenFlow port number assigned by OVS.
	OFPort int32

	// State is the current operational state of the tunnel.
	State TunnelStatus

	// CreatedAt is when this tunnel was created.
	CreatedAt time.Time

	// UpdatedAt is when this tunnel was last updated.
	UpdatedAt time.Time

	// BytesSent is the total bytes sent through this tunnel.
	BytesSent uint64

	// BytesRecv is the total bytes received through this tunnel.
	BytesRecv uint64
}

// TunnelStats holds detailed tunnel statistics.
type TunnelStats struct {
	// BytesSent is the total bytes sent through the tunnel.
	BytesSent uint64

	// BytesRecv is the total bytes received through the tunnel.
	BytesRecv uint64

	// PacketsSent is the total packets sent through the tunnel.
	PacketsSent uint64

	// PacketsRecv is the total packets received through the tunnel.
	PacketsRecv uint64

	// ErrorsSent is the total send errors on the tunnel.
	ErrorsSent uint64

	// ErrorsRecv is the total receive errors on the tunnel.
	ErrorsRecv uint64
}

// RemoteMACEntry represents a MAC address learned from a remote VTEP.
type RemoteMACEntry struct {
	// MAC is the hardware address of the remote endpoint.
	MAC net.HardwareAddr

	// VNI is the VXLAN Network Identifier where this MAC was learned.
	VNI VNI

	// RemoteVTEP is the VTEP IP address where this MAC resides.
	RemoteVTEP netip.Addr

	// LearnedAt is when this MAC entry was learned.
	LearnedAt time.Time

	// ExpiresAt is when this MAC entry expires and should be removed.
	ExpiresAt time.Time
}

// IsExpired returns true if the MAC entry has expired.
func (e *RemoteMACEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// VNIMappingConfig holds VNI to VLAN mapping configuration.
type VNIMappingConfig struct {
	// BaseVNI is the base VNI value for VLAN-to-VNI calculation.
	// VNI = BaseVNI + VLAN_ID
	// Default: 1000000
	BaseVNI VNI

	// MaxVLAN is the maximum VLAN ID that can be mapped.
	// Default: 4094 (maximum standard VLAN ID)
	MaxVLAN uint16
}

// DefaultVNIMappingConfig returns the default VNI mapping configuration.
func DefaultVNIMappingConfig() VNIMappingConfig {
	return VNIMappingConfig{
		BaseVNI: DefaultBaseVNI,
		MaxVLAN: 4094,
	}
}

// VXLANPortConfig holds configuration for creating a VXLAN port in OVS.
type VXLANPortConfig struct {
	// RemoteIP is the remote VTEP IP address.
	RemoteIP netip.Addr

	// VNI is the VXLAN Network Identifier.
	// If 0, the tunnel is created with flow-based VNI (key=flow).
	VNI VNI

	// DstPort is the UDP destination port for VXLAN traffic.
	DstPort uint16

	// TOS is the Type of Service value for the outer IP header.
	// 0 means inherit from inner packet.
	TOS uint8

	// TTL is the Time To Live for the outer IP header.
	// 0 means use system default.
	TTL uint8

	// DF controls the Don't Fragment flag on the outer IP header.
	DF bool
}

// Options returns the OVS options map for this VXLAN port configuration.
func (c *VXLANPortConfig) Options() map[string]string {
	opts := make(map[string]string)

	if c.RemoteIP.IsValid() {
		opts["remote_ip"] = c.RemoteIP.String()
	}

	if c.VNI > 0 {
		opts["key"] = string(rune(c.VNI.Uint32()))
	} else {
		opts["key"] = "flow"
	}

	if c.DstPort > 0 {
		opts["dst_port"] = string(rune(c.DstPort))
	}

	if c.TOS > 0 {
		opts["tos"] = string(rune(c.TOS))
	}

	if c.TTL > 0 {
		opts["ttl"] = string(rune(c.TTL))
	}

	if c.DF {
		opts["df_default"] = "true"
	}

	return opts
}
