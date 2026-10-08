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

// Package vxlan owns the local VTEP of the SDN overlay: the one flow-based
// VXLAN port a host carries (remote_ip=flow, key=flow), the overlay MTU,
// and VNI-to-VLAN mapping. Which remote VTEP and VNI a frame travels to is
// decided per flow (tun_dst, tun_id) by the overlay data plane, never by
// a port per tunnel.
package vxlan

import (
	"net/netip"
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

// VXLANOverhead is the number of bytes added by VXLAN encapsulation
// (14 outer Ethernet + 20 IPv4 + 8 UDP + 8 VXLAN).
const VXLANOverhead = 50

// OverlayMTU is the MTU every overlay segment carries: jumbo frames end to
// end, so a workload never has to fragment for the tunnel.
const OverlayMTU = 9000

// MinimumUnderlayMTU is the smallest underlay MTU that carries an
// OverlayMTU frame once encapsulated.
const MinimumUnderlayMTU = OverlayMTU + VXLANOverhead

// DefaultPortName is the name of the one flow-based VXLAN port a VTEP
// owns on its bridge. It fits the 15-byte Linux interface name limit.
const DefaultPortName = "vxlan-evpn"

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

	// UnderlayMTU is the MTU of the underlay network. It must be at least
	// MinimumUnderlayMTU (9050) to carry OverlayMTU frames; platform switch
	// ports run 9216.
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
	if c.UnderlayMTU < MinimumUnderlayMTU {
		return ErrMTUTooSmall
	}
	if c.VXLANPort == 0 {
		return ErrInvalidVXLANPort
	}
	return nil
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
