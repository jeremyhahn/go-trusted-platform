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

// Package switchwire is the platform switch wire contract: the port status
// the switch REST handlers return. The daemon's switch manager (pkg/switch)
// and the SDK switch client import this one definition, so the two cannot
// drift.
package switchwire

// PortMode is the switchport operating mode.
type PortMode string

const (
	// PortModeAccess represents an access-mode switchport.
	PortModeAccess PortMode = "access"

	// PortModeTrunk represents a trunk-mode switchport.
	PortModeTrunk PortMode = "trunk"
)

// PortStatus holds the observable state of a single switch port.
type PortStatus struct {
	Port        string   `json:"port"`
	Mode        PortMode `json:"mode"`
	AccessVLAN  uint16   `json:"access_vlan"`
	TrunkVLANs  []uint16 `json:"trunk_vlans,omitempty"`
	NativeVLAN  uint16   `json:"native_vlan,omitempty"`
	Enabled     bool     `json:"enabled"`
	LinkUp      bool     `json:"link_up"`
	Description string   `json:"description,omitempty"`
}
