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

package netlink

// LinkState represents the operational state of a network link
type LinkState string

const (
	// LinkStateUp indicates the link is up
	LinkStateUp LinkState = "up"
	// LinkStateDown indicates the link is down
	LinkStateDown LinkState = "down"
	// LinkStateUnknown indicates the link state is unknown
	LinkStateUnknown LinkState = "unknown"
)

// LinkInfo contains information about a network link
type LinkInfo struct {
	// Index is the kernel interface index
	Index int
	// Name is the interface name
	Name string
	// Type is the link type (e.g., "tuntap", "bridge", "veth")
	Type string
	// Flags contains link flags (IFF_UP, IFF_BROADCAST, etc.)
	Flags uint32
	// MTU is the Maximum Transmission Unit
	MTU int
	// HardwareAddr is the MAC address
	HardwareAddr string
	// OperState is the operational state
	OperState LinkState
	// Master is the index of the master device (for bridge slaves)
	Master int
}

// TAPInfo contains TAP-specific information
type TAPInfo struct {
	// LinkInfo contains common link information
	LinkInfo
	// Owner is the UID that owns the TAP device
	Owner uint32
	// Group is the GID that owns the TAP device
	Group uint32
	// MultiQueue indicates if multi-queue is enabled
	MultiQueue bool
	// Persist indicates if the device persists without file descriptors
	Persist bool
}

// TAPConfig contains configuration for creating a TAP device
type TAPConfig struct {
	// Name is the interface name (max 15 chars)
	Name string
	// Owner is the UID that should own the TAP device (0 = root)
	Owner uint32
	// Group is the GID that should own the TAP device (0 = root)
	Group uint32
	// MultiQueue enables multi-queue support
	MultiQueue bool
	// Persist makes the device persist without file descriptors
	Persist bool
	// MTU sets the Maximum Transmission Unit (0 = default 1500)
	MTU int
}

// Validate validates the TAP configuration
func (c *TAPConfig) Validate() error {
	if len(c.Name) == 0 {
		return ErrInvalidName("empty name")
	}
	if len(c.Name) > 15 {
		return ErrInvalidName("name too long (max 15 characters)")
	}
	return nil
}
