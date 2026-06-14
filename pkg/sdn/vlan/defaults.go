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

// Package vlan provides canonical VLAN segment-ID defaults and validation for
// the platform's zone-based network model. VLAN numbers are plain L2 segment
// identifiers; the security meaning is carried by the zone, not the number.
// All values here are defaults — everything is configurable. Defaults follow
// the mnemonic VLAN N → 172.16.N.0/24 where applicable.
//
// See docs/architecture/reference-network.md for the authoritative assignment
// table and zone taxonomy.
package vlan

import "fmt"

// Default segment IDs for the well-known zone subnets. All values are
// configurable; these are the defaults documented in the reference network
// architecture (docs/architecture/reference-network.md).
const (
	// DefaultTrusted is the default VLAN for the trusted zone (internal,
	// enrolled, attested). Subnet default: 198.18.0.0/24.
	DefaultTrusted = uint16(200)

	// DefaultProvisioning is the default VLAN for the provisioning zone
	// (onboarding / pre-trust). Subnet default: 172.16.201.0/24.
	DefaultProvisioning = uint16(201)

	// DefaultQuarantine is the default VLAN for the quarantine zone (untrusted
	// or compliance-failed devices). Subnet default: 172.16.202.0/24.
	DefaultQuarantine = uint16(202)

	// DefaultStorage is the default VLAN for the storage zone (attested, high-
	// bandwidth, isolated). Subnet default: 172.16.203.0/24.
	DefaultStorage = uint16(203)

	// DefaultManagement is the default VLAN for the management zone (out-of-band
	// IPMI/BMC; never routes to a data zone). VLAN 50 has no mnemonic subnet.
	DefaultManagement = uint16(50)

	// DefaultTransit is the default VLAN for transit links (gateway ↔
	// upstream/BGP point-to-point /31s). Subnet default: 172.16.0.0/24.
	DefaultTransit = uint16(10)

	// DefaultNative is the IEEE 802.1Q default VLAN (catch-all for untagged
	// traffic on a trunk). Devices connect here before classification.
	DefaultNative = uint16(1)

	// TenantBase is the lowest VLAN ID reserved for per-tenant micro-zones.
	// Tenant VLANs are allocated from TenantBase upward (up to MaxVLAN).
	TenantBase = uint16(1000)

	// MinVLAN is the minimum valid VLAN ID per IEEE 802.1Q.
	MinVLAN = uint16(1)

	// MaxVLAN is the maximum valid VLAN ID per IEEE 802.1Q.
	MaxVLAN = uint16(4094)
)

// ErrInvalidVLAN is returned by Validate when id is outside [MinVLAN, MaxVLAN].
type ErrInvalidVLAN struct {
	ID uint16
}

// Error implements the error interface.
func (e ErrInvalidVLAN) Error() string {
	return fmt.Sprintf("vlan: invalid VLAN ID %d: must be between %d and %d", e.ID, MinVLAN, MaxVLAN)
}

// Validate returns ErrInvalidVLAN if id is outside the IEEE 802.1Q range
// [1, 4094]. A zero value is rejected because it is not a legal on-wire tag.
func Validate(id uint16) error {
	if id < MinVLAN || id > MaxVLAN {
		return ErrInvalidVLAN{ID: id}
	}
	return nil
}

// ValidateTenantOffset returns ErrInvalidVLAN if TenantBase+offset exceeds
// MaxVLAN. Callers that allocate tenant VLANs sequentially from TenantBase
// should call this before assigning a new tenant slot.
func ValidateTenantOffset(offset uint16) error {
	id := TenantBase + offset
	if id > MaxVLAN {
		return ErrInvalidVLAN{ID: id}
	}
	return nil
}
