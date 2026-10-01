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

package netplan

import (
	"fmt"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ErrEnvironmentID is returned when the environment number is outside
// MinEnvironment–MaxEnvironment.
type ErrEnvironmentID struct {
	// ID is the offending environment number.
	ID uint16
}

// Error implements the error interface.
func (e ErrEnvironmentID) Error() string {
	return fmt.Sprintf("netplan: environment %d is outside %d-%d (VLANs 1-199 belong to the site)",
		e.ID, MinEnvironment, MaxEnvironment)
}

// ErrBase is returned when the IPv4 address base is not a masked IPv4 /8.
type ErrBase struct {
	// Base is the offending prefix.
	Base netip.Prefix
}

// Error implements the error interface.
func (e ErrBase) Error() string {
	return fmt.Sprintf("netplan: base %s must be an IPv4 /8 (for example 10.0.0.0/8)", e.Base)
}

// ErrULA is returned when the deployment ULA prefix is not a masked /48
// inside fd00::/8 (RFC 4193).
type ErrULA struct {
	// ULA is the offending prefix.
	ULA netip.Prefix
}

// Error implements the error interface.
func (e ErrULA) Error() string {
	return fmt.Sprintf("netplan: ula %s must be a /48 inside fd00::/8 (RFC 4193)", e.ULA)
}

// ErrVLANOutOfRange is returned when a derived or overridden VLAN ID is not
// a valid IEEE 802.1Q ID (1-4094).
type ErrVLANOutOfRange struct {
	// Zone is the zone the VLAN belongs to; empty for a bare derivation.
	Zone zone.Zone
	// VLAN is the offending ID.
	VLAN uint32
}

// Error implements the error interface.
func (e ErrVLANOutOfRange) Error() string {
	if e.Zone == "" {
		return fmt.Sprintf("netplan: VLAN %d is outside 1-4094", e.VLAN)
	}
	return fmt.Sprintf("netplan: zone %q: VLAN %d is outside 1-4094", e.Zone, e.VLAN)
}

// ErrOffset is returned when a zone offset is outside 0-99.
type ErrOffset struct {
	// Offset is the offending offset.
	Offset zone.Offset
}

// Error implements the error interface.
func (e ErrOffset) Error() string {
	return fmt.Sprintf("netplan: offset %d is outside 0-%d", e.Offset, zone.MaxOffset)
}

// ErrVNIOutOfRange is returned when an overlay network number is outside
// 1-MaxNetworksPerEnvironment.
type ErrVNIOutOfRange struct {
	// Network is the offending overlay network number.
	Network uint32
}

// Error implements the error interface.
func (e ErrVNIOutOfRange) Error() string {
	return fmt.Sprintf("netplan: overlay network %d is outside 1-%d", e.Network, MaxNetworksPerEnvironment)
}

// ErrOverride is returned when an Override entry is malformed.
type ErrOverride struct {
	// Zone is the zone the override names.
	Zone zone.Zone
	// Reason says what is wrong with it.
	Reason string
}

// Error implements the error interface.
func (e ErrOverride) Error() string {
	return fmt.Sprintf("netplan: override for zone %q: %s", e.Zone, e.Reason)
}

// ErrDuplicateVLAN is returned when two zones end up on the same VLAN.
type ErrDuplicateVLAN struct {
	// VLAN is the shared ID.
	VLAN uint16
	// Zones are the two zones that claim it.
	Zones [2]zone.Zone
}

// Error implements the error interface.
func (e ErrDuplicateVLAN) Error() string {
	return fmt.Sprintf("netplan: zones %q and %q are both on VLAN %d", e.Zones[0], e.Zones[1], e.VLAN)
}

// ErrOverlap is returned when a zone subnet overlaps another zone's subnet,
// the IPAM pool or a reserved range.
type ErrOverlap struct {
	// Zone is the zone whose subnet overlaps.
	Zone zone.Zone
	// Subnet is that zone's subnet.
	Subnet netip.Prefix
	// Other names what it overlaps.
	Other string
}

// Error implements the error interface.
func (e ErrOverlap) Error() string {
	return fmt.Sprintf("netplan: zone %q subnet %s overlaps %s", e.Zone, e.Subnet, e.Other)
}

// ErrUnknownZone is returned when a lookup names a zone the plan does not
// hold.
type ErrUnknownZone struct {
	// Zone is the unknown name.
	Zone zone.Zone
}

// Error implements the error interface.
func (e ErrUnknownZone) Error() string {
	return fmt.Sprintf("netplan: zone %q is not in the plan", e.Zone)
}

// ErrHostNumber is returned when a host number does not fit its subnet or
// falls outside the reference band for its role.
type ErrHostNumber struct {
	// Prefix is the subnet.
	Prefix netip.Prefix
	// Host is the offending host number.
	Host uint32
}

// Error implements the error interface.
func (e ErrHostNumber) Error() string {
	return fmt.Sprintf("netplan: host .%d does not fit %s", e.Host, e.Prefix)
}

// ErrUnknownPortClass is returned for a port class the plan does not know.
type ErrUnknownPortClass struct {
	// Class is the unknown class.
	Class zone.PortClass
}

// Error implements the error interface.
func (e ErrUnknownPortClass) Error() string {
	return fmt.Sprintf("netplan: unknown port class %q", e.Class)
}

// ErrEmptyPortClass is returned when no zone in the plan is carried by a
// port class, so the class has no VLAN to carry (for example the BMC class
// with the management zone omitted).
type ErrEmptyPortClass struct {
	// Class is the empty class.
	Class zone.PortClass
}

// Error implements the error interface.
func (e ErrEmptyPortClass) Error() string {
	return fmt.Sprintf("netplan: port class %q carries no zone in this plan", e.Class)
}
