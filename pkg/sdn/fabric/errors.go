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

// Package fabric manages physical switch fabric for VLAN/VNI provisioning
// and port lifecycle on Cisco Nexus and compatible switches.
package fabric

import "fmt"

// ErrUnknownSegment is returned when a segment name cannot be resolved.
type ErrUnknownSegment struct {
	Name string
}

func (e ErrUnknownSegment) Error() string {
	return fmt.Sprintf("fabric: unknown segment %q", e.Name)
}

// ErrUnknownSwitch is returned when a switch ID cannot be found.
type ErrUnknownSwitch struct {
	ID string
}

func (e ErrUnknownSwitch) Error() string {
	return fmt.Sprintf("fabric: unknown switch %q", e.ID)
}

// ErrDuplicateVLAN is returned when two segments share the same VLAN ID.
type ErrDuplicateVLAN struct {
	VLAN     uint16
	Segment1 string
	Segment2 string
}

func (e ErrDuplicateVLAN) Error() string {
	return fmt.Sprintf("fabric: duplicate vlan %d in segments %q and %q", e.VLAN, e.Segment1, e.Segment2)
}

// ErrInvalidPortRef is returned when a port reference is malformed.
type ErrInvalidPortRef struct {
	Reason string
}

func (e ErrInvalidPortRef) Error() string {
	return fmt.Sprintf("fabric: invalid port reference: %s", e.Reason)
}

// ErrDriverConnect is returned when a switch driver fails to connect.
type ErrDriverConnect struct {
	SwitchID string
	Cause    error
}

func (e ErrDriverConnect) Error() string {
	return fmt.Sprintf("fabric: driver connect failed for switch %q: %s", e.SwitchID, e.Cause)
}

func (e ErrDriverConnect) Unwrap() error {
	return e.Cause
}

// ErrSegmentRoleMismatch is returned when a port operation targets a
// segment with an incompatible role.
type ErrSegmentRoleMismatch struct {
	Segment  string
	Expected SegmentRole
	Got      SegmentRole
}

func (e ErrSegmentRoleMismatch) Error() string {
	return fmt.Sprintf("fabric: segment %q role mismatch: expected %s, got %s", e.Segment, e.Expected, e.Got)
}

// ErrInvalidFabricConfig is returned when the fabric configuration is invalid.
type ErrInvalidFabricConfig struct {
	Reason string
}

func (e ErrInvalidFabricConfig) Error() string {
	return fmt.Sprintf("fabric: invalid config: %s", e.Reason)
}

// ErrDriverNotFound is returned when no driver factory is registered for a vendor.
type ErrDriverNotFound struct {
	Vendor string
}

func (e ErrDriverNotFound) Error() string {
	return fmt.Sprintf("fabric: no driver registered for vendor %q", e.Vendor)
}

// ErrDriverOperation is returned when a driver operation fails.
type ErrDriverOperation struct {
	SwitchID  string
	Operation string
	Cause     error
}

func (e ErrDriverOperation) Error() string {
	return fmt.Sprintf("fabric: %s failed on switch %q: %s", e.Operation, e.SwitchID, e.Cause)
}

func (e ErrDriverOperation) Unwrap() error {
	return e.Cause
}

// ErrNilConfig is returned when a nil configuration is provided.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "fabric: nil config"
}
