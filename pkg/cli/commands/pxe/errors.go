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

package pxe

import "fmt"

// ErrDeviceIDRequired is returned when a verb that names one device is given
// an empty device ID.
// minTargetVLAN and maxTargetVLAN bound --target-vlan: 802.1Q VLAN IDs
// 0 and 4095 are reserved.
const (
	minTargetVLAN = 1
	maxTargetVLAN = 4094
)

// ErrInvalidTargetVLAN reports a missing or out-of-range --target-vlan.
type ErrInvalidTargetVLAN struct {
	Value uint32
}

func (e *ErrInvalidTargetVLAN) Error() string {
	if e.Value == 0 {
		return "--target-vlan is required (1-4094)"
	}
	return fmt.Sprintf("--target-vlan %d is out of range (1-4094)", e.Value)
}

// ErrInvalidVLANFilter is a list --vlan outside 1-4094. The daemon narrows
// the filter VLAN to 16 bits, so an unchecked 65556 would select VLAN 20 and
// 65536 would drop the filter.
type ErrInvalidVLANFilter struct {
	Value uint32
}

func (e *ErrInvalidVLANFilter) Error() string {
	return fmt.Sprintf("--vlan %d is out of range (1-4094)", e.Value)
}

type ErrDeviceIDRequired struct {
	Verb string
}

func (e *ErrDeviceIDRequired) Error() string {
	return fmt.Sprintf("pxe %s: a device ID is required", e.Verb)
}

// ErrReasonRequired is returned when quarantine is run without --reason: a
// quarantine is recorded in the device's audit trail and must say why.
type ErrReasonRequired struct{}

func (e *ErrReasonRequired) Error() string {
	return "pxe quarantine: --reason is required"
}

// ErrInvalidState is returned when --state names no provisioning state.
type ErrInvalidState struct {
	Value string
	Valid []string
}

func (e *ErrInvalidState) Error() string {
	return fmt.Sprintf("pxe list: unknown --state %q (valid: %v)", e.Value, e.Valid)
}

// ErrRPCFailed wraps a failed PXE service call.
type ErrRPCFailed struct {
	RPC   string
	Cause error
}

func (e *ErrRPCFailed) Error() string {
	return fmt.Sprintf("pxe %s failed: %v", e.RPC, e.Cause)
}

func (e *ErrRPCFailed) Unwrap() error { return e.Cause }
