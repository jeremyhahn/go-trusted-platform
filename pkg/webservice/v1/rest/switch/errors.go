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

// Package switchapi provides REST handlers for physical switch management.
package switchapi

import "fmt"

// ErrMissingSwitchName is returned when the switch name path parameter is missing.
type ErrMissingSwitchName struct{}

func (e ErrMissingSwitchName) Error() string {
	return "switchapi: switch name is required"
}

// ErrMissingPortName is returned when the port name path parameter is missing.
type ErrMissingPortName struct{}

func (e ErrMissingPortName) Error() string {
	return "switchapi: port name is required"
}

// ErrInvalidRequestBody is returned when the request body cannot be decoded.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("switchapi: invalid request body: %s", e.Reason)
}

// ErrMissingVLANID is returned when the VLAN ID is missing from the request body.
type ErrMissingVLANID struct{}

func (e ErrMissingVLANID) Error() string {
	return "switchapi: vlan_id is required"
}

// ErrInvalidVLANID is returned when the VLAN ID is out of range.
type ErrInvalidVLANID struct {
	Value uint16
}

func (e ErrInvalidVLANID) Error() string {
	return fmt.Sprintf("switchapi: invalid vlan_id %d (must be 1-4094)", e.Value)
}

// ErrSwitchNotFound is returned when the requested switch is not registered.
type ErrSwitchNotFound struct {
	Name string
}

func (e ErrSwitchNotFound) Error() string {
	return fmt.Sprintf("switchapi: switch %q not found", e.Name)
}

// ErrPortOperationFailed is returned when a port operation fails on the switch.
type ErrPortOperationFailed struct {
	Operation string
	Switch    string
	Port      string
	Cause     error
}

func (e ErrPortOperationFailed) Error() string {
	return fmt.Sprintf("switchapi: %s failed on switch %q port %q: %v",
		e.Operation, e.Switch, e.Port, e.Cause)
}

func (e ErrPortOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrListPortsFailed is returned when listing ports fails on the switch.
type ErrListPortsFailed struct {
	Switch string
	Cause  error
}

func (e ErrListPortsFailed) Error() string {
	return fmt.Sprintf("switchapi: list ports failed on switch %q: %v", e.Switch, e.Cause)
}

func (e ErrListPortsFailed) Unwrap() error {
	return e.Cause
}

// ErrServiceNil is returned when the switch service is not initialized.
type ErrServiceNil struct{}

func (e ErrServiceNil) Error() string {
	return "switchapi: switch service is not initialized"
}
