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

package entities

import "strconv"

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// ErrUnknownDeviceRole reports a role string outside the DeviceRole
// vocabulary. Callers surface it as a 400 rather than storing the record
// with DeviceRoleUnknown.
type ErrUnknownDeviceRole struct {
	Role string
}

// Error implements the error interface.
func (e ErrUnknownDeviceRole) Error() string {
	return "device: unknown role " + strconv.Quote(e.Role)
}

// ErrNoPortClassForRole reports a device role that maps to no switch port
// class, so an enrolled device of that role cannot be admitted to role zones
// and needs an explicit profile zone instead.
type ErrNoPortClassForRole struct {
	Role DeviceRole
}

// Error implements the error interface.
func (e ErrNoPortClassForRole) Error() string {
	return "device: role " + strconv.Quote(string(e.Role)) + " has no port class; set an explicit profile zone"
}
