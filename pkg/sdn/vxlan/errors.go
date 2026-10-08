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

package vxlan

import (
	"errors"
	"fmt"
)

// Sentinel errors for VXLAN operations.
var (
	// ErrVNIOutOfRange is returned when a VNI is outside the valid range (1-16777215).
	ErrVNIOutOfRange = errors.New("VNI must be between 1 and 16777215")

	// ErrVNIInUse is returned when attempting to use a VNI that is already allocated.
	ErrVNIInUse = errors.New("VNI already in use")

	// ErrVTEPNotConfigured is returned when VTEP operations are attempted before configuration.
	ErrVTEPNotConfigured = errors.New("VTEP not configured")

	// ErrInvalidVTEPIP is returned when an invalid VTEP IP address is provided.
	ErrInvalidVTEPIP = errors.New("invalid VTEP IP address")

	// ErrUnderlayNotReady is returned when the underlay interface is not available.
	ErrUnderlayNotReady = errors.New("underlay interface not ready")

	// ErrMTUTooSmall is returned when the MTU is insufficient for VXLAN encapsulation.
	ErrMTUTooSmall = errors.New("underlay MTU too small for a 9000-byte overlay (minimum 9050)")

	// ErrInvalidVXLANPort is returned when an invalid VXLAN UDP port is specified.
	ErrInvalidVXLANPort = errors.New("invalid VXLAN UDP port")

	// ErrVLANOutOfRange is returned when a VLAN ID is outside the valid range.
	ErrVLANOutOfRange = errors.New("VLAN ID out of range (0-4094)")

	// ErrMappingNotFound is returned when a VNI/VLAN mapping does not exist.
	ErrMappingNotFound = errors.New("VNI/VLAN mapping not found")

	// ErrManagerNotStarted is returned when operations are attempted on an unstarted manager.
	ErrManagerNotStarted = errors.New("VTEP manager not started")

	// ErrManagerAlreadyStarted is returned when Start is called on an already running manager.
	ErrManagerAlreadyStarted = errors.New("VTEP manager already started")

	// ErrInvalidPortName is returned when the VXLAN port name is empty.
	ErrInvalidPortName = errors.New("VXLAN port name is empty")

	// ErrOVSClientNil is returned when OVS client is not provided.
	ErrOVSClientNil = errors.New("OVS client is nil")

	// ErrBridgeNameEmpty is returned when bridge name is empty.
	ErrBridgeNameEmpty = errors.New("bridge name is empty")

	// ErrLoggerNil is returned when logger is not provided.
	ErrLoggerNil = errors.New("logger is nil")
)

// ErrPortConflict is returned when a port of the VTEP's name exists but is
// not a flow-based VXLAN port on the configured UDP port, so adopting it
// would carry traffic somewhere other than the overlay intends.
type ErrPortConflict struct {
	Port    string
	Options map[string]string
}

// Error implements the error interface.
func (e *ErrPortConflict) Error() string {
	return fmt.Sprintf("VXLAN port %s exists with options %v, not remote_ip=flow,key=flow on the configured UDP port",
		e.Port, e.Options)
}

// ErrVNIMappingFailed represents a VNI mapping failure with context.
type ErrVNIMappingFailed struct {
	VLAN  uint16
	VNI   VNI
	Cause error
}

// Error implements the error interface.
func (e *ErrVNIMappingFailed) Error() string {
	return fmt.Sprintf("failed to map VLAN %d to VNI %d: %v", e.VLAN, e.VNI, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrVNIMappingFailed) Unwrap() error {
	return e.Cause
}

// ErrOVSOperationFailed represents an OVS operation failure with context.
type ErrOVSOperationFailed struct {
	Operation string
	Target    string
	Cause     error
}

// Error implements the error interface.
func (e *ErrOVSOperationFailed) Error() string {
	return fmt.Sprintf("OVS %s operation failed for %s: %v",
		e.Operation, e.Target, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrOVSOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrVTEPValidationFailed represents a VTEP configuration validation failure.
type ErrVTEPValidationFailed struct {
	Field string
	Value string
	Cause error
}

// Error implements the error interface.
func (e *ErrVTEPValidationFailed) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("VTEP validation failed for %s=%s: %v",
			e.Field, e.Value, e.Cause)
	}
	return fmt.Sprintf("VTEP validation failed for %s: %v", e.Field, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrVTEPValidationFailed) Unwrap() error {
	return e.Cause
}
