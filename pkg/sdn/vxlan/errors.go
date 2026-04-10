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
	"net/netip"
)

// Sentinel errors for VXLAN operations.
var (
	// ErrVNIOutOfRange is returned when a VNI is outside the valid range (1-16777215).
	ErrVNIOutOfRange = errors.New("VNI must be between 1 and 16777215")

	// ErrVNIInUse is returned when attempting to use a VNI that is already allocated.
	ErrVNIInUse = errors.New("VNI already in use")

	// ErrTunnelNotFound is returned when a requested tunnel does not exist.
	ErrTunnelNotFound = errors.New("tunnel not found")

	// ErrTunnelExists is returned when attempting to create a tunnel that already exists.
	ErrTunnelExists = errors.New("tunnel already exists")

	// ErrVTEPNotConfigured is returned when VTEP operations are attempted before configuration.
	ErrVTEPNotConfigured = errors.New("VTEP not configured")

	// ErrInvalidVTEPIP is returned when an invalid VTEP IP address is provided.
	ErrInvalidVTEPIP = errors.New("invalid VTEP IP address")

	// ErrUnderlayNotReady is returned when the underlay interface is not available.
	ErrUnderlayNotReady = errors.New("underlay interface not ready")

	// ErrMTUTooSmall is returned when the MTU is insufficient for VXLAN encapsulation.
	ErrMTUTooSmall = errors.New("MTU too small for VXLAN (minimum 1550)")

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

	// ErrInvalidTunnelID is returned when a tunnel ID is malformed or empty.
	ErrInvalidTunnelID = errors.New("invalid tunnel ID")

	// ErrOVSClientNil is returned when OVS client is not provided.
	ErrOVSClientNil = errors.New("OVS client is nil")

	// ErrBridgeNameEmpty is returned when bridge name is empty.
	ErrBridgeNameEmpty = errors.New("bridge name is empty")

	// ErrLoggerNil is returned when logger is not provided.
	ErrLoggerNil = errors.New("logger is nil")
)

// ErrTunnelCreationFailed represents a tunnel creation failure with context.
type ErrTunnelCreationFailed struct {
	RemoteVTEP netip.Addr
	VNI        VNI
	Cause      error
}

// Error implements the error interface.
func (e *ErrTunnelCreationFailed) Error() string {
	return fmt.Sprintf("failed to create tunnel to %s for VNI %d: %v",
		e.RemoteVTEP, e.VNI, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrTunnelCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrTunnelDeletionFailed represents a tunnel deletion failure with context.
type ErrTunnelDeletionFailed struct {
	TunnelID string
	Cause    error
}

// Error implements the error interface.
func (e *ErrTunnelDeletionFailed) Error() string {
	return fmt.Sprintf("failed to delete tunnel %s: %v", e.TunnelID, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrTunnelDeletionFailed) Unwrap() error {
	return e.Cause
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

// ErrHealthCheckFailed represents a tunnel health check failure.
type ErrHealthCheckFailed struct {
	TunnelID   string
	RemoteVTEP netip.Addr
	Cause      error
}

// Error implements the error interface.
func (e *ErrHealthCheckFailed) Error() string {
	return fmt.Sprintf("health check failed for tunnel %s (remote: %s): %v",
		e.TunnelID, e.RemoteVTEP, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *ErrHealthCheckFailed) Unwrap() error {
	return e.Cause
}
