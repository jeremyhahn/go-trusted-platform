// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package dhcp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Sentinel errors for DHCP operations.
var (
	// ErrPluginClosed indicates the plugin has been closed.
	ErrPluginClosed = errors.New("plugin closed")
	// ErrAllocatorRequired indicates an allocator must be provided.
	ErrAllocatorRequired = errors.New("allocator required")
	// ErrPoolIDRequired indicates a pool ID must be provided.
	ErrPoolIDRequired = errors.New("pool ID required")
	// ErrPoolNotFound indicates the specified pool was not found.
	ErrPoolNotFound = errors.New("pool not found")
	// ErrLeaseNotFound indicates the lease was not found.
	ErrLeaseNotFound = errors.New("lease not found")
	// ErrInvalidMAC indicates the MAC address is invalid.
	ErrInvalidMAC = errors.New("invalid MAC address")
	// ErrInvalidIP indicates the IP address is invalid.
	ErrInvalidIP = errors.New("invalid IP address")
	// ErrLeaseExpired indicates the lease has expired.
	ErrLeaseExpired = errors.New("lease expired")
	// ErrNilRequest indicates a nil DHCP request was received.
	ErrNilRequest = errors.New("nil DHCP request")
	// ErrNilResponse indicates a nil DHCP response was provided.
	ErrNilResponse = errors.New("nil DHCP response")
	// ErrAllocationFailed indicates IP allocation failed.
	ErrAllocationFailed = errors.New("allocation failed")
	// ErrInvalidMessageType indicates an invalid DHCP message type.
	ErrInvalidMessageType = errors.New("invalid message type")
	// ErrPXENotSupported indicates PXE boot is not supported for this client.
	ErrPXENotSupported = errors.New("PXE boot not supported")
	// ErrInvalidBootFile indicates the boot file path is invalid.
	ErrInvalidBootFile = errors.New("invalid boot file")
	// ErrInvalidNextServer indicates the next server address is invalid.
	ErrInvalidNextServer = errors.New("invalid next server address")
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("invalid configuration")
	// ErrInvalidLeaseRequest indicates the lease request is invalid.
	ErrInvalidLeaseRequest = errors.New("invalid lease request")
	// ErrIPAMBackendInvalid indicates an invalid IPAM backend was specified.
	ErrIPAMBackendInvalid = errors.New("invalid IPAM backend")

	// Server-related errors
	// ErrServerAlreadyRunning indicates the server is already running.
	ErrServerAlreadyRunning = errors.New("server already running")
	// ErrServerNotRunning indicates the server is not running.
	ErrServerNotRunning = errors.New("server not running")
	// ErrNoInterfacesConfigured indicates no interfaces are configured.
	ErrNoInterfacesConfigured = errors.New("no interfaces configured")
	// ErrInvalidInterface indicates the interface configuration is invalid.
	ErrInvalidInterface = errors.New("invalid interface configuration")
	// ErrInterfaceNotFound indicates the network interface was not found.
	ErrInterfaceNotFound = errors.New("network interface not found")
	// ErrBindFailed indicates binding to the interface failed.
	ErrBindFailed = errors.New("failed to bind to interface")
	// ErrNilConfig indicates a nil configuration was provided.
	ErrNilConfig = errors.New("nil configuration")
	// ErrNilLeaseManager indicates a nil lease manager was provided.
	ErrNilLeaseManager = errors.New("nil lease manager")
	// ErrNilIPAMAllocator indicates a nil IPAM allocator was provided.
	ErrNilIPAMAllocator = errors.New("nil IPAM allocator")
)

// ErrLeaseConflict indicates a lease conflict occurred.
type ErrLeaseConflict struct {
	IP           netip.Addr
	ExistingMAC  net.HardwareAddr
	RequestedMAC net.HardwareAddr
}

// Error returns the error message.
func (e *ErrLeaseConflict) Error() string {
	return fmt.Sprintf("lease conflict: IP %s already leased to %s, requested by %s",
		e.IP, e.ExistingMAC, e.RequestedMAC)
}

// ErrPoolExhausted indicates the IP pool is exhausted.
type ErrPoolExhausted struct {
	PoolID string
}

// Error returns the error message.
func (e *ErrPoolExhausted) Error() string {
	return fmt.Sprintf("pool %s exhausted: no available IP addresses", e.PoolID)
}

// ErrDHCPOperation indicates a DHCP operation failed.
type ErrDHCPOperation struct {
	Operation string
	MAC       net.HardwareAddr
	Cause     error
}

// Error returns the error message.
func (e *ErrDHCPOperation) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("DHCP %s failed for %s: %v", e.Operation, e.MAC, e.Cause)
	}
	return fmt.Sprintf("DHCP %s failed for %s", e.Operation, e.MAC)
}

// Unwrap returns the underlying error.
func (e *ErrDHCPOperation) Unwrap() error {
	return e.Cause
}

// ErrPXEOperation indicates a PXE operation failed.
type ErrPXEOperation struct {
	Operation string
	MAC       net.HardwareAddr
	Cause     error
}

// Error returns the error message.
func (e *ErrPXEOperation) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("PXE %s failed for %s: %v", e.Operation, e.MAC, e.Cause)
	}
	return fmt.Sprintf("PXE %s failed for %s", e.Operation, e.MAC)
}

// Unwrap returns the underlying error.
func (e *ErrPXEOperation) Unwrap() error {
	return e.Cause
}

// ErrInterfaceOperation indicates an interface operation failed.
type ErrInterfaceOperation struct {
	Interface string
	Operation string
	Cause     error
}

// Error returns the error message.
func (e *ErrInterfaceOperation) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("interface %s %s failed: %v", e.Interface, e.Operation, e.Cause)
	}
	return fmt.Sprintf("interface %s %s failed", e.Interface, e.Operation)
}

// Unwrap returns the underlying error.
func (e *ErrInterfaceOperation) Unwrap() error {
	return e.Cause
}

// ErrServerOperation indicates a server operation failed.
type ErrServerOperation struct {
	Operation string
	Cause     error
}

// Error returns the error message.
func (e *ErrServerOperation) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("server %s failed: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("server %s failed", e.Operation)
}

// Unwrap returns the underlying error.
func (e *ErrServerOperation) Unwrap() error {
	return e.Cause
}

// IsLeaseError returns true if the error is related to lease operations.
func IsLeaseError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrLeaseNotFound) ||
		errors.Is(err, ErrLeaseExpired) ||
		errors.As(err, new(*ErrLeaseConflict))
}

// IsValidationError returns true if the error is a validation error.
func IsValidationError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrInvalidMAC) ||
		errors.Is(err, ErrInvalidIP) ||
		errors.Is(err, ErrNilRequest) ||
		errors.Is(err, ErrNilResponse) ||
		errors.Is(err, ErrInvalidMessageType) ||
		errors.Is(err, ErrInvalidBootFile) ||
		errors.Is(err, ErrInvalidNextServer) ||
		errors.Is(err, ErrNilConfig) ||
		errors.Is(err, ErrInvalidConfig) ||
		errors.Is(err, ErrInvalidInterface) ||
		errors.Is(err, ErrInvalidLeaseRequest) ||
		errors.Is(err, ErrIPAMBackendInvalid)
}

// IsServerError returns true if the error is a server operation error.
func IsServerError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrServerAlreadyRunning) ||
		errors.Is(err, ErrServerNotRunning) ||
		errors.Is(err, ErrNoInterfacesConfigured) ||
		errors.Is(err, ErrInterfaceNotFound) ||
		errors.Is(err, ErrBindFailed) ||
		errors.As(err, new(*ErrServerOperation)) ||
		errors.As(err, new(*ErrInterfaceOperation))
}

// IsPoolError returns true if the error is related to pool operations.
func IsPoolError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrPoolNotFound) ||
		errors.Is(err, ErrPoolIDRequired) ||
		errors.As(err, new(*ErrPoolExhausted))
}
