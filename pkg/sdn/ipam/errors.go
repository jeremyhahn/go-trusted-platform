// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package ipam

import (
	"errors"
	"fmt"
	"net/netip"
)

// Sentinel errors for common IPAM error conditions.
var (
	// ErrPoolNotFound indicates the requested pool does not exist.
	ErrPoolNotFound = errors.New("pool not found")
	// ErrPoolAlreadyExists indicates a pool with the same ID already exists.
	ErrPoolAlreadyExists = errors.New("pool already exists")
	// ErrPoolExhausted indicates no more IPs are available in the pool.
	ErrPoolExhausted = errors.New("pool exhausted")
	// ErrPoolNameExists indicates a pool with the same name already exists.
	ErrPoolNameExists = errors.New("pool name already exists")
	// ErrPoolCIDROverlaps indicates the pool CIDR overlaps with an existing pool.
	ErrPoolCIDROverlaps = errors.New("pool CIDR overlaps with existing pool")
	// ErrPoolHasAllocations indicates the pool cannot be deleted due to active allocations.
	ErrPoolHasAllocations = errors.New("pool has active allocations")

	// ErrAllocationNotFound indicates the requested allocation does not exist.
	ErrAllocationNotFound = errors.New("allocation not found")
	// ErrIPAlreadyAllocated indicates the IP is already allocated.
	ErrIPAlreadyAllocated = errors.New("IP already allocated")
	// ErrIPNotInPool indicates the IP is not within the pool's CIDR.
	ErrIPNotInPool = errors.New("IP not in pool CIDR")

	// ErrInvalidCIDR indicates the provided CIDR is invalid.
	ErrInvalidCIDR = errors.New("invalid CIDR")
	// ErrInvalidIP indicates the provided IP address is invalid.
	ErrInvalidIP = errors.New("invalid IP address")
	// ErrInvalidGateway indicates the gateway is not within the pool's CIDR.
	ErrInvalidGateway = errors.New("gateway not in pool CIDR")
	// ErrInvalidPoolID indicates the pool ID is empty or invalid.
	ErrInvalidPoolID = errors.New("invalid pool ID")
	// ErrInvalidPoolName indicates the pool name is empty or invalid.
	ErrInvalidPoolName = errors.New("invalid pool name")
	// ErrInvalidOffset indicates the offset is out of range for the pool.
	ErrInvalidOffset = errors.New("offset out of range")
	// ErrInvalidBitmapData indicates the bitmap data is corrupted or invalid.
	ErrInvalidBitmapData = errors.New("invalid bitmap data")

	// ErrDeviceIDRequired indicates a device ID must be provided.
	ErrDeviceIDRequired = errors.New("device ID required")
	// ErrPoolIDRequired indicates a pool ID must be provided.
	ErrPoolIDRequired = errors.New("pool ID required")

	// ErrBackendUnavailable indicates the storage backend is not available.
	ErrBackendUnavailable = errors.New("backend unavailable")
	// ErrBackendTimeout indicates the storage backend operation timed out.
	ErrBackendTimeout = errors.New("backend timeout")

	// ErrNetworkAddress indicates the IP is a network address and cannot be allocated.
	ErrNetworkAddress = errors.New("cannot allocate network address")
	// ErrBroadcastAddress indicates the IP is a broadcast address and cannot be allocated.
	ErrBroadcastAddress = errors.New("cannot allocate broadcast address")

	// ErrAllocationExpired indicates the allocation has expired.
	ErrAllocationExpired = errors.New("allocation expired")
	// ErrAllocationReleased indicates the allocation was already released.
	ErrAllocationReleased = errors.New("allocation already released")

	// ErrCASConflict indicates a compare-and-swap operation failed due to concurrent modification.
	ErrCASConflict = errors.New("CAS conflict: concurrent modification detected")
	// ErrMaxRetriesExceeded indicates the maximum number of retries was exceeded.
	ErrMaxRetriesExceeded = errors.New("max retries exceeded")
)

// ErrAllocationFailed provides context when an allocation operation fails.
type ErrAllocationFailed struct {
	PoolID string
	Reason string
	Cause  error
}

// Error returns the error message.
func (e *ErrAllocationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("allocation failed for pool %s: %s: %v", e.PoolID, e.Reason, e.Cause)
	}
	return fmt.Sprintf("allocation failed for pool %s: %s", e.PoolID, e.Reason)
}

// Unwrap returns the underlying error.
func (e *ErrAllocationFailed) Unwrap() error {
	return e.Cause
}

// ErrIPConflict indicates an IP address conflict occurred.
type ErrIPConflict struct {
	IP       netip.Addr
	DeviceID string
}

// Error returns the error message.
func (e *ErrIPConflict) Error() string {
	return fmt.Sprintf("IP %s already allocated to device %s", e.IP, e.DeviceID)
}

// ErrPoolOperationFailed provides context when a pool operation fails.
type ErrPoolOperationFailed struct {
	PoolID    string
	Operation string
	Cause     error
}

// Error returns the error message.
func (e *ErrPoolOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("pool operation %s failed for pool %s: %v", e.Operation, e.PoolID, e.Cause)
	}
	return fmt.Sprintf("pool operation %s failed for pool %s", e.Operation, e.PoolID)
}

// Unwrap returns the underlying error.
func (e *ErrPoolOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidAllocationStatus indicates an invalid allocation status transition.
type ErrInvalidAllocationStatus struct {
	Current AllocationStatus
	Desired AllocationStatus
	Reason  string
}

// Error returns the error message.
func (e *ErrInvalidAllocationStatus) Error() string {
	return fmt.Sprintf("invalid status transition from %s to %s: %s", e.Current, e.Desired, e.Reason)
}

// ErrCIDRMismatch indicates the IP address family doesn't match the CIDR.
type ErrCIDRMismatch struct {
	IP   netip.Addr
	CIDR netip.Prefix
}

// Error returns the error message.
func (e *ErrCIDRMismatch) Error() string {
	ipFamily := "IPv4"
	if e.IP.Is6() {
		ipFamily = "IPv6"
	}
	cidrFamily := "IPv4"
	if e.CIDR.Addr().Is6() {
		cidrFamily = "IPv6"
	}
	return fmt.Sprintf("IP %s (%s) does not match CIDR %s (%s) address family",
		e.IP, ipFamily, e.CIDR, cidrFamily)
}

// ErrLeaseExpired indicates the allocation lease has expired.
type ErrLeaseExpired struct {
	IP        netip.Addr
	ExpiredAt string
}

// Error returns the error message.
func (e *ErrLeaseExpired) Error() string {
	return fmt.Sprintf("lease for IP %s expired at %s", e.IP, e.ExpiredAt)
}

// ErrStorageOperation indicates a storage backend operation failed.
type ErrStorageOperation struct {
	Operation string
	Key       string
	Cause     error
}

// Error returns the error message.
func (e *ErrStorageOperation) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("storage operation %s failed for key %s: %v", e.Operation, e.Key, e.Cause)
	}
	return fmt.Sprintf("storage operation %s failed for key %s", e.Operation, e.Key)
}

// Unwrap returns the underlying error.
func (e *ErrStorageOperation) Unwrap() error {
	return e.Cause
}

// ErrSerialization indicates serialization or deserialization failed.
type ErrSerialization struct {
	EntityType string
	Operation  string
	Cause      error
}

// Error returns the error message.
func (e *ErrSerialization) Error() string {
	return fmt.Sprintf("%s failed for %s: %v", e.Operation, e.EntityType, e.Cause)
}

// Unwrap returns the underlying error.
func (e *ErrSerialization) Unwrap() error {
	return e.Cause
}

// IsPoolError returns true if the error is related to pool operations.
func IsPoolError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrPoolNotFound) ||
		errors.Is(err, ErrPoolAlreadyExists) ||
		errors.Is(err, ErrPoolExhausted) ||
		errors.Is(err, ErrPoolNameExists) ||
		errors.Is(err, ErrPoolCIDROverlaps) ||
		errors.Is(err, ErrPoolHasAllocations)
}

// IsAllocationError returns true if the error is related to allocation operations.
func IsAllocationError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrAllocationNotFound) ||
		errors.Is(err, ErrIPAlreadyAllocated) ||
		errors.Is(err, ErrIPNotInPool) ||
		errors.Is(err, ErrAllocationExpired) ||
		errors.Is(err, ErrAllocationReleased)
}

// IsValidationError returns true if the error is related to validation.
func IsValidationError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrInvalidCIDR) ||
		errors.Is(err, ErrInvalidIP) ||
		errors.Is(err, ErrInvalidGateway) ||
		errors.Is(err, ErrInvalidPoolID) ||
		errors.Is(err, ErrInvalidPoolName) ||
		errors.Is(err, ErrInvalidOffset) ||
		errors.Is(err, ErrDeviceIDRequired) ||
		errors.Is(err, ErrPoolIDRequired) ||
		errors.Is(err, ErrInvalidBitmapData)
}

// IsBackendError returns true if the error is related to backend operations.
func IsBackendError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrBackendUnavailable) ||
		errors.Is(err, ErrBackendTimeout) ||
		errors.Is(err, ErrCASConflict) ||
		errors.Is(err, ErrMaxRetriesExceeded)
}
