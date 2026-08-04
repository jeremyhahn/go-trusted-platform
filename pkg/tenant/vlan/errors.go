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

package vlan

import "fmt"

// ErrVLANRangeExhausted is returned when no VLAN range is available for allocation
type ErrVLANRangeExhausted struct {
	Start uint16
	End   uint16
}

func (e *ErrVLANRangeExhausted) Error() string {
	return fmt.Sprintf("VLAN range exhausted: no available range in %d-%d", e.Start, e.End)
}

// ErrVLANInUse is returned when a VLAN is already allocated to another tenant
type ErrVLANInUse struct {
	VLAN     uint16
	TenantID string
}

func (e *ErrVLANInUse) Error() string {
	return fmt.Sprintf("VLAN %d is already in use by tenant %s", e.VLAN, e.TenantID)
}

// ErrVLANOutOfRange is returned when a VLAN ID is outside the valid range
type ErrVLANOutOfRange struct {
	VLAN uint16
	Min  uint16
	Max  uint16
}

func (e *ErrVLANOutOfRange) Error() string {
	return fmt.Sprintf("VLAN %d is outside valid range %d-%d", e.VLAN, e.Min, e.Max)
}

// ErrInvalidVLANRange is returned when a VLAN range configuration is invalid
type ErrInvalidVLANRange struct {
	Start  uint16
	End    uint16
	Reason string
}

func (e *ErrInvalidVLANRange) Error() string {
	return fmt.Sprintf("invalid VLAN range %d-%d: %s", e.Start, e.End, e.Reason)
}

// ErrVLANRangeOverlap is returned when a requested range overlaps with an existing allocation
type ErrVLANRangeOverlap struct {
	Existing  Range
	Requested Range
}

func (e *ErrVLANRangeOverlap) Error() string {
	return fmt.Sprintf("VLAN range %s overlaps with existing allocation %s", e.Requested.String(), e.Existing.String())
}

// ErrTenantVLANNotFound is returned when a tenant has no VLAN allocation
type ErrTenantVLANNotFound struct {
	TenantID string
}

func (e *ErrTenantVLANNotFound) Error() string {
	return fmt.Sprintf("no VLAN allocation found for tenant %s", e.TenantID)
}

// ErrStoreFailed is returned when a storage operation fails
type ErrStoreFailed struct {
	Operation string
	Err       error
}

func (e *ErrStoreFailed) Error() string {
	return fmt.Sprintf("store operation %s failed: %v", e.Operation, e.Err)
}

func (e *ErrStoreFailed) Unwrap() error {
	return e.Err
}

// ErrNilStore is returned when a nil store is provided
type ErrNilStore struct{}

func (e *ErrNilStore) Error() string {
	return "store cannot be nil"
}

// ErrNilConfig is returned when a nil configuration is provided
type ErrNilConfig struct{}

func (e *ErrNilConfig) Error() string {
	return "configuration cannot be nil"
}

// ErrEmptyTenantID is returned when an empty tenant ID is provided
type ErrEmptyTenantID struct{}

func (e *ErrEmptyTenantID) Error() string {
	return "tenant ID cannot be empty"
}

// ErrTenantAlreadyAllocated is returned when a tenant already has a VLAN allocation
type ErrTenantAlreadyAllocated struct {
	TenantID string
	Range    Range
}

func (e *ErrTenantAlreadyAllocated) Error() string {
	return fmt.Sprintf("tenant %s already has VLAN allocation %s", e.TenantID, e.Range.String())
}

// ErrInvalidRangeSize is returned when the requested range size is invalid
type ErrInvalidRangeSize struct {
	Requested uint16
	Available uint16
}

func (e *ErrInvalidRangeSize) Error() string {
	return fmt.Sprintf("requested range size %d exceeds available space %d", e.Requested, e.Available)
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
