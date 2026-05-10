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

// Package tenant provides tenant management with platform-specific extensions
// for OVS bridges, VLAN isolation, quotas, and key isolation.
package tenant

import (
	"fmt"
)

// ErrTenantExists is returned when attempting to create a tenant that already exists.
type ErrTenantExists struct {
	Name string
}

func (e ErrTenantExists) Error() string {
	return fmt.Sprintf("tenant already exists: %s", e.Name)
}

// ErrTenantNotFound is returned when a tenant cannot be found.
type ErrTenantNotFound struct {
	ID   string
	Name string
}

func (e ErrTenantNotFound) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("tenant not found: id=%s", e.ID)
	}
	return fmt.Sprintf("tenant not found: name=%s", e.Name)
}

// ErrInvalidRequest is returned when a request contains invalid parameters.
type ErrInvalidRequest struct {
	Reason string
}

func (e ErrInvalidRequest) Error() string {
	return fmt.Sprintf("invalid request: %s", e.Reason)
}

// ErrInvalidState is returned when a tenant is in an unexpected state.
type ErrInvalidState struct {
	Current State
}

func (e ErrInvalidState) Error() string {
	return fmt.Sprintf("invalid tenant state: %s", e.Current)
}

// ErrInvalidTransition is returned when a state transition is not allowed.
type ErrInvalidTransition struct {
	From State
	To   State
}

func (e ErrInvalidTransition) Error() string {
	return fmt.Sprintf("invalid state transition: %s -> %s", e.From, e.To)
}

// ErrStorageFailed is returned when a storage operation fails.
type ErrStorageFailed struct {
	Operation string
	Err       error
}

func (e ErrStorageFailed) Error() string {
	return fmt.Sprintf("storage operation failed: %s: %v", e.Operation, e.Err)
}

func (e ErrStorageFailed) Unwrap() error {
	return e.Err
}

// ErrBridgeOperationFailed is returned when an OVS bridge operation fails.
type ErrBridgeOperationFailed struct {
	Bridge    string
	Operation string
	Err       error
}

func (e ErrBridgeOperationFailed) Error() string {
	return fmt.Sprintf("bridge operation failed: %s on %s: %v", e.Operation, e.Bridge, e.Err)
}

func (e ErrBridgeOperationFailed) Unwrap() error {
	return e.Err
}

// ErrVLANAllocationFailed is returned when VLAN allocation fails for a tenant.
type ErrVLANAllocationFailed struct {
	TenantID string
	Err      error
}

func (e ErrVLANAllocationFailed) Error() string {
	return fmt.Sprintf("VLAN allocation failed for tenant %s: %v", e.TenantID, e.Err)
}

func (e ErrVLANAllocationFailed) Unwrap() error {
	return e.Err
}

// ErrQuotaExceeded is returned when a resource quota would be exceeded.
type ErrQuotaExceeded struct {
	TenantID  string
	Resource  string
	Requested int64
	Available int64
}

func (e ErrQuotaExceeded) Error() string {
	return fmt.Sprintf("quota exceeded for tenant %s: resource=%s, requested=%d, available=%d",
		e.TenantID, e.Resource, e.Requested, e.Available)
}

// ErrResourceLimitReached is returned when the maximum resource limit is reached.
type ErrResourceLimitReached struct {
	TenantID string
	Resource string
	Limit    int64
}

func (e ErrResourceLimitReached) Error() string {
	return fmt.Sprintf("resource limit reached for tenant %s: resource=%s, limit=%d",
		e.TenantID, e.Resource, e.Limit)
}

// ErrInvalidVLANRange is returned when a VLAN range is invalid.
type ErrInvalidVLANRange struct {
	Start  uint16
	End    uint16
	Reason string
}

func (e ErrInvalidVLANRange) Error() string {
	return fmt.Sprintf("invalid VLAN range %d-%d: %s", e.Start, e.End, e.Reason)
}

// ErrDEKOperationFailed is returned when a DEK (Data Encryption Key) operation fails.
type ErrDEKOperationFailed struct {
	TenantID  string
	Operation string
	Err       error
}

func (e ErrDEKOperationFailed) Error() string {
	return fmt.Sprintf("DEK operation failed for tenant %s: %s: %v", e.TenantID, e.Operation, e.Err)
}

func (e ErrDEKOperationFailed) Unwrap() error {
	return e.Err
}

// ErrConfigValidation is returned when configuration validation fails.
type ErrConfigValidation struct {
	Field  string
	Reason string
}

func (e ErrConfigValidation) Error() string {
	return fmt.Sprintf("configuration validation failed: %s: %s", e.Field, e.Reason)
}

// ErrBarrierOperationFailed is returned when a per-tenant barrier operation fails.
type ErrBarrierOperationFailed struct {
	TenantID  string
	Operation string
	Err       error
}

func (e ErrBarrierOperationFailed) Error() string {
	return fmt.Sprintf("barrier operation failed for tenant %s: %s: %v", e.TenantID, e.Operation, e.Err)
}

func (e ErrBarrierOperationFailed) Unwrap() error {
	return e.Err
}

// ErrBarrierNotSupported is returned when a barrier operation is not supported
// by the current SDK version or when no barrier client has been configured.
type ErrBarrierNotSupported struct {
	Operation string
}

func (e ErrBarrierNotSupported) Error() string {
	return fmt.Sprintf("barrier operation not supported: %s", e.Operation)
}

// ErrNilBarrierStatus is returned when the barrier status RPC returns nil
// without an error. It is a sentinel for an inconsistent SDK state and
// callers should treat it as a hard failure rather than retry.
type ErrNilBarrierStatusType struct{}

func (ErrNilBarrierStatusType) Error() string {
	return "tenant: nil barrier status response from SDK"
}

// ErrNilBarrierStatus is the sentinel returned from TenantBarrierStatus when
// the underlying SDK returns nil with no error.
var ErrNilBarrierStatus = ErrNilBarrierStatusType{}
