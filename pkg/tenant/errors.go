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
// for quotas, key isolation and per-tenant barriers.
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

// ErrDefaultRolesFailed is returned when the IAM tenant's default roles
// could not be provisioned. A tenant without them cannot hold a user: every
// user the platform mirrors into IAM names a role, and a name that resolves
// to nothing fails the create (#641).
type ErrDefaultRolesFailed struct {
	TenantID string
	Err      error
}

func (e ErrDefaultRolesFailed) Error() string {
	return fmt.Sprintf("failed to provision default IAM roles for tenant %s: %v", e.TenantID, e.Err)
}

func (e ErrDefaultRolesFailed) Unwrap() error {
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
