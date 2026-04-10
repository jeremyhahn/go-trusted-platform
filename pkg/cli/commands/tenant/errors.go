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

// Package tenant provides CLI commands for tenant management operations
// including quotas, VLANs, bridges, and lifecycle operations.
package tenant

import "fmt"

// ErrMissingTenantName is returned when tenant name is required but not provided
type ErrMissingTenantName struct{}

func (e ErrMissingTenantName) Error() string {
	return "tenant name is required"
}

// ErrTenantNotFound is returned when a tenant cannot be found
type ErrTenantNotFound struct {
	Name string
}

func (e ErrTenantNotFound) Error() string {
	return fmt.Sprintf("tenant not found: %s", e.Name)
}

// ErrInvalidQuotaValue is returned when a quota value is invalid
type ErrInvalidQuotaValue struct {
	Field  string
	Value  int64
	Reason string
}

func (e ErrInvalidQuotaValue) Error() string {
	return fmt.Sprintf("invalid quota value for %s (%d): %s", e.Field, e.Value, e.Reason)
}

// ErrInvalidVLANRange is returned when a VLAN range is invalid
type ErrInvalidVLANRange struct {
	Start  uint16
	End    uint16
	Reason string
}

func (e ErrInvalidVLANRange) Error() string {
	return fmt.Sprintf("invalid VLAN range %d-%d: %s", e.Start, e.End, e.Reason)
}

// ErrOperationFailed is returned when a tenant operation fails
type ErrOperationFailed struct {
	Operation string
	TenantID  string
	Err       error
}

func (e ErrOperationFailed) Error() string {
	return fmt.Sprintf("tenant operation %s failed for %s: %v", e.Operation, e.TenantID, e.Err)
}

func (e ErrOperationFailed) Unwrap() error {
	return e.Err
}

// ErrQuotaUpdateFailed is returned when updating quotas fails
type ErrQuotaUpdateFailed struct {
	TenantID string
	Err      error
}

func (e ErrQuotaUpdateFailed) Error() string {
	return fmt.Sprintf("failed to update quotas for tenant %s: %v", e.TenantID, e.Err)
}

func (e ErrQuotaUpdateFailed) Unwrap() error {
	return e.Err
}

// ErrUsageRetrievalFailed is returned when retrieving usage fails
type ErrUsageRetrievalFailed struct {
	TenantID string
	Err      error
}

func (e ErrUsageRetrievalFailed) Error() string {
	return fmt.Sprintf("failed to retrieve usage for tenant %s: %v", e.TenantID, e.Err)
}

func (e ErrUsageRetrievalFailed) Unwrap() error {
	return e.Err
}

// ErrVLANInfoFailed is returned when retrieving VLAN info fails
type ErrVLANInfoFailed struct {
	TenantID string
	Err      error
}

func (e ErrVLANInfoFailed) Error() string {
	return fmt.Sprintf("failed to retrieve VLAN info for tenant %s: %v", e.TenantID, e.Err)
}

func (e ErrVLANInfoFailed) Unwrap() error {
	return e.Err
}

// ErrBridgeInfoFailed is returned when retrieving bridge info fails
type ErrBridgeInfoFailed struct {
	TenantID string
	Err      error
}

func (e ErrBridgeInfoFailed) Error() string {
	return fmt.Sprintf("failed to retrieve bridge info for tenant %s: %v", e.TenantID, e.Err)
}

func (e ErrBridgeInfoFailed) Unwrap() error {
	return e.Err
}

// ErrTenantSuspended is returned when an operation cannot be performed on a suspended tenant
type ErrTenantSuspended struct {
	TenantID string
}

func (e ErrTenantSuspended) Error() string {
	return fmt.Sprintf("tenant %s is suspended", e.TenantID)
}

// ErrTenantAlreadyActive is returned when trying to resume an already active tenant
type ErrTenantAlreadyActive struct {
	TenantID string
}

func (e ErrTenantAlreadyActive) Error() string {
	return fmt.Sprintf("tenant %s is already active", e.TenantID)
}
