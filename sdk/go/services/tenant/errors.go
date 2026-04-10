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

package tenant

import "fmt"

// CRUD Errors

type ErrListTenantsFailed struct {
	Cause error
}

func (e *ErrListTenantsFailed) Error() string {
	return fmt.Sprintf("failed to list tenants: %v", e.Cause)
}

func (e *ErrListTenantsFailed) Unwrap() error { return e.Cause }

type ErrGetTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetTenantFailed) Error() string {
	return fmt.Sprintf("failed to get tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrGetTenantFailed) Unwrap() error { return e.Cause }

type ErrGetTenantByNameFailed struct {
	Name  string
	Cause error
}

func (e *ErrGetTenantByNameFailed) Error() string {
	return fmt.Sprintf("failed to get tenant by name %s: %v", e.Name, e.Cause)
}

func (e *ErrGetTenantByNameFailed) Unwrap() error { return e.Cause }

type ErrCreateTenantFailed struct {
	Cause error
}

func (e *ErrCreateTenantFailed) Error() string {
	return fmt.Sprintf("failed to create tenant: %v", e.Cause)
}

func (e *ErrCreateTenantFailed) Unwrap() error { return e.Cause }

type ErrUpdateTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateTenantFailed) Error() string {
	return fmt.Sprintf("failed to update tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateTenantFailed) Unwrap() error { return e.Cause }

type ErrDeleteTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteTenantFailed) Error() string {
	return fmt.Sprintf("failed to delete tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteTenantFailed) Unwrap() error { return e.Cause }

// Lifecycle Errors

type ErrSuspendTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrSuspendTenantFailed) Error() string {
	return fmt.Sprintf("failed to suspend tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrSuspendTenantFailed) Unwrap() error { return e.Cause }

type ErrResumeTenantFailed struct {
	ID    string
	Cause error
}

func (e *ErrResumeTenantFailed) Error() string {
	return fmt.Sprintf("failed to resume tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrResumeTenantFailed) Unwrap() error { return e.Cause }

// Quota Errors

type ErrGetQuotasFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetQuotasFailed) Error() string {
	return fmt.Sprintf("failed to get quotas for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrGetQuotasFailed) Unwrap() error { return e.Cause }

type ErrUpdateQuotasFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateQuotasFailed) Error() string {
	return fmt.Sprintf("failed to update quotas for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateQuotasFailed) Unwrap() error { return e.Cause }

type ErrGetUsageFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetUsageFailed) Error() string {
	return fmt.Sprintf("failed to get usage for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrGetUsageFailed) Unwrap() error { return e.Cause }

type ErrCheckQuotaFailed struct {
	ID    string
	Cause error
}

func (e *ErrCheckQuotaFailed) Error() string {
	return fmt.Sprintf("failed to check quota for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrCheckQuotaFailed) Unwrap() error { return e.Cause }

// Network Errors

type ErrValidateVLANFailed struct {
	ID    string
	Cause error
}

func (e *ErrValidateVLANFailed) Error() string {
	return fmt.Sprintf("failed to validate VLAN for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrValidateVLANFailed) Unwrap() error { return e.Cause }

type ErrGetBridgeNameFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetBridgeNameFailed) Error() string {
	return fmt.Sprintf("failed to get bridge name for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrGetBridgeNameFailed) Unwrap() error { return e.Cause }

// Sync Errors

type ErrSyncTenantsFailed struct {
	Cause error
}

func (e *ErrSyncTenantsFailed) Error() string {
	return fmt.Sprintf("failed to sync tenants: %v", e.Cause)
}

func (e *ErrSyncTenantsFailed) Unwrap() error { return e.Cause }

// DEK Errors

type ErrRotateDEKFailed struct {
	ID    string
	Cause error
}

func (e *ErrRotateDEKFailed) Error() string {
	return fmt.Sprintf("failed to rotate DEK for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrRotateDEKFailed) Unwrap() error { return e.Cause }

type ErrGetDEKStatusFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetDEKStatusFailed) Error() string {
	return fmt.Sprintf("failed to get DEK status for tenant %s: %v", e.ID, e.Cause)
}

func (e *ErrGetDEKStatusFailed) Unwrap() error { return e.Cause }
