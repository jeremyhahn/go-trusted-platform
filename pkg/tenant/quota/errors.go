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

package quota

import "fmt"

// ErrQuotaExceeded indicates the requested resources exceed available quota.
type ErrQuotaExceeded struct {
	TenantID  string
	Resource  ResourceType
	Requested int64
	Available int64
}

func (e ErrQuotaExceeded) Error() string {
	return fmt.Sprintf("quota: exceeded for tenant %s resource %s: requested %d, available %d",
		e.TenantID, e.Resource, e.Requested, e.Available)
}

// ErrReservationNotFound indicates the reservation does not exist.
type ErrReservationNotFound struct {
	ID string
}

func (e ErrReservationNotFound) Error() string {
	return fmt.Sprintf("quota: reservation not found: %s", e.ID)
}

// ErrReservationExpired indicates the reservation has expired.
type ErrReservationExpired struct {
	ID string
}

func (e ErrReservationExpired) Error() string {
	return fmt.Sprintf("quota: reservation expired: %s", e.ID)
}

// ErrInvalidResource indicates an unknown or invalid resource type.
type ErrInvalidResource struct {
	Resource ResourceType
}

func (e ErrInvalidResource) Error() string {
	return fmt.Sprintf("quota: invalid resource type: %s", e.Resource)
}

// ErrStoreFailed indicates a storage operation failed.
type ErrStoreFailed struct {
	Operation string
	Err       error
}

func (e ErrStoreFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("quota: store operation %s failed: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("quota: store operation %s failed", e.Operation)
}

func (e ErrStoreFailed) Unwrap() error {
	return e.Err
}

// ErrTenantNotFound indicates the tenant does not exist.
type ErrTenantNotFound struct {
	TenantID string
}

func (e ErrTenantNotFound) Error() string {
	return fmt.Sprintf("quota: tenant not found: %s", e.TenantID)
}

// ErrInvalidAmount indicates an invalid resource amount.
type ErrInvalidAmount struct {
	Resource ResourceType
	Amount   int64
}

func (e ErrInvalidAmount) Error() string {
	return fmt.Sprintf("quota: invalid amount %d for resource %s", e.Amount, e.Resource)
}

// ErrNilStore indicates the store is nil.
type ErrNilStore struct{}

func (e ErrNilStore) Error() string {
	return "quota: store is nil"
}

// ErrNilLogger indicates the logger is nil.
type ErrNilLogger struct{}

func (e ErrNilLogger) Error() string {
	return "quota: logger is nil"
}

// ErrReservationAlreadyCommitted indicates the reservation was already committed.
type ErrReservationAlreadyCommitted struct {
	ID string
}

func (e ErrReservationAlreadyCommitted) Error() string {
	return fmt.Sprintf("quota: reservation already committed: %s", e.ID)
}
