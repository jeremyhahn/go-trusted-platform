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

package kvstore

import (
	"fmt"
)

// ErrNotFound is returned when an entity is not found in the database.
type ErrNotFound struct {
	EntityType string
	ID         uint64
}

func (e ErrNotFound) Error() string {
	return fmt.Sprintf("entity not found: type=%s, id=%d", e.EntityType, e.ID)
}

// ErrNotFoundByIndex is returned when an entity is not found by index lookup.
type ErrNotFoundByIndex struct {
	EntityType string
	IndexField string
	Value      string
}

func (e ErrNotFoundByIndex) Error() string {
	return fmt.Sprintf("entity not found by index: type=%s, %s=%s", e.EntityType, e.IndexField, e.Value)
}

// ErrSerializationFailed is returned when entity serialization fails.
type ErrSerializationFailed struct {
	EntityType string
	Cause      error
}

func (e ErrSerializationFailed) Error() string {
	return fmt.Sprintf("serialization failed for %s: %v", e.EntityType, e.Cause)
}

func (e ErrSerializationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeserializationFailed is returned when entity deserialization fails.
type ErrDeserializationFailed struct {
	EntityType string
	Cause      error
}

func (e ErrDeserializationFailed) Error() string {
	return fmt.Sprintf("deserialization failed for %s: %v", e.EntityType, e.Cause)
}

func (e ErrDeserializationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidEntityID is returned when an entity has an invalid ID.
type ErrInvalidEntityID struct {
	EntityType string
	Reason     string
}

func (e ErrInvalidEntityID) Error() string {
	return fmt.Sprintf("invalid entity ID for %s: %s", e.EntityType, e.Reason)
}

// ErrFactoryClosed is returned when the factory has been closed.
type ErrFactoryClosed struct{}

func (e ErrFactoryClosed) Error() string {
	return "kvstore factory is closed"
}

// ErrTenantStorageInnerNil is returned when a nil inner storage is provided
// to NewTenantStorage.
type ErrTenantStorageInnerNil struct{}

func (e ErrTenantStorageInnerNil) Error() string {
	return "tenant storage: inner storage cannot be nil"
}

// ErrTenantIDEmpty is returned when an empty tenant ID is provided
// to NewTenantStorage.
type ErrTenantIDEmpty struct{}

func (e ErrTenantIDEmpty) Error() string {
	return "tenant storage: tenant ID cannot be empty"
}

// ErrTenantIDInvalid is returned when a tenant ID contains invalid characters.
type ErrTenantIDInvalid struct {
	TenantID string
	Reason   string
}

func (e ErrTenantIDInvalid) Error() string {
	return fmt.Sprintf("tenant storage: invalid tenant ID %q: %s", e.TenantID, e.Reason)
}
