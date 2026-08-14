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

package quicbaas

import "fmt"

// NilStorageError indicates a nil ObjectStorage client was provided to the factory.
type NilStorageError struct{}

func (e NilStorageError) Error() string {
	return "quicbaas: object storage client must not be nil"
}

// StorageOperationError indicates a storage operation failed.
type StorageOperationError struct {
	Op         string
	EntityType string
	Key        string
	Cause      error
}

func (e StorageOperationError) Error() string {
	return fmt.Sprintf("quicbaas: %s failed for %s (key=%s): %v",
		e.Op, e.EntityType, e.Key, e.Cause)
}

func (e StorageOperationError) Unwrap() error {
	return e.Cause
}

// ListOperationError indicates a list operation failed.
type ListOperationError struct {
	EntityType string
	Prefix     string
	Cause      error
}

func (e ListOperationError) Error() string {
	return fmt.Sprintf("quicbaas: list failed for %s (prefix=%s): %v",
		e.EntityType, e.Prefix, e.Cause)
}

func (e ListOperationError) Unwrap() error {
	return e.Cause
}

// InvalidTenantIDError indicates an empty or invalid tenant ID was provided.
type InvalidTenantIDError struct{}

func (e InvalidTenantIDError) Error() string {
	return "quicbaas: tenant ID must not be empty"
}

// TenantDEKProvisionError is returned when DEK provisioning fails during
// tenant creation.
type TenantDEKProvisionError struct {
	TenantID string
	Cause    error
}

func (e TenantDEKProvisionError) Error() string {
	return fmt.Sprintf("quicbaas: failed to provision DEK for tenant %s: %v",
		e.TenantID, e.Cause)
}

func (e TenantDEKProvisionError) Unwrap() error {
	return e.Cause
}

// TenantDEKDeprovisionError is returned when DEK cleanup fails during
// tenant deletion.
type TenantDEKDeprovisionError struct {
	TenantID string
	Cause    error
}

func (e TenantDEKDeprovisionError) Error() string {
	return fmt.Sprintf("quicbaas: failed to deprovision DEK for tenant %s: %v",
		e.TenantID, e.Cause)
}

func (e TenantDEKDeprovisionError) Unwrap() error {
	return e.Cause
}

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

// AtomicWriteUnsupportedError is returned by SaveIfAbsent when the backing
// store cannot perform an atomic create-only write.
//
// The GenericDAO contract is explicit that SaveIfAbsent is the only write with
// a defined outcome under concurrency, and that it must NOT silently degrade to
// a read-then-write (two callers can both observe "absent" and both write, so
// anything requiring exactly-once — consuming a single-use token, claiming a
// unique name — would be silently broken). The QuicBaaS object-storage
// PutObject request carries no if-none-match / create-only precondition, so
// this DAO fails closed here instead of pretending to be atomic.
type AtomicWriteUnsupportedError struct {
	// EntityType is the DAO entity type the call was made against.
	EntityType string
}

// Error implements the error interface.
func (e AtomicWriteUnsupportedError) Error() string {
	return "acme storage: " + e.EntityType +
		": underlying object storage does not support atomic conditional writes (SaveIfAbsent)"
}
