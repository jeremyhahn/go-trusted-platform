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

package caquicbaas

import "fmt"

// ErrAdapterNotInitialized indicates the adapter was used before proper initialization.
// This error is returned when operations are attempted on an adapter that has not
// been initialized with the required dependencies.
type ErrAdapterNotInitialized struct{}

func (e ErrAdapterNotInitialized) Error() string {
	return "caquicbaas: adapter not initialized"
}

// ErrKeyConversionFailed indicates that a string key could not be converted to a uint64 ID.
// QuicBaaS uses uint64 identifiers internally, so string keys must be convertible.
type ErrKeyConversionFailed struct {
	Key   string
	Cause error
}

func (e ErrKeyConversionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("caquicbaas: failed to convert key %q to uint64: %v", e.Key, e.Cause)
	}
	return fmt.Sprintf("caquicbaas: failed to convert key %q to uint64", e.Key)
}

func (e ErrKeyConversionFailed) Unwrap() error {
	return e.Cause
}

// ErrUnsupportedOperation indicates that the requested operation is not supported
// by the QuicBaaS adapter. This may occur when the adapter does not implement
// certain optional interface methods or when integration with additional services
// is required.
type ErrUnsupportedOperation struct {
	Operation string
	Reason    string
}

func (e ErrUnsupportedOperation) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("caquicbaas: unsupported operation: %s: %s", e.Operation, e.Reason)
	}
	return fmt.Sprintf("caquicbaas: unsupported operation: %s", e.Operation)
}

// ErrQuicBaaSUnavailable indicates that the QuicBaaS service is nil or unavailable.
// This error is returned when the adapter cannot access the underlying QuicBaaS instance.
type ErrQuicBaaSUnavailable struct {
	Cause error
}

func (e ErrQuicBaaSUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("caquicbaas: quicbaas service unavailable: %v", e.Cause)
	}
	return "caquicbaas: quicbaas service unavailable"
}

func (e ErrQuicBaaSUnavailable) Unwrap() error {
	return e.Cause
}

// ErrInvalidInput indicates that input validation failed.
type ErrInvalidInput struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidInput) Error() string {
	return fmt.Sprintf("caquicbaas: invalid input: %s: %s", e.Field, e.Reason)
}

// ErrKeyNotFound indicates that a requested key does not exist.
type ErrKeyNotFound struct {
	KeyID string
	Cause error
}

// Error implements the error interface.
func (e ErrKeyNotFound) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("caquicbaas: key not found: %s: %v", e.KeyID, e.Cause)
	}
	return fmt.Sprintf("caquicbaas: key not found: %s", e.KeyID)
}

// Unwrap returns the underlying cause.
func (e ErrKeyNotFound) Unwrap() error {
	return e.Cause
}

// ErrKeyDisabled indicates that a key exists but is disabled.
type ErrKeyDisabled struct {
	KeyID string
}

// Error implements the error interface.
func (e ErrKeyDisabled) Error() string {
	return fmt.Sprintf("caquicbaas: key is disabled: %s", e.KeyID)
}

// ErrOperationFailed indicates that a KMS operation failed.
type ErrOperationFailed struct {
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e ErrOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("caquicbaas: KMS operation failed: %s: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("caquicbaas: KMS operation failed: %s", e.Operation)
}

// Unwrap returns the underlying cause.
func (e ErrOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrTenantMismatch indicates that a key does not belong to the expected tenant.
type ErrTenantMismatch struct {
	ExpectedTenant string
	ActualTenant   string
}

// Error implements the error interface.
func (e ErrTenantMismatch) Error() string {
	return fmt.Sprintf("caquicbaas: tenant mismatch: expected %s, got %s", e.ExpectedTenant, e.ActualTenant)
}

// ErrOperationNotSupported indicates that an operation is not supported by this adapter.
// Certificate operations are not supported by the KMS adapter - use cluster storage instead.
type ErrOperationNotSupported struct {
	Operation string
}

// Error implements the error interface.
func (e ErrOperationNotSupported) Error() string {
	return fmt.Sprintf("caquicbaas: operation not supported: %s (use cluster storage for certificates)", e.Operation)
}

// ErrCertNotFound indicates that a requested certificate does not exist.
type ErrCertNotFound struct {
	CertID string
	Cause  error
}

// Error implements the error interface.
func (e ErrCertNotFound) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("caquicbaas: certificate not found: %s: %v", e.CertID, e.Cause)
	}
	return fmt.Sprintf("caquicbaas: certificate not found: %s", e.CertID)
}

// Unwrap returns the underlying cause.
func (e ErrCertNotFound) Unwrap() error {
	return e.Cause
}
