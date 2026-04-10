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

package ca

import (
	"fmt"
)

// Sentinel errors for adapter operations.
var (
	// ErrNilConfig is returned when a nil configuration is provided.
	ErrNilConfig = &AdapterError{Op: "NewAdapter", Msg: "configuration cannot be nil"}

	// ErrNilLogger is returned when a nil logger is provided.
	ErrNilLogger = &AdapterError{Op: "NewAdapter", Msg: "logger cannot be nil"}

	// ErrAdapterClosed is returned when an operation is attempted on a closed adapter.
	ErrAdapterClosed = &AdapterError{Op: "operation", Msg: "adapter is closed"}

	// ErrAdapterNotStarted is returned when an operation requires a started adapter.
	ErrAdapterNotStarted = &AdapterError{Op: "operation", Msg: "adapter not started"}

	// ErrEmbeddedServiceRequired is returned when embedded mode is used without a CA service.
	ErrEmbeddedServiceRequired = &AdapterError{Op: "createEmbeddedClient", Msg: "embedded CA service is required for embedded mode"}

	// ErrMissingUnixSocket is returned when Unix transport is used without a socket path.
	ErrMissingUnixSocket = &AdapterError{Op: "validate", Msg: "unix_socket is required for unix transport"}

	// ErrMissingAddress is returned when a remote transport is used without an address.
	ErrMissingAddress = &AdapterError{Op: "validate", Msg: "address is required for remote transport"}

	// ErrMissingTLSCACert is returned when a remote transport is used without a TLS CA certificate.
	ErrMissingTLSCACert = &AdapterError{Op: "validate", Msg: "tls.ca_cert is required for remote transport"}

	// ErrCANotInitialized is returned when the CA has not been initialized.
	ErrCANotInitialized = &AdapterError{Op: "CA", Msg: "certificate authority not initialized"}

	// ErrACMENotInitialized is returned when the ACME service has not been initialized.
	ErrACMENotInitialized = &AdapterError{Op: "ACME", Msg: "ACME service not initialized"}
)

// AdapterError represents an error in the CA adapter.
type AdapterError struct {
	Op    string // Operation that failed
	Msg   string // Error message
	Cause error  // Underlying error
}

// Error returns the error message.
func (e *AdapterError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ca adapter %s: %s: %v", e.Op, e.Msg, e.Cause)
	}
	return fmt.Sprintf("ca adapter %s: %s", e.Op, e.Msg)
}

// Unwrap returns the underlying error.
func (e *AdapterError) Unwrap() error {
	return e.Cause
}

// WithCause returns a new error with the given cause.
func (e *AdapterError) WithCause(cause error) *AdapterError {
	return &AdapterError{
		Op:    e.Op,
		Msg:   e.Msg,
		Cause: cause,
	}
}

// ErrUnsupportedTransport is returned when an unsupported transport is specified.
type ErrUnsupportedTransport struct {
	Transport Transport
}

// Error returns the error message.
func (e ErrUnsupportedTransport) Error() string {
	return fmt.Sprintf("ca adapter: unsupported transport: %s", e.Transport)
}

// ErrConnectionFailed is returned when the adapter fails to connect.
type ErrConnectionFailed struct {
	Address   string
	Transport Transport
	Cause     error
}

// Error returns the error message.
func (e ErrConnectionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ca adapter: connection failed to %s via %s: %v",
			e.Address, e.Transport, e.Cause)
	}
	return fmt.Sprintf("ca adapter: connection failed to %s via %s",
		e.Address, e.Transport)
}

// Unwrap returns the underlying error.
func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrServiceUnavailable is returned when a service client is not available.
type ErrServiceUnavailable struct {
	Service string
}

// Error returns the error message.
func (e ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("ca adapter: service unavailable: %s", e.Service)
}

// ErrBackendNotFound is returned when a referenced backend is not found.
type ErrBackendNotFound struct {
	Backend string
}

// Error returns the error message.
func (e ErrBackendNotFound) Error() string {
	return fmt.Sprintf("ca adapter: backend not found: %s", e.Backend)
}

// ErrCertificateNotFound is returned when a certificate cannot be found.
type ErrCertificateNotFound struct {
	CN string
}

// Error returns the error message.
func (e ErrCertificateNotFound) Error() string {
	return fmt.Sprintf("ca adapter: certificate not found: %s", e.CN)
}

// ErrSigningFailed is returned when certificate signing fails.
type ErrSigningFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrSigningFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ca adapter: signing failed: %v", e.Cause)
	}
	return "ca adapter: signing failed"
}

// Unwrap returns the underlying error.
func (e ErrSigningFailed) Unwrap() error {
	return e.Cause
}

// ErrRevocationFailed is returned when certificate revocation fails.
type ErrRevocationFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrRevocationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ca adapter: revocation failed: %v", e.Cause)
	}
	return "ca adapter: revocation failed"
}

// Unwrap returns the underlying error.
func (e ErrRevocationFailed) Unwrap() error {
	return e.Cause
}

// ErrVerificationFailed is returned when certificate verification fails.
type ErrVerificationFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrVerificationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ca adapter: verification failed: %v", e.Cause)
	}
	return "ca adapter: verification failed"
}

// Unwrap returns the underlying error.
func (e ErrVerificationFailed) Unwrap() error {
	return e.Cause
}
