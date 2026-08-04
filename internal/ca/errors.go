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

	"github.com/jeremyhahn/go-trusted-platform/internal/adapters"
)

// Sentinel errors for adapter operations.
var (
	// ErrNilConfig is returned when a nil configuration is provided.
	ErrNilConfig = newAdapterError("NewAdapter", "configuration cannot be nil")

	// ErrNilLogger is returned when a nil logger is provided.
	ErrNilLogger = newAdapterError("NewAdapter", "logger cannot be nil")

	// ErrAdapterClosed is returned when an operation is attempted on a closed adapter.
	ErrAdapterClosed = newAdapterError("operation", "adapter is closed")

	// ErrAdapterNotStarted is returned when an operation requires a started adapter.
	ErrAdapterNotStarted = newAdapterError("operation", "adapter not started")

	// ErrEmbeddedServiceRequired is returned when embedded mode is used without a CA service.
	ErrEmbeddedServiceRequired = newAdapterError("createEmbeddedClient", "embedded CA service is required for embedded mode")

	// ErrMissingUnixSocket is returned when Unix transport is used without a socket path.
	ErrMissingUnixSocket = newAdapterError("validate", "unix_socket is required for unix transport")

	// ErrMissingAddress is returned when a remote transport is used without an address.
	ErrMissingAddress = newAdapterError("validate", "address is required for remote transport")

	// ErrMissingTLSCACert is returned when a remote transport is used without a TLS CA certificate.
	ErrMissingTLSCACert = newAdapterError("validate", "tls.ca_cert is required for remote transport")

	// ErrCANotInitialized is returned when the CA has not been initialized.
	ErrCANotInitialized = newAdapterError("CA", "certificate authority not initialized")

	// ErrACMENotInitialized is returned when the ACME service has not been initialized.
	ErrACMENotInitialized = newAdapterError("ACME", "ACME service not initialized")

	// ErrNilRequest is returned when a required request argument is nil.
	ErrNilRequest = newAdapterError("operation", "request cannot be nil")

	// ErrNilCertificate is returned when a required certificate argument is nil.
	ErrNilCertificate = newAdapterError("operation", "certificate cannot be nil")
)

// AdapterError is the shared transport adapter error type. Construct it
// via newAdapterError so the component prefix is always stamped.
type AdapterError = adapters.AdapterError

// adapterComponent is the prefix rendered in this adapter's error strings.
const adapterComponent = "ca"

// newAdapterError builds an AdapterError stamped with this adapter's component.
func newAdapterError(op, msg string) *AdapterError {
	return &AdapterError{Component: adapterComponent, Op: op, Msg: msg}
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
