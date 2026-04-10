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

	// ErrEmbeddedServiceRequired is returned when embedded mode is used without a service.
	ErrEmbeddedServiceRequired = &AdapterError{Op: "createEmbeddedClient", Msg: "embedded service is required for embedded mode"}

	// ErrMissingUnixSocket is returned when Unix transport is used without a socket path.
	ErrMissingUnixSocket = &AdapterError{Op: "validate", Msg: "unix_socket is required for unix transport"}

	// ErrMissingAddress is returned when a remote transport is used without an address.
	ErrMissingAddress = &AdapterError{Op: "validate", Msg: "address is required for remote transport"}

	// ErrMissingTLSCACert is returned when a remote transport is used without a TLS CA certificate.
	ErrMissingTLSCACert = &AdapterError{Op: "validate", Msg: "tls.ca_cert is required for remote transport"}
)

// AdapterError represents an error in the QuicBaaS adapter.
type AdapterError struct {
	Op    string // Operation that failed
	Msg   string // Error message
	Cause error  // Underlying error
}

// Error returns the error message.
func (e *AdapterError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaas adapter %s: %s: %v", e.Op, e.Msg, e.Cause)
	}
	return fmt.Sprintf("quicbaas adapter %s: %s", e.Op, e.Msg)
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
	return fmt.Sprintf("quicbaas adapter: unsupported transport: %s", e.Transport)
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
		return fmt.Sprintf("quicbaas adapter: connection failed to %s via %s: %v",
			e.Address, e.Transport, e.Cause)
	}
	return fmt.Sprintf("quicbaas adapter: connection failed to %s via %s",
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
	return fmt.Sprintf("quicbaas adapter: service unavailable: %s", e.Service)
}

// ErrBackendNotFound is returned when a referenced backend is not found.
type ErrBackendNotFound struct {
	Backend string
}

// Error returns the error message.
func (e ErrBackendNotFound) Error() string {
	return fmt.Sprintf("quicbaas adapter: backend not found: %s", e.Backend)
}

// ErrSecretResolutionFailed is returned when a secret cannot be resolved.
type ErrSecretResolutionFailed struct {
	URI   string
	Cause error
}

// Error returns the error message.
func (e ErrSecretResolutionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaas adapter: secret resolution failed for %s: %v", e.URI, e.Cause)
	}
	return fmt.Sprintf("quicbaas adapter: secret resolution failed for %s", e.URI)
}

// Unwrap returns the underlying error.
func (e ErrSecretResolutionFailed) Unwrap() error {
	return e.Cause
}
