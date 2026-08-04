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

	// ErrEmbeddedServiceRequired is returned when embedded mode is used without a service.
	ErrEmbeddedServiceRequired = newAdapterError("createEmbeddedClient", "embedded service is required for embedded mode")

	// ErrMissingUnixSocket is returned when Unix transport is used without a socket path.
	ErrMissingUnixSocket = newAdapterError("validate", "unix_socket is required for unix transport")

	// ErrMissingAddress is returned when a remote transport is used without an address.
	ErrMissingAddress = newAdapterError("validate", "address is required for remote transport")

	// ErrMissingTLSCACert is returned when a remote transport is used without a TLS CA certificate.
	ErrMissingTLSCACert = newAdapterError("validate", "tls.ca_cert is required for remote transport")
)

// AdapterError is the shared transport adapter error type. Construct it
// via newAdapterError so the component prefix is always stamped.
type AdapterError = adapters.AdapterError

// adapterComponent is the prefix rendered in this adapter's error strings.
const adapterComponent = "quicbaas"

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
