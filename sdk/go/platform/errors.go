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

package platform

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors for common conditions.
var (
	// ErrNilOptions indicates that nil options were provided where required.
	ErrNilOptions = errors.New("options cannot be nil")

	// ErrEmptyAddress indicates that an empty address was provided.
	ErrEmptyAddress = errors.New("address cannot be empty")

	// ErrEmptySocketPath indicates that an empty socket path was provided.
	ErrEmptySocketPath = errors.New("socket path cannot be empty")

	// ErrNotConnected indicates an operation was attempted on a disconnected client.
	ErrNotConnected = errors.New("client is not connected")
)

// ErrConnectionFailed is returned when a connection to the daemon fails.
type ErrConnectionFailed struct {
	Protocol Protocol
	Target   string
	Err      error
}

// Error implements the error interface.
func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("failed to connect via %s to %s: %v", e.Protocol, e.Target, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrDaemonUnavailable is returned when the daemon is not reachable via any protocol.
type ErrDaemonUnavailable struct {
	Attempted []Protocol
	LastErr   error
}

// Error implements the error interface.
func (e ErrDaemonUnavailable) Error() string {
	if len(e.Attempted) == 0 {
		return "daemon unavailable: no protocols attempted"
	}
	protocols := make([]string, len(e.Attempted))
	for i, p := range e.Attempted {
		protocols[i] = p.String()
	}
	return fmt.Sprintf("daemon unavailable: tried protocols [%s], last error: %v",
		strings.Join(protocols, ", "), e.LastErr)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrDaemonUnavailable) Unwrap() error {
	return e.LastErr
}

// ErrProtocolNotSupported is returned when a requested protocol is not supported.
type ErrProtocolNotSupported struct {
	Protocol Protocol
}

// Error implements the error interface.
func (e ErrProtocolNotSupported) Error() string {
	return fmt.Sprintf("protocol not supported: %s", e.Protocol)
}

// ErrProtocolNotImplemented is returned when a protocol is valid but not yet implemented.
type ErrProtocolNotImplemented struct {
	Protocol Protocol
}

// Error implements the error interface.
func (e ErrProtocolNotImplemented) Error() string {
	return fmt.Sprintf("protocol not implemented: %s", e.Protocol)
}

// ErrTimeout is returned when a connection or operation times out.
type ErrTimeout struct {
	Operation string
	Duration  string
}

// Error implements the error interface.
func (e ErrTimeout) Error() string {
	return fmt.Sprintf("operation %s timed out after %s", e.Operation, e.Duration)
}

// ErrInvalidOptions is returned when client options are invalid.
type ErrInvalidOptions struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidOptions) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("invalid options: %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("invalid options: %s", e.Reason)
}

// ErrTLSConfigFailed is returned when TLS configuration fails.
type ErrTLSConfigFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrTLSConfigFailed) Error() string {
	return fmt.Sprintf("failed to configure TLS: %v", e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrTLSConfigFailed) Unwrap() error {
	return e.Err
}

// ErrServiceUnavailable is returned when a specific service client is not available.
type ErrServiceUnavailable struct {
	Service string
}

// Error implements the error interface.
func (e ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("service unavailable: %s", e.Service)
}

// ErrCloseFailed is returned when closing a client connection fails.
type ErrCloseFailed struct {
	Protocol Protocol
	Err      error
}

// Error implements the error interface.
func (e ErrCloseFailed) Error() string {
	return fmt.Sprintf("failed to close %s connection: %v", e.Protocol, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrCloseFailed) Unwrap() error {
	return e.Err
}

// ErrTLSConfigRequired is returned when a TLS configuration is required but not provided.
type ErrTLSConfigRequired struct {
	Protocol Protocol
}

// Error implements the error interface.
func (e ErrTLSConfigRequired) Error() string {
	return fmt.Sprintf("TLS configuration required for %s transport", e.Protocol)
}

// ErrQuicBaaSNotConfigured is returned by Client.QuicBaaS() when the
// platform SDK client was constructed without a QuicBaaSAddr option.
// platformctl barrier verbs require a quicbaas SDK connection; the CLI
// surfaces this error to the operator with guidance on setting
// PLATFORMCTL_QUICBAAS_ADDR or the context's quicbaas_addr field.
type ErrQuicBaaSNotConfigured struct{}

// Error implements the error interface.
func (ErrQuicBaaSNotConfigured) Error() string {
	return "QuicBaaS client is not configured: set platform.WithQuicBaaSAddr or the context's quicbaas_addr field"
}

// ErrQuicBaaSInitFailed is returned when the platform SDK client failed
// to construct the underlying go-quicbaas SDK client (e.g. invalid
// address, unsupported transport).
type ErrQuicBaaSInitFailed struct {
	Addr      string
	Transport string
	Err       error
}

// Error implements the error interface.
func (e ErrQuicBaaSInitFailed) Error() string {
	return fmt.Sprintf("failed to initialize QuicBaaS client (addr=%q, transport=%q): %v",
		e.Addr, e.Transport, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrQuicBaaSInitFailed) Unwrap() error {
	return e.Err
}
