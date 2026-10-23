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
	"time"
)

// Sentinel errors for common conditions.
var (
	// ErrNilOptions indicates that nil options were provided where required.
	ErrNilOptions = errors.New("options cannot be nil")

	// ErrEmptyAddress indicates that an empty address was provided.
	ErrEmptyAddress = errors.New("address cannot be empty")

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

// ErrProtocolNotSupported is returned when a transport name is not one the
// QuicBaaS side-client can dial, rather than silently auto-detecting.
type ErrProtocolNotSupported struct {
	Transport string
}

// Error implements the error interface.
func (e ErrProtocolNotSupported) Error() string {
	return fmt.Sprintf("protocol not supported: %q (want unix, grpc, rest, quic or mcp)", e.Transport)
}

// ErrProtocolNotImplemented is returned when a protocol is valid but not yet implemented.
type ErrProtocolNotImplemented struct {
	Protocol Protocol
}

// Error implements the error interface.
func (e ErrProtocolNotImplemented) Error() string {
	return fmt.Sprintf("protocol not implemented: %s", e.Protocol)
}

// ErrTimeout is returned, inside ErrConnectionFailed, when a connect-time
// exchange with the daemon runs out of time: a context deadline or a network
// timeout.
type ErrTimeout struct {
	Operation string
	Elapsed   time.Duration
	Err       error
}

// Error implements the error interface.
func (e ErrTimeout) Error() string {
	return fmt.Sprintf("%s timed out after %s: %v", e.Operation, e.Elapsed, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrTimeout) Unwrap() error {
	return e.Err
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

// ErrInsecureTransport is returned when a connection would travel over
// plaintext HTTP and that is not acceptable: the server only offers TLS, or
// the caller set a bearer token or TLS options that plaintext would leak or
// silently drop.
type ErrInsecureTransport struct {
	Protocol Protocol
	Target   string
	Reason   string
}

// Error implements the error interface.
func (e ErrInsecureTransport) Error() string {
	return fmt.Sprintf("refusing plaintext %s connection to %s: %s", e.Protocol, e.Target, e.Reason)
}

// ErrUnsupportedOption is returned when a transport cannot honour a
// connection option the caller set, rather than silently ignoring it.
type ErrUnsupportedOption struct {
	Protocol Protocol
	Option   string
	Reason   string
}

// Error implements the error interface.
func (e ErrUnsupportedOption) Error() string {
	return fmt.Sprintf("%s transport does not support %s: %s", e.Protocol, e.Option, e.Reason)
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

// ErrQuicBaaSTLSNotConfigured is the cause ErrQuicBaaSInitFailed wraps
// when the platform SDK client was given a QuicBaaSAddr without
// WithQuicBaaSTLSConfig. The go-quicbaas SDK refuses every connection
// without TLS, the Unix transport included, and has no insecure mode.
type ErrQuicBaaSTLSNotConfigured struct{}

// Error implements the error interface.
func (ErrQuicBaaSTLSNotConfigured) Error() string {
	return "QuicBaaS connection has no TLS configuration: set platform.WithQuicBaaSTLSConfig, or the context's TLS files (local: quicbaas_ca_cert, quicbaas_client_cert, quicbaas_client_key; remote: ca_cert, client_cert, client_key)"
}
