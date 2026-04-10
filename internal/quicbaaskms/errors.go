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

package quicbaaskms

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

// AdapterError represents an error in the QuicBaaS KMS adapter.
type AdapterError struct {
	Op    string // Operation that failed
	Msg   string // Error message
	Cause error  // Underlying error
}

// Error returns the error message.
func (e *AdapterError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter %s: %s: %v", e.Op, e.Msg, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter %s: %s", e.Op, e.Msg)
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
	return fmt.Sprintf("quicbaaskms adapter: unsupported transport: %s", e.Transport)
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
		return fmt.Sprintf("quicbaaskms adapter: connection failed to %s via %s: %v",
			e.Address, e.Transport, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: connection failed to %s via %s",
		e.Address, e.Transport)
}

// Unwrap returns the underlying error.
func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrKeyNotFound is returned when a key is not found.
type ErrKeyNotFound struct {
	KeyID string
}

// Error returns the error message.
func (e ErrKeyNotFound) Error() string {
	return fmt.Sprintf("quicbaaskms adapter: key not found: %s", e.KeyID)
}

// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is specified.
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
}

// Error returns the error message.
func (e ErrInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("quicbaaskms adapter: invalid key algorithm: %s", e.Algorithm)
}

// ErrSigningFailed is returned when a signing operation fails.
type ErrSigningFailed struct {
	KeyID string
	Cause error
}

// Error returns the error message.
func (e ErrSigningFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: signing failed for key %s: %v", e.KeyID, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: signing failed for key %s", e.KeyID)
}

// Unwrap returns the underlying error.
func (e ErrSigningFailed) Unwrap() error {
	return e.Cause
}

// ErrVerificationFailed is returned when a verification operation fails.
type ErrVerificationFailed struct {
	KeyID string
	Cause error
}

// Error returns the error message.
func (e ErrVerificationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: verification failed for key %s: %v", e.KeyID, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: verification failed for key %s", e.KeyID)
}

// Unwrap returns the underlying error.
func (e ErrVerificationFailed) Unwrap() error {
	return e.Cause
}

// ErrEncryptionFailed is returned when an encryption operation fails.
type ErrEncryptionFailed struct {
	KeyID string
	Cause error
}

// Error returns the error message.
func (e ErrEncryptionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: encryption failed for key %s: %v", e.KeyID, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: encryption failed for key %s", e.KeyID)
}

// Unwrap returns the underlying error.
func (e ErrEncryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrDecryptionFailed is returned when a decryption operation fails.
type ErrDecryptionFailed struct {
	KeyID string
	Cause error
}

// Error returns the error message.
func (e ErrDecryptionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: decryption failed for key %s: %v", e.KeyID, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: decryption failed for key %s", e.KeyID)
}

// Unwrap returns the underlying error.
func (e ErrDecryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrKeyGenerationFailed is returned when key generation fails.
type ErrKeyGenerationFailed struct {
	Name  string
	Cause error
}

// Error returns the error message.
func (e ErrKeyGenerationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: key generation failed for %s: %v", e.Name, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: key generation failed for %s", e.Name)
}

// Unwrap returns the underlying error.
func (e ErrKeyGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrKeyDeletionFailed is returned when key deletion fails.
type ErrKeyDeletionFailed struct {
	KeyID string
	Cause error
}

// Error returns the error message.
func (e ErrKeyDeletionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: key deletion failed for %s: %v", e.KeyID, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: key deletion failed for %s", e.KeyID)
}

// Unwrap returns the underlying error.
func (e ErrKeyDeletionFailed) Unwrap() error {
	return e.Cause
}

// ErrKeyRotationFailed is returned when key rotation fails.
type ErrKeyRotationFailed struct {
	KeyID string
	Cause error
}

// Error returns the error message.
func (e ErrKeyRotationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: key rotation failed for %s: %v", e.KeyID, e.Cause)
	}
	return fmt.Sprintf("quicbaaskms adapter: key rotation failed for %s", e.KeyID)
}

// Unwrap returns the underlying error.
func (e ErrKeyRotationFailed) Unwrap() error {
	return e.Cause
}

// ErrHealthCheckFailed is returned when a health check fails.
type ErrHealthCheckFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrHealthCheckFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("quicbaaskms adapter: health check failed: %v", e.Cause)
	}
	return "quicbaaskms adapter: health check failed"
}

// Unwrap returns the underlying error.
func (e ErrHealthCheckFailed) Unwrap() error {
	return e.Cause
}
