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

// ErrInvalidConfig is returned when configuration validation fails.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid configuration: %s: %s", e.Field, e.Reason)
}

// ErrInvalidTransport is returned when an invalid transport string is provided.
type ErrInvalidTransport struct {
	Value string
}

func (e ErrInvalidTransport) Error() string {
	return fmt.Sprintf("invalid transport: %q (valid values: embedded, unix, grpc, rest, quic)", e.Value)
}

// ErrServerNotStarted is returned when operations are attempted before the server is started.
type ErrServerNotStarted struct{}

func (e ErrServerNotStarted) Error() string {
	return "quicbaas server not started"
}

// ErrServerClosed is returned when operations are attempted after the server is closed.
type ErrServerClosed struct{}

func (e ErrServerClosed) Error() string {
	return "quicbaas server is closed"
}

// ErrConnectionFailed is returned when connection to QuicBaaS fails.
type ErrConnectionFailed struct {
	Cause error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("quicbaas connection failed: %v", e.Cause)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrOperationFailed is returned when a database operation fails.
type ErrOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrOperationFailed) Error() string {
	return fmt.Sprintf("quicbaas operation failed: %s: %v", e.Operation, e.Cause)
}

func (e ErrOperationFailed) Unwrap() error {
	return e.Cause
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

// ErrTimeout is returned when an operation times out.
type ErrTimeout struct {
	Operation string
}

func (e ErrTimeout) Error() string {
	return fmt.Sprintf("quicbaas operation timed out: %s", e.Operation)
}

// ErrRaftNotReady is returned when Raft consensus is not ready.
type ErrRaftNotReady struct {
	Reason string
}

func (e ErrRaftNotReady) Error() string {
	return fmt.Sprintf("raft not ready: %s", e.Reason)
}

// ErrFactoryClosed is returned when the factory has been closed.
type ErrFactoryClosed struct{}

func (e ErrFactoryClosed) Error() string {
	return "quicbaas factory is closed"
}

// ErrSDKClientClosed is returned when operations are attempted on a closed SDK client.
type ErrSDKClientClosed struct{}

func (e ErrSDKClientClosed) Error() string {
	return "quicbaas SDK client is closed"
}

// ErrSDKClientNotInitialized is returned when the SDK client is not initialized.
type ErrSDKClientNotInitialized struct{}

func (e ErrSDKClientNotInitialized) Error() string {
	return "quicbaas SDK client is not initialized"
}

// ErrUnsupportedTransport is returned when an unsupported transport is requested.
type ErrUnsupportedTransport struct {
	Transport Transport
}

func (e ErrUnsupportedTransport) Error() string {
	return fmt.Sprintf("unsupported transport: %s", e.Transport)
}

// ErrEmbeddedServiceRequired is returned when embedded transport is used without a service.
type ErrEmbeddedServiceRequired struct{}

func (e ErrEmbeddedServiceRequired) Error() string {
	return "embedded transport requires a QuicBaaS service instance"
}

// ErrSDKClientNil is returned when a nil SDK client is provided.
type ErrSDKClientNil struct{}

func (e ErrSDKClientNil) Error() string {
	return "quicbaas SDK client cannot be nil"
}

// ErrStorageClosed is returned when storage operations are attempted after close.
type ErrStorageClosed struct{}

func (e ErrStorageClosed) Error() string {
	return "quicbaas storage is closed"
}

// ErrStorageNotStarted is returned when storage operations are attempted before start.
type ErrStorageNotStarted struct{}

func (e ErrStorageNotStarted) Error() string {
	return "quicbaas storage not started"
}

// ErrContextCancelled is returned when an operation is attempted with a cancelled
// or expired context.
type ErrContextCancelled struct {
	Operation string
	Cause     error
}

func (e ErrContextCancelled) Error() string {
	return fmt.Sprintf("context cancelled for operation %s: %v", e.Operation, e.Cause)
}

func (e ErrContextCancelled) Unwrap() error {
	return e.Cause
}
