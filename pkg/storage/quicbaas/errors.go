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
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// ErrNotFound is returned when an entity is not found in the database.
type ErrNotFound struct {
	EntityType string
	ID         uint64
}

func (e ErrNotFound) Error() string {
	return fmt.Sprintf("entity not found: type=%s, id=%d", e.EntityType, e.ID)
}

// Is reports the error as datastore.ErrRecordNotFound, the miss every
// datastore Get returns, so a caller classifies it without knowing the store.
func (e ErrNotFound) Is(target error) bool {
	return target == datastore.ErrRecordNotFound
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

// Is reports the error as datastore.ErrRecordNotFound, as ErrNotFound does.
func (e ErrNotFoundByIndex) Is(target error) bool {
	return target == datastore.ErrRecordNotFound
}

// ErrInvalidConfig is returned when configuration validation fails.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid configuration: %s: %s", e.Field, e.Reason)
}

// ErrVectorUnavailable is returned by every Vector call when the embedded
// server serves no vector service, instead of the transport's bare
// "unimplemented". Reason says whether the build lacks the service or the
// configuration leaves it disabled.
type ErrVectorUnavailable struct {
	Reason string
}

func (e ErrVectorUnavailable) Error() string {
	return fmt.Sprintf("vector service unavailable: %s", e.Reason)
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

// ErrStartupCanceled reports that the CALLER's context ended before the
// embedded server finished starting. It is deliberately distinct from
// ErrStartupTimeout: the two have different causes and different fixes, and
// collapsing them into one message is what made #270 read as a budget
// problem when the caller's deadline was the binding constraint.
type ErrStartupCanceled struct {
	// Elapsed is how long startup had been running when the context ended.
	Elapsed time.Duration
	// Cause is the context's own error (deadline exceeded, or canceled).
	Cause error
}

func (e ErrStartupCanceled) Error() string {
	return fmt.Sprintf(
		"embedded server startup was cut short after %s by the calling context (%v); "+
			"the server had not reported a failure — give Start a context that allows for first-boot work",
		e.Elapsed.Round(time.Millisecond), e.Cause)
}

func (e ErrStartupCanceled) Unwrap() error { return e.Cause }

// ErrStartupTimeout reports that the embedded server did not report itself
// started within its own startup budget. It names the budget so the reader
// is sent to the thing that actually expired.
type ErrStartupTimeout struct {
	// Budget is the startup budget that expired.
	Budget time.Duration
}

func (e ErrStartupTimeout) Error() string {
	return fmt.Sprintf(
		"embedded server did not report started within its %s startup budget "+
			"(startup-timeout); first boot constructs the barrier, opens the TPM and seeds IAM, "+
			"so a loaded host may need more than the default",
		e.Budget)
}

// ErrRaftNotReady is returned when Raft consensus is not ready.
type ErrRaftNotReady struct {
	Reason string
}

func (e ErrRaftNotReady) Error() string {
	return fmt.Sprintf("raft not ready: %s", e.Reason)
}

// ErrRaftAdvertiseAddress is returned when a node that joins peers has no
// routable Raft advertise address. Peers dial the advertised address, so a
// loopback, unspecified or empty quicbaas.raft-address would publish a peer
// nobody can reach; the node refuses to start instead.
type ErrRaftAdvertiseAddress struct {
	Address string
}

func (e ErrRaftAdvertiseAddress) Error() string {
	return fmt.Sprintf("quicbaas.raft-address %q is not routable: a node with join-addresses must advertise an address its peers can dial (set quicbaas.raft-address, PLATFORMD_QUICBAAS_RAFT_ADDRESS or --raft-address)", e.Address)
}

// ErrRaftPeerAddress is returned when a quicbaas.join-addresses entry is not
// in go-quicbaas's "id=host:port" member form. go-quicbaas silently drops an
// entry without an id, so a bare "host:port" would leave the node clustered
// with no peers; it is refused here instead.
type ErrRaftPeerAddress struct {
	Entry  string
	Reason string
}

func (e ErrRaftPeerAddress) Error() string {
	return fmt.Sprintf("quicbaas.join-addresses entry %q is not \"id=host:port\": %s", e.Entry, e.Reason)
}

// ErrRaftDuplicatePeer is returned when two quicbaas.join-addresses entries
// carry the same node ID. Every cluster member needs its own ID.
type ErrRaftDuplicatePeer struct {
	NodeID uint64
}

func (e ErrRaftDuplicatePeer) Error() string {
	return fmt.Sprintf("quicbaas.join-addresses lists node ID %d more than once", e.NodeID)
}

// ErrRaftSelfPeer is returned when a clustered node's own member entry is
// missing from quicbaas.join-addresses or names an address other than its
// quicbaas.raft-address. A bootstrapping member must be in the member list,
// at the address its peers dial.
type ErrRaftSelfPeer struct {
	NodeID      uint64
	RaftAddress string
}

func (e ErrRaftSelfPeer) Error() string {
	return fmt.Sprintf("quicbaas.join-addresses must list this node as \"%d=%s\" (quicbaas.node-id=quicbaas.raft-address)", e.NodeID, e.RaftAddress)
}

// ErrRaftClusterField is returned when a clustered node leaves a field the
// cluster cannot form without at its zero value.
type ErrRaftClusterField struct {
	Field  string
	Reason string
}

func (e ErrRaftClusterField) Error() string {
	return fmt.Sprintf("quicbaas.%s is required with join-addresses: %s", e.Field, e.Reason)
}

// ErrRaftTLSRequired is returned when a clustered node does not name all
// three Raft TLS files. Raft traffic between peers is always mutually
// authenticated TLS; the platform never lets a cluster form in plaintext or
// on material it did not supply.
type ErrRaftTLSRequired struct {
	Missing []string
}

func (e ErrRaftTLSRequired) Error() string {
	return fmt.Sprintf("Raft TLS between peers is required with join-addresses: set %s", strings.Join(e.Missing, ", "))
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
