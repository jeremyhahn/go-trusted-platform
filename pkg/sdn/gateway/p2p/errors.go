//go:build platform_p2p

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

package p2p

import (
	"fmt"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Sentinel errors for p2p operations.
var (
	// ErrNodeNotStarted is returned when operations require a started node.
	ErrNodeNotStarted = &errNodeNotStarted{}

	// ErrNodeAlreadyStarted is returned when Start is called on a running node.
	ErrNodeAlreadyStarted = &errNodeAlreadyStarted{}

	// ErrAlreadyRunning is returned when attempting to start an already running node.
	ErrAlreadyRunning = &errAlreadyRunning{}

	// ErrNotRunning is returned when operations are attempted on a stopped node.
	ErrNotRunning = &errNotRunning{}

	// ErrConfigNil is returned when a nil configuration is provided.
	ErrConfigNil = &errConfigNil{}

	// ErrDHTNotReady is returned when the DHT is not yet bootstrapped.
	ErrDHTNotReady = &errDHTNotReady{}

	// ErrPeerNotFound is returned when a peer cannot be found.
	ErrPeerNotFound = &errPeerNotFound{}

	// ErrProvidersNotFound is returned when no providers are found for a key.
	ErrProvidersNotFound = &errProvidersNotFound{}

	// ErrPrivateKeyNil is returned when a nil private key is provided.
	ErrPrivateKeyNil = &errPrivateKeyNil{}

	// ErrLoggerNil is returned when a nil logger is provided.
	ErrLoggerNil = &errLoggerNil{}

	// ErrMDNSNotEnabled is returned when mDNS operations are attempted but mDNS is disabled.
	ErrMDNSNotEnabled = &errMDNSNotEnabled{}

	// ErrShutdownInProgress is returned when operations are attempted during shutdown.
	ErrShutdownInProgress = &errShutdownInProgress{}

	// ErrDeviceIDRequired is returned when a device ID is required but not provided.
	ErrDeviceIDRequired = &errDeviceIDRequired{}

	// ErrNodeIDRequired is returned when a node ID is required but not provided.
	ErrNodeIDRequired = &errNodeIDRequired{}

	// ErrPeerIDRequired is returned when a peer ID is required but not provided.
	ErrPeerIDRequired = &errPeerIDRequired{}
)

type errNodeNotStarted struct{}

func (e *errNodeNotStarted) Error() string { return "p2p node not started" }

type errNodeAlreadyStarted struct{}

func (e *errNodeAlreadyStarted) Error() string { return "p2p node already started" }

type errAlreadyRunning struct{}

func (e *errAlreadyRunning) Error() string { return "node already running" }

type errNotRunning struct{}

func (e *errNotRunning) Error() string { return "node not running" }

type errConfigNil struct{}

func (e *errConfigNil) Error() string { return "configuration is nil" }

type errDHTNotReady struct{}

func (e *errDHTNotReady) Error() string { return "DHT not ready" }

type errPeerNotFound struct{}

func (e *errPeerNotFound) Error() string { return "peer not found" }

type errProvidersNotFound struct{}

func (e *errProvidersNotFound) Error() string { return "no providers found" }

type errPrivateKeyNil struct{}

func (e *errPrivateKeyNil) Error() string { return "private key is nil" }

type errLoggerNil struct{}

func (e *errLoggerNil) Error() string { return "logger is nil" }

type errMDNSNotEnabled struct{}

func (e *errMDNSNotEnabled) Error() string { return "mDNS is not enabled" }

type errShutdownInProgress struct{}

func (e *errShutdownInProgress) Error() string { return "shutdown in progress" }

type errDeviceIDRequired struct{}

func (e *errDeviceIDRequired) Error() string { return "device ID required" }

type errNodeIDRequired struct{}

func (e *errNodeIDRequired) Error() string { return "node ID required" }

type errPeerIDRequired struct{}

func (e *errPeerIDRequired) Error() string { return "peer ID required" }

// ErrInvalidConfigField is returned when a configuration field is invalid.
type ErrInvalidConfigField struct {
	Field  string
	Reason string
}

func (e *ErrInvalidConfigField) Error() string {
	return fmt.Sprintf("invalid configuration field %q: %s", e.Field, e.Reason)
}

// ErrNodeInitFailed is returned when node initialization fails.
type ErrNodeInitFailed struct {
	Component string
	Cause     error
}

func (e *ErrNodeInitFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to initialize %s: %v", e.Component, e.Cause)
	}
	return fmt.Sprintf("failed to initialize %s", e.Component)
}

func (e *ErrNodeInitFailed) Unwrap() error {
	return e.Cause
}

// ErrNodeStopFailed is returned when stopping a component fails.
type ErrNodeStopFailed struct {
	Component string
	Cause     error
}

func (e *ErrNodeStopFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to stop %s: %v", e.Component, e.Cause)
	}
	return fmt.Sprintf("failed to stop %s", e.Component)
}

func (e *ErrNodeStopFailed) Unwrap() error {
	return e.Cause
}

// ErrBootstrapFailed is returned when bootstrap fails.
type ErrBootstrapFailed struct {
	Peer  string
	Cause error
}

func (e *ErrBootstrapFailed) Error() string {
	if e.Cause != nil {
		if e.Peer != "" {
			return fmt.Sprintf("bootstrap failed for peer %s: %v", e.Peer, e.Cause)
		}
		return fmt.Sprintf("DHT bootstrap failed: %v", e.Cause)
	}
	if e.Peer != "" {
		return fmt.Sprintf("bootstrap failed for peer %s", e.Peer)
	}
	return "DHT bootstrap failed"
}

func (e *ErrBootstrapFailed) Unwrap() error {
	return e.Cause
}

// ErrConnectionFailed is returned when connecting to a peer fails.
type ErrConnectionFailed struct {
	PeerID peer.ID
	Addr   string
	Cause  error
}

func (e *ErrConnectionFailed) Error() string {
	if e.Cause != nil {
		if e.Addr != "" {
			return fmt.Sprintf("connection failed to peer %s at %s: %v", e.PeerID, e.Addr, e.Cause)
		}
		return fmt.Sprintf("connection failed to peer %s: %v", e.PeerID, e.Cause)
	}
	if e.Addr != "" {
		return fmt.Sprintf("connection failed to peer %s at %s", e.PeerID, e.Addr)
	}
	return fmt.Sprintf("connection failed to peer %s", e.PeerID)
}

func (e *ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidMultiaddr is returned when a multiaddr is invalid.
type ErrInvalidMultiaddr struct {
	Addr  string
	Cause error
}

func (e *ErrInvalidMultiaddr) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("invalid multiaddr %q: %v", e.Addr, e.Cause)
	}
	return fmt.Sprintf("invalid multiaddr %q", e.Addr)
}

func (e *ErrInvalidMultiaddr) Unwrap() error {
	return e.Cause
}

// ErrMultipleFailures is returned when multiple operations fail.
type ErrMultipleFailures struct {
	Errors []error
}

func (e *ErrMultipleFailures) Error() string {
	if len(e.Errors) == 0 {
		return "multiple failures occurred"
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}

	var sb strings.Builder
	sb.WriteString("multiple failures: ")
	for i, err := range e.Errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Error())
	}
	return sb.String()
}

// ErrDHTOperationFailed is returned when a DHT operation fails.
type ErrDHTOperationFailed struct {
	Operation string
	Key       string
	Cause     error
}

func (e *ErrDHTOperationFailed) Error() string {
	if e.Cause != nil {
		if e.Key != "" {
			return fmt.Sprintf("DHT operation %q failed for key %s: %v", e.Operation, e.Key, e.Cause)
		}
		return fmt.Sprintf("DHT operation %q failed: %v", e.Operation, e.Cause)
	}
	if e.Key != "" {
		return fmt.Sprintf("DHT operation %q failed for key %s", e.Operation, e.Key)
	}
	return fmt.Sprintf("DHT operation %q failed", e.Operation)
}

func (e *ErrDHTOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrHostCreationFailed is returned when creating the libp2p host fails.
type ErrHostCreationFailed struct {
	Cause error
}

func (e *ErrHostCreationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to create libp2p host: %v", e.Cause)
	}
	return "failed to create libp2p host"
}

func (e *ErrHostCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrDHTCreationFailed is returned when creating the DHT fails.
type ErrDHTCreationFailed struct {
	Cause error
}

func (e *ErrDHTCreationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to create DHT: %v", e.Cause)
	}
	return "failed to create DHT"
}

func (e *ErrDHTCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrMultiaddrParseFailed is returned when parsing a multiaddr fails.
type ErrMultiaddrParseFailed struct {
	Addr  string
	Cause error
}

func (e *ErrMultiaddrParseFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to parse multiaddr %q: %v", e.Addr, e.Cause)
	}
	return fmt.Sprintf("failed to parse multiaddr %q", e.Addr)
}

func (e *ErrMultiaddrParseFailed) Unwrap() error {
	return e.Cause
}

// ErrPeerInfoParseFailed is returned when parsing peer info fails.
type ErrPeerInfoParseFailed struct {
	Addr  string
	Cause error
}

func (e *ErrPeerInfoParseFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to parse peer info from %q: %v", e.Addr, e.Cause)
	}
	return fmt.Sprintf("failed to parse peer info from %q", e.Addr)
}

func (e *ErrPeerInfoParseFailed) Unwrap() error {
	return e.Cause
}

// ErrTimeout is returned when an operation times out.
type ErrTimeout struct {
	Operation string
	Duration  time.Duration
}

func (e *ErrTimeout) Error() string {
	return fmt.Sprintf("operation %q timed out after %v", e.Operation, e.Duration)
}

// ErrContextCanceled is returned when an operation is canceled via context.
type ErrContextCanceled struct {
	Operation string
}

func (e *ErrContextCanceled) Error() string {
	return fmt.Sprintf("operation %q canceled", e.Operation)
}

// ErrMDNSSetupFailed is returned when mDNS setup fails.
type ErrMDNSSetupFailed struct {
	Cause error
}

func (e *ErrMDNSSetupFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to setup mDNS: %v", e.Cause)
	}
	return "failed to setup mDNS"
}

func (e *ErrMDNSSetupFailed) Unwrap() error {
	return e.Cause
}

// ErrIdentityCreationFailed is returned when creating an identity fails.
type ErrIdentityCreationFailed struct {
	Cause error
}

func (e *ErrIdentityCreationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to create identity: %v", e.Cause)
	}
	return "failed to create identity"
}

func (e *ErrIdentityCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrProvideOperationFailed is returned when a provide operation fails.
type ErrProvideOperationFailed struct {
	Key   string
	Cause error
}

func (e *ErrProvideOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to provide key %q: %v", e.Key, e.Cause)
	}
	return fmt.Sprintf("failed to provide key %q", e.Key)
}

func (e *ErrProvideOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrFindProvidersOperationFailed is returned when finding providers fails.
type ErrFindProvidersOperationFailed struct {
	Key   string
	Cause error
}

func (e *ErrFindProvidersOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to find providers for key %q: %v", e.Key, e.Cause)
	}
	return fmt.Sprintf("failed to find providers for key %q", e.Key)
}

func (e *ErrFindProvidersOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrKeyConversionFailed is returned when key conversion fails.
type ErrKeyConversionFailed struct {
	Key   string
	Cause error
}

func (e *ErrKeyConversionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to convert key %q: %v", e.Key, e.Cause)
	}
	return fmt.Sprintf("failed to convert key %q", e.Key)
}

func (e *ErrKeyConversionFailed) Unwrap() error {
	return e.Cause
}
