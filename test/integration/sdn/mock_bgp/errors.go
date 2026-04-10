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

//go:build integration

package mock_bgp

import (
	"fmt"
	"net/netip"
)

// Sentinel errors for mock BGP peer operations.
var (
	// ErrPeerNotStarted is returned when operations are attempted on an unstarted peer.
	ErrPeerNotStarted = &errPeerNotStarted{}

	// ErrPeerAlreadyStarted is returned when Start is called on an already running peer.
	ErrPeerAlreadyStarted = &errPeerAlreadyStarted{}

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = &errInvalidConfig{}

	// ErrInvalidASN is returned when an invalid ASN is provided.
	ErrInvalidASN = &errInvalidASN{}

	// ErrInvalidRouterID is returned when an invalid router ID is provided.
	ErrInvalidRouterID = &errInvalidRouterID{}

	// ErrInvalidListenAddr is returned when an invalid listen address is provided.
	ErrInvalidListenAddr = &errInvalidListenAddr{}

	// ErrNeighborNotFound is returned when a neighbor is not found.
	ErrNeighborNotFound = &errNeighborNotFound{}

	// ErrNeighborExists is returned when a neighbor already exists.
	ErrNeighborExists = &errNeighborExists{}

	// ErrSessionNotEstablished is returned when the BGP session is not established.
	ErrSessionNotEstablished = &errSessionNotEstablished{}

	// ErrInvalidPrefix is returned when an invalid prefix is provided.
	ErrInvalidPrefix = &errInvalidPrefix{}

	// ErrInvalidNextHop is returned when an invalid next-hop is provided.
	ErrInvalidNextHop = &errInvalidNextHop{}

	// ErrNilConfig is returned when a nil configuration is provided.
	ErrNilConfig = &errNilConfig{}

	// ErrNilLogger is returned when a nil logger is provided.
	ErrNilLogger = &errNilLogger{}
)

type errPeerNotStarted struct{}

func (e *errPeerNotStarted) Error() string { return "mock BGP peer not started" }

type errPeerAlreadyStarted struct{}

func (e *errPeerAlreadyStarted) Error() string { return "mock BGP peer already started" }

type errInvalidConfig struct{}

func (e *errInvalidConfig) Error() string { return "invalid mock BGP peer configuration" }

type errInvalidASN struct{}

func (e *errInvalidASN) Error() string { return "invalid ASN (must be > 0)" }

type errInvalidRouterID struct{}

func (e *errInvalidRouterID) Error() string { return "invalid router ID" }

type errInvalidListenAddr struct{}

func (e *errInvalidListenAddr) Error() string { return "invalid listen address" }

type errNeighborNotFound struct{}

func (e *errNeighborNotFound) Error() string { return "neighbor not found" }

type errNeighborExists struct{}

func (e *errNeighborExists) Error() string { return "neighbor already exists" }

type errSessionNotEstablished struct{}

func (e *errSessionNotEstablished) Error() string { return "BGP session not established" }

type errInvalidPrefix struct{}

func (e *errInvalidPrefix) Error() string { return "invalid IP prefix" }

type errInvalidNextHop struct{}

func (e *errInvalidNextHop) Error() string { return "invalid next-hop address" }

type errNilConfig struct{}

func (e *errNilConfig) Error() string { return "configuration is nil" }

type errNilLogger struct{}

func (e *errNilLogger) Error() string { return "logger is nil" }

// ErrServerOperationFailed represents a server operation failure.
type ErrServerOperationFailed struct {
	Operation string
	Cause     error
}

func (e *ErrServerOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("server operation %q failed: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("server operation %q failed", e.Operation)
}

func (e *ErrServerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrPeerOperationFailed represents a peer operation failure.
type ErrPeerOperationFailed struct {
	Operation   string
	PeerAddress netip.Addr
	Cause       error
}

func (e *ErrPeerOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("peer %s operation %q failed: %v", e.PeerAddress, e.Operation, e.Cause)
	}
	return fmt.Sprintf("peer %s operation %q failed", e.PeerAddress, e.Operation)
}

func (e *ErrPeerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrRouteOperationFailed represents a route operation failure.
type ErrRouteOperationFailed struct {
	Operation string
	Prefix    netip.Prefix
	Cause     error
}

func (e *ErrRouteOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("route operation %q for %s failed: %v", e.Operation, e.Prefix, e.Cause)
	}
	return fmt.Sprintf("route operation %q for %s failed", e.Operation, e.Prefix)
}

func (e *ErrRouteOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrConfigValidation represents a configuration validation error.
type ErrConfigValidation struct {
	Field  string
	Value  string
	Reason string
}

func (e *ErrConfigValidation) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("configuration validation failed for %s=%q: %s", e.Field, e.Value, e.Reason)
	}
	return fmt.Sprintf("configuration validation failed for %s: %s", e.Field, e.Reason)
}

// ErrWaitTimeout represents a wait timeout error.
type ErrWaitTimeout struct {
	Condition string
	Duration  string
}

func (e *ErrWaitTimeout) Error() string {
	return fmt.Sprintf("timed out waiting for %s after %s", e.Condition, e.Duration)
}
