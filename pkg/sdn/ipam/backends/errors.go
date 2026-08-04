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

package backends

import "fmt"

// ErrDHTBackendInit is returned when DHT backend initialization fails.
type ErrDHTBackendInit struct {
	Reason string
	Cause  error
}

// Error returns the error message.
func (e *ErrDHTBackendInit) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("DHT backend initialization failed: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("DHT backend initialization failed: %s", e.Reason)
}

// Unwrap returns the underlying error.
func (e *ErrDHTBackendInit) Unwrap() error {
	return e.Cause
}

// ErrDHTOperationFailed is returned when a DHT operation fails.
type ErrDHTOperationFailed struct {
	Operation string
	Key       string
	Cause     error
}

// Error returns the error message.
func (e *ErrDHTOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("DHT operation %s failed for key %s: %v", e.Operation, e.Key, e.Cause)
	}
	return fmt.Sprintf("DHT operation %s failed for key %s", e.Operation, e.Key)
}

// Unwrap returns the underlying error.
func (e *ErrDHTOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrClaimConflict is returned when an IP claim conflicts with another node's claim.
type ErrClaimConflict struct {
	IP            string
	ClaimedBy     string
	OurDeviceID   string
	TheirDeviceID string
}

// Error returns the error message.
func (e *ErrClaimConflict) Error() string {
	return fmt.Sprintf("claim conflict for IP %s: our device %s vs their device %s",
		e.IP, e.OurDeviceID, e.TheirDeviceID)
}

// ErrVerificationFailed is returned when claim verification fails.
type ErrVerificationFailed struct {
	IP     string
	Reason string
	Cause  error
}

// Error returns the error message.
func (e *ErrVerificationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("verification failed for IP %s: %s: %v", e.IP, e.Reason, e.Cause)
	}
	return fmt.Sprintf("verification failed for IP %s: %s", e.IP, e.Reason)
}

// Unwrap returns the underlying error.
func (e *ErrVerificationFailed) Unwrap() error {
	return e.Cause
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}
