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

package fhrp

import (
	"fmt"
	"net/netip"
)

// ErrInvalidGroupConfig reports a group configuration the speaker refuses.
type ErrInvalidGroupConfig struct {
	VRID   uint8
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidGroupConfig) Error() string {
	return fmt.Sprintf("fhrp: group %d: %s %s", e.VRID, e.Field, e.Reason)
}

// ErrDuplicateGroup reports two groups sharing a VRID on one interface.
type ErrDuplicateGroup struct {
	VRID      uint8
	Interface string
}

// Error implements the error interface.
func (e *ErrDuplicateGroup) Error() string {
	return fmt.Sprintf("fhrp: group %d is configured twice on %s", e.VRID, e.Interface)
}

// ErrInvalidPacket reports an advertisement that does not parse or fails
// its RFC 5798 §7.1 receive checks.
type ErrInvalidPacket struct {
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidPacket) Error() string {
	return "fhrp: invalid advertisement: " + e.Reason
}

// ErrTransportRequired is returned when a speaker is built without a
// Transport or a Programmer.
type ErrTransportRequired struct {
	Dependency string
}

// Error implements the error interface.
func (e *ErrTransportRequired) Error() string {
	return "fhrp: " + e.Dependency + " is required"
}

// ErrTransportFailed wraps a send, receive or open failure on the wire.
type ErrTransportFailed struct {
	VRID      uint8
	Interface string
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e *ErrTransportFailed) Error() string {
	return fmt.Sprintf("fhrp: group %d on %s: %s: %v", e.VRID, e.Interface, e.Operation, e.Cause)
}

// Unwrap exposes the cause.
func (e *ErrTransportFailed) Unwrap() error { return e.Cause }

// ErrAddressOperationFailed wraps an address add/remove or a gratuitous
// announcement that the programmer could not perform.
type ErrAddressOperationFailed struct {
	VRID      uint8
	Interface string
	Operation string
	Address   netip.Prefix
	Cause     error
}

// Error implements the error interface.
func (e *ErrAddressOperationFailed) Error() string {
	return fmt.Sprintf("fhrp: group %d on %s: %s %s: %v", e.VRID, e.Interface, e.Operation, e.Address, e.Cause)
}

// Unwrap exposes the cause.
func (e *ErrAddressOperationFailed) Unwrap() error { return e.Cause }

// ErrSpeakerNotRunning is returned for operations on a stopped speaker.
type ErrSpeakerNotRunning struct{}

// Error implements the error interface.
func (ErrSpeakerNotRunning) Error() string { return "fhrp: speaker is not running" }

// ErrSpeakerAlreadyRunning is returned when Start is called twice.
type ErrSpeakerAlreadyRunning struct{}

// Error implements the error interface.
func (ErrSpeakerAlreadyRunning) Error() string { return "fhrp: speaker is already running" }

// ErrGroupNotFound is returned when a VRID is not configured.
type ErrGroupNotFound struct {
	VRID      uint8
	Interface string
}

// Error implements the error interface.
func (e *ErrGroupNotFound) Error() string {
	return fmt.Sprintf("fhrp: no group %d on %s", e.VRID, e.Interface)
}

// ErrRollbackIncomplete is a failed Start whose rollback of the groups already
// started also failed: Cause is what stopped the start, Rollback what could
// not be undone. Both branches are reachable through errors.Is / errors.As.
type ErrRollbackIncomplete struct {
	Cause    error
	Rollback error
}

// Error implements the error interface.
func (e *ErrRollbackIncomplete) Error() string {
	return fmt.Sprintf("%v (rollback incomplete: %v)", e.Cause, e.Rollback)
}

// Unwrap exposes both branches.
func (e *ErrRollbackIncomplete) Unwrap() []error { return []error{e.Cause, e.Rollback} }
