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

package hostfw

import (
	"errors"
	"strconv"
)

var (
	// ErrNilApplier is returned when Deps lacks an Applier.
	ErrNilApplier = errors.New("hostfw: applier is nil")
	// ErrNilInventory is returned when Deps lacks a listener inventory.
	ErrNilInventory = errors.New("hostfw: listener inventory is nil")
	// ErrAlreadyStarted is returned when Start is called on a running service.
	ErrAlreadyStarted = errors.New("hostfw: service already started")
	// ErrNotStarted is returned when an operation requires a running service.
	ErrNotStarted = errors.New("hostfw: service not started")
	// ErrEmptyInterface is returned when an entry that needs an interface
	// names none.
	ErrEmptyInterface = errors.New("hostfw: interface name must be non-empty")
	// ErrInvalidInterface is returned when an interface name is not a valid
	// Linux interface name.
	ErrInvalidInterface = errors.New("hostfw: interface name is invalid")
	// ErrUnknownProtocol is returned when a protocol is not one the filter
	// renders.
	ErrUnknownProtocol = errors.New("hostfw: unknown protocol")
	// ErrZeroPort is returned when a listener declares port 0.
	ErrZeroPort = errors.New("hostfw: listener port must be non-zero")
	// ErrInvalidPrefix is returned when a listener source is not a valid
	// prefix.
	ErrInvalidPrefix = errors.New("hostfw: source prefix is invalid")
	// ErrInvalidAddress is returned when a peer address is invalid or
	// unspecified.
	ErrInvalidAddress = errors.New("hostfw: peer address is invalid")
	// ErrNoPeerAddresses is returned when a peer allowance names no address.
	ErrNoPeerAddresses = errors.New("hostfw: peer allowance needs at least one address")
	// ErrDuplicateListener is returned when two listeners claim the same
	// interface, protocol and port.
	ErrDuplicateListener = errors.New("hostfw: duplicate listener")
	// ErrTableMissing is reported by an Applier whose table was removed
	// underneath it.
	ErrTableMissing = errors.New("hostfw: table " + TableName + " is not installed")
)

// ValidationError names the ruleset entry that failed validation.
type ValidationError struct {
	// Field is the Ruleset field ("listeners", "peers", "tunnels",
	// "unfiltered").
	Field string
	// Index is the entry's position in that field.
	Index int
	// Err is the rule it broke.
	Err error
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return "hostfw: " + e.Field + "[" + strconv.Itoa(e.Index) + "]: " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *ValidationError) Unwrap() error { return e.Err }

// OpError is a failed operation against the kernel table.
type OpError struct {
	// Op is the operation that failed ("apply", "remove", "inspect",
	// "rollback", "write-base").
	Op string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *OpError) Error() string {
	return "hostfw: " + e.Op + ": " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *OpError) Unwrap() error { return e.Err }

// RollbackError reports an apply that failed and whose rollback to the
// previous ruleset also failed — the table state is unknown and the
// service refuses to claim health until the next successful reconcile.
type RollbackError struct {
	Apply    error
	Rollback error
}

// Error implements the error interface.
func (e *RollbackError) Error() string {
	return "hostfw: apply failed (" + e.Apply.Error() + ") and rollback failed (" + e.Rollback.Error() + ")"
}

// Unwrap implements errors.Unwrap.
func (e *RollbackError) Unwrap() error { return e.Apply }

func itoa(i int) string { return strconv.Itoa(i) }
