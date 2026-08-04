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

package luks

import (
	"errors"
	"fmt"
)

// Sentinel errors for token operations
var (
	// ErrTokenNil indicates a nil token was provided
	ErrTokenNil = errors.New("luks: token cannot be nil")

	// ErrTokenTypeEmpty indicates the token type is empty
	ErrTokenTypeEmpty = errors.New("luks: token type cannot be empty")

	// ErrTokenNoFreeSlot indicates no free token slots are available
	ErrTokenNoFreeSlot = errors.New("luks: no free token slots available")
)

// TokenNotFoundError indicates the token was not found at the specified ID
type TokenNotFoundError struct {
	ID int
}

// Error implements the error interface
func (e *TokenNotFoundError) Error() string {
	return fmt.Sprintf("luks: token not found at slot %d", e.ID)
}

// TokenInvalidIDError indicates the token ID is invalid
type TokenInvalidIDError struct {
	ID int
}

// Error implements the error interface
func (e *TokenInvalidIDError) Error() string {
	return fmt.Sprintf("luks: invalid token ID %d (must be 0-%d)", e.ID, MaxTokenSlots-1)
}

// TokenSlotOccupiedError indicates the token slot is already occupied
type TokenSlotOccupiedError struct {
	ID int
}

// Error implements the error interface
func (e *TokenSlotOccupiedError) Error() string {
	return fmt.Sprintf("luks: token slot %d is already occupied", e.ID)
}

// TokenOperationError wraps an underlying error from a token operation
type TokenOperationError struct {
	Op  string
	Err error
}

// Error implements the error interface
func (e *TokenOperationError) Error() string {
	return fmt.Sprintf("luks: token operation %q failed: %v", e.Op, e.Err)
}

// Unwrap implements the errors.Unwrap interface
func (e *TokenOperationError) Unwrap() error {
	return e.Err
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

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
