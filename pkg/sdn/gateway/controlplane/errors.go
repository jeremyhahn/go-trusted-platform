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

package controlplane

import "fmt"

// ErrMissingField is returned when a required ReporterConfig field is empty.
type ErrMissingField struct {
	Field string
}

func (e ErrMissingField) Error() string {
	return fmt.Sprintf("controlplane: %s is required", e.Field)
}

// ErrConfigInvalid is returned when a control-plane configuration field
// carries a value that fails validation.
type ErrConfigInvalid struct {
	// Field is the configuration key that failed.
	Field string
	// Reason describes why the value is invalid.
	Reason string
}

// Error implements the error interface.
func (e *ErrConfigInvalid) Error() string {
	return fmt.Sprintf("controlplane: invalid %s: %s", e.Field, e.Reason)
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
