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

package authenticode

import "fmt"

// TimestampError reports that the RFC 3161 time-stamp authority at URL could
// not countersign a signature: the request failed, the TSA refused it, or
// the token it returned does not match the signature it was asked to stamp.
type TimestampError struct {
	URL    string
	Reason string
	Err    error
}

// Error returns the error message.
func (e *TimestampError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("authenticode: timestamp from %s: %s: %v", e.URL, e.Reason, e.Err)
	}
	return fmt.Sprintf("authenticode: timestamp from %s: %s", e.URL, e.Reason)
}

// Unwrap returns the underlying error.
func (e *TimestampError) Unwrap() error {
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
