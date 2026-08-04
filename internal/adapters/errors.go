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

// Package adapters provides primitives shared by the transport adapter
// packages under internal/ (quicbaas, ca, quicbaaskms, xkms).
package adapters

import "fmt"

// AdapterError represents an error originating from a transport adapter.
//
// Component identifies the adapter (e.g. "quicbaas", "ca", "quicbaaskms",
// "xkms") and is rendered as the prefix of the formatted error string, which
// preserves the canonical "<component> adapter <op>: <msg>" layout used across
// all adapters.
type AdapterError struct {
	Component string // Adapter name used as the error prefix
	Op        string // Operation that failed
	Msg       string // Error message
	Cause     error  // Underlying error
}

// Error returns the error message.
func (e *AdapterError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s adapter %s: %s: %v", e.Component, e.Op, e.Msg, e.Cause)
	}
	return fmt.Sprintf("%s adapter %s: %s", e.Component, e.Op, e.Msg)
}

// Unwrap returns the underlying error.
func (e *AdapterError) Unwrap() error {
	return e.Cause
}

// WithCause returns a copy of the error with the given cause, preserving the
// component, operation, and message.
func (e *AdapterError) WithCause(cause error) *AdapterError {
	return &AdapterError{
		Component: e.Component,
		Op:        e.Op,
		Msg:       e.Msg,
		Cause:     cause,
	}
}
