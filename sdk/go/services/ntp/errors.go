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

package ntp

// ErrGetStatusFailed is returned when the status query fails.
type ErrGetStatusFailed struct{ Cause error }

// Error implements the error interface.
func (e *ErrGetStatusFailed) Error() string {
	return "ntp: get status failed: " + e.Cause.Error()
}

// Unwrap returns the underlying transport error.
func (e *ErrGetStatusFailed) Unwrap() error { return e.Cause }

// ErrListSourcesFailed is returned when the source enumeration fails.
type ErrListSourcesFailed struct{ Cause error }

// Error implements the error interface.
func (e *ErrListSourcesFailed) Error() string {
	return "ntp: list sources failed: " + e.Cause.Error()
}

// Unwrap returns the underlying transport error.
func (e *ErrListSourcesFailed) Unwrap() error { return e.Cause }

// ErrStepFailed is returned when the manual clock step fails, which includes
// the expected "no reachable source" conflict.
type ErrStepFailed struct{ Cause error }

// Error implements the error interface.
func (e *ErrStepFailed) Error() string {
	return "ntp: clock step failed: " + e.Cause.Error()
}

// Unwrap returns the underlying transport error.
func (e *ErrStepFailed) Unwrap() error { return e.Cause }
