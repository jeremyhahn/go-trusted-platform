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

package piv

import "fmt"

// ErrDeviceRequired indicates --device was not provided.
type ErrDeviceRequired struct{}

// Error implements the error interface.
func (ErrDeviceRequired) Error() string { return "piv: --device is required" }

// ErrSlotRequired indicates --slot was not provided.
type ErrSlotRequired struct{}

// Error implements the error interface.
func (ErrSlotRequired) Error() string { return "piv: --slot is required" }

// ErrPINRequired indicates --pin was not provided.
type ErrPINRequired struct{}

// Error implements the error interface.
func (ErrPINRequired) Error() string { return "piv: --pin is required" }

// ErrInvalidAlgorithm indicates an unknown --algorithm value was supplied.
type ErrInvalidAlgorithm struct {
	Value string
}

// Error implements the error interface.
func (e ErrInvalidAlgorithm) Error() string {
	return fmt.Sprintf("piv: invalid --algorithm %q (must be rsa, ecdsa, or ed25519)", e.Value)
}

// ErrKeyFileRequired indicates --key-file was not provided.
type ErrKeyFileRequired struct{}

// Error implements the error interface.
func (ErrKeyFileRequired) Error() string { return "piv: --key-file is required" }

// ErrInputFileRequired indicates --input-file was not provided.
type ErrInputFileRequired struct{}

// Error implements the error interface.
func (ErrInputFileRequired) Error() string { return "piv: --input-file is required" }

// ErrKeyFileRead indicates the --key-file could not be read.
type ErrKeyFileRead struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e ErrKeyFileRead) Error() string {
	return fmt.Sprintf("piv: failed to read key file %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrKeyFileRead) Unwrap() error { return e.Cause }

// ErrInputFileRead indicates the --input-file could not be read.
type ErrInputFileRead struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e ErrInputFileRead) Error() string {
	return fmt.Sprintf("piv: failed to read input file %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrInputFileRead) Unwrap() error { return e.Cause }

// ErrResetNotConfirmed indicates the destructive reset was not confirmed.
type ErrResetNotConfirmed struct{}

// Error implements the error interface.
func (ErrResetNotConfirmed) Error() string {
	return "piv: reset requires --yes-i-understand to confirm destructive action"
}
