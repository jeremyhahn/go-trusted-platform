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

import "errors"

// ErrNotYetWired indicates the PIV service handler has not yet been wired up
// on the server side. Phase 3 delivers the CLI + SDK stub only; the handler
// implementation lands in Phase 3.5.
var ErrNotYetWired = errors.New("piv: service not yet wired in this release")

// ErrListDevicesFailed indicates a list-devices RPC failure.
type ErrListDevicesFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrListDevicesFailed) Error() string {
	return "piv: list devices failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrListDevicesFailed) Unwrap() error { return e.Cause }

// ErrListSlotsFailed indicates a list-slots RPC failure.
type ErrListSlotsFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrListSlotsFailed) Error() string {
	return "piv: list slots failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrListSlotsFailed) Unwrap() error { return e.Cause }

// ErrSlotInfoFailed indicates a slot-info RPC failure.
type ErrSlotInfoFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrSlotInfoFailed) Error() string {
	return "piv: slot info failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrSlotInfoFailed) Unwrap() error { return e.Cause }

// ErrGenerateFailed indicates a key generation RPC failure.
type ErrGenerateFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrGenerateFailed) Error() string {
	return "piv: generate failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrGenerateFailed) Unwrap() error { return e.Cause }

// ErrImportFailed indicates a key import RPC failure.
type ErrImportFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrImportFailed) Error() string {
	return "piv: import failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrImportFailed) Unwrap() error { return e.Cause }

// ErrSignFailed indicates a sign RPC failure.
type ErrSignFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrSignFailed) Error() string {
	return "piv: sign failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrSignFailed) Unwrap() error { return e.Cause }

// ErrAttestFailed indicates an attestation RPC failure.
type ErrAttestFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrAttestFailed) Error() string {
	return "piv: attest failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrAttestFailed) Unwrap() error { return e.Cause }

// ErrResetFailed indicates a device reset RPC failure.
type ErrResetFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrResetFailed) Error() string {
	return "piv: reset failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrResetFailed) Unwrap() error { return e.Cause }
