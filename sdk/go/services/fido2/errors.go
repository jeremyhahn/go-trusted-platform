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

package fido2

import "errors"

// ErrNotYetWired indicates the FIDO2 service handler has not yet been wired
// up on the server side. Phase 3 delivers the CLI + SDK stub only; handler
// implementations land in Phase 3.5.
var ErrNotYetWired = errors.New("fido2: service not yet wired in this release")

// ErrListDevicesFailed indicates a list-devices RPC failure.
type ErrListDevicesFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrListDevicesFailed) Error() string {
	return "fido2: list devices failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrListDevicesFailed) Unwrap() error { return e.Cause }

// ErrWaitDeviceFailed indicates a wait-device RPC failure.
type ErrWaitDeviceFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrWaitDeviceFailed) Error() string {
	return "fido2: wait device failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrWaitDeviceFailed) Unwrap() error { return e.Cause }

// ErrDeviceInfoFailed indicates a device-info RPC failure.
type ErrDeviceInfoFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrDeviceInfoFailed) Error() string {
	return "fido2: device info failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrDeviceInfoFailed) Unwrap() error { return e.Cause }

// ErrRegisterFailed indicates a WebAuthn register RPC failure.
type ErrRegisterFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrRegisterFailed) Error() string { return "fido2: register failed: " + e.Cause.Error() }

// Unwrap returns the underlying cause.
func (e *ErrRegisterFailed) Unwrap() error { return e.Cause }

// ErrAuthenticateFailed indicates an authenticate RPC failure.
type ErrAuthenticateFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrAuthenticateFailed) Error() string {
	return "fido2: authenticate failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrAuthenticateFailed) Unwrap() error { return e.Cause }
