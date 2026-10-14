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

// ErrStatusFailed indicates a status RPC failure.
type ErrStatusFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrStatusFailed) Error() string { return "luks: status failed: " + e.Cause.Error() }

// Unwrap returns the underlying cause.
func (e *ErrStatusFailed) Unwrap() error { return e.Cause }

// ErrListSlotsFailed indicates a list-slots RPC failure.
type ErrListSlotsFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrListSlotsFailed) Error() string { return "luks: list slots failed: " + e.Cause.Error() }

// Unwrap returns the underlying cause.
func (e *ErrListSlotsFailed) Unwrap() error { return e.Cause }

// ErrInfoFailed indicates an info RPC failure.
type ErrInfoFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrInfoFailed) Error() string { return "luks: info failed: " + e.Cause.Error() }

// Unwrap returns the underlying cause.
func (e *ErrInfoFailed) Unwrap() error { return e.Cause }

// ErrEnrollPassphraseFailed indicates a passphrase enroll failure.
type ErrEnrollPassphraseFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrEnrollPassphraseFailed) Error() string {
	return "luks: enroll passphrase failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrEnrollPassphraseFailed) Unwrap() error { return e.Cause }

// ErrEnrollFIDO2Failed indicates a FIDO2 enroll failure.
type ErrEnrollFIDO2Failed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrEnrollFIDO2Failed) Error() string {
	return "luks: enroll fido2 failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrEnrollFIDO2Failed) Unwrap() error { return e.Cause }

// ErrEnrollTPMFailed indicates a TPM enroll failure.
type ErrEnrollTPMFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrEnrollTPMFailed) Error() string { return "luks: enroll tpm failed: " + e.Cause.Error() }

// Unwrap returns the underlying cause.
func (e *ErrEnrollTPMFailed) Unwrap() error { return e.Cause }

// ErrEnrollRecoveryFailed indicates a recovery-key enroll failure.
type ErrEnrollRecoveryFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrEnrollRecoveryFailed) Error() string {
	return "luks: enroll recovery failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrEnrollRecoveryFailed) Unwrap() error { return e.Cause }

// ErrRemoveKeyFailed indicates a slot removal failure.
type ErrRemoveKeyFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrRemoveKeyFailed) Error() string { return "luks: remove key failed: " + e.Cause.Error() }

// Unwrap returns the underlying cause.
func (e *ErrRemoveKeyFailed) Unwrap() error { return e.Cause }

// ErrTestUnlockFailed indicates a test-unlock failure.
type ErrTestUnlockFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrTestUnlockFailed) Error() string {
	return "luks: test unlock failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrTestUnlockFailed) Unwrap() error { return e.Cause }

// ErrChangePassphraseFailed indicates a change-passphrase failure.
type ErrChangePassphraseFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrChangePassphraseFailed) Error() string {
	return "luks: change passphrase failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrChangePassphraseFailed) Unwrap() error { return e.Cause }

// ErrUnknownWireValue indicates a transport carried an enum value the SDK
// does not recognise. It is refused rather than reported as UNSPECIFIED.
type ErrUnknownWireValue struct {
	Kind  string
	Value string
}

// Error implements the error interface.
func (e *ErrUnknownWireValue) Error() string {
	return "luks: unknown " + e.Kind + " " + e.Value
}

// ErrWireDecode indicates an MCP result could not be decoded.
type ErrWireDecode struct {
	Message string
	Err     error
}

// Error implements the error interface.
func (e *ErrWireDecode) Error() string {
	return "luks: decode " + e.Message + " result: " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrWireDecode) Unwrap() error { return e.Err }
