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

package initrd

import "fmt"

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

// CommandError pairs a failed external command's underlying error with the
// command's combined output.
type CommandError struct {
	Err    error
	Output string
}

// Error implements the error interface.
func (e *CommandError) Error() string {
	return e.Err.Error() + ": " + e.Output
}

// Unwrap returns the wrapped cause.
func (e *CommandError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// ResealNoSlotError reports that the volume configuration has no TPM-PCR key
// slot, so the recovery reseal has nothing to reseal.
type ResealNoSlotError struct {
	DevicePath string
}

// Error implements the error interface.
func (e *ResealNoSlotError) Error() string {
	return "reseal: no TPM-PCR key slot configured for " + e.DevicePath
}

// ResealStoreError reports that the recovery reseal refused to run. The
// unlock path reads the TPM-PCR seal from the EFI partition files first boot
// writes, and the initrd has no writer for them, so a resealed key could not
// be stored and the next unlock would still read the old seal.
type ResealStoreError struct {
	Slots []int
}

// Error implements the error interface.
func (e *ResealStoreError) Error() string {
	return fmt.Sprintf("reseal refused for TPM-PCR slot(s) %v: the resealed data cannot be stored, "+
		"the initrd has no writer for %s and %s", e.Slots, pcrPublicFile, pcrPrivateFile)
}

// FIDO2TokenUnsupportedError reports that the platform's LUKS handler has no
// LUKS2 token support, so the FIDO2 strategy can neither persist nor read
// its enrolment.
type FIDO2TokenUnsupportedError struct{}

// Error implements the error interface.
func (e *FIDO2TokenUnsupportedError) Error() string {
	return "fido2: the LUKS handler has no LUKS2 token support"
}

// FIDO2TokenNotFoundError reports that no LUKS2 token bound to a FIDO2 slot
// carries a credential and a salt.
type FIDO2TokenNotFoundError struct {
	DevicePath string
	Slot       int
}

// Error implements the error interface.
func (e *FIDO2TokenNotFoundError) Error() string {
	return fmt.Sprintf("fido2: no LUKS2 FIDO2 token for slot %d on %s", e.Slot, e.DevicePath)
}

// FIDO2TokenDecodeError reports a FIDO2 token field that is not valid base64.
type FIDO2TokenDecodeError struct {
	Slot  int
	Field string
	Err   error
}

// Error implements the error interface.
func (e *FIDO2TokenDecodeError) Error() string {
	return fmt.Sprintf("fido2: LUKS2 token for slot %d has an invalid %s: %v", e.Slot, e.Field, e.Err)
}

// Unwrap returns the decode error.
func (e *FIDO2TokenDecodeError) Unwrap() error {
	return e.Err
}

// FIDO2SaltError reports that a fresh hmac-secret salt could not be read
// from the entropy source.
type FIDO2SaltError struct {
	Err error
}

// Error implements the error interface.
func (e *FIDO2SaltError) Error() string {
	return fmt.Sprintf("fido2: failed to generate the hmac-secret salt: %v", e.Err)
}

// Unwrap returns the entropy source error.
func (e *FIDO2SaltError) Unwrap() error {
	return e.Err
}

// FIDO2TokenStoreError reports that the enrolment token could not be written
// after the key was added. The slot is killed again so boot is never left
// with a slot it cannot open; RollbackErr is set when that also failed.
type FIDO2TokenStoreError struct {
	Slot        int
	Err         error
	RollbackErr error
}

// Error implements the error interface.
func (e *FIDO2TokenStoreError) Error() string {
	if e.RollbackErr != nil {
		return fmt.Sprintf("fido2: failed to store the enrolment token for slot %d: %v; killing the slot also failed: %v",
			e.Slot, e.Err, e.RollbackErr)
	}
	return fmt.Sprintf("fido2: failed to store the enrolment token for slot %d, the slot was killed: %v", e.Slot, e.Err)
}

// Unwrap returns the token error and, when set, the rollback error.
func (e *FIDO2TokenStoreError) Unwrap() []error {
	if e.RollbackErr != nil {
		return []error{e.Err, e.RollbackErr}
	}
	return []error{e.Err}
}
