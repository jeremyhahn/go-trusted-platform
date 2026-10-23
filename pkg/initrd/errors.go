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
