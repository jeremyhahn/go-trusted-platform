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

import "fmt"

// ErrRootRequired indicates a LUKS operation was attempted without root
// privileges. LUKS block-device operations require CAP_SYS_ADMIN.
type ErrRootRequired struct{}

// Error implements the error interface.
func (ErrRootRequired) Error() string { return "luks: this command must be run as root" }

// ErrDeviceAutoDetectFailed indicates auto-detection could not find a LUKS
// device on the common partition paths.
type ErrDeviceAutoDetectFailed struct{}

// Error implements the error interface.
func (ErrDeviceAutoDetectFailed) Error() string {
	return "luks: could not auto-detect LUKS device; please specify with --device"
}

// ErrExistingPassphraseRequired indicates --existing-passphrase was not
// provided for an operation that requires it.
type ErrExistingPassphraseRequired struct{}

// Error implements the error interface.
func (ErrExistingPassphraseRequired) Error() string {
	return "luks: --existing-passphrase is required"
}

// ErrNewPassphraseRequired indicates --new-passphrase was not provided.
type ErrNewPassphraseRequired struct{}

// Error implements the error interface.
func (ErrNewPassphraseRequired) Error() string { return "luks: --new-passphrase is required" }

// ErrOldPassphraseRequired indicates --old-passphrase was not provided.
type ErrOldPassphraseRequired struct{}

// Error implements the error interface.
func (ErrOldPassphraseRequired) Error() string { return "luks: --old-passphrase is required" }

// ErrCredentialIDRequired indicates --credential-id was not provided.
type ErrCredentialIDRequired struct{}

// Error implements the error interface.
func (ErrCredentialIDRequired) Error() string { return "luks: --credential-id is required" }

// ErrOutputPathRequired indicates --output was not provided for recovery enrollment.
type ErrOutputPathRequired struct{}

// Error implements the error interface.
func (ErrOutputPathRequired) Error() string {
	return "luks: --output is required for enroll-recovery"
}

// ErrSlotRequired indicates --slot was not provided.
type ErrSlotRequired struct{}

// Error implements the error interface.
func (ErrSlotRequired) Error() string { return "luks: --slot is required" }

// ErrInvalidSlot indicates --slot was outside the LUKS2 valid range (0-31).
type ErrInvalidSlot struct {
	Slot int32
}

// Error implements the error interface.
func (e ErrInvalidSlot) Error() string {
	return fmt.Sprintf("luks: invalid --slot %d (must be 0-31)", e.Slot)
}

// ErrRecoveryKeyWrite indicates writing the recovery key to --output failed.
type ErrRecoveryKeyWrite struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e ErrRecoveryKeyWrite) Error() string {
	return fmt.Sprintf("luks: failed to write recovery key to %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrRecoveryKeyWrite) Unwrap() error { return e.Cause }
