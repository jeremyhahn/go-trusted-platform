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

//go:build pkcs11

package pkcs11

import "fmt"

// ErrDaemonConnectionRequired is returned when the command requires
// a daemon connection that is not yet implemented
type ErrDaemonConnectionRequired struct{}

func (e ErrDaemonConnectionRequired) Error() string {
	return "daemon connection required"
}

// ErrInvalidModulePath is returned when no valid PKCS#11 module path is specified
type ErrInvalidModulePath struct{}

func (e ErrInvalidModulePath) Error() string {
	return "invalid PKCS #11 module path: specify --module, --ykcs11, --softhsm2, or --opensc"
}

// ErrModuleLoadFailed is returned when the PKCS#11 module cannot be loaded
type ErrModuleLoadFailed struct {
	Module string
	Reason string
}

func (e ErrModuleLoadFailed) Error() string {
	return fmt.Sprintf("failed to load PKCS #11 module '%s': %s", e.Module, e.Reason)
}

// ErrTokenLoginFailed is returned when login to the token fails
type ErrTokenLoginFailed struct {
	Reason string
}

func (e ErrTokenLoginFailed) Error() string {
	return fmt.Sprintf("failed to login to PKCS #11 token: %s", e.Reason)
}

// ErrTokenNotFound is returned when the specified token is not found
type ErrTokenNotFound struct {
	Label string
	Slot  int
}

func (e ErrTokenNotFound) Error() string {
	if e.Label != "" {
		return fmt.Sprintf("PKCS #11 token not found: label '%s'", e.Label)
	}
	return fmt.Sprintf("PKCS #11 token not found: slot %d", e.Slot)
}

// ErrSlotNotFound is returned when the specified slot is not found
type ErrSlotNotFound struct {
	Slot int
}

func (e ErrSlotNotFound) Error() string {
	return fmt.Sprintf("PKCS #11 slot not found: %d", e.Slot)
}

// ErrInvalidPIN is returned when an invalid PIN is provided
type ErrInvalidPIN struct {
	PINType string
}

func (e ErrInvalidPIN) Error() string {
	return fmt.Sprintf("invalid %s PIN", e.PINType)
}

// ErrOperationFailed is returned when a PKCS#11 operation fails
type ErrOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrOperationFailed) Error() string {
	return fmt.Sprintf("PKCS #11 operation '%s' failed: %s", e.Operation, e.Reason)
}
