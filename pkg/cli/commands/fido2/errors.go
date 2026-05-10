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

import "fmt"

// ErrDeviceRequired indicates --device was not provided.
type ErrDeviceRequired struct{}

// Error implements the error interface.
func (ErrDeviceRequired) Error() string { return "fido2: --device is required" }

// ErrUsernameRequired indicates --username was not provided.
type ErrUsernameRequired struct{}

// Error implements the error interface.
func (ErrUsernameRequired) Error() string { return "fido2: --username is required" }

// ErrCredentialIDRequired indicates --credential-id was not provided.
type ErrCredentialIDRequired struct{}

// Error implements the error interface.
func (ErrCredentialIDRequired) Error() string { return "fido2: --credential-id is required" }

// ErrInvalidRole indicates an unknown --role was supplied.
type ErrInvalidRole struct {
	Value string
}

// Error implements the error interface.
func (e ErrInvalidRole) Error() string {
	return fmt.Sprintf("fido2: invalid --role %q (must be so, admin, or user)", e.Value)
}

// ErrInvalidTimeout indicates --timeout was negative.
type ErrInvalidTimeout struct {
	Value int32
}

// Error implements the error interface.
func (e ErrInvalidTimeout) Error() string {
	return fmt.Sprintf("fido2: invalid --timeout %d (must be >= 0)", e.Value)
}
