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

package ceremony

import "fmt"

// ErrUsernameRequired indicates --username was not provided.
type ErrUsernameRequired struct{}

// Error implements the error interface.
func (ErrUsernameRequired) Error() string { return "ceremony: --username is required" }

// ErrInvalidAuthenticatorType indicates an unknown authenticator type was
// passed via --authenticator-type.
type ErrInvalidAuthenticatorType struct {
	Value string
}

// Error implements the error interface.
func (e ErrInvalidAuthenticatorType) Error() string {
	return fmt.Sprintf("ceremony: invalid --authenticator-type %q (must be piv, fido2, or software)", e.Value)
}

// ErrAuthenticatorSelectorRequired indicates that the caller asked for PIV or
// FIDO2 but did not provide the corresponding selector flag.
type ErrAuthenticatorSelectorRequired struct {
	Type string
	Flag string
}

// Error implements the error interface.
func (e ErrAuthenticatorSelectorRequired) Error() string {
	return fmt.Sprintf("ceremony: %s authenticator requires %s", e.Type, e.Flag)
}

// ErrInvalidRole indicates an unknown role was passed via --role.
type ErrInvalidRole struct {
	Value string
}

// Error implements the error interface.
func (e ErrInvalidRole) Error() string {
	return fmt.Sprintf("ceremony: invalid --role %q (must be so, admin, or user)", e.Value)
}

// ErrCSRFileRequired indicates --csr-file was not provided.
type ErrCSRFileRequired struct{}

// Error implements the error interface.
func (ErrCSRFileRequired) Error() string { return "ceremony: --csr-file is required" }

// ErrCSRFileRead indicates the CSR file could not be read.
type ErrCSRFileRead struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e ErrCSRFileRead) Error() string {
	return fmt.Sprintf("ceremony: failed to read CSR file %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrCSRFileRead) Unwrap() error { return e.Cause }

// ErrSOPinRequired indicates --so-pin was not provided for a sign-csr operation.
type ErrSOPinRequired struct{}

// Error implements the error interface.
func (ErrSOPinRequired) Error() string { return "ceremony: --so-pin is required" }

// ErrNonceRequired indicates --nonce was not provided for claim-cert complete.
type ErrNonceRequired struct{}

// Error implements the error interface.
func (ErrNonceRequired) Error() string { return "ceremony: --nonce is required" }

// ErrSignatureRequired indicates --signature was not provided.
type ErrSignatureRequired struct{}

// Error implements the error interface.
func (ErrSignatureRequired) Error() string { return "ceremony: --signature is required" }

// ErrSignatureDecode indicates --signature was not valid base64.
type ErrSignatureDecode struct {
	Cause error
}

// Error implements the error interface.
func (e ErrSignatureDecode) Error() string {
	return "ceremony: --signature is not valid base64: " + e.Cause.Error()
}

// Unwrap returns the underlying decode error.
func (e ErrSignatureDecode) Unwrap() error { return e.Cause }
