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

package eab

import "fmt"

// ErrCredentialNotFound is returned when an EAB credential is not found.
type ErrCredentialNotFound struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialNotFound) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential not found: keyID=%s", e.KeyID)
	}
	return fmt.Sprintf("eab: credential not found: id=%d", e.ID)
}

// ErrCredentialExpired is returned when an EAB credential has expired.
type ErrCredentialExpired struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialExpired) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential expired: keyID=%s", e.KeyID)
	}
	return fmt.Sprintf("eab: credential expired: id=%d", e.ID)
}

// ErrCredentialRevoked is returned when an EAB credential has been revoked.
type ErrCredentialRevoked struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialRevoked) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential revoked: keyID=%s", e.KeyID)
	}
	return fmt.Sprintf("eab: credential revoked: id=%d", e.ID)
}

// ErrCredentialAlreadyUsed is returned when an EAB credential has already been used.
type ErrCredentialAlreadyUsed struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialAlreadyUsed) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential already used: keyID=%s", e.KeyID)
	}
	return fmt.Sprintf("eab: credential already used: id=%d", e.ID)
}

// ErrInvalidCredential is returned when an EAB credential is invalid.
type ErrInvalidCredential struct {
	Reason string
}

func (e ErrInvalidCredential) Error() string {
	return fmt.Sprintf("eab: invalid credential: %s", e.Reason)
}

// ErrInvalidProfileID is returned when an invalid profile ID is provided.
type ErrInvalidProfileID struct {
	ProfileID uint64
}

func (e ErrInvalidProfileID) Error() string {
	return fmt.Sprintf("eab: invalid profile ID: %d", e.ProfileID)
}

// ErrInvalidTenantID is returned when an invalid tenant ID is provided.
type ErrInvalidTenantID struct {
	TenantID string
}

func (e ErrInvalidTenantID) Error() string {
	return fmt.Sprintf("eab: invalid tenant ID: %s", e.TenantID)
}

// ErrKeyGenerationFailed is returned when HMAC key generation fails.
type ErrKeyGenerationFailed struct {
	Cause error
}

func (e ErrKeyGenerationFailed) Error() string {
	return fmt.Sprintf("eab: key generation failed: %v", e.Cause)
}

func (e ErrKeyGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrQRCodeGenerationFailed is returned when QR code generation fails.
type ErrQRCodeGenerationFailed struct {
	Cause error
}

func (e ErrQRCodeGenerationFailed) Error() string {
	return fmt.Sprintf("eab: QR code generation failed: %v", e.Cause)
}

func (e ErrQRCodeGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrFileExportFailed is returned when file export fails.
type ErrFileExportFailed struct {
	Path  string
	Cause error
}

func (e ErrFileExportFailed) Error() string {
	return fmt.Sprintf("eab: file export failed: path=%s: %v", e.Path, e.Cause)
}

func (e ErrFileExportFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidExpiresAt is returned when an invalid expiration time is provided.
type ErrInvalidExpiresAt struct {
	Reason string
}

func (e ErrInvalidExpiresAt) Error() string {
	return fmt.Sprintf("eab: invalid expiration time: %s", e.Reason)
}
