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

// ErrCreateCredentialFailed is returned when creating an EAB credential fails.
type ErrCreateCredentialFailed struct {
	Cause error
}

func (e *ErrCreateCredentialFailed) Error() string {
	return fmt.Sprintf("failed to create EAB credential: %v", e.Cause)
}

func (e *ErrCreateCredentialFailed) Unwrap() error { return e.Cause }

// ErrGetCredentialFailed is returned when retrieving an EAB credential fails.
type ErrGetCredentialFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrGetCredentialFailed) Error() string {
	return fmt.Sprintf("failed to get EAB credential %d: %v", e.ID, e.Cause)
}

func (e *ErrGetCredentialFailed) Unwrap() error { return e.Cause }

// ErrGetCredentialByKeyIDFailed is returned when retrieving an EAB credential by key ID fails.
type ErrGetCredentialByKeyIDFailed struct {
	KeyID string
	Cause error
}

func (e *ErrGetCredentialByKeyIDFailed) Error() string {
	return fmt.Sprintf("failed to get EAB credential by key ID %s: %v", e.KeyID, e.Cause)
}

func (e *ErrGetCredentialByKeyIDFailed) Unwrap() error { return e.Cause }

// ErrListCredentialsFailed is returned when listing EAB credentials fails.
type ErrListCredentialsFailed struct {
	Cause error
}

func (e *ErrListCredentialsFailed) Error() string {
	return fmt.Sprintf("failed to list EAB credentials: %v", e.Cause)
}

func (e *ErrListCredentialsFailed) Unwrap() error { return e.Cause }

// ErrRevokeCredentialFailed is returned when revoking an EAB credential fails.
type ErrRevokeCredentialFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrRevokeCredentialFailed) Error() string {
	return fmt.Sprintf("failed to revoke EAB credential %d: %v", e.ID, e.Cause)
}

func (e *ErrRevokeCredentialFailed) Unwrap() error { return e.Cause }

// ErrValidateCredentialFailed is returned when validating an EAB credential fails.
type ErrValidateCredentialFailed struct {
	KeyID string
	Cause error
}

func (e *ErrValidateCredentialFailed) Error() string {
	return fmt.Sprintf("failed to validate EAB credential %s: %v", e.KeyID, e.Cause)
}

func (e *ErrValidateCredentialFailed) Unwrap() error { return e.Cause }

// ErrDeleteCredentialFailed is returned when deleting an EAB credential fails.
type ErrDeleteCredentialFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrDeleteCredentialFailed) Error() string {
	return fmt.Sprintf("failed to delete EAB credential %d: %v", e.ID, e.Cause)
}

func (e *ErrDeleteCredentialFailed) Unwrap() error { return e.Cause }

// ErrGetQRCodeFailed is returned when getting an EAB credential QR code fails.
type ErrGetQRCodeFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrGetQRCodeFailed) Error() string {
	return fmt.Sprintf("failed to get QR code for EAB credential %d: %v", e.ID, e.Cause)
}

func (e *ErrGetQRCodeFailed) Unwrap() error { return e.Cause }

// ErrGetEnrollmentURLFailed is returned when getting an enrollment URL fails.
type ErrGetEnrollmentURLFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrGetEnrollmentURLFailed) Error() string {
	return fmt.Sprintf("failed to get enrollment URL for EAB credential %d: %v", e.ID, e.Cause)
}

func (e *ErrGetEnrollmentURLFailed) Unwrap() error { return e.Cause }

// ErrMarkCredentialUsedFailed is returned when marking a credential as used fails.
type ErrMarkCredentialUsedFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrMarkCredentialUsedFailed) Error() string {
	return fmt.Sprintf("failed to mark EAB credential %d as used: %v", e.ID, e.Cause)
}

func (e *ErrMarkCredentialUsedFailed) Unwrap() error { return e.Cause }

// ErrCleanupExpiredCredentialsFailed is returned when cleanup of expired credentials fails.
type ErrCleanupExpiredCredentialsFailed struct {
	Cause error
}

func (e *ErrCleanupExpiredCredentialsFailed) Error() string {
	return fmt.Sprintf("failed to cleanup expired EAB credentials: %v", e.Cause)
}

func (e *ErrCleanupExpiredCredentialsFailed) Unwrap() error { return e.Cause }
