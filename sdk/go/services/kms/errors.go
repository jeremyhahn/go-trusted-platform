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

package kms

import "fmt"

// Key Management Errors

type ErrGenerateKeyFailed struct {
	Cause error
}

func (e *ErrGenerateKeyFailed) Error() string {
	return fmt.Sprintf("failed to generate key: %v", e.Cause)
}

func (e *ErrGenerateKeyFailed) Unwrap() error { return e.Cause }

type ErrImportKeyFailed struct {
	Cause error
}

func (e *ErrImportKeyFailed) Error() string {
	return fmt.Sprintf("failed to import key: %v", e.Cause)
}

func (e *ErrImportKeyFailed) Unwrap() error { return e.Cause }

type ErrGetKeyFailed struct {
	KeyID string
	Cause error
}

func (e *ErrGetKeyFailed) Error() string {
	return fmt.Sprintf("failed to get key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrGetKeyFailed) Unwrap() error { return e.Cause }

type ErrListKeysFailed struct {
	Cause error
}

func (e *ErrListKeysFailed) Error() string {
	return fmt.Sprintf("failed to list keys: %v", e.Cause)
}

func (e *ErrListKeysFailed) Unwrap() error { return e.Cause }

type ErrDeleteKeyFailed struct {
	KeyID string
	Cause error
}

func (e *ErrDeleteKeyFailed) Error() string {
	return fmt.Sprintf("failed to delete key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrDeleteKeyFailed) Unwrap() error { return e.Cause }

type ErrRotateKeyFailed struct {
	KeyID string
	Cause error
}

func (e *ErrRotateKeyFailed) Error() string {
	return fmt.Sprintf("failed to rotate key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrRotateKeyFailed) Unwrap() error { return e.Cause }

type ErrUpdateKeyStatusFailed struct {
	KeyID string
	Cause error
}

func (e *ErrUpdateKeyStatusFailed) Error() string {
	return fmt.Sprintf("failed to update key status for %s: %v", e.KeyID, e.Cause)
}

func (e *ErrUpdateKeyStatusFailed) Unwrap() error { return e.Cause }

type ErrExportKeyFailed struct {
	KeyID string
	Cause error
}

func (e *ErrExportKeyFailed) Error() string {
	return fmt.Sprintf("failed to export key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrExportKeyFailed) Unwrap() error { return e.Cause }

type ErrGetKeyVersionsFailed struct {
	KeyID string
	Cause error
}

func (e *ErrGetKeyVersionsFailed) Error() string {
	return fmt.Sprintf("failed to get key versions for %s: %v", e.KeyID, e.Cause)
}

func (e *ErrGetKeyVersionsFailed) Unwrap() error { return e.Cause }

// Cryptographic Errors

type ErrEncryptFailed struct {
	KeyID string
	Cause error
}

func (e *ErrEncryptFailed) Error() string {
	return fmt.Sprintf("failed to encrypt with key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrEncryptFailed) Unwrap() error { return e.Cause }

type ErrDecryptFailed struct {
	KeyID string
	Cause error
}

func (e *ErrDecryptFailed) Error() string {
	return fmt.Sprintf("failed to decrypt with key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrDecryptFailed) Unwrap() error { return e.Cause }

type ErrSignFailed struct {
	KeyID string
	Cause error
}

func (e *ErrSignFailed) Error() string {
	return fmt.Sprintf("failed to sign with key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrSignFailed) Unwrap() error { return e.Cause }

type ErrVerifyFailed struct {
	KeyID string
	Cause error
}

func (e *ErrVerifyFailed) Error() string {
	return fmt.Sprintf("failed to verify with key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrVerifyFailed) Unwrap() error { return e.Cause }

type ErrHashFailed struct {
	Cause error
}

func (e *ErrHashFailed) Error() string {
	return fmt.Sprintf("failed to compute hash: %v", e.Cause)
}

func (e *ErrHashFailed) Unwrap() error { return e.Cause }

type ErrHMACFailed struct {
	KeyID string
	Cause error
}

func (e *ErrHMACFailed) Error() string {
	return fmt.Sprintf("failed to compute HMAC with key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrHMACFailed) Unwrap() error { return e.Cause }

type ErrVerifyHMACFailed struct {
	KeyID string
	Cause error
}

func (e *ErrVerifyHMACFailed) Error() string {
	return fmt.Sprintf("failed to verify HMAC with key %s: %v", e.KeyID, e.Cause)
}

func (e *ErrVerifyHMACFailed) Unwrap() error { return e.Cause }

// Utility Errors

type ErrGenerateRandomFailed struct {
	Cause error
}

func (e *ErrGenerateRandomFailed) Error() string {
	return fmt.Sprintf("failed to generate random bytes: %v", e.Cause)
}

func (e *ErrGenerateRandomFailed) Unwrap() error { return e.Cause }

type ErrGenerateDataKeyFailed struct {
	Cause error
}

func (e *ErrGenerateDataKeyFailed) Error() string {
	return fmt.Sprintf("failed to generate data key: %v", e.Cause)
}

func (e *ErrGenerateDataKeyFailed) Unwrap() error { return e.Cause }

type ErrGenerateWrappedDataKeyFailed struct {
	Cause error
}

func (e *ErrGenerateWrappedDataKeyFailed) Error() string {
	return fmt.Sprintf("failed to generate wrapped data key: %v", e.Cause)
}

func (e *ErrGenerateWrappedDataKeyFailed) Unwrap() error { return e.Cause }

type ErrBackendStatusFailed struct {
	Cause error
}

func (e *ErrBackendStatusFailed) Error() string {
	return fmt.Sprintf("failed to get backend status: %v", e.Cause)
}

func (e *ErrBackendStatusFailed) Unwrap() error { return e.Cause }

// ErrRewrapFailed is returned when a rewrap operation fails.
type ErrRewrapFailed struct {
	Cause error
}

func (e *ErrRewrapFailed) Error() string {
	return fmt.Sprintf("failed to rewrap: %v", e.Cause)
}

func (e *ErrRewrapFailed) Unwrap() error { return e.Cause }

// ErrBatchEncryptFailed is returned when a batch encrypt operation fails.
type ErrBatchEncryptFailed struct {
	Cause error
}

func (e *ErrBatchEncryptFailed) Error() string {
	return fmt.Sprintf("failed to batch encrypt: %v", e.Cause)
}

func (e *ErrBatchEncryptFailed) Unwrap() error { return e.Cause }

// ErrBatchDecryptFailed is returned when a batch decrypt operation fails.
type ErrBatchDecryptFailed struct {
	Cause error
}

func (e *ErrBatchDecryptFailed) Error() string {
	return fmt.Sprintf("failed to batch decrypt: %v", e.Cause)
}

func (e *ErrBatchDecryptFailed) Unwrap() error { return e.Cause }
