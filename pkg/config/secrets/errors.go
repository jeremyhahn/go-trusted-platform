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

// Package secrets provides secret resolution for configuration values that
// reference externally stored secrets. It supports multiple resolution
// schemes including IDevID-bound secrets (idevid://) and file-backed secrets
// (file://).
package secrets

import "fmt"

// ErrDecrypterRequired is returned when no decrypter is provided to the resolver.
type ErrDecrypterRequired struct{}

func (e ErrDecrypterRequired) Error() string {
	return "secrets: decrypter is required"
}

// ErrInvalidSecretFormat is returned when the secret string format is invalid.
type ErrInvalidSecretFormat struct {
	Raw    string
	Reason string
}

func (e ErrInvalidSecretFormat) Error() string {
	return fmt.Sprintf("secrets: invalid secret format %q: %s", e.Raw, e.Reason)
}

// ErrBase64DecodeFailed is returned when base64 decoding of the ciphertext fails.
type ErrBase64DecodeFailed struct {
	Reason string
}

func (e ErrBase64DecodeFailed) Error() string {
	return fmt.Sprintf("secrets: base64 decode failed: %s", e.Reason)
}

// ErrDecryptionFailed is returned when decryption of the ciphertext fails.
type ErrDecryptionFailed struct {
	Reason string
}

func (e ErrDecryptionFailed) Error() string {
	return fmt.Sprintf("secrets: decryption failed: %s", e.Reason)
}

// ErrContextCanceled is returned when the context is canceled during resolution.
type ErrContextCanceled struct {
	Reason string
}

func (e ErrContextCanceled) Error() string {
	return fmt.Sprintf("secrets: context canceled: %s", e.Reason)
}

// ErrContextDeadlineExceeded is returned when the context deadline is exceeded.
type ErrContextDeadlineExceeded struct {
	Reason string
}

func (e ErrContextDeadlineExceeded) Error() string {
	return fmt.Sprintf("secrets: context deadline exceeded: %s", e.Reason)
}

// ErrEmptyCiphertext is returned when the ciphertext is empty after decoding.
type ErrEmptyCiphertext struct{}

func (e ErrEmptyCiphertext) Error() string {
	return "secrets: ciphertext is empty"
}

// ErrUnsupportedKeyType is returned when the key type is not supported for decryption.
type ErrUnsupportedKeyType struct {
	KeyType string
}

func (e ErrUnsupportedKeyType) Error() string {
	return fmt.Sprintf("secrets: unsupported key type: %s", e.KeyType)
}

// ErrInvalidFileURI is returned when a file:// URI is malformed.
type ErrInvalidFileURI struct {
	Raw    string
	Reason string
}

func (e ErrInvalidFileURI) Error() string {
	return fmt.Sprintf("secrets: invalid file URI %q: %s", e.Raw, e.Reason)
}

// ErrFileReadFailed is returned when the file referenced by a file:// URI
// cannot be read.
type ErrFileReadFailed struct {
	Path  string
	Cause error
}

func (e ErrFileReadFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("secrets: failed to read file secret %q: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("secrets: failed to read file secret %q", e.Path)
}

func (e ErrFileReadFailed) Unwrap() error {
	return e.Cause
}

// ErrFileEmpty is returned when the file referenced by a file:// URI is empty.
type ErrFileEmpty struct {
	Path string
}

func (e ErrFileEmpty) Error() string {
	return fmt.Sprintf("secrets: file secret %q is empty", e.Path)
}
