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

package secrets

import "fmt"

// ErrDecrypterRequired is returned when no decrypter is provided to the resolver.
type ErrDecrypterRequired struct{}

func (e ErrDecrypterRequired) Error() string {
	return "encrypted resolver: decrypter is required"
}

// ErrInvalidSecretFormat is returned when the secret string format is invalid.
type ErrInvalidSecretFormat struct {
	Raw    string
	Reason string
}

func (e ErrInvalidSecretFormat) Error() string {
	return fmt.Sprintf("encrypted resolver: invalid secret format %q: %s", e.Raw, e.Reason)
}

// ErrBase64DecodeFailed is returned when base64 decoding of the ciphertext fails.
type ErrBase64DecodeFailed struct {
	Reason string
}

func (e ErrBase64DecodeFailed) Error() string {
	return fmt.Sprintf("encrypted resolver: base64 decode failed: %s", e.Reason)
}

// ErrDecryptionFailed is returned when decryption of the ciphertext fails.
type ErrDecryptionFailed struct {
	Reason string
}

func (e ErrDecryptionFailed) Error() string {
	return fmt.Sprintf("encrypted resolver: decryption failed: %s", e.Reason)
}

// ErrContextCanceled is returned when the context is canceled during resolution.
type ErrContextCanceled struct {
	Reason string
}

func (e ErrContextCanceled) Error() string {
	return fmt.Sprintf("encrypted resolver: context canceled: %s", e.Reason)
}

// ErrContextDeadlineExceeded is returned when the context deadline is exceeded.
type ErrContextDeadlineExceeded struct {
	Reason string
}

func (e ErrContextDeadlineExceeded) Error() string {
	return fmt.Sprintf("encrypted resolver: context deadline exceeded: %s", e.Reason)
}

// ErrEmptyCiphertext is returned when the ciphertext is empty after decoding.
type ErrEmptyCiphertext struct{}

func (e ErrEmptyCiphertext) Error() string {
	return "encrypted resolver: ciphertext is empty"
}

// ErrUnsupportedKeyType is returned when the key type is not supported for decryption.
type ErrUnsupportedKeyType struct {
	KeyType string
}

func (e ErrUnsupportedKeyType) Error() string {
	return fmt.Sprintf("encrypted resolver: unsupported key type: %s", e.KeyType)
}
