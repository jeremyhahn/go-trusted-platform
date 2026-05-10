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

import (
	"context"
	"encoding/base64"
)

// EncryptFunc performs AES-256-GCM encryption of the given plaintext bytes.
// The returned ciphertext contains the nonce, encrypted data, and authentication
// tag concatenated together. The implementation is provided by the KMS layer.
type EncryptFunc func(ctx context.Context, plaintext []byte) ([]byte, error)

// Encrypt encrypts plaintext using AES-256-GCM and returns the encrypted://
// URI string. The encryptFn performs the actual AES-256-GCM encryption,
// returning nonce || ciphertext || tag bytes. The result is base64url-encoded
// (no padding) and prefixed with the encrypted:// scheme.
func Encrypt(ctx context.Context, plaintext []byte, encryptFn EncryptFunc) (string, error) {
	if encryptFn == nil {
		return "", ErrEncryptFailed{
			Cause: ErrDecrypterRequired{},
		}
	}

	// Check context before starting
	if err := checkContext(ctx); err != nil {
		return "", err
	}

	ciphertext, err := encryptFn(ctx, plaintext)
	if err != nil {
		return "", ErrEncryptFailed{Cause: err}
	}

	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	return SchemeEncryptedURIPrefix + encoded, nil
}
