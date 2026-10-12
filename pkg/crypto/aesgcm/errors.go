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

package aesgcm

import "fmt"

// ErrCiphertextTooShort is returned by Open for a blob shorter than a nonce
// plus an authentication tag, which therefore cannot be anything Seal produced.
type ErrCiphertextTooShort struct {
	Length int
}

// Error implements the error interface.
func (e ErrCiphertextTooShort) Error() string {
	return fmt.Sprintf("aesgcm: ciphertext of %d bytes is shorter than nonce and tag (%d bytes)",
		e.Length, NonceSize+TagSize)
}
