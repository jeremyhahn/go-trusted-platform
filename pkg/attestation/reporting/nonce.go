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

package reporting

import "crypto/rand"

// nonceBytes is the anti-replay nonce length. 32 bytes matches the SHA-256
// digest size the quote path already works in.
const nonceBytes = 32

// randomNonce is the production nonce source: crypto/rand, and an error
// rather than a fallback if it fails. A predictable nonce would let a
// recorded quote be replayed as a current one, so there is no degraded mode
// here — a collection that cannot get randomness does not happen.
func randomNonce() ([]byte, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
