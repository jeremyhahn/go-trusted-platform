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

package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// jsonDecoder returns the encoding/json Unmarshal function. Wrapped
// so a future swap to a faster decoder is a single-call change.
func jsonDecoder() func([]byte, interface{}) error {
	return json.Unmarshal
}

// jsonEncoder returns a marshal function that emits without HTML
// escaping and without indentation. The OCI manifest digest is the
// SHA-256 of the canonical byte representation; we don't try to
// reproduce a specific client's exact byte layout — the Distribution
// spec digest contract is "what the registry returned" not "what the
// client originally sent."
func jsonEncoder() func(interface{}) ([]byte, error) {
	return json.Marshal
}

// hexSha256 returns the hex-encoded SHA-256 sum of content.
func hexSha256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
