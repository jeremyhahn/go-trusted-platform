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

package memguard

// This file holds the pre-MemoryEnclave names. They are kept as aliases so
// the rename does not break any caller ahead of the coordinated
// portfolio-wide protected-memory wave, and are removed in that wave. No
// new code may use them.

// Secret is the former name of MemoryEnclave.
//
// Deprecated: use MemoryEnclave. "Secret" is ambiguous in this codebase —
// it already means a config value, a secret reference URI, an ACME account
// secret and a Shamir share. The type name describes its mechanism: a
// region of locked, zeroized memory.
type Secret = MemoryEnclave

// New wraps b in a locked memory region and zeroes the source slice.
//
// Deprecated: use NewMemoryEnclave.
func New(b []byte) *MemoryEnclave {
	return NewMemoryEnclave(b)
}

// NewFromString copies s into locked memory.
//
// Deprecated: use NewMemoryEnclaveFromString.
func NewFromString(s string) *MemoryEnclave {
	return NewMemoryEnclaveFromString(s)
}

// NewRandom generates an enclave of size random bytes from a CSPRNG.
//
// Deprecated: use NewRandomMemoryEnclave.
func NewRandom(size int) (*MemoryEnclave, error) {
	return NewRandomMemoryEnclave(size)
}

// WithBytes invokes fn with a borrowed view of the enclave bytes.
//
// Deprecated: use MemoryEnclave.Open.
func (e *MemoryEnclave) WithBytes(fn func([]byte) error) error {
	return e.Open(fn)
}
