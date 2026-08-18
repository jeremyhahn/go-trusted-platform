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

// Package memguard provides the platform's protected-memory primitive.
//
// The MemoryEnclave type wraps awnumar/memguard's LockedBuffer to keep
// credentials, keys, and other sensitive material in mlock'd, guard-paged
// memory that is zeroed on release. Values are never serialized in
// plaintext: marshaling emits a redacted placeholder regardless of format.
//
// Any key, passphrase, token, share, private key or credential this process
// holds in memory belongs in a MemoryEnclave for its whole lifetime, and is
// zeroized on release — never a plain []byte or string.
//
// # Naming
//
// The type is deliberately named for its mechanism — a region of locked,
// zeroized memory — and not "Secret". "Secret" is ambiguous across this
// codebase: it already denotes a config value, a secret *reference*
// (kms:// / env:// / file:// URIs), an ACME account secret and a Shamir
// share, none of which are a buffer of locked memory. MemoryEnclave is the
// portfolio-wide vocabulary; do not introduce SecureString, SecureBytes,
// ProtectedBuffer or any other repo-local synonym.
//
// # Deprecated names
//
// Secret, New, NewFromString, NewRandom and MemoryEnclave.WithBytes remain
// as deprecated aliases so no caller breaks; see deprecated.go. They are
// removed in the coordinated portfolio-wide protected-memory wave.
package memguard

import (
	"crypto/subtle"
	"encoding/json"

	"github.com/awnumar/memguard"
)

// redactedPlaceholder is the string emitted in any plaintext rendering or
// marshaling of a MemoryEnclave. It must never be substituted with the
// actual value.
const redactedPlaceholder = "[REDACTED]"

// redactedJSON is the JSON literal emitted when a MemoryEnclave is marshaled.
var redactedJSON = []byte(`"[REDACTED]"`)

// MemoryEnclave holds a sensitive byte sequence in locked, guard-paged
// memory that is zeroed on release.
//
// The zero value is not usable; construct via NewMemoryEnclave,
// NewMemoryEnclaveFromString, or NewRandomMemoryEnclave. A destroyed
// enclave returns nil from Bytes and false from IsAlive. Enclaves are not
// safe for concurrent Destroy with concurrent reads; callers must
// coordinate lifecycle.
//
// An empty enclave (zero-length value) is permitted and is alive until
// destroyed; it simply has no backing locked buffer. Callers rely on this:
// "no password supplied" is modelled as a live, zero-length enclave that
// the callee rejects via Size() == 0, not as a construction failure.
type MemoryEnclave struct {
	buf       *memguard.LockedBuffer
	alive     bool
	destroyed bool
}

// NewMemoryEnclave wraps b in a locked memory region and zeroes the source
// slice. The caller must not retain b after this call.
//
// There is no error return: a nil or empty b yields a live, zero-length
// enclave rather than a failure, because callers model "no value supplied"
// that way and validate it at the point of use with Size().
func NewMemoryEnclave(b []byte) *MemoryEnclave {
	if len(b) == 0 {
		return &MemoryEnclave{alive: true}
	}
	return &MemoryEnclave{buf: memguard.NewBufferFromBytes(b), alive: true}
}

// NewMemoryEnclaveFromString copies s into locked memory.
//
// Note: Go strings are immutable and live in the read-only data segment or
// on the heap; the original s cannot be wiped. Prefer NewMemoryEnclave with
// a []byte the caller can scrub. NewMemoryEnclaveFromString exists for the
// unavoidable cases where input arrives as a string (config files, flags,
// decoded JSON request bodies).
func NewMemoryEnclaveFromString(s string) *MemoryEnclave {
	if s == "" {
		return &MemoryEnclave{alive: true}
	}
	return &MemoryEnclave{buf: memguard.NewBufferFromBytes([]byte(s)), alive: true}
}

// NewRandomMemoryEnclave generates an enclave of size random bytes from a
// CSPRNG.
func NewRandomMemoryEnclave(size int) (*MemoryEnclave, error) {
	if size < 0 {
		return nil, ErrInvalidSize{Size: size}
	}
	if size == 0 {
		return &MemoryEnclave{alive: true}, nil
	}
	return &MemoryEnclave{buf: memguard.NewBufferRandom(size), alive: true}, nil
}

// Bytes returns the underlying byte slice. The caller must not retain the
// slice beyond the immediate use and must not modify it. Returns nil if the
// enclave has been destroyed. Prefer Open for safer scoped access.
func (e *MemoryEnclave) Bytes() []byte {
	if !e.IsAlive() {
		return nil
	}
	if e.buf == nil {
		return []byte{}
	}
	return e.buf.Bytes()
}

// Open invokes fn with a borrowed view of the enclave bytes. The slice
// passed to fn must not be retained or modified. Returns ErrDestroyed if
// the enclave is no longer alive.
func (e *MemoryEnclave) Open(fn func([]byte) error) error {
	if !e.IsAlive() {
		return ErrDestroyed{}
	}
	if e.buf == nil {
		return fn([]byte{})
	}
	return fn(e.buf.Bytes())
}

// Size returns the length of the enclave contents in bytes, or 0 if
// destroyed.
func (e *MemoryEnclave) Size() int {
	if !e.IsAlive() {
		return 0
	}
	if e.buf == nil {
		return 0
	}
	return e.buf.Size()
}

// IsAlive reports whether the enclave memory is still allocated.
func (e *MemoryEnclave) IsAlive() bool {
	return e != nil && e.alive && !e.destroyed
}

// Destroy wipes and frees the backing memory. Safe to call multiple times.
func (e *MemoryEnclave) Destroy() {
	if e == nil || e.destroyed {
		return
	}
	e.destroyed = true
	e.alive = false
	if e.buf != nil && e.buf.IsAlive() {
		e.buf.Destroy()
	}
}

// Equal reports whether e and other hold byte-equal contents, in constant
// time. Two destroyed enclaves compare equal; a destroyed enclave never
// equals a live one.
func (e *MemoryEnclave) Equal(other *MemoryEnclave) bool {
	ea := e.IsAlive()
	oa := other.IsAlive()
	if !ea && !oa {
		return true
	}
	if ea != oa {
		return false
	}
	return subtle.ConstantTimeCompare(e.Bytes(), other.Bytes()) == 1
}

// EqualBytes reports whether the enclave contents equal b, in constant
// time. Always false if the enclave has been destroyed.
func (e *MemoryEnclave) EqualBytes(b []byte) bool {
	if !e.IsAlive() {
		return false
	}
	return subtle.ConstantTimeCompare(e.Bytes(), b) == 1
}

// String returns the redacted placeholder. The plaintext is never returned.
// This implements fmt.Stringer so logging an enclave cannot leak its value.
func (e *MemoryEnclave) String() string {
	return redactedPlaceholder
}

// reset replaces the enclave contents with b.
//
// Any buffer already held is destroyed first, so a replaced value cannot be
// read back afterwards and its locked pages are not leaked. An enclave that
// was previously destroyed is revived, which keeps Destroy honest: without
// clearing the flag, a later Destroy would return early and leave the newly
// locked value unwiped.
//
// An empty b leaves the enclave alive with no backing buffer, matching the
// zero-length contract of NewMemoryEnclave.
func (e *MemoryEnclave) reset(b []byte) {
	if e.buf != nil && e.buf.IsAlive() {
		e.buf.Destroy()
	}
	e.buf = nil
	e.alive = true
	e.destroyed = false
	if len(b) > 0 {
		e.buf = memguard.NewBufferFromBytes(b)
	}
}

// MarshalJSON emits a redacted JSON string. Plaintext is never serialized.
func (e *MemoryEnclave) MarshalJSON() ([]byte, error) {
	return redactedJSON, nil
}

// UnmarshalJSON accepts a JSON string and stores its decoded value.
//
// Decoding goes through encoding/json so escape sequences (\", \\, control
// characters, \uXXXX) yield the value the sender meant rather than its wire
// spelling, and so an escaped spelling of the redacted placeholder cannot
// slip past the sentinel check. The redacted placeholder is rejected to
// avoid round-tripping a redacted value as if it were the real one.
//
// Note: encoding/json hands back a Go string, which cannot be wiped. That
// intermediate is unavoidable for a JSON string field; it is the same
// decode-boundary gap recorded in docs/security/protected-memory.md.
func (e *MemoryEnclave) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return ErrInvalidEncoding{Reason: err.Error()}
	}
	if raw == redactedPlaceholder {
		return ErrRedactedInput{}
	}
	e.reset([]byte(raw))
	return nil
}

// MarshalYAML emits a redacted scalar. Plaintext is never serialized.
func (e *MemoryEnclave) MarshalYAML() (any, error) {
	return redactedPlaceholder, nil
}

// UnmarshalYAML accepts a YAML scalar and stores it as the enclave value.
// Rejects an explicit redacted placeholder to avoid round-trip leakage.
func (e *MemoryEnclave) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return ErrInvalidEncoding{Reason: err.Error()}
	}
	if raw == redactedPlaceholder {
		return ErrRedactedInput{}
	}
	e.reset([]byte(raw))
	return nil
}
