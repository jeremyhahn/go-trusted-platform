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

// Package secure provides primitives for handling sensitive values in memory.
//
// The Secret type wraps awnumar/memguard's LockedBuffer to keep credentials,
// keys, and other sensitive material in mlock'd, guard-paged memory that is
// zeroed on release. Values are never serialized in plaintext: marshaling
// emits a redacted placeholder regardless of format. This package is the
// platform-wide primitive for any sensitive value held in process memory.
package memguard

import (
	"crypto/subtle"

	"github.com/awnumar/memguard"
)

// redactedPlaceholder is the string emitted in any plaintext rendering or
// marshaling of a Secret. It must never be substituted with the actual value.
const redactedPlaceholder = "[REDACTED]"

// redactedJSON is the JSON literal emitted when a Secret is marshaled.
var redactedJSON = []byte(`"[REDACTED]"`)

// Secret holds a sensitive byte sequence in locked, guard-paged memory.
//
// The zero value is not usable; construct via New, NewFromString, or
// NewRandom. A destroyed Secret returns nil from Bytes and false from
// IsAlive. Secrets are not safe for concurrent Destroy with concurrent
// reads; callers must coordinate lifecycle.
//
// An empty Secret (zero-length value) is permitted and is alive until
// destroyed; it simply has no backing locked buffer.
type Secret struct {
	buf       *memguard.LockedBuffer
	alive     bool
	destroyed bool
}

// New wraps b in a locked memory region and zeroes the source slice.
// The caller must not retain b after this call.
func New(b []byte) *Secret {
	if len(b) == 0 {
		return &Secret{alive: true}
	}
	return &Secret{buf: memguard.NewBufferFromBytes(b), alive: true}
}

// NewFromString copies s into locked memory.
//
// Note: Go strings are immutable and live in the read-only data segment or
// on the heap; the original s cannot be wiped. Prefer New with a []byte
// that the caller can scrub. NewFromString exists for the unavoidable cases
// where input arrives as string (config files, flags).
func NewFromString(s string) *Secret {
	if s == "" {
		return &Secret{alive: true}
	}
	return &Secret{buf: memguard.NewBufferFromBytes([]byte(s)), alive: true}
}

// NewRandom generates a Secret of size random bytes from a CSPRNG.
func NewRandom(size int) (*Secret, error) {
	if size < 0 {
		return nil, ErrInvalidSize{Size: size}
	}
	if size == 0 {
		return &Secret{alive: true}, nil
	}
	return &Secret{buf: memguard.NewBufferRandom(size), alive: true}, nil
}

// Bytes returns the underlying byte slice. The caller must not retain the
// slice beyond the immediate use and must not modify it. Returns nil if the
// Secret has been destroyed. Prefer WithBytes for safer scoped access.
func (s *Secret) Bytes() []byte {
	if !s.IsAlive() {
		return nil
	}
	if s.buf == nil {
		return []byte{}
	}
	return s.buf.Bytes()
}

// WithBytes invokes fn with a borrowed view of the secret bytes. The slice
// passed to fn must not be retained or modified. Returns ErrDestroyed if
// the Secret is no longer alive.
func (s *Secret) WithBytes(fn func([]byte) error) error {
	if !s.IsAlive() {
		return ErrDestroyed{}
	}
	if s.buf == nil {
		return fn([]byte{})
	}
	return fn(s.buf.Bytes())
}

// Size returns the length of the secret in bytes, or 0 if destroyed.
func (s *Secret) Size() int {
	if !s.IsAlive() {
		return 0
	}
	if s.buf == nil {
		return 0
	}
	return s.buf.Size()
}

// IsAlive reports whether the secret memory is still allocated.
func (s *Secret) IsAlive() bool {
	return s != nil && s.alive && !s.destroyed
}

// Destroy wipes and frees the backing memory. Safe to call multiple times.
func (s *Secret) Destroy() {
	if s == nil || s.destroyed {
		return
	}
	s.destroyed = true
	s.alive = false
	if s.buf != nil && s.buf.IsAlive() {
		s.buf.Destroy()
	}
}

// Equal reports whether s and other hold byte-equal secrets, in constant
// time. Two destroyed secrets compare equal; a destroyed secret never
// equals a live one.
func (s *Secret) Equal(other *Secret) bool {
	sa := s.IsAlive()
	oa := other.IsAlive()
	if !sa && !oa {
		return true
	}
	if sa != oa {
		return false
	}
	return subtle.ConstantTimeCompare(s.Bytes(), other.Bytes()) == 1
}

// EqualBytes reports whether the secret equals b, in constant time.
// Always false if the secret has been destroyed.
func (s *Secret) EqualBytes(b []byte) bool {
	if !s.IsAlive() {
		return false
	}
	return subtle.ConstantTimeCompare(s.Bytes(), b) == 1
}

// String returns the redacted placeholder. The plaintext is never returned.
// This implements fmt.Stringer so logging a Secret cannot leak its value.
func (s *Secret) String() string {
	return redactedPlaceholder
}

// MarshalJSON emits a redacted JSON string. Plaintext is never serialized.
func (s *Secret) MarshalJSON() ([]byte, error) {
	return redactedJSON, nil
}

// UnmarshalJSON accepts a JSON string and stores it as the secret value.
// An explicit redacted placeholder is rejected to avoid accidentally
// round-tripping a redacted value as if it were the real secret.
func (s *Secret) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return ErrInvalidEncoding{Reason: "expected JSON string"}
	}
	raw := data[1 : len(data)-1]
	if string(raw) == redactedPlaceholder {
		return ErrRedactedInput{}
	}
	if len(raw) == 0 {
		s.alive = true
		return nil
	}
	s.buf = memguard.NewBufferFromBytes(append([]byte(nil), raw...))
	s.alive = true
	return nil
}

// MarshalYAML emits a redacted scalar. Plaintext is never serialized.
func (s *Secret) MarshalYAML() (any, error) {
	return redactedPlaceholder, nil
}

// UnmarshalYAML accepts a YAML scalar and stores it as the secret value.
// Rejects an explicit redacted placeholder to avoid round-trip leakage.
func (s *Secret) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return ErrInvalidEncoding{Reason: err.Error()}
	}
	if raw == redactedPlaceholder {
		return ErrRedactedInput{}
	}
	if raw == "" {
		s.alive = true
		return nil
	}
	s.buf = memguard.NewBufferFromBytes([]byte(raw))
	s.alive = true
	return nil
}
