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
// The MemoryEnclave type keeps credentials, keys, and other sensitive
// material in mlock'd, guard-paged memory that is zeroed on release. Values
// are never serialized in plaintext: marshaling emits a redacted
// placeholder regardless of format.
//
// Any key, passphrase, token, share, private key or credential this process
// holds in memory belongs in a MemoryEnclave for its whole lifetime, and is
// zeroized on release — never a plain []byte or string.
//
// # Layering
//
// The locked region itself is owned by the stack, not by this package.
// MemoryEnclave holds a secure.Buffer obtained from the sanctioned SDK
// re-export github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure, which
// aliases go-xkms's alias of the canonical go-qrdb implementation. The
// platform does not import awnumar/memguard, and no platform code allocates
// locked memory by any other route.
//
// What this package adds on top of secure.Buffer is platform API the SDK
// re-export does not carry: the live zero-length enclave ("no value
// supplied" is a value, not a construction failure), scoped borrowing via
// Open, liveness reporting via IsAlive, constant-time comparison, and
// redacting marshalers. Those belong upstream; until the SDK exposes them
// the shape is preserved here so no caller has to change when it does.
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
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
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
	buf       *secure.Buffer
	alive     bool
	destroyed bool

	// lockErr records a failure to allocate the locked region. The
	// constructors report no error of their own, so an enclave that could
	// not be locked is born dead: it is never alive, reads fail closed,
	// and Open returns this error rather than the plaintext.
	lockErr error
}

// lockRegion copies b into a locked memory region owned by the SDK's
// protected-memory type, wiping b in the process. A zero-length b yields no
// region at all, which is how a live, empty enclave is represented.
func lockRegion(b []byte) (*secure.Buffer, error) {
	if len(b) == 0 {
		return nil, nil
	}
	return secure.NewBufferFromBytes(b)
}

// NewMemoryEnclave wraps b in a locked memory region and zeroes the source
// slice. The caller must not retain b after this call.
//
// There is no error return: a nil or empty b yields a live, zero-length
// enclave rather than a failure, because callers model "no value supplied"
// that way and validate it at the point of use with Size(). If the locked
// region cannot be allocated the enclave is born dead — reads fail closed
// and Open reports ErrLockFailed — rather than degrading to plaintext.
func NewMemoryEnclave(b []byte) *MemoryEnclave {
	buf, err := lockRegion(b)
	if err != nil {
		return &MemoryEnclave{lockErr: ErrLockFailed{Reason: err.Error()}}
	}
	return &MemoryEnclave{buf: buf, alive: true}
}

// NewMemoryEnclaveFromString copies s into locked memory.
//
// Note: Go strings are immutable and live in the read-only data segment or
// on the heap; the original s cannot be wiped. Prefer NewMemoryEnclave with
// a []byte the caller can scrub. NewMemoryEnclaveFromString exists for the
// unavoidable cases where input arrives as a string (config files, flags,
// decoded JSON request bodies).
func NewMemoryEnclaveFromString(s string) *MemoryEnclave {
	return NewMemoryEnclave([]byte(s))
}

// NewRandomMemoryEnclave generates an enclave of size random bytes from a
// CSPRNG.
//
// Note: the sanctioned SDK re-export carries only NewBufferFromBytes, so
// the draw lands in an ordinary heap slice that is wiped as it is copied
// into the locked region. The failure paths clear that slice with the
// builtin, the re-export carrying no wipe helper of its own. Both the
// momentary unlocked copy and the weaker wipe close when the SDK
// re-exports an allocate-then-fill constructor; see
// docs/security/protected-memory.md.
func NewRandomMemoryEnclave(size int) (*MemoryEnclave, error) {
	if size < 0 {
		return nil, ErrInvalidSize{Size: size}
	}
	if size == 0 {
		return &MemoryEnclave{alive: true}, nil
	}

	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		clear(b)
		return nil, ErrRandomSource{Reason: err.Error()}
	}

	buf, err := lockRegion(b)
	if err != nil {
		clear(b)
		return nil, ErrLockFailed{Reason: err.Error()}
	}
	return &MemoryEnclave{buf: buf, alive: true}, nil
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
// the enclave is no longer alive, or ErrLockFailed if its locked region was
// never allocated.
func (e *MemoryEnclave) Open(fn func([]byte) error) error {
	if !e.IsAlive() {
		if e != nil && e.lockErr != nil {
			return e.lockErr
		}
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
	e.buf.Destroy()
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
// Any region already held is destroyed first, so a replaced value cannot be
// read back afterwards and its locked pages are not leaked. The enclave is
// marked dead for the duration and revived only once the new region is in
// hand, so a failed replacement leaves nothing readable behind. Reviving
// also keeps Destroy honest: without clearing the flag, a later Destroy
// would return early and leave the newly locked value unwiped.
//
// An empty b leaves the enclave alive with no backing region, matching the
// zero-length contract of NewMemoryEnclave.
func (e *MemoryEnclave) reset(b []byte) error {
	e.buf.Destroy()
	e.buf = nil
	e.alive = false
	e.destroyed = true
	e.lockErr = nil

	buf, err := lockRegion(b)
	if err != nil {
		e.lockErr = ErrLockFailed{Reason: err.Error()}
		return e.lockErr
	}

	e.buf = buf
	e.alive = true
	e.destroyed = false
	return nil
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
	return e.reset([]byte(raw))
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
	return e.reset([]byte(raw))
}
