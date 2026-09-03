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

import "fmt"

// ErrDestroyed indicates an operation was attempted on a MemoryEnclave
// whose backing memory has been wiped and freed.
type ErrDestroyed struct{}

func (ErrDestroyed) Error() string {
	return "memguard: enclave has been destroyed"
}

// ErrInvalidSize indicates a non-negative size was required.
type ErrInvalidSize struct {
	Size int
}

func (e ErrInvalidSize) Error() string {
	return fmt.Sprintf("memguard: invalid size: %d", e.Size)
}

// ErrInvalidEncoding indicates the input could not be decoded into a
// MemoryEnclave.
type ErrInvalidEncoding struct {
	Reason string
}

func (e ErrInvalidEncoding) Error() string {
	return "memguard: invalid encoding: " + e.Reason
}

// ErrRedactedInput indicates the unmarshal input was the redacted
// placeholder, which would silently lose the original value.
type ErrRedactedInput struct{}

func (ErrRedactedInput) Error() string {
	return "memguard: refusing to unmarshal redacted placeholder into an enclave"
}

// ErrLockFailed indicates the locked memory region backing a
// MemoryEnclave could not be allocated. An enclave in this state is dead:
// it never reports alive, reads return nothing, and Open returns this
// error rather than any plaintext.
type ErrLockFailed struct {
	Reason string
}

func (e ErrLockFailed) Error() string {
	return "memguard: cannot allocate locked memory: " + e.Reason
}

// ErrRandomSource indicates the CSPRNG failed while filling an enclave.
type ErrRandomSource struct {
	Reason string
}

func (e ErrRandomSource) Error() string {
	return "memguard: random source failed: " + e.Reason
}

// ErrFileUnreadable indicates a file could not be read into locked memory.
type ErrFileUnreadable struct {
	Path   string
	Reason string
}

func (e ErrFileUnreadable) Error() string {
	return fmt.Sprintf("memguard: cannot read %s into locked memory: %s", e.Path, e.Reason)
}

// ErrFileTooLarge indicates a file exceeds the largest region this package
// will lock in memory. Locked pages are a finite process resource, so the
// bound is enforced rather than left to the caller.
type ErrFileTooLarge struct {
	Path  string
	Size  int64
	Limit int64
}

func (e ErrFileTooLarge) Error() string {
	return fmt.Sprintf("memguard: %s is %d bytes, above the %d byte locked-memory limit",
		e.Path, e.Size, e.Limit)
}
