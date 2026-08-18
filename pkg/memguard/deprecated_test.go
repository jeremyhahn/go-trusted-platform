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

import (
	"bytes"
	"errors"
	"testing"
)

// The deprecated names must keep behaving exactly like the MemoryEnclave
// names until the coordinated portfolio-wide protected-memory wave removes
// them. These tests are the regression guard for that promise.

// Compile-time proof that Secret is an alias of MemoryEnclave rather than a
// distinct defined type; if it were ever redefined this stops compiling.
var _ *Secret = (*MemoryEnclave)(nil)

func TestDeprecated_SecretObservesMemoryEnclave(t *testing.T) {
	enclave := New([]byte("alias"))
	defer enclave.Destroy()

	alias := (*Secret)(enclave)
	if !alias.EqualBytes([]byte("alias")) {
		t.Error("Secret alias does not observe the MemoryEnclave contents")
	}
	enclave.Destroy()
	if alias.IsAlive() {
		t.Error("destroying through MemoryEnclave left the Secret alias alive")
	}
}

func TestDeprecated_NewMatchesNewMemoryEnclave(t *testing.T) {
	old := New([]byte("credential"))
	defer old.Destroy()
	current := NewMemoryEnclave([]byte("credential"))
	defer current.Destroy()

	if !old.Equal(current) {
		t.Error("New and NewMemoryEnclave produced different contents")
	}
	if !old.IsAlive() || old.Size() != len("credential") {
		t.Errorf("New: alive=%v size=%d, want alive size=%d",
			old.IsAlive(), old.Size(), len("credential"))
	}
}

func TestDeprecated_NewEmptyStaysAlive(t *testing.T) {
	// The "no value supplied" contract: nil input yields a live, empty
	// enclave rather than a failure, so callees can reject it via Size().
	e := New(nil)
	defer e.Destroy()

	if !e.IsAlive() {
		t.Error("New(nil) is not alive")
	}
	if e.Size() != 0 {
		t.Errorf("New(nil).Size() = %d, want 0", e.Size())
	}
}

func TestDeprecated_NewFromStringMatchesNewMemoryEnclaveFromString(t *testing.T) {
	old := NewFromString("hunter2")
	defer old.Destroy()
	current := NewMemoryEnclaveFromString("hunter2")
	defer current.Destroy()

	if !old.Equal(current) {
		t.Error("NewFromString and NewMemoryEnclaveFromString differ")
	}
}

func TestDeprecated_NewFromStringEmptyStaysAlive(t *testing.T) {
	e := NewFromString("")
	defer e.Destroy()

	if !e.IsAlive() || e.Size() != 0 {
		t.Errorf("NewFromString(\"\"): alive=%v size=%d, want alive and 0",
			e.IsAlive(), e.Size())
	}
}

func TestDeprecated_NewRandomMatchesNewRandomMemoryEnclave(t *testing.T) {
	e, err := NewRandom(16)
	if err != nil {
		t.Fatalf("NewRandom(16): %v", err)
	}
	defer e.Destroy()

	if e.Size() != 16 {
		t.Errorf("NewRandom(16).Size() = %d, want 16", e.Size())
	}
	if bytes.Equal(e.Bytes(), make([]byte, 16)) {
		t.Error("NewRandom returned an all-zero buffer")
	}
}

func TestDeprecated_NewRandomRejectsNegativeSize(t *testing.T) {
	_, err := NewRandom(-1)

	var want ErrInvalidSize
	if !errors.As(err, &want) {
		t.Fatalf("NewRandom(-1) err = %v, want ErrInvalidSize", err)
	}
	if want.Size != -1 {
		t.Errorf("ErrInvalidSize.Size = %d, want -1", want.Size)
	}
}

func TestDeprecated_WithBytesDelegatesToOpen(t *testing.T) {
	e := New([]byte("borrowed"))
	defer e.Destroy()

	var seen []byte
	if err := e.WithBytes(func(b []byte) error {
		seen = append(seen, b...)
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if string(seen) != "borrowed" {
		t.Errorf("WithBytes saw %q, want %q", seen, "borrowed")
	}
}

func TestDeprecated_WithBytesAfterDestroy(t *testing.T) {
	e := New([]byte("gone"))
	e.Destroy()

	err := e.WithBytes(func([]byte) error {
		t.Error("callback ran on a destroyed enclave")
		return nil
	})

	var want ErrDestroyed
	if !errors.As(err, &want) {
		t.Fatalf("WithBytes after Destroy err = %v, want ErrDestroyed", err)
	}
}
