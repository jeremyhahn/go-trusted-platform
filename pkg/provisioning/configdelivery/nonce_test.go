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

package configdelivery

import (
	"testing"
	"time"
)

func TestNonceStore_Issue(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)

	nonce1, err := ns.Issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nonce1 == "" {
		t.Fatal("expected non-empty nonce")
	}
	if len(nonce1) != nonceLength*2 { // hex encoding doubles length
		t.Fatalf("expected nonce length %d, got %d", nonceLength*2, len(nonce1))
	}

	nonce2, err := ns.Issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nonce1 == nonce2 {
		t.Fatal("expected unique nonces, got duplicates")
	}
}

func TestNonceStore_Validate(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)

	nonce, err := ns.Issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ns.Validate(nonce) {
		t.Fatal("expected valid nonce to return true")
	}
}

func TestNonceStore_Validate_Expired(t *testing.T) {
	ns := NewNonceStore(1 * time.Nanosecond)

	nonce, err := ns.Issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The nonce TTL is 1ns, so by the time we validate it should be expired.
	// Busy-wait until at least 1ns has elapsed to guarantee expiration.
	deadline := time.Now().Add(2 * time.Nanosecond)
	for time.Now().Before(deadline) {
		// spin until the nanosecond TTL has elapsed
	}

	if ns.Validate(nonce) {
		t.Fatal("expected expired nonce to return false")
	}
}

func TestNonceStore_Validate_AlreadyUsed(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)

	nonce, err := ns.Issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ns.Validate(nonce) {
		t.Fatal("expected first validation to return true")
	}

	if ns.Validate(nonce) {
		t.Fatal("expected second validation to return false (already used)")
	}
}

func TestNonceStore_Validate_Unknown(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)

	if ns.Validate("nonexistent-nonce-value") {
		t.Fatal("expected unknown nonce to return false")
	}
}
