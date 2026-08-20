// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

package secureboot

import (
	"crypto/sha1" // #nosec G505 -- asserting the non-FIPS SKI derivation itself.
	"testing"
)

// TestSubjectKeyIdentifier_Default proves the default build still derives the
// SKI exactly as before (RFC 5280 method 1, SHA-1 of the SPKI). This is the
// guard that keeps already-deployed module-signing certificates working: if
// this value ever changed silently, previously-signed modules could stop
// verifying.
func TestSubjectKeyIdentifier_Default(t *testing.T) {
	spki := []byte("subject public key info fixture")

	skid := subjectKeyIdentifier(spki)

	want := sha1.Sum(spki)
	if len(skid) != len(want) {
		t.Fatalf("SKI length = %d, want %d", len(skid), len(want))
	}
	for i := range skid {
		if skid[i] != want[i] {
			t.Fatalf("non-FIPS SKI must remain SHA-1(SPKI); byte %d = %#x, want %#x",
				i, skid[i], want[i])
		}
	}
}
