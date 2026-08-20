// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package secureboot

import (
	"crypto/sha256"
	"testing"
)

// TestSubjectKeyIdentifier_FIPS pins the FIPS derivation. Module-signing certs
// are hardware-adjacent: the kernel matches a signature's signer identity
// against the certificate's SKI, so a silent change here means modules stop
// loading. The properties that matter are width, determinism, and that it is
// NOT the SHA-1 digest.
func TestSubjectKeyIdentifier_FIPS(t *testing.T) {
	spki := []byte("subject public key info fixture")

	skid := subjectKeyIdentifier(spki)

	if len(skid) != 20 {
		t.Fatalf("SKI length = %d, want 20 (the width every tool expects)", len(skid))
	}

	full := sha256.Sum256(spki)
	for i := range skid {
		if skid[i] != full[i] {
			t.Fatalf("SKI must be SHA-256 truncated to 20 bytes; byte %d = %#x, want %#x",
				i, skid[i], full[i])
		}
	}

	if again := subjectKeyIdentifier(spki); string(again) != string(skid) {
		t.Error("SKI derivation must be deterministic")
	}

	other := subjectKeyIdentifier([]byte("a different key"))
	if string(other) == string(skid) {
		t.Error("distinct SPKIs must yield distinct SKIs")
	}
}
