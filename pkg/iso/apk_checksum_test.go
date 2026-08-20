// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

package iso

import (
	"crypto/sha1" // #nosec G505 -- asserting the APKINDEX Q1 format itself.
	"encoding/base64"
	"testing"
)

// TestAPKChecksumDefault proves the default build still produces the exact
// APKINDEX "Q1" value apk expects: base64 of the SHA-1 digest. Offline repo
// prefetch depends on it, and apk silently rejects an index whose checksums
// do not match.
func TestAPKChecksumDefault(t *testing.T) {
	hasher, err := newAPKChecksumHasher()
	if err != nil {
		t.Fatalf("non-FIPS build must provide the Q1 hasher: %v", err)
	}
	if hasher == nil {
		t.Fatal("hasher must not be nil in a non-FIPS build")
	}

	payload := []byte("apk package bytes")
	hasher.Write(payload)
	got := "Q1" + base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	sum := sha1.Sum(payload)
	want := "Q1" + base64.StdEncoding.EncodeToString(sum[:])

	if got != want {
		t.Errorf("Q1 checksum = %q, want %q", got, want)
	}
}
