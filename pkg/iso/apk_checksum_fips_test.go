// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package iso

import (
	"errors"
	"fmt"
	"testing"
)

// TestAPKChecksumRefusedUnderFIPS pins the one FIPS gate in this repository
// that has NO approved alternative. The APKINDEX "Q1" field is defined as
// base64(SHA-1) and apk rejects anything else, so a FIPS build cannot satisfy
// the format and must refuse rather than emit an index apk would reject.
//
// The regression this guards against is a future change that returns a working
// hasher, or a nil error, and quietly reintroduces SHA-1 into a FIPS build.
func TestAPKChecksumRefusedUnderFIPS(t *testing.T) {
	hasher, err := newAPKChecksumHasher()

	if err == nil {
		t.Fatal("FIPS build returned no error; it must refuse to compute the Q1 checksum")
	}
	if hasher != nil {
		t.Error("hasher must be nil when the checksum is refused")
	}

	var typed ErrFIPSAPKChecksumUnavailable
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrFIPSAPKChecksumUnavailable, got %T: %v", err, err)
	}
	if typed.Error() == "" {
		t.Error("the typed error must explain why prefetch is unavailable")
	}
}

// TestIsFIPSChecksumRefusal_Discriminates pins the predicate that decides
// abort-vs-skip inside GenerateAPKINDEX. Getting this wrong in either
// direction is bad: returning false for the refusal reinstates the
// empty-index-reported-as-success defect, and returning true for an ordinary
// malformed package would abort a build that should just skip it.
func TestIsFIPSChecksumRefusal_Discriminates(t *testing.T) {
	if !isFIPSChecksumRefusal(ErrFIPSAPKChecksumUnavailable{}) {
		t.Error("the checksum refusal must be recognised, or the index silently ships empty")
	}
	if !isFIPSChecksumRefusal(fmt.Errorf("wrapped: %w", ErrFIPSAPKChecksumUnavailable{})) {
		t.Error("the refusal must be recognised through wrapping")
	}
	if isFIPSChecksumRefusal(errors.New("corrupt .apk archive")) {
		t.Error("an ordinary extraction failure must remain skippable, not abort the build")
	}
}
