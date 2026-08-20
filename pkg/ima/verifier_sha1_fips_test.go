// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package ima

import (
	"errors"
	"testing"
)

// TestVerifier_getHasher_SHA1_FIPS is the load-bearing half of "parse but never
// trust": a FIPS build must refuse to COMPUTE a SHA-1 digest, so a caller can
// never receive a verification pass that rests on it.
func TestVerifier_getHasher_SHA1_FIPS(t *testing.T) {
	h, err := NewVerifier().getHasher("sha1")
	if err == nil {
		t.Fatal("FIPS build returned a SHA-1 hasher; it must fail closed")
	}
	if h != nil {
		t.Error("hasher must be nil when the algorithm is refused")
	}
	var fipsErr ErrFIPSHashNotApproved
	if !errors.As(err, &fipsErr) {
		t.Fatalf("expected ErrFIPSHashNotApproved, got %T: %v", err, err)
	}
	if fipsErr.Algorithm != "sha1" {
		t.Errorf("Algorithm = %q, want %q", fipsErr.Algorithm, "sha1")
	}
}

// TestVerifier_ParsesSHA1LengthUnderFIPS proves the measurement stays READABLE:
// length dispatch uses a constant, so a SHA-1 entry is still structurally
// valid even though it cannot be verified. Losing this would mean a FIPS build
// could not read a SHA-1 IMA log at all, which is not what the gate is for.
func TestVerifier_ParsesSHA1LengthUnderFIPS(t *testing.T) {
	if sha1DigestSize != 20 {
		t.Fatalf("sha1DigestSize = %d, want 20", sha1DigestSize)
	}
	v := NewVerifier()
	err := v.verifyTemplateHash(&Event{TemplateHash: make([]byte, sha1DigestSize)})
	if err != nil {
		t.Errorf("a SHA-1-length template hash must remain parseable under FIPS: %v", err)
	}
}

// TestVerifyEventLog_RefusesSHA1UnderFIPS is the regression test for the defect
// Codex caught on the first pass of #24: parsing was gated but VERIFYING was
// not, so an event log whose entries are SHA-1 still came back Passed=true
// purely because a 20-byte template hash is structurally valid. "Parse but
// never trust" is only half-implemented without this.
func TestVerifyEventLog_RefusesSHA1UnderFIPS(t *testing.T) {
	v := NewVerifier()
	log := &EventLog{Events: []*Event{{
		PCR:           10,
		HashAlgorithm: "sha1",
		TemplateHash:  make([]byte, sha1DigestSize),
		FilePath:      "/usr/bin/example",
	}}}

	result := v.VerifyEventLog(log)
	if result == nil {
		t.Fatal("VerifyEventLog returned nil")
	}
	if result.Passed {
		t.Error("a SHA-1 event log must NOT pass verification in a FIPS build")
	}
}

// TestVerifyEventLog_ApprovedStillPasses guards the other direction: the
// refusal must not reject approved algorithms, or FIPS verification would be
// vacuous.
func TestVerifyEventLog_ApprovedStillPasses(t *testing.T) {
	v := NewVerifier()
	log := &EventLog{Events: []*Event{{
		PCR:           10,
		HashAlgorithm: "sha256",
		TemplateHash:  make([]byte, 32),
		FilePath:      "/usr/bin/example",
	}}}

	result := v.VerifyEventLog(log)
	if result == nil {
		t.Fatal("VerifyEventLog returned nil")
	}
	if !result.Passed {
		t.Errorf("a SHA-256 event log must still pass under FIPS: %+v", result)
	}
}

// TestVerifyEventLog_RefusesSHA1TemplateHashRegardlessOfLabel is the regression
// test for the second defect the hosted review caught on PR #27.
//
// In an ima-ng record, HashAlgorithm describes the FILE DATA hash, not the
// template hash. So a perfectly ordinary event can declare "sha256" and still
// carry a 20-byte SHA-1 TemplateHash. Checking only the label passed that shape
// with Passed=true — a FIPS verification verdict resting on SHA-1, which is the
// exact outcome this gate exists to prevent.
func TestVerifyEventLog_RefusesSHA1TemplateHashRegardlessOfLabel(t *testing.T) {
	cases := []struct {
		name string
		alg  string
	}{
		{"label claims sha256", "sha256"},
		{"label claims sha512", "sha512"},
		{"label absent", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := NewVerifier().VerifyEventLog(&EventLog{Events: []*Event{{
				PCR:           10,
				HashAlgorithm: tc.alg,
				TemplateHash:  make([]byte, sha1DigestSize), // 20 bytes = SHA-1 width
				FilePath:      "/usr/bin/example",
			}}})
			if result == nil {
				t.Fatal("VerifyEventLog returned nil")
			}
			if result.Passed {
				t.Errorf("a 20-byte template hash must not pass under FIPS even when the label says %q", tc.alg)
			}
		})
	}
}
