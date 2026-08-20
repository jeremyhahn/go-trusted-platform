// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build !fips

// SHA-1 PCR bank coverage for the default build. A FIPS build refuses to
// compute SHA-1 (hash_sha1_fips.go), so these assertions describe behaviour it
// deliberately does not have; the FIPS counterparts live in
// hash_sha1_fips_test.go. Separated by build tag rather than skipped: the
// SHA-1 bank is real hardware behaviour and must keep its coverage in the
// build that supports it.

package workload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
)

func TestComputeExpectedPCR_SHA1(t *testing.T) {
	currentPCR := make([]byte, 20)
	digest := make([]byte, 20)
	digest[0] = 0xFF

	newPCR, err := computeExpectedPCR(HashAlgorithmSHA1, currentPCR, digest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(newPCR) != 20 {
		t.Errorf("PCR size = %d, want 20", len(newPCR))
	}
}

func TestSoftwareTPM_ExtendPCR_DifferentBanks(t *testing.T) {
	tpm := NewSoftwareTPM()
	ctx := context.Background()

	// Extend SHA256 bank
	digest256 := make([]byte, 32)
	digest256[0] = 0xFF
	if err := tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest256); err != nil {
		t.Fatalf("ExtendPCR SHA256 failed: %v", err)
	}

	// SHA1 bank should still be zero
	value1, _ := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA1)
	zeroSHA1 := make([]byte, 20)
	if !bytes.Equal(value1, zeroSHA1) {
		t.Error("SHA1 bank should be unchanged")
	}

	// Extend SHA1 bank
	digest1 := make([]byte, 20)
	digest1[0] = 0xAB
	if err := tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA1, digest1); err != nil {
		t.Fatalf("ExtendPCR SHA1 failed: %v", err)
	}

	// SHA256 bank should be unchanged from before
	value256, _ := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)
	expected256 := sha256.New()
	expected256.Write(make([]byte, 32))
	expected256.Write(digest256)
	if !bytes.Equal(value256, expected256.Sum(nil)) {
		t.Error("SHA256 bank should be unchanged after SHA1 extension")
	}
}

func TestComputeDigest_SHA1(t *testing.T) {
	measurement := &WorkloadMeasurement{
		WorkloadType: WorkloadTypeVM,
		WorkloadID:   "vm-uuid",
		ImageDigest:  "digest",
	}

	digest, err := computeDigest(HashAlgorithmSHA1, measurement)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(digest) != 20 {
		t.Errorf("digest size = %d, want 20", len(digest))
	}
}

// TestGetHasher_SHA1 keeps the SHA-1 row of the getHasher table covered in the
// build that supports it, after it was lifted out of the shared table test.
func TestGetHasher_SHA1(t *testing.T) {
	hasher := getHasher(HashAlgorithmSHA1)
	if hasher == nil {
		t.Fatal("expected a SHA-1 hasher in a non-FIPS build")
	}
	hasher.Write([]byte("test"))
	if got := len(hasher.Sum(nil)); got != 20 {
		t.Errorf("digest size = %d, want 20", got)
	}
}
