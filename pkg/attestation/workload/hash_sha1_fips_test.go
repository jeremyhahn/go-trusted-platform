// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build fips

package workload

import (
	"context"
	"testing"
)

// TestFIPSRefusesSHA1Bank is the load-bearing assertion: a FIPS build must not
// compute a SHA-1 measurement, so every path that would do so fails closed
// with a typed error instead of returning a digest nobody may rely on.
func TestFIPSRefusesSHA1Bank(t *testing.T) {
	t.Run("getHasher", func(t *testing.T) {
		if h := getHasher(HashAlgorithmSHA1); h != nil {
			t.Error("FIPS build returned a SHA-1 hasher; it must return nil")
		}
	})

	t.Run("computeExpectedPCR", func(t *testing.T) {
		_, err := computeExpectedPCR(HashAlgorithmSHA1, make([]byte, 20), make([]byte, 20))
		if err == nil {
			t.Fatal("expected a typed refusal for the SHA-1 bank, got nil")
		}
		if _, ok := err.(ErrInvalidHashAlgorithm); !ok {
			t.Errorf("expected ErrInvalidHashAlgorithm, got %T: %v", err, err)
		}
	})

	t.Run("ExtendPCR", func(t *testing.T) {
		digest := make([]byte, 20)
		digest[0] = 0xAB
		if err := NewSoftwareTPM().ExtendPCR(context.Background(), 14, HashAlgorithmSHA1, digest); err == nil {
			t.Fatal("FIPS build extended a SHA-1 PCR bank; it must refuse")
		}
	})
}

// TestFIPSApprovedBanksStillWork guards the other direction: the gate must not
// take the approved algorithms down with it, or a FIPS build could measure
// nothing at all.
func TestFIPSApprovedBanksStillWork(t *testing.T) {
	for _, algo := range []HashAlgorithm{HashAlgorithmSHA256, HashAlgorithmSHA384, HashAlgorithmSHA512} {
		if h := getHasher(algo); h == nil {
			t.Errorf("approved algorithm %v unavailable under FIPS", algo)
		}
	}
	digest := make([]byte, 32)
	digest[0] = 0xFF
	if err := NewSoftwareTPM().ExtendPCR(context.Background(), 14, HashAlgorithmSHA256, digest); err != nil {
		t.Errorf("SHA-256 bank must work under FIPS: %v", err)
	}
}
