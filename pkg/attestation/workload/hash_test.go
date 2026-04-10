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

package workload

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestGetHasher(t *testing.T) {
	tests := []struct {
		algorithm    HashAlgorithm
		expectedSize int
		expectNil    bool
	}{
		{HashAlgorithmSHA1, 20, false},
		{HashAlgorithmSHA256, 32, false},
		{HashAlgorithmSHA384, 48, false},
		{HashAlgorithmSHA512, 64, false},
		{HashAlgorithm("invalid"), 0, true},
		{HashAlgorithm(""), 0, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			hasher := getHasher(tt.algorithm)
			if tt.expectNil {
				if hasher != nil {
					t.Error("expected nil hasher for invalid algorithm")
				}
			} else {
				if hasher == nil {
					t.Error("expected non-nil hasher")
					return
				}
				// Test that the hasher produces the expected size
				hasher.Write([]byte("test"))
				result := hasher.Sum(nil)
				if len(result) != tt.expectedSize {
					t.Errorf("digest size = %d, want %d", len(result), tt.expectedSize)
				}
			}
		})
	}
}

func TestComputeDigest(t *testing.T) {
	t.Run("valid SHA256 digest", func(t *testing.T) {
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "abc123",
			ImageDigest:  "sha256:xyz789",
		}

		digest, err := computeDigest(HashAlgorithmSHA256, measurement)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(digest) != 32 {
			t.Errorf("digest size = %d, want 32", len(digest))
		}

		// Verify the digest is computed correctly
		expected := sha256.New()
		expected.Write([]byte("container|abc123|sha256:xyz789"))
		if !bytes.Equal(digest, expected.Sum(nil)) {
			t.Error("digest does not match expected value")
		}
	})

	t.Run("valid SHA1 digest", func(t *testing.T) {
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
	})

	t.Run("valid SHA384 digest", func(t *testing.T) {
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "test",
			ImageDigest:  "test",
		}

		digest, err := computeDigest(HashAlgorithmSHA384, measurement)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(digest) != 48 {
			t.Errorf("digest size = %d, want 48", len(digest))
		}
	})

	t.Run("valid SHA512 digest", func(t *testing.T) {
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeVM,
			WorkloadID:   "test",
			ImageDigest:  "test",
		}

		digest, err := computeDigest(HashAlgorithmSHA512, measurement)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(digest) != 64 {
			t.Errorf("digest size = %d, want 64", len(digest))
		}
	})

	t.Run("empty image digest", func(t *testing.T) {
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "abc123",
			ImageDigest:  "",
		}

		digest, err := computeDigest(HashAlgorithmSHA256, measurement)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should still produce a valid hash
		expected := sha256.New()
		expected.Write([]byte("container|abc123|"))
		if !bytes.Equal(digest, expected.Sum(nil)) {
			t.Error("digest does not match expected value")
		}
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "abc123",
			ImageDigest:  "test",
		}

		_, err := computeDigest(HashAlgorithm("invalid"), measurement)
		if err == nil {
			t.Error("expected error for invalid algorithm")
		}

		errInvalid, ok := err.(ErrInvalidHashAlgorithm)
		if !ok {
			t.Errorf("expected ErrInvalidHashAlgorithm, got %T", err)
		}
		if errInvalid.Algorithm != "invalid" {
			t.Errorf("Algorithm = %s, want invalid", errInvalid.Algorithm)
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "abc123",
			ImageDigest:  "sha256:xyz789",
		}

		digest1, _ := computeDigest(HashAlgorithmSHA256, measurement)
		digest2, _ := computeDigest(HashAlgorithmSHA256, measurement)

		if !bytes.Equal(digest1, digest2) {
			t.Error("digest should be deterministic")
		}
	})
}

func TestComputeExpectedPCR(t *testing.T) {
	t.Run("valid extension", func(t *testing.T) {
		currentPCR := make([]byte, 32) // Zero PCR
		digest := make([]byte, 32)
		for i := range digest {
			digest[i] = byte(i)
		}

		newPCR, err := computeExpectedPCR(HashAlgorithmSHA256, currentPCR, digest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(newPCR) != 32 {
			t.Errorf("PCR size = %d, want 32", len(newPCR))
		}

		// Verify the extension is computed correctly
		expected := sha256.New()
		expected.Write(currentPCR)
		expected.Write(digest)
		if !bytes.Equal(newPCR, expected.Sum(nil)) {
			t.Error("PCR does not match expected value")
		}
	})

	t.Run("chained extensions", func(t *testing.T) {
		pcr := make([]byte, 32) // Start with zero PCR

		// First extension
		digest1 := make([]byte, 32)
		digest1[0] = 0x01
		pcr, _ = computeExpectedPCR(HashAlgorithmSHA256, pcr, digest1)

		// Second extension
		digest2 := make([]byte, 32)
		digest2[0] = 0x02
		pcr, _ = computeExpectedPCR(HashAlgorithmSHA256, pcr, digest2)

		// Third extension
		digest3 := make([]byte, 32)
		digest3[0] = 0x03
		pcr, _ = computeExpectedPCR(HashAlgorithmSHA256, pcr, digest3)

		// PCR should not be zero anymore
		zeroPCR := make([]byte, 32)
		if bytes.Equal(pcr, zeroPCR) {
			t.Error("PCR should not be zero after extensions")
		}

		if len(pcr) != 32 {
			t.Errorf("PCR size = %d, want 32", len(pcr))
		}
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		currentPCR := make([]byte, 32)
		digest := make([]byte, 32)

		_, err := computeExpectedPCR(HashAlgorithm("invalid"), currentPCR, digest)
		if err == nil {
			t.Error("expected error for invalid algorithm")
		}

		_, ok := err.(ErrInvalidHashAlgorithm)
		if !ok {
			t.Errorf("expected ErrInvalidHashAlgorithm, got %T", err)
		}
	})

	t.Run("SHA1 extension", func(t *testing.T) {
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
	})

	t.Run("SHA384 extension", func(t *testing.T) {
		currentPCR := make([]byte, 48)
		digest := make([]byte, 48)
		digest[0] = 0xFF

		newPCR, err := computeExpectedPCR(HashAlgorithmSHA384, currentPCR, digest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(newPCR) != 48 {
			t.Errorf("PCR size = %d, want 48", len(newPCR))
		}
	})

	t.Run("SHA512 extension", func(t *testing.T) {
		currentPCR := make([]byte, 64)
		digest := make([]byte, 64)
		digest[0] = 0xFF

		newPCR, err := computeExpectedPCR(HashAlgorithmSHA512, currentPCR, digest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(newPCR) != 64 {
			t.Errorf("PCR size = %d, want 64", len(newPCR))
		}
	})

	t.Run("deterministic output", func(t *testing.T) {
		currentPCR := make([]byte, 32)
		digest := make([]byte, 32)
		digest[0] = 0xAB

		pcr1, _ := computeExpectedPCR(HashAlgorithmSHA256, currentPCR, digest)
		pcr2, _ := computeExpectedPCR(HashAlgorithmSHA256, currentPCR, digest)

		if !bytes.Equal(pcr1, pcr2) {
			t.Error("PCR extension should be deterministic")
		}
	})
}

func TestDigestFormula(t *testing.T) {
	// Test the specific formula: digest = SHA256(workload_type || "|" || workload_id || "|" || image_digest)
	measurement := &WorkloadMeasurement{
		WorkloadType: WorkloadTypeContainer,
		WorkloadID:   "test-container",
		ImageDigest:  "sha256:abc123",
	}

	digest, err := computeDigest(HashAlgorithmSHA256, measurement)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually compute expected digest
	hasher := sha256.New()
	hasher.Write([]byte("container"))
	hasher.Write([]byte("|"))
	hasher.Write([]byte("test-container"))
	hasher.Write([]byte("|"))
	hasher.Write([]byte("sha256:abc123"))
	expected := hasher.Sum(nil)

	if !bytes.Equal(digest, expected) {
		t.Error("digest formula does not match specification")
	}
}

func TestPCRExtensionFormula(t *testing.T) {
	// Test the specific formula: new_pcr = SHA256(current_pcr || digest)
	currentPCR := make([]byte, 32)
	for i := range currentPCR {
		currentPCR[i] = byte(i)
	}

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(31 - i)
	}

	newPCR, err := computeExpectedPCR(HashAlgorithmSHA256, currentPCR, digest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually compute expected PCR
	hasher := sha256.New()
	hasher.Write(currentPCR)
	hasher.Write(digest)
	expected := hasher.Sum(nil)

	if !bytes.Equal(newPCR, expected) {
		t.Error("PCR extension formula does not match specification")
	}
}
