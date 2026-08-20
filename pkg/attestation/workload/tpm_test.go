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
	"context"
	"crypto/sha256"
	"testing"
)

func TestNewSoftwareTPM(t *testing.T) {
	tpm := NewSoftwareTPM()
	if tpm == nil {
		t.Fatal("NewSoftwareTPM returned nil")
	}

	// Verify PCRs are initialized
	if tpm.pcrs == nil {
		t.Error("PCRs map not initialized")
	}

	// Verify PCR 14 SHA256 bank is zero
	ctx := context.Background()
	value, err := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("ReadPCR failed: %v", err)
	}

	if len(value) != 32 {
		t.Errorf("PCR value length = %d, want 32", len(value))
	}

	zeroPCR := make([]byte, 32)
	if !bytes.Equal(value, zeroPCR) {
		t.Error("PCR should be zero initially")
	}
}

func TestSoftwareTPM_ReadPCR(t *testing.T) {
	tpm := NewSoftwareTPM()
	ctx := context.Background()

	tests := []struct {
		name        string
		pcr         int
		algorithm   HashAlgorithm
		expectSize  int
		expectError bool
	}{
		{"PCR 0 SHA256", 0, HashAlgorithmSHA256, 32, false},
		{"PCR 14 SHA256", 14, HashAlgorithmSHA256, 32, false},
		{"PCR 23 SHA256", 23, HashAlgorithmSHA256, 32, false},
		{"PCR 0 SHA1", 0, HashAlgorithmSHA1, 20, false},
		{"PCR 14 SHA384", 14, HashAlgorithmSHA384, 48, false},
		{"PCR 14 SHA512", 14, HashAlgorithmSHA512, 64, false},
		{"PCR -1 invalid", -1, HashAlgorithmSHA256, 0, true},
		{"PCR 24 invalid", 24, HashAlgorithmSHA256, 0, true},
		{"invalid algorithm", 14, HashAlgorithm("md5"), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := tpm.ReadPCR(ctx, tt.pcr, tt.algorithm)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(value) != tt.expectSize {
					t.Errorf("PCR value length = %d, want %d", len(value), tt.expectSize)
				}
			}
		})
	}
}

func TestSoftwareTPM_ExtendPCR(t *testing.T) {
	t.Run("valid extension", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		ctx := context.Background()

		digest := make([]byte, 32)
		digest[0] = 0xFF

		err := tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest)
		if err != nil {
			t.Fatalf("ExtendPCR failed: %v", err)
		}

		// Verify PCR was extended
		value, err := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("ReadPCR failed: %v", err)
		}

		// PCR should not be zero anymore
		zeroPCR := make([]byte, 32)
		if bytes.Equal(value, zeroPCR) {
			t.Error("PCR should not be zero after extension")
		}

		// Verify expected value
		expected := sha256.New()
		expected.Write(zeroPCR)
		expected.Write(digest)
		if !bytes.Equal(value, expected.Sum(nil)) {
			t.Error("PCR value does not match expected")
		}
	})

	t.Run("multiple extensions", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		ctx := context.Background()

		// First extension
		digest1 := make([]byte, 32)
		digest1[0] = 0x01
		if err := tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest1); err != nil {
			t.Fatalf("first ExtendPCR failed: %v", err)
		}

		value1, _ := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)

		// Second extension
		digest2 := make([]byte, 32)
		digest2[0] = 0x02
		if err := tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest2); err != nil {
			t.Fatalf("second ExtendPCR failed: %v", err)
		}

		value2, _ := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)

		// Values should be different
		if bytes.Equal(value1, value2) {
			t.Error("PCR values should differ after multiple extensions")
		}
	})

	t.Run("invalid PCR index", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		ctx := context.Background()
		digest := make([]byte, 32)

		err := tpm.ExtendPCR(ctx, -1, HashAlgorithmSHA256, digest)
		if err == nil {
			t.Error("expected error for negative PCR index")
		}

		err = tpm.ExtendPCR(ctx, 24, HashAlgorithmSHA256, digest)
		if err == nil {
			t.Error("expected error for PCR index > 23")
		}
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		ctx := context.Background()
		digest := make([]byte, 32)

		err := tpm.ExtendPCR(ctx, 14, HashAlgorithm("invalid"), digest)
		if err == nil {
			t.Error("expected error for invalid algorithm")
		}

		_, ok := err.(ErrInvalidHashAlgorithm)
		if !ok {
			t.Errorf("expected ErrInvalidHashAlgorithm, got %T", err)
		}
	})

	t.Run("wrong digest size", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		ctx := context.Background()

		// SHA256 expects 32 bytes
		shortDigest := make([]byte, 16)
		err := tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, shortDigest)
		if err == nil {
			t.Error("expected error for wrong digest size")
		}

		longDigest := make([]byte, 64)
		err = tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, longDigest)
		if err == nil {
			t.Error("expected error for wrong digest size")
		}
	})

}

func TestSoftwareTPM_Close(t *testing.T) {
	tpm := NewSoftwareTPM()
	ctx := context.Background()

	err := tpm.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Operations after close should fail
	_, err = tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)
	if err == nil {
		t.Error("expected error after close")
	}

	_, ok := err.(ErrTPMNotAvailable)
	if !ok {
		t.Errorf("expected ErrTPMNotAvailable, got %T", err)
	}

	digest := make([]byte, 32)
	err = tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest)
	if err == nil {
		t.Error("expected error after close")
	}
}

func TestSoftwareTPM_SetPCRValue(t *testing.T) {
	t.Run("valid set", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		ctx := context.Background()

		value := make([]byte, 32)
		for i := range value {
			value[i] = byte(i)
		}

		err := tpm.SetPCRValue(14, HashAlgorithmSHA256, value)
		if err != nil {
			t.Fatalf("SetPCRValue failed: %v", err)
		}

		readValue, err := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("ReadPCR failed: %v", err)
		}

		if !bytes.Equal(readValue, value) {
			t.Error("read value does not match set value")
		}
	})

	t.Run("invalid PCR", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		value := make([]byte, 32)

		err := tpm.SetPCRValue(-1, HashAlgorithmSHA256, value)
		if err == nil {
			t.Error("expected error for negative PCR")
		}

		err = tpm.SetPCRValue(24, HashAlgorithmSHA256, value)
		if err == nil {
			t.Error("expected error for PCR > 23")
		}
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		value := make([]byte, 32)

		err := tpm.SetPCRValue(14, HashAlgorithm("invalid"), value)
		if err == nil {
			t.Error("expected error for invalid algorithm")
		}
	})

	t.Run("wrong value size", func(t *testing.T) {
		tpm := NewSoftwareTPM()

		value := make([]byte, 16) // SHA256 expects 32
		err := tpm.SetPCRValue(14, HashAlgorithmSHA256, value)
		if err == nil {
			t.Error("expected error for wrong value size")
		}
	})

	t.Run("after close", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		if err := tpm.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		value := make([]byte, 32)
		err := tpm.SetPCRValue(14, HashAlgorithmSHA256, value)
		if err == nil {
			t.Error("expected error after close")
		}
	})
}

func TestSoftwareTPM_ContextCancellation(t *testing.T) {
	tpm := NewSoftwareTPM()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// ReadPCR with canceled context
	_, err := tpm.ReadPCR(ctx, 14, HashAlgorithmSHA256)
	if err == nil {
		t.Error("expected error for canceled context")
	}

	ctxCanceled, ok := err.(ErrContextCanceled)
	if !ok {
		t.Errorf("expected ErrContextCanceled, got %T", err)
	}
	if ctxCanceled.Operation != "ReadPCR" {
		t.Errorf("Operation = %s, want ReadPCR", ctxCanceled.Operation)
	}

	// ExtendPCR with canceled context
	digest := make([]byte, 32)
	err = tpm.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest)
	if err == nil {
		t.Error("expected error for canceled context")
	}

	ctxCanceled, ok = err.(ErrContextCanceled)
	if !ok {
		t.Errorf("expected ErrContextCanceled, got %T", err)
	}
	if ctxCanceled.Operation != "ExtendPCR" {
		t.Errorf("Operation = %s, want ExtendPCR", ctxCanceled.Operation)
	}
}

func TestNewSoftwareTPMFactory(t *testing.T) {
	t.Run("with existing TPM", func(t *testing.T) {
		existingTPM := NewSoftwareTPM()
		factory := NewSoftwareTPMFactory(existingTPM)

		ctx := context.Background()
		tpm, err := factory.Open(ctx)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if tpm != existingTPM {
			t.Error("factory should return the provided TPM")
		}
	})

	t.Run("without existing TPM", func(t *testing.T) {
		factory := NewSoftwareTPMFactory(nil)

		ctx := context.Background()
		tpm, err := factory.Open(ctx)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if tpm == nil {
			t.Error("factory should create a new TPM")
		}
	})

	t.Run("with canceled context", func(t *testing.T) {
		factory := NewSoftwareTPMFactory(nil)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := factory.Open(ctx)
		if err == nil {
			t.Error("expected error for canceled context")
		}
	})
}

func TestSoftwareTPM_AllPCRs(t *testing.T) {
	tpm := NewSoftwareTPM()
	ctx := context.Background()

	// Verify all 24 PCRs are accessible
	for pcr := 0; pcr <= 23; pcr++ {
		value, err := tpm.ReadPCR(ctx, pcr, HashAlgorithmSHA256)
		if err != nil {
			t.Errorf("ReadPCR(%d) failed: %v", pcr, err)
			continue
		}

		if len(value) != 32 {
			t.Errorf("PCR %d size = %d, want 32", pcr, len(value))
		}
	}
}

func TestSoftwareTPM_ExtendionConsistency(t *testing.T) {
	// Verify that the same sequence of extensions produces the same result
	digest1 := make([]byte, 32)
	digest1[0] = 0x11
	digest2 := make([]byte, 32)
	digest2[0] = 0x22
	digest3 := make([]byte, 32)
	digest3[0] = 0x33

	ctx := context.Background()

	// First TPM with extensions
	tpm1 := NewSoftwareTPM()
	if err := tpm1.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest1); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	if err := tpm1.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest2); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	if err := tpm1.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest3); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	value1, _ := tpm1.ReadPCR(ctx, 14, HashAlgorithmSHA256)

	// Second TPM with same extensions
	tpm2 := NewSoftwareTPM()
	if err := tpm2.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest1); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	if err := tpm2.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest2); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	if err := tpm2.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest3); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	value2, _ := tpm2.ReadPCR(ctx, 14, HashAlgorithmSHA256)

	if !bytes.Equal(value1, value2) {
		t.Error("same extension sequence should produce same PCR value")
	}

	// Different order should produce different result
	tpm3 := NewSoftwareTPM()
	if err := tpm3.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest3); err != nil { // Changed order
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	if err := tpm3.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest2); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	if err := tpm3.ExtendPCR(ctx, 14, HashAlgorithmSHA256, digest1); err != nil {
		t.Fatalf("ExtendPCR failed: %v", err)
	}
	value3, _ := tpm3.ReadPCR(ctx, 14, HashAlgorithmSHA256)

	if bytes.Equal(value1, value3) {
		t.Error("different extension order should produce different PCR value")
	}
}
