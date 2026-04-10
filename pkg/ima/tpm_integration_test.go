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

package ima

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadPCR10FromTPM(t *testing.T) {
	v := NewVerifier()

	t.Run("success with valid PCR", func(t *testing.T) {
		// Create temporary mock TPM sysfs structure
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Create mock PCR 10 file with valid SHA256 hash (32 bytes = 64 hex chars)
		expectedPCR := make([]byte, 32)
		for i := range expectedPCR {
			expectedPCR[i] = byte(i)
		}
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(expectedPCR)), 0644))

		// Read PCR
		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA256)
		require.NoError(t, err)
		assert.Equal(t, expectedPCR, pcr)
	})

	t.Run("success with SHA1 bank", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA1Dir := filepath.Join(mockTPMPath, "pcr-sha1")
		require.NoError(t, os.MkdirAll(pcrSHA1Dir, 0755))

		// SHA1 produces 20 bytes
		expectedPCR := make([]byte, 20)
		for i := range expectedPCR {
			expectedPCR[i] = byte(i * 2)
		}
		pcrFile := filepath.Join(pcrSHA1Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(expectedPCR)), 0644))

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA1)
		require.NoError(t, err)
		assert.Equal(t, expectedPCR, pcr)
		assert.Equal(t, 20, len(pcr))
	})

	t.Run("success with SHA384 bank", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA384Dir := filepath.Join(mockTPMPath, "pcr-sha384")
		require.NoError(t, os.MkdirAll(pcrSHA384Dir, 0755))

		// SHA384 produces 48 bytes
		expectedPCR := make([]byte, 48)
		for i := range expectedPCR {
			expectedPCR[i] = byte(i % 256)
		}
		pcrFile := filepath.Join(pcrSHA384Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(expectedPCR)), 0644))

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA384)
		require.NoError(t, err)
		assert.Equal(t, expectedPCR, pcr)
		assert.Equal(t, 48, len(pcr))
	})

	t.Run("success with SHA512 bank", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA512Dir := filepath.Join(mockTPMPath, "pcr-sha512")
		require.NoError(t, os.MkdirAll(pcrSHA512Dir, 0755))

		// SHA512 produces 64 bytes
		expectedPCR := make([]byte, 64)
		for i := range expectedPCR {
			expectedPCR[i] = byte(i % 256)
		}
		pcrFile := filepath.Join(pcrSHA512Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(expectedPCR)), 0644))

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA512)
		require.NoError(t, err)
		assert.Equal(t, expectedPCR, pcr)
		assert.Equal(t, 64, len(pcr))
	})

	t.Run("success with whitespace in PCR file", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		expectedPCR := make([]byte, 32)
		for i := range expectedPCR {
			expectedPCR[i] = byte(i)
		}

		// Write with leading/trailing whitespace
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		hexStr := "  " + hex.EncodeToString(expectedPCR) + "\n  "
		require.NoError(t, os.WriteFile(pcrFile, []byte(hexStr), 0644))

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA256)
		require.NoError(t, err)
		assert.Equal(t, expectedPCR, pcr)
	})

	t.Run("error when TPM not available", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "nonexistent")

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA256)
		require.Error(t, err)
		assert.Nil(t, pcr)
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})

	t.Run("error when PCR bank directory missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		require.NoError(t, os.MkdirAll(mockTPMPath, 0755))
		// Don't create pcr-sha256 directory

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA256)
		require.Error(t, err)
		assert.Nil(t, pcr)
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})

	t.Run("error when PCR file has invalid hex", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Write invalid hex
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte("not-valid-hex"), 0644))

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA256)
		require.Error(t, err)
		assert.Nil(t, pcr)
		assert.ErrorIs(t, err, ErrPCRReadFailed)
	})

	t.Run("error when PCR value has wrong length", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Write PCR with wrong length (should be 32 bytes for SHA256, write 16)
		wrongSizePCR := make([]byte, 16)
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(wrongSizePCR)), 0644))

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, PCRBankSHA256)
		require.Error(t, err)
		assert.Nil(t, pcr)
		assert.ErrorIs(t, err, ErrPCRReadFailed)
	})

	t.Run("error with invalid PCR bank", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, "invalid-bank")
		require.Error(t, err)
		assert.Nil(t, pcr)
		assert.ErrorIs(t, err, ErrInvalidPCRBank)
	})

	t.Run("error with empty bank name", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		pcr, err := v.ReadPCR10FromTPMWithPath(mockTPMPath, "")
		require.Error(t, err)
		assert.Nil(t, pcr)
		assert.ErrorIs(t, err, ErrInvalidPCRBank)
	})
}

func TestVerifyPCR10AgainstTPM(t *testing.T) {
	v := NewVerifier()

	t.Run("success with matching PCR", func(t *testing.T) {
		// Create mock TPM sysfs
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Create event log with one measurement
		templateHash := sha256.Sum256([]byte("test-measurement"))
		log := &EventLog{
			TotalCount: 1,
			Events: []*Event{
				{
					PCR:          10,
					TemplateHash: templateHash[:],
				},
			},
		}

		// Compute what PCR 10 should be
		expectedPCR, err := v.ComputePCR10(log, PCRBankSHA256)
		require.NoError(t, err)

		// Write expected PCR to mock TPM
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(expectedPCR)), 0644))

		// Verify
		err = v.VerifyPCR10AgainstTPMWithPath(log, mockTPMPath, PCRBankSHA256)
		assert.NoError(t, err)
	})

	t.Run("success with multiple measurements", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Create event log with multiple measurements
		hash1 := sha256.Sum256([]byte("measurement-1"))
		hash2 := sha256.Sum256([]byte("measurement-2"))
		hash3 := sha256.Sum256([]byte("measurement-3"))

		log := &EventLog{
			TotalCount: 3,
			Events: []*Event{
				{PCR: 10, TemplateHash: hash1[:]},
				{PCR: 10, TemplateHash: hash2[:]},
				{PCR: 10, TemplateHash: hash3[:]},
			},
		}

		// Compute expected PCR
		expectedPCR, err := v.ComputePCR10(log, PCRBankSHA256)
		require.NoError(t, err)

		// Write to mock TPM
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(expectedPCR)), 0644))

		// Verify
		err = v.VerifyPCR10AgainstTPMWithPath(log, mockTPMPath, PCRBankSHA256)
		assert.NoError(t, err)
	})

	t.Run("success with mixed PCR events", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Create event log with PCR 10 and other PCRs (should only use PCR 10)
		hash1 := sha256.Sum256([]byte("pcr10-measurement"))
		hash2 := sha256.Sum256([]byte("pcr0-measurement"))

		log := &EventLog{
			TotalCount: 2,
			Events: []*Event{
				{PCR: 0, TemplateHash: hash2[:]},  // Different PCR, should be ignored
				{PCR: 10, TemplateHash: hash1[:]}, // PCR 10
			},
		}

		// Compute expected PCR
		expectedPCR, err := v.ComputePCR10(log, PCRBankSHA256)
		require.NoError(t, err)

		// Write to mock TPM
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(expectedPCR)), 0644))

		// Verify
		err = v.VerifyPCR10AgainstTPMWithPath(log, mockTPMPath, PCRBankSHA256)
		assert.NoError(t, err)
	})

	t.Run("error with PCR mismatch", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Create event log
		templateHash := sha256.Sum256([]byte("test-measurement"))
		log := &EventLog{
			TotalCount: 1,
			Events: []*Event{
				{PCR: 10, TemplateHash: templateHash[:]},
			},
		}

		// Write DIFFERENT PCR to mock TPM
		wrongPCR := make([]byte, 32)
		for i := range wrongPCR {
			wrongPCR[i] = 0xFF
		}
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte(hex.EncodeToString(wrongPCR)), 0644))

		// Verify - should fail
		err := v.VerifyPCR10AgainstTPMWithPath(log, mockTPMPath, PCRBankSHA256)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPCRMismatch)
	})

	t.Run("error with nil event log", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		err := v.VerifyPCR10AgainstTPMWithPath(nil, mockTPMPath, PCRBankSHA256)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotAvailable)
	})

	t.Run("error with invalid PCR bank", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		log := &EventLog{Events: []*Event{}}

		err := v.VerifyPCR10AgainstTPMWithPath(log, mockTPMPath, "invalid")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPCRBank)
	})

	t.Run("error when TPM not available", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "nonexistent")

		log := &EventLog{
			TotalCount: 1,
			Events: []*Event{
				{PCR: 10, TemplateHash: make([]byte, 32)},
			},
		}

		err := v.VerifyPCR10AgainstTPMWithPath(log, mockTPMPath, PCRBankSHA256)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTPMNotAvailable)
	})

	t.Run("error when compute PCR fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		// Use invalid hash algorithm
		log := &EventLog{Events: []*Event{}}

		err := v.VerifyPCR10AgainstTPMWithPath(log, mockTPMPath, "md5") // Invalid
		require.Error(t, err)
	})
}

func TestIsPCR10Available(t *testing.T) {
	v := NewVerifier()

	t.Run("available when file exists and is readable", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.WriteFile(pcrFile, []byte("0000"), 0644))

		available := v.IsPCR10AvailableWithPath(mockTPMPath, PCRBankSHA256)
		assert.True(t, available)
	})

	t.Run("not available when TPM path missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "nonexistent")

		available := v.IsPCR10AvailableWithPath(mockTPMPath, PCRBankSHA256)
		assert.False(t, available)
	})

	t.Run("not available when PCR bank missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		require.NoError(t, os.MkdirAll(mockTPMPath, 0755))
		// Don't create pcr-sha256 directory

		available := v.IsPCR10AvailableWithPath(mockTPMPath, PCRBankSHA256)
		assert.False(t, available)
	})

	t.Run("not available when PCR file missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))
		// Don't create PCR 10 file

		available := v.IsPCR10AvailableWithPath(mockTPMPath, PCRBankSHA256)
		assert.False(t, available)
	})

	t.Run("not available with invalid bank", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		available := v.IsPCR10AvailableWithPath(mockTPMPath, "invalid-bank")
		assert.False(t, available)
	})

	t.Run("not available when file is directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Create PCR 10 as directory instead of file
		pcrDir := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.MkdirAll(pcrDir, 0755))

		available := v.IsPCR10AvailableWithPath(mockTPMPath, PCRBankSHA256)
		assert.False(t, available)
	})

	t.Run("not available when file is not readable", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		pcrSHA256Dir := filepath.Join(mockTPMPath, "pcr-sha256")
		require.NoError(t, os.MkdirAll(pcrSHA256Dir, 0755))

		// Use a broken symlink instead of file permissions, because root
		// bypasses permission bits (causes failures when running in Docker).
		pcrFile := filepath.Join(pcrSHA256Dir, "10")
		require.NoError(t, os.Symlink(filepath.Join(tmpDir, "nonexistent-target"), pcrFile))

		available := v.IsPCR10AvailableWithPath(mockTPMPath, PCRBankSHA256)
		assert.False(t, available)
	})
}

func TestIsTPMAvailable(t *testing.T) {
	v := NewVerifier()

	t.Run("available when directory exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		require.NoError(t, os.MkdirAll(mockTPMPath, 0755))

		available := v.IsTPMAvailableWithPath(mockTPMPath)
		assert.True(t, available)
	})

	t.Run("not available when directory missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "nonexistent")

		available := v.IsTPMAvailableWithPath(mockTPMPath)
		assert.False(t, available)
	})

	t.Run("not available when path is file", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		require.NoError(t, os.WriteFile(mockTPMPath, []byte("not-a-dir"), 0644))

		available := v.IsTPMAvailableWithPath(mockTPMPath)
		assert.False(t, available)
	})
}

func TestGetAvailablePCRBanks(t *testing.T) {
	v := NewVerifier()

	t.Run("all banks available", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		// Create all PCR bank directories
		require.NoError(t, os.MkdirAll(filepath.Join(mockTPMPath, "pcr-sha1"), 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(mockTPMPath, "pcr-sha256"), 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(mockTPMPath, "pcr-sha384"), 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(mockTPMPath, "pcr-sha512"), 0755))

		banks := v.GetAvailablePCRBanksWithPath(mockTPMPath)
		assert.Len(t, banks, 4)
		assert.Contains(t, banks, PCRBankSHA1)
		assert.Contains(t, banks, PCRBankSHA256)
		assert.Contains(t, banks, PCRBankSHA384)
		assert.Contains(t, banks, PCRBankSHA512)
	})

	t.Run("only SHA256 available", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")

		// Create only SHA256 bank
		require.NoError(t, os.MkdirAll(filepath.Join(mockTPMPath, "pcr-sha256"), 0755))

		banks := v.GetAvailablePCRBanksWithPath(mockTPMPath)
		assert.Len(t, banks, 1)
		assert.Contains(t, banks, PCRBankSHA256)
	})

	t.Run("no banks available", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		require.NoError(t, os.MkdirAll(mockTPMPath, 0755))

		banks := v.GetAvailablePCRBanksWithPath(mockTPMPath)
		assert.Len(t, banks, 0)
	})

	t.Run("TPM directory missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "nonexistent")

		banks := v.GetAvailablePCRBanksWithPath(mockTPMPath)
		assert.Len(t, banks, 0)
	})

	t.Run("ignores files instead of directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		mockTPMPath := filepath.Join(tmpDir, "tpm0")
		require.NoError(t, os.MkdirAll(mockTPMPath, 0755))

		// Create SHA256 as directory
		require.NoError(t, os.MkdirAll(filepath.Join(mockTPMPath, "pcr-sha256"), 0755))

		// Create SHA1 as file (should be ignored)
		require.NoError(t, os.WriteFile(filepath.Join(mockTPMPath, "pcr-sha1"), []byte("file"), 0644))

		banks := v.GetAvailablePCRBanksWithPath(mockTPMPath)
		assert.Len(t, banks, 1)
		assert.Contains(t, banks, PCRBankSHA256)
		assert.NotContains(t, banks, PCRBankSHA1)
	})
}

func TestIsValidPCRBank(t *testing.T) {
	tests := []struct {
		name  string
		bank  string
		valid bool
	}{
		{"sha1 valid", PCRBankSHA1, true},
		{"sha256 valid", PCRBankSHA256, true},
		{"sha384 valid", PCRBankSHA384, true},
		{"sha512 valid", PCRBankSHA512, true},
		{"md5 invalid", "md5", false},
		{"empty invalid", "", false},
		{"random invalid", "random", false},
		{"SHA256 uppercase invalid", "SHA256", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPCRBank(tt.bank)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestGetExpectedPCRSize(t *testing.T) {
	tests := []struct {
		name         string
		bank         string
		expectedSize int
	}{
		{"sha1", PCRBankSHA1, 20},
		{"sha256", PCRBankSHA256, 32},
		{"sha384", PCRBankSHA384, 48},
		{"sha512", PCRBankSHA512, 64},
		{"invalid", "invalid", 0},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size := getExpectedPCRSize(tt.bank)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}

func TestPCRConstants(t *testing.T) {
	t.Run("PCR bank constants", func(t *testing.T) {
		assert.Equal(t, "sha1", PCRBankSHA1)
		assert.Equal(t, "sha256", PCRBankSHA256)
		assert.Equal(t, "sha384", PCRBankSHA384)
		assert.Equal(t, "sha512", PCRBankSHA512)
	})

	t.Run("PCR index constant", func(t *testing.T) {
		assert.Equal(t, 10, PCR10)
	})

	t.Run("TPM path constant", func(t *testing.T) {
		assert.Equal(t, "/sys/class/tpm/tpm0", DefaultTPMSysPath)
	})
}

func TestTPMIntegrationErrors(t *testing.T) {
	t.Run("error types are distinct", func(t *testing.T) {
		assert.NotEqual(t, ErrTPMNotAvailable, ErrPCRReadFailed)
		assert.NotEqual(t, ErrTPMNotAvailable, ErrPCRMismatch)
		assert.NotEqual(t, ErrPCRReadFailed, ErrPCRMismatch)
		assert.NotEqual(t, ErrInvalidPCRBank, ErrTPMNotAvailable)
	})

	t.Run("error messages are descriptive", func(t *testing.T) {
		assert.Contains(t, ErrTPMNotAvailable.Error(), "TPM")
		assert.Contains(t, ErrPCRReadFailed.Error(), "PCR")
		assert.Contains(t, ErrPCRMismatch.Error(), "mismatch")
		assert.Contains(t, ErrInvalidPCRBank.Error(), "invalid")
	})
}
