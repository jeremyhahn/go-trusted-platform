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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifier(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		v := NewVerifier()
		require.NotNil(t, v)
		assert.NotNil(t, v.reader)
		assert.NotNil(t, v.allowlist)
	})

	t.Run("with allowlist", func(t *testing.T) {
		allowlist := map[string][]byte{
			"/bin/bash": {0x01, 0x02, 0x03},
		}
		v := NewVerifier(WithAllowlist(allowlist))
		require.NotNil(t, v)
		assert.Equal(t, allowlist, v.allowlist)
	})

	t.Run("with custom reader", func(t *testing.T) {
		reader := NewReader(WithSecurityFSPath("/custom"))
		v := NewVerifier(WithReader(reader))
		require.NotNil(t, v)
		assert.Equal(t, reader, v.reader)
	})
}

func TestVerifier_VerifyEventLog(t *testing.T) {
	v := NewVerifier()

	t.Run("nil log", func(t *testing.T) {
		result := v.VerifyEventLog(nil)
		require.NotNil(t, result)
		assert.False(t, result.Passed)
		assert.ErrorIs(t, result.Errors[0], ErrNotAvailable)
	})

	t.Run("empty log", func(t *testing.T) {
		log := &EventLog{
			Events:     make([]*Event, 0),
			TotalCount: 0,
		}

		result := v.VerifyEventLog(log)
		require.NotNil(t, result)
		assert.True(t, result.Passed)
		assert.Equal(t, 0, result.TotalMeasurements)
	})

	t.Run("valid events", func(t *testing.T) {
		// SHA-256-width template hash so this case holds in every build. The
		// 20-byte (SHA-1-width) legacy shape is build-dependent — a FIPS build
		// refuses to verify it — and is covered in verifier_sha1_test.go and
		// verifier_sha1_fips_test.go.
		templateHash := make([]byte, 32) // SHA256 size
		fileHash := make([]byte, 32)     // SHA256 size

		log := &EventLog{
			TotalCount: 2,
			Events: []*Event{
				{
					PCR:           10,
					TemplateHash:  templateHash,
					TemplateName:  "ima-ng",
					FileHash:      fileHash,
					HashAlgorithm: "sha256",
					FilePath:      "/bin/bash",
				},
				{
					PCR:           10,
					TemplateHash:  templateHash,
					TemplateName:  "ima-ng",
					FileHash:      fileHash,
					HashAlgorithm: "sha256",
					FilePath:      "/bin/ls",
				},
			},
		}

		result := v.VerifyEventLog(log)
		require.NotNil(t, result)
		assert.True(t, result.Passed)
		assert.Equal(t, 2, result.TotalMeasurements)
		assert.Equal(t, 2, result.ValidMeasurements)
		assert.Equal(t, 0, result.InvalidMeasurements)
	})

	t.Run("event with invalid template hash length", func(t *testing.T) {
		log := &EventLog{
			TotalCount: 1,
			Events: []*Event{
				{
					PCR:          10,
					TemplateHash: []byte{0x01, 0x02, 0x03}, // Invalid length
					TemplateName: "ima-ng",
					FilePath:     "/bin/bad",
				},
			},
		}

		result := v.VerifyEventLog(log)
		require.NotNil(t, result)
		assert.False(t, result.Passed)
		assert.Equal(t, 1, result.InvalidMeasurements)
		assert.Contains(t, result.ViolationFiles, "/bin/bad")
	})

	t.Run("missing file from allowlist", func(t *testing.T) {
		allowlist := map[string][]byte{
			"/required/file": {0x01, 0x02},
		}
		v := NewVerifier(WithAllowlist(allowlist))

		templateHash := make([]byte, 32)
		log := &EventLog{
			TotalCount: 1,
			Events: []*Event{
				{
					PCR:          10,
					TemplateHash: templateHash,
					TemplateName: "ima-ng",
					FilePath:     "/other/file",
				},
			},
		}

		result := v.VerifyEventLog(log)
		require.NotNil(t, result)
		assert.Contains(t, result.MissingFiles, "/required/file")
	})
}

func TestVerifier_verifyTemplateHash(t *testing.T) {
	v := NewVerifier()

	tests := []struct {
		name       string
		hashLen    int
		shouldPass bool
	}{
		// A 20-byte (SHA-1-length) template hash stays structurally valid in
		// EVERY build, FIPS included: reading the shape of a legacy entry is
		// not a cryptographic operation. Whether it can be VERIFIED is the
		// build-dependent part, covered in verifier_sha1_test.go (!fips) and
		// verifier_sha1_fips_test.go (fips).
		{"sha1", 20, true},
		{"sha256", 32, true},
		{"sha384", 48, true},
		{"sha512", 64, true},
		{"invalid", 15, false},
		{"empty", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{
				TemplateHash: make([]byte, tt.hashLen),
			}

			err := v.verifyTemplateHash(event)
			if tt.shouldPass {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestVerifier_verifyAgainstAllowlist(t *testing.T) {
	expectedHash := []byte{0xab, 0xcd, 0xef}
	allowlist := map[string][]byte{
		"/bin/bash": expectedHash,
	}
	v := NewVerifier(WithAllowlist(allowlist))

	t.Run("hash matches", func(t *testing.T) {
		event := &Event{
			FilePath: "/bin/bash",
			FileHash: expectedHash,
		}
		err := v.verifyAgainstAllowlist(event)
		assert.NoError(t, err)
	})

	t.Run("hash mismatch", func(t *testing.T) {
		event := &Event{
			FilePath: "/bin/bash",
			FileHash: []byte{0x11, 0x22, 0x33},
		}
		err := v.verifyAgainstAllowlist(event)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrHashMismatch)
	})

	t.Run("file not in allowlist", func(t *testing.T) {
		event := &Event{
			FilePath: "/bin/other",
			FileHash: []byte{0x11, 0x22, 0x33},
		}
		err := v.verifyAgainstAllowlist(event)
		assert.NoError(t, err) // Not in allowlist, so no error
	})
}

func TestVerifier_VerifyFile(t *testing.T) {
	v := NewVerifier()

	t.Run("nil event", func(t *testing.T) {
		err := v.VerifyFile(nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEventFormat)
	})

	t.Run("empty file path", func(t *testing.T) {
		event := &Event{FilePath: ""}
		err := v.VerifyFile(event)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEventFormat)
	})

	t.Run("file not found", func(t *testing.T) {
		event := &Event{
			FilePath:      "/nonexistent/file",
			HashAlgorithm: "sha256",
		}
		err := v.VerifyFile(event)
		assert.Error(t, err)
	})

	t.Run("valid file verification", func(t *testing.T) {
		// Create a temp file
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "testfile")
		content := []byte("test content")
		err := os.WriteFile(testFile, content, 0644)
		require.NoError(t, err)

		// Calculate expected hash
		h := sha256.Sum256(content)

		event := &Event{
			FilePath:      testFile,
			FileHash:      h[:],
			HashAlgorithm: "sha256",
		}

		err = v.VerifyFile(event)
		assert.NoError(t, err)
	})

	t.Run("modified file detection", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "testfile")

		// Write original content and hash it
		originalContent := []byte("original content")
		err := os.WriteFile(testFile, originalContent, 0644)
		require.NoError(t, err)

		h := sha256.Sum256(originalContent)

		// Modify the file
		modifiedContent := []byte("modified content")
		err = os.WriteFile(testFile, modifiedContent, 0644)
		require.NoError(t, err)

		event := &Event{
			FilePath:      testFile,
			FileHash:      h[:], // Original hash
			HashAlgorithm: "sha256",
		}

		err = v.VerifyFile(event)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrHashMismatch)
	})
}

func TestVerifier_ComputePCR10(t *testing.T) {
	v := NewVerifier()

	t.Run("nil log", func(t *testing.T) {
		_, err := v.ComputePCR10(nil, "sha256")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNotAvailable)
	})

	t.Run("empty log", func(t *testing.T) {
		log := &EventLog{Events: []*Event{}}
		pcr, err := v.ComputePCR10(log, "sha256")
		require.NoError(t, err)
		// Should be all zeros
		assert.Equal(t, make([]byte, 32), pcr)
	})

	t.Run("single event", func(t *testing.T) {
		templateHash := make([]byte, 32)
		for i := range templateHash {
			templateHash[i] = byte(i)
		}

		log := &EventLog{
			Events: []*Event{
				{
					PCR:          10,
					TemplateHash: templateHash,
				},
			},
		}

		pcr, err := v.ComputePCR10(log, "sha256")
		require.NoError(t, err)
		assert.Len(t, pcr, 32)
		// Should not be all zeros after extending
		assert.NotEqual(t, make([]byte, 32), pcr)
	})

	t.Run("skip non-PCR10 events", func(t *testing.T) {
		log := &EventLog{
			Events: []*Event{
				{
					PCR:          9, // Not PCR 10
					TemplateHash: make([]byte, 32),
				},
			},
		}

		pcr, err := v.ComputePCR10(log, "sha256")
		require.NoError(t, err)
		// Should still be zeros since PCR 9 event was skipped
		assert.Equal(t, make([]byte, 32), pcr)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		log := &EventLog{Events: []*Event{}}
		_, err := v.ComputePCR10(log, "md5")
		assert.Error(t, err)
	})
}

func TestVerifier_VerifyPCR10(t *testing.T) {
	v := NewVerifier()

	t.Run("nil log", func(t *testing.T) {
		err := v.VerifyPCR10(nil, []byte{}, "sha256")
		assert.Error(t, err)
	})

	t.Run("matching PCR", func(t *testing.T) {
		log := &EventLog{Events: []*Event{}}
		expectedPCR := make([]byte, 32) // Empty log = all zeros

		err := v.VerifyPCR10(log, expectedPCR, "sha256")
		assert.NoError(t, err)
	})

	t.Run("mismatched PCR", func(t *testing.T) {
		log := &EventLog{Events: []*Event{}}
		wrongPCR := []byte{0x01, 0x02, 0x03}

		err := v.VerifyPCR10(log, wrongPCR, "sha256")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrHashMismatch)
	})
}

func TestVerifier_getHasher(t *testing.T) {
	v := NewVerifier()

	tests := []struct {
		alg         string
		expectedLen int
		shouldPass  bool
	}{
		// "sha1" is build-dependent — available by default, refused under FIPS.
		// Covered in verifier_sha1_test.go and verifier_sha1_fips_test.go.
		{"sha256", 32, true},
		{"sha384", 48, true},
		{"sha512", 64, true},
		{"md5", 0, false},
		{"unknown", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			h, err := v.getHasher(tt.alg)
			if tt.shouldPass {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedLen, h.Size())
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestVerifier_AllowlistOperations(t *testing.T) {
	v := NewVerifier()

	t.Run("add and get", func(t *testing.T) {
		hash := []byte{0x01, 0x02, 0x03}
		v.AddToAllowlist("/bin/test", hash)

		allowlist := v.GetAllowlist()
		assert.Equal(t, hash, allowlist["/bin/test"])
	})

	t.Run("add with algorithm", func(t *testing.T) {
		hash := []byte{0x04, 0x05, 0x06}
		v.AddToAllowlistWithAlg("sha256", "/bin/test2", hash)

		assert.Equal(t, hash, v.allowlistByAlg["sha256"]["/bin/test2"])
	})

	t.Run("remove", func(t *testing.T) {
		v.AddToAllowlist("/bin/remove", []byte{0x01})
		v.RemoveFromAllowlist("/bin/remove")

		allowlist := v.GetAllowlist()
		_, exists := allowlist["/bin/remove"]
		assert.False(t, exists)
	})

	t.Run("clear", func(t *testing.T) {
		v.AddToAllowlist("/bin/a", []byte{0x01})
		v.AddToAllowlist("/bin/b", []byte{0x02})
		v.ClearAllowlist()

		allowlist := v.GetAllowlist()
		assert.Len(t, allowlist, 0)
	})

	t.Run("get returns copy", func(t *testing.T) {
		hash := []byte{0x01, 0x02, 0x03}
		v.AddToAllowlist("/bin/copy", hash)

		allowlist := v.GetAllowlist()
		// Modify the returned copy
		allowlist["/bin/copy"][0] = 0xff

		// Original should be unchanged
		original := v.GetAllowlist()
		assert.Equal(t, byte(0x01), original["/bin/copy"][0])
	})
}

func TestVerifier_BuildAllowlistFromLog(t *testing.T) {
	v := NewVerifier()

	t.Run("nil log", func(t *testing.T) {
		err := v.BuildAllowlistFromLog(nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNotAvailable)
	})

	t.Run("valid log", func(t *testing.T) {
		hash1 := []byte{0x01, 0x02}
		hash2 := []byte{0x03, 0x04}

		log := &EventLog{
			Events: []*Event{
				{FilePath: "/bin/a", FileHash: hash1},
				{FilePath: "/bin/b", FileHash: hash2},
				{FilePath: "", FileHash: []byte{0x05}}, // No path, should be skipped
			},
		}

		err := v.BuildAllowlistFromLog(log)
		require.NoError(t, err)

		allowlist := v.GetAllowlist()
		assert.Equal(t, hash1, allowlist["/bin/a"])
		assert.Equal(t, hash2, allowlist["/bin/b"])
		assert.Len(t, allowlist, 2)
	})
}

func TestVerifier_HashFile(t *testing.T) {
	v := NewVerifier()

	t.Run("file not found", func(t *testing.T) {
		_, err := v.HashFile("/nonexistent", "sha256")
		assert.Error(t, err)
	})

	t.Run("valid file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "testfile")
		content := []byte("test content")
		err := os.WriteFile(testFile, content, 0644)
		require.NoError(t, err)

		hash, err := v.HashFile(testFile, "sha256")
		require.NoError(t, err)

		expected := sha256.Sum256(content)
		assert.Equal(t, expected[:], hash)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "testfile")
		err := os.WriteFile(testFile, []byte("test"), 0644)
		require.NoError(t, err)

		_, err = v.HashFile(testFile, "md5")
		assert.Error(t, err)
	})
}

func TestVerifier_HashFileToHex(t *testing.T) {
	v := NewVerifier()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "testfile")
	content := []byte("test content")
	err := os.WriteFile(testFile, content, 0644)
	require.NoError(t, err)

	hashHex, err := v.HashFileToHex(testFile, "sha256")
	require.NoError(t, err)

	expected := sha256.Sum256(content)
	assert.Equal(t, hex.EncodeToString(expected[:]), hashHex)
}

func TestVerifier_VerifySignature(t *testing.T) {
	v := NewVerifier()

	t.Run("nil event", func(t *testing.T) {
		err := v.VerifySignature(nil, nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEventFormat)
	})

	t.Run("no signature", func(t *testing.T) {
		event := &Event{Signature: nil}
		err := v.VerifySignature(event, nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrKeyNotLoaded)
	})

	t.Run("no public key", func(t *testing.T) {
		event := &Event{Signature: make([]byte, 100)}
		err := v.VerifySignature(event, nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrKeyNotLoaded)
	})

	t.Run("signature too short", func(t *testing.T) {
		event := &Event{Signature: []byte{0x01, 0x02}}
		// Need a mock public key - just testing length check
		err := v.VerifySignature(event, "fake-key")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAppraisalFailure)
	})
}

func TestVerifier_DetectMeasurementGaps(t *testing.T) {
	v := NewVerifier()

	t.Run("nil log", func(t *testing.T) {
		gaps := v.DetectMeasurementGaps(nil, time.Hour)
		assert.Nil(t, gaps)
	})

	t.Run("single event", func(t *testing.T) {
		log := &EventLog{
			Events: []*Event{
				{Timestamp: time.Now()},
			},
		}
		gaps := v.DetectMeasurementGaps(log, time.Hour)
		assert.Nil(t, gaps)
	})

	t.Run("no gaps", func(t *testing.T) {
		now := time.Now()
		log := &EventLog{
			Events: []*Event{
				{Timestamp: now},
				{Timestamp: now.Add(time.Minute)},
				{Timestamp: now.Add(2 * time.Minute)},
			},
		}
		gaps := v.DetectMeasurementGaps(log, time.Hour)
		assert.Len(t, gaps, 0)
	})

	t.Run("with gaps", func(t *testing.T) {
		now := time.Now()
		log := &EventLog{
			Events: []*Event{
				{Timestamp: now, FilePath: "/file1"},
				{Timestamp: now.Add(2 * time.Hour), FilePath: "/file2"},
			},
		}
		gaps := v.DetectMeasurementGaps(log, time.Hour)
		assert.Len(t, gaps, 1)
	})

	t.Run("events without timestamps", func(t *testing.T) {
		log := &EventLog{
			Events: []*Event{
				{FilePath: "/file1"},
				{FilePath: "/file2"},
			},
		}
		gaps := v.DetectMeasurementGaps(log, time.Hour)
		assert.Len(t, gaps, 0)
	})
}

func TestVerifier_FindDuplicateMeasurements(t *testing.T) {
	v := NewVerifier()

	t.Run("nil log", func(t *testing.T) {
		dups := v.FindDuplicateMeasurements(nil)
		assert.Nil(t, dups)
	})

	t.Run("no duplicates", func(t *testing.T) {
		log := &EventLog{
			Events: []*Event{
				{FilePath: "/bin/a"},
				{FilePath: "/bin/b"},
				{FilePath: "/bin/c"},
			},
		}
		dups := v.FindDuplicateMeasurements(log)
		assert.Len(t, dups, 0)
	})

	t.Run("with duplicates", func(t *testing.T) {
		log := &EventLog{
			Events: []*Event{
				{FilePath: "/bin/bash"},
				{FilePath: "/bin/ls"},
				{FilePath: "/bin/bash"},
				{FilePath: "/bin/bash"},
			},
		}
		dups := v.FindDuplicateMeasurements(log)
		assert.Equal(t, 3, dups["/bin/bash"])
		_, hasLs := dups["/bin/ls"]
		assert.False(t, hasLs)
	})
}

func TestVerifier_FindModifiedFiles(t *testing.T) {
	v := NewVerifier()

	t.Run("nil log", func(t *testing.T) {
		modified := v.FindModifiedFiles(nil)
		assert.Nil(t, modified)
	})

	t.Run("no modifications", func(t *testing.T) {
		hash := []byte{0x01, 0x02, 0x03}
		log := &EventLog{
			Events: []*Event{
				{FilePath: "/bin/bash", FileHash: hash},
				{FilePath: "/bin/bash", FileHash: hash}, // Same hash
			},
		}
		modified := v.FindModifiedFiles(log)
		assert.Len(t, modified, 0)
	})

	t.Run("with modifications", func(t *testing.T) {
		log := &EventLog{
			Events: []*Event{
				{FilePath: "/bin/bash", FileHash: []byte{0x01, 0x02}},
				{FilePath: "/bin/bash", FileHash: []byte{0x03, 0x04}}, // Different hash
			},
		}
		modified := v.FindModifiedFiles(log)
		assert.Contains(t, modified, "/bin/bash")
	})

	t.Run("events without path or hash", func(t *testing.T) {
		log := &EventLog{
			Events: []*Event{
				{FilePath: "", FileHash: []byte{0x01}},
				{FilePath: "/bin/a", FileHash: nil},
			},
		}
		modified := v.FindModifiedFiles(log)
		assert.Len(t, modified, 0)
	})
}
