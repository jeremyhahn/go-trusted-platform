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

package kms

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// =============================================================================
// ParseKeyUsage Tests (via SDK)
// =============================================================================

func TestParseKeyUsage(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  kmssvc.KeyUsage
		expectErr bool
	}{
		{"encrypt", "encrypt", kmssvc.KeyUsageEncrypt, false},
		{"decrypt", "decrypt", kmssvc.KeyUsageDecrypt, false},
		{"sign", "sign", kmssvc.KeyUsageSign, false},
		{"verify", "verify", kmssvc.KeyUsageVerify, false},
		{"wrap", "wrap", kmssvc.KeyUsageWrap, false},
		{"wrap-key", "wrap-key", kmssvc.KeyUsageWrap, false},
		{"unwrap", "unwrap", kmssvc.KeyUsageUnwrap, false},
		{"unwrap-key", "unwrap-key", kmssvc.KeyUsageUnwrap, false},
		{"derive", "derive", kmssvc.KeyUsageDerive, false},
		{"derive-key", "derive-key", kmssvc.KeyUsageDerive, false},
		{"hmac", "hmac", kmssvc.KeyUsageHMAC, false},
		{"generate-mac", "generate-mac", kmssvc.KeyUsageHMAC, false},
		{"mac", "mac", kmssvc.KeyUsageHMAC, false},
		{"uppercase ENCRYPT", "ENCRYPT", kmssvc.KeyUsageEncrypt, false},
		{"underscore wrap_key", "wrap_key", kmssvc.KeyUsageWrap, false},
		{"invalid", "invalid", kmssvc.KeyUsageUnspecified, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := kmssvc.ParseKeyUsage(tt.input)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// =============================================================================
// ParseKeyUsages Tests (via SDK)
// =============================================================================

func TestParseKeyUsages(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result, err := kmssvc.ParseKeyUsages("")
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("single usage", func(t *testing.T) {
		result, err := kmssvc.ParseKeyUsages("encrypt")
		require.NoError(t, err)
		assert.Equal(t, []kmssvc.KeyUsage{kmssvc.KeyUsageEncrypt}, result)
	})

	t.Run("multiple usages", func(t *testing.T) {
		result, err := kmssvc.ParseKeyUsages("encrypt,decrypt,sign")
		require.NoError(t, err)
		assert.Len(t, result, 3)
		assert.Equal(t, kmssvc.KeyUsageEncrypt, result[0])
		assert.Equal(t, kmssvc.KeyUsageDecrypt, result[1])
		assert.Equal(t, kmssvc.KeyUsageSign, result[2])
	})

	t.Run("with spaces", func(t *testing.T) {
		result, err := kmssvc.ParseKeyUsages("encrypt , decrypt")
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("invalid usage in list", func(t *testing.T) {
		_, err := kmssvc.ParseKeyUsages("encrypt,invalid,sign")
		require.Error(t, err)
	})
}

// =============================================================================
// readInputData Tests
// =============================================================================

func TestReadInputData(t *testing.T) {
	t.Run("read from file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "input.dat")
		require.NoError(t, os.WriteFile(tmpFile, []byte("test data"), 0600))

		data, err := readInputData(tmpFile)
		require.NoError(t, err)
		assert.Equal(t, []byte("test data"), data)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := readInputData("/nonexistent/path/file.dat")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidInputFile{}, err)
	})
}

// =============================================================================
// writeOutputData Tests
// =============================================================================

func TestWriteOutputData(t *testing.T) {
	t.Run("write to file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "output.dat")
		err := writeOutputData(tmpFile, []byte("output data"), false)
		require.NoError(t, err)

		data, readErr := os.ReadFile(tmpFile)
		require.NoError(t, readErr)
		assert.Equal(t, []byte("output data"), data)
	})

	t.Run("write base64 to file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "output.b64")
		err := writeOutputData(tmpFile, []byte("hello"), true)
		require.NoError(t, err)

		data, readErr := os.ReadFile(tmpFile)
		require.NoError(t, readErr)
		assert.Equal(t, "aGVsbG8=", string(data))
	})

	t.Run("write to invalid path", func(t *testing.T) {
		err := writeOutputData("/nonexistent/dir/file.dat", []byte("data"), false)
		require.Error(t, err)
		assert.IsType(t, ErrInvalidOutputFile{}, err)
	})
}

// =============================================================================
// Testable Error Types Tests
// =============================================================================

func TestTestableErrors(t *testing.T) {
	t.Run("ErrKeyGenerationFailed with error", func(t *testing.T) {
		err := ErrKeyGenerationFailed{KeyID: "key-1", Err: errors.New("gen failed")}
		assert.Contains(t, err.Error(), "key-1")
		assert.Contains(t, err.Error(), "gen failed")
	})

	t.Run("ErrKeyGenerationFailed without error", func(t *testing.T) {
		err := ErrKeyGenerationFailed{KeyID: "key-1"}
		assert.Contains(t, err.Error(), "key-1")
		assert.NotContains(t, err.Error(), "<nil>")
	})

	t.Run("ErrKeyGetFailed with error", func(t *testing.T) {
		err := ErrKeyGetFailed{KeyID: "key-2", Err: errors.New("not found")}
		assert.Contains(t, err.Error(), "key-2")
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ErrKeyGetFailed without error", func(t *testing.T) {
		err := ErrKeyGetFailed{KeyID: "key-2"}
		assert.Contains(t, err.Error(), "key-2")
	})

	t.Run("ErrKeyListFailed with error", func(t *testing.T) {
		err := ErrKeyListFailed{Err: errors.New("list failed")}
		assert.Contains(t, err.Error(), "list failed")
	})

	t.Run("ErrKeyListFailed without error", func(t *testing.T) {
		err := ErrKeyListFailed{}
		assert.Contains(t, err.Error(), "failed to list keys")
	})

	t.Run("ErrKeyDeleteFailed with error", func(t *testing.T) {
		err := ErrKeyDeleteFailed{KeyID: "key-3", Err: errors.New("delete failed")}
		assert.Contains(t, err.Error(), "key-3")
		assert.Contains(t, err.Error(), "delete failed")
	})

	t.Run("ErrKeyDeleteFailed without error", func(t *testing.T) {
		err := ErrKeyDeleteFailed{KeyID: "key-3"}
		assert.Contains(t, err.Error(), "key-3")
	})

	t.Run("ErrKeyRotateFailed with error", func(t *testing.T) {
		err := ErrKeyRotateFailed{KeyID: "key-4", Err: errors.New("rotate failed")}
		assert.Contains(t, err.Error(), "key-4")
		assert.Contains(t, err.Error(), "rotate failed")
	})

	t.Run("ErrKeyRotateFailed without error", func(t *testing.T) {
		err := ErrKeyRotateFailed{KeyID: "key-4"}
		assert.Contains(t, err.Error(), "key-4")
	})

	t.Run("ErrTestableNotImplemented", func(t *testing.T) {
		err := ErrTestableNotImplemented{Function: "runKeyGenerate"}
		assert.Contains(t, err.Error(), "runKeyGenerate")
		assert.Contains(t, err.Error(), "not implemented")
	})
}
