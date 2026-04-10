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

package iso

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveFileIfExists_FileExists(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "remove-test-*")
	require.NoError(t, err)
	tmpFile.Close()
	tmpPath := tmpFile.Name()

	// File should exist
	_, err = os.Stat(tmpPath)
	require.NoError(t, err)

	// Remove it
	err = removeFileIfExists(tmpPath)
	assert.NoError(t, err)

	// File should no longer exist
	_, err = os.Stat(tmpPath)
	assert.True(t, os.IsNotExist(err))
}

func TestRemoveFileIfExists_FileNotExists(t *testing.T) {
	// Should not return error for non-existent file
	err := removeFileIfExists("/nonexistent/path/file.txt")
	assert.NoError(t, err)
}

func TestRemoveFileIfExists_NonEmptyDirectory(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "remove-test-dir-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a file inside to make it non-empty
	tmpFile := filepath.Join(tmpDir, "test.txt")
	err = os.WriteFile(tmpFile, []byte("test"), 0644)
	require.NoError(t, err)

	// Trying to remove a non-empty directory with os.Remove should fail
	// and our function should return the error
	err = removeFileIfExists(tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove")
}

func TestRemoveFileIfExists_EmptyDirectory(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "remove-empty-dir-*")
	require.NoError(t, err)

	// On Unix, os.Remove can remove an empty directory
	// Our function should succeed for empty directories
	err = removeFileIfExists(tmpDir)
	assert.NoError(t, err)

	// Directory should no longer exist
	_, err = os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(err))
}

func TestFileExists_True(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "exists-test-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	assert.True(t, fileExists(tmpFile.Name()))
}

func TestFileExists_False(t *testing.T) {
	assert.False(t, fileExists("/nonexistent/path/file.txt"))
}

func TestFileExists_Directory(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "exists-test-dir-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// fileExists returns true for directories too (it uses os.Stat)
	assert.True(t, fileExists(tmpDir))
}

func TestDirExists_True(t *testing.T) {
	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "dir-exists-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	assert.True(t, dirExists(tmpDir))
}

func TestDirExists_False(t *testing.T) {
	assert.False(t, dirExists("/nonexistent/directory"))
}

func TestDirExists_FileNotDir(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "dir-exists-file-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Should return false for a file
	assert.False(t, dirExists(tmpFile.Name()))
}

func TestPrintHeader(t *testing.T) {
	// Test that printHeader doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printHeader panicked: %v", r)
		}
	}()

	printHeader("Test Header")
}

func TestPrintInfo(t *testing.T) {
	// Test that printInfo doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printInfo panicked: %v", r)
		}
	}()

	printInfo("Test Info Message")
}

func TestPrintSuccess(t *testing.T) {
	// Test that printSuccess doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printSuccess panicked: %v", r)
		}
	}()

	printSuccess("Test Success Message")
}

func TestPrintWarn(t *testing.T) {
	// Test that printWarn doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printWarn panicked: %v", r)
		}
	}()

	printWarn("Test Warning Message")
}

func TestPrintError(t *testing.T) {
	// Test that printError doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printError panicked: %v", r)
		}
	}()

	printError("Test Error Message")
}

func TestPrintFunctions_EmptyStrings(t *testing.T) {
	// Test that print functions handle empty strings
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("print function panicked with empty string: %v", r)
		}
	}()

	printHeader("")
	printInfo("")
	printSuccess("")
	printWarn("")
	printError("")
}

func TestPrintFunctions_SpecialCharacters(t *testing.T) {
	// Test that print functions handle special characters
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("print function panicked with special characters: %v", r)
		}
	}()

	specialStr := "Test with special chars: @#$%^&*()[]{}|\\\"'"
	printHeader(specialStr)
	printInfo(specialStr)
	printSuccess(specialStr)
	printWarn(specialStr)
	printError(specialStr)
}

func TestPrintFunctions_LongStrings(t *testing.T) {
	// Test that print functions handle long strings
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("print function panicked with long string: %v", r)
		}
	}()

	longStr := ""
	for i := 0; i < 1000; i++ {
		longStr += "x"
	}

	printHeader(longStr)
	printInfo(longStr)
	printSuccess(longStr)
	printWarn(longStr)
	printError(longStr)
}

func TestPrintTestHeader(t *testing.T) {
	// Test that printTestHeader doesn't panic (from test.go)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printTestHeader panicked: %v", r)
		}
	}()

	printTestHeader("Test Header")
}
