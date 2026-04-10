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

package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEscapeFilePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "(STAGING) False Fennel E6",
			expected: `\(STAGING\)\ False\ Fennel\ E6`,
		},
		{
			input:    `Special chars !@#$%^&*()`,
			expected: `Special\ chars\ \!\@\#\$\%\^\&\*\(\)`,
		},
		{
			input:    `NoSpecialChars`,
			expected: `NoSpecialChars`,
		},
		{
			input:    `path/with spaces`,
			expected: `path/with\ spaces`,
		},
		{
			input:    `back\slash\test`,
			expected: `back\\slash\\test`,
		},
	}

	for _, test := range tests {
		result := EscapeFilePath(test.input)
		if result != test.expected {
			t.Errorf("EscapeFilePath(%q) = %q; want %q", test.input, result, test.expected)
		}
	}
}

func TestIsEmpty_EmptyDirectory(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "test-empty-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Test empty directory
	if !IsEmpty(tmpDir) {
		t.Error("Expected empty directory to return true")
	}
}

func TestIsEmpty_NonEmptyDirectory(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "test-nonempty-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Add a file to make it non-empty
	tmpFile := filepath.Join(tmpDir, "testfile.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test non-empty directory
	if IsEmpty(tmpDir) {
		t.Error("Expected non-empty directory to return false")
	}
}

func TestIsEmpty_NonExistentDirectory(t *testing.T) {
	// Test with a directory that doesn't exist
	if IsEmpty("/nonexistent/path/to/directory") {
		t.Error("Expected non-existent directory to return false")
	}
}

func TestIsEmpty_File(t *testing.T) {
	// Create a temporary file (not a directory)
	tmpFile, err := os.CreateTemp("", "test-file-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// Test with a file instead of directory
	if IsEmpty(tmpFile.Name()) {
		t.Error("Expected file path to return false")
	}
}
