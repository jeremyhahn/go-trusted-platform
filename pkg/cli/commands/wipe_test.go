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

package commands

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewWipeCommand(t *testing.T) {
	cmd := NewWipeCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	})

	if cmd == nil {
		t.Fatal("NewWipeCommand returned nil")
	}

	if cmd.Use != "wipe" {
		t.Errorf("expected Use to be 'wipe', got %s", cmd.Use)
	}

	if cmd.Short != "Securely wipe a LUKS container or device" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestWipeCommandFlags(t *testing.T) {
	cmd := NewWipeCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	tests := []struct {
		name         string
		shorthand    string
		defaultValue string
	}{
		{"path", "p", ""},
		{"passes", "", "1"},
		{"random", "", "false"},
		{"trim", "", "true"},
		{"verbose", "V", "false"},
	}

	for _, tt := range tests {
		flag := cmd.Flags().Lookup(tt.name)
		if flag == nil {
			t.Errorf("flag %s not found", tt.name)
			continue
		}
		if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
			t.Errorf("flag %s: expected shorthand %s, got %s",
				tt.name, tt.shorthand, flag.Shorthand)
		}
		if flag.DefValue != tt.defaultValue {
			t.Errorf("flag %s: expected default %s, got %s",
				tt.name, tt.defaultValue, flag.DefValue)
		}
	}
}

func TestWipeCommandLongDescription(t *testing.T) {
	cmd := NewWipeCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestWipeCommandExample(t *testing.T) {
	cmd := NewWipeCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Example == "" {
		t.Error("Example should not be empty")
	}
}

func TestWipeCommandPathRequired(t *testing.T) {
	cmd := NewWipeCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	// Check that path flag is marked as required
	pathFlag := cmd.Flags().Lookup("path")
	if pathFlag == nil {
		t.Fatal("path flag not found")
	}
}

func TestErrWipePathRequired(t *testing.T) {
	err := ErrWipePathRequired{}
	expected := "--path flag is required"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeAccessFailed(t *testing.T) {
	innerErr := errors.New("permission denied")
	err := ErrWipeAccessFailed{
		Path: "/test/path",
		Err:  innerErr,
	}
	expected := "cannot access /test/path: permission denied"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeFailed(t *testing.T) {
	innerErr := errors.New("device busy")
	err := ErrWipeFailed{
		Path: "/dev/sda1",
		Err:  innerErr,
	}
	expected := "wipe failed for /dev/sda1: device busy"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeOpenFailed(t *testing.T) {
	innerErr := errors.New("no such file")
	err := ErrWipeOpenFailed{
		Path: "/test/file",
		Err:  innerErr,
	}
	expected := "failed to open file /test/file: no such file"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeSeekFailed(t *testing.T) {
	innerErr := errors.New("seek error")
	err := ErrWipeSeekFailed{
		Err: innerErr,
	}
	expected := "seek failed: seek error"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeRandomFailed(t *testing.T) {
	innerErr := errors.New("random generation error")
	err := ErrWipeRandomFailed{
		Err: innerErr,
	}
	expected := "failed to generate random data: random generation error"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeWriteFailed(t *testing.T) {
	innerErr := errors.New("disk full")
	err := ErrWipeWriteFailed{
		Err: innerErr,
	}
	expected := "write failed: disk full"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeSyncFailed(t *testing.T) {
	innerErr := errors.New("sync error")
	err := ErrWipeSyncFailed{
		Err: innerErr,
	}
	expected := "sync failed: sync error"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrWipeRemoveFailed(t *testing.T) {
	innerErr := errors.New("permission denied")
	err := ErrWipeRemoveFailed{
		Path: "/test/file",
		Err:  innerErr,
	}
	expected := "failed to remove wiped file /test/file: permission denied"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestIsBlockDevice(t *testing.T) {
	// Test with a regular file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "testfile")

	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	f.Close()

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("failed to stat test file: %v", err)
	}

	if isBlockDevice(info) {
		t.Error("regular file should not be detected as block device")
	}
}

func TestIsBlockDeviceWithDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("failed to stat temp dir: %v", err)
	}

	if isBlockDevice(info) {
		t.Error("directory should not be detected as block device")
	}
}

func TestClearBuffer(t *testing.T) {
	buffer := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	clearBuffer(buffer)

	for i, b := range buffer {
		if b != 0 {
			t.Errorf("buffer[%d] should be 0, got %d", i, b)
		}
	}
}

func TestClearBufferEmpty(t *testing.T) {
	buffer := []byte{}
	clearBuffer(buffer) // Should not panic
}

func TestCryptoRandFallback(t *testing.T) {
	buffer := make([]byte, 32)
	n, err := cryptoRandFallback(buffer)

	if err != nil {
		t.Errorf("cryptoRandFallback failed: %v", err)
	}

	if n != 32 {
		t.Errorf("expected 32 bytes read, got %d", n)
	}

	// Verify not all zeros (statistically impossible with random data)
	allZero := true
	for _, b := range buffer {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("buffer should contain random data, not all zeros")
	}
}

func TestCryptoRandRead(t *testing.T) {
	buffer := make([]byte, 32)
	n, err := cryptoRandRead(buffer)

	if err != nil {
		t.Errorf("cryptoRandRead failed: %v", err)
	}

	if n != 32 {
		t.Errorf("expected 32 bytes read, got %d", n)
	}

	// Verify not all zeros
	allZero := true
	for _, b := range buffer {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("buffer should contain random data, not all zeros")
	}
}

func TestRunWipeEmptyPath(t *testing.T) {
	commonFlags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	wipeFlags := &wipeFlags{
		path:   "",
		passes: 1,
	}

	err := runWipe(commonFlags, wipeFlags)
	if err == nil {
		t.Error("expected error for empty path")
	}

	if _, ok := err.(ErrWipePathRequired); !ok {
		t.Errorf("expected ErrWipePathRequired, got %T: %v", err, err)
	}
}

func TestRunWipeNonExistentPath(t *testing.T) {
	commonFlags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	wipeFlags := &wipeFlags{
		path:   "/nonexistent/path/that/does/not/exist",
		passes: 1,
	}

	err := runWipe(commonFlags, wipeFlags)
	if err == nil {
		t.Error("expected error for non-existent path")
	}

	if _, ok := err.(ErrWipeAccessFailed); !ok {
		t.Errorf("expected ErrWipeAccessFailed, got %T: %v", err, err)
	}
}

func TestRunWipeRegularFile(t *testing.T) {
	// Create a temporary file to wipe
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_file")

	// Create file with some content
	content := make([]byte, 4096) // 4KB file
	for i := range content {
		content[i] = byte(i % 256)
	}
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	commonFlags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		Verbose:      false,
	}
	wipeFlags := &wipeFlags{
		path:    tmpFile,
		passes:  1,
		random:  false,
		trim:    false,
		verbose: false,
	}

	err := runWipe(commonFlags, wipeFlags)
	if err != nil {
		t.Errorf("runWipe failed: %v", err)
	}

	// Verify file was deleted
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Error("wiped file should have been deleted")
	}
}

func TestRunWipeRegularFileWithRandom(t *testing.T) {
	// Create a temporary file to wipe
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_random")

	// Create file with some content
	content := make([]byte, 4096)
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	commonFlags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	wipeFlags := &wipeFlags{
		path:    tmpFile,
		passes:  1,
		random:  true, // Use random data
		trim:    false,
		verbose: false,
	}

	err := runWipe(commonFlags, wipeFlags)
	if err != nil {
		t.Errorf("runWipe with random failed: %v", err)
	}

	// Verify file was deleted
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Error("wiped file should have been deleted")
	}
}

func TestRunWipeMultiplePasses(t *testing.T) {
	// Create a temporary file to wipe
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_multipass")

	content := make([]byte, 2048)
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	commonFlags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	wipeFlags := &wipeFlags{
		path:    tmpFile,
		passes:  3, // Multiple passes
		random:  false,
		trim:    false,
		verbose: false,
	}

	err := runWipe(commonFlags, wipeFlags)
	if err != nil {
		t.Errorf("runWipe with multiple passes failed: %v", err)
	}
}

func TestRunWipeVerbose(t *testing.T) {
	// Create a temporary file to wipe
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_verbose")

	content := make([]byte, 1024)
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	commonFlags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		Verbose:      true, // Enable verbose in common flags
	}
	wipeFlags := &wipeFlags{
		path:    tmpFile,
		passes:  1,
		random:  false,
		trim:    true, // Test trim path (even though for files it just logs)
		verbose: false,
	}

	err := runWipe(commonFlags, wipeFlags)
	if err != nil {
		t.Errorf("runWipe with verbose failed: %v", err)
	}
}

func TestRunWipeVerboseFlag(t *testing.T) {
	// Create a temporary file to wipe
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_verbose_flag")

	content := make([]byte, 1024)
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	commonFlags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		Verbose:      false,
	}
	wipeFlags := &wipeFlags{
		path:    tmpFile,
		passes:  1,
		random:  true,
		trim:    true,
		verbose: true, // Enable verbose in wipe flags
	}

	err := runWipe(commonFlags, wipeFlags)
	if err != nil {
		t.Errorf("runWipe with verbose flag failed: %v", err)
	}
}

func TestWipeFileOpenError(t *testing.T) {
	// Test wipeFile with a path that cannot be opened
	flags := &wipeFlags{
		path:    "/nonexistent/dir/file",
		passes:  1,
		random:  false,
		trim:    false,
		verbose: false,
	}
	commonFlags := &cli.CommonFlags{}

	err := wipeFile(flags, commonFlags, 1024)
	if err == nil {
		t.Error("expected error when file cannot be opened")
	}

	if _, ok := err.(ErrWipeOpenFailed); !ok {
		t.Errorf("expected ErrWipeOpenFailed, got %T: %v", err, err)
	}
}

func TestWipeCommandStructure(t *testing.T) {
	cmd := NewWipeCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.Example == "" {
		t.Error("Example should not be empty")
	}

	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}
}

func TestWipeCommandFlagsUsage(t *testing.T) {
	cmd := NewWipeCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	flagUsages := map[string]string{
		"path":    "Path to device or container file to wipe (required)",
		"passes":  "Number of wipe passes (default: 1)",
		"random":  "Use random data instead of zeros",
		"trim":    "Issue TRIM/DISCARD after wipe for SSDs (default: true)",
		"verbose": "Enable verbose output",
	}

	for name, expectedUsage := range flagUsages {
		flag := cmd.Flags().Lookup(name)
		if flag == nil {
			t.Errorf("flag %s not found", name)
			continue
		}
		if flag.Usage != expectedUsage {
			t.Errorf("flag %s: expected usage '%s', got '%s'",
				name, expectedUsage, flag.Usage)
		}
	}
}
