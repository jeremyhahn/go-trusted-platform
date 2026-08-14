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

package initrd

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestTPMTypeString(t *testing.T) {
	tests := []struct {
		name     string
		tpmType  TPMType
		expected string
	}{
		{"hardware", HardwareTPM, "hardware"},
		{"software", SoftwareTPM, "software"},
		{"unknown", TPMType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tpmType.String()
			if result != tt.expected {
				t.Errorf("TPMType(%d).String() = %s, want %s", tt.tpmType, result, tt.expected)
			}
		})
	}
}

func TestNewTPMDetector(t *testing.T) {
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	if detector == nil {
		t.Fatal("NewTPMDetector returned nil")
	}

	if detector.logger != logger {
		t.Error("logger not set correctly")
	}
}

func TestDetectTPMTypeNoDevices(t *testing.T) {
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	// On a typical test system without TPM devices, this should fail
	// We test the error path - no TPM device found
	tpmType, device, err := detector.DetectTPMType()
	if err == nil {
		// TPM exists on this system, verify the return values are reasonable
		if device == "" {
			t.Error("expected non-empty device path when TPM is detected")
		}
		_ = tpmType
	} else if device != "" {
		// Expected error when no TPM device is available
		t.Errorf("expected empty device when no TPM found, got %s", device)
	}
}

func TestIsSocket(t *testing.T) {
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	t.Run("unix_socket", func(t *testing.T) {
		tmpDir := t.TempDir()
		sockPath := filepath.Join(tmpDir, "test.sock")

		// Create a real Unix domain socket
		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("failed to create socket: %v", err)
		}
		defer listener.Close()

		if !detector.isSocket(sockPath) {
			t.Error("expected isSocket to return true for Unix socket")
		}
	})

	t.Run("regular_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "regular.txt")
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		if detector.isSocket(filePath) {
			t.Error("expected isSocket to return false for regular file")
		}
	})

	t.Run("nonexistent", func(t *testing.T) {
		if detector.isSocket("/nonexistent/path/sock") {
			t.Error("expected isSocket to return false for nonexistent path")
		}
	})
}

func TestIsDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	t.Run("regular_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "regular.txt")
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		if detector.isDevice(filePath) {
			t.Error("expected isDevice to return false for regular file")
		}
	})

	t.Run("nonexistent", func(t *testing.T) {
		if detector.isDevice("/nonexistent/path/dev") {
			t.Error("expected isDevice to return false for nonexistent path")
		}
	})

	t.Run("dev_null", func(t *testing.T) {
		// /dev/null is a device file that should exist on all Linux systems
		result := detector.isDevice("/dev/null")
		if !result {
			t.Error("expected isDevice to return true for /dev/null")
		}
	})
}

func TestCommandExists(t *testing.T) {
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	t.Run("nonexistent_command", func(t *testing.T) {
		if detector.commandExists("nonexistent-command-xyz-12345") {
			t.Error("expected commandExists to return false for nonexistent command")
		}
	})

	t.Run("ls_command", func(t *testing.T) {
		// /usr/bin/ls should exist on most systems
		if _, err := os.Stat("/usr/bin/ls"); err == nil {
			if !detector.commandExists("ls") {
				t.Error("expected commandExists to return true for ls")
			}
		}
	})
}

func TestDetectOrStartTPMNoDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	tmpDir := t.TempDir()

	tpmType, device, started, err := detector.DetectOrStartTPM(tmpDir)

	// On test systems without TPM or swtpm, this may fail or succeed
	// depending on what's available
	if err != nil {
		// Expected on most CI/test systems
		if started {
			t.Error("expected started=false when error occurs")
		}
		return
	}

	// If we got here, either a TPM exists or swtpm was "prepared"
	if device == "" {
		t.Error("expected non-empty device path")
	}
	_ = tpmType
	_ = started
}

func TestDetectOrStartTPMEmptyStateDir(t *testing.T) {
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	// Pass empty string for state dir to use default
	_, _, _, err := detector.DetectOrStartTPM("")
	// Either succeeds (TPM exists) or fails (no TPM + no swtpm)
	// We just ensure it doesn't panic
	_ = err
}

func TestDetectTPMTypeSoftwareTPMSocket(t *testing.T) {
	// Create a socket at a custom location to test detection logic
	// We can't test /var/lib/swtpm/swtpm.sock directly but we can
	// verify the detection mechanism works
	logger := logging.DefaultLogger()
	detector := NewTPMDetector(logger)

	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test-tpm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}
	defer listener.Close()

	// Verify our socket is detected as a socket
	if !detector.isSocket(sockPath) {
		t.Error("test socket should be detected as socket")
	}
}
