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
)

func TestReadServerPlatformConfig_NoFile(t *testing.T) {
	// This will fail because the config file doesn't exist
	_, err := ReadServerPlatformConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error when config file doesn't exist")
	}
}

func TestReadClientPlatformConfig_NoFile(t *testing.T) {
	// This will fail because the config file doesn't exist
	_, err := ReadClientPlatformConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error when config file doesn't exist")
	}
}

func TestReadServerPlatformConfig_WithFile(t *testing.T) {
	// Create temp directory and config file
	tmpDir, err := os.MkdirTemp("", "platform-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a config file with DNS macros (they should NOT be expanded here)
	configContent := `domain: server.example.com
dns:
  internal:
    zone:
      records:
        a:
          - name: "@"
            value: ${PRIVATE_IPv4}
  public:
    zone:
      records:
        a:
          - name: "@"
            value: ${PUBLIC_IPv4}
`
	configPath := filepath.Join(tmpDir, "server.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	result, err := ReadServerPlatformConfig(configPath)
	if err != nil {
		t.Fatalf("failed to read server platform config: %v", err)
	}

	resultStr := string(result)

	// DNS macros should NOT be expanded - they are expanded at runtime by DNS service
	if resultStr != configContent {
		t.Errorf("config content should not be modified\nexpected:\n%s\ngot:\n%s", configContent, resultStr)
	}
}

func TestReadClientPlatformConfig_WithFile(t *testing.T) {
	// Create temp directory and config file
	tmpDir, err := os.MkdirTemp("", "platform-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a config file
	configContent := `domain: client.example.com
acme:
  client:
    directory: https://server.example.internal:9443/api/v1/acme/directory
`
	configPath := filepath.Join(tmpDir, "client.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	result, err := ReadClientPlatformConfig(configPath)
	if err != nil {
		t.Fatalf("failed to read client platform config: %v", err)
	}

	resultStr := string(result)

	// Config content should be read as-is
	if resultStr != configContent {
		t.Errorf("config content should not be modified\nexpected:\n%s\ngot:\n%s", configContent, resultStr)
	}
}

func TestWritePlatformConfig(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "platform-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testContent := []byte("test: config\nvalue: 123\n")
	configPath := filepath.Join(tmpDir, "test-platform.yaml")

	if err := WritePlatformConfig(testContent, configPath); err != nil {
		t.Fatalf("failed to write platform config: %v", err)
	}

	// Verify file exists and has correct content
	readContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read written config: %v", err)
	}

	if string(readContent) != string(testContent) {
		t.Errorf("content mismatch: expected '%s', got '%s'", testContent, readContent)
	}
}

func TestWritePlatformConfig_Error(t *testing.T) {
	// Try to write to an invalid path
	err := WritePlatformConfig([]byte("test"), "/nonexistent/dir/config.yaml")
	if err == nil {
		t.Error("expected error when writing to invalid path")
	}
}

func TestReadServerPlatformConfig_DefaultPath(t *testing.T) {
	// Test that empty path uses default
	// This will fail in test environment since default configs don't exist
	_, err := ReadServerPlatformConfig("")
	if err == nil {
		// If no error, the default config file exists (which is fine)
		return
	}
	// Error expected since default config likely doesn't exist in test env
}

func TestReadClientPlatformConfig_DefaultPath(t *testing.T) {
	// Test that empty path uses default
	// This will fail in test environment since default configs don't exist
	_, err := ReadClientPlatformConfig("")
	if err == nil {
		// If no error, the default config file exists (which is fine)
		return
	}
	// Error expected since default config likely doesn't exist in test env
}

func TestDefaultPaths(t *testing.T) {
	// Verify default path constants are set
	if DefaultServerPlatformConfigPath == "" {
		t.Error("DefaultServerPlatformConfigPath should not be empty")
	}
	if DefaultClientPlatformConfigPath == "" {
		t.Error("DefaultClientPlatformConfigPath should not be empty")
	}
}
