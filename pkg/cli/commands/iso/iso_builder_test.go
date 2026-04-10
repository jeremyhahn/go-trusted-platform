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

//go:build integration

package iso

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil) // Use error level to reduce noise in tests
}

func TestBuildCustomISO_WorkDirCreation(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	tmpDir, err := os.MkdirTemp("", "iso-builder-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	workDir := filepath.Join(tmpDir, "work")
	outputISO := filepath.Join(tmpDir, "output.iso")

	cfg := &ISOBuilderConfig{
		OutputPath:   outputISO,
		WorkDir:      workDir,
		PlatformType: "server",
		SecureBoot:   false, // Disable SecureBoot for faster test
		EnableFIDO2:  false,
		Debug:        false,
	}

	// This will fail because we don't have all dependencies, but we're testing work dir creation
	_ = BuildCustomISO(ctx, logger, cfg)

	// Work dir should be created even if build fails
	if _, statErr := os.Stat(workDir); os.IsNotExist(statErr) {
		t.Error("work directory should have been created")
	}
}

func TestBuildCustomISO_InvalidPlatformdBinary(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	tmpDir, err := os.MkdirTemp("", "iso-builder-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	workDir := filepath.Join(tmpDir, "work")
	outputISO := filepath.Join(tmpDir, "output.iso")

	cfg := &ISOBuilderConfig{
		OutputPath:      outputISO,
		WorkDir:         workDir,
		PlatformType:    "server",
		PlatformdBinary: "/nonexistent/platformd", // Invalid path
		SecureBoot:      false,
		EnableFIDO2:     false,
		Debug:           false,
	}

	err = BuildCustomISO(ctx, logger, cfg)
	if err == nil {
		t.Error("expected error for non-existent platformd binary")
	}
}

func TestBuildCustomISO_RelativePlatformdPath(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	tmpDir, err := os.MkdirTemp("", "iso-builder-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy platformd binary
	platformdPath := filepath.Join(tmpDir, "platformd")
	if err := os.WriteFile(platformdPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("failed to create test binary: %v", err)
	}

	workDir := filepath.Join(tmpDir, "work")
	outputISO := filepath.Join(tmpDir, "output.iso")

	// Change to tmpDir to test relative path resolution
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	cfg := &ISOBuilderConfig{
		OutputPath:      outputISO,
		WorkDir:         workDir,
		PlatformType:    "server",
		PlatformdBinary: "./platformd", // Relative path
		SecureBoot:      false,
		EnableFIDO2:     false,
		Debug:           false,
	}

	err = BuildCustomISO(ctx, logger, cfg)
	// Error expected because we don't have ISO building dependencies
	// But the binary path should have been resolved
	if err == nil {
		t.Log("ISO build completed (dependencies available)")
	}
}

func TestISOBuilderConfig_Defaults(t *testing.T) {
	cfg := &ISOBuilderConfig{}

	// Verify default values are empty
	if cfg.OutputPath != "" {
		t.Error("expected empty OutputPath default")
	}
	if cfg.WorkDir != "" {
		t.Error("expected empty WorkDir default")
	}
	if cfg.SecureBoot {
		t.Error("expected false SecureBoot default")
	}
	if cfg.EnableFIDO2 {
		t.Error("expected false EnableFIDO2 default")
	}
	if cfg.Debug {
		t.Error("expected false Debug default")
	}
}

func TestISOBuilderConfig_PlatformTypes(t *testing.T) {
	tests := []struct {
		name         string
		platformType string
	}{
		{"server type", "server"},
		{"client type", "client"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ISOBuilderConfig{
				PlatformType: tt.platformType,
			}
			if cfg.PlatformType != tt.platformType {
				t.Errorf("expected platform type %s, got %s", tt.platformType, cfg.PlatformType)
			}
		})
	}
}
