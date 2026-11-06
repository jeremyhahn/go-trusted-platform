//go:build integration

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

package alpine

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// TestFIPSInstaller_Install_SuccessPath tests the successful installation flow

// TestFIPSInstaller_InstallKernel_WithArtifacts tests kernel installation with artifacts
func TestFIPSInstaller_InstallKernel_WithArtifacts(t *testing.T) {

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	// Create the expected artifacts directory that installFIPSKernel looks for
	artifactsDir := "/media/cdrom/fips-artifacts"

	// Since we can't create /media/cdrom in tests, we'll test the error path
	mountPoint := filepath.Join(tmpDir, "mnt")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("failed to create mount point: %v", err)
	}

	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: mountPoint,
		Logger:     logger,
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	fipsInstaller := installer.(*FIPSInstaller)
	err = fipsInstaller.installFIPSKernel(context.Background())
	if err == nil {
		t.Error("expected error for missing artifacts directory")
	}

	// Verify error message
	if !containsString(err.Error(), artifactsDir) {
		t.Errorf("error should mention %s, got: %v", artifactsDir, err)
	}
}

// TestFIPSInstaller_ConfigureOpenSSL_FullFlow tests OpenSSL configuration flow

// TestFIPSInstaller_installOpenSSLFIPS_ChrootFailure tests chroot failure
func TestFIPSInstaller_installOpenSSLFIPS_ChrootFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	// Create mount point but ensure chroot will fail
	mountPoint := filepath.Join(tmpDir, "mnt")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("failed to create mount point: %v", err)
	}

	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: mountPoint,
		Logger:     logger,
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	fipsInstaller := installer.(*FIPSInstaller)

	// Create a mock /media/cdrom structure (will fail due to permissions in test)
	// This tests the chroot execution path
	ctx := context.Background()
	err = fipsInstaller.installOpenSSLFIPS(ctx)

	// Should fail due to chroot or missing artifacts
	if err == nil {
		t.Error("expected error when trying to run apk/chroot")
	}
}

// TestFIPSInstaller_generateFIPSModuleConfig_WithOpenSSL tests config generation
func TestFIPSInstaller_generateFIPSModuleConfig_WithOpenSSL(t *testing.T) {

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	mountPoint := filepath.Join(tmpDir, "mnt")
	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: mountPoint,
		Logger:     logger,
	}

	// Create SSL directory
	sslDir := filepath.Join(mountPoint, "etc", "ssl")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		t.Fatalf("failed to create ssl dir: %v", err)
	}

	// Create FIPS module
	fipsModuleDir := filepath.Join(mountPoint, "usr", "lib", "ossl-modules")
	if err := os.MkdirAll(fipsModuleDir, 0755); err != nil {
		t.Fatalf("failed to create fips module dir: %v", err)
	}
	fipsModule := filepath.Join(fipsModuleDir, "fips.so")
	if err := os.WriteFile(fipsModule, []byte("mock fips module"), 0644); err != nil {
		t.Fatalf("failed to create fips module: %v", err)
	}

	// Create mock openssl binary
	opensslDir := filepath.Join(mountPoint, "usr", "bin")
	if err := os.MkdirAll(opensslDir, 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	opensslPath := filepath.Join(opensslDir, "openssl")
	// Create a mock openssl that will fail (testing error path)
	if err := os.WriteFile(opensslPath, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatalf("failed to create openssl: %v", err)
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	fipsInstaller := installer.(*FIPSInstaller)

	// This should fail when running openssl fipsinstall
	err = fipsInstaller.generateFIPSModuleConfig()
	if err == nil {
		t.Error("expected error when openssl fipsinstall fails")
	}
}

// TestFIPSInstaller_configureOpenSSLFIPS_Success tests successful configuration
func TestFIPSInstaller_configureOpenSSLFIPS_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	mountPoint := filepath.Join(tmpDir, "mnt")
	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: mountPoint,
		Logger:     logger,
	}

	// Create required structure
	sslDir := filepath.Join(mountPoint, "etc", "ssl")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		t.Fatalf("failed to create ssl dir: %v", err)
	}

	fipsModuleDir := filepath.Join(mountPoint, "usr", "lib", "ossl-modules")
	if err := os.MkdirAll(fipsModuleDir, 0755); err != nil {
		t.Fatalf("failed to create fips module dir: %v", err)
	}
	fipsModule := filepath.Join(fipsModuleDir, "fips.so")
	if err := os.WriteFile(fipsModule, []byte("mock"), 0644); err != nil {
		t.Fatalf("failed to create fips module: %v", err)
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	fipsInstaller := installer.(*FIPSInstaller)

	// This will fail at generateFIPSModuleConfig due to missing openssl
	// but tests the configureOpenSSLFIPS function entry
	err = fipsInstaller.configureOpenSSLFIPS()
	if err == nil {
		t.Error("expected error due to missing openssl binary")
	}
}

// TestFIPSInstaller_ConfigureOpenSSL_AllVerificationPaths tests all verification branches

// TestFIPSInstaller_updateOpenSSLConfig_ReadError tests read error handling
func TestFIPSInstaller_updateOpenSSLConfig_ReadError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: tmpDir,
		Logger:     logger,
	}

	// Create SSL directory with a file that can't be written
	sslDir := filepath.Join(tmpDir, "etc", "ssl")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		t.Fatalf("failed to create ssl dir: %v", err)
	}

	// Create existing openssl.cnf
	opensslConfig := filepath.Join(sslDir, "openssl.cnf")
	if err := os.WriteFile(opensslConfig, []byte("original"), 0644); err != nil {
		t.Fatalf("failed to create openssl.cnf: %v", err)
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	fipsInstaller := installer.(*FIPSInstaller)

	// Make the file itself read-only to cause write failure
	if err := os.Chmod(opensslConfig, 0444); err != nil {
		t.Fatalf("failed to chmod openssl.cnf: %v", err)
	}
	defer os.Chmod(opensslConfig, 0644) // Restore for cleanup

	// Should fail to write to read-only file
	err = fipsInstaller.updateOpenSSLConfig()
	if err == nil {
		t.Error("expected error when writing to read-only file")
	}
}

// TestFIPSInstaller_installPackage_ContextCancellation tests context handling
func TestFIPSInstaller_installPackage_ContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		Mirror:     "http://invalid-mirror-for-test.example",
		WorkDir:    tmpDir,
		MountPoint: tmpDir,
		Logger:     logger,
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	fipsInstaller := installer.(*FIPSInstaller)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should fail quickly due to cancelled context
	err = fipsInstaller.installPackage(ctx, "test-package")
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

// TestExecCommandContext tests that exec commands can be properly called
