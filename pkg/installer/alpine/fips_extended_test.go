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
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// TestFIPSInstaller_Install_WithValidArtifacts tests successful install flow with artifacts
// This test verifies error handling when /media/cdrom is not available (expected in test env)

// TestFIPSInstaller_InstallFIPSKernel_SuccessPath tests kernel installation success path
// This test verifies the error path when root privileges are not available

// TestFIPSInstaller_ConfigureOpenSSL_WithValidSetup tests OpenSSL configuration

// TestFIPSInstaller_generateFIPSModuleConfig_OpenSSLNotFound tests missing openssl
func TestFIPSInstaller_generateFIPSModuleConfig_OpenSSLNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()
	mountPoint := filepath.Join(tmpDir, "mnt")

	if err := os.MkdirAll(filepath.Join(mountPoint, "usr", "lib", "ossl-modules"), 0755); err != nil {
		t.Fatalf("failed to create ossl-modules dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(mountPoint, "etc", "ssl"), 0755); err != nil {
		t.Fatalf("failed to create ssl dir: %v", err)
	}

	// Create FIPS module but NO openssl binary
	fipsModule := filepath.Join(mountPoint, "usr", "lib", "ossl-modules", "fips.so")
	if err := os.WriteFile(fipsModule, []byte("mock"), 0644); err != nil {
		t.Fatalf("failed to create fips module: %v", err)
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
	err = fipsInstaller.generateFIPSModuleConfig()
	if err == nil {
		t.Error("expected error when openssl binary not found")
	}
	if !strings.Contains(err.Error(), "openssl") && !strings.Contains(err.Error(), "not found") {
		t.Logf("Got error (expected): %v", err)
	}
}

// TestFIPSInstaller_generateFIPSModuleConfig_FipsinstallFails tests openssl failure
func TestFIPSInstaller_generateFIPSModuleConfig_FipsinstallFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()
	mountPoint := filepath.Join(tmpDir, "mnt")

	if err := os.MkdirAll(filepath.Join(mountPoint, "usr", "lib", "ossl-modules"), 0755); err != nil {
		t.Fatalf("failed to create ossl-modules dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(mountPoint, "usr", "bin"), 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(mountPoint, "etc", "ssl"), 0755); err != nil {
		t.Fatalf("failed to create ssl dir: %v", err)
	}

	// Create FIPS module
	fipsModule := filepath.Join(mountPoint, "usr", "lib", "ossl-modules", "fips.so")
	if err := os.WriteFile(fipsModule, []byte("mock"), 0644); err != nil {
		t.Fatalf("failed to create fips module: %v", err)
	}

	// Create openssl that fails
	opensslPath := filepath.Join(mountPoint, "usr", "bin", "openssl")
	failScript := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(opensslPath, []byte(failScript), 0755); err != nil {
		t.Fatalf("failed to create openssl: %v", err)
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
	err = fipsInstaller.generateFIPSModuleConfig()
	if err == nil {
		t.Error("expected error when openssl fipsinstall fails")
	}
}

// TestFIPSInstaller_generateFIPSModuleConfig_ConfigNotCreated tests verification
func TestFIPSInstaller_generateFIPSModuleConfig_ConfigNotCreated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()
	mountPoint := filepath.Join(tmpDir, "mnt")

	if err := os.MkdirAll(filepath.Join(mountPoint, "usr", "lib", "ossl-modules"), 0755); err != nil {
		t.Fatalf("failed to create ossl-modules dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(mountPoint, "usr", "bin"), 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(mountPoint, "etc", "ssl"), 0755); err != nil {
		t.Fatalf("failed to create ssl dir: %v", err)
	}

	// Create FIPS module
	fipsModule := filepath.Join(mountPoint, "usr", "lib", "ossl-modules", "fips.so")
	if err := os.WriteFile(fipsModule, []byte("mock"), 0644); err != nil {
		t.Fatalf("failed to create fips module: %v", err)
	}

	// Create openssl that succeeds but doesn't create config
	opensslPath := filepath.Join(mountPoint, "usr", "bin", "openssl")
	noopScript := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(opensslPath, []byte(noopScript), 0755); err != nil {
		t.Fatalf("failed to create openssl: %v", err)
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
	err = fipsInstaller.generateFIPSModuleConfig()
	if err == nil {
		t.Error("expected error when fipsmodule.cnf is not created")
	}
	if !strings.Contains(err.Error(), "was not created") && !strings.Contains(err.Error(), "fipsmodule.cnf") {
		t.Logf("Got error about missing config (expected): %v", err)
	}
}

// TestFIPSInstaller_installPackage_APKManagerError tests APK manager integration
func TestFIPSInstaller_installPackage_APKManagerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		Mirror:     closedMirror(t),
		WorkDir:    tmpDir,
		MountPoint: tmpDir,
		Logger:     logger,
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	fipsInstaller := installer.(*FIPSInstaller)

	// Should fail with download error
	err = fipsInstaller.installPackage(context.Background(), "nonexistent-pkg")
	if err == nil {
		t.Error("expected error for invalid package")
	}
	if !strings.Contains(err.Error(), "failed to install") {
		t.Logf("Got expected error: %v", err)
	}
}

// TestFIPSInstaller_Verify_ReadFileError tests file read error handling
func TestFIPSInstaller_Verify_ReadFileError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	// Create all required files
	fipsModuleDir := filepath.Join(tmpDir, "usr", "lib", "ossl-modules")
	if err := os.MkdirAll(fipsModuleDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fipsModuleDir, "fips.so"), []byte("mock"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	sslDir := filepath.Join(tmpDir, "etc", "ssl")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		t.Fatalf("failed to create ssl dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sslDir, "fipsmodule.cnf"), []byte("mock"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create openssl.cnf but make it unreadable
	opensslConfig := filepath.Join(sslDir, "openssl.cnf")
	if err := os.WriteFile(opensslConfig, []byte("config"), 0000); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: tmpDir,
		Logger:     logger,
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	err = installer.Verify()
	if err == nil {
		t.Error("expected error when reading openssl.cnf fails")
	}
}

// TestExecCommand tests exec.Command functionality

// TestTarCreation tests tar.gz creation used in modules
