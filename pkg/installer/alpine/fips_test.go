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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

func TestNewFIPSInstaller(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			Mirror:     "https://dl-cdn.alpinelinux.org/alpine",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if installer == nil {
			t.Fatal("expected installer to be non-nil")
		}

		// Verify it implements the interface (compile-time check via return type)
		_ = installer
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewFIPSInstaller(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("nil logger uses default", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			Mirror:     "https://dl-cdn.alpinelinux.org/alpine",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     nil, // Should use default
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if installer == nil {
			t.Fatal("expected installer to be non-nil")
		}
	})

	t.Run("empty config fields", func(t *testing.T) {
		config := &fips.Config{} // All fields empty

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if installer == nil {
			t.Fatal("expected installer to be non-nil even with empty fields")
		}
	})
}

func TestFIPSInstaller_GetKernelCommandLine(t *testing.T) {
	tmpDir := t.TempDir()
	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: tmpDir,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	installer, err := NewFIPSInstaller(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmdline := installer.GetKernelCommandLine()
	if cmdline != "fips=1" {
		t.Errorf("expected 'fips=1', got '%s'", cmdline)
	}
}

func TestFIPSInstaller_Verify(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("all files present and valid", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     logger,
		}

		// Create required directories and files
		fipsModulePath := filepath.Join(tmpDir, "usr", "lib", "ossl-modules")
		if err := os.MkdirAll(fipsModulePath, 0755); err != nil {
			t.Fatalf("failed to create fips module dir: %v", err)
		}

		sslDir := filepath.Join(tmpDir, "etc", "ssl")
		if err := os.MkdirAll(sslDir, 0755); err != nil {
			t.Fatalf("failed to create ssl dir: %v", err)
		}

		// Create fips.so
		fipsModule := filepath.Join(fipsModulePath, "fips.so")
		if err := os.WriteFile(fipsModule, []byte("fake fips module"), 0644); err != nil {
			t.Fatalf("failed to create fips module: %v", err)
		}

		// Create fipsmodule.cnf
		fipsConfig := filepath.Join(sslDir, "fipsmodule.cnf")
		if err := os.WriteFile(fipsConfig, []byte("[fips_sect]\nactivate = 1"), 0644); err != nil {
			t.Fatalf("failed to create fipsmodule.cnf: %v", err)
		}

		// Create openssl.cnf with fips_sect
		opensslConfig := filepath.Join(sslDir, "openssl.cnf")
		opensslContent := `config_diagnostics = 1
openssl_conf = openssl_init

.include /etc/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[fips_sect]
activate = 1
`
		if err := os.WriteFile(opensslConfig, []byte(opensslContent), 0644); err != nil {
			t.Fatalf("failed to create openssl.cnf: %v", err)
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = installer.Verify()
		if err != nil {
			t.Errorf("verification should pass: %v", err)
		}
	})

	t.Run("missing fips module", func(t *testing.T) {
		tmpDir := t.TempDir()
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
			t.Fatalf("unexpected error: %v", err)
		}

		err = installer.Verify()
		if err == nil {
			t.Error("expected error for missing fips module")
		}
	})

	t.Run("missing fipsmodule.cnf", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     logger,
		}

		// Create fips module but not config
		fipsModulePath := filepath.Join(tmpDir, "usr", "lib", "ossl-modules")
		if err := os.MkdirAll(fipsModulePath, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		fipsModule := filepath.Join(fipsModulePath, "fips.so")
		if err := os.WriteFile(fipsModule, []byte("fake"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = installer.Verify()
		if err == nil {
			t.Error("expected error for missing fipsmodule.cnf")
		}
	})

	t.Run("missing openssl.cnf", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     logger,
		}

		// Create fips module and fipsmodule.cnf but not openssl.cnf
		fipsModulePath := filepath.Join(tmpDir, "usr", "lib", "ossl-modules")
		if err := os.MkdirAll(fipsModulePath, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		sslDir := filepath.Join(tmpDir, "etc", "ssl")
		if err := os.MkdirAll(sslDir, 0755); err != nil {
			t.Fatalf("failed to create ssl dir: %v", err)
		}

		fipsModule := filepath.Join(fipsModulePath, "fips.so")
		if err := os.WriteFile(fipsModule, []byte("fake"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		fipsConfig := filepath.Join(sslDir, "fipsmodule.cnf")
		if err := os.WriteFile(fipsConfig, []byte("[fips_sect]"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = installer.Verify()
		if err == nil {
			t.Error("expected error for missing openssl.cnf")
		}
	})

	t.Run("openssl.cnf without fips_sect", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     logger,
		}

		// Create all files but openssl.cnf without fips_sect
		fipsModulePath := filepath.Join(tmpDir, "usr", "lib", "ossl-modules")
		if err := os.MkdirAll(fipsModulePath, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		sslDir := filepath.Join(tmpDir, "etc", "ssl")
		if err := os.MkdirAll(sslDir, 0755); err != nil {
			t.Fatalf("failed to create ssl dir: %v", err)
		}

		fipsModule := filepath.Join(fipsModulePath, "fips.so")
		if err := os.WriteFile(fipsModule, []byte("fake"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		fipsConfig := filepath.Join(sslDir, "fipsmodule.cnf")
		if err := os.WriteFile(fipsConfig, []byte("[fips_sect]"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		opensslConfig := filepath.Join(sslDir, "openssl.cnf")
		// Note: no fips_sect reference
		if err := os.WriteFile(opensslConfig, []byte("[default]\nopenssl_conf = default"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = installer.Verify()
		if err == nil {
			t.Error("expected error for openssl.cnf without fips_sect")
		}
	})
}

func TestFIPSInstaller_updateOpenSSLConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("backup and replace existing config", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     logger,
		}

		// Create original openssl.cnf
		sslDir := filepath.Join(tmpDir, "etc", "ssl")
		if err := os.MkdirAll(sslDir, 0755); err != nil {
			t.Fatalf("failed to create ssl dir: %v", err)
		}

		opensslConfig := filepath.Join(sslDir, "openssl.cnf")
		originalContent := "# Original OpenSSL config\n[default]"
		if err := os.WriteFile(opensslConfig, []byte(originalContent), 0644); err != nil {
			t.Fatalf("failed to create original config: %v", err)
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.updateOpenSSLConfig()
		if err != nil {
			t.Fatalf("updateOpenSSLConfig failed: %v", err)
		}

		// Check backup was created
		backupPath := opensslConfig + ".backup"
		backupContent, err := os.ReadFile(backupPath)
		if err != nil {
			t.Fatalf("failed to read backup: %v", err)
		}
		if string(backupContent) != originalContent {
			t.Error("backup content doesn't match original")
		}

		// Check new config has FIPS settings
		newContent, err := os.ReadFile(opensslConfig)
		if err != nil {
			t.Fatalf("failed to read new config: %v", err)
		}
		if string(newContent) == originalContent {
			t.Error("config was not replaced")
		}
		if !containsAll(string(newContent), "fips_sect", "fipsmodule.cnf", "provider_sect") {
			t.Error("new config missing expected FIPS settings")
		}
	})

	t.Run("create new config if none exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     logger,
		}

		// Create ssl directory but no openssl.cnf
		sslDir := filepath.Join(tmpDir, "etc", "ssl")
		if err := os.MkdirAll(sslDir, 0755); err != nil {
			t.Fatalf("failed to create ssl dir: %v", err)
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.updateOpenSSLConfig()
		if err != nil {
			t.Fatalf("updateOpenSSLConfig failed: %v", err)
		}

		// Config should be created
		opensslConfig := filepath.Join(sslDir, "openssl.cnf")
		if _, err := os.Stat(opensslConfig); os.IsNotExist(err) {
			t.Error("openssl.cnf was not created")
		}

		// No backup should exist (nothing to backup)
		backupPath := opensslConfig + ".backup"
		if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
			t.Error("backup should not exist when there was no original file")
		}
	})

	t.Run("fail on missing directory", func(t *testing.T) {
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    "/nonexistent",
			MountPoint: "/nonexistent",
			Logger:     logger,
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.updateOpenSSLConfig()
		if err == nil {
			t.Error("expected error for nonexistent directory")
		}
	})
}

func TestFIPSInstaller_configureOpenSSLFIPS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("requires fips module to exist", func(t *testing.T) {
		tmpDir := t.TempDir()
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
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		// configureOpenSSLFIPS calls generateFIPSModuleConfig which requires fips.so
		err = fipsInstaller.configureOpenSSLFIPS()
		if err == nil {
			t.Error("expected error when fips module doesn't exist")
		}
	})
}

func TestFIPSInstaller_generateFIPSModuleConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("missing fips module", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    tmpDir,
			MountPoint: tmpDir,
			Logger:     logger,
		}

		// Create ssl directory but no fips module
		sslDir := filepath.Join(tmpDir, "etc", "ssl")
		if err := os.MkdirAll(sslDir, 0755); err != nil {
			t.Fatalf("failed to create ssl dir: %v", err)
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.generateFIPSModuleConfig()
		if err == nil {
			t.Error("expected error for missing fips module")
		}
	})

	t.Run("missing ssl directory", func(t *testing.T) {
		config := &fips.Config{
			OS:         "alpine",
			Version:    "3.20",
			Arch:       "x86_64",
			WorkDir:    "/nonexistent",
			MountPoint: "/nonexistent",
			Logger:     logger,
		}

		installer, err := NewFIPSInstaller(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.generateFIPSModuleConfig()
		if err == nil {
			t.Error("expected error for nonexistent directory")
		}
	})
}

func TestFIPSInstaller_Install(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("missing FIPS artifacts", func(t *testing.T) {
		tmpDir := t.TempDir()
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
			t.Fatalf("unexpected error: %v", err)
		}

		// Should fail because /media/cdrom/fips-artifacts doesn't exist
		err = installer.Install(context.Background())
		if err == nil {
			t.Error("expected error when FIPS artifacts don't exist")
		}
	})
}

func TestFIPSInstaller_InstallKernel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("missing FIPS artifacts", func(t *testing.T) {
		tmpDir := t.TempDir()
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
			t.Fatalf("unexpected error: %v", err)
		}

		// Should fail because /media/cdrom/fips-artifacts doesn't exist
		err = installer.InstallKernel(context.Background())
		if err == nil {
			t.Error("expected error when FIPS artifacts don't exist")
		}
	})
}

func TestFIPSInstaller_ConfigureOpenSSL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("missing FIPS artifacts", func(t *testing.T) {
		tmpDir := t.TempDir()
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
			t.Fatalf("unexpected error: %v", err)
		}

		// Should fail because /media/cdrom/fips-artifacts doesn't exist
		err = installer.ConfigureOpenSSL(context.Background())
		if err == nil {
			t.Error("expected error when FIPS artifacts don't exist")
		}
	})
}

func TestFIPSInstaller_installFIPSKernel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("missing artifacts directory", func(t *testing.T) {
		tmpDir := t.TempDir()
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
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.installFIPSKernel(context.Background())
		if err == nil {
			t.Error("expected error for missing FIPS artifacts")
		}
		if err != nil && !containsString(err.Error(), "FIPS artifacts not found") {
			t.Errorf("expected 'FIPS artifacts not found' in error, got: %v", err)
		}
	})
}

func TestFIPSInstaller_installOpenSSLFIPS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("missing artifacts directory", func(t *testing.T) {
		tmpDir := t.TempDir()
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
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.installOpenSSLFIPS(context.Background())
		if err == nil {
			t.Error("expected error for missing FIPS provider module")
		}
		// The function tries to run chroot first, which will fail in tests
		// Just verify it returns an error
	})
}

// closedMirror returns the URL of a mirror that has stopped listening, so
// a download fails at connect on loopback instead of in a host DNS lookup.
func closedMirror(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	return srv.URL
}

func TestFIPSInstaller_installPackage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("invalid package name causes download failure", func(t *testing.T) {
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
			t.Fatalf("unexpected error: %v", err)
		}

		fipsInstaller := installer.(*FIPSInstaller)
		err = fipsInstaller.installPackage(context.Background(), "nonexistent-package")
		if err == nil {
			t.Error("expected error for package installation failure")
		}
	})
}

// Helper function to check if string contains all substrings
func containsAll(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if !containsString(s, substr) {
			return false
		}
	}
	return true
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestFIPSInstaller_installPackage_Success installs a package from a local
// mirror and checks that it lands in the target root.
func TestFIPSInstaller_installPackage_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tmpDir := t.TempDir()

	// Lay out a local mirror the way APKManager addresses it:
	// <mirror>/v<version>/<repo>/<arch>/{APKINDEX.tar.gz,<name>-<version>.apk}
	repoDir := filepath.Join(tmpDir, "mirror", "v3.20", "main", "x86_64")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create mirror repo dir: %v", err)
	}
	index := "P:openssl-fips\nV:3.1.2-r0\nA:x86_64\nC:Q1testchecksum\n\n"
	if err := createTestAPKINDEX(filepath.Join(repoDir, "APKINDEX.tar.gz"), index); err != nil {
		t.Fatalf("failed to create APKINDEX: %v", err)
	}
	pkg := map[string]testEntry{
		"usr/":                      {isDir: true},
		"usr/lib/":                  {isDir: true},
		"usr/lib/ossl-modules/":     {isDir: true},
		"usr/lib/ossl-modules/x.so": {content: "provider"},
	}
	if err := createTestAPK(filepath.Join(repoDir, "openssl-fips-3.1.2-r0.apk"), pkg); err != nil {
		t.Fatalf("failed to create apk: %v", err)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(tmpDir, "mirror"))))
	defer server.Close()

	workDir := filepath.Join(tmpDir, "work")
	mountPoint := filepath.Join(tmpDir, "mnt")
	for _, dir := range []string{workDir, mountPoint} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create %s: %v", dir, err)
		}
	}
	installer, err := NewFIPSInstaller(&fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		Mirror:     server.URL,
		WorkDir:    workDir,
		MountPoint: mountPoint,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}

	if err := installer.(*FIPSInstaller).installPackage(context.Background(), "openssl-fips"); err != nil {
		t.Fatalf("installPackage: %v", err)
	}

	// The package must land in the target root, not the work directory.
	got, err := os.ReadFile(filepath.Join(mountPoint, "usr", "lib", "ossl-modules", "x.so"))
	if err != nil {
		t.Fatalf("package file not installed into mount point: %v", err)
	}
	if string(got) != "provider" {
		t.Errorf("installed file content = %q, want %q", got, "provider")
	}
}

// TestFIPSInstaller_installFIPSKernel_ReadDirFailure covers a modules archive
// without lib/modules: nothing to run depmod against, so the install still
// succeeds and the skipped depmod is logged.
func TestFIPSInstaller_installFIPSKernel_ReadDirFailure(t *testing.T) {
	installer, mountPoint, logs := newKernelTestInstaller(t, func(path string) error {
		return createTestAPK(path, map[string]testEntry{"boot/": {isDir: true}})
	})

	if err := installer.installFIPSKernel(context.Background()); err != nil {
		t.Fatalf("installFIPSKernel: %v", err)
	}

	if _, err := os.Stat(filepath.Join(mountPoint, "boot", "vmlinuz-fips")); err != nil {
		t.Errorf("kernel not copied into boot directory: %v", err)
	}
	if !containsString(logs.String(), "Could not read modules directory to run depmod") {
		t.Errorf("expected a ReadDir warning in the log, got: %s", logs.String())
	}
}

// TestFIPSInstaller_installFIPSKernel_DepmodWarning covers a failed depmod.
// The extracted root has lib/modules/6.1.0-fips but no depmod binary, so
// `chroot <root> depmod` fails for any user. depmod is not fatal: the install
// succeeds and the failure is logged.
func TestFIPSInstaller_installFIPSKernel_DepmodWarning(t *testing.T) {
	installer, mountPoint, logs := newKernelTestInstaller(t, createMockModulesArchive)

	if err := installer.installFIPSKernel(context.Background()); err != nil {
		t.Fatalf("installFIPSKernel: %v", err)
	}

	module := filepath.Join(mountPoint, "lib", "modules", "6.1.0-fips", "kernel", "crypto", "sha256.ko")
	if _, err := os.Stat(module); err != nil {
		t.Errorf("kernel modules not extracted: %v", err)
	}
	if !containsString(logs.String(), "depmod failed (may not be critical)") {
		t.Errorf("expected a depmod warning in the log, got: %s", logs.String())
	}
}

// newKernelTestInstaller returns an installer whose FIPS artifacts directory
// holds a kernel and a modules archive written by writeModules, the mount
// point it installs into, and the buffer its log is written to.
func newKernelTestInstaller(t *testing.T, writeModules func(path string) error) (*FIPSInstaller, string, *bytes.Buffer) {
	t.Helper()
	tmpDir := t.TempDir()

	artifactsDir := filepath.Join(tmpDir, "fips-artifacts")
	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		t.Fatalf("failed to create artifacts dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "vmlinuz-fips"), []byte("mock kernel"), 0644); err != nil {
		t.Fatalf("failed to create mock kernel: %v", err)
	}
	if err := writeModules(filepath.Join(artifactsDir, "modules-fips.tar.gz")); err != nil {
		t.Fatalf("failed to create modules archive: %v", err)
	}

	mountPoint := filepath.Join(tmpDir, "mnt")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("failed to create mount point: %v", err)
	}

	logs := &bytes.Buffer{}
	installer, err := NewFIPSInstaller(&fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: mountPoint,
		Logger:     slog.New(slog.NewTextHandler(logs, nil)),
	})
	if err != nil {
		t.Fatalf("failed to create installer: %v", err)
	}
	fipsInstaller := installer.(*FIPSInstaller)
	fipsInstaller.artifactsDir = artifactsDir
	return fipsInstaller, mountPoint, logs
}

// createMockModulesArchive writes a modules-fips.tar.gz holding one module
// under lib/modules/6.1.0-fips.
func createMockModulesArchive(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gzw := gzip.NewWriter(f)
	defer func() { _ = gzw.Close() }()

	tw := tar.NewWriter(gzw)
	defer func() { _ = tw.Close() }()

	entries := []struct {
		name    string
		isDir   bool
		content string
	}{
		{"lib/", true, ""},
		{"lib/modules/", true, ""},
		{"lib/modules/6.1.0-fips/", true, ""},
		{"lib/modules/6.1.0-fips/kernel/", true, ""},
		{"lib/modules/6.1.0-fips/kernel/crypto/", true, ""},
		{"lib/modules/6.1.0-fips/kernel/crypto/sha256.ko", false, "mock kernel module"},
	}

	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0644,
			Size:     int64(len(entry.content)),
			Typeflag: tar.TypeReg,
		}
		if entry.isDir {
			hdr.Mode = 0755
			hdr.Typeflag = tar.TypeDir
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(entry.content)); err != nil {
			return err
		}
	}

	return nil
}

func TestFIPSInstaller_Registration(t *testing.T) {
	// The init() function in fips.go registers the Alpine installer
	// We can verify this by creating an installer through the fips package

	tmpDir := t.TempDir()
	config := &fips.Config{
		OS:         "alpine",
		Version:    "3.20",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: tmpDir,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// This should work because Alpine installer was registered via init()
	installer, err := fips.NewInstaller(config)
	if err != nil {
		t.Fatalf("failed to create installer through fips package: %v", err)
	}
	if installer == nil {
		t.Fatal("expected installer to be non-nil")
	}

	// Verify it's the Alpine installer
	cmdline := installer.GetKernelCommandLine()
	if cmdline != "fips=1" {
		t.Errorf("expected 'fips=1', got '%s'", cmdline)
	}
}

func TestFIPSInstaller_UnregisteredOS(t *testing.T) {
	tmpDir := t.TempDir()
	config := &fips.Config{
		OS:         "unsupported-os",
		Version:    "1.0",
		Arch:       "x86_64",
		WorkDir:    tmpDir,
		MountPoint: tmpDir,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	_, err := fips.NewInstaller(config)
	if err == nil {
		t.Error("expected error for unsupported OS")
	}
}
