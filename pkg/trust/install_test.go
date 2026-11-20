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

package trust

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallToSystemTrust(t *testing.T) {
	bundle := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
	certPath := filepath.Join(t.TempDir(), "nested", "dir", "ca.crt")

	if err := InstallToSystemTrust(bundle, certPath); err != nil {
		t.Fatal(err)
	}

	written, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, bundle) {
		t.Error("written bundle does not match input")
	}
}

func TestInstallToSystemTrust_EmptyBundle(t *testing.T) {
	err := InstallToSystemTrust(nil, filepath.Join(t.TempDir(), "ca.crt"))
	if !errors.Is(err, ErrCABundleEmpty{}) {
		t.Fatalf("expected ErrCABundleEmpty, got %v", err)
	}
}

func TestInstallToSystemTrust_WriteFailure(t *testing.T) {
	// Using a regular file as the parent directory forces MkdirAll
	// to fail.
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	err := InstallToSystemTrust([]byte("bundle"), filepath.Join(parent, "sub", "ca.crt"))
	var writeErr *ErrWriteFailed
	if !errors.As(err, &writeErr) {
		t.Fatalf("expected ErrWriteFailed, got %v", err)
	}
}

func TestUninstallFromSystemTrust(t *testing.T) {
	bundle := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
	certPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := InstallToSystemTrust(bundle, certPath); err != nil {
		t.Fatal(err)
	}

	removed, err := UninstallFromSystemTrust(certPath, []byte("other"), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("expected the installed bundle to be removed")
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Errorf("bundle still present: %v", err)
	}
}

func TestUninstallFromSystemTrust_NothingInstalled(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "ca.crt")

	removed, err := UninstallFromSystemTrust(certPath, []byte("bundle"))
	if err != nil {
		t.Fatalf("missing file: expected nil error, got %v", err)
	}
	if removed {
		t.Error("missing file reported as removed")
	}
}

func TestUninstallFromSystemTrust_RefusesAnotherBundle(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "ca.crt")
	other := []byte("-----BEGIN CERTIFICATE-----\nother\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(certPath, other, 0o644); err != nil {
		t.Fatal(err)
	}

	removed, err := UninstallFromSystemTrust(certPath, []byte("mine"))
	var mismatch ErrSystemTrustBundleMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrSystemTrustBundleMismatch, got %v", err)
	}
	if mismatch.Path != certPath {
		t.Errorf("mismatch path = %q, want %q", mismatch.Path, certPath)
	}
	if removed {
		t.Error("a foreign bundle was reported as removed")
	}
	kept, readErr := os.ReadFile(certPath)
	if readErr != nil || !bytes.Equal(kept, other) {
		t.Errorf("foreign bundle not kept: %v", readErr)
	}
}
