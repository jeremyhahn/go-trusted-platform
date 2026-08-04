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

package switchmgmt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeTestSSHKey generates an unencrypted ed25519 private key in PKCS#8 PEM
// form, writes it to a temp file, and returns the path. The key is valid
// enough for keys.ParsePEM, letting tests reach the post-precondition code
// paths without any network I/O.
func writeTestSSHKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestNewSSHExecutor_NilConfig(t *testing.T) {
	executor, err := NewSSHExecutor(context.Background(), nil)
	if executor != nil {
		t.Fatal("expected nil executor for nil config")
	}
	var nilCfg ErrNilConfig
	if !errors.As(err, &nilCfg) {
		t.Fatalf("expected ErrNilConfig, got: %T %v", err, err)
	}
}

func TestNewSSHExecutor_MissingKeyFile(t *testing.T) {
	config := &Config{
		Host:           "10.0.0.1",
		Port:           22,
		User:           "admin",
		SSHKey:         "/nonexistent/path/to/key",
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
	}
	executor, err := NewSSHExecutor(context.Background(), config)
	if executor != nil {
		t.Fatal("expected nil executor for missing key file")
	}
	var connErr ErrSSHConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("expected ErrSSHConnectionFailed, got: %T %v", err, err)
	}
	if connErr.Host != "10.0.0.1" {
		t.Fatalf("expected host '10.0.0.1', got: %s", connErr.Host)
	}
}

func TestNewSSHExecutor_InvalidKeyContent(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad_key")
	if err := os.WriteFile(tmpFile, []byte("not-a-valid-key"), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	config := &Config{
		Host:           "10.0.0.1",
		Port:           22,
		User:           "admin",
		SSHKey:         tmpFile,
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
	}
	executor, err := NewSSHExecutor(context.Background(), config)
	if executor != nil {
		t.Fatal("expected nil executor for invalid key content")
	}
	var connErr ErrSSHConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("expected ErrSSHConnectionFailed, got: %T %v", err, err)
	}
}

// TestNewSSHExecutor_MissingKnownHostsPath locks in the fail-closed posture
// that replaced trust-on-first-use: even with a fully valid private key,
// an executor cannot be built without a pinned host-key store, and the
// rejection happens before any network I/O.
func TestNewSSHExecutor_MissingKnownHostsPath(t *testing.T) {
	config := &Config{
		Host:   "10.0.0.1",
		Port:   22,
		User:   "admin",
		SSHKey: writeTestSSHKey(t),
		// KnownHostsPath intentionally empty.
	}
	executor, err := NewSSHExecutor(context.Background(), config)
	if executor != nil {
		t.Fatal("expected nil executor when no known-hosts pin is provisioned")
	}
	var connErr ErrSSHConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("expected ErrSSHConnectionFailed, got: %T %v", err, err)
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected wrapped ErrInvalidConfig, got: %T %v", err, err)
	}
	if invalidCfg.Field != "known_hosts_path" {
		t.Fatalf("expected field 'known_hosts_path', got: %s", invalidCfg.Field)
	}
}
