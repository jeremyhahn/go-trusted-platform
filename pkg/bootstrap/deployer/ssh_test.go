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

package deployer

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
	"time"
)

// generateTestKey generates an unencrypted ed25519 private key in PKCS#8 PEM
// form and writes it to path. The key is valid enough for keys.ParsePEM,
// letting Connect tests reach the post-key-load code paths without any
// network I/O.
func generateTestKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal pkcs8 key: %v", err)
	}
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, keyBytes, 0o600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}
}

// knownHostsPath returns a usable known_hosts pin path rooted in a temp
// directory. NewSSHClient only checks the path is non-empty; Connect roots a
// file-backed store in its parent directory.
func knownHostsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "known_hosts")
}

func TestNewSSHClient_MissingHost(t *testing.T) {
	_, err := NewSSHClient("", 22, "root", "/key", knownHostsPath(t))
	var target ErrInvalidDeployConfig
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrInvalidDeployConfig, got %T: %v", err, err)
	}
	if target.Field != "host" {
		t.Errorf("expected field host, got %q", target.Field)
	}
}

func TestNewSSHClient_MissingUser(t *testing.T) {
	_, err := NewSSHClient("h", 22, "", "/key", knownHostsPath(t))
	var target ErrInvalidDeployConfig
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrInvalidDeployConfig, got %T: %v", err, err)
	}
	if target.Field != "user" {
		t.Errorf("expected field user, got %q", target.Field)
	}
}

func TestNewSSHClient_MissingKeyPath(t *testing.T) {
	_, err := NewSSHClient("h", 22, "root", "", knownHostsPath(t))
	var target ErrInvalidDeployConfig
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrInvalidDeployConfig, got %T: %v", err, err)
	}
	if target.Field != "ssh_key_path" {
		t.Errorf("expected field ssh_key_path, got %q", target.Field)
	}
}

// TestNewSSHClient_MissingKnownHostsPath locks in the fail-closed posture
// that replaced trust-on-first-use: even with valid connection details, a
// client cannot be built without a pinned host-key store, and the rejection
// happens before any network or key I/O.
func TestNewSSHClient_MissingKnownHostsPath(t *testing.T) {
	_, err := NewSSHClient("h", 22, "root", "/key", "")
	var target ErrInvalidDeployConfig
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrInvalidDeployConfig, got %T: %v", err, err)
	}
	if target.Field != "known_hosts_path" {
		t.Errorf("expected field known_hosts_path, got %q", target.Field)
	}
}

func TestNewSSHClient_ValidArgs(t *testing.T) {
	client, err := NewSSHClient("h", 0, "root", "/key", knownHostsPath(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.IsConnected() {
		t.Error("expected new client to not be connected")
	}
	// Port 0 should default to 22.
	if client.port != DefaultSSHPort {
		t.Errorf("expected port to default to %d, got %d", DefaultSSHPort, client.port)
	}
}

// TestSSHClient_Connect_MissingKey verifies key loading moved to Connect:
// a nonexistent key file surfaces ErrSSHKeyRead.
func TestSSHClient_Connect_MissingKey(t *testing.T) {
	client, err := NewSSHClient("192.0.2.1", 22, "root", "/nonexistent/key", knownHostsPath(t))
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	err = client.Connect(ctx)
	var target ErrSSHKeyRead
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSSHKeyRead, got %T: %v", err, err)
	}
}

// TestSSHClient_Connect_UnparseableKey verifies an unparseable key file
// surfaces ErrSSHKeyParse from Connect.
func TestSSHClient_Connect_UnparseableKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad_key")
	if err := os.WriteFile(keyPath, []byte("not a valid ssh key"), 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := NewSSHClient("192.0.2.1", 22, "root", keyPath, knownHostsPath(t))
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	err = client.Connect(ctx)
	var target ErrSSHKeyParse
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSSHKeyParse, got %T: %v", err, err)
	}
}

// TestSSHClient_Connect_Unreachable verifies that with a valid key and a
// pinned store, an unreachable host surfaces ErrSSHConnect (the dial fails
// at the TCP layer before host-key verification).
func TestSSHClient_Connect_Unreachable(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	generateTestKey(t, keyPath)

	client, err := NewSSHClient("192.0.2.1", 22, "root", keyPath, knownHostsPath(t))
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	// Short timeout so the test does not block on the unroutable address.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	t.Cleanup(cancel)

	err = client.Connect(ctx)
	if err == nil {
		client.Close()
		t.Fatal("expected error connecting to unreachable host")
	}
	var target ErrSSHConnect
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSSHConnect, got %T: %v", err, err)
	}
}

func TestSSHClient_Run_NotConnected(t *testing.T) {
	client, err := NewSSHClient("192.0.2.1", 22, "root", "/key", knownHostsPath(t))
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	_, err = client.Run(context.Background(), "echo hello")
	var target ErrSSHNotConnected
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSSHNotConnected, got %T: %v", err, err)
	}
}

func TestSSHClient_CopyFileStream_NotConnected(t *testing.T) {
	client, err := NewSSHClient("192.0.2.1", 22, "root", "/key", knownHostsPath(t))
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	err = client.CopyFileStream(context.Background(), "/tmp/local", "/tmp/remote")
	var target ErrSSHNotConnected
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSSHNotConnected, got %T: %v", err, err)
	}
}

func TestSSHClient_IsConnected_Default(t *testing.T) {
	client, err := NewSSHClient("192.0.2.1", 22, "root", "/key", knownHostsPath(t))
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}
	if client.IsConnected() {
		t.Error("expected new client to not be connected")
	}
}

func TestSSHClient_Close_NotConnected(t *testing.T) {
	client, err := NewSSHClient("192.0.2.1", 22, "root", "/key", knownHostsPath(t))
	if err != nil {
		t.Fatalf("NewSSHClient failed: %v", err)
	}

	// Close on a non-connected client should not error.
	if err := client.Close(); err != nil {
		t.Errorf("expected no error closing non-connected client, got %v", err)
	}
}
