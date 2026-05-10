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
	"errors"
	"os"
	"testing"
)

func TestNewSSHExecutor_NilConfig(t *testing.T) {
	executor, err := NewSSHExecutor(nil)
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
		Host:   "10.0.0.1",
		Port:   22,
		User:   "admin",
		SSHKey: "/nonexistent/path/to/key",
	}
	executor, err := NewSSHExecutor(config)
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
	tmpFile := t.TempDir() + "/bad_key"
	if err := os.WriteFile(tmpFile, []byte("not-a-valid-key"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	config := &Config{
		Host:   "10.0.0.1",
		Port:   22,
		User:   "admin",
		SSHKey: tmpFile,
	}
	executor, err := NewSSHExecutor(config)
	if executor != nil {
		t.Fatal("expected nil executor for invalid key content")
	}
	var connErr ErrSSHConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("expected ErrSSHConnectionFailed, got: %T %v", err, err)
	}
}
