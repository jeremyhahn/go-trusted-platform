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

package memguard

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCredential drops a file with 0600 permissions, the mode a key
// bundle actually carries on a node.
func writeCredential(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestNewMemoryEnclaveFromFile_HoldsTheFileContent(t *testing.T) {
	content := []byte("-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n")
	path := writeCredential(t, "admin.key", content)

	enclave, err := NewMemoryEnclaveFromFile(path)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromFile: %v", err)
	}
	defer enclave.Destroy()

	if !enclave.IsAlive() {
		t.Fatal("enclave is not alive")
	}
	if got := enclave.Size(); got != len(content) {
		t.Errorf("Size() = %d, want %d", got, len(content))
	}
	if !bytes.Equal(enclave.Bytes(), content) {
		t.Errorf("Bytes() = %q, want %q", enclave.Bytes(), content)
	}
}

// The value must be redacted like any other enclave — a key read from a
// file must not become loggable just because it came from disk.
func TestNewMemoryEnclaveFromFile_RedactsOnRender(t *testing.T) {
	path := writeCredential(t, "admin.key", []byte("top-secret-pem"))

	enclave, err := NewMemoryEnclaveFromFile(path)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromFile: %v", err)
	}
	defer enclave.Destroy()

	if got := enclave.String(); got != redactedPlaceholder {
		t.Errorf("String() = %q, want %q", got, redactedPlaceholder)
	}
	if strings.Contains(enclave.String(), "top-secret") {
		t.Error("String() leaked the file content")
	}
}

func TestNewMemoryEnclaveFromFile_ReadsTheExactByteRange(t *testing.T) {
	// A file whose size is not a round number, to catch an off-by-one in
	// the size-exact allocation.
	content := []byte("abcdefghijklmnopq")
	path := writeCredential(t, "odd.key", content)

	enclave, err := NewMemoryEnclaveFromFile(path)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromFile: %v", err)
	}
	defer enclave.Destroy()

	if got := string(enclave.Bytes()); got != string(content) {
		t.Errorf("Bytes() = %q, want %q", got, content)
	}
}

func TestNewMemoryEnclaveFromFile_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.key")

	enclave, err := NewMemoryEnclaveFromFile(path)
	if err == nil {
		enclave.Destroy()
		t.Fatal("expected an error for a missing file")
	}
	var unreadable ErrFileUnreadable
	if !errors.As(err, &unreadable) {
		t.Fatalf("error = %T (%v), want ErrFileUnreadable", err, err)
	}
	if unreadable.Path != path {
		t.Errorf("Path = %q, want %q", unreadable.Path, path)
	}
	if enclave != nil {
		t.Error("expected a nil enclave on failure")
	}
}

// An empty credential file is a deployment fault, not an empty secret: a
// live zero-length enclave here would let a caller proceed with no key.
func TestNewMemoryEnclaveFromFile_EmptyFile(t *testing.T) {
	path := writeCredential(t, "empty.key", nil)

	if _, err := NewMemoryEnclaveFromFile(path); err == nil {
		t.Fatal("expected an error for an empty file")
	} else if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %v, want it to name the empty file", err)
	}
}

func TestNewMemoryEnclaveFromFile_Directory(t *testing.T) {
	dir := t.TempDir()

	if _, err := NewMemoryEnclaveFromFile(dir); err == nil {
		t.Fatal("expected an error for a directory")
	} else if !strings.Contains(err.Error(), "regular") {
		t.Errorf("error = %v, want it to report a non-regular file", err)
	}
}

func TestNewMemoryEnclaveFromFile_AboveTheLockedMemoryLimit(t *testing.T) {
	path := writeCredential(t, "huge.key", bytes.Repeat([]byte("x"), MaxFileSize+1))

	enclave, err := NewMemoryEnclaveFromFile(path)
	if err == nil {
		enclave.Destroy()
		t.Fatal("expected an error above MaxFileSize")
	}
	var tooLarge ErrFileTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("error = %T (%v), want ErrFileTooLarge", err, err)
	}
	if tooLarge.Limit != MaxFileSize {
		t.Errorf("Limit = %d, want %d", tooLarge.Limit, MaxFileSize)
	}
	if tooLarge.Size != int64(MaxFileSize+1) {
		t.Errorf("Size = %d, want %d", tooLarge.Size, MaxFileSize+1)
	}
}

// Exactly at the limit is accepted; the bound is inclusive.
func TestNewMemoryEnclaveFromFile_AtTheLockedMemoryLimit(t *testing.T) {
	path := writeCredential(t, "atlimit.key", bytes.Repeat([]byte("x"), MaxFileSize))

	enclave, err := NewMemoryEnclaveFromFile(path)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromFile at the limit: %v", err)
	}
	defer enclave.Destroy()

	if got := enclave.Size(); got != MaxFileSize {
		t.Errorf("Size() = %d, want %d", got, MaxFileSize)
	}
}

func TestErrFileMessages(t *testing.T) {
	unreadable := ErrFileUnreadable{Path: "/var/lib/x/admin.key", Reason: "permission denied"}
	if !strings.Contains(unreadable.Error(), "/var/lib/x/admin.key") ||
		!strings.Contains(unreadable.Error(), "permission denied") {
		t.Errorf("ErrFileUnreadable.Error() = %q", unreadable.Error())
	}

	tooLarge := ErrFileTooLarge{Path: "/var/lib/x/admin.key", Size: 4096, Limit: 1024}
	for _, want := range []string{"/var/lib/x/admin.key", "4096", "1024"} {
		if !strings.Contains(tooLarge.Error(), want) {
			t.Errorf("ErrFileTooLarge.Error() = %q, want it to contain %q", tooLarge.Error(), want)
		}
	}
}
