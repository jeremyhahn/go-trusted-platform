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

package secrets

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestFileResolver_Scheme(t *testing.T) {
	r := NewFileResolver(nil)
	if got := r.Scheme(); got != SchemeFile {
		t.Errorf("expected scheme %q, got %q", SchemeFile, got)
	}
}

func TestFileResolver_CanResolve(t *testing.T) {
	r := NewFileResolver(slog.New(slog.DiscardHandler))

	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"file URI", "file:///etc/secret", true},
		{"file URI uppercase scheme", "FILE:///etc/secret", true},
		{"relative file URI", "file://secret.txt", true},
		{"kms URI", "kms://bmc/password", false},
		{"idevid URI", "idevid://abcdef", false},
		{"plain text", "/etc/secret", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.CanResolve(tt.raw); got != tt.want {
				t.Errorf("CanResolve(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestFileResolver_Resolve_Success verifies the happy path: a file:// URI
// pointing at a readable file yields the file's raw bytes as the secret value.
func TestFileResolver_Resolve_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	want := []byte("super-secret-password\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	r := NewFileResolver(slog.New(slog.DiscardHandler))
	value, err := r.Resolve(context.Background(), SchemeFileURIPrefix+path)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if value == nil {
		t.Fatal("Resolve returned nil value")
	}
	if string(value.Bytes()) != string(want) {
		t.Errorf("Resolve value = %q, want %q", value.Bytes(), want)
	}
}

// TestFileResolver_Resolve_MissingFile verifies that a missing file surfaces a
// typed ErrFileReadFailed wrapping the underlying os error.
func TestFileResolver_Resolve_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist")

	r := NewFileResolver(nil)
	_, err := r.Resolve(context.Background(), SchemeFileURIPrefix+path)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	var readErr ErrFileReadFailed
	if !errors.As(err, &readErr) {
		t.Fatalf("expected ErrFileReadFailed, got %T: %v", err, err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected wrapped os.ErrNotExist, got %v", err)
	}
}

func TestFileResolver_Resolve_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	r := NewFileResolver(nil)
	_, err := r.Resolve(context.Background(), SchemeFileURIPrefix+path)
	var emptyErr ErrFileEmpty
	if !errors.As(err, &emptyErr) {
		t.Fatalf("expected ErrFileEmpty, got %T: %v", err, err)
	}
}

func TestFileResolver_Resolve_InvalidScheme(t *testing.T) {
	r := NewFileResolver(nil)
	_, err := r.Resolve(context.Background(), "kms://bmc/password")
	var invalid ErrInvalidFileURI
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidFileURI, got %T: %v", err, err)
	}
}

func TestFileResolver_Resolve_EmptyPath(t *testing.T) {
	r := NewFileResolver(nil)
	_, err := r.Resolve(context.Background(), SchemeFileURIPrefix)
	var invalid ErrInvalidFileURI
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidFileURI, got %T: %v", err, err)
	}
}

func TestFileResolver_Resolve_ContextCanceled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := NewFileResolver(nil)
	_, err := r.Resolve(ctx, SchemeFileURIPrefix+path)
	var canceled ErrContextCanceled
	if !errors.As(err, &canceled) {
		t.Fatalf("expected ErrContextCanceled, got %T: %v", err, err)
	}
}
