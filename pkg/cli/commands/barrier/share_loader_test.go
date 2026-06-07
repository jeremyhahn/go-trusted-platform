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

package barrier

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveShares_FromFlags(t *testing.T) {
	got, err := resolveShares(nil, &unsealSharesFlags{shares: []string{"s1", "s2"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "s1" || got[1] != "s2" {
		t.Errorf("unexpected shares: %v", got)
	}
}

func TestResolveShares_MissingShares(t *testing.T) {
	_, err := resolveShares(nil, &unsealSharesFlags{})
	if _, ok := err.(ErrMissingShares); !ok {
		t.Errorf("expected ErrMissingShares, got %T: %v", err, err)
	}
}

func TestResolveShares_ConflictBothSources(t *testing.T) {
	_, err := resolveShares(nil, &unsealSharesFlags{
		shares:     []string{"s1"},
		sharesFile: "/tmp/x",
	})
	if _, ok := err.(ErrShareSourcesConflict); !ok {
		t.Errorf("expected ErrShareSourcesConflict, got %T: %v", err, err)
	}
}

func TestResolveShares_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shares.txt")
	content := "share-1\n\nshare-2\n   share-3   \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write tmp shares: %v", err)
	}
	got, err := resolveShares(nil, &unsealSharesFlags{sharesFile: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"share-1", "share-2", "share-3"}
	if len(got) != len(want) {
		t.Fatalf("expected %d shares, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("share[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestResolveShares_FromStdin(t *testing.T) {
	stdin := strings.NewReader("share-1\nshare-2\n")
	got, err := resolveShares(stdin, &unsealSharesFlags{sharesFile: "-"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "share-1" || got[1] != "share-2" {
		t.Errorf("unexpected shares: %v", got)
	}
}

func TestResolveShares_FileMissing(t *testing.T) {
	_, err := resolveShares(nil, &unsealSharesFlags{sharesFile: "/nonexistent/path/shares.txt"})
	if _, ok := err.(ErrSharesFileReadFailed); !ok {
		t.Errorf("expected ErrSharesFileReadFailed, got %T: %v", err, err)
	}
}

func TestResolveShares_EmptyFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("\n\n   \n"), 0o600); err != nil {
		t.Fatalf("write tmp shares: %v", err)
	}
	_, err := resolveShares(nil, &unsealSharesFlags{sharesFile: path})
	if _, ok := err.(ErrMissingShares); !ok {
		t.Errorf("expected ErrMissingShares for empty file, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// confirmSeal
// ---------------------------------------------------------------------------

func TestConfirmSeal_Yes(t *testing.T) {
	for _, input := range []string{"y\n", "Y\n", "yes\n", "YES\n", "  yes  \n"} {
		stdin := strings.NewReader(input)
		stdout := &bytes.Buffer{}
		ok, err := confirmSeal(stdin, stdout)
		if err != nil {
			t.Fatalf("input %q: %v", input, err)
		}
		if !ok {
			t.Errorf("input %q: expected confirmation", input)
		}
	}
}

func TestConfirmSeal_No(t *testing.T) {
	for _, input := range []string{"n\n", "no\n", "\n", "anything else\n"} {
		stdin := strings.NewReader(input)
		stdout := &bytes.Buffer{}
		ok, err := confirmSeal(stdin, stdout)
		if err != nil {
			t.Fatalf("input %q: %v", input, err)
		}
		if ok {
			t.Errorf("input %q: expected decline", input)
		}
	}
}

func TestConfirmSeal_EOF(t *testing.T) {
	stdin := strings.NewReader("")
	stdout := &bytes.Buffer{}
	ok, err := confirmSeal(stdin, stdout)
	if err != nil {
		t.Fatalf("unexpected EOF error: %v", err)
	}
	if ok {
		t.Error("EOF without input must decline")
	}
}

// failingWriter returns an error from every Write call.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errStubWriteFail }

var errStubWriteFail = errors.New("stub write fail")

func TestConfirmSeal_WriteError(t *testing.T) {
	stdin := strings.NewReader("y\n")
	_, err := confirmSeal(stdin, failingWriter{})
	if !errors.Is(err, errStubWriteFail) {
		t.Errorf("expected stub write error, got %v", err)
	}
}

// failingReader returns an error from every Read call.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errStubReadFail }

var errStubReadFail = errors.New("stub read fail")

func TestConfirmSeal_ReadError(t *testing.T) {
	out := &bytes.Buffer{}
	_, err := confirmSeal(failingReader{}, out)
	if !errors.Is(err, errStubReadFail) {
		t.Errorf("expected stub read error, got %v", err)
	}
}
