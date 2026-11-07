package artifacts

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBuild(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var sums string
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		sums += hex.EncodeToString(sum[:]) + "  ./" + name + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVerifyChecksums_Passes(t *testing.T) {
	dir := writeBuild(t, map[string]string{"vmlinuz": "kernel", "sub/modules.tar.gz": "modules"})
	if err := VerifyChecksums(dir, "run make"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChecksums_Failures(t *testing.T) {
	t.Run("missing SHA256SUMS", func(t *testing.T) {
		err := VerifyChecksums(t.TempDir(), "run `make virt-kernel-build`")
		var missing *MissingError
		if !errors.As(err, &missing) || missing.Hint != "run `make virt-kernel-build`" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("altered file", func(t *testing.T) {
		dir := writeBuild(t, map[string]string{"vmlinuz": "kernel"})
		if err := os.WriteFile(filepath.Join(dir, "vmlinuz"), []byte("tampered"), 0o644); err != nil {
			t.Fatal(err)
		}
		var mismatch *ChecksumMismatchError
		if err := VerifyChecksums(dir, "x"); !errors.As(err, &mismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("file without an entry", func(t *testing.T) {
		dir := writeBuild(t, map[string]string{"vmlinuz": "kernel"})
		if err := os.WriteFile(filepath.Join(dir, "extra"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		var mismatch *ChecksumMismatchError
		if err := VerifyChecksums(dir, "x"); !errors.As(err, &mismatch) || mismatch.Reason != "no SHA256SUMS entry" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("malformed SHA256SUMS", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("garbage\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var mismatch *ChecksumMismatchError
		if err := VerifyChecksums(dir, "x"); !errors.As(err, &mismatch) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestVerifyChecksums_UnreadableInputs(t *testing.T) {
	t.Run("SHA256SUMS line longer than the scanner buffer", func(t *testing.T) {
		dir := t.TempDir()
		line := strings.Repeat("a", bufio.MaxScanTokenSize+1) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
		var mismatch *ChecksumMismatchError
		err := VerifyChecksums(dir, "x")
		if !errors.As(err, &mismatch) || mismatch.Reason != bufio.ErrTooLong.Error() {
			t.Fatalf("err = %v, want a ChecksumMismatchError carrying %v", err, bufio.ErrTooLong)
		}
	})
	t.Run("listed file is a dangling symlink", func(t *testing.T) {
		dir := writeBuild(t, map[string]string{"vmlinuz": "kernel"})
		link := filepath.Join(dir, "initramfs")
		if err := os.Symlink(filepath.Join(dir, "absent"), link); err != nil {
			t.Fatal(err)
		}
		sums := filepath.Join(dir, "SHA256SUMS")
		f, err := os.OpenFile(sums, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(strings.Repeat("0", 64) + "  ./initramfs\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		var mismatch *ChecksumMismatchError
		err = VerifyChecksums(dir, "x")
		if !errors.As(err, &mismatch) || mismatch.Path != link {
			t.Fatalf("err = %v, want a ChecksumMismatchError for %s", err, link)
		}
	})
}

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := FileSHA256(path)
	if err != nil || got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("got %s, %v", got, err)
	}
	if _, err := FileSHA256(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: err = %v, want fs.ErrNotExist", err)
	}
	if got, err := FileSHA256(t.TempDir()); err == nil || got != "" {
		t.Fatalf("directory: got %q, %v, want a read error and no digest", got, err)
	}
}

func TestAbsPath(t *testing.T) {
	if got := AbsPath("relative/dir"); !filepath.IsAbs(got) {
		t.Errorf("AbsPath(relative) = %s", got)
	}
	if got := AbsPath("/already/abs"); got != "/already/abs" {
		t.Errorf("AbsPath(abs) = %s", got)
	}
}

// TestAbsPath_UnresolvableWorkingDirectory proves the fallback: when the
// working directory is gone, filepath.Abs fails and the path comes back as
// given rather than as an empty string.
func TestAbsPath_UnresolvableWorkingDirectory(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	t.Setenv("PWD", "")
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if got := AbsPath("relative/dir"); got != "relative/dir" {
		t.Errorf("AbsPath(relative) with no working directory = %s, want relative/dir", got)
	}
}

func TestErrorStrings(t *testing.T) {
	if got := (&MissingError{Path: "/p", Hint: "h"}).Error(); got != "artifact /p is missing (h)" {
		t.Error(got)
	}
	if got := (&ChecksumMismatchError{Path: "/p", Reason: "r"}).Error(); got != "artifact /p: r" {
		t.Error(got)
	}
}
