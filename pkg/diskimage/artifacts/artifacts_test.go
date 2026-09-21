package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := FileSHA256(path)
	if err != nil || got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("got %s, %v", got, err)
	}
	if _, err := FileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing file must fail")
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

func TestErrorStrings(t *testing.T) {
	if got := (&MissingError{Path: "/p", Hint: "h"}).Error(); got != "artifact /p is missing (h)" {
		t.Error(got)
	}
	if got := (&ChecksumMismatchError{Path: "/p", Reason: "r"}).Error(); got != "artifact /p: r" {
		t.Error(got)
	}
}
