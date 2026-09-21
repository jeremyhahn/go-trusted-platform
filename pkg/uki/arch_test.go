package uki

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStubPathAndBootFileName(t *testing.T) {
	tests := []struct {
		arch Architecture
		stub string
		boot string
	}{
		{ArchX86_64, "/usr/lib/systemd/boot/efi/linuxx64.efi.stub", "BOOTX64.EFI"},
		{ArchAArch64, "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub", "BOOTAA64.EFI"},
		{ArchARM, "/usr/lib/systemd/boot/efi/linuxarm.efi.stub", "BOOTARM.EFI"},
		{ArchRISCV64, "/usr/lib/systemd/boot/efi/linuxriscv64.efi.stub", "BOOTRISCV64.EFI"},
	}
	for _, tc := range tests {
		stub, err := StubPath(tc.arch)
		if err != nil || stub != tc.stub {
			t.Errorf("StubPath(%s) = %q, %v; want %q", tc.arch, stub, err, tc.stub)
		}
		boot, err := BootFileName(tc.arch)
		if err != nil || boot != tc.boot {
			t.Errorf("BootFileName(%s) = %q, %v; want %q", tc.arch, boot, err, tc.boot)
		}
	}
	if stub, err := StubPath(ArchX86_64); err != nil || stub != DefaultStubPath {
		t.Errorf("StubPath(x86_64) must equal DefaultStubPath, got %q, %v", stub, err)
	}
}

func TestStubPathAndBootFileNameRejectUnknownArchitecture(t *testing.T) {
	for _, arch := range []Architecture{"", "mips", "x86"} {
		if _, err := StubPath(arch); !isUnsupported(err, string(arch)) {
			t.Errorf("StubPath(%q) error = %v, want *UnsupportedArchitectureError", arch, err)
		}
		if _, err := BootFileName(arch); !isUnsupported(err, string(arch)) {
			t.Errorf("BootFileName(%q) error = %v, want *UnsupportedArchitectureError", arch, err)
		}
	}
	if got := (&UnsupportedArchitectureError{Arch: "mips"}).Error(); got != "uki: unsupported architecture mips" {
		t.Errorf("UnsupportedArchitectureError.Error() = %q", got)
	}
}

func isUnsupported(err error, arch string) bool {
	var unsupported *UnsupportedArchitectureError
	return errors.As(err, &unsupported) && unsupported.Arch == arch
}

func TestParseArchitecture(t *testing.T) {
	tests := map[string]Architecture{
		"":        ArchX86_64,
		"x86_64":  ArchX86_64,
		"amd64":   ArchX86_64,
		"aarch64": ArchAArch64,
		"arm64":   ArchAArch64,
		"arm":     ArchARM,
		"riscv64": ArchRISCV64,
	}
	for name, want := range tests {
		got, err := ParseArchitecture(name)
		if err != nil || got != want {
			t.Errorf("ParseArchitecture(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"mips", "x86", "ARM64"} {
		if _, err := ParseArchitecture(name); !isUnsupported(err, name) {
			t.Errorf("ParseArchitecture(%q) error = %v, want *UnsupportedArchitectureError", name, err)
		}
	}
}

func TestHostArchitecture(t *testing.T) {
	got := HostArchitecture()
	want, err := ParseArchitecture(runtime.GOARCH)
	if err != nil {
		// A GOARCH this package does not model falls back to x86_64.
		want = ArchX86_64
	}
	if got != want {
		t.Errorf("HostArchitecture() = %q, want %q for GOARCH %s", got, want, runtime.GOARCH)
	}
}

func TestFromFilesDecompressesGzipKernel(t *testing.T) {
	dir := t.TempDir()
	raw := bytes.Repeat([]byte("ARM64 Image payload "), 64)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(dir, "vmlinuz-rpi")
	initramfs := filepath.Join(dir, "initramfs")
	if err := os.WriteFile(kernel, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(initramfs, []byte("initramfs"), 0o600); err != nil {
		t.Fatal(err)
	}

	u, err := FromFiles(kernel, initramfs, "console=ttyAMA0")
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	got, err := io.ReadAll(u.Kernel)
	if err != nil {
		t.Fatalf("read kernel: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("kernel was not decompressed: got %d bytes, want %d", len(got), len(raw))
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestFromFilesPassesThroughUncompressedKernel(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("MZ\x90\x00 bzImage-like payload that is not gzip")
	kernel := filepath.Join(dir, "vmlinuz")
	initramfs := filepath.Join(dir, "initramfs")
	if err := os.WriteFile(kernel, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(initramfs, []byte("initramfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := FromFiles(kernel, initramfs, "root=/dev/mapper/cryptroot")
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	defer u.Close()
	got, err := io.ReadAll(u.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("uncompressed kernel was altered: %q", got)
	}

	// A one-byte kernel is shorter than the gzip magic and must still open.
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte{0x1f}, 0o600); err != nil {
		t.Fatal(err)
	}
	u2, err := FromFiles(short, initramfs, "x")
	if err != nil {
		t.Fatalf("FromFiles(short): %v", err)
	}
	if err := u2.Close(); err != nil {
		t.Fatalf("Close(short): %v", err)
	}
}

func TestFromFilesRejectsCorruptGzipKernel(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "vmlinuz")
	initramfs := filepath.Join(dir, "initramfs")
	// gzip magic followed by garbage: an unreadable gzip header.
	if err := os.WriteFile(kernel, []byte{0x1f, 0x8b, 0xff, 0xff, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(initramfs, []byte("initramfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := FromFiles(kernel, initramfs, "x")
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("FromFiles error = %v, want *WrappedError", err)
	}
	if wrapped.Msg != "failed to decompress gzip kernel" {
		t.Errorf("WrappedError.Msg = %q", wrapped.Msg)
	}

	if _, err := FromFiles(filepath.Join(dir, "missing"), initramfs, "x"); !errors.As(err, &wrapped) || wrapped.Msg != "failed to open kernel" {
		t.Errorf("FromFiles(missing kernel) error = %v", err)
	}
}
