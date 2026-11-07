// Package diskimagetest lays out the inputs an image build consumes — target
// binaries, verified U-Boot and virt-kernel builder outputs, a platform
// config — for the tests of the packages that build images.
package diskimagetest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
)

// WriteELF writes a minimal 64-bit ELF header for machine: enough for the
// media staging's architecture check.
func WriteELF(t *testing.T, path string, machine elf.Machine) {
	t.Helper()
	if err := os.WriteFile(path, elfHeader(machine), 0o755); err != nil {
		t.Fatal(err)
	}
}

// WriteDynamicELF writes a minimal 64-bit ELF for machine that names a
// program interpreter (PT_INTERP), as a CGO-enabled, dynamically linked
// executable does.
func WriteDynamicELF(t *testing.T, path string, machine elf.Machine) {
	t.Helper()
	const phoff, phentsize = 64, 56
	interp := []byte("/lib64/ld-linux-x86-64.so.2\x00")
	file := elfHeader(machine)
	binary.LittleEndian.PutUint64(file[32:], phoff)
	binary.LittleEndian.PutUint16(file[56:], 1)
	phdr := make([]byte, phentsize)
	binary.LittleEndian.PutUint32(phdr[0:], uint32(elf.PT_INTERP))
	binary.LittleEndian.PutUint32(phdr[4:], uint32(elf.PF_R))
	binary.LittleEndian.PutUint64(phdr[8:], phoff+phentsize)
	binary.LittleEndian.PutUint64(phdr[32:], uint64(len(interp)))
	binary.LittleEndian.PutUint64(phdr[40:], uint64(len(interp)))
	binary.LittleEndian.PutUint64(phdr[48:], 1)
	file = append(file, phdr...)
	file = append(file, interp...)
	if err := os.WriteFile(path, file, 0o755); err != nil {
		t.Fatal(err)
	}
}

// elfHeader is a 64-bit little-endian ELF executable header for machine,
// with no program or section headers.
func elfHeader(machine elf.Machine) []byte {
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(hdr[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(hdr[18:], uint16(machine))
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	binary.LittleEndian.PutUint16(hdr[52:], 64)
	binary.LittleEndian.PutUint16(hdr[54:], 56)
	binary.LittleEndian.PutUint16(hdr[58:], 64)
	return hdr
}

// Binaries lays out the platform binaries the media staging looks for, built
// for machine.
func Binaries(t *testing.T, machine elf.Machine) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"platformd", "platformctl", "platformctl-static", "platform-initrd", "gatewayd"} {
		WriteELF(t, filepath.Join(dir, name), machine)
	}
	return dir
}

// writeVerified writes files under dir with the SHA256SUMS a builder writes
// beside them.
func writeVerified(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(files[name]), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(files[name]))
		sums.WriteString(hex.EncodeToString(sum[:]) + "  ./" + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// UBootOutput lays out verified U-Boot builder output for both boards.
func UBootOutput(t *testing.T) string {
	t.Helper()
	out := t.TempDir()
	writeVerified(t, filepath.Join(out, string(uboot.BoardRPiArm64)), map[string]string{
		"u-boot.bin": "rpi", "u-boot.config": "c", "overlays/tpm-soft-spi.dtbo": "o",
	})
	writeVerified(t, filepath.Join(out, string(uboot.BoardQEMUArm64)), map[string]string{
		"u-boot.bin": "qemu", "u-boot.config": "c",
	})
	m, err := json.Marshal(uboot.Manifest{Version: uboot.DefaultVersion, CacheKey: "k", Boards: []string{"rpi_arm64", "qemu_arm64"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, uboot.ManifestName), m, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// VirtKernelRelease is the kernel release VirtKernelOutput lays out.
const VirtKernelRelease = "6.12.110-0-virt"

// VirtKernelOutput lays out verified virt-kernel builder output: a gzip'd
// EFI-stub kernel (a PE, so it can be signed) and a modules tarball with one
// module under lib/modules/<release>.
func VirtKernelOutput(t *testing.T) string {
	t.Helper()
	out := t.TempDir()
	writeVerified(t, filepath.Join(out, "virt"), map[string]string{
		"vmlinuz-virt":        string(gzipped(t, authenticodetest.MinimalPE(authenticodetest.MachineARM64))),
		"modules-virt.tar.gz": string(ModulesTarball(t, VirtKernelRelease)),
		"kernel-version.txt":  VirtKernelRelease + "\n",
		"config-virt":         "c",
	})
	manifest := `{"kernel_version":"6.12.110","kernel_release":"` + VirtKernelRelease + `","tarball_sha256":"x","cache_key":"k","flavor":"virt","built_at":"now"}`
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// PlatformConfig writes a minimal platform config carrying seal-pcrs, with
// Secure Boot off.
func PlatformConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "platform.yaml")
	if err := os.WriteFile(p, []byte("os:\n  architecture: x86_64\n  hostname: node\ndisk:\n  partition-table: gpt\nseal-pcrs: [0, 7, 9]\nsecure-boot:\n  enabled: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ModulesTarball is a kernel modules tarball for release, as the kernel
// builder packs it: lib/modules/<release>/ with one module and modules.dep.
func ModulesTarball(t *testing.T, release string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"lib/modules/" + release + "/kernel/drivers/net/virtio_net.ko": "ko",
		"lib/modules/" + release + "/modules.dep":                      "kernel/drivers/net/virtio_net.ko:\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
