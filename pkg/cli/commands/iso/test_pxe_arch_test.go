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

package iso

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// copySigner is an Authenticode that "signs" by appending a marker, so a
// test can see the decompressed bytes that reached it.
type copySigner struct{ signed [][]byte }

func (c *copySigner) Sign(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	c.signed = append(c.signed, data)
	_, err = out.Write(append(data, []byte("+SIG")...))
	return err
}

func (c *copySigner) SignFile(inputPath, outputPath string) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	return c.Sign(in, out)
}

func (c *copySigner) Verify(io.Reader) error                                   { return nil }
func (c *copySigner) VerifyFile(string) error                                  { return nil }
func (c *copySigner) ExtractCertificate(io.Reader) (*x509.Certificate, error)  { return nil, nil }
func (c *copySigner) ExtractCertificateFile(string) (*x509.Certificate, error) { return nil, nil }

func withFlags(t *testing.T, arch, uboot, ipxeBinary, keys string) {
	t.Helper()
	prevArch, prevUBoot, prevIPXE, prevKeys := pxeArchitectureFlag, pxeUBoot, pxeIPXE, pxeKeysDir
	pxeArchitectureFlag, pxeUBoot, pxeIPXE, pxeKeysDir = arch, uboot, ipxeBinary, keys
	t.Cleanup(func() {
		pxeArchitectureFlag, pxeUBoot, pxeIPXE, pxeKeysDir = prevArch, prevUBoot, prevIPXE, prevKeys
	})
}

// secureBootKeysDir returns a directory holding a fresh DB.key/DB.crt.
func secureBootKeysDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	authenticodetest.WriteKeyPair(t, dir)
	return dir
}

// writeFile creates a small file under dir and returns its path.
func writeFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(name), 0o644))
	return path
}

func TestPreparePXEArchitecture(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("x86_64 is the default and needs nothing", func(t *testing.T) {
		withFlags(t, "", "", "", "")
		a, err := preparePXEArchitecture(context.Background(), logger)
		require.NoError(t, err)
		assert.Equal(t, qemu.ArchX86_64, a.qemu)
		assert.Equal(t, ipxe.ArchitectureX86_64, a.entryArch)
		assert.Nil(t, a.signer)
		assert.Empty(t, a.firmware)
		assert.Empty(t, a.firmwareOverrides, "x86 serves upstream's binaries")
	})

	t.Run("aarch64 needs the U-Boot binary", func(t *testing.T) {
		withFlags(t, "aarch64", filepath.Join(t.TempDir(), "absent.bin"), "", "")
		_, err := preparePXEArchitecture(context.Background(), logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--uboot")
	})

	t.Run("aarch64 needs the platform-built arm64 iPXE", func(t *testing.T) {
		dir := t.TempDir()
		withFlags(t, "aarch64", writeFile(t, dir, "u-boot.bin"), filepath.Join(dir, "absent.efi"), "")
		_, err := preparePXEArchitecture(context.Background(), logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--ipxe")
		assert.Contains(t, err.Error(), "make ipxe-build")
	})

	t.Run("aarch64 needs the db key pair", func(t *testing.T) {
		dir := t.TempDir()
		withFlags(t, "arm64", writeFile(t, dir, "u-boot.bin"), writeFile(t, dir, "snponly.efi"), filepath.Join(dir, "no-keys"))
		_, err := preparePXEArchitecture(context.Background(), logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--keys-dir")
	})

	t.Run("aarch64 serves the platform-built iPXE in place of upstream's", func(t *testing.T) {
		dir := t.TempDir()
		ipxeBinary := writeFile(t, dir, "snponly.efi")
		withFlags(t, "aarch64", writeFile(t, dir, "u-boot.bin"), ipxeBinary, secureBootKeysDir(t))
		a, err := preparePXEArchitecture(context.Background(), logger)
		require.NoError(t, err)
		assert.Equal(t, qemu.ArchAArch64, a.qemu)
		assert.Equal(t, ipxe.ArchitectureARM64, a.entryArch)
		assert.NotNil(t, a.signer)
		assert.Equal(t, map[string]string{ipxe.FirmwareSNPOnlyAArch64: ipxeBinary}, a.firmwareOverrides)
	})

	t.Run("an unknown architecture is refused", func(t *testing.T) {
		withFlags(t, "riscv64", "", "", "")
		_, err := preparePXEArchitecture(context.Background(), logger)
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
	})
}

func TestLocalizeKernel(t *testing.T) {
	logger := logging.DefaultLogger()
	kernel := []byte("MZ-arm64-kernel-image")
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, err := w.Write(kernel)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	t.Run("without a signer the entry only gains its architecture", func(t *testing.T) {
		a := &pxeArchitecture{entryArch: ipxe.ArchitectureX86_64}
		entry, err := a.localizeKernel(context.Background(), logger, ipxe.BootEntry{Kernel: "http://example/vmlinuz"}, t.TempDir())
		require.NoError(t, err)
		assert.Equal(t, "http://example/vmlinuz", entry.Kernel)
		assert.Equal(t, ipxe.ArchitectureX86_64, entry.Architecture)
	})

	t.Run("a gzip vmlinuz URL is downloaded, decompressed and signed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz.Bytes()) }))
		defer srv.Close()
		signer := &copySigner{}
		a := &pxeArchitecture{entryArch: ipxe.ArchitectureARM64, signer: signer}
		work := t.TempDir()

		entry, err := a.localizeKernel(context.Background(), logger, ipxe.BootEntry{Kernel: srv.URL + "/vmlinuz-lts"}, work)

		require.NoError(t, err)
		assert.Equal(t, ipxe.ArchitectureARM64, entry.Architecture)
		assert.Equal(t, "file://"+filepath.Join(work, "kernel.signed.efi"), entry.Kernel)
		require.Len(t, signer.signed, 1)
		assert.Equal(t, kernel, signer.signed[0], "the PE image inside the gzip is what gets signed")
		signed, err := os.ReadFile(filepath.Join(work, "kernel.signed.efi"))
		require.NoError(t, err)
		assert.Equal(t, append(append([]byte{}, kernel...), []byte("+SIG")...), signed)
	})

	t.Run("a local uncompressed kernel is signed as is", func(t *testing.T) {
		work := t.TempDir()
		src := filepath.Join(work, "Image")
		require.NoError(t, os.WriteFile(src, kernel, 0o644))
		signer := &copySigner{}
		a := &pxeArchitecture{entryArch: ipxe.ArchitectureARM64, signer: signer}

		entry, err := a.localizeKernel(context.Background(), logger, ipxe.BootEntry{Kernel: "file://" + src}, work)

		require.NoError(t, err)
		assert.Equal(t, "file://"+filepath.Join(work, "kernel.signed.efi"), entry.Kernel)
		assert.Equal(t, [][]byte{kernel}, signer.signed)
	})

	t.Run("a download failure is reported", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }))
		defer srv.Close()
		a := &pxeArchitecture{entryArch: ipxe.ArchitectureARM64, signer: &copySigner{}}
		_, err := a.localizeKernel(context.Background(), logger, ipxe.BootEntry{Kernel: srv.URL + "/missing"}, t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, "x"), expandHome("~/x"))
	assert.Equal(t, "/abs/x", expandHome("/abs/x"))
	assert.Equal(t, "", expandHome(""))
}

func TestPXEDiskPath_DefaultsUnderWorkDir(t *testing.T) {
	prevDisk, prevWork := pxeDisk, pxeWorkDir
	t.Cleanup(func() { pxeDisk, pxeWorkDir = prevDisk, prevWork })

	pxeDisk, pxeWorkDir = "", "work-x"
	assert.Equal(t, filepath.Join("work-x", DefaultPXEDiskName), pxeDiskPath())

	pxeDisk = "/tmp/explicit.qcow2"
	assert.Equal(t, "/tmp/explicit.qcow2", pxeDiskPath())
}

func TestTestPXECommand_DiskFlags(t *testing.T) {
	cmd := newTestPXECommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	disk := cmd.Flags().Lookup("disk")
	require.NotNil(t, disk)
	assert.Equal(t, "", disk.DefValue)
	size := cmd.Flags().Lookup("disk-size")
	require.NotNil(t, size)
	assert.Equal(t, "10G", size.DefValue)
}

func TestPublishBootFiles(t *testing.T) {
	src := t.TempDir()
	kernel := writeFile(t, src, "vmlinuz-lts")
	initrd := writeFile(t, src, "initramfs-lts")
	files := t.TempDir()

	t.Run("local files are copied and served by URL", func(t *testing.T) {
		entry, err := publishBootFiles(ipxe.BootEntry{Kernel: "file://" + kernel, Initrd: "file://" + initrd}, files, "http://10.99.99.1:8080/files")
		require.NoError(t, err)
		assert.Equal(t, "http://10.99.99.1:8080/files/vmlinuz-lts", entry.Kernel)
		assert.Equal(t, "http://10.99.99.1:8080/files/initramfs-lts", entry.Initrd)
		data, err := os.ReadFile(filepath.Join(files, "initramfs-lts"))
		require.NoError(t, err)
		assert.Equal(t, "initramfs-lts", string(data))
	})

	t.Run("URLs pass through untouched", func(t *testing.T) {
		in := ipxe.BootEntry{Kernel: "https://mirror/vmlinuz", Initrd: "http://10.99.99.1:8080/files/initramfs"}
		entry, err := publishBootFiles(in, files, "http://10.99.99.1:8080/files")
		require.NoError(t, err)
		assert.Equal(t, in, entry)
	})

	t.Run("a missing local file is reported", func(t *testing.T) {
		_, err := publishBootFiles(ipxe.BootEntry{Kernel: "file://" + filepath.Join(src, "absent")}, files, "http://10.99.99.1:8080/files")
		require.Error(t, err)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}
