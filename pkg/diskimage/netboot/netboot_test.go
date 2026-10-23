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

package netboot

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
)

// writeImage writes an MBR with a FAT partition 1, as the factory image has.
func writeImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rpi.img")
	mbr := make([]byte, 512)
	e := mbr[446:]
	e[0], e[4] = 0x80, 0x0c
	binary.LittleEndian.PutUint32(e[8:], 2048)
	binary.LittleEndian.PutUint32(e[12:], 1048576)
	mbr[510], mbr[511] = 0x55, 0xaa
	require.NoError(t, os.WriteFile(path, mbr, 0o644))
	return path
}

// fakeMtools answers mdir and mcopy from a map, the way the image's ESP
// would.
type fakeMtools struct {
	files map[string][]byte
}

func (m *fakeMtools) run(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "mdir":
		var out strings.Builder
		out.WriteString("::/EFI/\n::/EFI/BOOT/\n::/overlays/\n::/tpm2/\n")
		for path := range m.files {
			out.WriteString("::/" + path + "\n")
		}
		return []byte(out.String()), nil
	case "mcopy":
		src := strings.TrimPrefix(args[len(args)-2], "::/")
		data, ok := m.files[src]
		if !ok {
			return nil, errors.New("no such file")
		}
		return nil, os.WriteFile(args[len(args)-1], data, 0o644)
	}
	return nil, nil
}

func TestStageFromImage_ServesTheBootPartitionLessTheSDCardParts(t *testing.T) {
	esp := &fakeMtools{files: map[string][]byte{
		"config.txt":                       []byte("kernel=kernel8.img\n"),
		"kernel8.img":                      []byte("U-Boot"),
		"start4.elf":                       []byte("ELF"),
		"fixup4.dat":                       []byte("fix"),
		"bcm2711-rpi-4-b.dtb":              []byte("dtb"),
		"overlays/tpm-soft-spi.dtbo":       []byte("tpm"),
		"EFI/BOOT/BOOTAA64.EFI":            []byte("UKI"),
		"tpm2/installer.luks":              []byte("LUKS"),
		"ubootefi.var":                     []byte("vars"),
		"EFI/TRUSTED_PLATFORM/PROVISIONED": []byte(""),
	}}
	dest := filepath.Join(t.TempDir(), "tftp")
	require.NoError(t, os.WriteFile(dest, []byte("stale"), 0o644), "dest is replaced whatever it was")

	files, err := StageFromImage(context.Background(), writeImage(t), dest, esp.run)
	require.NoError(t, err)

	assert.Equal(t, []string{"bcm2711-rpi-4-b.dtb", "config.txt", "fixup4.dat", "kernel8.img", "overlays/tpm-soft-spi.dtbo", "start4.elf"}, files)
	for _, absent := range []string{"EFI/BOOT/BOOTAA64.EFI", "tpm2/installer.luks", "ubootefi.var", "EFI/TRUSTED_PLATFORM/PROVISIONED"} {
		_, err := os.Stat(filepath.Join(dest, filepath.FromSlash(absent)))
		assert.True(t, os.IsNotExist(err), "%s must not be served", absent)
	}
	data, err := os.ReadFile(filepath.Join(dest, "overlays", "tpm-soft-spi.dtbo"))
	require.NoError(t, err)
	assert.Equal(t, "tpm", string(data))
}

func TestStageFromImage_RequiresTheBootFiles(t *testing.T) {
	esp := &fakeMtools{files: map[string][]byte{"start4.elf": []byte("ELF")}}
	_, err := StageFromImage(context.Background(), writeImage(t), filepath.Join(t.TempDir(), "tftp"), esp.run)
	var missing *MissingFileError
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "config.txt", missing.File)
	var treeErr *Error
	assert.ErrorAs(t, err, &treeErr)
}

func TestStageFromImage_NoImage(t *testing.T) {
	_, err := StageFromImage(context.Background(), filepath.Join(t.TempDir(), "absent.img"), filepath.Join(t.TempDir(), "tftp"), (&fakeMtools{}).run)
	var treeErr *Error
	require.ErrorAs(t, err, &treeErr)
}

func TestStageFromImage_UnusableDestination(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o644))
	_, err := StageFromImage(context.Background(), writeImage(t), filepath.Join(file, "tftp"), (&fakeMtools{}).run)
	var treeErr *Error
	require.ErrorAs(t, err, &treeErr)
	assert.Contains(t, treeErr.Error(), "from "+treeErr.Source)
}

// writeAPK writes a minimal apk (a gzip tar) holding files under boot/.
func writeAPK(t *testing.T, dir, name, version string, files map[string]string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name+"-"+version+".apk"))
	require.NoError(t, err)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for path, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())
}

func TestStage_FromBuildInputs(t *testing.T) {
	prefetch := t.TempDir()
	writeAPK(t, prefetch, "raspberrypi-bootloader", "1.20250101-r0", map[string]string{"boot/start4.elf": "ELF4", "boot/fixup4.dat": "FIX4", "boot/start.elf": "ELF"})
	writeAPK(t, prefetch, "raspberrypi-bootloader-common", "1.20250101-r0", map[string]string{"boot/bootcode.bin": "BOOT"})
	writeAPK(t, prefetch, "linux-rpi", "6.12.0-r0", map[string]string{
		"boot/bcm2711-rpi-4-b.dtb":      "dtb4",
		"boot/bcm2712-rpi-5-b.dtb":      "dtb5",
		"boot/overlays/disable-bt.dtbo": "bt",
		"boot/overlays/other.dtbo":      "other",
		"boot/vmlinuz-rpi":              "kernel",
	})
	ubootDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(ubootDir, "overlays"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ubootDir, "u-boot.bin"), []byte("U-Boot"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(ubootDir, "overlays", "tpm-soft-spi.dtbo"), []byte("tpm"), 0o644))
	art := uboot.Artifacts{Board: uboot.BoardRPiArm64, Dir: ubootDir, Binary: filepath.Join(ubootDir, "u-boot.bin"), OverlaysDir: filepath.Join(ubootDir, "overlays")}
	dest := filepath.Join(t.TempDir(), "tftp")

	require.NoError(t, Stage(context.Background(), Inputs{Model: "rpi4", PrefetchDir: prefetch, UBoot: art}, dest))

	for name, want := range map[string]string{
		"kernel8.img":                "U-Boot",
		"start4.elf":                 "ELF4",
		"fixup4.dat":                 "FIX4",
		"bcm2711-rpi-4-b.dtb":        "dtb4",
		"bcm2712-rpi-5-b.dtb":        "dtb5",
		"overlays/disable-bt.dtbo":   "bt",
		"overlays/tpm-soft-spi.dtbo": "tpm",
	} {
		data, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(name)))
		require.NoError(t, err, name)
		assert.Equal(t, want, string(data), name)
	}
	_, err := os.Stat(filepath.Join(dest, "vmlinuz-rpi"))
	assert.True(t, os.IsNotExist(err), "the Linux kernel is not served; U-Boot is the kernel")
	_, err = os.Stat(filepath.Join(dest, "overlays", "other.dtbo"))
	assert.True(t, os.IsNotExist(err), "only the overlays config.txt names")
	cfg, err := os.ReadFile(filepath.Join(dest, "config.txt"))
	require.NoError(t, err)
	assert.Contains(t, string(cfg), "kernel=kernel8.img")
	assert.Contains(t, string(cfg), "dtoverlay=tpm-soft-spi")
}

func TestStage_Failures(t *testing.T) {
	err := Stage(context.Background(), Inputs{Model: "rpi2"}, t.TempDir())
	var treeErr *Error
	require.ErrorAs(t, err, &treeErr)
	assert.Equal(t, "model", treeErr.Source)

	err = Stage(context.Background(), Inputs{Model: "rpi4", PrefetchDir: t.TempDir()}, filepath.Join(t.TempDir(), "tftp"))
	require.ErrorAs(t, err, &treeErr)
	assert.Equal(t, "build inputs", treeErr.Source)
}
