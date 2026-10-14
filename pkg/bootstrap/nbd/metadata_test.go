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

package nbd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd/nbdtest"
)

// installedImage is an arm64 node's volume after a diskless-nbd install.
func installedImage(t *testing.T, sectorSize int64, uki []byte) nbdtest.Image {
	t.Helper()
	return nbdtest.BuildImage(t, sectorSize, nbdtest.InstalledTree("BOOTAA64.EFI", uki))
}

func writeVolume(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	if content != nil {
		if err := os.WriteFile(filepath.Join(dir, "node-01"+volumeSuffix), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func pattern(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	return data
}

// installedTree is a metadata area as the installer leaves it.
func TestOpenMetadataFile_ReadsTheInstalledArea(t *testing.T) {
	for _, sectorSize := range []int64{512, 4096} {
		uki := pattern(int(sectorSize)*5 + 123)
		dir := writeVolume(t, installedImage(t, sectorSize, uki).Bytes)
		for name, want := range map[string][]byte{
			"EFI/BOOT/BOOTAA64.EFI":  uki,
			"efi/boot/bootaa64.efi":  uki,
			"tpm2/seal-platform.pub": []byte("sealed public"),
			"/tpm2/pcr-banks":        []byte("sha256\n"),
			"tpm2/empty":             {},
		} {
			file, err := OpenMetadataFile(dir, "node-01", name)
			if err != nil {
				t.Fatalf("%d-byte sectors: %s: %v", sectorSize, name, err)
			}
			if file.Size != int64(len(want)) {
				t.Errorf("%d-byte sectors: %s: size %d, want %d", sectorSize, name, file.Size, len(want))
			}
			if err := iotest.TestReader(file, want); err != nil {
				t.Errorf("%d-byte sectors: %s: %v", sectorSize, name, err)
			}
			if err := file.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}
	}
}

func TestOpenMetadataFile_NotInstalled(t *testing.T) {
	for name, content := range map[string][]byte{
		"no volume":        nil,
		"blank volume":     make([]byte, 4<<20),
		"truncated volume": make([]byte, 100),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := OpenMetadataFile(writeVolume(t, content), "node-01", "EFI/BOOT/BOOTAA64.EFI")
			var notInstalled ErrNotInstalled
			if !errors.As(err, &notInstalled) || notInstalled.Identity != "node-01" {
				t.Fatalf("err = %v, want ErrNotInstalled for node-01", err)
			}
		})
	}
}

func TestOpenMetadataFile_RefusesWhatIsNotAnInstalledArea(t *testing.T) {
	uki := pattern(512*3 + 9)
	tests := map[string]struct {
		file    string
		corrupt func(img nbdtest.Image)
		reason  string
	}{
		"MBR without GPT": {corrupt: func(img nbdtest.Image) { clear(img.Bytes[512:1024]) }, reason: "not GPT"},
		"header checksum": {corrupt: func(img nbdtest.Image) { img.Bytes[512+40] ^= 1 }, reason: "header checksum"},
		"entry checksum":  {corrupt: func(img nbdtest.Image) { img.Bytes[1024+60] ^= 1 }, reason: "entry checksum"},
		"partition 1 empty": {corrupt: func(img nbdtest.Image) {
			clear(img.Bytes[1024 : 1024+16])
			img.ResealGPT()
		}, reason: "partition 1 is empty"},
		"partition 1 past the end": {corrupt: func(img nbdtest.Image) {
			binary.LittleEndian.PutUint64(img.Bytes[1024+40:], 1<<40)
			img.ResealGPT()
		}, reason: "outside the volume"},
		"no FAT":              {corrupt: func(img nbdtest.Image) { img.Bytes[img.PartitionOffset+510] = 0 }, reason: "no FAT file system"},
		"FAT16":               {corrupt: func(img nbdtest.Image) { img.Bytes[img.PartitionOffset+22] = 1 }, reason: "not FAT32"},
		"no UKI":              {file: "EFI/BOOT/BOOTX64.EFI", reason: "EFI/BOOT/BOOTX64.EFI not found"},
		"directory":           {file: "EFI/BOOT", reason: "is a directory"},
		"file as a directory": {file: "EFI/BOOT/BOOTAA64.EFI/x", reason: "EFI/BOOT/BOOTAA64.EFI is not a directory"},
		"chain loop": {corrupt: func(img nbdtest.Image) {
			first := img.FirstCluster["EFI/BOOT/BOOTAA64.EFI"]
			img.SetLink(first, first)
		}, reason: "loops"},
		"chain to a free cluster": {corrupt: func(img nbdtest.Image) {
			img.SetLink(img.FirstCluster["EFI/BOOT/BOOTAA64.EFI"], 0)
		}, reason: "invalid cluster 0x0"},
		"chain too short": {corrupt: func(img nbdtest.Image) {
			img.SetLink(img.FirstCluster["EFI/BOOT/BOOTAA64.EFI"], fatClusterMask)
		}, reason: "need 4 clusters"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			img := installedImage(t, 512, uki)
			if tc.corrupt != nil {
				tc.corrupt(img)
			}
			file := tc.file
			if file == "" {
				file = "EFI/BOOT/BOOTAA64.EFI"
			}
			_, err := OpenMetadataFile(writeVolume(t, img.Bytes), "node-01", file)
			var area ErrMetadataArea
			if !errors.As(err, &area) {
				t.Fatalf("err = %v, want ErrMetadataArea", err)
			}
			if area.Identity != "node-01" || !strings.Contains(area.Error(), tc.reason) {
				t.Errorf("err = %v, want it to name node-01 and %q", err, tc.reason)
			}
		})
	}
}

func TestOpenMetadataFile_RefusesAnInvalidIdentity(t *testing.T) {
	_, err := OpenMetadataFile(t.TempDir(), "../node-01", "EFI/BOOT/BOOTAA64.EFI")
	var volumeErr ErrVolume
	if !errors.As(err, &volumeErr) || !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("err = %v, want ErrVolume wrapping fs.ErrInvalid", err)
	}
}

func TestParseDir(t *testing.T) {
	var dir []byte
	dir = append(dir, nbdtest.LongNameEntries("seal-platform.pub", "SEAL-P~1PUB")...)
	dir = append(dir, nbdtest.DirEntry("SEAL-P~1PUB", 0x20, 0x00012345, 10)...)
	// A long name whose checksum is not its short entry's is ignored.
	dir = append(dir, nbdtest.LongNameEntries("stolen-name", "STOLEN  TXT")...)
	dir = append(dir, nbdtest.DirEntry("REAL    TXT", 0x20, 9, 1)...)
	dir = append(dir, nbdtest.DirEntry("EFI        ", fatAttrVolumeID, 0, 0)...)
	dir = append(dir, make([]byte, fatDirEntrySize)...)
	dir = append(dir, nbdtest.DirEntry("AFTEREND   ", 0x20, 3, 1)...)

	got := parseDir(dir)
	want := []fatEntry{
		{name: "seal-platform.pub", cluster: 0x00012345, size: 10},
		{name: "REAL.TXT", cluster: 9, size: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("parseDir = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if entries := parseDir(nil); entries != nil {
		t.Errorf("parseDir(nil) = %+v, want none", entries)
	}
}

type failingReaderAt struct{}

func (failingReaderAt) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestMetadataReader_ReadAtRefusesOutsideTheVolume(t *testing.T) {
	area := &metadataReader{identity: "node-01", volume: bytes.NewReader(make([]byte, 16)), size: 16}
	for _, off := range []int64{-1, 9, 17} {
		var areaErr ErrMetadataArea
		if err := area.readAt(make([]byte, 8), off, "probe"); !errors.As(err, &areaErr) {
			t.Errorf("readAt(8 bytes at %d) = %v, want ErrMetadataArea", off, err)
		}
	}
	if err := area.readAt(make([]byte, 8), 8, "probe"); err != nil {
		t.Errorf("readAt(8 bytes at 8) = %v", err)
	}
	failing := &metadataReader{identity: "node-01", volume: failingReaderAt{}, size: 16}
	if err := failing.readAt(make([]byte, 8), 0, "probe"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("readAt on a failing volume = %v, want the read error", err)
	}
}
