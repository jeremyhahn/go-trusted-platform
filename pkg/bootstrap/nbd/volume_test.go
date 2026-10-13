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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func openVolume(t *testing.T, store *volumeStore, identity string) *volume {
	t.Helper()
	vol, err := store.open(identity)
	if err != nil {
		t.Fatalf("open %s: %v", identity, err)
	}
	t.Cleanup(func() {
		if err := vol.file.Close(); err != nil && !errors.Is(err, fs.ErrClosed) {
			t.Errorf("close: %v", err)
		}
	})
	return vol
}

func TestVolumeStore_CreatesOnFirstAttach(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "volumes")
	store := newVolumeStore(dir, 4096)

	vol := openVolume(t, store, "node-01")
	if vol.size != 4096 {
		t.Fatalf("size = %d, want 4096", vol.size)
	}
	info, err := os.Stat(filepath.Join(dir, "node-01"+volumeSuffix))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != volumeFileMode {
		t.Fatalf("mode = %v, want %v", info.Mode().Perm(), os.FileMode(volumeFileMode))
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != volumeDirMode {
		t.Fatalf("dir mode = %v, want %v", dirInfo.Mode().Perm(), os.FileMode(volumeDirMode))
	}
}

func TestVolumeStore_ExistingVolumeKeepsItsSizeAndData(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte{7}, 1024)
	if err := os.WriteFile(filepath.Join(dir, "node-01"+volumeSuffix), content, volumeFileMode); err != nil {
		t.Fatalf("write: %v", err)
	}

	vol := openVolume(t, newVolumeStore(dir, 4096), "node-01")
	if vol.size != 1024 {
		t.Fatalf("size = %d, want the existing 1024", vol.size)
	}
	got := make([]byte, len(content))
	if _, err := vol.file.ReadAt(got, 0); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("existing data not preserved: %v", err)
	}
}

func TestVolumeStore_RefusesBadIdentityAndDirectory(t *testing.T) {
	store := newVolumeStore(t.TempDir(), 4096)
	var refused ErrVolume
	if _, err := store.open("../escape"); !errors.As(err, &refused) || refused.Op != "validate" {
		t.Fatalf("open(../escape) = %v, want ErrVolume validate", err)
	}

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := newVolumeStore(blocker, 4096).open("node-01"); !errors.As(err, &refused) || refused.Op != "create directory" {
		t.Fatalf("open under a file = %v, want ErrVolume create directory", err)
	}
}

func TestVolumeStore_UnopenableVolumeIsReported(t *testing.T) {
	dir := t.TempDir()
	// A directory where the volume file should be: it exists, but cannot
	// be opened read-write.
	if err := os.Mkdir(filepath.Join(dir, "node-01"+volumeSuffix), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var refused ErrVolume
	if _, err := newVolumeStore(dir, 4096).open("node-01"); !errors.As(err, &refused) || refused.Op != "open" {
		t.Fatalf("open = %v, want ErrVolume open", err)
	}
}

func TestVolume_InRange(t *testing.T) {
	vol := &volume{size: 4096}
	tests := []struct {
		offset uint64
		length uint32
		want   bool
	}{
		{0, 4096, true},
		{4095, 1, true},
		{4096, 0, true},
		{4096, 1, false},
		{4097, 0, false},
		{^uint64(0), 2, false},
	}
	for _, tc := range tests {
		if got := vol.inRange(tc.offset, tc.length); got != tc.want {
			t.Errorf("inRange(%d, %d) = %v, want %v", tc.offset, tc.length, got, tc.want)
		}
	}
}

func TestVolume_TrimZeroesTheRange(t *testing.T) {
	vol := openVolume(t, newVolumeStore(t.TempDir(), 1<<20), "node-01")
	if _, err := vol.file.WriteAt(bytes.Repeat([]byte{0xff}, 3*4096), 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := vol.trim(4096, 4096); err != nil {
		t.Fatalf("trim: %v", err)
	}

	got := make([]byte, 3*4096)
	if _, err := vol.file.ReadAt(got, 0); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got[4096:8192], make([]byte, 4096)) {
		t.Fatal("trimmed range is not zero")
	}
	if !bytes.Equal(got[:4096], bytes.Repeat([]byte{0xff}, 4096)) || !bytes.Equal(got[8192:], bytes.Repeat([]byte{0xff}, 4096)) {
		t.Fatal("trim touched data outside its range")
	}
}

func TestZeroRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zero")
	content := bytes.Repeat([]byte{1}, 200*1024)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Spans several 64 KiB chunks.
	if err := zeroRange(file, 10, 150*1024); err != nil {
		t.Fatalf("zeroRange: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got[9] != 1 || got[10+150*1024] != 1 || !bytes.Equal(got[10:10+150*1024], make([]byte, 150*1024)) {
		t.Fatal("zeroRange wrote outside or missed its range")
	}

	// Writing through a closed file fails.
	if err := zeroRange(file, 0, 1); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("zeroRange on a closed file = %v, want fs.ErrClosed", err)
	}
}

func TestVolume_TrimFailsOnAClosedFile(t *testing.T) {
	store := newVolumeStore(t.TempDir(), 4096)
	vol, err := store.open("node-01")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := vol.file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := vol.trim(0, 512); err == nil {
		t.Fatal("trim on a closed file succeeded")
	}
}
