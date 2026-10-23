package partition

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPath(t *testing.T) {
	tests := []struct {
		disk string
		n    int
		want string
	}{
		{"/dev/sda", 2, "/dev/sda2"},
		{"/dev/vda", 1, "/dev/vda1"},
		{"/dev/nvme0n1", 2, "/dev/nvme0n1p2"},
		{"/dev/mmcblk0", 1, "/dev/mmcblk0p1"},
		{"/dev/loop3", 2, "/dev/loop3p2"},
		{"/dev/xvda", 3, "/dev/xvda3"},
		{"", 1, ""},
	}
	for _, tc := range tests {
		if got := Path(tc.disk, tc.n); got != tc.want {
			t.Errorf("Path(%q, %d) = %q, want %q", tc.disk, tc.n, got, tc.want)
		}
	}
}

func TestParent(t *testing.T) {
	tests := []struct {
		part string
		disk string
		n    int
	}{
		{"/dev/sda2", "/dev/sda", 2},
		{"/dev/vda1", "/dev/vda", 1},
		{"/dev/nvme0n1p2", "/dev/nvme0n1", 2},
		{"/dev/mmcblk0p1", "/dev/mmcblk0", 1},
		{"/dev/loop3p2", "/dev/loop3", 2},
		{"/dev/sda12", "/dev/sda", 12},
	}
	for _, tc := range tests {
		disk, n, err := Parent(tc.part)
		if err != nil {
			t.Fatalf("Parent(%q) returned error: %v", tc.part, err)
		}
		if disk != tc.disk || n != tc.n {
			t.Errorf("Parent(%q) = (%q, %d), want (%q, %d)", tc.part, disk, n, tc.disk, tc.n)
		}
		if got := Path(disk, n); got != tc.part {
			t.Errorf("Path(Parent(%q)) = %q, does not round-trip", tc.part, got)
		}
	}
}

func TestParentRejectsNonPartitions(t *testing.T) {
	for _, part := range []string{"", "/dev/sda", "/dev/mapper/cryptroot", "/dev/mapper/vg0-root", "1234", "/dev/loop0", "/dev/", "/dev/sda0"} {
		_, _, err := Parent(part)
		var notPart *NotAPartitionError
		if !errors.As(err, &notPart) {
			t.Errorf("Parent(%q) error = %v, want *NotAPartitionError", part, err)
			continue
		}
		if notPart.Path != part {
			t.Errorf("NotAPartitionError.Path = %q, want %q", notPart.Path, part)
		}
	}
}

// fakeInfo is the FileInfo the injected stat returns for a block device.
type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }

// blockDevices builds a stat function that reports the listed paths as block
// devices, charDevices as character devices, and everything else as missing.
func blockDevices(block []string, charDevices ...string) func(string) (os.FileInfo, error) {
	return func(path string) (os.FileInfo, error) {
		for _, b := range block {
			if b == path {
				return fakeInfo{name: filepath.Base(path), mode: os.ModeDevice}, nil
			}
		}
		for _, c := range charDevices {
			if c == path {
				return fakeInfo{name: filepath.Base(path), mode: os.ModeDevice | os.ModeCharDevice}, nil
			}
		}
		return nil, os.ErrNotExist
	}
}

func noSymlinks(string) (string, error) { return "", os.ErrNotExist }

func TestFindESPSiblingOfRootPartition(t *testing.T) {
	tests := []struct {
		root string
		want string
	}{
		{"/dev/sda2", "/dev/sda1"},
		{"/dev/nvme0n1p2", "/dev/nvme0n1p1"},
		{"/dev/mmcblk0p2", "/dev/mmcblk0p1"},
		{"/dev/loop7p2", "/dev/loop7p1"},
	}
	for _, tc := range tests {
		got, err := FindESP(tc.root, WithStat(blockDevices([]string{tc.want})), WithEvalSymlinks(noSymlinks))
		if err != nil {
			t.Fatalf("FindESP(%q) error: %v", tc.root, err)
		}
		if got != tc.want {
			t.Errorf("FindESP(%q) = %q, want %q", tc.root, got, tc.want)
		}
	}
}

func TestFindESPPrefersSiblingOverLabelAndProbe(t *testing.T) {
	stat := blockDevices([]string{"/dev/mmcblk0p1", "/dev/sda1", "/dev/vda1"})
	labelOnly := func(path string) (string, error) {
		if path == "/dev/disk/by-label/EFI" {
			return "/dev/sda1", nil
		}
		return "", os.ErrNotExist
	}
	got, err := FindESP("/dev/mmcblk0p2", WithStat(stat), WithEvalSymlinks(labelOnly))
	if err != nil {
		t.Fatalf("FindESP error: %v", err)
	}
	if got != "/dev/mmcblk0p1" {
		t.Errorf("FindESP = %q, want the sibling /dev/mmcblk0p1", got)
	}
}

// A diskless-nbd node's sealed key and pcr-banks live in the metadata
// partition of its NBD export (docs/installer/engineering.md). The unseal code
// finds it from the root, /dev/nbd0p2, even when a local SD card carries an
// EFI-labelled partition of its own.
func TestFindESPNBDExportMetadataPartition(t *testing.T) {
	stat := blockDevices([]string{"/dev/nbd0p1", "/dev/mmcblk0p1"})
	localLabel := func(path string) (string, error) {
		if path == "/dev/disk/by-label/EFI" {
			return "/dev/mmcblk0p1", nil
		}
		return "", os.ErrNotExist
	}
	got, err := FindESP("/dev/nbd0p2", WithStat(stat), WithEvalSymlinks(localLabel))
	if err != nil {
		t.Fatalf("FindESP error: %v", err)
	}
	if got != "/dev/nbd0p1" {
		t.Errorf("FindESP = %q, want the export's metadata partition /dev/nbd0p1", got)
	}
}

func TestFindESPByLabelWhenRootIsDeviceMapper(t *testing.T) {
	stat := blockDevices([]string{"/dev/mmcblk1p1"})
	eval := func(path string) (string, error) {
		if path == "/dev/disk/by-label/EFI" {
			return "/dev/mmcblk1p1", nil
		}
		return "", os.ErrNotExist
	}
	got, err := FindESP("/dev/mapper/cryptroot", WithStat(stat), WithEvalSymlinks(eval))
	if err != nil {
		t.Fatalf("FindESP error: %v", err)
	}
	if got != "/dev/mmcblk1p1" {
		t.Errorf("FindESP = %q, want /dev/mmcblk1p1 from the EFI label", got)
	}
}

func TestFindESPProbeListOrderAndDevDir(t *testing.T) {
	stat := blockDevices([]string{"/devices/nvme0n1p1", "/devices/mmcblk0p1"})
	got, err := FindESP("", WithStat(stat), WithEvalSymlinks(noSymlinks), WithDevDir("/devices"))
	if err != nil {
		t.Fatalf("FindESP error: %v", err)
	}
	if got != "/devices/nvme0n1p1" {
		t.Errorf("FindESP = %q, want the first probe hit /devices/nvme0n1p1", got)
	}

	got, err = FindESP("", WithStat(stat), WithEvalSymlinks(noSymlinks), WithDevDir("/devices"), WithCandidates([]string{"mmcblk0p1"}))
	if err != nil {
		t.Fatalf("FindESP with custom candidates error: %v", err)
	}
	if got != "/devices/mmcblk0p1" {
		t.Errorf("FindESP = %q, want /devices/mmcblk0p1", got)
	}
}

func TestFindESPIgnoresCharacterDevicesAndRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sda1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stat := blockDevices(nil, "/dev/sda1")
	_, err := FindESP("/dev/sda2", WithStat(stat), WithEvalSymlinks(noSymlinks))
	var notFound *ESPNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("FindESP error = %v, want *ESPNotFoundError", err)
	}
	if notFound.RootDevice != "/dev/sda2" {
		t.Errorf("ESPNotFoundError.RootDevice = %q", notFound.RootDevice)
	}
	if len(notFound.Tried) != 1+1+len(DefaultESPCandidates) {
		t.Errorf("ESPNotFoundError.Tried = %v, want sibling + label + %d candidates", notFound.Tried, len(DefaultESPCandidates))
	}

	// A regular file under a real device directory is not a block device.
	_, err = FindESP("", WithDevDir(dir))
	if !errors.As(err, &notFound) {
		t.Fatalf("FindESP with regular files error = %v, want *ESPNotFoundError", err)
	}
}

func TestFindESPDoesNotReturnTheRootDeviceItself(t *testing.T) {
	// A whole-disk name that Parent misreads as a partition must never be
	// reported as its own ESP.
	stat := blockDevices([]string{"/dev/nvme0n1"})
	_, err := FindESP("/dev/nvme0n1", WithStat(stat), WithEvalSymlinks(noSymlinks))
	var notFound *ESPNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("FindESP error = %v, want *ESPNotFoundError", err)
	}
}

func TestErrorMessages(t *testing.T) {
	if got := (&NotAPartitionError{Path: "/dev/sda"}).Error(); got != "partition: /dev/sda is not a partition path" {
		t.Errorf("NotAPartitionError.Error() = %q", got)
	}
	got := (&ESPNotFoundError{RootDevice: "/dev/sda2", Tried: []string{"/dev/sda1", "/dev/vda1"}}).Error()
	if got != "partition: no EFI system partition found for root device /dev/sda2 (tried /dev/sda1, /dev/vda1)" {
		t.Errorf("ESPNotFoundError.Error() = %q", got)
	}
}

func TestFindESPResolvesSymlinkedRootDevice(t *testing.T) {
	stat := blockDevices([]string{"/dev/nvme0n1p1", "/dev/sda1"})
	eval := func(path string) (string, error) {
		if path == "/dev/disk/by-uuid/1234-abcd" {
			return "/dev/nvme0n1p2", nil
		}
		return "", os.ErrNotExist
	}
	got, err := FindESP("/dev/disk/by-uuid/1234-abcd", WithStat(stat), WithEvalSymlinks(eval))
	if err != nil {
		t.Fatalf("FindESP error: %v", err)
	}
	if got != "/dev/nvme0n1p1" {
		t.Errorf("FindESP = %q, want the sibling of the resolved root /dev/nvme0n1p1", got)
	}
}
