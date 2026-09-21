// Package partition names and locates disk partitions the way the Linux
// kernel does.
//
// The kernel derives a partition's device name from its disk: it appends the
// partition number directly (sda -> sda2) unless the disk name already ends in
// a digit, in which case it inserts a "p" first (nvme0n1 -> nvme0n1p2,
// mmcblk0 -> mmcblk0p2, loop3 -> loop3p2). Every installer, initramfs and
// first-boot path that derives one device from another goes through this
// package so the rule lives in exactly one place.
package partition

import (
	"os"
	"path/filepath"
	"strconv"
)

// DefaultESPCandidates lists the well-known first-partition device names
// FindESP probes, relative to the device directory, after the sibling and
// by-label lookups have failed. The order is the historical probe order of
// the initramfs strategies with the SD-card names appended.
var DefaultESPCandidates = []string{
	"vda1",      // VirtIO disk (QEMU/KVM)
	"sda1",      // SCSI/SATA disk
	"nvme0n1p1", // NVMe disk
	"mmcblk0p1", // SD card / eMMC (Raspberry Pi)
	"mmcblk1p1", // second MMC controller
}

// espLabel is the filesystem label the installer writes on the EFI system
// partition (pkg/installer/disk.go formats it with "EFI").
const espLabel = "EFI"

// Path returns the device path of partition n on disk.
func Path(disk string, n int) string {
	if disk == "" {
		return ""
	}
	if isDigit(disk[len(disk)-1]) {
		return disk + "p" + strconv.Itoa(n)
	}
	return disk + strconv.Itoa(n)
}

// Parent returns the disk a partition path belongs to and the partition
// number, inverting Path. It works on the name alone, so a whole-disk name
// that itself ends in digits and does not carry the "p" separator (nvme0n1,
// loop0, mmcblk0) is reported as a partition of the shorter name; callers
// that may receive whole disks must not rely on Parent to reject them.
func Parent(part string) (string, int, error) {
	end := len(part)
	for end > 0 && isDigit(part[end-1]) {
		end--
	}
	if end == 0 || end == len(part) {
		return "", 0, &NotAPartitionError{Path: part}
	}
	n, err := strconv.Atoi(part[end:])
	if err != nil {
		return "", 0, &NotAPartitionError{Path: part}
	}
	if n < 1 {
		return "", 0, &NotAPartitionError{Path: part}
	}
	disk := part[:end]
	if len(disk) >= 2 && disk[len(disk)-1] == 'p' && isDigit(disk[len(disk)-2]) {
		disk = disk[:len(disk)-1]
	}
	if disk == "" || disk[len(disk)-1] == '/' {
		return "", 0, &NotAPartitionError{Path: part}
	}
	return disk, n, nil
}

// Option configures FindESP.
type Option func(*finder)

type finder struct {
	stat         func(string) (os.FileInfo, error)
	evalSymlinks func(string) (string, error)
	devDir       string
	candidates   []string
}

// WithStat replaces the stat function used to test candidate devices. Tests
// use it to describe block devices that do not exist on the host.
func WithStat(stat func(string) (os.FileInfo, error)) Option {
	return func(f *finder) { f.stat = stat }
}

// WithEvalSymlinks replaces the symlink resolver used for the by-label lookup.
func WithEvalSymlinks(eval func(string) (string, error)) Option {
	return func(f *finder) { f.evalSymlinks = eval }
}

// WithDevDir replaces the device directory (default /dev) that the by-label
// lookup and the candidate probe are rooted in.
func WithDevDir(dir string) Option {
	return func(f *finder) { f.devDir = dir }
}

// WithCandidates replaces DefaultESPCandidates for one lookup.
func WithCandidates(names []string) Option {
	return func(f *finder) { f.candidates = names }
}

// FindESP locates the EFI system partition that belongs to rootDevice.
//
// Three strategies run in order and the first block device wins: the first
// partition of the disk rootDevice sits on (when rootDevice, after symlink
// resolution, is a partition path), the partition labelled EFI under
// <devDir>/disk/by-label, and finally the candidate probe list. A rootDevice
// that is not a partition path (a device-mapper name, an unresolvable UUID)
// simply skips the first strategy. The returned error lists every path that
// was tried.
func FindESP(rootDevice string, opts ...Option) (string, error) {
	f := &finder{
		stat:         os.Stat,
		evalSymlinks: filepath.EvalSymlinks,
		devDir:       "/dev",
		candidates:   DefaultESPCandidates,
	}
	for _, opt := range opts {
		opt(f)
	}

	var tried []string
	// A root given as /dev/disk/by-uuid/<uuid> (what the dracut hook passes
	// from rd.luks.uuid) names its disk only once the symlink is resolved.
	if resolved, err := f.evalSymlinks(rootDevice); err == nil && resolved != "" {
		rootDevice = resolved
	}
	if disk, _, err := Parent(rootDevice); err == nil {
		sibling := Path(disk, 1)
		if sibling != rootDevice {
			tried = append(tried, sibling)
			if f.isBlockDevice(sibling) {
				return sibling, nil
			}
		}
	}

	byLabel := filepath.Join(f.devDir, "disk", "by-label", espLabel)
	tried = append(tried, byLabel)
	if resolved, err := f.evalSymlinks(byLabel); err == nil && f.isBlockDevice(resolved) {
		return resolved, nil
	}

	for _, name := range f.candidates {
		candidate := filepath.Join(f.devDir, name)
		tried = append(tried, candidate)
		if f.isBlockDevice(candidate) {
			return candidate, nil
		}
	}

	return "", &ESPNotFoundError{RootDevice: rootDevice, Tried: tried}
}

// isBlockDevice reports whether path stats as a block device node.
func (f *finder) isBlockDevice(path string) bool {
	info, err := f.stat(path)
	if err != nil {
		return false
	}
	mode := info.Mode()
	return mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
