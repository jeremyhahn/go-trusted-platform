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

package installer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The EFI system partition as the installer mounts it, and the unified kernel
// image inside it. BOOTX64.EFI is the file firmware loads at the next POST:
// if it is absent or empty, the machine does not boot, whatever else the
// install achieved.
const (
	espMountPoint = "/mnt/boot/efi"
	espBootDir    = "EFI/BOOT"
	espUKIName    = "BOOTX64.EFI"
)

// syncUKIOnESP makes the unified kernel image durable on the EFI partition and
// proves it is there, using the installer's real mount point.
func (i *installer) syncUKIOnESP() error {
	return i.syncUKIOnESPAt(espMountPoint)
}

// syncUKIOnESPAt is syncUKIOnESP against an arbitrary ESP root so it can be
// exercised without a mounted partition.
//
// It replaces an fsync of the mount point itself. /mnt/boot/efi is a
// directory, so fsyncing it flushes directory metadata -- the name entry --
// and not BOOTX64.EFI's contents, which is not what a reader would take that
// call to mean. pkg/installer/uki_rebuild.go already does this correctly
// (file first, then the directory naming it); this brings the completion path
// into line with it.
//
// Every failure here returns rather than warns. The symptom of getting this
// wrong appears at the next boot, on a machine the installer has already
// reported success for, so there is no later opportunity to notice it.
func (i *installer) syncUKIOnESPAt(espRoot string) error {
	bootDir := filepath.Join(espRoot, espBootDir)
	ukiPath := filepath.Join(bootDir, espUKIName)

	f, err := os.Open(ukiPath)
	if err != nil {
		return ErrCompletion(
			"the unified kernel image is not readable on the EFI partition ("+ukiPath+"); the installed system would not boot", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			i.logger.Warn("[INSTALLER] failed to close UKI after fsync", "path", ukiPath, "error", closeErr)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return ErrCompletion("cannot stat the unified kernel image on the EFI partition ("+ukiPath+")", err)
	}
	// A zero-length BOOTX64.EFI is exactly as unbootable as an absent one, and
	// os.Stat succeeds for it. The previous code logged the size and continued.
	if info.Size() == 0 {
		return ErrCompletion(
			"the unified kernel image on the EFI partition ("+ukiPath+") is empty; the installed system would not boot", nil)
	}

	if err := f.Sync(); err != nil {
		return ErrCompletion("fsync of the unified kernel image ("+ukiPath+") failed", err)
	}

	// Then the directory that names it, so the entry survives too.
	d, err := os.Open(bootDir)
	if err != nil {
		return ErrCompletion("cannot open the EFI boot directory ("+bootDir+") to fsync it", err)
	}
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			i.logger.Warn("[INSTALLER] failed to close EFI boot directory after fsync", "path", bootDir, "error", closeErr)
		}
	}()
	if err := d.Sync(); err != nil {
		return ErrCompletion("fsync of the EFI boot directory ("+bootDir+") failed", err)
	}

	i.logger.Info("[INSTALLER] UKI fsynced and verified on the EFI partition",
		"path", ukiPath, "size", info.Size())
	return nil
}

// unmountOrFail unmounts a mount point, falling back to a lazy unmount, and
// fails the install when neither succeeds.
//
// A lazy unmount detaches the tree and completes the teardown once the last
// reference goes away, so it is a legitimate fallback. When it too is refused,
// the filesystem is still attached and still dirty at reboot -- for the FAT32
// EFI partition that is how a written UKI fails to be a readable one.
//
// unmount is unix.Unmount in production and a substitute under test; the
// syscall is the only part of this that cannot run in a unit test.
func (i *installer) unmountOrFail(mountPoint string, unmount func(target string, flags int) error) error {
	i.logger.Info("[INSTALLER] Unmounting", "path", mountPoint)
	if err := unmount(mountPoint, 0); err == nil {
		return nil
	} else {
		i.logger.Warn("[INSTALLER] Regular unmount failed, trying lazy unmount", "path", mountPoint, "error", err)
	}

	if err := unmount(mountPoint, unix.MNT_DETACH); err != nil {
		return ErrCompletion(
			"could not unmount "+mountPoint+", even lazily; it would still be mounted and unflushed at reboot", err)
	}
	i.logger.Info("[INSTALLER] Lazy unmount succeeded", "path", mountPoint)
	return nil
}

// flushBuffers runs `blockdev --flushbufs` against a device and decides whether
// a failure should end the install.
//
// The distinction matters and is the reason this is not a plain "return the
// error". These calls sit AFTER a unix.Sync() that already blocked until
// writeback completed, so they are a second belt rather than the only one:
//
//   - The device refused the flush (non-zero exit). Something is wrong with
//     the write path and the data may not be durable. Fail the install.
//   - blockdev is not present or not executable. Nothing was attempted, and
//     the preceding sync already did the work. Record it and continue --
//     failing here would turn a missing optional tool into a failed install
//     on hardware where the install actually succeeded.
func (i *installer) flushBuffers(ctx context.Context, device string, run commandRunner) error {
	output, err := run(ctx, "blockdev", "--flushbufs", device)
	if err == nil {
		return nil
	}
	if !flushFailureIsFatal(err) {
		i.logger.Warn("[INSTALLER] blockdev unavailable; relying on the preceding sync",
			"device", device, "error", err, "output", string(output))
		return nil
	}
	return ErrCompletion("blockdev --flushbufs was refused by "+device+
		"; pending writes may not have reached the disk ("+string(output)+")", err)
}

// commandRunner runs a command and returns its combined output. runCommand is
// the production implementation; tests substitute it so the classification
// below can be exercised without depending on whether the host has blockdev.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// runCommand is the production commandRunner.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// flushFailureIsFatal reports whether a blockdev failure means the device
// refused to flush, as opposed to blockdev being unavailable to ask.
//
// exec reports an unavailable binary as *exec.Error (from LookPath) and a
// command that ran and failed as *exec.ExitError. Anything else -- a cancelled
// context, most obviously -- is treated as fatal, because the install is being
// torn down and completing it would be reporting success for work that stopped.
func flushFailureIsFatal(err error) bool {
	if err == nil {
		return false
	}
	var lookupErr *exec.Error
	return !errors.As(err, &lookupErr)
}
