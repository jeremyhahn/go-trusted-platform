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

package initrd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// PartitionScheme defines the disk partition layout
type PartitionScheme struct {
	Device        string // e.g., /dev/vda
	EFIPartition  string // e.g., /dev/vda1
	RootPartition string // e.g., /dev/vda2
	EFISize       string // e.g., "512M"
	MountPoint    string // e.g., /mnt
}

// DiskPreparer handles OS-agnostic disk preparation
type DiskPreparer struct {
	scheme *PartitionScheme
	logger *logging.Logger
}

// NewDiskPreparer creates a new disk preparer
func NewDiskPreparer(device string, mountPoint string, logger *logging.Logger) *DiskPreparer {
	return &DiskPreparer{
		scheme: &PartitionScheme{
			Device:        device,
			EFIPartition:  device + "1",
			RootPartition: device + "2",
			EFISize:       "512M",
			MountPoint:    mountPoint,
		},
		logger: logger,
	}
}

// PartitionDisk creates GPT partition table with EFI and root partitions
func (dp *DiskPreparer) PartitionDisk(ctx context.Context) error {
	dp.logger.Info("[DISK] Creating GPT partition table", "device", dp.scheme.Device)

	// Wipe any existing partition table
	if err := dp.runCommand(ctx, "wipefs", "-a", dp.scheme.Device); err != nil {
		dp.logger.Warn("Failed to wipe existing partition table (may not exist)", "error", err)
	}

	// Create GPT partition table
	dp.logger.Info("[DISK] Creating new GPT partition table")
	if err := dp.runCommand(ctx, "parted", "-s", dp.scheme.Device, "mklabel", "gpt"); err != nil {
		return &WrappedError{Msg: "failed to create GPT partition table", Err: err}
	}

	// Create EFI System Partition (512MB)
	dp.logger.Info("[DISK] Creating EFI System Partition", "size", dp.scheme.EFISize)
	if err := dp.runCommand(ctx, "parted", "-s", dp.scheme.Device,
		"mkpart", "primary", "fat32", "1MiB", dp.scheme.EFISize); err != nil {
		return &WrappedError{Msg: "failed to create EFI partition", Err: err}
	}

	// Set ESP flag on first partition
	if err := dp.runCommand(ctx, "parted", "-s", dp.scheme.Device, "set", "1", "esp", "on"); err != nil {
		return &WrappedError{Msg: "failed to set ESP flag", Err: err}
	}

	// Create root partition (remaining space)
	dp.logger.Info("[DISK] Creating root partition", "start", dp.scheme.EFISize)
	if err := dp.runCommand(ctx, "parted", "-s", dp.scheme.Device,
		"mkpart", "primary", "ext4", dp.scheme.EFISize, "100%"); err != nil {
		return &WrappedError{Msg: "failed to create root partition", Err: err}
	}

	// Wait for kernel to re-read partition table
	dp.logger.Info("[DISK] Waiting for kernel to recognize new partitions")
	time.Sleep(2 * time.Second)

	// Inform kernel of partition changes
	if err := dp.runCommand(ctx, "partprobe", dp.scheme.Device); err != nil {
		dp.logger.Warn("partprobe failed (may not be critical)", "error", err)
	}

	// Additional wait for udev
	time.Sleep(2 * time.Second)

	dp.logger.Info("[DISK] Partition table created successfully",
		"efi_partition", dp.scheme.EFIPartition,
		"root_partition", dp.scheme.RootPartition)

	return nil
}

// FormatEFIPartition formats the EFI System Partition as FAT32
func (dp *DiskPreparer) FormatEFIPartition(ctx context.Context) error {
	dp.logger.Info("[DISK] Formatting EFI partition as FAT32", "partition", dp.scheme.EFIPartition)

	if err := dp.runCommand(ctx, "mkfs.fat", "-F", "32", "-n", "EFI", dp.scheme.EFIPartition); err != nil {
		return &WrappedError{Msg: "failed to format EFI partition", Err: err}
	}

	dp.logger.Info("[DISK] EFI partition formatted successfully")
	return nil
}

// FormatRootFilesystem formats the opened LUKS volume with ext4
func (dp *DiskPreparer) FormatRootFilesystem(ctx context.Context, luksDevicePath string) error {
	dp.logger.Info("[DISK] Formatting root filesystem as ext4", "device", luksDevicePath)

	if err := dp.runCommand(ctx, "mkfs.ext4", "-L", "root", luksDevicePath); err != nil {
		return &WrappedError{Msg: "failed to format root filesystem", Err: err}
	}

	dp.logger.Info("[DISK] Root filesystem formatted successfully")
	return nil
}

// MountFilesystems mounts the prepared filesystems
func (dp *DiskPreparer) MountFilesystems(ctx context.Context, luksDevicePath string) error {
	// Create mount points
	dp.logger.Info("[DISK] Creating mount point", "path", dp.scheme.MountPoint)
	if err := dp.runCommand(ctx, "mkdir", "-p", dp.scheme.MountPoint); err != nil {
		return &WrappedError{Msg: "failed to create mount point", Err: err}
	}

	// Mount root filesystem
	dp.logger.Info("[DISK] Mounting root filesystem", "device", luksDevicePath, "mount", dp.scheme.MountPoint)
	if err := dp.runCommand(ctx, "mount", luksDevicePath, dp.scheme.MountPoint); err != nil {
		return &WrappedError{Msg: "failed to mount root filesystem", Err: err}
	}

	// Create boot directory
	bootDir := dp.scheme.MountPoint + "/boot"
	dp.logger.Info("[DISK] Creating boot directory", "path", bootDir)
	if err := dp.runCommand(ctx, "mkdir", "-p", bootDir); err != nil {
		return &WrappedError{Msg: "failed to create boot directory", Err: err}
	}

	// Mount EFI partition
	dp.logger.Info("[DISK] Mounting EFI partition", "device", dp.scheme.EFIPartition, "mount", bootDir)
	if err := dp.runCommand(ctx, "mount", dp.scheme.EFIPartition, bootDir); err != nil {
		return &WrappedError{Msg: "failed to mount EFI partition", Err: err}
	}

	dp.logger.Info("[DISK] All filesystems mounted successfully")
	return nil
}

// UnmountFilesystems unmounts all filesystems
func (dp *DiskPreparer) UnmountFilesystems(ctx context.Context) error {
	// Unmount in reverse order
	bootDir := dp.scheme.MountPoint + "/boot"

	dp.logger.Info("[DISK] Unmounting EFI partition", "mount", bootDir)
	if err := dp.runCommand(ctx, "umount", bootDir); err != nil {
		dp.logger.Warn("Failed to unmount EFI partition", "error", err)
	}

	dp.logger.Info("[DISK] Unmounting root filesystem", "mount", dp.scheme.MountPoint)
	if err := dp.runCommand(ctx, "umount", dp.scheme.MountPoint); err != nil {
		return &WrappedError{Msg: "failed to unmount root filesystem", Err: err}
	}

	dp.logger.Info("[DISK] All filesystems unmounted successfully")
	return nil
}

// GetScheme returns the partition scheme
func (dp *DiskPreparer) GetScheme() *PartitionScheme {
	return dp.scheme
}

// runCommand executes a shell command with logging
func (dp *DiskPreparer) runCommand(ctx context.Context, name string, args ...string) error {
	cmdStr := name + " " + strings.Join(args, " ")
	dp.logger.Debug("[DISK] Executing command", "cmd", cmdStr)

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dp.logger.Error(&CommandError{Err: err, Output: string(output)}, "command", cmdStr)
		return &WrappedError{Msg: fmt.Sprintf("command failed: %s", cmdStr), Err: err}
	}

	if len(output) > 0 {
		dp.logger.Debug("[DISK] Command output", "output", string(output))
	}

	return nil
}
