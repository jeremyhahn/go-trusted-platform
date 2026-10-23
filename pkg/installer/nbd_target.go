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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

const (
	// nbdTargetDevice is the block device a diskless-nbd install writes to:
	// the node's NBD export, attached before the installer runs.
	nbdTargetDevice = "/dev/nbd0"

	// defaultSysfsRoot is where the attachment of nbdTargetDevice is read.
	defaultSysfsRoot = "/sys"
)

// useNBDTarget points a diskless-nbd install at nbdTargetDevice, partitioned
// GPT. It refuses, before Install clears the TPM or touches a disk, a
// configuration without LUKS (the export's root is always LUKS2) and a device
// that is not an attached NBD export. The disk manager shares i.config.Disk, so every
// partition, LUKS and mount step that follows uses the export.
func (i *installer) useNBDTarget() error {
	if i.config.Disk == nil || i.config.Disk.Encryption == nil {
		return ErrNBDTarget("refusing to install", &NBDTargetError{
			Device: nbdTargetDevice,
			Reason: "a diskless-nbd root must be LUKS2-encrypted; disk.encryption is not set",
		})
	}
	if err := checkNBDAttached(i.sysfsPath(), nbdTargetDevice); err != nil {
		return ErrNBDTarget("refusing to install", err)
	}
	if i.config.Disk.Device != nbdTargetDevice || i.config.Disk.PartitionTable != PartitionTableGPT {
		i.logger.Info("[INSTALLER] diskless-nbd node: installing to the NBD export",
			"configured_device", i.config.Disk.Device, "device", nbdTargetDevice,
			"configured_partition_table", i.config.Disk.PartitionTable, "partition_table", PartitionTableGPT)
	}
	i.config.Disk.Device = nbdTargetDevice
	// The boot server reads the installed UKI out of the metadata area
	// (nbd.OpenMetadataFile), so its layout is fixed: GPT, whatever the
	// profile chose for a local disk (a Pi's is MBR, for its firmware).
	i.config.Disk.PartitionTable = PartitionTableGPT
	return nil
}

func (i *installer) sysfsPath() string {
	if i.sysfsRoot != "" {
		return i.sysfsRoot
	}
	return defaultSysfsRoot
}

// checkNBDAttached reports whether device is an NBD device the kernel has
// connected to a server. The nbd driver creates <sysfs>/block/<name>/pid only
// while a client holds the connection, and size (in 512-byte sectors) is the
// export's; a module loaded with no export attached has neither.
func checkNBDAttached(sysfsRoot, device string) error {
	name := filepath.Base(device)
	blockDir := filepath.Join(sysfsRoot, "block", name)
	if _, err := os.Stat(blockDir); err != nil {
		return &NBDTargetError{Device: device, Reason: "no such block device (" + blockDir + ")"}
	}
	if _, err := os.Stat(filepath.Join(blockDir, "pid")); err != nil {
		return &NBDTargetError{Device: device, Reason: "not attached to an NBD export (no pid)"}
	}
	raw, err := os.ReadFile(filepath.Join(blockDir, "size"))
	if err != nil {
		return &NBDTargetError{Device: device, Reason: "size unreadable: " + err.Error()}
	}
	sectors, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return &NBDTargetError{Device: device, Reason: "size is not a number: " + strconv.Quote(strings.TrimSpace(string(raw)))}
	}
	if sectors == 0 {
		return &NBDTargetError{Device: device, Reason: "attached export has size 0"}
	}
	return nil
}

// nbdCmdlineParams are the root parameters a diskless-nbd UKI carries: the
// boot model and the NBD server the initrd attaches its root from. There is
// no root=, rd.luks.* or rd.lvm.* device: the root is on the export, which
// exists only once platform-initrd has attached it.
func nbdCmdlineParams(server nbd.ServerAddr) []string {
	return []string{disklessroot.ParamBootModel + "=" + nbd.BootModel, server.Arg()}
}

// espFstabSource names the partition the installed system mounts at
// /boot/efi. A diskless-nbd node mounts the export's metadata partition by
// path, so a local partition labelled EFI (an old SD card) can never take its
// place and receive the sealed key.
func espFstabSource(diskInfo *DiskInfo) string {
	if diskInfo.Device == nbdTargetDevice {
		return diskInfo.EFIPartition
	}
	return "LABEL=EFI"
}
