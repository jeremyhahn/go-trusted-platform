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

package daemon

import (
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bootDiskID is the id the boot disk (InstanceConfig.DiskPath) is listed
// under. It is one of the boot aliases the disk manager accepts, so the id a
// client reads back can be passed to ResizeDisk unchanged.
const bootDiskID = "hd0"

// instanceDisksToProto lists the instance's disks for VMConfig.Disks: the boot
// disk first (when the config names one), then every attached disk in the
// order the orchestrator holds them, each with its real id.
func instanceDisksToProto(instance *compute.Instance) []*platformv1.DiskConfig {
	if instance == nil {
		return nil
	}
	var disks []*platformv1.DiskConfig
	if instance.Config != nil && instance.Config.DiskPath != "" {
		disks = append(disks, &platformv1.DiskConfig{
			Id:       bootDiskID,
			Path:     instance.Config.DiskPath,
			SizeGb:   diskSizeToGiB(instance.Config.DiskSize),
			Bootable: true,
		})
	}
	for _, d := range instance.Disks {
		disks = append(disks, &platformv1.DiskConfig{
			Id:       d.ID,
			Path:     d.Path,
			Bus:      diskBusFromString(d.Bus),
			SizeGb:   d.SizeGB,
			Readonly: d.Readonly,
			Bootable: d.Bootable,
		})
	}
	return disks
}

// diskBusFromString is the inverse of diskBusToString. Unknown or empty bus
// names map to DISK_BUS_UNSPECIFIED.
func diskBusFromString(bus string) platformv1.DiskBus {
	switch strings.ToLower(strings.TrimSpace(bus)) {
	case "virtio":
		return platformv1.DiskBus_DISK_BUS_VIRTIO
	case "sata":
		return platformv1.DiskBus_DISK_BUS_SATA
	case "scsi":
		return platformv1.DiskBus_DISK_BUS_SCSI
	case "ide":
		return platformv1.DiskBus_DISK_BUS_IDE
	case "nvme":
		return platformv1.DiskBus_DISK_BUS_NVME
	default:
		return platformv1.DiskBus_DISK_BUS_UNSPECIFIED
	}
}

// diskSizeToGiB converts a qemu-img style size ("10G", "512M", "1T", "20GiB",
// a plain byte count) to whole gibibytes, rounding sizes below a GiB up.
// An empty or unparseable size gives 0.
func diskSizeToGiB(size string) uint64 {
	s := strings.ToLower(strings.TrimSpace(size))
	if strings.HasSuffix(s, "ib") {
		s = strings.TrimSuffix(s, "ib")
	} else if strings.HasSuffix(s, "b") {
		s = strings.TrimSuffix(s, "b")
	}
	if s == "" {
		return 0
	}

	const (
		kib = uint64(1) << 10
		mib = uint64(1) << 20
		gib = uint64(1) << 30
	)
	var divisor, multiplier uint64 = 1, 1
	switch s[len(s)-1] {
	case 't':
		multiplier = 1024
		s = s[:len(s)-1]
	case 'g':
		s = s[:len(s)-1]
	case 'm':
		divisor = kib
		s = s[:len(s)-1]
	case 'k':
		divisor = mib
		s = s[:len(s)-1]
	default:
		divisor = gib
	}

	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	if multiplier > 1 {
		if n > ^uint64(0)/multiplier {
			return 0
		}
		return n * multiplier
	}
	if divisor > 1 {
		return n/divisor + boolToUint64(n%divisor != 0)
	}
	return n
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
