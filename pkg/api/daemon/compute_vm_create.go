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
	"math"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vmCreateRefusal is one VMConfig field the compute backend cannot honour.
// refuses reports whether a request sets it.
type vmCreateRefusal struct {
	field   string
	reason  string
	refuses func(config *platformv1.VMConfig) bool
}

// firstDisk and firstNetwork return a VM's only disk and NIC, or nil; the
// generated getters are nil-safe, so the refusals read through them freely.
func firstDisk(config *platformv1.VMConfig) *platformv1.DiskConfig {
	if len(config.GetDisks()) == 0 {
		return nil
	}
	return config.GetDisks()[0]
}

func firstNetwork(config *platformv1.VMConfig) *platformv1.NetworkConfig {
	if len(config.GetNetworks()) == 0 {
		return nil
	}
	return config.GetNetworks()[0]
}

// vmCreateRefusals lists every VMConfig setting CreateVM refuses. A VM gets
// UEFI firmware, one qcow2 boot disk on the architecture's bus, one
// virtio-net NIC on the orchestrator's bridge, an emulated TPM 2.0 and no
// display; a request for anything else is refused rather than ignored.
var vmCreateRefusals = []vmCreateRefusal{
	{"firmware", "VMs boot UEFI firmware; BIOS is not available", func(c *platformv1.VMConfig) bool {
		f := c.GetFirmware()
		return f != platformv1.FirmwareType_FIRMWARE_TYPE_UNSPECIFIED &&
			f != platformv1.FirmwareType_FIRMWARE_TYPE_UEFI &&
			f != platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT
	}},
	{"boot_device", "VMs boot from their disk or the network; CD-ROM boot needs an installation ISO, which CreateVM cannot carry", func(c *platformv1.VMConfig) bool {
		d := c.GetBootDevice()
		return d != platformv1.BootDevice_BOOT_DEVICE_UNSPECIFIED &&
			d != platformv1.BootDevice_BOOT_DEVICE_DISK &&
			d != platformv1.BootDevice_BOOT_DEVICE_NETWORK
	}},
	{"cpu.sockets", "vCPUs are cores on one socket", func(c *platformv1.VMConfig) bool { return c.GetCpu().GetSockets() > 1 }},
	{"cpu.threads", "vCPUs are cores with one thread each", func(c *platformv1.VMConfig) bool { return c.GetCpu().GetThreads() > 1 }},
	{"cpu.model", "the CPU model is not selectable", func(c *platformv1.VMConfig) bool { return c.GetCpu().GetModel() != "" }},
	{"cpu.features", "CPU features are not selectable", func(c *platformv1.VMConfig) bool { return len(c.GetCpu().GetFeatures()) > 0 }},
	{"memory.size_mb", "the size is out of range", func(c *platformv1.VMConfig) bool { return c.GetMemory().GetSizeMb() > math.MaxInt32 }},
	{"memory.hugepages", "huge pages are not available", func(c *platformv1.VMConfig) bool { return c.GetMemory().GetHugepages() }},
	{"memory.shared", "shared memory is not available", func(c *platformv1.VMConfig) bool { return c.GetMemory().GetShared() }},
	{"disks", "a VM has one disk, its boot disk; attach more with AttachVMDisk", func(c *platformv1.VMConfig) bool { return len(c.GetDisks()) > 1 }},
	{"disks[0].id", "disk ids are assigned by the orchestrator", func(c *platformv1.VMConfig) bool { return firstDisk(c).GetId() != "" }},
	{"disks[0].path", "the boot disk is created by the orchestrator; an existing image cannot be used", func(c *platformv1.VMConfig) bool { return firstDisk(c).GetPath() != "" }},
	{"disks[0].type", "the boot disk is qcow2", func(c *platformv1.VMConfig) bool {
		t := firstDisk(c).GetType()
		return t != platformv1.DiskType_DISK_TYPE_UNSPECIFIED && t != platformv1.DiskType_DISK_TYPE_QCOW2
	}},
	{"disks[0].bus", "the boot disk is on SATA (x86_64) or virtio (aarch64)", func(c *platformv1.VMConfig) bool {
		b := firstDisk(c).GetBus()
		return b != platformv1.DiskBus_DISK_BUS_UNSPECIFIED && b != platformv1.DiskBus_DISK_BUS_SATA && b != platformv1.DiskBus_DISK_BUS_VIRTIO
	}},
	{"disks[0].size_gb", "the size is out of range", func(c *platformv1.VMConfig) bool { return firstDisk(c).GetSizeGb() > math.MaxInt32 }},
	{"disks[0].readonly", "the boot disk is writable", func(c *platformv1.VMConfig) bool { return firstDisk(c).GetReadonly() }},
	{"disks[0].backing_file", "the boot disk has no backing file", func(c *platformv1.VMConfig) bool { return firstDisk(c).GetBackingFile() != "" }},
	{"networks", "a VM has one NIC; attach more with AttachNetwork", func(c *platformv1.VMConfig) bool { return len(c.GetNetworks()) > 1 }},
	{"networks[0].id", "NIC ids are assigned by the orchestrator", func(c *platformv1.VMConfig) bool { return firstNetwork(c).GetId() != "" }},
	{"networks[0].model", "the NIC is virtio-net", func(c *platformv1.VMConfig) bool {
		m := firstNetwork(c).GetModel()
		return m != platformv1.NetworkModel_NETWORK_MODEL_UNSPECIFIED && m != platformv1.NetworkModel_NETWORK_MODEL_VIRTIO
	}},
	{"networks[0].vlan", "VLANs are assigned by the network policy, not at create", func(c *platformv1.VMConfig) bool { return firstNetwork(c).GetVlan() != 0 }},
	{"networks[0].bandwidth_limit_mbps", "NIC bandwidth limits are not available", func(c *platformv1.VMConfig) bool { return firstNetwork(c).GetBandwidthLimitMbps() != 0 }},
	{"graphics", "VMs have no display; use the serial console", func(c *platformv1.VMConfig) bool {
		g := c.GetGraphics()
		t := g.GetType()
		return (t != platformv1.GraphicsType_GRAPHICS_TYPE_UNSPECIFIED && t != platformv1.GraphicsType_GRAPHICS_TYPE_NONE) ||
			g.GetListen() != "" || g.GetPort() != 0 || g.GetPassword() != "" || g.GetKeymap() != ""
	}},
	{"tpm.version", "the vTPM is TPM 2.0", func(c *platformv1.VMConfig) bool {
		v := c.GetTpm().GetVersion()
		return v != platformv1.TPMVersion_TPM_VERSION_UNSPECIFIED && v != platformv1.TPMVersion_TPM_VERSION_2_0
	}},
	{"tpm.device_path", "the vTPM is emulated; a host TPM cannot be passed through", func(c *platformv1.VMConfig) bool { return c.GetTpm().GetDevicePath() != "" }},
	{"tpm.state_dir", "the vTPM state lives in the VM's work directory", func(c *platformv1.VMConfig) bool { return c.GetTpm().GetStateDir() != "" }},
	{"nvram", "UEFI variables start from the configured template", func(c *platformv1.VMConfig) bool { return len(c.GetNvram()) > 0 }},
}

// vmDiskBuses maps the buses CreateVM accepts to the compute names; the
// rest are refused by vmCreateRefusals.
var vmDiskBuses = map[platformv1.DiskBus]string{
	platformv1.DiskBus_DISK_BUS_SATA:   compute.DiskBusSATA,
	platformv1.DiskBus_DISK_BUS_VIRTIO: compute.DiskBusVirtio,
}

// vmSpecFromConfig translates a CreateVM config into the compute VMSpec, or
// refuses the first field the backend cannot honour. Whether the backend
// can honour what remains on its architecture (the disk bus, secure boot,
// the bridge) is the orchestrator's check.
func vmSpecFromConfig(config *platformv1.VMConfig) (compute.VMSpec, error) {
	for _, refusal := range vmCreateRefusals {
		if refusal.refuses(config) {
			return compute.VMSpec{}, ErrVMCreateUnsupportedField{Field: refusal.field, Reason: refusal.reason}
		}
	}

	spec := compute.VMSpec{
		MemoryMB:    int(config.GetMemory().GetSizeMb()),
		CPUs:        int(config.GetCpu().GetCores()),
		DiskSizeGB:  int(firstDisk(config).GetSizeGb()),
		DiskBus:     vmDiskBuses[firstDisk(config).GetBus()],
		SecureBoot:  config.GetSecureBoot() || config.GetFirmware() == platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT,
		DisableTPM:  config.GetTpm() != nil && !config.GetTpm().GetEnabled(),
		MACAddress:  firstNetwork(config).GetMacAddress(),
		Bridge:      firstNetwork(config).GetBridge(),
		Description: config.GetDescription(),
		Labels:      config.GetLabels(),
		Metadata:    config.GetMetadata(),
	}
	if config.GetBootDevice() == platformv1.BootDevice_BOOT_DEVICE_NETWORK {
		spec.BootMode = compute.BootModePXE
	}
	return spec, nil
}

// vmConfigFirmware is the firmware a VM boots.
func vmConfigFirmware(secureBoot bool) platformv1.FirmwareType {
	if secureBoot {
		return platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT
	}
	return platformv1.FirmwareType_FIRMWARE_TYPE_UEFI
}

// vmConfigBootDevice is the device a VM boots from.
func vmConfigBootDevice(bootMode string) platformv1.BootDevice {
	if bootMode == compute.BootModePXE {
		return platformv1.BootDevice_BOOT_DEVICE_NETWORK
	}
	return platformv1.BootDevice_BOOT_DEVICE_DISK
}
