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

package compute

import (
	"maps"
	"path/filepath"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// archDiskBus is the bus each architecture attaches the boot disk on: AHCI
// SATA on x86_64, virtio-blk on aarch64.
var archDiskBus = map[qemu.Arch]string{
	qemu.ArchX86_64:  DiskBusSATA,
	qemu.ArchAArch64: DiskBusVirtio,
}

// bridgeName is the bridge every VM's primary NIC attaches to. The network
// attachment and port-auth paths are wired to it, so a VM cannot pick
// another one.
func (c *OrchestratorConfig) bridgeName() string {
	if c.NetworkBridge != "" {
		return c.NetworkBridge
	}
	return qemu.DefaultBridgeName
}

// checkVMSpec refuses what this orchestrator cannot honour: secure boot
// without a secure-boot firmware image (QEMU would boot the plain image
// instead), a disk bus the architecture does not use, and a bridge other
// than the orchestrator's.
func (o *QEMUOrchestrator) checkVMSpec(spec VMSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if spec.SecureBoot && o.config.OVMFCodeSecure == "" {
		return invalidVMSpec("secure boot needs a secure-boot firmware image, and ovmf_code_secure is not configured")
	}
	arch := o.config.Arch.OrDefault()
	if bus := archDiskBus[arch]; spec.DiskBus != "" && spec.DiskBus != bus {
		return invalidVMSpec("disk bus " + spec.DiskBus + " is not available on " + string(arch) + ", which uses " + bus)
	}
	if bridge := o.config.bridgeName(); spec.Bridge != "" && spec.Bridge != bridge {
		return invalidVMSpec("bridge " + spec.Bridge + " is not available; VMs attach to " + bridge)
	}
	return nil
}

// instanceConfig is the orchestrator's default VM with spec applied.
func (o *QEMUOrchestrator) instanceConfig(instanceID string, spec VMSpec) *InstanceConfig {
	cfg := &InstanceConfig{
		Memory:      o.config.DefaultMemory,
		CPUs:        o.config.DefaultCPUs,
		DiskSize:    o.config.DefaultDiskSize,
		WorkDir:     filepath.Join(o.config.WorkDir, instanceID),
		SecureBoot:  spec.SecureBoot,
		EnableKVM:   o.config.EnableKVM,
		TPMEnabled:  !spec.DisableTPM,
		NetworkMode: "bridge",
		MACAddress:  spec.MACAddress,
		BootMode:    BootModeDisk,
		Description: spec.Description,
		Labels:      maps.Clone(spec.Labels),
		Metadata:    maps.Clone(spec.Metadata),
	}
	if spec.MemoryMB > 0 {
		cfg.Memory = spec.MemoryMB
	}
	if spec.CPUs > 0 {
		cfg.CPUs = spec.CPUs
	}
	if spec.DiskSizeGB > 0 {
		cfg.DiskSize = strconv.Itoa(spec.DiskSizeGB) + "G"
	}
	if spec.BootMode != "" {
		cfg.BootMode = spec.BootMode
	}
	cfg.DiskPath = filepath.Join(cfg.WorkDir, "disk.qcow2")
	return cfg
}
