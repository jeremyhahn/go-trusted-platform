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
	"fmt"
	"runtime"
)

// IsVM reports whether the provider launches virtual machines (the local QEMU
// provider or one of its aliases). The daemon uses this to decide whether to
// construct a VM-typed orchestrator configuration — one carrying the QEMU
// binary and OVMF firmware paths the QEMU orchestrator requires — instead of
// the default container configuration. Cloud VM providers are launched through
// their own SDKs and validated separately, so they are not treated as local
// VMs here.
func (k ProviderKind) IsVM() bool {
	return k.normalize() == ProviderLocalQEMU
}

// ApplyLocalQEMUDefaults fills the QEMU/OVMF fields the local QEMU orchestrator
// requires with sensible defaults, without overwriting any value the operator
// already set. It is used by the daemon when the compute provider resolves to
// local-qemu so a minimal `compute: { provider: local-qemu }` config is
// sufficient to launch VMs. The compute Type is forced to VM.
//
// An unset Arch follows the host architecture, and the QEMU binary and
// firmware defaults follow Arch. A host with no compute VM guest architecture
// returns ErrUnsupportedHostArch rather than assuming x86_64.
func (c *OrchestratorConfig) ApplyLocalQEMUDefaults() error {
	return c.applyLocalQEMUDefaults(runtime.GOARCH)
}

// applyLocalQEMUDefaults is ApplyLocalQEMUDefaults for a host of the given Go
// architecture.
func (c *OrchestratorConfig) applyLocalQEMUDefaults(hostArch string) error {
	c.Type = ComputeTypeVM
	if c.Arch == "" {
		arch, ok := hostGuestArch[hostArch]
		if !ok {
			return &SentinelCauseError{Sentinel: ErrUnsupportedHostArch, Cause: &MessageError{Msg: fmt.Sprintf("host %q has no VM guest arch: set compute arch", hostArch)}}
		}
		c.Arch = arch
	}
	firmware, ok := vmFirmwareDefaults[c.Arch]
	if !ok {
		return unsupportedVMArchError(c.Arch)
	}
	c.fillVMFirmware(firmware)

	defaults := defaultOrchestratorConfig(ComputeTypeVM, hostArch)
	if c.DefaultDiskSize == "" {
		c.DefaultDiskSize = defaults.DefaultDiskSize
	}
	if c.NetworkBridge == "" {
		c.NetworkBridge = defaults.NetworkBridge
	}
	if c.MigrationListenAddress == "" {
		c.MigrationListenAddress = defaults.MigrationListenAddress
	}
	return nil
}
