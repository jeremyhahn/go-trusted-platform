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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultOrchestratorConfig_Arm64HostGetsAArch64AndAAVMF(t *testing.T) {
	cfg := defaultOrchestratorConfig(ComputeTypeVM, "arm64")

	assert.Equal(t, qemu.ArchAArch64, cfg.Arch)
	assert.Equal(t, "qemu-system-aarch64", cfg.QEMUBinary)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_CODE.fd", cfg.OVMFCode)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_CODE.fd", cfg.OVMFCodeSecure)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_VARS.fd", cfg.OVMFVars)
}

func TestDefaultOrchestratorConfig_Amd64HostStaysX86(t *testing.T) {
	cfg := defaultOrchestratorConfig(ComputeTypeVM, "amd64")

	assert.Equal(t, qemu.ArchX86_64, cfg.Arch)
	assert.Equal(t, "qemu-system-x86_64", cfg.QEMUBinary)
	assert.Equal(t, "/usr/share/OVMF/OVMF_CODE_4M.fd", cfg.OVMFCode)
	assert.Equal(t, "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd", cfg.OVMFCodeSecure)
	assert.Equal(t, "/usr/share/OVMF/OVMF_VARS_4M.fd", cfg.OVMFVars)
}

func TestDefaultOrchestratorConfig_UnknownHostArchIsNeverX86(t *testing.T) {
	cfg := defaultOrchestratorConfig(ComputeTypeVM, "riscv64")

	assert.Empty(t, cfg.Arch)
	assert.Empty(t, cfg.QEMUBinary)
	assert.ErrorIs(t, cfg.Validate(), ErrInvalidConfiguration)
}

func TestDefaultOrchestratorConfig_ContainerHasNoVMArch(t *testing.T) {
	cfg := defaultOrchestratorConfig(ComputeTypeContainer, "arm64")

	assert.Empty(t, cfg.Arch)
	assert.Empty(t, cfg.QEMUBinary)
}

func TestApplyLocalQEMUDefaults_FollowsTheHostArch(t *testing.T) {
	cfg := &OrchestratorConfig{}
	require.NoError(t, cfg.applyLocalQEMUDefaults("arm64"))

	assert.Equal(t, ComputeTypeVM, cfg.Type)
	assert.Equal(t, qemu.ArchAArch64, cfg.Arch)
	assert.Equal(t, "qemu-system-aarch64", cfg.QEMUBinary)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_VARS.fd", cfg.OVMFVars)
}

func TestApplyLocalQEMUDefaults_UnknownHostArchIsATypedError(t *testing.T) {
	cfg := &OrchestratorConfig{}
	err := cfg.applyLocalQEMUDefaults("riscv64")

	assert.ErrorIs(t, err, ErrUnsupportedHostArch)
	assert.Contains(t, err.Error(), "riscv64")
	assert.Empty(t, cfg.QEMUBinary, "no x86_64 fallback")
}

func TestApplyLocalQEMUDefaults_ConfiguredArchPicksItsOwnDefaults(t *testing.T) {
	cfg := &OrchestratorConfig{Arch: qemu.ArchAArch64}
	require.NoError(t, cfg.applyLocalQEMUDefaults("amd64"))

	assert.Equal(t, qemu.ArchAArch64, cfg.Arch, "the configured arch wins over the host's")
	assert.Equal(t, "qemu-system-aarch64", cfg.QEMUBinary)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_CODE.fd", cfg.OVMFCode)
}

func TestApplyLocalQEMUDefaults_ConfiguredArchOnAnUnknownHost(t *testing.T) {
	cfg := &OrchestratorConfig{Arch: qemu.ArchX86_64}
	require.NoError(t, cfg.applyLocalQEMUDefaults("riscv64"))

	assert.Equal(t, "qemu-system-x86_64", cfg.QEMUBinary)
}

func TestApplyLocalQEMUDefaults_ConfiguredValuesWin(t *testing.T) {
	cfg := &OrchestratorConfig{
		QEMUBinary:     "/opt/qemu/bin/qemu-system-aarch64",
		OVMFCode:       "/opt/edk2/code.fd",
		OVMFCodeSecure: "/opt/edk2/code.secboot.fd",
		OVMFVars:       "/opt/edk2/vars.fd",
	}
	require.NoError(t, cfg.applyLocalQEMUDefaults("arm64"))

	assert.Equal(t, "/opt/qemu/bin/qemu-system-aarch64", cfg.QEMUBinary)
	assert.Equal(t, "/opt/edk2/code.fd", cfg.OVMFCode)
	assert.Equal(t, "/opt/edk2/code.secboot.fd", cfg.OVMFCodeSecure)
	assert.Equal(t, "/opt/edk2/vars.fd", cfg.OVMFVars)
}

func TestApplyLocalQEMUDefaults_UnknownConfiguredArch(t *testing.T) {
	cfg := &OrchestratorConfig{Arch: qemu.Arch("riscv64")}

	assert.ErrorIs(t, cfg.applyLocalQEMUDefaults("arm64"), ErrInvalidConfiguration)
}

func TestOrchestratorConfigValidate_LocalVMNeedsAKnownArch(t *testing.T) {
	for name, arch := range map[string]qemu.Arch{"unset": "", "unknown": "riscv64"} {
		t.Run(name, func(t *testing.T) {
			cfg := defaultOrchestratorConfig(ComputeTypeVM, "arm64")
			cfg.Arch = arch

			assert.ErrorIs(t, cfg.Validate(), ErrInvalidConfiguration)
		})
	}
}

func TestQEMUBase_CarriesTheArchAndFirmware(t *testing.T) {
	cfg := defaultOrchestratorConfig(ComputeTypeVM, "arm64")
	cfg.NetworkBridge = "br-test"
	cfg.Debug = true

	base := cfg.qemuBase()

	assert.Equal(t, qemu.ArchAArch64, base.Arch)
	assert.Equal(t, "qemu-system-aarch64", base.QEMUBinary)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_CODE.fd", base.OVMFCode)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_CODE.fd", base.OVMFCodeSecure)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_VARS.fd", base.OVMFVars)
	assert.Empty(t, base.Firmware, "compute VMs boot UEFI from pflash, never a -bios image")
	assert.Equal(t, qemu.DiskFormatQCOW2, base.DiskFormat, "snapshots need the qcow2 disk on every arch")
	assert.Equal(t, "br-test", base.BridgeName)
	assert.True(t, base.Debug)
	assert.True(t, base.NoGraphic)
	assert.Equal(t, "c", base.BootOrder)
}
