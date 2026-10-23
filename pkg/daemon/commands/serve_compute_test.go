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

package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// localQEMUConfig layers the operator's settings and then the defaults, in the
// order newComputeOrchestrator applies them.
func localQEMUConfig(t *testing.T, operator *compute.OrchestratorConfig) *compute.OrchestratorConfig {
	t.Helper()
	cfg := &compute.OrchestratorConfig{WorkDir: "/var/lib/platformd/compute", DefaultMemory: 512, DefaultCPUs: 1}
	applyLocalQEMUSettings(cfg, operator)
	require.NoError(t, cfg.ApplyLocalQEMUDefaults())
	return cfg
}

func TestApplyLocalQEMUSettings_ConfiguredValuesWin(t *testing.T) {
	shared := &compute.SharedStorageConfig{Enabled: true, Backend: "nfs", MountPath: "/vms"}
	dst := localQEMUConfig(t, &compute.OrchestratorConfig{
		Arch:                   qemu.ArchX86_64,
		QEMUBinary:             "/opt/qemu/bin/qemu-system-x86_64",
		WorkDir:                "/srv/compute",
		NetworkBridge:          "br-vm",
		EnableKVM:              true,
		DefaultMemory:          2048,
		DefaultCPUs:            4,
		MigrationListenAddress: "10.20.0.11:49152",
		SharedStorage:          shared,
	})

	assert.Equal(t, qemu.ArchX86_64, dst.Arch)
	assert.Equal(t, "/opt/qemu/bin/qemu-system-x86_64", dst.QEMUBinary)
	assert.Equal(t, "/srv/compute", dst.WorkDir)
	assert.Equal(t, "br-vm", dst.NetworkBridge)
	assert.True(t, dst.EnableKVM)
	assert.Equal(t, 2048, dst.DefaultMemory)
	assert.Equal(t, 4, dst.DefaultCPUs)
	assert.Equal(t, "10.20.0.11:49152", dst.MigrationListenAddress)
	assert.Same(t, shared, dst.SharedStorage, "compute.shared_storage gates live migration and must reach the orchestrator")
	assert.True(t, dst.SharedStorageEnabled())
}

func TestApplyLocalQEMUSettings_UnsetValuesKeepTheDefaults(t *testing.T) {
	want := &compute.OrchestratorConfig{WorkDir: "/var/lib/platformd/compute", DefaultMemory: 512, DefaultCPUs: 1}
	require.NoError(t, want.ApplyLocalQEMUDefaults())

	dst := localQEMUConfig(t, &compute.OrchestratorConfig{})

	assert.Equal(t, want, dst)
	assert.NotEmpty(t, dst.Arch, "the arch follows the host")
	assert.Equal(t, compute.DefaultMigrationListenAddress, dst.MigrationListenAddress)
	assert.False(t, dst.SharedStorageEnabled(), "live migration stays off without a shared_storage section")
}

func TestApplyLocalQEMUSettings_ConfiguredArchPicksItsFirmwareDefaults(t *testing.T) {
	dst := localQEMUConfig(t, &compute.OrchestratorConfig{Arch: qemu.ArchAArch64})

	assert.Equal(t, qemu.ArchAArch64, dst.Arch)
	assert.Equal(t, "qemu-system-aarch64", dst.QEMUBinary)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_CODE.fd", dst.OVMFCode)
	assert.Equal(t, "/usr/share/AAVMF/AAVMF_VARS.fd", dst.OVMFVars)
}
