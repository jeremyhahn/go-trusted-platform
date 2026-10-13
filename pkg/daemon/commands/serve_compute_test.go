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

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// localQEMUDefaults is the defaults layer newComputeOrchestrator starts from.
func localQEMUDefaults() *compute.OrchestratorConfig {
	cfg := &compute.OrchestratorConfig{WorkDir: "/var/lib/platformd/compute", DefaultMemory: 512, DefaultCPUs: 1}
	cfg.ApplyLocalQEMUDefaults()
	return cfg
}

func TestApplyLocalQEMUSettings_ConfiguredValuesWin(t *testing.T) {
	shared := &compute.SharedStorageConfig{Enabled: true, Backend: "nfs", MountPath: "/vms"}
	dst := localQEMUDefaults()
	applyLocalQEMUSettings(dst, &compute.OrchestratorConfig{
		QEMUBinary:             "/opt/qemu/bin/qemu-system-x86_64",
		WorkDir:                "/srv/compute",
		NetworkBridge:          "br-vm",
		EnableKVM:              true,
		DefaultMemory:          2048,
		DefaultCPUs:            4,
		MigrationListenAddress: "10.20.0.11:49152",
		SharedStorage:          shared,
	})

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
	want := localQEMUDefaults()
	dst := localQEMUDefaults()
	applyLocalQEMUSettings(dst, &compute.OrchestratorConfig{})

	assert.Equal(t, want, dst)
	assert.Equal(t, compute.DefaultMigrationListenAddress, dst.MigrationListenAddress)
	assert.False(t, dst.SharedStorageEnabled(), "live migration stays off without a shared_storage section")
}
