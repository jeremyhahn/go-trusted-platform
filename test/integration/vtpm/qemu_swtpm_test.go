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

//go:build integration

package vtpm_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQEMUOrchestrator_SWTPM creates a VM with the real swtpm_setup and
// qemu-img and the host's OVMF firmware, then deletes it. The VM is never
// booted. A missing binary or firmware file fails the test.
func TestQEMUOrchestrator_SWTPM(t *testing.T) {
	config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)
	config.WorkDir = t.TempDir()
	orch, err := compute.NewQEMUOrchestrator(config, logging.DefaultLogger())
	require.NoError(t, err)
	defer orch.Close()
	ctx := context.Background()

	instance, err := orch.Create(ctx, &entities.DeviceProfile{ID: 1, Name: "swtpm-vm"})
	require.NoError(t, err)

	tpmStateDir := filepath.Join(instance.Config.WorkDir, "tpm")
	assert.Equal(t, filepath.Join(tpmStateDir, "swtpm.sock"), instance.Metadata["tpm_socket"])
	assert.FileExists(t, filepath.Join(tpmStateDir, "tpm2-00.permall"))
	info, err := os.Stat(tpmStateDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm()&0700)

	output, err := exec.Command("qemu-img", "info", "--output=json", instance.Config.DiskPath).CombinedOutput()
	require.NoError(t, err, string(output))
	assert.Contains(t, string(output), `"format": "qcow2"`)

	require.NoError(t, orch.Delete(ctx, instance.ID))
	assert.NoDirExists(t, instance.Config.WorkDir)
}
