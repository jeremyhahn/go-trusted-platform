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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQEMUOrchestrator_SWTPM_Integration tests the full swtpm integration lifecycle
func TestQEMUOrchestrator_SWTPM_Integration(t *testing.T) {
	// Skip if swtpm is not installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping integration test")
	}

	// Skip if QEMU is not installed
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Skip("qemu-system-x86_64 not installed, skipping integration test")
	}

	// Create temp work directory
	workDir := t.TempDir()

	// Create orchestrator config
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = workDir
	config.Debug = true

	logger := logging.DefaultLogger()

	// Create orchestrator
	orch, err := NewQEMUOrchestrator(config, logger)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	// Create a minimal device profile
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-vm",
	}

	ctx := context.Background()

	// Test: Create instance with TPM
	t.Run("CreateInstanceWithTPM", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)
		require.NotNil(t, instance)
		assert.True(t, instance.Config.TPMEnabled)
		assert.NotEmpty(t, instance.Metadata["tpm_socket"])

		// Verify TPM state directory was created
		tpmStateDir := filepath.Join(instance.Config.WorkDir, "tpm")
		assert.DirExists(t, tpmStateDir)

		// Verify TPM state files were initialized
		stateFile := filepath.Join(tpmStateDir, "tpm2-00.permall")
		assert.FileExists(t, stateFile)

		// Verify instance exists in orchestrator
		qemuInst, exists := orch.instances[instance.ID]
		require.True(t, exists)
		require.NotNil(t, qemuInst.swtpm)
		assert.False(t, qemuInst.swtpm.IsRunning())

		// Cleanup
		err = orch.Delete(ctx, instance.ID)
		assert.NoError(t, err)
	})
}

// TestQEMUOrchestrator_SWTPM_Lifecycle tests swtpm start/stop lifecycle
func TestQEMUOrchestrator_SWTPM_Lifecycle(t *testing.T) {
	// Skip if swtpm is not installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping lifecycle test")
	}

	// Skip if QEMU is not installed
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Skip("qemu-system-x86_64 not installed, skipping lifecycle test")
	}

	// Skip if OVMF is not available
	if _, err := os.Stat("/usr/share/OVMF/OVMF_CODE_4M.fd"); err != nil {
		t.Skip("OVMF firmware not found, skipping lifecycle test")
	}

	// Create temp work directory
	workDir := t.TempDir()

	// Create orchestrator config
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = workDir
	config.Debug = true

	logger := logging.DefaultLogger()

	// Create orchestrator
	orch, err := NewQEMUOrchestrator(config, logger)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	// Create a minimal device profile
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-vm-lifecycle",
	}

	ctx := context.Background()

	// Create instance
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)
	require.NotNil(t, instance)

	// Get internal instance
	qemuInst, exists := orch.instances[instance.ID]
	require.True(t, exists)
	require.NotNil(t, qemuInst.swtpm)

	// Test: swtpm should not be running initially
	t.Run("SWTPMNotRunningInitially", func(t *testing.T) {
		assert.False(t, qemuInst.swtpm.IsRunning())
	})

	// Note: We cannot test full VM start without a bootable disk image
	// Testing swtpm start requires VM start, so we test the helper method directly
	t.Run("SWTPMStartStop", func(t *testing.T) {
		// Start swtpm manually
		err := qemuInst.swtpm.Start(ctx)
		require.NoError(t, err)

		// Wait for socket
		err = qemuInst.swtpm.WaitForSocket(5 * time.Second)
		require.NoError(t, err)

		// Verify running
		assert.True(t, qemuInst.swtpm.IsRunning())
		assert.Greater(t, qemuInst.swtpm.PID(), 0)

		// Verify socket exists
		socketPath := qemuInst.swtpm.SocketPath()
		assert.FileExists(t, socketPath)

		// Stop swtpm
		err = qemuInst.swtpm.Stop()
		assert.NoError(t, err)

		// Verify stopped
		assert.False(t, qemuInst.swtpm.IsRunning())
		assert.Equal(t, 0, qemuInst.swtpm.PID())
	})

	// Cleanup
	err = orch.Delete(ctx, instance.ID)
	assert.NoError(t, err)

	// Verify swtpm was stopped during delete
	assert.False(t, qemuInst.swtpm.IsRunning())
}

// TestQEMUOrchestrator_SWTPM_CreateHelper tests the createSWTPM helper method
func TestQEMUOrchestrator_SWTPM_CreateHelper(t *testing.T) {
	// Skip if swtpm is not installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping helper test")
	}

	// Create temp work directory
	workDir := t.TempDir()

	// Create orchestrator config
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = workDir
	config.Debug = true

	logger := logging.DefaultLogger()

	// Create orchestrator
	orch, err := NewQEMUOrchestrator(config, logger)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	ctx := context.Background()
	instanceID := "test-instance-123"
	instanceWorkDir := filepath.Join(workDir, instanceID)

	// Create work directory
	err = os.MkdirAll(instanceWorkDir, 0755)
	require.NoError(t, err)

	// Test: Create swtpm
	t.Run("CreateSWTPM", func(t *testing.T) {
		tpm, err := orch.createSWTPM(ctx, instanceID, instanceWorkDir)
		require.NoError(t, err)
		require.NotNil(t, tpm)

		// Verify configuration
		assert.True(t, tpm.IsInitialized())
		assert.NotEmpty(t, tpm.SocketPath())
		assert.NotEmpty(t, tpm.StateDir())

		// Verify TPM state directory structure
		tpmStateDir := filepath.Join(instanceWorkDir, "tpm")
		assert.DirExists(t, tpmStateDir)

		// Verify socket path is correct
		expectedSocket := filepath.Join(tpmStateDir, "swtpm.sock")
		assert.Equal(t, expectedSocket, tpm.SocketPath())

		// Verify state files exist
		stateFile := filepath.Join(tpmStateDir, "tpm2-00.permall")
		assert.FileExists(t, stateFile)
	})

	// Test: Re-use existing TPM state
	t.Run("ReuseExistingTPMState", func(t *testing.T) {
		// Create again - should reuse existing state
		tpm, err := orch.createSWTPM(ctx, instanceID, instanceWorkDir)
		require.NoError(t, err)
		require.NotNil(t, tpm)

		// Should still be initialized
		assert.True(t, tpm.IsInitialized())
	})
}

// TestQEMUOrchestrator_SWTPM_SocketPath tests TPM socket path management
func TestQEMUOrchestrator_SWTPM_SocketPath(t *testing.T) {
	// Skip if swtpm is not installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping socket path test")
	}

	// Create temp work directory
	workDir := t.TempDir()

	// Create orchestrator config
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = workDir

	logger := logging.DefaultLogger()

	// Create orchestrator
	orch, err := NewQEMUOrchestrator(config, logger)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	// Create a minimal device profile
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-vm-socket",
	}

	ctx := context.Background()

	// Create instance
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)
	require.NotNil(t, instance)

	// Test: Verify unique socket path per instance
	t.Run("UniqueSocketPathPerInstance", func(t *testing.T) {
		tpmSocket := instance.Metadata["tpm_socket"]
		assert.NotEmpty(t, tpmSocket)

		// Socket should be in instance work directory
		expectedPrefix := filepath.Join(instance.Config.WorkDir, "tpm")
		assert.Contains(t, tpmSocket, expectedPrefix)

		// Verify QEMU config has TPM socket set
		qemuInst, exists := orch.instances[instance.ID]
		require.True(t, exists)
		vmConfig := qemuInst.vm.GetConfig()
		assert.Equal(t, tpmSocket, vmConfig.TPMSocket)
	})

	// Cleanup
	err = orch.Delete(ctx, instance.ID)
	assert.NoError(t, err)
}

// TestQEMUOrchestrator_SWTPM_CleanupOnError tests cleanup when swtpm fails
func TestQEMUOrchestrator_SWTPM_CleanupOnError(t *testing.T) {
	// This test verifies error handling but doesn't require actual swtpm

	// Create temp work directory
	workDir := t.TempDir()

	// Create orchestrator config with invalid path to force failure
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = "/nonexistent/invalid/path"

	logger := logging.DefaultLogger()

	// Test: Creating orchestrator with invalid work dir should fail early
	t.Run("InvalidWorkDirectory", func(t *testing.T) {
		_, err := NewQEMUOrchestrator(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create work directory")
	})

	// Test: Create with valid config but read-only work dir
	t.Run("ReadOnlyWorkDirectory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping read-only test when running as root")
		}

		// Skip if swtpm is not installed
		if _, err := exec.LookPath("swtpm"); err != nil {
			t.Skip("swtpm not installed, skipping error handling test")
		}

		// Create read-only directory
		readOnlyDir := filepath.Join(workDir, "readonly")
		err := os.MkdirAll(readOnlyDir, 0555)
		require.NoError(t, err)
		defer os.Chmod(readOnlyDir, 0755)

		config := DefaultOrchestratorConfig(ComputeTypeVM)
		config.WorkDir = readOnlyDir

		orch, err := NewQEMUOrchestrator(config, logger)
		require.NoError(t, err)
		defer orch.Close()

		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-vm-readonly",
		}

		ctx := context.Background()

		// Create should fail due to read-only work directory
		_, err = orch.Create(ctx, profile)
		assert.Error(t, err)
	})
}

// TestQEMUOrchestrator_SWTPM_MultipleInstances tests managing multiple VMs with swtpm
func TestQEMUOrchestrator_SWTPM_MultipleInstances(t *testing.T) {
	// Skip if swtpm is not installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping multiple instances test")
	}

	// Create temp work directory
	workDir := t.TempDir()

	// Create orchestrator config
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = workDir
	config.MaxInstances = 5

	logger := logging.DefaultLogger()

	// Create orchestrator
	orch, err := NewQEMUOrchestrator(config, logger)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	ctx := context.Background()

	// Create multiple instances
	instances := make([]*Instance, 3)
	socketPaths := make(map[string]bool)

	for i := 0; i < 3; i++ {
		profile := &entities.DeviceProfile{
			ID:   uint64(i + 1),
			Name: "test-vm-" + string(rune('a'+i)),
		}

		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)
		require.NotNil(t, instance)
		instances[i] = instance

		// Track socket paths
		socketPath := instance.Metadata["tpm_socket"]
		assert.NotEmpty(t, socketPath)

		// Verify each instance has unique socket path
		assert.False(t, socketPaths[socketPath], "Socket path should be unique per instance")
		socketPaths[socketPath] = true

		// Verify TPM state directory exists
		tpmStateDir := filepath.Join(instance.Config.WorkDir, "tpm")
		assert.DirExists(t, tpmStateDir)
	}

	// Test: Each instance has its own swtpm
	t.Run("EachInstanceHasOwnSWTPM", func(t *testing.T) {
		for _, instance := range instances {
			qemuInst, exists := orch.instances[instance.ID]
			require.True(t, exists)
			require.NotNil(t, qemuInst.swtpm)
			assert.False(t, qemuInst.swtpm.IsRunning())

			// Each should have unique state directory
			stateDir := qemuInst.swtpm.StateDir()
			assert.Contains(t, stateDir, instance.ID)
		}
	})

	// Cleanup all instances
	for _, instance := range instances {
		err := orch.Delete(ctx, instance.ID)
		assert.NoError(t, err)
	}

	// Verify all instances were cleaned up
	assert.Equal(t, 0, len(orch.instances))
}

// TestQEMUOrchestrator_SWTPM_StatePermissions tests TPM state file permissions
func TestQEMUOrchestrator_SWTPM_StatePermissions(t *testing.T) {
	// Skip if swtpm is not installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping permissions test")
	}

	// Create temp work directory
	workDir := t.TempDir()

	// Create orchestrator config
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = workDir

	logger := logging.DefaultLogger()

	// Create orchestrator
	orch, err := NewQEMUOrchestrator(config, logger)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	// Create a minimal device profile
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-vm-perms",
	}

	ctx := context.Background()

	// Create instance
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)
	require.NotNil(t, instance)

	// Test: Verify TPM state directory permissions
	t.Run("StateDirectoryPermissions", func(t *testing.T) {
		tpmStateDir := filepath.Join(instance.Config.WorkDir, "tpm")
		info, err := os.Stat(tpmStateDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())

		// Directory should be readable/writable by owner
		mode := info.Mode()
		assert.True(t, mode&0700 == 0700, "TPM state directory should have owner rwx permissions")
	})

	// Cleanup
	err = orch.Delete(ctx, instance.ID)
	assert.NoError(t, err)
}
