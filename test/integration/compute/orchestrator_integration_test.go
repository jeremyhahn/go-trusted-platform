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

package compute_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testBridgeName = "test-compute-br"
	testTimeout    = 5 * time.Minute
	ovsSocketPath  = "/var/run/openvswitch/db.sock"
	qemuBinary     = "qemu-system-x86_64"
	ovmfCodePath   = "/usr/share/OVMF/OVMF_CODE_4M.fd"
	ovmfVarsPath   = "/usr/share/OVMF/OVMF_VARS_4M.fd"
)

// skipIfNotInDevcontainer skips the test if not running in the devcontainer
// environment with QEMU/OVS/swtpm available.
func skipIfNotInDevcontainer(t *testing.T) {
	t.Helper()

	// Check for integration test environment variable
	if os.Getenv("INTEGRATION_TEST") != "1" {
		t.Skip("Skipping: INTEGRATION_TEST environment variable not set (not in devcontainer)")
	}

	// Check root privileges (required for OVS/QEMU operations)
	if os.Geteuid() != 0 {
		t.Skip("Skipping: root privileges required for compute integration tests")
	}

	// Check QEMU availability
	if _, err := exec.LookPath(qemuBinary); err != nil {
		t.Skip("Skipping: QEMU not available")
	}

	// Check OVS availability
	if _, err := os.Stat(ovsSocketPath); os.IsNotExist(err) {
		t.Skip("Skipping: OVS socket not available at " + ovsSocketPath)
	}

	// Check OVS is running
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ovs-vsctl", "show")
	if err := cmd.Run(); err != nil {
		t.Skip("Skipping: OVS is not running")
	}

	// Check swtpm availability
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("Skipping: swtpm not available")
	}

	// Check OVMF firmware availability
	if _, err := os.Stat(ovmfCodePath); os.IsNotExist(err) {
		t.Skip("Skipping: OVMF firmware not available at " + ovmfCodePath)
	}
}

// createTestOrchestrator creates a QEMU orchestrator configured for integration testing.
func createTestOrchestrator(t *testing.T, workDir string) *compute.QEMUOrchestrator {
	t.Helper()

	logger := logging.DefaultLogger()

	config := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeVM,
		WorkDir:         workDir,
		DefaultMemory:   512,
		DefaultCPUs:     1,
		DefaultDiskSize: "1G",
		MaxInstances:    10,
		EnableKVM:       isKVMAvailable(),
		NetworkBridge:   testBridgeName,
		OVSSocketPath:   ovsSocketPath,
		Arch:            qemu.ArchX86_64,
		QEMUBinary:      qemuBinary,
		OVMFCode:        ovmfCodePath,
		OVMFCodeSecure:  "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
		OVMFVars:        ovmfVarsPath,
		Debug:           true,
		PortAuthEnabled: false,
	}

	orchestrator, err := compute.NewQEMUOrchestrator(config, logger)
	require.NoError(t, err, "Failed to create QEMU orchestrator")

	return orchestrator
}

// createTestDeviceProfile creates a minimal device profile for testing.
func createTestDeviceProfile(name string) *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:    1,
		Name:  name,
		Model: "test-model",
		Role:  entities.DeviceRoleServer,
	}
}

// isKVMAvailable checks if KVM acceleration is available.
func isKVMAvailable() bool {
	_, err := os.Stat("/dev/kvm")
	return err == nil
}

// setupTestBridge creates an OVS bridge for testing.
func setupTestBridge(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if bridge already exists
	cmd := exec.CommandContext(ctx, "ovs-vsctl", "br-exists", testBridgeName)
	if err := cmd.Run(); err == nil {
		// Bridge exists, nothing to do
		return
	}

	// Create bridge
	cmd = exec.CommandContext(ctx, "ovs-vsctl", "add-br", testBridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create test bridge: %s", string(output))
}

// cleanupTestBridge removes the test OVS bridge.
func cleanupTestBridge(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "--if-exists", "del-br", testBridgeName)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Warning: failed to cleanup test bridge: %v, output: %s", err, string(output))
	}
}

// cleanupTestDir removes the test working directory.
func cleanupTestDir(t *testing.T, dir string) {
	t.Helper()

	if err := os.RemoveAll(dir); err != nil {
		t.Logf("Warning: failed to cleanup test directory %s: %v", dir, err)
	}
}

// TestQEMUOrchestratorStart tests the full VM lifecycle with Start().
func TestQEMUOrchestratorStart(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	profile := createTestDeviceProfile("test-vm-start")

	// Create VM instance
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err, "Failed to create VM instance")
	require.NotNil(t, instance)
	require.NotEmpty(t, instance.ID)

	t.Logf("Created VM instance: %s", instance.ID)

	// Verify initial state is stopped
	state, err := orchestrator.GetState(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, compute.StateStopped, state, "Initial state should be stopped")

	// Start the VM
	err = orchestrator.Start(ctx, instance.ID)
	require.NoError(t, err, "Failed to start VM instance")

	// Verify state is running
	state, err = orchestrator.GetState(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, compute.StateRunning, state, "State should be running after start")

	// Verify instance has a PID
	runningInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	assert.Greater(t, runningInstance.PID, 0, "Running instance should have a valid PID")

	t.Logf("VM instance started with PID: %d", runningInstance.PID)

	// Verify TPM socket exists if TPM was enabled
	if tpmSocket, ok := runningInstance.Metadata["tpm_socket"]; ok && tpmSocket != "" {
		_, err := os.Stat(tpmSocket)
		assert.NoError(t, err, "TPM socket should exist")
		t.Logf("TPM socket available at: %s", tpmSocket)
	}

	// Cleanup: Stop the VM
	err = orchestrator.Stop(ctx, instance.ID)
	require.NoError(t, err, "Failed to stop VM instance")

	// Delete the VM
	err = orchestrator.Delete(ctx, instance.ID)
	require.NoError(t, err, "Failed to delete VM instance")
}

// TestQEMUOrchestratorStartError tests Start() error handling.
func TestQEMUOrchestratorStartError(t *testing.T) {
	skipIfNotInDevcontainer(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Test starting a non-existent instance
	err := orchestrator.Start(ctx, "non-existent-instance-id")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInstanceNotFound)

	// Test starting with empty instance ID
	err = orchestrator.Start(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInvalidInstanceID)
}

// TestQEMUOrchestratorStop tests stopping a running VM.
func TestQEMUOrchestratorStop(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	profile := createTestDeviceProfile("test-vm-stop")

	// Create and start VM
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err)

	err = orchestrator.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Verify it's running
	state, err := orchestrator.GetState(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, compute.StateRunning, state)

	t.Logf("VM instance running, now stopping: %s", instance.ID)

	// Stop the VM
	err = orchestrator.Stop(ctx, instance.ID)
	require.NoError(t, err, "Failed to stop VM instance")

	// Verify state is stopped
	state, err = orchestrator.GetState(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, compute.StateStopped, state, "State should be stopped after stop")

	// Verify PID is cleared
	stoppedInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, stoppedInstance.PID, "Stopped instance should have PID 0")

	// Cleanup
	err = orchestrator.Delete(ctx, instance.ID)
	require.NoError(t, err)
}

// TestQEMUOrchestratorStopError tests Stop() error handling.
func TestQEMUOrchestratorStopError(t *testing.T) {
	skipIfNotInDevcontainer(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Test stopping a non-existent instance
	err := orchestrator.Stop(ctx, "non-existent-instance-id")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInstanceNotFound)

	// Test stopping with empty instance ID
	err = orchestrator.Stop(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInvalidInstanceID)

	// Test stopping a stopped instance
	profile := createTestDeviceProfile("test-vm-stop-error")
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err)
	defer orchestrator.Delete(ctx, instance.ID)

	err = orchestrator.Stop(ctx, instance.ID)
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInstanceNotRunning)
}

// TestQEMUOrchestratorAttachNetwork tests OVS network attachment.
func TestQEMUOrchestratorAttachNetwork(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	profile := createTestDeviceProfile("test-vm-attach-network")
	portName := "test-tap-attach"

	// Create VM instance
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err)
	defer orchestrator.Delete(ctx, instance.ID)

	// Attach network
	err = orchestrator.AttachNetwork(ctx, instance.ID, portName)
	require.NoError(t, err, "Failed to attach network")

	// Verify network attachment is recorded
	updatedInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	require.Len(t, updatedInstance.NetworkAttachments, 1, "Should have one network attachment")
	assert.Equal(t, portName, updatedInstance.NetworkAttachments[0].PortName)
	assert.Equal(t, testBridgeName, updatedInstance.NetworkAttachments[0].BridgeName)

	t.Logf("Network attached: port=%s bridge=%s", portName, testBridgeName)

	// Verify TAP device exists in OVS
	exists, err := ovsPortExists(testBridgeName, portName)
	if err == nil && exists {
		t.Logf("OVS port verified: %s on bridge %s", portName, testBridgeName)
	}
}

// TestQEMUOrchestratorAttachNetworkError tests AttachNetwork() error handling.
func TestQEMUOrchestratorAttachNetworkError(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Test attaching to non-existent instance
	err := orchestrator.AttachNetwork(ctx, "non-existent-id", "test-port")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInstanceNotFound)

	// Test attaching with empty instance ID
	err = orchestrator.AttachNetwork(ctx, "", "test-port")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInvalidInstanceID)

	// Test attaching with empty port name
	profile := createTestDeviceProfile("test-vm-attach-error")
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err)
	defer orchestrator.Delete(ctx, instance.ID)

	err = orchestrator.AttachNetwork(ctx, instance.ID, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrNetworkAttachmentFailed)
}

// TestQEMUOrchestratorDetachNetwork tests OVS network detachment.
func TestQEMUOrchestratorDetachNetwork(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	profile := createTestDeviceProfile("test-vm-detach-network")
	portName := "test-tap-detach"

	// Create VM instance
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err)
	defer orchestrator.Delete(ctx, instance.ID)

	// Attach network first
	err = orchestrator.AttachNetwork(ctx, instance.ID, portName)
	require.NoError(t, err)

	// Verify attachment
	attachedInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	require.Len(t, attachedInstance.NetworkAttachments, 1)

	// Detach network
	err = orchestrator.DetachNetwork(ctx, instance.ID, portName)
	require.NoError(t, err, "Failed to detach network")

	// Verify network attachment is removed
	detachedInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	assert.Len(t, detachedInstance.NetworkAttachments, 0, "Should have no network attachments after detach")

	t.Logf("Network detached successfully: port=%s", portName)
}

// TestQEMUOrchestratorDetachNetworkError tests DetachNetwork() error handling.
func TestQEMUOrchestratorDetachNetworkError(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Test detaching from non-existent instance
	err := orchestrator.DetachNetwork(ctx, "non-existent-id", "test-port")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInstanceNotFound)

	// Test detaching with empty instance ID
	err = orchestrator.DetachNetwork(ctx, "", "test-port")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInvalidInstanceID)

	// Test detaching with empty port name
	profile := createTestDeviceProfile("test-vm-detach-error")
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err)
	defer orchestrator.Delete(ctx, instance.ID)

	err = orchestrator.DetachNetwork(ctx, instance.ID, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrNetworkDetachmentFailed)

	// Test detaching when no network is attached
	err = orchestrator.DetachNetwork(ctx, instance.ID, "some-port")
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrNetworkDetachmentFailed)
}

// TestQEMUOrchestratorE2ELifecycle tests the complete end-to-end lifecycle:
// Create VM -> Start -> Attach Network -> Stop -> Delete
func TestQEMUOrchestratorE2ELifecycle(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	profile := createTestDeviceProfile("test-vm-e2e-lifecycle")
	portName := "test-tap-e2e"

	t.Log("=== Phase 1: Create VM ===")
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err, "Failed to create VM instance")
	require.NotEmpty(t, instance.ID)
	t.Logf("Created VM: %s", instance.ID)

	// Verify initial state
	state, err := orchestrator.GetState(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, compute.StateStopped, state)

	t.Log("=== Phase 2: Start VM ===")
	err = orchestrator.Start(ctx, instance.ID)
	require.NoError(t, err, "Failed to start VM")

	state, err = orchestrator.GetState(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, compute.StateRunning, state)

	runningInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	require.Greater(t, runningInstance.PID, 0)
	t.Logf("VM running with PID: %d", runningInstance.PID)

	// Allow VM to stabilize; nothing observable marks the end, so this is elapsed time
	require.NoError(t, testenv.Elapse(ctx, 2*time.Second))

	t.Log("=== Phase 3: Attach Network ===")
	err = orchestrator.AttachNetwork(ctx, instance.ID, portName)
	require.NoError(t, err, "Failed to attach network")

	attachedInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	require.Len(t, attachedInstance.NetworkAttachments, 1)
	t.Logf("Network attached: port=%s", portName)

	// Verify OVS port was created
	exists, err := ovsPortExists(testBridgeName, portName)
	if err == nil {
		t.Logf("OVS port exists: %v", exists)
	}

	t.Log("=== Phase 4: Stop VM ===")
	err = orchestrator.Stop(ctx, instance.ID)
	require.NoError(t, err, "Failed to stop VM")

	state, err = orchestrator.GetState(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, compute.StateStopped, state)

	stoppedInstance, err := orchestrator.Get(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, stoppedInstance.PID)
	t.Log("VM stopped")

	t.Log("=== Phase 5: Delete VM ===")
	err = orchestrator.Delete(ctx, instance.ID)
	require.NoError(t, err, "Failed to delete VM")

	// Verify instance no longer exists
	_, err = orchestrator.Get(ctx, instance.ID)
	assert.Error(t, err)
	assert.ErrorIs(t, err, compute.ErrInstanceNotFound)
	t.Log("VM deleted")

	// Verify work directory is cleaned up
	instanceWorkDir := filepath.Join(workDir, instance.ID)
	_, err = os.Stat(instanceWorkDir)
	assert.True(t, os.IsNotExist(err), "Instance work directory should be removed")

	t.Log("=== E2E Lifecycle Test Complete ===")
}

// TestQEMUOrchestratorMultipleInstances tests managing multiple VM instances.
func TestQEMUOrchestratorMultipleInstances(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	instanceCount := 3
	instances := make([]*compute.Instance, 0, instanceCount)

	// Create multiple instances
	for i := 0; i < instanceCount; i++ {
		profile := createTestDeviceProfile(fmt.Sprintf("test-vm-multi-%d", i))
		instance, err := orchestrator.Create(ctx, profile)
		require.NoError(t, err, "Failed to create instance %d", i)
		instances = append(instances, instance)
		t.Logf("Created instance %d: %s", i, instance.ID)
	}

	// List all instances
	allInstances, err := orchestrator.List(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, allInstances, instanceCount)

	// Start all instances
	for i, inst := range instances {
		err := orchestrator.Start(ctx, inst.ID)
		require.NoError(t, err, "Failed to start instance %d", i)
	}

	// Verify all are running
	for i, inst := range instances {
		state, err := orchestrator.GetState(ctx, inst.ID)
		require.NoError(t, err)
		assert.Equal(t, compute.StateRunning, state, "Instance %d should be running", i)
	}

	// Filter by state
	runningState := compute.StateRunning
	filter := &compute.InstanceFilter{State: &runningState}
	runningInstances, err := orchestrator.List(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, runningInstances, instanceCount, "All instances should be running")

	// Stop and delete all instances
	for i, inst := range instances {
		err := orchestrator.Stop(ctx, inst.ID)
		require.NoError(t, err, "Failed to stop instance %d", i)

		err = orchestrator.Delete(ctx, inst.ID)
		require.NoError(t, err, "Failed to delete instance %d", i)
	}

	// Verify all deleted
	allInstances, err = orchestrator.List(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, allInstances, 0, "All instances should be deleted")
}

// TestQEMUOrchestratorWithTPM tests VM creation with TPM enabled.
func TestQEMUOrchestratorWithTPM(t *testing.T) {
	skipIfNotInDevcontainer(t)
	setupTestBridge(t)
	defer cleanupTestBridge(t)

	workDir := t.TempDir()
	defer cleanupTestDir(t, workDir)

	orchestrator := createTestOrchestrator(t, workDir)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	profile := createTestDeviceProfile("test-vm-with-tpm")

	// Create VM with TPM (default configuration enables TPM)
	instance, err := orchestrator.Create(ctx, profile)
	require.NoError(t, err)
	defer func() {
		orchestrator.Stop(ctx, instance.ID)
		orchestrator.Delete(ctx, instance.ID)
	}()

	// Verify TPM socket path is in metadata
	tpmSocket, ok := instance.Metadata["tpm_socket"]
	require.True(t, ok, "TPM socket should be in metadata")
	require.NotEmpty(t, tpmSocket)
	t.Logf("TPM socket path: %s", tpmSocket)

	// Start the VM
	err = orchestrator.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Verify TPM socket exists after start
	_, err = os.Stat(tpmSocket)
	assert.NoError(t, err, "TPM socket should exist after VM start")

	// Allow swtpm to initialize; Start already waited for its socket, so this is elapsed time
	require.NoError(t, testenv.Elapse(ctx, 2*time.Second))

	// Stop the VM
	err = orchestrator.Stop(ctx, instance.ID)
	require.NoError(t, err)
}

// Helper functions for OVS operations

func ovsPortExists(bridge, port string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "list-ports", bridge)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to list ports: %v, output: %s", err, string(output))
	}

	ports := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, p := range ports {
		if strings.TrimSpace(p) == port {
			return true, nil
		}
	}
	return false, nil
}
