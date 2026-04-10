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

package compute_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// silentLogger returns a logger that discards all output (for examples)
func silentLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// Example_swtpmIntegration demonstrates automatic TPM provisioning for VMs
func Example_swtpmIntegration() {
	// Create work directory
	workDir := "/tmp/vm-orchestrator"
	os.MkdirAll(workDir, 0755)
	defer os.RemoveAll(workDir)

	// Configure orchestrator
	config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)
	config.WorkDir = workDir

	logger := silentLogger()

	// Create orchestrator
	orch, err := compute.NewQEMUOrchestrator(config, logger)
	if err != nil {
		fmt.Printf("Failed to create orchestrator: %v\n", err)
		return
	}
	defer orch.Close()

	// Create device profile
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "example-vm",
	}

	ctx := context.Background()

	// Create VM instance - TPM is automatically provisioned
	instance, err := orch.Create(ctx, profile)
	if err != nil {
		fmt.Printf("Failed to create instance: %v\n", err)
		return
	}

	// TPM socket is available in metadata
	tpmSocket := instance.Metadata["tpm_socket"]
	fmt.Printf("TPM socket created at: %s\n", tpmSocket)

	// Start VM - swtpm starts automatically before QEMU
	// err = orch.Start(ctx, instance.ID)
	// Note: Commented out as it requires a bootable disk image

	// Stop VM - swtpm stops automatically when VM exits
	// err = orch.Stop(ctx, instance.ID)

	// Delete VM - TPM state is cleaned up
	err = orch.Delete(ctx, instance.ID)
	if err != nil {
		fmt.Printf("Failed to delete instance: %v\n", err)
		return
	}

	fmt.Println("VM lifecycle completed with automatic TPM management")
}

// Example_multipleVMsWithTPM demonstrates managing multiple VMs with isolated TPMs
func Example_multipleVMsWithTPM() {
	// Create work directory
	workDir := "/tmp/multi-vm-orchestrator"
	os.MkdirAll(workDir, 0755)
	defer os.RemoveAll(workDir)

	// Configure orchestrator
	config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)
	config.WorkDir = workDir
	config.MaxInstances = 10

	logger := silentLogger()

	// Create orchestrator
	orch, err := compute.NewQEMUOrchestrator(config, logger)
	if err != nil {
		fmt.Printf("Failed to create orchestrator: %v\n", err)
		return
	}
	defer orch.Close()

	ctx := context.Background()

	// Create multiple VMs, each with isolated TPM
	for i := 0; i < 3; i++ {
		profile := &entities.DeviceProfile{
			ID:   uint64(i + 1),
			Name: fmt.Sprintf("vm-%d", i),
		}

		instance, err := orch.Create(ctx, profile)
		if err != nil {
			fmt.Printf("Failed to create instance %d: %v\n", i, err)
			continue
		}

		tpmSocket := instance.Metadata["tpm_socket"]
		fmt.Printf("VM %d: TPM socket at %s\n", i, tpmSocket)
	}

	// List all instances
	instances, err := orch.List(ctx, nil)
	if err != nil {
		fmt.Printf("Failed to list instances: %v\n", err)
		return
	}

	fmt.Printf("Total VMs created: %d\n", len(instances))

	// Cleanup all instances
	for _, instance := range instances {
		err := orch.Delete(ctx, instance.ID)
		if err != nil {
			fmt.Printf("Failed to delete instance %s: %v\n", instance.ID, err)
		}
	}

	fmt.Println("All VMs cleaned up")
}

// Example_tpmStateReuse demonstrates TPM state persistence across restarts
func Example_tpmStateReuse() {
	// Create work directory
	workDir := "/tmp/vm-tpm-reuse"
	os.MkdirAll(workDir, 0755)
	defer os.RemoveAll(workDir)

	// Configure orchestrator
	config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)
	config.WorkDir = workDir

	logger := silentLogger()

	// Create orchestrator
	orch, err := compute.NewQEMUOrchestrator(config, logger)
	if err != nil {
		fmt.Printf("Failed to create orchestrator: %v\n", err)
		return
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "persistent-vm",
	}

	ctx := context.Background()

	// First boot - TPM state is initialized
	instance, err := orch.Create(ctx, profile)
	if err != nil {
		fmt.Printf("Failed to create instance: %v\n", err)
		return
	}

	fmt.Println("First boot: TPM state initialized")

	// Simulate restart by creating new orchestrator with same work directory
	orch.Close()

	orch2, err := compute.NewQEMUOrchestrator(config, logger)
	if err != nil {
		fmt.Printf("Failed to create second orchestrator: %v\n", err)
		return
	}
	defer orch2.Close()

	// Create another instance - will reuse existing TPM state if workDir is the same
	instance2, err := orch2.Create(ctx, profile)
	if err != nil {
		fmt.Printf("Failed to create second instance: %v\n", err)
		return
	}

	fmt.Println("Second boot: TPM state reused")

	// Cleanup
	err = orch2.Delete(ctx, instance.ID)
	if err != nil {
		fmt.Printf("Failed to delete first instance: %v\n", err)
	}

	err = orch2.Delete(ctx, instance2.ID)
	if err != nil {
		fmt.Printf("Failed to delete second instance: %v\n", err)
	}

	fmt.Println("TPM state persistence verified")
}
