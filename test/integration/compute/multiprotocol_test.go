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
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestComputeMultiProtocol runs all compute VM tests across multiple protocols.
func TestComputeMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []ComputeCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Skipping %s: setup failed: %v", adapter.Name(), err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown failed: %v", err)
				}
			})

			t.Run("VMLifecycle", func(t *testing.T) { testVMLifecycle(t, ctx, adapter) })
			t.Run("VMGet", func(t *testing.T) { testVMGet(t, ctx, adapter) })
			t.Run("VMList", func(t *testing.T) { testVMList(t, ctx, adapter) })
			t.Run("VMListFiltered", func(t *testing.T) { testVMListFiltered(t, ctx, adapter) })
			t.Run("VMCreateWithLabels", func(t *testing.T) { testVMCreateWithLabels(t, ctx, adapter) })
			t.Run("VMDeleteNotFound", func(t *testing.T) { testVMDeleteNotFound(t, ctx, adapter) })
		})
	}
}

// =============================================================================
// Test Suites
// =============================================================================

// testVMLifecycle tests the full VM lifecycle:
// create -> get (verify stopped) -> start -> get (verify running) -> stop ->
// get (verify stopped) -> delete -> get (verify not found).
func testVMLifecycle(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	vmName := generateTestVMName("lifecycle-" + testID)

	// Create VM
	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   512,
		DiskSizeGB: 1,
		Firmware:   "bios",
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("CreateVM failed: %v", err)
	}

	if createResult.VMID == "" {
		t.Fatal("CreateVM returned empty VM ID")
	}

	vmID := createResult.VMID

	// Ensure cleanup on test exit
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	// Get VM - verify stopped
	getResult, err := adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("GetVM after create failed: %v", err)
	}

	if getResult.State != "stopped" {
		t.Errorf("Expected VM state 'stopped' after create, got %q", getResult.State)
	}

	if getResult.Name != vmName {
		t.Errorf("Expected VM name %q, got %q", vmName, getResult.Name)
	}

	// Start VM
	startResult, err := adapter.StartVM(ctx, StartVMOptions{VMID: vmID})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("StartVM failed: %v", err)
	}

	if !startResult.Success {
		t.Errorf("StartVM returned success=false: %s", startResult.Message)
	}

	// Get VM - verify running
	getResult, err = adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("GetVM after start failed: %v", err)
	}

	if getResult.State != "running" {
		t.Errorf("Expected VM state 'running' after start, got %q", getResult.State)
	}

	// Stop VM
	stopResult, err := adapter.StopVM(ctx, StopVMOptions{
		VMID:           vmID,
		TimeoutSeconds: 30,
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("StopVM failed: %v", err)
	}

	if !stopResult.Success {
		t.Errorf("StopVM returned success=false: %s", stopResult.Message)
	}

	// Get VM - verify stopped
	getResult, err = adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		t.Fatalf("GetVM after stop failed: %v", err)
	}

	if getResult.State != "stopped" {
		t.Errorf("Expected VM state 'stopped' after stop, got %q", getResult.State)
	}

	// Delete VM
	deleteResult, err := adapter.DeleteVM(ctx, DeleteVMOptions{
		VMID:        vmID,
		DeleteDisks: true,
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("DeleteVM failed: %v", err)
	}

	if !deleteResult.Success {
		t.Errorf("DeleteVM returned success=false: %s", deleteResult.Message)
	}

	// Get VM - verify not found
	_, err = adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err == nil {
		t.Error("Expected error when getting deleted VM, got nil")
	}
}

// testVMGet tests creating a VM and verifying all returned fields match.
func testVMGet(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	vmName := generateTestVMName("get-" + testID)

	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       2,
		MemoryMB:   1024,
		DiskSizeGB: 5,
		Firmware:   "uefi",
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("CreateVM failed: %v", err)
	}

	vmID := createResult.VMID
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	getResult, err := adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("GetVM failed: %v", err)
	}

	if getResult.VMID != vmID {
		t.Errorf("Expected VM ID %q, got %q", vmID, getResult.VMID)
	}

	if getResult.Name != vmName {
		t.Errorf("Expected VM name %q, got %q", vmName, getResult.Name)
	}

	if getResult.CPUs != 2 {
		t.Errorf("Expected 2 CPUs, got %d", getResult.CPUs)
	}

	if getResult.MemoryMB != 1024 {
		t.Errorf("Expected 1024 MB memory, got %d", getResult.MemoryMB)
	}

	if getResult.State != "stopped" {
		t.Errorf("Expected state 'stopped', got %q", getResult.State)
	}
}

// testVMList tests creating multiple VMs and verifying list results.
func testVMList(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]

	vmIDs := make([]string, 0, 2)

	// Create 2 VMs
	for i := range 2 {
		vmName := generateTestVMName("list-" + testID + "-" + string(rune('a'+i)))
		result, err := adapter.CreateVM(ctx, CreateVMOptions{
			Name:       vmName,
			CPUs:       1,
			MemoryMB:   256,
			DiskSizeGB: 1,
		})
		if err != nil {
			skipIfNotImplemented(t, err)
			t.Fatalf("CreateVM[%d] failed: %v", i, err)
		}
		vmIDs = append(vmIDs, result.VMID)
	}

	// Cleanup all created VMs
	t.Cleanup(func() {
		for _, id := range vmIDs {
			_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
				VMID:        id,
				DeleteDisks: true,
			})
			if deleteErr != nil {
				t.Logf("Cleanup: failed to delete VM %s: %v", id, deleteErr)
			}
		}
	})

	// List all VMs
	listResult, err := adapter.ListVMs(ctx, ListVMsOptions{})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("ListVMs failed: %v", err)
	}

	if len(listResult.VMs) < 2 {
		t.Errorf("Expected at least 2 VMs in list, got %d", len(listResult.VMs))
	}

	// Verify our created VMs appear in the list
	foundCount := 0
	for _, vm := range listResult.VMs {
		for _, id := range vmIDs {
			if vm.VMID == id {
				foundCount++
			}
		}
	}

	if foundCount != len(vmIDs) {
		t.Errorf("Expected to find %d test VMs in list, found %d", len(vmIDs), foundCount)
	}
}

// testVMListFiltered tests listing VMs with label-based filtering.
func testVMListFiltered(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	filterLabel := "test-filter-" + testID

	// Create a VM with a unique label
	vmName := generateTestVMName("filtered-" + testID)
	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   256,
		DiskSizeGB: 1,
		Labels: map[string]string{
			"env":     filterLabel,
			"purpose": "filter-test",
		},
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("CreateVM failed: %v", err)
	}

	vmID := createResult.VMID
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	// List with matching label
	listResult, err := adapter.ListVMs(ctx, ListVMsOptions{
		Labels: map[string]string{
			"env": filterLabel,
		},
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("ListVMs with filter failed: %v", err)
	}

	if len(listResult.VMs) < 1 {
		t.Fatalf("Expected at least 1 VM with label env=%s, got %d", filterLabel, len(listResult.VMs))
	}

	// Verify our VM is in the result
	found := false
	for _, vm := range listResult.VMs {
		if vm.VMID == vmID {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected to find VM %s in filtered list", vmID)
	}
}

// testVMCreateWithLabels tests creating a VM with labels and verifying them.
func testVMCreateWithLabels(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	testID := uuid.New().String()[:8]
	vmName := generateTestVMName("labels-" + testID)

	labels := map[string]string{
		"env":     "test",
		"team":    "platform",
		"purpose": "integration-" + testID,
	}

	createResult, err := adapter.CreateVM(ctx, CreateVMOptions{
		Name:       vmName,
		CPUs:       1,
		MemoryMB:   256,
		DiskSizeGB: 1,
		Labels:     labels,
	})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("CreateVM with labels failed: %v", err)
	}

	vmID := createResult.VMID
	t.Cleanup(func() {
		_, deleteErr := adapter.DeleteVM(ctx, DeleteVMOptions{
			VMID:        vmID,
			DeleteDisks: true,
		})
		if deleteErr != nil {
			t.Logf("Cleanup: failed to delete VM %s: %v", vmID, deleteErr)
		}
	})

	// Retrieve VM and verify labels
	getResult, err := adapter.GetVM(ctx, GetVMOptions{VMID: vmID})
	if err != nil {
		skipIfNotImplemented(t, err)
		t.Fatalf("GetVM failed: %v", err)
	}

	for key, expectedVal := range labels {
		actualVal, ok := getResult.Labels[key]
		if !ok {
			t.Errorf("Expected label %q not found on VM", key)
			continue
		}
		if actualVal != expectedVal {
			t.Errorf("Label %q: expected %q, got %q", key, expectedVal, actualVal)
		}
	}
}

// testVMDeleteNotFound tests deleting a non-existent VM and expecting an error.
func testVMDeleteNotFound(t *testing.T, ctx context.Context, adapter ComputeCommands) {
	fakeID := "nonexistent-vm-" + uuid.New().String()[:8]

	_, err := adapter.DeleteVM(ctx, DeleteVMOptions{
		VMID:        fakeID,
		DeleteDisks: true,
	})
	if err == nil {
		t.Error("Expected error when deleting non-existent VM, got nil")
		return
	}

	skipIfNotImplemented(t, err)

	// The operation should have returned an error; we just verify it did
	t.Logf("Delete non-existent VM returned expected error: %v", err)
}
