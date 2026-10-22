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
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestQEMUOrchestrator_Start_MoreEdgeCases tests additional Start edge cases
func TestQEMUOrchestrator_Start_MoreEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("Start already running instance", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Manually set state to running to test the edge case
		orch.mu.Lock()
		orch.lifecycle.SetState(instance.ID, StateStarting)
		orch.lifecycle.SetState(instance.ID, StateRunning)
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.instance.State = StateRunning
		}
		orch.mu.Unlock()

		// Try to start again
		err = orch.Start(ctx, instance.ID)
		if err != ErrInstanceAlreadyRunning {
			t.Errorf("Expected ErrInstanceAlreadyRunning, got %v", err)
		}
	})

	t.Run("Start instance in invalid state", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Set to an invalid starting state (Starting)
		orch.mu.Lock()
		orch.lifecycle.SetState(instance.ID, StateStarting)
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.instance.State = StateStarting
		}
		orch.mu.Unlock()

		// Try to start - should fail because not in Stopped state
		err = orch.Start(ctx, instance.ID)
		if err == nil {
			t.Error("Expected error when starting from non-stopped state")
		}
	})
}

// TestQEMUOrchestrator_Stop_MoreEdgeCases tests additional Stop edge cases
func TestQEMUOrchestrator_Stop_MoreEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("Stop stopped instance", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Instance starts in Stopped state by default
		err = orch.Stop(ctx, instance.ID)
		if err != ErrInstanceNotRunning {
			t.Errorf("Expected ErrInstanceNotRunning, got %v", err)
		}
	})

	t.Run("Stop instance in error state", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		// Set to error state
		orch.mu.Lock()
		orch.lifecycle.SetState(instance.ID, StateError)
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.instance.State = StateError
		}
		orch.mu.Unlock()

		// Try to stop - should fail because not running
		err = orch.Stop(ctx, instance.ID)
		if err != ErrInstanceNotRunning {
			t.Errorf("Expected ErrInstanceNotRunning, got %v", err)
		}
	})
}

// TestQEMUOrchestrator_AttachNetwork_MoreEdgeCases tests additional AttachNetwork edge cases
func TestQEMUOrchestrator_AttachNetwork_MoreEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("AttachNetwork when already attached", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Manually set network attached
		orch.mu.Lock()
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.networkAttached = true
		}
		// Set OVS client to simulate it being available
		// But since we don't have a real OVS, it will fail at OVS client nil check
		orch.mu.Unlock()

		// Try to attach again - will fail because OVS client is nil
		// but the code path that checks already attached should be exercised
		err = orch.AttachNetwork(ctx, instance.ID, "test-port")
		if err == nil {
			t.Error("Expected error when attaching network")
		}
	})
}

// TestQEMUOrchestrator_DetachNetwork_MoreEdgeCases tests additional DetachNetwork edge cases
func TestQEMUOrchestrator_DetachNetwork_MoreEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("DetachNetwork with different port name", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Set network attached with multiple attachments
		orch.mu.Lock()
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.networkAttached = true
			qemuInst.primaryPortName = "port-1"
			qemuInst.primaryBridgeName = "br-int"
			qemuInst.instance.NetworkAttachments = []NetworkAttachment{
				{
					PortName:   "port-1",
					BridgeName: "br-int",
					AttachedAt: time.Now(),
				},
				{
					PortName:   "port-2",
					BridgeName: "br-int",
					AttachedAt: time.Now(),
				},
			}
		}
		orch.instanceToPort[instance.ID] = "port-1"
		orch.mu.Unlock()

		// Detach port-2 (not the primary port)
		err = orch.DetachNetwork(ctx, instance.ID, "port-2")
		if err != nil {
			t.Fatalf("Failed to detach network: %v", err)
		}

		// Verify port-2 was removed from attachments
		retrieved, _ := orch.Get(ctx, instance.ID)
		foundPort2 := false
		for _, att := range retrieved.NetworkAttachments {
			if att.PortName == "port-2" {
				foundPort2 = true
			}
		}
		if foundPort2 {
			t.Error("Expected port-2 to be removed from network attachments")
		}
	})
}

// TestQEMUOrchestrator_Wait_StoppedInstance tests Wait on stopped instance
func TestQEMUOrchestrator_Wait_StoppedInstance(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("Wait on stopped instance returns immediately", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Wait should return immediately since the instance is stopped
		// and has never had a run
		done := make(chan bool)
		go func() {
			orch.Wait(ctx, instance.ID)
			done <- true
		}()

		select {
		case <-done:
			// Good - Wait returned
		case <-time.After(100 * time.Millisecond):
			t.Error("Wait should have returned immediately for stopped instance")
		}
	})
}

// TestQEMUOrchestrator_Delete_MoreEdgeCases tests additional Delete edge cases
func TestQEMUOrchestrator_Delete_MoreEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("Delete instance in error state removes it", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		// A failed start leaves the VM in error; delete is the one way out.
		orch.mu.Lock()
		orch.lifecycle.SetState(instance.ID, StateError)
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.instance.State = StateError
		}
		orch.mu.Unlock()

		if err := orch.Delete(ctx, instance.ID); err != nil {
			t.Fatalf("Delete of an instance in error state: %v", err)
		}
		if _, err := orch.Get(ctx, instance.ID); !errors.Is(err, ErrInstanceNotFound) {
			t.Errorf("Get after delete = %v, want ErrInstanceNotFound", err)
		}
	})

	t.Run("Delete with OVS network attached", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		// Simulate OVS network attached (will be nil, but code path should execute)
		orch.mu.Lock()
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.networkAttached = true
			// ovsNetwork is nil, so cleanup will be skipped
		}
		orch.mu.Unlock()

		// Delete should still work
		err = orch.Delete(ctx, instance.ID)
		if err != nil {
			t.Fatalf("Failed to delete instance with network attached: %v", err)
		}
	})
}

// TestLifecycleManager_WaitForState_InstanceDeleted tests WaitForState when instance is deleted
func TestLifecycleManager_WaitForState_InstanceDeleted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lm := NewLifecycleManager()
		mustSetState(t, lm, "test-instance", StateCreating)

		// Delete the instance while waiting
		done := startWaitForState(lm, "test-instance", StateStopped, 200*time.Millisecond)
		if err := lm.DeleteInstance("test-instance"); err != nil {
			t.Fatalf("DeleteInstance() error = %v", err)
		}

		// Wait should return error because instance is deleted
		if err := <-done; err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})
}

// TestInstanceFilter_Matches_TimeFilters tests time-based filtering
func TestInstanceFilter_Matches_TimeFilters(t *testing.T) {
	now := time.Now()
	hourAgo := now.Add(-1 * time.Hour)
	hourFromNow := now.Add(1 * time.Hour)

	instance := &Instance{
		ID:        "test-instance",
		Name:      "test-vm",
		Type:      ComputeTypeVM,
		State:     StateRunning,
		CreatedAt: now,
	}

	t.Run("CreatedAfter filters correctly", func(t *testing.T) {
		filter := &InstanceFilter{CreatedAfter: &hourAgo}
		if !filter.Matches(instance) {
			t.Error("Instance created now should match CreatedAfter hour ago")
		}

		filter = &InstanceFilter{CreatedAfter: &hourFromNow}
		if filter.Matches(instance) {
			t.Error("Instance created now should not match CreatedAfter hour from now")
		}
	})

	t.Run("CreatedBefore filters correctly", func(t *testing.T) {
		filter := &InstanceFilter{CreatedBefore: &hourFromNow}
		if !filter.Matches(instance) {
			t.Error("Instance created now should match CreatedBefore hour from now")
		}

		filter = &InstanceFilter{CreatedBefore: &hourAgo}
		if filter.Matches(instance) {
			t.Error("Instance created now should not match CreatedBefore hour ago")
		}
	})
}

// TestQEMUOrchestrator_List_Empty tests List on empty orchestrator
func TestQEMUOrchestrator_List_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	instances, err := orch.List(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to list instances: %v", err)
	}
	if len(instances) != 0 {
		t.Errorf("Expected empty list, got %d instances", len(instances))
	}
}

// TestQEMUOrchestrator_Create_DuplicateCheck tests instance ID collision handling
func TestQEMUOrchestrator_Create_DuplicateCheck(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profiles := []*entities.DeviceProfile{
		{ID: 1, Name: "vm-1"},
		{ID: 2, Name: "vm-2"},
		{ID: 3, Name: "vm-3"},
	}

	ctx := context.Background()
	createdIDs := make(map[string]bool)

	// Create multiple instances and verify unique IDs
	for _, profile := range profiles {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		if createdIDs[instance.ID] {
			t.Errorf("Duplicate instance ID detected: %s", instance.ID)
		}
		createdIDs[instance.ID] = true
	}
}

// TestQEMUOrchestrator_Get_CopiesData tests that Get returns a copy
func TestQEMUOrchestrator_Get_CopiesData(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Get the instance
	retrieved, err := orch.Get(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to get instance: %v", err)
	}

	// Modify the retrieved instance
	retrieved.Name = "modified-name"

	// Get again and verify original is unchanged
	retrieved2, err := orch.Get(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to get instance: %v", err)
	}

	if retrieved2.Name == "modified-name" {
		t.Error("Get should return a copy, not the original")
	}
}

// TestLifecycleManager_ListInstances_Copy tests that ListInstances returns a copy
func TestLifecycleManager_ListInstances_Copy(t *testing.T) {
	lm := NewLifecycleManager()

	lm.SetState("instance-1", StateRunning)
	lm.SetState("instance-2", StateStopped)

	// Get list
	list := lm.ListInstances()

	// Modify returned map
	list["instance-3"] = StateError

	// Get list again and verify original is unchanged
	list2 := lm.ListInstances()
	if _, exists := list2["instance-3"]; exists {
		t.Error("ListInstances should return a copy, not the original map")
	}
}

// TestQEMUOrchestrator_Get_NonExistent tests Get with non-existent instance
func TestQEMUOrchestrator_Get_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	_, err = orch.Get(ctx, "non-existent-id")
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestQEMUOrchestrator_Get_EmptyID tests Get with empty instance ID
func TestQEMUOrchestrator_Get_EmptyID(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	_, err = orch.Get(ctx, "")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestQEMUOrchestrator_Delete_NonExistent tests Delete with non-existent instance
func TestQEMUOrchestrator_Delete_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	err = orch.Delete(ctx, "non-existent-id")
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestQEMUOrchestrator_Delete_EmptyID tests Delete with empty instance ID
func TestQEMUOrchestrator_Delete_EmptyID(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	err = orch.Delete(ctx, "")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestQEMUOrchestrator_AttachNetwork_EmptyID tests AttachNetwork with empty instance ID
func TestQEMUOrchestrator_AttachNetwork_EmptyID(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	err = orch.AttachNetwork(ctx, "", "test-port")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestQEMUOrchestrator_AttachNetwork_NonExistent tests AttachNetwork with non-existent instance
func TestQEMUOrchestrator_AttachNetwork_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	err = orch.AttachNetwork(ctx, "non-existent", "test-port")
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestQEMUOrchestrator_DetachNetwork_EmptyID tests DetachNetwork with empty instance ID
func TestQEMUOrchestrator_DetachNetwork_EmptyID(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	err = orch.DetachNetwork(ctx, "", "test-port")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestQEMUOrchestrator_DetachNetwork_NonExistent tests DetachNetwork with non-existent instance
func TestQEMUOrchestrator_DetachNetwork_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	err = orch.DetachNetwork(ctx, "non-existent", "test-port")
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestQEMUOrchestrator_Create_MaxInstances tests max instances limit
func TestQEMUOrchestrator_Create_MaxInstances(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir
	config.MaxInstances = 2

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := newFakeHostOrchestrator(t, config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	// Create first instance
	_, err = orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create first instance: %v", err)
	}

	// Create second instance
	_, err = orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create second instance: %v", err)
	}

	// Third instance should fail due to max instances limit
	_, err = orch.Create(ctx, profile)
	if err != ErrResourceExhausted {
		t.Errorf("Expected ErrResourceExhausted, got %v", err)
	}
}
