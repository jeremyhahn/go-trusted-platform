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
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// TestGenerateInstanceID tests the uniqueness and format of generated instance IDs
func TestGenerateInstanceID(t *testing.T) {
	t.Run("generates valid hex ID", func(t *testing.T) {
		id := generateInstanceID()

		if id == "" {
			t.Error("generateInstanceID() returned empty string")
		}

		// Should be 32 hex characters (16 bytes * 2)
		if len(id) != 32 {
			t.Errorf("generateInstanceID() returned ID of length %d, expected 32", len(id))
		}

		// Verify it's valid hex
		for _, c := range id {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Errorf("generateInstanceID() returned non-hex character: %c", c)
			}
		}
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		numIterations := 1000

		for i := 0; i < numIterations; i++ {
			id := generateInstanceID()
			if ids[id] {
				t.Errorf("generateInstanceID() generated duplicate ID: %s", id)
			}
			ids[id] = true
		}
	})

	t.Run("concurrent generation produces unique IDs", func(t *testing.T) {
		var mu sync.Mutex
		ids := make(map[string]bool)
		numGoroutines := 10
		numPerGoroutine := 100

		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < numPerGoroutine; j++ {
					id := generateInstanceID()
					mu.Lock()
					if ids[id] {
						t.Errorf("generateInstanceID() generated duplicate ID in concurrent test: %s", id)
					}
					ids[id] = true
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		expectedCount := numGoroutines * numPerGoroutine
		if len(ids) != expectedCount {
			t.Errorf("Expected %d unique IDs, got %d", expectedCount, len(ids))
		}
	})
}

// TestOrchestratorConfig_Validate_PortAuth tests validation with port auth enabled
func TestOrchestratorConfig_Validate_PortAuth(t *testing.T) {
	tests := []struct {
		name    string
		config  *OrchestratorConfig
		wantErr bool
	}{
		{
			name: "PortAuthEnabled without PolicyEngine",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "/path/to/vars",
				PortAuthEnabled: true,
				PolicyEngine:    nil,
			},
			wantErr: true,
		},
		{
			name: "PortAuthEnabled with PolicyEngine",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "/path/to/vars",
				PortAuthEnabled: true,
				PolicyEngine:    newMockPolicyEngine(),
			},
			wantErr: false,
		},
		{
			name: "PortAuthDisabled without PolicyEngine is OK",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "/path/to/vars",
				PortAuthEnabled: false,
				PolicyEngine:    nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("OrchestratorConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestQEMUOrchestrator_ActivateInstance tests the ActivateInstance method
func TestQEMUOrchestrator_ActivateInstance(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir
	config.PortAuthEnabled = true
	config.PolicyEngine = newMockPolicyEngine()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("ActivateInstance with empty instance ID", func(t *testing.T) {
		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err := orch.ActivateInstance(ctx, "", portPolicy)
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})

	t.Run("ActivateInstance with nil policy", func(t *testing.T) {
		err := orch.ActivateInstance(ctx, "test-instance", nil)
		if err == nil {
			t.Error("Expected error for nil port policy")
		}
	})

	t.Run("ActivateInstance with non-existent instance", func(t *testing.T) {
		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err := orch.ActivateInstance(ctx, "non-existent", portPolicy)
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("ActivateInstance without port auth enabled", func(t *testing.T) {
		// Create orchestrator without port auth
		noAuthConfig := DefaultOrchestratorConfig(ComputeTypeVM)
		noAuthConfig.WorkDir = t.TempDir()
		noAuthConfig.PortAuthEnabled = false

		noAuthOrch, err := NewQEMUOrchestrator(noAuthConfig, logger)
		if err != nil {
			t.Fatalf("Failed to create orchestrator: %v", err)
		}
		defer noAuthOrch.Close()

		instance, err := noAuthOrch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err = noAuthOrch.ActivateInstance(ctx, instance.ID, portPolicy)
		if err == nil {
			t.Error("Expected error when port auth not enabled")
		}
	})

	t.Run("ActivateInstance without network attached", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
		if err == nil {
			t.Error("Expected error when no network attached")
		}
	})

	t.Run("ActivateInstance with network attached but no port mapping", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Set network attached but no port mapping
		orch.mu.Lock()
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.networkAttached = true
		}
		orch.mu.Unlock()

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
		if err == nil {
			t.Error("Expected error when no port mapping exists")
		}
	})

	t.Run("ActivateInstance with network and port mapping", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
		defer orch.Delete(ctx, instance.ID)

		// Set network attached with port mapping
		orch.mu.Lock()
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.networkAttached = true
			qemuInst.primaryPortName = "test-port"
			qemuInst.primaryBridgeName = "trusted0"
		}
		orch.instanceToPort[instance.ID] = "test-port"
		orch.mu.Unlock()

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
		if err != nil {
			t.Fatalf("Failed to activate instance: %v", err)
		}

		// Verify metadata was updated
		updated, _ := orch.Get(ctx, instance.ID)
		if updated.Metadata["port_state"] != "authorized" {
			t.Errorf("Expected port_state=authorized, got %s", updated.Metadata["port_state"])
		}
		if updated.Metadata["vlan"] != "100" {
			t.Errorf("Expected vlan=100, got %s", updated.Metadata["vlan"])
		}
	})
}

// TestQEMUOrchestrator_Stop_EdgeCases tests Stop method edge cases
func TestQEMUOrchestrator_Stop_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	t.Run("Stop with empty instance ID", func(t *testing.T) {
		err := orch.Stop(ctx, "")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})

	t.Run("Stop non-existent instance", func(t *testing.T) {
		err := orch.Stop(ctx, "non-existent")
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})
}

// TestQEMUOrchestrator_Wait_EdgeCases tests Wait method edge cases
func TestQEMUOrchestrator_Wait_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	t.Run("Wait with empty instance ID", func(t *testing.T) {
		err := orch.Wait(ctx, "")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})
}

// TestQEMUOrchestrator_Delete_EdgeCases tests Delete method edge cases
func TestQEMUOrchestrator_Delete_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir
	config.PortAuthEnabled = true
	config.PolicyEngine = newMockPolicyEngine()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	t.Run("Delete instance with port auth info", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		// Manually set port info to simulate network attached state
		orch.mu.Lock()
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.primaryPortName = "test-port"
			qemuInst.primaryBridgeName = "trusted0"
		}
		orch.instanceToPort[instance.ID] = "test-port"
		orch.mu.Unlock()

		// Delete should clean up port auth
		err = orch.Delete(ctx, instance.ID)
		if err != nil {
			t.Fatalf("Failed to delete instance: %v", err)
		}

		// Verify instance is deleted
		_, err = orch.Get(ctx, instance.ID)
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}

		// Verify port mapping is cleaned up
		orch.mu.RLock()
		_, exists := orch.instanceToPort[instance.ID]
		orch.mu.RUnlock()
		if exists {
			t.Error("Expected instanceToPort mapping to be cleaned up")
		}
	})
}

// TestQEMUOrchestrator_AttachNetwork_EdgeCases tests AttachNetwork edge cases
func TestQEMUOrchestrator_AttachNetwork_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
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

	t.Run("AttachNetwork without OVS client", func(t *testing.T) {
		// OVS client is nil by default in tests (no OVS running)
		err := orch.AttachNetwork(ctx, instance.ID, "test-port")
		if err == nil {
			t.Error("Expected error when OVS client not available")
		}
	})
}

// TestQEMUOrchestrator_DetachNetwork_EdgeCases tests DetachNetwork edge cases
func TestQEMUOrchestrator_DetachNetwork_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir
	config.PortAuthEnabled = true
	config.PolicyEngine = newMockPolicyEngine()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
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

	t.Run("DetachNetwork when network is attached", func(t *testing.T) {
		// Manually set network attached state
		orch.mu.Lock()
		if qemuInst, exists := orch.instances[instance.ID]; exists {
			qemuInst.networkAttached = true
			qemuInst.primaryPortName = "test-port"
			qemuInst.primaryBridgeName = "trusted0"
			qemuInst.instance.NetworkAttachments = []NetworkAttachment{
				{
					PortName:   "test-port",
					BridgeName: "trusted0",
					AttachedAt: time.Now(),
				},
			}
		}
		orch.instanceToPort[instance.ID] = "test-port"
		orch.mu.Unlock()

		// Detach should succeed (even without OVS network object)
		err = orch.DetachNetwork(ctx, instance.ID, "test-port")
		if err != nil {
			t.Fatalf("Failed to detach network: %v", err)
		}

		// Verify state is updated
		orch.mu.RLock()
		qemuInst := orch.instances[instance.ID]
		networkAttached := qemuInst.networkAttached
		orch.mu.RUnlock()

		if networkAttached {
			t.Error("Expected networkAttached to be false after detach")
		}
	})
}

// TestQEMUOrchestrator_Close_WithRunningInstances tests Close with running VMs
func TestQEMUOrchestrator_Close_WithRunningInstances(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()

	// Create multiple instances
	for i := 0; i < 3; i++ {
		_, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
	}

	// Close should not error
	err = orch.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// TestLifecycleManager_GetStateTimestamp_EmptyID tests GetStateTimestamp with empty ID
func TestLifecycleManager_GetStateTimestamp_EmptyID(t *testing.T) {
	lm := NewLifecycleManager()

	_, err := lm.GetStateTimestamp("")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestLifecycleManager_StateTransition_InvalidState tests transition with invalid state
func TestLifecycleManager_StateTransition_InvalidState(t *testing.T) {
	lm := NewLifecycleManager()
	instanceID := "test-instance"

	// Set initial state
	err := lm.SetState(instanceID, StateCreating)
	if err != nil {
		t.Fatalf("Failed to set initial state: %v", err)
	}

	// Try invalid transition (Creating -> Running is not valid)
	err = lm.SetState(instanceID, StateRunning)
	if err == nil {
		t.Error("Expected error for invalid state transition")
	}
}

// TestInstanceState_CanTransitionTo_UnknownState tests transitions from unknown state
func TestInstanceState_CanTransitionTo_UnknownState(t *testing.T) {
	// Test invalid state value
	invalidState := InstanceState("totally-invalid")

	// Invalid state should not be able to transition
	if invalidState.CanTransitionTo(StateCreating) {
		t.Error("Invalid state should not be able to transition")
	}
}

// TestSetProvisioningState_ErrorCases tests additional error cases
func TestSetProvisioningState_ErrorCases(t *testing.T) {
	t.Run("empty port ID", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "",
			BridgeName:   "trusted0",
			PolicyEngine: newMockPolicyEngine(),
		}

		err := SetProvisioningState(config)
		if err == nil {
			t.Error("Expected error for empty port ID")
		}
	})

	t.Run("nil policy engine", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "test-port",
			BridgeName:   "trusted0",
			PolicyEngine: nil,
		}

		err := SetProvisioningState(config)
		if err == nil {
			t.Error("Expected error for nil policy engine")
		}
	})
}

// TestActivatePort_ErrorCases tests additional error cases
func TestActivatePort_ErrorCases(t *testing.T) {
	t.Run("empty port ID", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "",
			BridgeName:   "trusted0",
			PolicyEngine: newMockPolicyEngine(),
		}
		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err := ActivatePort(config, portPolicy)
		if err == nil {
			t.Error("Expected error for empty port ID")
		}
	})

	t.Run("nil policy engine", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "test-port",
			BridgeName:   "trusted0",
			PolicyEngine: nil,
		}
		portPolicy := &policy.PortPolicy{
			TenantID: "tenant1",
			VLAN:     100,
		}

		err := ActivatePort(config, portPolicy)
		if err == nil {
			t.Error("Expected error for nil policy engine")
		}
	})
}

// TestGetPortState_ErrorCases tests additional error cases
func TestGetPortState_ErrorCases(t *testing.T) {
	t.Run("empty port ID", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "",
			BridgeName:   "trusted0",
			PolicyEngine: newMockPolicyEngine(),
		}

		_, err := GetPortState(config)
		if err == nil {
			t.Error("Expected error for empty port ID")
		}
	})

	t.Run("nil policy engine", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "test-port",
			BridgeName:   "trusted0",
			PolicyEngine: nil,
		}

		_, err := GetPortState(config)
		if err == nil {
			t.Error("Expected error for nil policy engine")
		}
	})
}

// TestRemovePortAuth_ErrorCases tests additional error cases
func TestRemovePortAuth_ErrorCases(t *testing.T) {
	t.Run("empty port ID", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "",
			BridgeName:   "trusted0",
			PolicyEngine: newMockPolicyEngine(),
		}

		err := RemovePortAuth(config)
		if err == nil {
			t.Error("Expected error for empty port ID")
		}
	})

	t.Run("nil policy engine", func(t *testing.T) {
		config := &PortAuthConfig{
			PortID:       "test-port",
			BridgeName:   "trusted0",
			PolicyEngine: nil,
		}

		err := RemovePortAuth(config)
		if err == nil {
			t.Error("Expected error for nil policy engine")
		}
	})
}

// TestQEMUOrchestrator_List_WithFilters tests List with various filter combinations
func TestQEMUOrchestrator_List_WithFilters(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir
	config.MaxInstances = 10

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	// Create instances
	profiles := []*entities.DeviceProfile{
		{ID: 1, Name: "vm-alpha"},
		{ID: 2, Name: "vm-beta"},
		{ID: 3, Name: "vm-gamma"},
	}

	for _, profile := range profiles {
		_, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
	}

	t.Run("Filter by name", func(t *testing.T) {
		filter := &InstanceFilter{Name: "vm-alpha"}
		instances, err := orch.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != 1 {
			t.Errorf("Expected 1 instance, got %d", len(instances))
		}
		if len(instances) > 0 && instances[0].Name != "vm-alpha" {
			t.Errorf("Expected vm-alpha, got %s", instances[0].Name)
		}
	})

	t.Run("Filter by profile ID", func(t *testing.T) {
		profileID := uint64(2)
		filter := &InstanceFilter{ProfileID: &profileID}
		instances, err := orch.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != 1 {
			t.Errorf("Expected 1 instance, got %d", len(instances))
		}
	})

	t.Run("Filter with no matches", func(t *testing.T) {
		filter := &InstanceFilter{Name: "non-existent"}
		instances, err := orch.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != 0 {
			t.Errorf("Expected 0 instances, got %d", len(instances))
		}
	})

	t.Run("Combined filters", func(t *testing.T) {
		stoppedState := StateStopped
		vmType := ComputeTypeVM
		filter := &InstanceFilter{
			Type:  &vmType,
			State: &stoppedState,
		}
		instances, err := orch.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != 3 {
			t.Errorf("Expected 3 instances, got %d", len(instances))
		}
	})
}

// TestOrchestratorConfig_Validate_Comprehensive tests comprehensive validation
func TestOrchestratorConfig_Validate_Comprehensive(t *testing.T) {
	tests := []struct {
		name    string
		config  *OrchestratorConfig
		wantErr bool
	}{
		{
			name: "Negative memory",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp/test",
				DefaultMemory:   -1,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "/path/to/vars",
			},
			wantErr: true,
		},
		{
			name: "Negative CPUs",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     -1,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "/path/to/vars",
			},
			wantErr: true,
		},
		{
			name: "Negative max instances",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    -1,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "/path/to/vars",
			},
			wantErr: true,
		},
		{
			name: "Container type does not require QEMU paths",
			config: &OrchestratorConfig{
				Type:            ComputeTypeContainer,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("OrchestratorConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewQEMUOrchestrator_NilLogger tests creating orchestrator with nil logger
func TestNewQEMUOrchestrator_NilLogger(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	// Pass nil logger
	orch, err := NewQEMUOrchestrator(config, nil)
	if err != nil {
		t.Fatalf("Failed to create orchestrator with nil logger: %v", err)
	}
	defer orch.Close()

	// Should have default logger
	if orch.logger == nil {
		t.Error("Expected default logger to be set")
	}
}

// TestQEMUOrchestrator_Create_WithProfile tests Create with profile configuration
func TestQEMUOrchestrator_Create_WithProfile(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	t.Run("Create with PlatformdConfig set", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "test-profile",
			PlatformdConfig: &entities.PlatformdConfigRef{
				ConfigName: "test-config",
				ConfigPath: "/path/to/config",
				Version:    "1.0.0",
			},
		}

		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		if instance.Profile.PlatformdConfig == nil {
			t.Error("Expected PlatformdConfig to be preserved")
		}
	})
}

// TestQEMUOrchestrator_Start_EdgeCases tests Start method edge cases
func TestQEMUOrchestrator_Start_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	t.Run("Start with empty instance ID", func(t *testing.T) {
		err := orch.Start(ctx, "")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})

	t.Run("Start non-existent instance", func(t *testing.T) {
		err := orch.Start(ctx, "non-existent")
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})
}
