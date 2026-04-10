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
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewQEMUOrchestrator(t *testing.T) {
	tests := []struct {
		name    string
		config  *OrchestratorConfig
		wantErr bool
	}{
		{
			name:    "Valid config",
			config:  DefaultOrchestratorConfig(ComputeTypeVM),
			wantErr: false,
		},
		{
			name:    "Nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "Invalid config - wrong type",
			config: &OrchestratorConfig{
				Type:            ComputeTypeContainer,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		// Use temp directory for test
		if tt.config != nil && tt.name == "Valid config" {
			tmpDir := t.TempDir()
			tt.config.WorkDir = tmpDir
		}

		t.Run(tt.name, func(t *testing.T) {
			logger := logging.NewLogger(slog.LevelDebug, nil)
			orch, err := NewQEMUOrchestrator(tt.config, logger)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewQEMUOrchestrator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if orch == nil {
					t.Fatal("Expected non-nil orchestrator")
				}
				if orch.config != tt.config {
					t.Error("Config not properly set")
				}
				if orch.logger == nil {
					t.Error("Logger should not be nil")
				}
				if orch.lifecycle == nil {
					t.Error("Lifecycle manager should not be nil")
				}
				if orch.instances == nil {
					t.Error("Instances map should not be nil")
				}
				// Close orchestrator
				orch.Close()
			}
		})
	}
}

func TestQEMUOrchestrator_Create(t *testing.T) {
	// Create temporary work directory
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

	t.Run("Create instance", func(t *testing.T) {
		instance, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}

		if instance.ID == "" {
			t.Error("Instance ID should not be empty")
		}
		if instance.Name != profile.Name {
			t.Errorf("Expected name %s, got %s", profile.Name, instance.Name)
		}
		if instance.Type != ComputeTypeVM {
			t.Errorf("Expected type VM, got %s", instance.Type)
		}
		if instance.State != StateStopped {
			t.Errorf("Expected state Stopped, got %s", instance.State)
		}
		if instance.Profile.ID != profile.ID {
			t.Errorf("Expected profile ID %d, got %d", profile.ID, instance.Profile.ID)
		}

		// Verify work directory was created
		if _, err := os.Stat(instance.Config.WorkDir); os.IsNotExist(err) {
			t.Error("Work directory was not created")
		}

		// Verify disk was created
		if _, err := os.Stat(instance.Config.DiskPath); os.IsNotExist(err) {
			t.Error("Disk was not created")
		}
	})

	t.Run("Create with nil profile", func(t *testing.T) {
		_, err := orch.Create(ctx, nil)
		if err != ErrInvalidProfile {
			t.Errorf("Expected ErrInvalidProfile, got %v", err)
		}
	})

	t.Run("Max instances limit", func(t *testing.T) {
		// Set max instances to 1
		orch.config.MaxInstances = 1

		// Try to create second instance
		_, err := orch.Create(ctx, profile)
		if err != ErrResourceExhausted {
			t.Errorf("Expected ErrResourceExhausted, got %v", err)
		}
	})
}

func TestQEMUOrchestrator_GetState(t *testing.T) {
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

	t.Run("Get valid state", func(t *testing.T) {
		state, err := orch.GetState(ctx, instance.ID)
		if err != nil {
			t.Errorf("Failed to get state: %v", err)
		}
		if state != StateStopped {
			t.Errorf("Expected state Stopped, got %s", state)
		}
	})

	t.Run("Get state for non-existent instance", func(t *testing.T) {
		_, err := orch.GetState(ctx, "non-existent")
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("Get state with empty ID", func(t *testing.T) {
		_, err := orch.GetState(ctx, "")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})
}

func TestQEMUOrchestrator_Get(t *testing.T) {
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

	t.Run("Get existing instance", func(t *testing.T) {
		retrieved, err := orch.Get(ctx, instance.ID)
		if err != nil {
			t.Fatalf("Failed to get instance: %v", err)
		}

		if retrieved.ID != instance.ID {
			t.Errorf("Expected ID %s, got %s", instance.ID, retrieved.ID)
		}
		if retrieved.Name != instance.Name {
			t.Errorf("Expected name %s, got %s", instance.Name, retrieved.Name)
		}
	})

	t.Run("Get non-existent instance", func(t *testing.T) {
		_, err := orch.Get(ctx, "non-existent")
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("Get with empty ID", func(t *testing.T) {
		_, err := orch.Get(ctx, "")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})
}

func TestQEMUOrchestrator_List(t *testing.T) {
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

	t.Run("List empty", func(t *testing.T) {
		instances, err := orch.List(ctx, nil)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != 0 {
			t.Errorf("Expected 0 instances, got %d", len(instances))
		}
	})

	// Create multiple instances
	profiles := []*entities.DeviceProfile{
		{ID: 1, Name: "profile-1"},
		{ID: 2, Name: "profile-2"},
		{ID: 3, Name: "profile-3"},
	}

	for _, profile := range profiles {
		_, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
	}

	t.Run("List all", func(t *testing.T) {
		instances, err := orch.List(ctx, nil)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != len(profiles) {
			t.Errorf("Expected %d instances, got %d", len(profiles), len(instances))
		}
	})

	t.Run("List with filter by state", func(t *testing.T) {
		stoppedState := StateStopped
		filter := &InstanceFilter{State: &stoppedState}
		instances, err := orch.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != len(profiles) {
			t.Errorf("Expected %d instances, got %d", len(profiles), len(instances))
		}
		for _, inst := range instances {
			if inst.State != StateStopped {
				t.Errorf("Expected state Stopped, got %s", inst.State)
			}
		}
	})

	t.Run("List with filter by type", func(t *testing.T) {
		vmType := ComputeTypeVM
		filter := &InstanceFilter{Type: &vmType}
		instances, err := orch.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != len(profiles) {
			t.Errorf("Expected %d instances, got %d", len(profiles), len(instances))
		}
	})

	t.Run("List with filter no matches", func(t *testing.T) {
		runningState := StateRunning
		filter := &InstanceFilter{State: &runningState}
		instances, err := orch.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list instances: %v", err)
		}
		if len(instances) != 0 {
			t.Errorf("Expected 0 instances, got %d", len(instances))
		}
	})
}

func TestQEMUOrchestrator_Delete(t *testing.T) {
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

	workDir := instance.Config.WorkDir

	t.Run("Delete instance", func(t *testing.T) {
		err := orch.Delete(ctx, instance.ID)
		if err != nil {
			t.Fatalf("Failed to delete instance: %v", err)
		}

		// Verify instance is deleted
		_, err = orch.Get(ctx, instance.ID)
		if err != ErrInstanceNotFound {
			t.Errorf("Instance should be deleted, got error: %v", err)
		}

		// Verify work directory is removed
		if _, err := os.Stat(workDir); !os.IsNotExist(err) {
			t.Error("Work directory should be removed")
		}
	})

	t.Run("Delete non-existent instance", func(t *testing.T) {
		err := orch.Delete(ctx, "non-existent")
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("Delete with empty ID", func(t *testing.T) {
		err := orch.Delete(ctx, "")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})
}

func TestQEMUOrchestrator_Stop_NotRunning(t *testing.T) {
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

	// Try to stop a stopped instance
	err = orch.Stop(ctx, instance.ID)
	if err != ErrInstanceNotRunning {
		t.Errorf("Expected ErrInstanceNotRunning, got %v", err)
	}
}

func TestQEMUOrchestrator_AttachNetwork_Errors(t *testing.T) {
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

	t.Run("Attach with empty instance ID", func(t *testing.T) {
		err := orch.AttachNetwork(ctx, "", "test-port")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})

	t.Run("Attach with empty port name", func(t *testing.T) {
		err := orch.AttachNetwork(ctx, "test-instance", "")
		if err == nil || err == ErrInvalidInstanceID {
			t.Errorf("Expected error for empty port name, got %v", err)
		}
	})

	t.Run("Attach to non-existent instance", func(t *testing.T) {
		err := orch.AttachNetwork(ctx, "non-existent", "test-port")
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})
}

func TestQEMUOrchestrator_DetachNetwork_Errors(t *testing.T) {
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

	t.Run("Detach with empty instance ID", func(t *testing.T) {
		err := orch.DetachNetwork(ctx, "", "test-port")
		if err != ErrInvalidInstanceID {
			t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
		}
	})

	t.Run("Detach with empty port name", func(t *testing.T) {
		err := orch.DetachNetwork(ctx, "test-instance", "")
		if err == nil || err == ErrInvalidInstanceID {
			t.Errorf("Expected error for empty port name, got %v", err)
		}
	})

	t.Run("Detach from non-existent instance", func(t *testing.T) {
		err := orch.DetachNetwork(ctx, "non-existent", "test-port")
		if err != ErrInstanceNotFound {
			t.Errorf("Expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("Detach when no network attached", func(t *testing.T) {
		err := orch.DetachNetwork(ctx, instance.ID, "test-port")
		if err == nil {
			t.Error("Expected error when no network is attached")
		}
	})
}

func TestQEMUOrchestrator_Wait_NonExistent(t *testing.T) {
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

	err = orch.Wait(ctx, "non-existent")
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

func TestQEMUOrchestrator_Close(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Create some instances
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance: %v", err)
		}
	}

	// Close orchestrator
	err = orch.Close()
	if err != nil {
		t.Errorf("Failed to close orchestrator: %v", err)
	}
}

func TestQEMUOrchestrator_ConfigPropagation(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir
	config.DefaultMemory = 8192
	config.DefaultCPUs = 8
	config.DefaultDiskSize = "50G"

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

	// Verify config propagation
	if instance.Config.Memory != 8192 {
		t.Errorf("Expected Memory 8192, got %d", instance.Config.Memory)
	}
	if instance.Config.CPUs != 8 {
		t.Errorf("Expected CPUs 8, got %d", instance.Config.CPUs)
	}
	if instance.Config.DiskSize != "50G" {
		t.Errorf("Expected DiskSize 50G, got %s", instance.Config.DiskSize)
	}
	if !filepath.IsAbs(instance.Config.WorkDir) {
		t.Error("WorkDir should be an absolute path")
	}
}
