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
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// TestContainerOrchestrator_NewContainerOrchestrator_NilConfig tests NewContainerOrchestrator with nil config
func TestContainerOrchestrator_NewContainerOrchestrator_NilConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	_, err := NewContainerOrchestrator(nil, logger)
	if err == nil {
		t.Error("Expected error for nil config")
	}
}

// TestContainerOrchestrator_NewContainerOrchestrator_NilLogger tests NewContainerOrchestrator with nil logger
func TestContainerOrchestrator_NewContainerOrchestrator_NilLogger(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()

	orch, err := NewContainerOrchestrator(config, nil, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer orch.Close()

	// Should have default logger
	if orch.logger == nil {
		t.Error("Expected default logger to be set")
	}
}

// TestContainerOrchestrator_NewContainerOrchestrator_WrongComputeType tests NewContainerOrchestrator with wrong compute type
func TestContainerOrchestrator_NewContainerOrchestrator_WrongComputeType(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	_, err := NewContainerOrchestrator(config, logger)
	if err == nil {
		t.Error("Expected error for wrong compute type")
	}
}

// TestContainerOrchestrator_Create_Closed tests Create when orchestrator is closed
func TestContainerOrchestrator_Create_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Close the orchestrator
	orch.Close()

	// Try to create an instance
	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	_, err = orch.Create(ctx, profile)
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_Create_PodmanError tests Create when Podman fails
func TestContainerOrchestrator_Create_PodmanError(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	mockManager.createErr = errors.New("podman error")

	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	_, err = orch.Create(ctx, profile)
	if err == nil {
		t.Error("Expected error when Podman fails")
	}
}

// TestContainerOrchestrator_Start_Closed tests Start when orchestrator is closed
func TestContainerOrchestrator_Start_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	err = orch.Start(ctx, "test-id")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_Start_EmptyID tests Start with empty ID
func TestContainerOrchestrator_Start_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.Start(ctx, "")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestContainerOrchestrator_Start_PodmanError tests Start when Podman fails
func TestContainerOrchestrator_Start_PodmanError(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Set start error
	mockManager.startErr = errors.New("podman start error")

	err = orch.Start(ctx, instance.ID)
	if err == nil {
		t.Error("Expected error when Podman start fails")
	}
}

// TestContainerOrchestrator_Stop_Closed tests Stop when orchestrator is closed
func TestContainerOrchestrator_Stop_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	err = orch.Stop(ctx, "test-id")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_Stop_EmptyID tests Stop with empty ID
func TestContainerOrchestrator_Stop_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.Stop(ctx, "")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestContainerOrchestrator_Stop_PodmanError tests Stop when Podman fails
func TestContainerOrchestrator_Stop_PodmanError(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Start the instance
	err = orch.Start(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to start instance: %v", err)
	}

	// Set stop error
	mockManager.stopErr = errors.New("podman stop error")

	err = orch.Stop(ctx, instance.ID)
	if err == nil {
		t.Error("Expected error when Podman stop fails")
	}
}

// TestContainerOrchestrator_Delete_Closed tests Delete when orchestrator is closed
func TestContainerOrchestrator_Delete_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	err = orch.Delete(ctx, "test-id")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_Delete_EmptyID tests Delete with empty ID
func TestContainerOrchestrator_Delete_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
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

// TestContainerOrchestrator_Wait_Closed tests Wait when orchestrator is closed
func TestContainerOrchestrator_Wait_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	err = orch.Wait(ctx, "test-id")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_Wait_EmptyID tests Wait with empty ID
func TestContainerOrchestrator_Wait_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.Wait(ctx, "")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestContainerOrchestrator_Wait_PodmanError tests Wait when Podman fails
func TestContainerOrchestrator_Wait_PodmanError(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Set wait error
	mockManager.waitErr = errors.New("podman wait error")

	err = orch.Wait(ctx, instance.ID)
	if err == nil {
		t.Error("Expected error when Podman wait fails")
	}
}

// TestContainerOrchestrator_GetState_Closed tests GetState when orchestrator is closed
func TestContainerOrchestrator_GetState_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	_, err = orch.GetState(ctx, "test-id")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_GetState_EmptyID tests GetState with empty ID
func TestContainerOrchestrator_GetState_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	_, err = orch.GetState(ctx, "")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestContainerOrchestrator_List_Closed tests List when orchestrator is closed
func TestContainerOrchestrator_List_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	_, err = orch.List(ctx, nil)
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_Get_Closed tests Get when orchestrator is closed
func TestContainerOrchestrator_Get_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	_, err = orch.Get(ctx, "test-id")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_Get_EmptyID tests Get with empty ID
func TestContainerOrchestrator_Get_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
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

// TestContainerOrchestrator_AttachNetwork_Closed tests AttachNetwork when orchestrator is closed
func TestContainerOrchestrator_AttachNetwork_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	err = orch.AttachNetwork(ctx, "test-id", "port")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_AttachNetwork_EmptyID tests AttachNetwork with empty ID
func TestContainerOrchestrator_AttachNetwork_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.AttachNetwork(ctx, "", "port")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestContainerOrchestrator_AttachNetwork_EmptyPort tests AttachNetwork with empty port
func TestContainerOrchestrator_AttachNetwork_EmptyPort(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.AttachNetwork(ctx, "test-id", "")
	if err == nil {
		t.Error("Expected error for empty port name")
	}
}

// TestContainerOrchestrator_DetachNetwork_Closed tests DetachNetwork when orchestrator is closed
func TestContainerOrchestrator_DetachNetwork_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	err = orch.DetachNetwork(ctx, "test-id", "port")
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_DetachNetwork_EmptyID tests DetachNetwork with empty ID
func TestContainerOrchestrator_DetachNetwork_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.DetachNetwork(ctx, "", "port")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestContainerOrchestrator_DetachNetwork_EmptyPort tests DetachNetwork with empty port
func TestContainerOrchestrator_DetachNetwork_EmptyPort(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.DetachNetwork(ctx, "test-id", "")
	if err == nil {
		t.Error("Expected error for empty port name")
	}
}

// TestContainerOrchestrator_ActivateInstance_Closed tests ActivateInstance when orchestrator is closed
func TestContainerOrchestrator_ActivateInstance_Closed(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	orch.Close()

	ctx := context.Background()
	portPolicy := &policy.PortPolicy{TenantID: "test", VLAN: 100}
	err = orch.ActivateInstance(ctx, "test-id", portPolicy)
	if err != ErrOrchestratorNotInitialized {
		t.Errorf("Expected ErrOrchestratorNotInitialized, got %v", err)
	}
}

// TestContainerOrchestrator_ActivateInstance_EmptyID tests ActivateInstance with empty ID
func TestContainerOrchestrator_ActivateInstance_EmptyID(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.PortAuthEnabled = true
	config.PolicyEngine = newContainerTestPolicyEngine()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	portPolicy := &policy.PortPolicy{TenantID: "test", VLAN: 100}
	err = orch.ActivateInstance(ctx, "", portPolicy)
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestContainerOrchestrator_ActivateInstance_NilPolicy tests ActivateInstance with nil policy
func TestContainerOrchestrator_ActivateInstance_NilPolicy(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.PortAuthEnabled = true
	config.PolicyEngine = newContainerTestPolicyEngine()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	err = orch.ActivateInstance(ctx, "test-id", nil)
	if err == nil {
		t.Error("Expected error for nil policy")
	}
}

// TestContainerOrchestrator_ActivateInstance_NoPortAuth tests ActivateInstance without port auth
func TestContainerOrchestrator_ActivateInstance_NoPortAuth(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.PortAuthEnabled = false

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()
	portPolicy := &policy.PortPolicy{TenantID: "test", VLAN: 100}
	err = orch.ActivateInstance(ctx, "test-id", portPolicy)
	if err == nil {
		t.Error("Expected error when port auth not enabled")
	}
}

// TestContainerStateMappings tests the container state mapping functions
func TestContainerStateMappings(t *testing.T) {
	t.Run("mapContainerStateToInstanceState", func(t *testing.T) {
		tests := []struct {
			input    podman.ContainerState
			expected InstanceState
		}{
			{podman.ContainerStateCreated, StateStopped},
			{podman.ContainerStateRunning, StateRunning},
			{podman.ContainerStatePaused, StateRunning},
			{podman.ContainerStateStopped, StateStopped},
			{podman.ContainerStateExited, StateStopped},
			{podman.ContainerStateUnknown, StateUnknown},
		}

		for _, tt := range tests {
			result := mapContainerStateToInstanceState(tt.input)
			if result != tt.expected {
				t.Errorf("mapContainerStateToInstanceState(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("mapInstanceStateToContainerState", func(t *testing.T) {
		tests := []struct {
			input    InstanceState
			expected podman.ContainerState
		}{
			{StateCreating, podman.ContainerStateCreated},
			{StateStopped, podman.ContainerStateStopped},
			{StateStarting, podman.ContainerStateRunning},
			{StateRunning, podman.ContainerStateRunning},
			{StateStopping, podman.ContainerStateStopped},
			{StateError, podman.ContainerStateExited},
			{StateDeleting, podman.ContainerStateExited},
			{StateUnknown, podman.ContainerStateUnknown},
		}

		for _, tt := range tests {
			result := mapInstanceStateToContainerState(tt.input)
			if result != tt.expected {
				t.Errorf("mapInstanceStateToContainerState(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	})
}

// TestContainerOrchestrator_Close_WithRunningInstances tests Close with running instances
func TestContainerOrchestrator_Close_WithRunningInstances(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Create and start an instance
	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	err = orch.Start(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to start instance: %v", err)
	}

	// Close should stop running instances
	err = orch.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// TestContainerOrchestrator_Delete_Running tests Delete on a running instance
func TestContainerOrchestrator_Delete_Running(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Start the instance
	err = orch.Start(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to start instance: %v", err)
	}

	// Delete should stop and remove the instance
	err = orch.Delete(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to delete running instance: %v", err)
	}

	// Verify instance is gone
	_, err = orch.Get(ctx, instance.ID)
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestContainerOrchestrator_Delete_WithPortAuth tests Delete with port authentication
func TestContainerOrchestrator_Delete_WithPortAuth(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.PortAuthEnabled = true
	config.PolicyEngine = newContainerTestPolicyEngine()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Simulate network attachment with port auth
	value, _ := orch.instances.Load(instance.ID)
	contInst := value.(*containerInstance)
	contInst.primaryPortName.Store("test-port")
	contInst.primaryBridgeName.Store("trusted0")
	orch.instanceToPort.Store(instance.ID, "test-port")

	// Delete should clean up port auth
	err = orch.Delete(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to delete instance: %v", err)
	}

	// Verify instance is gone
	_, err = orch.Get(ctx, instance.ID)
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestContainerOrchestrator_List_WithFilter tests List with a filter
func TestContainerOrchestrator_List_WithFilter(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.MaxInstances = 10

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	// Create multiple instances
	for i := 0; i < 3; i++ {
		profile := createTestDeviceProfile(uint64(i+1), "test-profile")
		_, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance %d: %v", i, err)
		}
	}

	// List with filter - use pointer for type
	containerType := ComputeTypeContainer
	filter := &InstanceFilter{
		Type: &containerType,
	}
	instances, err := orch.List(ctx, filter)
	if err != nil {
		t.Fatalf("Failed to list instances: %v", err)
	}

	if len(instances) != 3 {
		t.Errorf("Expected 3 instances, got %d", len(instances))
	}

	// List with filter that doesn't match
	vmType := ComputeTypeVM
	vmFilter := &InstanceFilter{
		Type: &vmType,
	}
	instances, err = orch.List(ctx, vmFilter)
	if err != nil {
		t.Fatalf("Failed to list instances: %v", err)
	}

	if len(instances) != 0 {
		t.Errorf("Expected 0 instances, got %d", len(instances))
	}
}

// TestContainerOrchestrator_Start_InspectFails tests Start when inspect fails after start
func TestContainerOrchestrator_Start_InspectFails(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Set inspect error - this should just log warning, not fail the start
	mockManager.inspectErr = errors.New("inspect error")

	err = orch.Start(ctx, instance.ID)
	if err != nil {
		t.Errorf("Start should succeed even if inspect fails, got error: %v", err)
	}
}

// TestContainerOrchestrator_ActivateInstance_Success tests ActivateInstance success case
func TestContainerOrchestrator_ActivateInstance_Success(t *testing.T) {
	policyEngine := newContainerTestPolicyEngine()

	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.PortAuthEnabled = true
	config.PolicyEngine = policyEngine

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Set up network attachment
	value, _ := orch.instances.Load(instance.ID)
	contInst := value.(*containerInstance)
	contInst.networkAttached.Store(true)
	contInst.primaryPortName.Store("test-port")
	contInst.primaryBridgeName.Store("trusted0")
	orch.instanceToPort.Store(instance.ID, "test-port")

	// Activate instance
	portPolicy := &policy.PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
	}

	err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
	if err != nil {
		t.Fatalf("ActivateInstance failed: %v", err)
	}

	// Verify metadata was updated
	updatedInstance, _ := orch.Get(ctx, instance.ID)
	if updatedInstance.Metadata["port_state"] != "authorized" {
		t.Errorf("Expected port_state 'authorized', got %q", updatedInstance.Metadata["port_state"])
	}
}

// TestContainerOrchestrator_DetachNetwork_Success tests DetachNetwork success case
func TestContainerOrchestrator_DetachNetwork_Success(t *testing.T) {
	policyEngine := newContainerTestPolicyEngine()

	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.PortAuthEnabled = true
	config.PolicyEngine = policyEngine
	config.NetworkBridge = "trusted0"

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	profile := createTestDeviceProfile(1, "test")
	ctx := context.Background()

	instance, err := orch.Create(ctx, profile)
	if err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Set up network attachment
	value, _ := orch.instances.Load(instance.ID)
	contInst := value.(*containerInstance)
	contInst.networkAttached.Store(true)
	contInst.primaryPortName.Store("test-port")
	contInst.primaryBridgeName.Store("trusted0")
	contInst.instance.NetworkAttachments = []NetworkAttachment{
		{
			PortName:   "test-port",
			BridgeName: "trusted0",
			AttachedAt: time.Now(),
		},
	}
	orch.instanceToPort.Store(instance.ID, "test-port")

	// Detach network
	err = orch.DetachNetwork(ctx, instance.ID, "test-port")
	if err != nil {
		t.Fatalf("DetachNetwork failed: %v", err)
	}

	// Verify network is detached
	if contInst.networkAttached.Load() {
		t.Error("Expected network to be detached")
	}

	// Verify port mapping is removed
	if _, exists := orch.instanceToPort.Load(instance.ID); exists {
		t.Error("Expected port mapping to be removed")
	}
}

// TestContainerOrchestrator_Create_ResourceExhausted tests Create when max instances reached
func TestContainerOrchestrator_Create_ResourceExhausted(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.MaxInstances = 1

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger, WithContainerPodmanManager(mockManager))
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	ctx := context.Background()

	// Create first instance (should succeed)
	profile1 := createTestDeviceProfile(1, "test1")
	_, err = orch.Create(ctx, profile1)
	if err != nil {
		t.Fatalf("Failed to create first instance: %v", err)
	}

	// Create second instance (should fail due to resource exhaustion)
	profile2 := createTestDeviceProfile(2, "test2")
	_, err = orch.Create(ctx, profile2)
	if err != ErrResourceExhausted {
		t.Errorf("Expected ErrResourceExhausted, got %v", err)
	}
}

// TestWithContainerPodmanConfig tests the WithContainerPodmanConfig option
func TestWithContainerPodmanConfig(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()

	podmanConfig := &podman.PodmanConfig{
		MaxContainers: 50,
		Debug:         true,
	}

	mockManager := newMockPodmanManager()
	logger := logging.NewLogger(slog.LevelDebug, nil)

	orch, err := NewContainerOrchestrator(config, logger,
		WithContainerPodmanConfig(podmanConfig),
		WithContainerPodmanManager(mockManager),
	)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}
	defer orch.Close()

	if orch.podmanConfig != podmanConfig {
		t.Error("Expected podman config to be set")
	}
}
