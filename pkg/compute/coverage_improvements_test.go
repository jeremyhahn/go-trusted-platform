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
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// errMockPolicyEngine implements policy.PolicyEngine with configurable errors
type errMockPolicyEngine struct {
	portStates   map[string]policy.PortState
	portPolicies map[string]*policy.PortPolicy
	getStateErr  error
}

func newErrMockPolicyEngine() *errMockPolicyEngine {
	return &errMockPolicyEngine{
		portStates:   make(map[string]policy.PortState),
		portPolicies: make(map[string]*policy.PortPolicy),
	}
}

func (m *errMockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	m.portStates[portID] = state
	return nil
}

func (m *errMockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	if m.getStateErr != nil {
		return policy.PortStateUnconnected, m.getStateErr
	}
	state, ok := m.portStates[portID]
	if !ok {
		return policy.PortStateUnconnected, nil
	}
	return state, nil
}

func (m *errMockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	state, _ := m.GetPortState(portID)
	portPolicy, _ := m.GetPolicy(portID)
	return &policy.PortInfo{
		PortID: portID,
		State:  state,
		Policy: portPolicy,
	}, nil
}

func (m *errMockPolicyEngine) ApplyPolicy(portID string, portPolicy *policy.PortPolicy) error {
	m.portPolicies[portID] = portPolicy
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *errMockPolicyEngine) RemovePolicy(portID string) error {
	delete(m.portPolicies, portID)
	delete(m.portStates, portID)
	return nil
}

func (m *errMockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	portPolicy, ok := m.portPolicies[portID]
	if !ok {
		return nil, nil
	}
	return portPolicy, nil
}

func (m *errMockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	return nil
}

func (m *errMockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	portPolicy, ok := m.portPolicies[portID]
	if !ok {
		return 0, nil
	}
	return portPolicy.VLAN, nil
}

func (m *errMockPolicyEngine) BlockPort(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *errMockPolicyEngine) UnblockPort(portID string) error {
	m.portStates[portID] = policy.PortStateUnconnected
	return nil
}

func (m *errMockPolicyEngine) GetOFPort(portID string) (int32, error) {
	return 1, nil
}

func (m *errMockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	m.portStates[portID] = policy.PortStateAuthenticating
	return nil
}

func (m *errMockPolicyEngine) OnCertificateExpired(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *errMockPolicyEngine) OnCertificateRevoked(portID string) error {
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *errMockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}

// TestGetPortState_PolicyEngineError tests GetPortState when the policy engine returns an error
func TestGetPortState_PolicyEngineError(t *testing.T) {
	mockEngine := newErrMockPolicyEngine()
	mockEngine.getStateErr = errors.New("mock policy engine error")

	config := &PortAuthConfig{
		PortID:       "test-port",
		BridgeName:   "br-int",
		PolicyEngine: mockEngine,
	}

	state, err := GetPortState(config)
	if err == nil {
		t.Error("Expected error from GetPortState")
	}
	if state != policy.PortStateUnconnected {
		t.Errorf("Expected PortStateUnconnected, got %v", state)
	}
	// Verify error message contains context
	if err.Error() != "failed to get port state: mock policy engine error" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestQEMUOrchestrator_Start_AlreadyRunning tests Start when instance is already running
func TestQEMUOrchestrator_Start_AlreadyRunning(t *testing.T) {
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

	// Manually set state to running to simulate already running instance
	orch.lifecycle.states[instance.ID] = StateRunning

	err = orch.Start(ctx, instance.ID)
	if err != ErrInstanceAlreadyRunning {
		t.Errorf("Expected ErrInstanceAlreadyRunning, got %v", err)
	}
}

// TestQEMUOrchestrator_Start_InvalidState tests Start from invalid state
func TestQEMUOrchestrator_Start_InvalidState(t *testing.T) {
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

	// Manually set state to starting (invalid for starting again)
	orch.lifecycle.states[instance.ID] = StateStarting

	err = orch.Start(ctx, instance.ID)
	if err == nil {
		t.Error("Expected error when starting from invalid state")
	}
}

// TestQEMUOrchestrator_Stop_AlreadyStopped tests Stop when instance is already stopped
func TestQEMUOrchestrator_Stop_AlreadyStopped(t *testing.T) {
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

	// Instance is already stopped from creation
	err = orch.Stop(ctx, instance.ID)
	if err != ErrInstanceNotRunning {
		t.Errorf("Expected ErrInstanceNotRunning, got %v", err)
	}
}

// TestQEMUOrchestrator_Delete_WithSWTPM tests Delete with swtpm configured
func TestQEMUOrchestrator_Delete_WithSWTPM(t *testing.T) {
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

	// Delete should succeed and clean up TPM
	err = orch.Delete(ctx, instance.ID)
	if err != nil {
		t.Fatalf("Failed to delete instance: %v", err)
	}

	// Verify instance is deleted
	_, err = orch.Get(ctx, instance.ID)
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestQEMUOrchestrator_AttachNetwork_NoOVSClient tests AttachNetwork without OVS client
func TestQEMUOrchestrator_AttachNetwork_NoOVSClient(t *testing.T) {
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

	// AttachNetwork should fail without OVS client
	err = orch.AttachNetwork(ctx, instance.ID, "test-port")
	if err == nil {
		t.Error("Expected error when OVS client not available")
	}
}

// TestQEMUOrchestrator_AttachNetwork_AlreadyAttached tests AttachNetwork when already attached
func TestQEMUOrchestrator_AttachNetwork_AlreadyAttached(t *testing.T) {
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

	// Manually set network as attached
	orch.mu.Lock()
	if qemuInst, exists := orch.instances[instance.ID]; exists {
		qemuInst.networkAttached = true
	}
	orch.mu.Unlock()

	// AttachNetwork should fail because network already attached
	err = orch.AttachNetwork(ctx, instance.ID, "test-port")
	if err == nil {
		t.Error("Expected error when network already attached")
	}
}

// TestQEMUOrchestrator_DetachNetwork_NoNetworkAttached tests DetachNetwork when no network is attached
func TestQEMUOrchestrator_DetachNetwork_NoNetworkAttached(t *testing.T) {
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

	// DetachNetwork should fail because no network is attached
	err = orch.DetachNetwork(ctx, instance.ID, "test-port")
	if err == nil {
		t.Error("Expected error when no network is attached")
	}
}

// TestQEMUOrchestrator_ActivateInstance_NoNetwork tests ActivateInstance without network
func TestQEMUOrchestrator_ActivateInstance_NoNetwork(t *testing.T) {
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

	portPolicy := &policy.PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
	}

	// ActivateInstance should fail without network
	err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
	if err == nil {
		t.Error("Expected error when no network is attached")
	}
}

// TestQEMUOrchestrator_Close_MultipleInstances tests Close with multiple stopped instances
func TestQEMUOrchestrator_Close_MultipleInstances(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = tmpDir
	config.MaxInstances = 10

	logger := logging.NewLogger(slog.LevelDebug, nil)
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	ctx := context.Background()

	// Create multiple instances
	for i := 0; i < 5; i++ {
		profile := &entities.DeviceProfile{
			ID:   uint64(i + 1),
			Name: "test-profile",
		}
		_, err := orch.Create(ctx, profile)
		if err != nil {
			t.Fatalf("Failed to create instance %d: %v", i, err)
		}
	}

	// Close should succeed
	err = orch.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// TestInstanceFilter_Matches_CreatedAfter tests filter with CreatedAfter
func TestInstanceFilter_Matches_CreatedAfter(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	instance := &Instance{
		ID:        "test-id",
		Name:      "test-instance",
		Type:      ComputeTypeVM,
		State:     StateStopped,
		CreatedAt: now,
	}

	t.Run("created after past matches", func(t *testing.T) {
		filter := &InstanceFilter{CreatedAfter: &past}
		if !filter.Matches(instance) {
			t.Error("Expected filter to match")
		}
	})

	t.Run("created after future does not match", func(t *testing.T) {
		filter := &InstanceFilter{CreatedAfter: &future}
		if filter.Matches(instance) {
			t.Error("Expected filter not to match")
		}
	})
}

// TestInstanceFilter_Matches_CreatedBefore tests filter with CreatedBefore
func TestInstanceFilter_Matches_CreatedBefore(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	instance := &Instance{
		ID:        "test-id",
		Name:      "test-instance",
		Type:      ComputeTypeVM,
		State:     StateStopped,
		CreatedAt: now,
	}

	t.Run("created before future matches", func(t *testing.T) {
		filter := &InstanceFilter{CreatedBefore: &future}
		if !filter.Matches(instance) {
			t.Error("Expected filter to match")
		}
	})

	t.Run("created before past does not match", func(t *testing.T) {
		filter := &InstanceFilter{CreatedBefore: &past}
		if filter.Matches(instance) {
			t.Error("Expected filter not to match")
		}
	})
}

// TestInstanceFilter_Matches_NilInstance tests filter with nil instance
func TestInstanceFilter_Matches_NilInstance(t *testing.T) {
	filter := &InstanceFilter{Name: "test"}
	if filter.Matches(nil) {
		t.Error("Expected filter not to match nil instance")
	}
}

// TestInstanceFilter_Matches_ProfileID tests filter with ProfileID
func TestInstanceFilter_Matches_ProfileID(t *testing.T) {
	profileID := uint64(123)
	differentProfileID := uint64(456)

	instance := &Instance{
		ID:    "test-id",
		Name:  "test-instance",
		Type:  ComputeTypeVM,
		State: StateStopped,
		Profile: &entities.DeviceProfile{
			ID: profileID,
		},
	}

	t.Run("matching profile ID", func(t *testing.T) {
		filter := &InstanceFilter{ProfileID: &profileID}
		if !filter.Matches(instance) {
			t.Error("Expected filter to match")
		}
	})

	t.Run("non-matching profile ID", func(t *testing.T) {
		filter := &InstanceFilter{ProfileID: &differentProfileID}
		if filter.Matches(instance) {
			t.Error("Expected filter not to match")
		}
	})

	t.Run("nil profile with profile ID filter", func(t *testing.T) {
		instanceWithoutProfile := &Instance{
			ID:      "test-id",
			Name:    "test-instance",
			Type:    ComputeTypeVM,
			State:   StateStopped,
			Profile: nil,
		}
		filter := &InstanceFilter{ProfileID: &profileID}
		if filter.Matches(instanceWithoutProfile) {
			t.Error("Expected filter not to match instance without profile")
		}
	})
}

// TestLifecycleManager_WaitForState_InvalidState tests WaitForState with invalid target state
func TestLifecycleManager_WaitForState_InvalidState(t *testing.T) {
	lm := NewLifecycleManager()

	err := lm.WaitForState("test-instance", InstanceState("invalid"), time.Second)
	if err == nil {
		t.Error("Expected error for invalid target state")
	}
}

// TestLifecycleManager_WaitForState_EmptyID tests WaitForState with empty ID
func TestLifecycleManager_WaitForState_EmptyID(t *testing.T) {
	lm := NewLifecycleManager()

	err := lm.WaitForState("", StateStopped, time.Second)
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestLifecycleManager_WaitForState_InstanceNotFound tests WaitForState when instance not found
func TestLifecycleManager_WaitForState_InstanceNotFound(t *testing.T) {
	lm := NewLifecycleManager()

	err := lm.WaitForState("non-existent", StateStopped, time.Millisecond*200)
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestLifecycleManager_WaitForState_Timeout tests WaitForState timeout
func TestLifecycleManager_WaitForState_Timeout(t *testing.T) {
	lm := NewLifecycleManager()

	// Set initial state
	err := lm.SetState("test-instance", StateCreating)
	if err != nil {
		t.Fatalf("Failed to set initial state: %v", err)
	}

	// Wait for a state that will never be reached
	err = lm.WaitForState("test-instance", StateRunning, time.Millisecond*200)
	if err != ErrTimeout {
		t.Errorf("Expected ErrTimeout, got %v", err)
	}
}

// TestLifecycleManager_WaitForState_EntersError tests WaitForState when instance enters error state
func TestLifecycleManager_WaitForState_EntersError(t *testing.T) {
	lm := NewLifecycleManager()

	// Set initial state
	err := lm.SetState("test-instance", StateCreating)
	if err != nil {
		t.Fatalf("Failed to set initial state: %v", err)
	}

	// Start waiting in goroutine
	done := make(chan error, 1)
	go func() {
		done <- lm.WaitForState("test-instance", StateRunning, time.Second*5)
	}()

	// Transition to error state after a short delay
	time.Sleep(time.Millisecond * 150)
	lm.SetState("test-instance", StateError)

	// Check result
	select {
	case err := <-done:
		if err == nil {
			t.Error("Expected error when instance enters error state")
		}
	case <-time.After(time.Second * 2):
		t.Error("WaitForState did not return in time")
	}
}

// TestLifecycleManager_WaitForState_Success tests WaitForState success case
func TestLifecycleManager_WaitForState_Success(t *testing.T) {
	lm := NewLifecycleManager()

	// Set initial state
	err := lm.SetState("test-instance", StateCreating)
	if err != nil {
		t.Fatalf("Failed to set initial state: %v", err)
	}

	// Start waiting in goroutine
	done := make(chan error, 1)
	go func() {
		done <- lm.WaitForState("test-instance", StateStopped, time.Second*5)
	}()

	// Transition to target state after a short delay
	time.Sleep(time.Millisecond * 150)
	lm.SetState("test-instance", StateStopped)

	// Check result
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	case <-time.After(time.Second * 2):
		t.Error("WaitForState did not return in time")
	}
}

// TestLifecycleManager_GetStateTimestamp_NotFound tests GetStateTimestamp when instance not found
func TestLifecycleManager_GetStateTimestamp_NotFound(t *testing.T) {
	lm := NewLifecycleManager()

	_, err := lm.GetStateTimestamp("non-existent")
	if err != ErrInstanceNotFound {
		t.Errorf("Expected ErrInstanceNotFound, got %v", err)
	}
}

// TestOrchestratorConfig_Validate_EmptyDiskSize tests validation with empty disk size
func TestOrchestratorConfig_Validate_EmptyDiskSize(t *testing.T) {
	config := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		WorkDir:         "/tmp/test",
		DefaultMemory:   4096,
		DefaultCPUs:     2,
		DefaultDiskSize: "",
		MaxInstances:    10,
		QEMUBinary:      "qemu-system-x86_64",
		OVMFCode:        "/path/to/ovmf",
		OVMFVars:        "/path/to/vars",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for empty disk size")
	}
}

// TestOrchestratorConfig_Validate_EmptyWorkDir tests validation with empty work dir
func TestOrchestratorConfig_Validate_EmptyWorkDir(t *testing.T) {
	config := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		WorkDir:         "",
		DefaultMemory:   4096,
		DefaultCPUs:     2,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for empty work dir")
	}
}

// TestOrchestratorConfig_Validate_InvalidComputeType tests validation with invalid compute type
func TestOrchestratorConfig_Validate_InvalidComputeType(t *testing.T) {
	config := &OrchestratorConfig{
		Type:            ComputeType("invalid"),
		WorkDir:         "/tmp/test",
		DefaultMemory:   4096,
		DefaultCPUs:     2,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for invalid compute type")
	}
}

// TestOrchestratorConfig_Validate_VM_MissingQEMU tests VM config missing QEMU binary
func TestOrchestratorConfig_Validate_VM_MissingQEMU(t *testing.T) {
	config := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		WorkDir:         "/tmp/test",
		DefaultMemory:   4096,
		DefaultCPUs:     2,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
		QEMUBinary:      "",
		OVMFCode:        "/path/to/ovmf",
		OVMFVars:        "/path/to/vars",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for missing QEMU binary")
	}
}

// TestOrchestratorConfig_Validate_VM_MissingOVMFCode tests VM config missing OVMF code
func TestOrchestratorConfig_Validate_VM_MissingOVMFCode(t *testing.T) {
	config := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		WorkDir:         "/tmp/test",
		DefaultMemory:   4096,
		DefaultCPUs:     2,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
		QEMUBinary:      "qemu-system-x86_64",
		OVMFCode:        "",
		OVMFVars:        "/path/to/vars",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for missing OVMF code")
	}
}

// TestOrchestratorConfig_Validate_VM_MissingOVMFVars tests VM config missing OVMF vars
func TestOrchestratorConfig_Validate_VM_MissingOVMFVars(t *testing.T) {
	config := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		WorkDir:         "/tmp/test",
		DefaultMemory:   4096,
		DefaultCPUs:     2,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
		QEMUBinary:      "qemu-system-x86_64",
		OVMFCode:        "/path/to/ovmf",
		OVMFVars:        "",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Expected error for missing OVMF vars")
	}
}

// TestDefaultOrchestratorConfig_Container tests default config for container type
func TestDefaultOrchestratorConfig_Container(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)

	if config.Type != ComputeTypeContainer {
		t.Errorf("Expected type Container, got %v", config.Type)
	}

	// Container type should not have QEMU paths set
	if config.QEMUBinary != "" {
		t.Errorf("Expected empty QEMUBinary for container, got %q", config.QEMUBinary)
	}

	// But should have valid defaults
	if config.DefaultMemory <= 0 {
		t.Error("Expected positive DefaultMemory")
	}
	if config.DefaultCPUs <= 0 {
		t.Error("Expected positive DefaultCPUs")
	}
}

// TestQEMUOrchestrator_Wait_EmptyID tests Wait with empty instance ID
func TestQEMUOrchestrator_Wait_EmptyID(t *testing.T) {
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

	err = orch.Wait(ctx, "")
	if err != ErrInvalidInstanceID {
		t.Errorf("Expected ErrInvalidInstanceID, got %v", err)
	}
}

// TestQEMUOrchestrator_Wait_NotFound tests Wait with non-existent instance
func TestQEMUOrchestrator_Wait_NotFound(t *testing.T) {
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

// TestQEMUOrchestrator_DetachNetwork_WithPortAuth tests DetachNetwork with port authentication
func TestQEMUOrchestrator_DetachNetwork_WithPortAuth(t *testing.T) {
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

	// Manually set network attached with port auth info
	orch.mu.Lock()
	if qemuInst, exists := orch.instances[instance.ID]; exists {
		qemuInst.networkAttached = true
		qemuInst.primaryPortName = "test-port"
		qemuInst.primaryBridgeName = "br-int"
		qemuInst.instance.NetworkAttachments = []NetworkAttachment{
			{
				PortName:   "test-port",
				BridgeName: "br-int",
				AttachedAt: time.Now(),
			},
		}
	}
	orch.instanceToPort[instance.ID] = "test-port"
	orch.mu.Unlock()

	// DetachNetwork should succeed and clean up port auth
	err = orch.DetachNetwork(ctx, instance.ID, "test-port")
	if err != nil {
		t.Fatalf("Failed to detach network: %v", err)
	}

	// Verify network is detached
	orch.mu.RLock()
	qemuInst := orch.instances[instance.ID]
	attached := qemuInst.networkAttached
	orch.mu.RUnlock()

	if attached {
		t.Error("Expected network to be detached")
	}
}

// TestQEMUOrchestrator_Delete_WithPortAuth tests Delete with port authentication enabled
func TestQEMUOrchestrator_Delete_WithPortAuth(t *testing.T) {
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

	// Set port auth info
	orch.mu.Lock()
	if qemuInst, exists := orch.instances[instance.ID]; exists {
		qemuInst.primaryPortName = "test-port"
		qemuInst.primaryBridgeName = "br-int"
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

	// Verify port mapping is removed
	orch.mu.RLock()
	_, exists := orch.instanceToPort[instance.ID]
	orch.mu.RUnlock()
	if exists {
		t.Error("Expected port mapping to be removed")
	}
}
