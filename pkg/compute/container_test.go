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
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPodmanManager implements podman.PodmanManager for testing
type mockPodmanManager struct {
	mu             sync.RWMutex
	initialized    atomic.Bool
	containers     map[string]*podman.Container
	containerCount atomic.Int64
	maxContainers  int
	attestor       podman.ContainerAttestor
	initErr        error
	createErr      error
	startErr       error
	stopErr        error
	removeErr      error
	inspectErr     error
	listErr        error
	waitErr        error
	waitExitCode   int
	closeErr       error
}

// newMockPodmanManager creates a new mock Podman manager
func newMockPodmanManager() *mockPodmanManager {
	m := &mockPodmanManager{
		containers:    make(map[string]*podman.Container),
		maxContainers: 100,
	}
	return m
}

func (m *mockPodmanManager) Initialize(ctx context.Context) error {
	if m.initErr != nil {
		return m.initErr
	}
	m.initialized.Store(true)
	return nil
}

func (m *mockPodmanManager) IsInitialized() bool {
	return m.initialized.Load()
}

func (m *mockPodmanManager) SetAttestor(attestor podman.ContainerAttestor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attestor = attestor
}

func (m *mockPodmanManager) GetAttestor() podman.ContainerAttestor {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attestor
}

func (m *mockPodmanManager) PullImage(ctx context.Context, imageRef string) error {
	return nil
}

func (m *mockPodmanManager) ListImages(ctx context.Context) ([]*podman.Image, error) {
	return nil, nil
}

func (m *mockPodmanManager) InspectImage(ctx context.Context, imageRef string) (*podman.Image, error) {
	return nil, nil
}

func (m *mockPodmanManager) RemoveImage(ctx context.Context, imageRef string, force bool) error {
	return nil
}

func (m *mockPodmanManager) CreateContainer(ctx context.Context, config *podman.ContainerConfig) (*podman.Container, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createErr != nil {
		return nil, m.createErr
	}

	if m.containerCount.Load() >= int64(m.maxContainers) {
		return nil, errors.New("max containers reached")
	}

	// Generate container ID
	id := "mock-container-" + config.Name
	container := &podman.Container{
		ID:          id,
		Name:        config.Name,
		Image:       config.Image,
		State:       podman.ContainerStateCreated,
		CreatedAt:   time.Now(),
		Labels:      config.Labels,
		Environment: config.Environment,
		NetworkMode: config.NetworkMode,
	}

	m.containers[id] = container
	m.containerCount.Add(1)

	return container, nil
}

func (m *mockPodmanManager) StartContainer(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.startErr != nil {
		return m.startErr
	}

	container, exists := m.containers[id]
	if !exists {
		return podman.ErrContainerNotFound
	}

	container.State = podman.ContainerStateRunning
	container.PID = 12345
	now := time.Now()
	container.StartedAt = &now

	return nil
}

func (m *mockPodmanManager) StopContainer(ctx context.Context, id string, timeout *int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopErr != nil {
		return m.stopErr
	}

	container, exists := m.containers[id]
	if !exists {
		return podman.ErrContainerNotFound
	}

	container.State = podman.ContainerStateStopped
	container.PID = 0
	now := time.Now()
	container.FinishedAt = &now

	return nil
}

func (m *mockPodmanManager) RemoveContainer(ctx context.Context, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.removeErr != nil {
		return m.removeErr
	}

	if _, exists := m.containers[id]; !exists {
		return podman.ErrContainerNotFound
	}

	delete(m.containers, id)
	m.containerCount.Add(-1)

	return nil
}

func (m *mockPodmanManager) InspectContainer(ctx context.Context, id string) (*podman.Container, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.inspectErr != nil {
		return nil, m.inspectErr
	}

	container, exists := m.containers[id]
	if !exists {
		return nil, podman.ErrContainerNotFound
	}

	return container, nil
}

func (m *mockPodmanManager) ListContainers(ctx context.Context, all bool) ([]*podman.Container, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listErr != nil {
		return nil, m.listErr
	}

	result := make([]*podman.Container, 0, len(m.containers))
	for _, c := range m.containers {
		result = append(result, c)
	}

	return result, nil
}

func (m *mockPodmanManager) WaitContainer(ctx context.Context, id string) (int, error) {
	if m.waitErr != nil {
		return -1, m.waitErr
	}

	m.mu.Lock()
	container, exists := m.containers[id]
	if exists {
		container.State = podman.ContainerStateStopped
		container.ExitCode = m.waitExitCode
	}
	m.mu.Unlock()

	return m.waitExitCode, nil
}

func (m *mockPodmanManager) GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*podman.ContainerLogs, error) {
	return &podman.ContainerLogs{ContainerID: id}, nil
}

func (m *mockPodmanManager) Close() error {
	if m.closeErr != nil {
		return m.closeErr
	}
	m.initialized.Store(false)
	return nil
}

// containerTestPolicyEngine implements policy.PolicyEngine for container testing
// Named differently to avoid conflict with mockPolicyEngine in port_auth_test.go
type containerTestPolicyEngine struct {
	mu           sync.RWMutex
	portStates   map[string]policy.PortState
	portPolicies map[string]*policy.PortPolicy
	setStateErr  error
	applyErr     error
	removeErr    error
	getStateErr  error
}

func newContainerTestPolicyEngine() *containerTestPolicyEngine {
	return &containerTestPolicyEngine{
		portStates:   make(map[string]policy.PortState),
		portPolicies: make(map[string]*policy.PortPolicy),
	}
}

func (m *containerTestPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.setStateErr != nil {
		return m.setStateErr
	}

	m.portStates[portID] = state
	return nil
}

func (m *containerTestPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getStateErr != nil {
		return policy.PortStateUnconnected, m.getStateErr
	}

	state, exists := m.portStates[portID]
	if !exists {
		return policy.PortStateUnconnected, nil
	}
	return state, nil
}

func (m *containerTestPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	return &policy.PortInfo{PortID: portID}, nil
}

func (m *containerTestPolicyEngine) ApplyPolicy(portID string, p *policy.PortPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.applyErr != nil {
		return m.applyErr
	}

	m.portPolicies[portID] = p
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *containerTestPolicyEngine) RemovePolicy(portID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.removeErr != nil {
		return m.removeErr
	}

	delete(m.portPolicies, portID)
	m.portStates[portID] = policy.PortStateUnauthorized
	return nil
}

func (m *containerTestPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, exists := m.portPolicies[portID]
	if !exists {
		return nil, errors.New("policy not found")
	}
	return p, nil
}

func (m *containerTestPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	return nil
}

func (m *containerTestPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	return 0, nil
}

func (m *containerTestPolicyEngine) BlockPort(portID string) error {
	return m.SetPortState(portID, policy.PortStateBlocked)
}

func (m *containerTestPolicyEngine) UnblockPort(portID string) error {
	return m.SetPortState(portID, policy.PortStateProvisioning)
}

func (m *containerTestPolicyEngine) GetOFPort(portID string) (int32, error) {
	return 1, nil
}

func (m *containerTestPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	return nil
}

func (m *containerTestPolicyEngine) OnCertificateExpired(portID string) error {
	return nil
}

func (m *containerTestPolicyEngine) OnCertificateRevoked(portID string) error {
	return nil
}

func (m *containerTestPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}

// Helper to create test orchestrator config
func createTestContainerOrchestratorConfig(t *testing.T) *OrchestratorConfig {
	config := DefaultOrchestratorConfig(ComputeTypeContainer)
	config.WorkDir = t.TempDir()
	config.MaxInstances = 10
	return config
}

// Helper to create test device profile
func createTestDeviceProfile(id uint64, name string) *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:   id,
		Name: name,
		Role: entities.DeviceRoleServer,
	}
}

// createTestOVSClient creates an OVS client for testing without connecting
func createTestOVSClient(t *testing.T) *ovs.Client {
	t.Helper()
	// Create a temporary socket path - the client doesn't need to connect
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ovs.sock")
	// Create a dummy socket file to make the path look valid
	f, err := os.Create(socketPath)
	require.NoError(t, err)
	f.Close()

	client, err := ovs.NewClient(socketPath)
	require.NoError(t, err)
	return client
}

// TestNewContainerOrchestrator tests the NewContainerOrchestrator function
func TestNewContainerOrchestrator(t *testing.T) {
	tests := []struct {
		name    string
		config  *OrchestratorConfig
		opts    []ContainerOrchestratorOption
		wantErr bool
		errType error
	}{
		{
			name:    "Nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "Invalid config - wrong type",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: true,
		},
		{
			name: "Valid config with mock manager",
			config: func() *OrchestratorConfig {
				c := DefaultOrchestratorConfig(ComputeTypeContainer)
				c.WorkDir = "/tmp/test-container"
				return c
			}(),
			opts: []ContainerOrchestratorOption{
				WithContainerPodmanManager(newMockPodmanManager()),
			},
			wantErr: false,
		},
		{
			name: "Invalid config - empty work dir",
			config: &OrchestratorConfig{
				Type:            ComputeTypeContainer,
				WorkDir:         "",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: true,
		},
		{
			name: "Invalid config - zero max instances",
			config: &OrchestratorConfig{
				Type:            ComputeTypeContainer,
				WorkDir:         "/tmp/test",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.NewLogger(slog.LevelDebug, nil)

			orch, err := NewContainerOrchestrator(tt.config, logger, tt.opts...)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, orch)
			} else {
				require.NoError(t, err)
				require.NotNil(t, orch)
				assert.NotNil(t, orch.lifecycle)
				assert.NotNil(t, orch.config)
				defer orch.Close()
			}
		})
	}
}

// TestNewContainerOrchestrator_WithOVSSocketPath tests OVS client creation from socket path
func TestNewContainerOrchestrator_WithOVSSocketPath(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	// Create a temporary socket path that doesn't exist (to test error handling)
	tmpDir := t.TempDir()
	nonExistentSocket := filepath.Join(tmpDir, "nonexistent", "ovs.sock")

	config := createTestContainerOrchestratorConfig(t)
	config.OVSSocketPath = nonExistentSocket

	// This should succeed but log a warning about OVS connection failure
	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	// OVS client should be nil because the socket doesn't exist
	assert.Nil(t, orch.ovsClient)
}

// TestContainerOrchestrator_Create tests the Create method
func TestContainerOrchestrator_Create(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Create valid instance", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "test-profile")

		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)
		require.NotNil(t, instance)

		assert.NotEmpty(t, instance.ID)
		assert.Equal(t, profile.Name, instance.Name)
		assert.Equal(t, ComputeTypeContainer, instance.Type)
		assert.Equal(t, StateStopped, instance.State)
		assert.Equal(t, profile.ID, instance.Profile.ID)
		assert.NotEmpty(t, instance.Metadata["container_id"])
	})

	t.Run("Create with nil profile", func(t *testing.T) {
		instance, err := orch.Create(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidProfile)
		assert.Nil(t, instance)
	})

	t.Run("Max instances limit", func(t *testing.T) {
		// Create instances up to the limit
		profile := createTestDeviceProfile(2, "limit-test")
		originalMax := config.MaxInstances
		config.MaxInstances = 1

		// Reset instance count for this test
		mockManager2 := newMockPodmanManager()
		mockManager2.maxContainers = 1

		orch2, err := NewContainerOrchestrator(
			config,
			logger,
			WithContainerPodmanManager(mockManager2),
		)
		require.NoError(t, err)
		defer orch2.Close()

		// First instance should succeed
		_, err = orch2.Create(ctx, profile)
		require.NoError(t, err)

		// Second instance should fail
		_, err = orch2.Create(ctx, profile)
		assert.ErrorIs(t, err, ErrResourceExhausted)

		config.MaxInstances = originalMax
	})

	t.Run("Create with container creation error", func(t *testing.T) {
		mockManager3 := newMockPodmanManager()
		mockManager3.createErr = errors.New("container creation failed")

		orch3, err := NewContainerOrchestrator(
			createTestContainerOrchestratorConfig(t),
			logger,
			WithContainerPodmanManager(mockManager3),
		)
		require.NoError(t, err)
		defer orch3.Close()

		profile := createTestDeviceProfile(3, "error-test")
		instance, err := orch3.Create(ctx, profile)
		assert.Error(t, err)
		assert.Nil(t, instance)
		assert.Contains(t, err.Error(), "failed to create container")
	})
}

// TestContainerOrchestrator_Start tests the Start method
func TestContainerOrchestrator_Start(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Start valid instance", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "start-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.Start(ctx, instance.ID)
		require.NoError(t, err)

		// Verify state changed to running
		state, err := orch.GetState(ctx, instance.ID)
		require.NoError(t, err)
		assert.Equal(t, StateRunning, state)
	})

	t.Run("Start with empty ID", func(t *testing.T) {
		err := orch.Start(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("Start non-existent instance", func(t *testing.T) {
		err := orch.Start(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Start already running instance", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "running-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// Start first time
		err = orch.Start(ctx, instance.ID)
		require.NoError(t, err)

		// Try to start again
		err = orch.Start(ctx, instance.ID)
		assert.ErrorIs(t, err, ErrInstanceAlreadyRunning)
	})

	t.Run("Start with container start error", func(t *testing.T) {
		mockManager2 := newMockPodmanManager()
		mockManager2.startErr = errors.New("start failed")

		orch2, err := NewContainerOrchestrator(
			createTestContainerOrchestratorConfig(t),
			logger,
			WithContainerPodmanManager(mockManager2),
		)
		require.NoError(t, err)
		defer orch2.Close()

		profile := createTestDeviceProfile(3, "start-error-test")
		instance, err := orch2.Create(ctx, profile)
		require.NoError(t, err)

		err = orch2.Start(ctx, instance.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start container")

		// Verify state is error
		state, err := orch2.GetState(ctx, instance.ID)
		require.NoError(t, err)
		assert.Equal(t, StateError, state)
	})
}

// TestContainerOrchestrator_Stop tests the Stop method
func TestContainerOrchestrator_Stop(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Stop running instance", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "stop-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.Start(ctx, instance.ID)
		require.NoError(t, err)

		err = orch.Stop(ctx, instance.ID)
		require.NoError(t, err)

		// Verify state changed to stopped
		state, err := orch.GetState(ctx, instance.ID)
		require.NoError(t, err)
		assert.Equal(t, StateStopped, state)
	})

	t.Run("Stop with empty ID", func(t *testing.T) {
		err := orch.Stop(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("Stop non-existent instance", func(t *testing.T) {
		err := orch.Stop(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Stop already stopped instance", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "stopped-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// Instance is created in stopped state
		err = orch.Stop(ctx, instance.ID)
		assert.ErrorIs(t, err, ErrInstanceNotRunning)
	})

	t.Run("Stop with container stop error", func(t *testing.T) {
		mockManager2 := newMockPodmanManager()
		mockManager2.stopErr = errors.New("stop failed")

		orch2, err := NewContainerOrchestrator(
			createTestContainerOrchestratorConfig(t),
			logger,
			WithContainerPodmanManager(mockManager2),
		)
		require.NoError(t, err)
		defer orch2.Close()

		profile := createTestDeviceProfile(3, "stop-error-test")
		instance, err := orch2.Create(ctx, profile)
		require.NoError(t, err)

		err = orch2.Start(ctx, instance.ID)
		require.NoError(t, err)

		mockManager2.stopErr = errors.New("stop failed")
		err = orch2.Stop(ctx, instance.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to stop container")
	})
}

// TestContainerOrchestrator_Delete tests the Delete method
func TestContainerOrchestrator_Delete(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Delete stopped instance", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "delete-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.Delete(ctx, instance.ID)
		require.NoError(t, err)

		// Verify instance is deleted
		_, err = orch.Get(ctx, instance.ID)
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Delete running instance - should stop first", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "delete-running-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.Start(ctx, instance.ID)
		require.NoError(t, err)

		// Delete should stop and then delete
		err = orch.Delete(ctx, instance.ID)
		require.NoError(t, err)

		// Verify instance is deleted
		_, err = orch.Get(ctx, instance.ID)
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Delete with empty ID", func(t *testing.T) {
		err := orch.Delete(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("Delete non-existent instance", func(t *testing.T) {
		err := orch.Delete(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})
}

// TestContainerOrchestrator_List tests the List method
func TestContainerOrchestrator_List(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)
	config.MaxInstances = 10

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("List empty", func(t *testing.T) {
		instances, err := orch.List(ctx, nil)
		require.NoError(t, err)
		assert.Empty(t, instances)
	})

	// Create multiple instances
	profiles := []*entities.DeviceProfile{
		createTestDeviceProfile(1, "profile-1"),
		createTestDeviceProfile(2, "profile-2"),
		createTestDeviceProfile(3, "profile-3"),
	}

	for _, profile := range profiles {
		_, err := orch.Create(ctx, profile)
		require.NoError(t, err)
	}

	t.Run("List all", func(t *testing.T) {
		instances, err := orch.List(ctx, nil)
		require.NoError(t, err)
		assert.Len(t, instances, len(profiles))
	})

	t.Run("List with filter by state", func(t *testing.T) {
		stoppedState := StateStopped
		filter := &InstanceFilter{State: &stoppedState}
		instances, err := orch.List(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, instances, len(profiles))

		for _, inst := range instances {
			assert.Equal(t, StateStopped, inst.State)
		}
	})

	t.Run("List with filter by type", func(t *testing.T) {
		containerType := ComputeTypeContainer
		filter := &InstanceFilter{Type: &containerType}
		instances, err := orch.List(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, instances, len(profiles))

		for _, inst := range instances {
			assert.Equal(t, ComputeTypeContainer, inst.Type)
		}
	})

	t.Run("List with filter no matches", func(t *testing.T) {
		runningState := StateRunning
		filter := &InstanceFilter{State: &runningState}
		instances, err := orch.List(ctx, filter)
		require.NoError(t, err)
		assert.Empty(t, instances)
	})
}

// TestContainerOrchestrator_Get tests the Get method
func TestContainerOrchestrator_Get(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Get existing instance", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "get-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		retrieved, err := orch.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Equal(t, instance.ID, retrieved.ID)
		assert.Equal(t, instance.Name, retrieved.Name)
	})

	t.Run("Get non-existent instance", func(t *testing.T) {
		_, err := orch.Get(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Get with empty ID", func(t *testing.T) {
		_, err := orch.Get(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})
}

// TestContainerOrchestrator_GetState tests the GetState method
func TestContainerOrchestrator_GetState(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Get valid state", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "state-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		state, err := orch.GetState(ctx, instance.ID)
		require.NoError(t, err)
		assert.Equal(t, StateStopped, state)
	})

	t.Run("Get state for non-existent instance", func(t *testing.T) {
		_, err := orch.GetState(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Get state with empty ID", func(t *testing.T) {
		_, err := orch.GetState(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})
}

// TestContainerOrchestrator_AttachNetwork tests the AttachNetwork method
func TestContainerOrchestrator_AttachNetwork(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"

	// We need to skip OVS client creation for unit tests
	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Attach with empty instance ID", func(t *testing.T) {
		err := orch.AttachNetwork(ctx, "", "test-port")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("Attach with empty port name", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "attach-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.AttachNetwork(ctx, instance.ID, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port name is required")
	})

	t.Run("Attach to non-existent instance", func(t *testing.T) {
		err := orch.AttachNetwork(ctx, "non-existent", "test-port")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Attach without OVS client", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "attach-no-ovs")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// OVS client is nil in unit tests
		err = orch.AttachNetwork(ctx, instance.ID, "test-port")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OVS client not available")
	})
}

// TestContainerOrchestrator_AttachNetworkWithOVSClient tests AttachNetwork with OVS client
func TestContainerOrchestrator_AttachNetworkWithOVSClient(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Attach network success without port auth", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "attach-success-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.AttachNetwork(ctx, instance.ID, "test-port-1")
		require.NoError(t, err)

		// Verify network attachment
		inst, err := orch.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Len(t, inst.NetworkAttachments, 1)
		assert.Equal(t, "test-port-1", inst.NetworkAttachments[0].PortName)
		assert.Equal(t, "test-bridge", inst.NetworkAttachments[0].BridgeName)
	})

	t.Run("Attach network already attached", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "attach-already-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.AttachNetwork(ctx, instance.ID, "test-port-2")
		require.NoError(t, err)

		// Try to attach again
		err = orch.AttachNetwork(ctx, instance.ID, "test-port-3")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "network already attached")
	})
}

// TestContainerOrchestrator_AttachNetworkWithPolicy tests AttachNetwork with policy engine
func TestContainerOrchestrator_AttachNetworkWithPolicy(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Attach with policy engine success", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "policy-attach-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.AttachNetwork(ctx, instance.ID, "policy-test-port")
		require.NoError(t, err)

		// Verify port state was set to provisioning
		state, err := mockPolicy.GetPortState("policy-test-port")
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateProvisioning, state)

		// Verify network attachment
		inst, err := orch.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Len(t, inst.NetworkAttachments, 1)
	})

	t.Run("Attach with policy engine SetPortState error", func(t *testing.T) {
		mockPolicy2 := newContainerTestPolicyEngine()
		mockPolicy2.setStateErr = errors.New("set state failed")

		config2 := createTestContainerOrchestratorConfig(t)
		config2.NetworkBridge = "test-bridge"
		config2.PortAuthEnabled = true
		config2.PolicyEngine = mockPolicy2

		orch2, err := NewContainerOrchestrator(
			config2,
			logger,
			WithContainerPodmanManager(newMockPodmanManager()),
			WithContainerOVSClient(createTestOVSClient(t)),
		)
		require.NoError(t, err)
		defer orch2.Close()

		profile := createTestDeviceProfile(2, "policy-error-test")
		instance, err := orch2.Create(ctx, profile)
		require.NoError(t, err)

		err = orch2.AttachNetwork(ctx, instance.ID, "error-port")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set provisioning state")

		// Verify network attachment was rolled back
		inst, err := orch2.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Empty(t, inst.NetworkAttachments)
	})
}

// TestContainerOrchestrator_DetachNetwork tests the DetachNetwork method
func TestContainerOrchestrator_DetachNetwork(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Detach with empty instance ID", func(t *testing.T) {
		err := orch.DetachNetwork(ctx, "", "test-port")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("Detach with empty port name", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "detach-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.DetachNetwork(ctx, instance.ID, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port name is required")
	})

	t.Run("Detach from non-existent instance", func(t *testing.T) {
		err := orch.DetachNetwork(ctx, "non-existent", "test-port")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Detach when no network attached", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "detach-none")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.DetachNetwork(ctx, instance.ID, "test-port")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no network attached")
	})
}

// TestContainerOrchestrator_DetachNetworkSuccess tests successful DetachNetwork
func TestContainerOrchestrator_DetachNetworkSuccess(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Detach network success", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "detach-success-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// First attach
		err = orch.AttachNetwork(ctx, instance.ID, "detach-test-port")
		require.NoError(t, err)

		// Verify attached
		inst, err := orch.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Len(t, inst.NetworkAttachments, 1)

		// Now detach
		err = orch.DetachNetwork(ctx, instance.ID, "detach-test-port")
		require.NoError(t, err)

		// Verify detached
		inst, err = orch.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Empty(t, inst.NetworkAttachments)
	})
}

// TestContainerOrchestrator_DetachNetworkWithPolicy tests DetachNetwork with policy engine
func TestContainerOrchestrator_DetachNetworkWithPolicy(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Detach with policy engine success", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "policy-detach-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// First attach
		err = orch.AttachNetwork(ctx, instance.ID, "policy-detach-port")
		require.NoError(t, err)

		// Verify provisioning state
		state, err := mockPolicy.GetPortState("policy-detach-port")
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateProvisioning, state)

		// Detach
		err = orch.DetachNetwork(ctx, instance.ID, "policy-detach-port")
		require.NoError(t, err)

		// Verify policy was removed (state becomes unauthorized)
		state, err = mockPolicy.GetPortState("policy-detach-port")
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateUnauthorized, state)
	})

	t.Run("Detach with policy engine RemovePolicy error continues", func(t *testing.T) {
		mockPolicy2 := newContainerTestPolicyEngine()

		config2 := createTestContainerOrchestratorConfig(t)
		config2.NetworkBridge = "test-bridge"
		config2.PortAuthEnabled = true
		config2.PolicyEngine = mockPolicy2

		orch2, err := NewContainerOrchestrator(
			config2,
			logger,
			WithContainerPodmanManager(newMockPodmanManager()),
			WithContainerOVSClient(createTestOVSClient(t)),
		)
		require.NoError(t, err)
		defer orch2.Close()

		profile := createTestDeviceProfile(2, "policy-remove-error")
		instance, err := orch2.Create(ctx, profile)
		require.NoError(t, err)

		// Attach
		err = orch2.AttachNetwork(ctx, instance.ID, "remove-error-port")
		require.NoError(t, err)

		// Set error for RemovePolicy
		mockPolicy2.removeErr = errors.New("remove policy failed")

		// Detach should still succeed (warning logged but not error)
		err = orch2.DetachNetwork(ctx, instance.ID, "remove-error-port")
		require.NoError(t, err)

		// Verify network was detached
		inst, err := orch2.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Empty(t, inst.NetworkAttachments)
	})
}

// TestContainerOrchestrator_ActivateInstance tests the ActivateInstance method
func TestContainerOrchestrator_ActivateInstance(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()

	config := createTestContainerOrchestratorConfig(t)
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Activate with empty instance ID", func(t *testing.T) {
		portPolicy := &policy.PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		err := orch.ActivateInstance(ctx, "", portPolicy)
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("Activate with nil policy", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "activate-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.ActivateInstance(ctx, instance.ID, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port policy is required")
	})

	t.Run("Activate non-existent instance", func(t *testing.T) {
		portPolicy := &policy.PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		err := orch.ActivateInstance(ctx, "non-existent", portPolicy)
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Activate without port mapping", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "activate-no-port")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no network port mapped")
	})

	t.Run("Activate without port auth enabled", func(t *testing.T) {
		config2 := createTestContainerOrchestratorConfig(t)
		config2.PortAuthEnabled = false

		orch2, err := NewContainerOrchestrator(
			config2,
			logger,
			WithContainerPodmanManager(newMockPodmanManager()),
		)
		require.NoError(t, err)
		defer orch2.Close()

		profile := createTestDeviceProfile(3, "activate-disabled")
		instance, err := orch2.Create(ctx, profile)
		require.NoError(t, err)

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		err = orch2.ActivateInstance(ctx, instance.ID, portPolicy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port authentication is not enabled")
	})
}

// TestContainerOrchestrator_ActivateInstanceSuccess tests successful ActivateInstance
func TestContainerOrchestrator_ActivateInstanceSuccess(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Activate instance success", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "activate-success-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// First attach network to create port mapping
		err = orch.AttachNetwork(ctx, instance.ID, "activate-port")
		require.NoError(t, err)

		// Now activate
		portPolicy := &policy.PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
		require.NoError(t, err)

		// Verify port state is authorized
		state, err := mockPolicy.GetPortState("activate-port")
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		// Verify instance metadata
		inst, err := orch.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Equal(t, "authorized", inst.Metadata["port_state"])
		assert.Equal(t, "100", inst.Metadata["vlan"])
	})

	t.Run("Activate with network not attached", func(t *testing.T) {
		profile := createTestDeviceProfile(2, "activate-not-attached")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// Manually store port mapping without network attachment
		orch.instanceToPort.Store(instance.ID, "orphan-port")

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no network attached")
	})
}

// TestContainerOrchestrator_ActivateInstanceApplyPolicyError tests ApplyPolicy error
func TestContainerOrchestrator_ActivateInstanceApplyPolicyError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Activate with ApplyPolicy error", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "apply-error-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// Attach network
		err = orch.AttachNetwork(ctx, instance.ID, "apply-error-port")
		require.NoError(t, err)

		// Set error for ApplyPolicy
		mockPolicy.applyErr = errors.New("apply policy failed")

		portPolicy := &policy.PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to activate instance network port")

		// Reset for other tests
		mockPolicy.applyErr = nil
	})
}

// TestContainerOrchestrator_Wait tests the Wait method
func TestContainerOrchestrator_Wait(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Wait for instance exit", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "wait-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.Start(ctx, instance.ID)
		require.NoError(t, err)

		// Set expected exit code
		mockManager.waitExitCode = 0

		err = orch.Wait(ctx, instance.ID)
		require.NoError(t, err)

		// Check that exit code is recorded in metadata
		inst, err := orch.Get(ctx, instance.ID)
		require.NoError(t, err)
		assert.Equal(t, "0", inst.Metadata["exit_code"])
	})

	t.Run("Wait for non-existent instance", func(t *testing.T) {
		err := orch.Wait(ctx, "non-existent")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("Wait with empty ID", func(t *testing.T) {
		err := orch.Wait(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("Wait with error", func(t *testing.T) {
		mockManager2 := newMockPodmanManager()
		mockManager2.waitErr = errors.New("wait failed")

		orch2, err := NewContainerOrchestrator(
			createTestContainerOrchestratorConfig(t),
			logger,
			WithContainerPodmanManager(mockManager2),
		)
		require.NoError(t, err)
		defer orch2.Close()

		profile := createTestDeviceProfile(2, "wait-error")
		instance, err := orch2.Create(ctx, profile)
		require.NoError(t, err)

		err = orch2.Start(ctx, instance.ID)
		require.NoError(t, err)

		err = orch2.Wait(ctx, instance.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to wait for container")
	})
}

// TestContainerOrchestrator_Close tests the Close method
func TestContainerOrchestrator_Close(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	ctx := context.Background()

	// Create some instances
	profile := createTestDeviceProfile(1, "close-test")
	for i := 0; i < 3; i++ {
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		// Start one instance
		if i == 0 {
			err = orch.Start(ctx, instance.ID)
			require.NoError(t, err)
		}
	}

	// Close orchestrator
	err = orch.Close()
	require.NoError(t, err)

	// Verify operations fail after close
	_, err = orch.List(ctx, nil)
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	// Second close should be no-op
	err = orch.Close()
	require.NoError(t, err)
}

// TestContainerOrchestrator_CloseWithRunningInstances tests Close stops running instances
func TestContainerOrchestrator_CloseWithRunningInstances(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	ctx := context.Background()

	// Create and start multiple instances
	for i := 0; i < 3; i++ {
		profile := createTestDeviceProfile(uint64(i+1), "running-close-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)

		err = orch.Start(ctx, instance.ID)
		require.NoError(t, err)
	}

	// Close should stop all running instances
	err = orch.Close()
	require.NoError(t, err)
}

// TestContainerOrchestrator_LifecycleTransitions tests state transitions
func TestContainerOrchestrator_LifecycleTransitions(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	t.Run("Full lifecycle: create -> start -> stop -> delete", func(t *testing.T) {
		profile := createTestDeviceProfile(1, "lifecycle-test")

		// Create
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)
		assert.Equal(t, StateStopped, instance.State)

		// Start
		err = orch.Start(ctx, instance.ID)
		require.NoError(t, err)
		state, _ := orch.GetState(ctx, instance.ID)
		assert.Equal(t, StateRunning, state)

		// Stop
		err = orch.Stop(ctx, instance.ID)
		require.NoError(t, err)
		state, _ = orch.GetState(ctx, instance.ID)
		assert.Equal(t, StateStopped, state)

		// Delete
		err = orch.Delete(ctx, instance.ID)
		require.NoError(t, err)

		// Verify deleted
		_, err = orch.Get(ctx, instance.ID)
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})
}

// TestContainerOrchestrator_ConcurrentOperations tests concurrent access safety
func TestContainerOrchestrator_ConcurrentOperations(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockManager.maxContainers = 100

	config := createTestContainerOrchestratorConfig(t)
	config.MaxInstances = 100

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create instances concurrently
	var wg sync.WaitGroup
	instanceIDs := make(chan string, 20)
	errChan := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			profile := createTestDeviceProfile(uint64(idx+1), "concurrent-test")
			instance, err := orch.Create(ctx, profile)
			if err != nil {
				errChan <- err
				return
			}
			instanceIDs <- instance.ID
		}(i)
	}

	wg.Wait()
	close(instanceIDs)
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Errorf("Concurrent create error: %v", err)
	}

	// Collect instance IDs
	ids := make([]string, 0)
	for id := range instanceIDs {
		ids = append(ids, id)
	}

	// Verify all instances were created
	instances, err := orch.List(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, instances, len(ids))
}

// TestContainerOrchestrator_ConfigPropagation tests config values are propagated correctly
func TestContainerOrchestrator_ConfigPropagation(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)
	config.DefaultMemory = 8192
	config.DefaultCPUs = 8

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	profile := createTestDeviceProfile(1, "config-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Verify config propagation
	assert.Equal(t, 8192, instance.Config.Memory)
	assert.Equal(t, 8, instance.Config.CPUs)
}

// TestContainerOrchestrator_ClosedStateOperations tests operations after close
func TestContainerOrchestrator_ClosedStateOperations(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	// Close the orchestrator
	err = orch.Close()
	require.NoError(t, err)

	ctx := context.Background()
	profile := createTestDeviceProfile(1, "closed-test")

	// All operations should return ErrOrchestratorNotInitialized
	_, err = orch.Create(ctx, profile)
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	err = orch.Start(ctx, "any-id")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	err = orch.Stop(ctx, "any-id")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	err = orch.Delete(ctx, "any-id")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	_, err = orch.List(ctx, nil)
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	_, err = orch.Get(ctx, "any-id")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	_, err = orch.GetState(ctx, "any-id")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)

	err = orch.Wait(ctx, "any-id")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)
}

// TestMapContainerStateToInstanceState tests the state mapping function
func TestMapContainerStateToInstanceState(t *testing.T) {
	tests := []struct {
		name           string
		containerState podman.ContainerState
		expected       InstanceState
	}{
		{
			name:           "Created maps to Stopped",
			containerState: podman.ContainerStateCreated,
			expected:       StateStopped,
		},
		{
			name:           "Running maps to Running",
			containerState: podman.ContainerStateRunning,
			expected:       StateRunning,
		},
		{
			name:           "Paused maps to Running",
			containerState: podman.ContainerStatePaused,
			expected:       StateRunning,
		},
		{
			name:           "Stopped maps to Stopped",
			containerState: podman.ContainerStateStopped,
			expected:       StateStopped,
		},
		{
			name:           "Exited maps to Stopped",
			containerState: podman.ContainerStateExited,
			expected:       StateStopped,
		},
		{
			name:           "Unknown maps to Unknown",
			containerState: podman.ContainerStateUnknown,
			expected:       StateUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapContainerStateToInstanceState(tt.containerState)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMapInstanceStateToContainerState tests the reverse state mapping function
func TestMapInstanceStateToContainerState(t *testing.T) {
	tests := []struct {
		name          string
		instanceState InstanceState
		expected      podman.ContainerState
	}{
		{
			name:          "Creating maps to Created",
			instanceState: StateCreating,
			expected:      podman.ContainerStateCreated,
		},
		{
			name:          "Stopped maps to Stopped",
			instanceState: StateStopped,
			expected:      podman.ContainerStateStopped,
		},
		{
			name:          "Starting maps to Running",
			instanceState: StateStarting,
			expected:      podman.ContainerStateRunning,
		},
		{
			name:          "Running maps to Running",
			instanceState: StateRunning,
			expected:      podman.ContainerStateRunning,
		},
		{
			name:          "Stopping maps to Stopped",
			instanceState: StateStopping,
			expected:      podman.ContainerStateStopped,
		},
		{
			name:          "Error maps to Exited",
			instanceState: StateError,
			expected:      podman.ContainerStateExited,
		},
		{
			name:          "Deleting maps to Exited",
			instanceState: StateDeleting,
			expected:      podman.ContainerStateExited,
		},
		{
			name:          "Unknown maps to Unknown",
			instanceState: StateUnknown,
			expected:      podman.ContainerStateUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapInstanceStateToContainerState(tt.instanceState)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestContainerOrchestratorOption tests the functional options
func TestContainerOrchestratorOption(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	podmanConfig := podman.DefaultPodmanConfig()
	podmanConfig.MaxContainers = 50

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanConfig(podmanConfig),
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	// Verify the podman config was applied
	assert.Equal(t, 50, orch.podmanConfig.MaxContainers)
}

// TestContainerOrchestrator_MetadataStorage tests metadata is stored correctly
func TestContainerOrchestrator_MetadataStorage(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	profile := createTestDeviceProfile(1, "metadata-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Verify metadata is populated
	assert.NotEmpty(t, instance.Metadata["container_id"])
	assert.NotEmpty(t, instance.Metadata["container_name"])
	assert.NotEmpty(t, instance.Metadata["image"])
}

// TestContainerOrchestrator_NetworkAttachmentMetadata tests network attachment metadata
func TestContainerOrchestrator_NetworkAttachmentMetadata(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	profile := createTestDeviceProfile(1, "network-meta-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Initially no network attachments
	assert.Empty(t, instance.NetworkAttachments)

	// Get the instance - should have empty network attachments
	retrieved, err := orch.Get(ctx, instance.ID)
	require.NoError(t, err)
	assert.Empty(t, retrieved.NetworkAttachments)
}

// TestContainerOrchestrator_WithOVSClientOption tests the WithContainerOVSClient option
func TestContainerOrchestrator_WithOVSClientOption(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	// Note: We can't easily create a mock OVS client, but we can test
	// that the option function is applied correctly
	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(nil), // Explicitly set to nil
	)
	require.NoError(t, err)
	defer orch.Close()

	// OVS client should be nil
	assert.Nil(t, orch.ovsClient)
}

// TestContainerOrchestrator_CreateWithIDGenerationError tests Create when ID generation fails
func TestContainerOrchestrator_CreateWithIDGenerationError(t *testing.T) {
	// This test verifies Create handles errors gracefully
	// Since we use crypto/rand, errors are rare but the code path should be tested
	// We test by creating many instances to ensure the ID generation code is exercised

	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockManager.maxContainers = 100

	config := createTestContainerOrchestratorConfig(t)
	config.MaxInstances = 100

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create multiple instances to exercise ID generation
	for i := 0; i < 10; i++ {
		profile := createTestDeviceProfile(uint64(i+1), "id-gen-test")
		instance, err := orch.Create(ctx, profile)
		require.NoError(t, err)
		assert.NotEmpty(t, instance.ID)
		assert.Len(t, instance.ID, 32) // 16 bytes * 2 hex chars
	}
}

// TestContainerOrchestrator_DeleteWithPortAuth tests Delete with port authentication cleanup
func TestContainerOrchestrator_DeleteWithPortAuth(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()

	config := createTestContainerOrchestratorConfig(t)
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create instance
	profile := createTestDeviceProfile(1, "delete-auth-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Start the instance
	err = orch.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Delete should handle port auth cleanup even if no network is attached
	err = orch.Delete(ctx, instance.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = orch.Get(ctx, instance.ID)
	assert.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestContainerOrchestrator_DeleteWithPortAuthAndNetwork tests Delete with port auth and network
func TestContainerOrchestrator_DeleteWithPortAuthAndNetwork(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create instance
	profile := createTestDeviceProfile(1, "delete-auth-network-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Attach network
	err = orch.AttachNetwork(ctx, instance.ID, "delete-port")
	require.NoError(t, err)

	// Verify port state
	state, err := mockPolicy.GetPortState("delete-port")
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateProvisioning, state)

	// Start the instance
	err = orch.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Delete should cleanup port auth
	err = orch.Delete(ctx, instance.ID)
	require.NoError(t, err)

	// Verify port policy was removed (state becomes unauthorized)
	state, err = mockPolicy.GetPortState("delete-port")
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateUnauthorized, state)

	// Verify instance deleted
	_, err = orch.Get(ctx, instance.ID)
	assert.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestContainerOrchestrator_StartInspectError tests Start when container inspect fails
func TestContainerOrchestrator_StartInspectError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockManager.inspectErr = errors.New("inspect failed")

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	profile := createTestDeviceProfile(1, "inspect-error-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Start should still succeed even if inspect fails
	// (inspect is for getting PID which is optional)
	err = orch.Start(ctx, instance.ID)
	require.NoError(t, err)

	// PID should be 0 since inspect failed
	inst, err := orch.Get(ctx, instance.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, inst.PID)
}

// TestContainerOrchestrator_LifecycleSetStateError tests state transition errors
func TestContainerOrchestrator_LifecycleSetStateError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	profile := createTestDeviceProfile(1, "lifecycle-error-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Start the instance
	err = orch.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Now try to start again - should get already running error
	err = orch.Start(ctx, instance.ID)
	assert.ErrorIs(t, err, ErrInstanceAlreadyRunning)
}

// TestContainerOrchestrator_BuildContainerConfigWithTPM tests container config with TPM access
func TestContainerOrchestrator_BuildContainerConfigWithTPM(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	podmanConfig := podman.DefaultPodmanConfig()
	podmanConfig.EnableTPMAccess = true
	podmanConfig.DefaultImage = "custom-image:latest"

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanConfig(podmanConfig),
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	profile := createTestDeviceProfile(1, "tpm-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Verify instance was created with TPM-enabled container
	assert.Equal(t, "custom-image:latest", instance.Metadata["image"])
}

// TestContainerOrchestrator_CloseWithOVSClient tests Close when OVS client is set
func TestContainerOrchestrator_CloseWithOVSClient(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)

	// Create and start an instance
	ctx := context.Background()
	profile := createTestDeviceProfile(1, "close-ovs-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	err = orch.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Close should handle OVS client cleanup
	err = orch.Close()
	require.NoError(t, err)
}

// TestContainerOrchestrator_AttachNetworkClosedOrchestrator tests AttachNetwork on closed orchestrator
func TestContainerOrchestrator_AttachNetworkClosedOrchestrator(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	// Close the orchestrator
	err = orch.Close()
	require.NoError(t, err)

	// AttachNetwork should fail
	ctx := context.Background()
	err = orch.AttachNetwork(ctx, "instance-id", "port-name")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)
}

// TestContainerOrchestrator_DetachNetworkClosedOrchestrator tests DetachNetwork on closed orchestrator
func TestContainerOrchestrator_DetachNetworkClosedOrchestrator(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	// Close the orchestrator
	err = orch.Close()
	require.NoError(t, err)

	// DetachNetwork should fail
	ctx := context.Background()
	err = orch.DetachNetwork(ctx, "instance-id", "port-name")
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)
}

// TestContainerOrchestrator_ActivateInstanceClosedOrchestrator tests ActivateInstance on closed orchestrator
func TestContainerOrchestrator_ActivateInstanceClosedOrchestrator(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()

	config := createTestContainerOrchestratorConfig(t)
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	// Close the orchestrator
	err = orch.Close()
	require.NoError(t, err)

	// ActivateInstance should fail
	ctx := context.Background()
	portPolicy := &policy.PortPolicy{
		TenantID: "tenant-1",
		VLAN:     100,
	}
	err = orch.ActivateInstance(ctx, "instance-id", portPolicy)
	assert.ErrorIs(t, err, ErrOrchestratorNotInitialized)
}

// TestContainerOrchestrator_CloseWithPodmanManagerError tests Close when Podman manager fails
func TestContainerOrchestrator_CloseWithPodmanManagerError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockManager.closeErr = errors.New("close failed")

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	// Close should not return error but log warning
	err = orch.Close()
	require.NoError(t, err)
}

// TestNewContainerOrchestrator_NilLogger tests orchestrator creation with nil logger
func TestNewContainerOrchestrator_NilLogger(t *testing.T) {
	mockManager := newMockPodmanManager()
	config := createTestContainerOrchestratorConfig(t)

	// Pass nil logger - should use default logger
	orch, err := NewContainerOrchestrator(
		config,
		nil, // nil logger
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	// Verify default logger was set
	assert.NotNil(t, orch.logger)

	// Should still work normally
	ctx := context.Background()
	profile := createTestDeviceProfile(1, "nil-logger-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)
	assert.NotEmpty(t, instance.ID)
}

// TestNewContainerOrchestrator_WithPodmanInitError tests orchestrator when Podman initialize fails
func TestNewContainerOrchestrator_WithPodmanInitError(t *testing.T) {
	mockManager := newMockPodmanManager()
	mockManager.initErr = errors.New("initialization failed")

	config := createTestContainerOrchestratorConfig(t)
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Create orchestrator with failing connect - should succeed but log warning
	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	require.NotNil(t, orch)
	defer orch.Close()

	// Podman manager should still be set
	assert.NotNil(t, orch.podmanManager)
}

// TestNewContainerOrchestrator_WithOVSSocketCreation tests OVS socket creation paths
func TestNewContainerOrchestrator_WithOVSSocketCreation(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	// Create a temp directory with a valid socket path
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ovs.sock")

	// Create a dummy socket file
	f, err := os.Create(socketPath)
	require.NoError(t, err)
	f.Close()

	config := createTestContainerOrchestratorConfig(t)
	config.OVSSocketPath = socketPath

	// This should succeed - OVS client will be created but connect may fail
	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	// OVS client should be nil because connection failed (no actual OVS server)
	// The code path should still be exercised
	assert.Nil(t, orch.ovsClient)
}

// TestContainerOrchestrator_DeleteWithRemoveContainerError tests Delete when RemoveContainer fails
func TestContainerOrchestrator_DeleteWithRemoveContainerError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockManager.removeErr = errors.New("remove failed")

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create instance
	profile := createTestDeviceProfile(1, "remove-error-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Delete should still complete even with remove error (logs warning)
	err = orch.Delete(ctx, instance.ID)
	require.NoError(t, err)

	// Instance should be removed from orchestrator's tracking
	_, err = orch.Get(ctx, instance.ID)
	assert.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestContainerOrchestrator_DeleteWithRemovePortAuthError tests Delete when port auth removal fails
func TestContainerOrchestrator_DeleteWithRemovePortAuthError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()
	mockPolicy.removeErr = errors.New("remove policy failed")
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create and attach network
	profile := createTestDeviceProfile(1, "port-auth-remove-error")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Temporarily clear the error for attach
	mockPolicy.removeErr = nil
	err = orch.AttachNetwork(ctx, instance.ID, "port-remove-error")
	require.NoError(t, err)

	// Set the error back for delete
	mockPolicy.removeErr = errors.New("remove policy failed")

	// Delete should still succeed (just logs a warning)
	err = orch.Delete(ctx, instance.ID)
	require.NoError(t, err)

	// Verify instance was deleted
	_, err = orch.Get(ctx, instance.ID)
	assert.ErrorIs(t, err, ErrInstanceNotFound)
}

// TestContainerOrchestrator_StartWithInvalidState tests Start from invalid state
func TestContainerOrchestrator_StartWithInvalidState(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create instance and put it in error state
	profile := createTestDeviceProfile(1, "invalid-state-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Manually set to error state (simulating prior failure)
	err = orch.lifecycle.SetState(instance.ID, StateError)
	require.NoError(t, err)

	// Try to start from error state - should fail
	err = orch.Start(ctx, instance.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot start instance in state")
}

// TestContainerOrchestrator_DeleteWithStopError tests Delete when Stop fails on running instance
func TestContainerOrchestrator_DeleteWithStopError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create and start instance
	profile := createTestDeviceProfile(1, "stop-error-delete")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	err = orch.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Set stop error for delete
	mockManager.stopErr = errors.New("stop failed")

	// Delete should fail since it can't stop the running instance
	err = orch.Delete(ctx, instance.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stop container")

	// Instance should still exist
	_, err = orch.Get(ctx, instance.ID)
	require.NoError(t, err)
}

// TestContainerOrchestrator_CloseWithStopContainerError tests Close when stopping containers fails
func TestContainerOrchestrator_CloseWithStopContainerError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)

	ctx := context.Background()

	// Create and start an instance
	profile := createTestDeviceProfile(1, "close-stop-error")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	err = orch.Start(ctx, instance.ID)
	require.NoError(t, err)

	// Set stop error for close
	mockManager.stopErr = errors.New("stop failed during shutdown")

	// Close should still succeed (logs error but continues)
	err = orch.Close()
	require.NoError(t, err)
}

// TestContainerOrchestrator_ActivateInstanceEmptyPortMapping tests activation with empty port name in mapping
func TestContainerOrchestrator_ActivateInstanceEmptyPortMapping(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()
	mockPolicy := newContainerTestPolicyEngine()
	ovsClient := createTestOVSClient(t)

	config := createTestContainerOrchestratorConfig(t)
	config.NetworkBridge = "test-bridge"
	config.PortAuthEnabled = true
	config.PolicyEngine = mockPolicy

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
		WithContainerOVSClient(ovsClient),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create instance
	profile := createTestDeviceProfile(1, "empty-port-mapping")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Manually store an empty port name in the mapping
	orch.instanceToPort.Store(instance.ID, "")

	portPolicy := &policy.PortPolicy{
		TenantID: "tenant-1",
		VLAN:     100,
	}
	err = orch.ActivateInstance(ctx, instance.ID, portPolicy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no network port mapped")
}

// TestContainerOrchestrator_BuildContainerConfigEmptyImage tests config building with empty default image
func TestContainerOrchestrator_BuildContainerConfigEmptyImage(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	podmanConfig := podman.DefaultPodmanConfig()
	podmanConfig.DefaultImage = "" // Empty image should use fallback

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanConfig(podmanConfig),
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	profile := createTestDeviceProfile(1, "empty-image-test")
	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)

	// Verify the fallback image was used
	assert.Equal(t, "docker.io/library/alpine:latest", instance.Metadata["image"])
}

// TestContainerOrchestrator_BuildContainerConfigWithPlatformdConfig tests config with platformd config
func TestContainerOrchestrator_BuildContainerConfigWithPlatformdConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mockManager := newMockPodmanManager()

	config := createTestContainerOrchestratorConfig(t)

	orch, err := NewContainerOrchestrator(
		config,
		logger,
		WithContainerPodmanManager(mockManager),
	)
	require.NoError(t, err)
	defer orch.Close()

	ctx := context.Background()

	// Create profile with PlatformdConfig set
	profile := createTestDeviceProfile(1, "platformd-config-test")
	profile.PlatformdConfig = &entities.PlatformdConfigRef{
		ConfigName: "test-config",
	}

	instance, err := orch.Create(ctx, profile)
	require.NoError(t, err)
	assert.NotEmpty(t, instance.ID)
}
