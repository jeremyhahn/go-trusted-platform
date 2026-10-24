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

package container

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// MockPodmanBackend is a mock implementation of PodmanBackend for testing.
type MockPodmanBackend struct {
	mu           sync.Mutex
	connected    bool
	containers   map[string]*PodmanContainer
	images       map[string]*PodmanImage
	pullError    error
	createError  error
	startError   error
	stopError    error
	removeError  error
	inspectError error
	listError    error
	logsError    error
	waitError    error
	waitExitCode int
	pullCalled   int
	createCalled int
	startCalled  int
	stopCalled   int
	removeCalled int
	logsCalled   int

	// createConfig records the effective launch configuration the backend was
	// handed, so a test can re-derive the measurement from the very value the
	// container received.
	createConfig *PodmanContainerConfig
}

func NewMockPodmanBackend() *MockPodmanBackend {
	return &MockPodmanBackend{
		containers: make(map[string]*PodmanContainer),
		images:     make(map[string]*PodmanImage),
	}
}

func (m *MockPodmanBackend) WaitContainer(ctx context.Context, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.waitError != nil {
		return 0, m.waitError
	}
	c, ok := m.containers[id]
	if !ok {
		return 0, ErrContainerNotFound
	}
	c.State = "exited"
	c.ExitCode = m.waitExitCode
	return m.waitExitCode, nil
}

func (m *MockPodmanBackend) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = true
	return nil
}

func (m *MockPodmanBackend) PullImage(ctx context.Context, imageRef string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pullCalled++
	if m.pullError != nil {
		return m.pullError
	}
	// A pulled image carries the repository manifest digest the registry
	// reported, which is what an inspect afterwards must be able to return.
	m.images[imageRef] = &PodmanImage{
		ID:      "img-" + imageRef,
		Names:   []string{imageRef},
		Digest:  testRegistryDigest(imageRef),
		Created: time.Now(),
	}
	return nil
}

func (m *MockPodmanBackend) ListImages(ctx context.Context) ([]*PodmanImage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listError != nil {
		return nil, m.listError
	}
	result := make([]*PodmanImage, 0, len(m.images))
	for _, img := range m.images {
		result = append(result, img)
	}
	return result, nil
}

func (m *MockPodmanBackend) InspectImage(ctx context.Context, imageRef string) (*PodmanImage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inspectError != nil {
		return nil, m.inspectError
	}
	img, ok := m.images[imageRef]
	if !ok {
		return nil, errors.New("image not found")
	}
	return img, nil
}

func (m *MockPodmanBackend) CreateContainer(ctx context.Context, config *PodmanContainerConfig) (*PodmanContainer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalled++
	m.createConfig = config
	if m.createError != nil {
		return nil, m.createError
	}
	id := "ctr-" + config.Name
	container := &PodmanContainer{
		ID:        id,
		Name:      config.Name,
		Image:     config.Image,
		State:     "created",
		CreatedAt: time.Now(),
		Labels:    config.Labels,
	}
	m.containers[id] = container
	m.containers[config.Name] = container
	return container, nil
}

func (m *MockPodmanBackend) StartContainer(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled++
	if m.startError != nil {
		return m.startError
	}
	container, ok := m.containers[id]
	if !ok {
		return errors.New("container not found")
	}
	container.State = "running"
	now := time.Now()
	container.StartedAt = &now
	return nil
}

func (m *MockPodmanBackend) StopContainer(ctx context.Context, id string, timeout *int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled++
	if m.stopError != nil {
		return m.stopError
	}
	container, ok := m.containers[id]
	if !ok {
		return errors.New("container not found")
	}
	container.State = "stopped"
	now := time.Now()
	container.FinishedAt = &now
	return nil
}

func (m *MockPodmanBackend) RemoveContainer(ctx context.Context, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeCalled++
	if m.removeError != nil {
		return m.removeError
	}
	container, ok := m.containers[id]
	if !ok {
		return errors.New("container not found")
	}
	delete(m.containers, id)
	delete(m.containers, container.Name)
	return nil
}

func (m *MockPodmanBackend) InspectContainer(ctx context.Context, id string) (*PodmanContainer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inspectError != nil {
		return nil, m.inspectError
	}
	container, ok := m.containers[id]
	if !ok {
		return nil, errors.New("container not found")
	}
	return container, nil
}

func (m *MockPodmanBackend) ListContainers(ctx context.Context, all bool) ([]*PodmanContainer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listError != nil {
		return nil, m.listError
	}
	seen := make(map[string]bool)
	result := make([]*PodmanContainer, 0)
	for _, c := range m.containers {
		if seen[c.ID] {
			continue
		}
		if all || c.State == "running" {
			result = append(result, c)
			seen[c.ID] = true
		}
	}
	return result, nil
}

func (m *MockPodmanBackend) GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*PodmanContainerLogs, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logsCalled++
	if m.logsError != nil {
		return nil, m.logsError
	}
	_, ok := m.containers[id]
	if !ok {
		return nil, errors.New("container not found")
	}
	return &PodmanContainerLogs{
		ContainerID: id,
		Stdout:      []byte("test log output\n"),
		Stderr:      []byte(""),
		Since:       time.Now().Add(-time.Hour),
		Until:       time.Now(),
	}, nil
}

func (m *MockPodmanBackend) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

// MockTPMProvider is the shared mock host TPM: it fills the go-quicbaas SDK
// orchestration.HostTPM seam and the platform's QuoteVerifier extension.
type MockTPMProvider = mockHostTPM

// NewMockTPMProvider creates a mock host TPM with all PCRs zeroed.
func NewMockTPMProvider() *MockTPMProvider {
	return newMockHostTPM()
}

// MockLifecyclePolicyEvaluator is a mock implementation of LifecyclePolicyEvaluator for testing.
type MockLifecyclePolicyEvaluator struct {
	mu        sync.Mutex
	allowed   bool
	reasons   []string
	evalError error
	evalCount int
}

func NewMockLifecyclePolicyEvaluator(allowed bool) *MockLifecyclePolicyEvaluator {
	return &MockLifecyclePolicyEvaluator{
		allowed: allowed,
	}
}

func (m *MockLifecyclePolicyEvaluator) EvaluateContainerSpec(ctx context.Context, spec *OrchestratorContainerSpec) (bool, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evalCount++
	if m.evalError != nil {
		return false, nil, m.evalError
	}
	return m.allowed, m.reasons, nil
}

// MockLifecycleNetworkManager is a mock implementation of LifecycleNetworkManager for testing.
type MockLifecycleNetworkManager struct {
	mu             sync.Mutex
	setupError     error
	teardownError  error
	setupCalled    int
	teardownCalled int
}

func NewMockLifecycleNetworkManager() *MockLifecycleNetworkManager {
	return &MockLifecycleNetworkManager{}
}

func (m *MockLifecycleNetworkManager) SetupNetwork(ctx context.Context, containerID string, cfg *ContainerNetworkConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setupCalled++
	return m.setupError
}

func (m *MockLifecycleNetworkManager) TeardownNetwork(ctx context.Context, containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.teardownCalled++
	return m.teardownError
}

// Helper to create a test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// TestNewOrchestrator tests orchestrator creation.
func TestNewOrchestrator(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: false,
			EnablePolicy:      false,
		}
		podman := NewMockPodmanBackend()

		orch, err := NewOrchestrator(config, WithPodmanBackend(podman))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if orch == nil {
			t.Fatal("expected orchestrator, got nil")
		}
		defer orch.Close()
	})

	t.Run("nil logger returns error", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger: nil,
		}

		_, err := NewOrchestrator(config)
		if err == nil {
			t.Fatal("expected error for nil logger")
		}
	})

	t.Run("negative stop timeout returns error", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:             testLogger(),
			DefaultStopTimeout: -1 * time.Second,
		}

		_, err := NewOrchestrator(config)
		if err == nil {
			t.Fatal("expected error for negative timeout")
		}
	})

	t.Run("with all options", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
			EnablePolicy:      true,
			PolicyName:        "test-policy",
		}
		podman := NewMockPodmanBackend()
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))
		policy := NewMockLifecyclePolicyEvaluator(true)
		network := NewMockLifecycleNetworkManager()

		orch, err := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
			WithLifecyclePolicyEvaluator(policy),
			WithLifecycleNetworkManager(network),
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer orch.Close()

		if !orch.IsConnected() {
			t.Error("expected orchestrator to be connected")
		}
	})
}

// TestOrchestratorCreate tests container creation.
func TestOrchestratorCreate(t *testing.T) {
	t.Run("create simple container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "test-container",
			Image: "alpine:latest",
		}

		container, err := orch.Create(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if container == nil {
			t.Fatal("expected container, got nil")
		}
		if container.Name != "test-container" {
			t.Errorf("expected name 'test-container', got %q", container.Name)
		}
		if container.State != StateCreated {
			t.Errorf("expected state %q, got %q", StateCreated, container.State)
		}
		if podman.createCalled != 1 {
			t.Errorf("expected createCalled=1, got %d", podman.createCalled)
		}
	})

	t.Run("create with attestation", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "attested-container",
			Image: "alpine:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(tpm.getExtendCalls()) != 1 {
			t.Errorf("expected extendCalled=1, got %d", len(tpm.getExtendCalls()))
		}
	})

	t.Run("create with policy allowed", func(t *testing.T) {
		policy := NewMockLifecyclePolicyEvaluator(true)

		config := OrchestratorConfig{
			Logger:       testLogger(),
			EnablePolicy: true,
			PolicyName:   "test-policy",
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecyclePolicyEvaluator(policy),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "policy-container",
			Image: "alpine:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if policy.evalCount != 1 {
			t.Errorf("expected evalCount=1, got %d", policy.evalCount)
		}
	})

	t.Run("create with policy denied", func(t *testing.T) {
		policy := NewMockLifecyclePolicyEvaluator(false)
		policy.reasons = []string{"image not allowed"}

		config := OrchestratorConfig{
			Logger:       testLogger(),
			EnablePolicy: true,
			PolicyName:   "test-policy",
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecyclePolicyEvaluator(policy),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "denied-container",
			Image: "malicious:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected policy denial error")
		}
		if !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("expected ErrPolicyDenied, got %v", err)
		}
	})

	t.Run("create with nil spec", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, err := orch.Create(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil spec")
		}
	})

	t.Run("create with invalid spec", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "", // Invalid: empty name
			Image: "alpine:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error for invalid spec")
		}
	})

	t.Run("create duplicate container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "duplicate-container",
			Image: "alpine:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error on first create, got %v", err)
		}

		_, err = orch.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error for duplicate container")
		}
		if !errors.Is(err, ErrContainerExists) {
			t.Errorf("expected ErrContainerExists, got %v", err)
		}
	})

	t.Run("create on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "closed-container",
			Image: "alpine:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
	})
}

// TestOrchestratorStart tests container starting.
func TestOrchestratorStart(t *testing.T) {
	t.Run("start container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "start-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		err := orch.Start(context.Background(), container.ID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify container state
		updated, _ := orch.Get(context.Background(), container.ID)
		if updated.State != StateRunning {
			t.Errorf("expected state %q, got %q", StateRunning, updated.State)
		}
		if podman.startCalled != 1 {
			t.Errorf("expected startCalled=1, got %d", podman.startCalled)
		}
	})

	t.Run("start with SDN network", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		network := NewMockLifecycleNetworkManager()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecycleNetworkManager(network),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "sdn-container",
			Image: "alpine:latest",
			Network: ContainerNetworkConfig{
				Mode: NetworkModeSDN,
				SDN: &SDNConfig{
					Bridge: "br-test",
					VLANID: 100,
				},
			},
		}
		container, _ := orch.Create(context.Background(), spec)

		err := orch.Start(context.Background(), container.ID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if network.setupCalled != 1 {
			t.Errorf("expected setupCalled=1, got %d", network.setupCalled)
		}
	})

	t.Run("start already running container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "running-container",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		err := orch.Start(context.Background(), container.ID)
		if err == nil {
			t.Fatal("expected error for already running container")
		}
		if !errors.Is(err, ErrContainerRunning) {
			t.Errorf("expected ErrContainerRunning, got %v", err)
		}
	})

	t.Run("start nonexistent container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.Start(context.Background(), "nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent container")
		}
	})

	t.Run("start with empty ID", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.Start(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ID")
		}
	})
}

// TestOrchestratorStop tests container stopping.
func TestOrchestratorStop(t *testing.T) {
	t.Run("stop running container", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:             testLogger(),
			DefaultStopTimeout: 10 * time.Second,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "stop-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		err := orch.Stop(context.Background(), container.ID, 5*time.Second)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify container state
		updated, _ := orch.Get(context.Background(), container.ID)
		if updated.State != StateStopped {
			t.Errorf("expected state %q, got %q", StateStopped, updated.State)
		}
		if podman.stopCalled != 1 {
			t.Errorf("expected stopCalled=1, got %d", podman.stopCalled)
		}
	})

	t.Run("stop with attestation", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "attested-stop",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)
		tpm.resetExtendCalls()

		err := orch.Stop(context.Background(), container.ID, 5*time.Second)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(tpm.getExtendCalls()) != 1 {
			t.Errorf("expected extendCalled=1 for stop event, got %d", len(tpm.getExtendCalls()))
		}
	})

	t.Run("stop already stopped container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "stopped-container",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		err := orch.Stop(context.Background(), container.ID, 5*time.Second)
		if err == nil {
			t.Fatal("expected error for already stopped container")
		}
		if !errors.Is(err, ErrContainerStopped) {
			t.Errorf("expected ErrContainerStopped, got %v", err)
		}
	})
}

// TestOrchestratorRemove tests container removal.
func TestOrchestratorRemove(t *testing.T) {
	t.Run("remove stopped container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "remove-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		err := orch.Remove(context.Background(), container.ID, false)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify container is gone
		_, err = orch.Get(context.Background(), container.ID)
		if err == nil {
			t.Error("expected container to be removed")
		}
		if podman.removeCalled != 1 {
			t.Errorf("expected removeCalled=1, got %d", podman.removeCalled)
		}
	})

	t.Run("remove running container without force", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "running-remove",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		err := orch.Remove(context.Background(), container.ID, false)
		if err == nil {
			t.Fatal("expected error for running container without force")
		}
		if !errors.Is(err, ErrContainerRunning) {
			t.Errorf("expected ErrContainerRunning, got %v", err)
		}
	})

	t.Run("remove running container with force", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:             testLogger(),
			DefaultStopTimeout: 1 * time.Second,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "force-remove",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		err := orch.Remove(context.Background(), container.ID, true)
		if err != nil {
			t.Fatalf("expected no error with force=true, got %v", err)
		}
		if podman.stopCalled != 1 {
			t.Errorf("expected stopCalled=1, got %d", podman.stopCalled)
		}
	})
}

// TestOrchestratorGet tests container retrieval.
func TestOrchestratorGet(t *testing.T) {
	t.Run("get by ID", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "get-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		retrieved, err := orch.Get(context.Background(), container.ID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if retrieved.ID != container.ID {
			t.Errorf("expected ID %q, got %q", container.ID, retrieved.ID)
		}
	})

	t.Run("get by name", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "get-by-name",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		retrieved, err := orch.Get(context.Background(), "get-by-name")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if retrieved.Name != container.Name {
			t.Errorf("expected name %q, got %q", container.Name, retrieved.Name)
		}
	})

	t.Run("get nonexistent container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, err := orch.Get(context.Background(), "nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent container")
		}
	})
}

// TestOrchestratorList tests container listing.
func TestOrchestratorList(t *testing.T) {
	t.Run("list all containers", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		// Create some containers
		for i := 0; i < 3; i++ {
			spec := &OrchestratorContainerSpec{
				Name:  "list-test-" + string(rune('a'+i)),
				Image: "alpine:latest",
			}
			orch.Create(context.Background(), spec)
		}

		containers, err := orch.List(context.Background(), ListOptions{All: true})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(containers) != 3 {
			t.Errorf("expected 3 containers, got %d", len(containers))
		}
	})

	t.Run("list with limit", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		// Create some containers
		for i := 0; i < 5; i++ {
			spec := &OrchestratorContainerSpec{
				Name:  "limit-test-" + string(rune('a'+i)),
				Image: "alpine:latest",
			}
			orch.Create(context.Background(), spec)
		}

		containers, err := orch.List(context.Background(), ListOptions{All: true, Limit: 2})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(containers) != 2 {
			t.Errorf("expected 2 containers, got %d", len(containers))
		}
	})

	t.Run("list with label filter", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:   "labeled-container",
			Image:  "alpine:latest",
			Labels: map[string]string{"app": "test"},
		}
		orch.Create(context.Background(), spec)

		spec2 := &OrchestratorContainerSpec{
			Name:  "unlabeled-container",
			Image: "alpine:latest",
		}
		orch.Create(context.Background(), spec2)

		containers, err := orch.List(context.Background(), ListOptions{
			All:     true,
			Filters: map[string][]string{"label": {"app=test"}},
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(containers) != 1 {
			t.Errorf("expected 1 container, got %d", len(containers))
		}
	})
}

// TestOrchestratorLogs tests container log retrieval.
func TestOrchestratorLogs(t *testing.T) {
	t.Run("get container logs", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "logs-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		reader, err := orch.Logs(context.Background(), container.ID, LogOptions{
			Stdout: true,
			Stderr: true,
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer reader.Close()

		if podman.logsCalled != 1 {
			t.Errorf("expected logsCalled=1, got %d", podman.logsCalled)
		}
	})
}

// TestOrchestratorAttest tests container attestation.
func TestOrchestratorAttest(t *testing.T) {
	t.Run("attest container", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "attest-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		report, err := orch.Attest(context.Background(), container.ID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if report == nil {
			t.Fatal("expected attestation report, got nil")
		}
		if report.ContainerID != container.ID {
			t.Errorf("expected container ID %q, got %q", container.ID, report.ContainerID)
		}
		if len(report.Quote) == 0 {
			t.Error("expected quote data")
		}
		if report.ContainerName != spec.Name {
			t.Errorf("expected container name %q, got %q", spec.Name, report.ContainerName)
		}
		if len(report.Signature) == 0 {
			t.Error("expected signature data")
		}
		if report.Log == nil || len(report.Log.Entries) == 0 {
			t.Error("expected a measurement log with the create entry")
		}
		if !strings.HasPrefix(report.ImageDigest, "sha256:") {
			t.Errorf("expected a sha256 image digest, got %q", report.ImageDigest)
		}
		if !strings.HasPrefix(report.ConfigDigest, "sha256:") {
			t.Errorf("expected a sha256 config digest, got %q", report.ConfigDigest)
		}
		if report.Timestamp.IsZero() {
			t.Error("expected a non-zero timestamp")
		}
	})

	t.Run("attest without attestor", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: false,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "no-attestor",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		_, err := orch.Attest(context.Background(), container.ID)
		if err == nil {
			t.Fatal("expected error without attestor")
		}
	})
}

// TestOrchestratorEvaluatePolicy tests policy evaluation.
func TestOrchestratorEvaluatePolicy(t *testing.T) {
	t.Run("evaluate allowed policy", func(t *testing.T) {
		policy := NewMockLifecyclePolicyEvaluator(true)
		config := OrchestratorConfig{
			Logger:       testLogger(),
			EnablePolicy: true,
			PolicyName:   "test-policy",
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecyclePolicyEvaluator(policy),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "policy-test",
			Image: "alpine:latest",
		}

		allowed, _, err := orch.EvaluatePolicy(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !allowed {
			t.Error("expected policy to allow")
		}
	})

	t.Run("evaluate without policy evaluator", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:       testLogger(),
			EnablePolicy: false,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "no-policy",
			Image: "alpine:latest",
		}

		allowed, _, err := orch.EvaluatePolicy(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !allowed {
			t.Error("expected default allow without policy evaluator")
		}
	})

	t.Run("evaluate with nil spec", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, _, err := orch.EvaluatePolicy(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil spec")
		}
		if !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("evaluate on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "closed-policy",
			Image: "alpine:latest",
		}

		_, _, err := orch.EvaluatePolicy(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
	})
}

// TestOrchestratorClose tests orchestrator closure.
func TestOrchestratorClose(t *testing.T) {
	t.Run("close orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		podman.connected = true
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))

		err := orch.Close()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify closed state
		if orch.IsConnected() {
			t.Error("expected orchestrator to be disconnected after close")
		}
		// The orchestrator owns the backend, so closing it must release
		// the Podman connection.
		if podman.connected {
			t.Error("expected Podman backend to be closed with the orchestrator")
		}

		// Try operation after close
		_, err = orch.Get(context.Background(), "any")
		if err == nil {
			t.Error("expected error after close")
		}
	})

	t.Run("double close", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))

		orch.Close()
		err := orch.Close() // Second close should be no-op
		if err != nil {
			t.Fatalf("expected no error on double close, got %v", err)
		}
	})
}

// TestConvertSpecToPodmanConfig tests spec conversion.
func TestConvertSpecToPodmanConfig(t *testing.T) {
	t.Run("convert full spec", func(t *testing.T) {
		spec := &OrchestratorContainerSpec{
			Name:       "full-spec",
			Image:      "nginx:latest",
			Command:    []string{"nginx"},
			Args:       []string{"-g", "daemon off;"},
			Env:        map[string]string{"ENV": "test"},
			Labels:     map[string]string{"app": "nginx"},
			User:       "nginx",
			WorkingDir: "/app",
			Privileged: false,
			Capabilities: CapabilityConfig{
				Add:  []string{"NET_ADMIN"},
				Drop: []string{"ALL"},
			},
			Mounts: []MountConfig{
				{Source: "/data", Target: "/app/data", ReadOnly: true},
			},
			Ports: []PortMapping{
				{ContainerPort: 80, HostPort: 8080, Protocol: "tcp"},
			},
			Network: ContainerNetworkConfig{
				Mode:       NetworkModeHost,
				DNSServers: []string{"8.8.8.8"},
				Hostname:   "nginx-host",
			},
		}

		config := newLaunchConfig(spec)

		if config.Name != "full-spec" {
			t.Errorf("expected name 'full-spec', got %q", config.Name)
		}
		if config.Image != "nginx:latest" {
			t.Errorf("expected image 'nginx:latest', got %q", config.Image)
		}
		if len(config.Command) != 3 {
			t.Errorf("expected 3 command args, got %d", len(config.Command))
		}
		if config.NetworkMode != "host" {
			t.Errorf("expected network mode 'host', got %q", config.NetworkMode)
		}
		if len(config.Mounts) != 1 {
			t.Errorf("expected 1 mount, got %d", len(config.Mounts))
		}
		if len(config.Ports) != 1 {
			t.Errorf("expected 1 port, got %d", len(config.Ports))
		}
	})
}

// TestMatchFilters tests filter matching.
func TestMatchFilters(t *testing.T) {
	t.Run("match label filter", func(t *testing.T) {
		container := &Container{
			Labels: map[string]string{"app": "test", "env": "prod"},
		}

		if !matchFilters(container, map[string][]string{"label": {"app=test"}}) {
			t.Error("expected label filter to match")
		}

		if matchFilters(container, map[string][]string{"label": {"app=other"}}) {
			t.Error("expected label filter to not match")
		}
	})

	t.Run("match name filter", func(t *testing.T) {
		container := &Container{Name: "test-container"}

		if !matchFilters(container, map[string][]string{"name": {"test"}}) {
			t.Error("expected name filter to match")
		}

		if matchFilters(container, map[string][]string{"name": {"other"}}) {
			t.Error("expected name filter to not match")
		}
	})

	t.Run("match status filter", func(t *testing.T) {
		container := &Container{State: StateRunning}

		if !matchFilters(container, map[string][]string{"status": {"running"}}) {
			t.Error("expected status filter to match")
		}

		if matchFilters(container, map[string][]string{"status": {"stopped"}}) {
			t.Error("expected status filter to not match")
		}
	})

	t.Run("empty filters match all", func(t *testing.T) {
		container := &Container{Name: "any"}

		if !matchFilters(container, nil) {
			t.Error("expected empty filters to match")
		}
	})
}

// TestMapPodmanState tests state mapping.
func TestMapPodmanState(t *testing.T) {
	tests := []struct {
		input    string
		expected ContainerState
	}{
		{"created", StateCreated},
		{"running", StateRunning},
		{"paused", StatePaused},
		{"stopped", StateStopped},
		{"exited", StateExited},
		{"removing", StateRemoving},
		{"restarting", StateRestarting},
		{"dead", StateDead},
		{"RUNNING", StateRunning}, // Case insensitive
		{"unknown", StateCreated}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapPodmanState(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestOrchestratorVerifyAttestation tests attestation verification.
func TestOrchestratorVerifyAttestation(t *testing.T) {
	newAttestingOrchestrator := func(t *testing.T) (*Orchestrator, *MockTPMProvider) {
		t.Helper()
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		orch, err := NewOrchestrator(OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		},
			WithPodmanBackend(NewMockPodmanBackend()),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		if err != nil {
			t.Fatalf("NewOrchestrator: %v", err)
		}
		return orch, tpm
	}

	t.Run("verify attestation success", func(t *testing.T) {
		orch, _ := newAttestingOrchestrator(t)
		defer orch.Close()

		container, err := orch.Create(context.Background(), &OrchestratorContainerSpec{
			Name:  "verified-container",
			Image: "alpine:latest",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		if err := orch.VerifyAttestation(context.Background(), container.ID, nil); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	// A container that was never measured cannot be verified; the old
	// implementation returned nil for everything.
	t.Run("verify attestation for an unmeasured container", func(t *testing.T) {
		orch, _ := newAttestingOrchestrator(t)
		defer orch.Close()

		err := orch.VerifyAttestation(context.Background(), "never-created", nil)
		if err == nil {
			t.Fatal("verifying an unmeasured container must fail")
		}
	})

	// Drift between the TPM and the measurement log must be reported by the
	// SDK golden-PCR comparison, not swallowed.
	t.Run("verify attestation detects PCR drift", func(t *testing.T) {
		orch, tpm := newAttestingOrchestrator(t)
		defer orch.Close()

		container, err := orch.Create(context.Background(), &OrchestratorContainerSpec{
			Name:  "drifted-container",
			Image: "alpine:latest",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		if err := tpm.ExtendPCR(DefaultPCRIndex, "sha256", []byte("rogue")); err != nil {
			t.Fatalf("ExtendPCR: %v", err)
		}

		if err := orch.VerifyAttestation(context.Background(), container.ID, nil); err == nil {
			t.Fatal("PCR drift must fail verification")
		}
	})

	t.Run("verify attestation without attestor", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.VerifyAttestation(context.Background(), "test-container-id", []byte("evidence"))
		if err == nil {
			t.Fatal("expected error without attestor")
		}
		if !errors.Is(err, ErrAttestationFailed) {
			t.Errorf("expected ErrAttestationFailed, got %v", err)
		}
	})

	t.Run("verify attestation with empty ID", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		err := orch.VerifyAttestation(context.Background(), "", []byte("evidence"))
		if err == nil {
			t.Fatal("expected error for empty ID")
		}
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got %v", err)
		}
	})

	t.Run("verify attestation on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		err := orch.VerifyAttestation(context.Background(), "test-id", []byte("evidence"))
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})
}

// TestOrchestratorPullImage tests image pulling.
func TestOrchestratorPullImage(t *testing.T) {
	t.Run("pull image with podman backend", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.PullImage(context.Background(), "alpine:latest", PullOptions{})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if podman.pullCalled != 1 {
			t.Errorf("expected pullCalled=1, got %d", podman.pullCalled)
		}
	})

	t.Run("pull image with empty ref", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.PullImage(context.Background(), "", PullOptions{})
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
		if !errors.Is(err, ErrInvalidImage) {
			t.Errorf("expected ErrInvalidImage, got %v", err)
		}
	})

	t.Run("pull image on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		err := orch.PullImage(context.Background(), "alpine:latest", PullOptions{})
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})

	t.Run("pull image without podman or image manager", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		orch, _ := NewOrchestrator(config)
		defer orch.Close()

		err := orch.PullImage(context.Background(), "alpine:latest", PullOptions{})
		if err == nil {
			t.Fatal("expected error without podman")
		}
		if !errors.Is(err, ErrPodmanNotAvailable) {
			t.Errorf("expected ErrPodmanNotAvailable, got %v", err)
		}
	})
}

// TestOrchestratorVerifyImage tests image verification.
func TestOrchestratorVerifyImage(t *testing.T) {

	// Without an image manager there is no digest and no endorsement, so there
	// is nothing to report. A synthesized "unverified" result would be a
	// verdict about an artifact that was never identified.
	t.Run("verify image without image manager is an error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		result, err := orch.VerifyImage(context.Background(), "alpine:latest")
		if !errors.Is(err, ErrImageManagerUnavailable) {
			t.Fatalf("expected ErrImageManagerUnavailable, got %v", err)
		}
		if result != nil {
			t.Errorf("no result may be returned, got %+v", result)
		}
	})

	t.Run("verify image reports the content digest through the image manager", func(t *testing.T) {
		const ref = "alpine:latest"
		config := OrchestratorConfig{Logger: testLogger()}
		manager, podman := newImageManagerWithImages(t,
			ImageManagerConfig{Logger: testLogger()}, nil, ref)
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman), WithImageManager(manager))
		defer orch.Close()

		result, err := orch.VerifyImage(context.Background(), ref)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.Digest != testRegistryDigest(ref) {
			t.Errorf("Digest = %q, want %q", result.Digest, testRegistryDigest(ref))
		}
		if result.Digest == testRefHashDigest(ref) {
			t.Error("the image reference hash was substituted for the content digest")
		}
	})

	t.Run("verify image with empty ref", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, err := orch.VerifyImage(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
		if !errors.Is(err, ErrInvalidImage) {
			t.Errorf("expected ErrInvalidImage, got %v", err)
		}
	})

	t.Run("verify image on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		_, err := orch.VerifyImage(context.Background(), "alpine:latest")
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})
}

// TestOrchestratorGetAttestation tests getting the attestor.
func TestOrchestratorGetAttestation(t *testing.T) {
	t.Run("get attestation with attestor", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		result := orch.GetAttestation()
		if result == nil {
			t.Fatal("expected attestor, got nil")
		}
		if result != attestor {
			t.Error("expected same attestor instance")
		}
	})

	t.Run("get attestation without attestor", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		result := orch.GetAttestation()
		if result != nil {
			t.Error("expected nil attestor")
		}
	})
}

// TestOrchestratorGetMeasurementLog tests getting the measurement log.
func TestOrchestratorGetMeasurementLog(t *testing.T) {
	t.Run("get measurement log with attestor", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		log := orch.GetMeasurementLog()
		if log == nil {
			t.Fatal("expected measurement log, got nil")
		}
	})

	t.Run("get measurement log without attestor", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		log := orch.GetMeasurementLog()
		if log != nil {
			t.Error("expected nil measurement log")
		}
	})
}

// TestOrchestratorContainerCount tests container counting.
func TestOrchestratorContainerCount(t *testing.T) {
	t.Run("count containers", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		// Initial count should be 0
		if orch.ContainerCount() != 0 {
			t.Errorf("expected 0 containers, got %d", orch.ContainerCount())
		}

		// Create some containers
		for i := 0; i < 3; i++ {
			spec := &OrchestratorContainerSpec{
				Name:  "count-test-" + string(rune('a'+i)),
				Image: "alpine:latest",
			}
			orch.Create(context.Background(), spec)
		}

		if orch.ContainerCount() != 3 {
			t.Errorf("expected 3 containers, got %d", orch.ContainerCount())
		}
	})
}

// TestOrchestratorString tests string representation.
func TestOrchestratorString(t *testing.T) {
	t.Run("string representation", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
			EnablePolicy:      true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		str := orch.String()
		if str == "" {
			t.Error("expected non-empty string")
		}
		// Should contain key information
		if !containsString(str, "attestation=true") {
			t.Error("expected string to contain attestation status")
		}
		if !containsString(str, "policy=true") {
			t.Error("expected string to contain policy status")
		}
	})
}

// containsString is a helper to check if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestOrchestratorWithLogger tests the logger option.
func TestOrchestratorWithLogger(t *testing.T) {
	t.Run("with custom logger", func(t *testing.T) {
		customLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		config := OrchestratorConfig{
			Logger: testLogger(),
		}
		podman := NewMockPodmanBackend()
		orch, err := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithOrchestratorLogger(customLogger),
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer orch.Close()
	})
}

// TestOrchestratorRemoveWithAttestation tests removal with attestation.
func TestOrchestratorRemoveWithAttestation(t *testing.T) {
	t.Run("remove with attestation recording", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "attested-remove",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		tpm.resetExtendCalls()

		err := orch.Remove(context.Background(), container.ID, false)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if len(tpm.getExtendCalls()) != 1 {
			t.Errorf("expected extendCalled=1 for remove event, got %d", len(tpm.getExtendCalls()))
		}
	})
}

// TestOrchestratorRemoveWithNetwork tests removal with network teardown.
func TestOrchestratorRemoveWithNetwork(t *testing.T) {
	t.Run("remove with SDN network teardown", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		network := NewMockLifecycleNetworkManager()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecycleNetworkManager(network),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "sdn-remove",
			Image: "alpine:latest",
			Network: ContainerNetworkConfig{
				Mode: NetworkModeSDN,
				SDN: &SDNConfig{
					Bridge: "br-test",
					VLANID: 100,
				},
			},
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		err := orch.Remove(context.Background(), container.ID, true) // Force remove running
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if network.teardownCalled < 1 {
			t.Errorf("expected teardownCalled>=1, got %d", network.teardownCalled)
		}
	})
}

// TestOrchestratorLogsErrors tests log retrieval error cases.
func TestOrchestratorLogsErrors(t *testing.T) {
	t.Run("logs with empty container ID", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, err := orch.Logs(context.Background(), "", LogOptions{})
		if err == nil {
			t.Fatal("expected error for empty container ID")
		}
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got %v", err)
		}
	})

	t.Run("logs on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		_, err := orch.Logs(context.Background(), "test-id", LogOptions{})
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})

	t.Run("logs for nonexistent container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, err := orch.Logs(context.Background(), "nonexistent", LogOptions{})
		if err == nil {
			t.Fatal("expected error for nonexistent container")
		}
	})
}

// TestOrchestratorAttestErrors tests attestation error cases.
func TestOrchestratorAttestErrors(t *testing.T) {
	t.Run("attest with empty container ID", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		_, err := orch.Attest(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty container ID")
		}
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got %v", err)
		}
	})

	t.Run("attest on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		_, err := orch.Attest(context.Background(), "test-id")
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})

	t.Run("attest nonexistent container", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		_, err := orch.Attest(context.Background(), "nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent container")
		}
	})
}

// TestOrchestratorGetErrors tests get error cases.
func TestOrchestratorGetErrors(t *testing.T) {
	t.Run("get with empty ID", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, err := orch.Get(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ID")
		}
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got %v", err)
		}
	})

	t.Run("get on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		_, err := orch.Get(context.Background(), "test-id")
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})
}

// TestOrchestratorListErrors tests list error cases.
func TestOrchestratorListErrors(t *testing.T) {
	t.Run("list on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		_, err := orch.List(context.Background(), ListOptions{})
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})
}

// TestOrchestratorRemoveErrors tests remove error cases.
func TestOrchestratorRemoveErrors(t *testing.T) {
	t.Run("remove with empty ID", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.Remove(context.Background(), "", false)
		if err == nil {
			t.Fatal("expected error for empty ID")
		}
		if !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("expected ErrInvalidContainerID, got %v", err)
		}
	})

	t.Run("remove on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		err := orch.Remove(context.Background(), "test-id", false)
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})
}

// TestOrchestratorStopErrors tests stop error cases.
func TestOrchestratorStopErrors(t *testing.T) {
	t.Run("stop on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		err := orch.Stop(context.Background(), "test-id", time.Second)
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})
}

// TestOrchestratorStartErrors tests start error cases.
func TestOrchestratorStartErrors(t *testing.T) {
	t.Run("start on closed orchestrator", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		orch.Close()

		err := orch.Start(context.Background(), "test-id")
		if err == nil {
			t.Fatal("expected error on closed orchestrator")
		}
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("expected ErrOrchestratorClosed, got %v", err)
		}
	})
}

// TestOrchestratorGetFromPodman tests retrieval from Podman backend when not cached.
func TestOrchestratorGetFromPodman(t *testing.T) {
	t.Run("get from podman backend", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		// Add a container directly to podman mock, bypassing orchestrator cache
		podman.containers["direct-container"] = &PodmanContainer{
			ID:    "direct-container",
			Name:  "direct-name",
			Image: "alpine:latest",
			State: "running",
		}

		// Get should find it via Podman inspect
		container, err := orch.Get(context.Background(), "direct-container")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if container.ID != "direct-container" {
			t.Errorf("expected ID 'direct-container', got %q", container.ID)
		}
		if container.Name != "direct-name" {
			t.Errorf("expected name 'direct-name', got %q", container.Name)
		}
	})
}

// TestOrchestratorStopWithNetworkTeardown tests stop with network cleanup.
func TestOrchestratorStopWithNetworkTeardown(t *testing.T) {
	t.Run("stop tears down SDN network", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:             testLogger(),
			DefaultStopTimeout: 10 * time.Second,
		}
		podman := NewMockPodmanBackend()
		network := NewMockLifecycleNetworkManager()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecycleNetworkManager(network),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "sdn-stop-test",
			Image: "alpine:latest",
			Network: ContainerNetworkConfig{
				Mode: NetworkModeSDN,
				SDN: &SDNConfig{
					Bridge: "br-test",
					VLANID: 100,
				},
			},
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)
		network.setupCalled = 0 // Reset

		err := orch.Stop(context.Background(), container.ID, 5*time.Second)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if network.teardownCalled < 1 {
			t.Errorf("expected teardownCalled>=1, got %d", network.teardownCalled)
		}
	})
}

// TestConvertPodmanContainerToContainer tests container conversion.
func TestConvertPodmanContainerToContainer(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)

	t.Run("convert full container", func(t *testing.T) {
		podman := &PodmanContainer{
			ID:         "test-id-123",
			Name:       "test-container",
			Image:      "alpine:latest",
			State:      "running",
			Labels:     map[string]string{"app": "test"},
			CreatedAt:  now,
			StartedAt:  &now,
			FinishedAt: &later,
		}

		container := convertPodmanContainerToContainer(podman)

		if container.ID != "test-id-123" {
			t.Errorf("expected ID 'test-id-123', got %q", container.ID)
		}
		if container.Name != "test-container" {
			t.Errorf("expected name 'test-container', got %q", container.Name)
		}
		if container.State != StateRunning {
			t.Errorf("expected state running, got %q", container.State)
		}
		if container.Labels["app"] != "test" {
			t.Error("expected labels to be copied")
		}
	})

	t.Run("convert container with nil times", func(t *testing.T) {
		podman := &PodmanContainer{
			ID:        "test-id",
			Name:      "test",
			Image:     "alpine",
			State:     "created",
			CreatedAt: now,
		}

		container := convertPodmanContainerToContainer(podman)

		if !container.StartedAt.IsZero() {
			t.Error("expected nil StartedAt")
		}
		if !container.FinishedAt.IsZero() {
			t.Error("expected nil FinishedAt")
		}
	})
}

// TestOrchestratorCreateWithNetworkSetupError tests network setup error handling.
func TestOrchestratorCreateWithNetworkSetupError(t *testing.T) {
	t.Run("create continues if network setup fails", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		network := NewMockLifecycleNetworkManager()
		network.setupError = errors.New("network setup failed")

		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecycleNetworkManager(network),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "network-error-test",
			Image: "alpine:latest",
			Network: ContainerNetworkConfig{
				Mode: NetworkModeSDN,
				SDN: &SDNConfig{
					Bridge: "br-test",
					VLANID: 100,
				},
			},
		}

		container, err := orch.Create(context.Background(), spec)
		if err != nil {
			t.Fatalf("expected no error on create, got %v", err)
		}
		if container == nil {
			t.Fatal("expected container, got nil")
		}
	})
}

// TestOrchestratorRemoveNonexistent tests removing non-existent container.
func TestOrchestratorRemoveNonexistent(t *testing.T) {
	t.Run("remove non-existent container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.Remove(context.Background(), "nonexistent-id", false)
		if err == nil {
			t.Fatal("expected error for nonexistent container")
		}
	})
}

// TestOrchestratorStopNonexistent tests stopping non-existent container.
func TestOrchestratorStopNonexistent(t *testing.T) {
	t.Run("stop non-existent container", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.Stop(context.Background(), "nonexistent-id", time.Second)
		if err == nil {
			t.Fatal("expected error for nonexistent container")
		}
	})
}

// TestOrchestratorCloseWithContainers tests closing orchestrator with active containers.
func TestOrchestratorCloseWithContainers(t *testing.T) {
	t.Run("close with running containers", func(t *testing.T) {
		config := OrchestratorConfig{
			Logger:             testLogger(),
			DefaultStopTimeout: time.Second,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))

		// Create and start some containers
		for i := 0; i < 3; i++ {
			spec := &OrchestratorContainerSpec{
				Name:  "close-test-" + string(rune('a'+i)),
				Image: "alpine:latest",
			}
			container, _ := orch.Create(context.Background(), spec)
			orch.Start(context.Background(), container.ID)
		}

		// Close should succeed even with running containers
		err := orch.Close()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if orch.IsConnected() {
			t.Error("expected orchestrator to be disconnected")
		}
	})
}

// TestOrchestratorPullImageError tests image pull error handling.
func TestOrchestratorPullImageError(t *testing.T) {
	t.Run("pull fails with podman error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		podman.pullError = errors.New("pull failed")
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		err := orch.PullImage(context.Background(), "alpine:latest", PullOptions{})
		if err == nil {
			t.Fatal("expected error from failed pull")
		}
	})
}

// TestOrchestratorCreatePodmanError tests create with podman error.
func TestOrchestratorCreatePodmanError(t *testing.T) {
	t.Run("create fails with podman error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		podman.createError = errors.New("create failed")
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "create-error-test",
			Image: "alpine:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error from failed create")
		}
	})
}

// TestOrchestratorStartPodmanError tests start with podman error.
func TestOrchestratorStartPodmanError(t *testing.T) {
	t.Run("start fails with podman error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "start-error-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		// Now set error after container is created
		podman.startError = errors.New("start failed")

		err := orch.Start(context.Background(), container.ID)
		if err == nil {
			t.Fatal("expected error from failed start")
		}
	})
}

// TestOrchestratorStopPodmanError tests stop with podman error.
func TestOrchestratorStopPodmanError(t *testing.T) {
	t.Run("stop fails with podman error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "stop-error-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		// Now set error after container is started
		podman.stopError = errors.New("stop failed")

		err := orch.Stop(context.Background(), container.ID, time.Second)
		if err == nil {
			t.Fatal("expected error from failed stop")
		}
	})
}

// TestOrchestratorRemovePodmanError tests remove with podman error.
func TestOrchestratorRemovePodmanError(t *testing.T) {
	t.Run("remove fails with podman error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "remove-error-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		// Now set error after container is created
		podman.removeError = errors.New("remove failed")

		err := orch.Remove(context.Background(), container.ID, false)
		if err == nil {
			t.Fatal("expected error from failed remove")
		}
	})
}

// TestOrchestratorLogsPodmanError tests logs with podman error.
func TestOrchestratorLogsPodmanError(t *testing.T) {
	t.Run("logs fails with podman error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "logs-error-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)
		orch.Start(context.Background(), container.ID)

		// Now set error
		podman.logsError = errors.New("logs failed")

		_, err := orch.Logs(context.Background(), container.ID, LogOptions{})
		if err == nil {
			t.Fatal("expected error from failed logs")
		}
	})
}

// TestOrchestratorListPodmanError tests list with podman error.
func TestOrchestratorListPodmanError(t *testing.T) {
	t.Run("list fails with podman error", func(t *testing.T) {
		config := OrchestratorConfig{Logger: testLogger()}
		podman := NewMockPodmanBackend()
		podman.listError = errors.New("list failed")
		orch, _ := NewOrchestrator(config, WithPodmanBackend(podman))
		defer orch.Close()

		_, err := orch.List(context.Background(), ListOptions{All: true})
		if err == nil {
			t.Fatal("expected error from failed list")
		}
	})
}

// TestOrchestratorAttestPodmanError tests attestation with TPM error.
func TestOrchestratorAttestPodmanError(t *testing.T) {
	t.Run("attest fails with TPM error", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		tpm.quoteErr = errors.New("quote failed")
		attestor, _ := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))

		config := OrchestratorConfig{
			Logger:            testLogger(),
			EnableAttestation: true,
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "attest-error-test",
			Image: "alpine:latest",
		}
		container, _ := orch.Create(context.Background(), spec)

		_, err := orch.Attest(context.Background(), container.ID)
		if err == nil {
			t.Fatal("expected error from failed attestation")
		}
	})
}

// TestOrchestratorPolicyEvaluatorError tests policy evaluation error.
func TestOrchestratorPolicyEvaluatorError(t *testing.T) {
	t.Run("create fails with policy evaluator error", func(t *testing.T) {
		policy := NewMockLifecyclePolicyEvaluator(false)
		policy.evalError = errors.New("policy evaluation failed")

		config := OrchestratorConfig{
			Logger:       testLogger(),
			EnablePolicy: true,
			PolicyName:   "test-policy",
		}
		podman := NewMockPodmanBackend()
		orch, _ := NewOrchestrator(config,
			WithPodmanBackend(podman),
			WithLifecyclePolicyEvaluator(policy),
		)
		defer orch.Close()

		spec := &OrchestratorContainerSpec{
			Name:  "policy-error-test",
			Image: "alpine:latest",
		}

		_, err := orch.Create(context.Background(), spec)
		if err == nil {
			t.Fatal("expected error from failed policy evaluation")
		}
	})
}

// TestOrchestratorLifecycleErrors pins the typed error each lifecycle
// operation returns, so callers can branch with errors.Is.
func TestOrchestratorLifecycleErrors(t *testing.T) {
	newOrch := func(t *testing.T) *Orchestrator {
		t.Helper()
		orch, err := NewOrchestrator(OrchestratorConfig{Logger: testLogger()},
			WithPodmanBackend(NewMockPodmanBackend()))
		if err != nil {
			t.Fatalf("NewOrchestrator: %v", err)
		}
		t.Cleanup(func() { orch.Close() })
		return orch
	}
	ctx := context.Background()

	t.Run("create with nil spec returns ErrInvalidSpec", func(t *testing.T) {
		_, err := newOrch(t).Create(ctx, nil)
		if !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("create with empty image returns ErrInvalidImage", func(t *testing.T) {
		_, err := newOrch(t).Create(ctx, &OrchestratorContainerSpec{Name: "no-image"})
		if !errors.Is(err, ErrInvalidImage) {
			t.Fatalf("expected ErrInvalidImage, got %v", err)
		}
	})

	t.Run("create after close returns ErrOrchestratorClosed", func(t *testing.T) {
		orch := newOrch(t)
		if err := orch.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		_, err := orch.Create(ctx, &OrchestratorContainerSpec{Name: "closed", Image: "alpine:latest"})
		if !errors.Is(err, ErrOrchestratorClosed) {
			t.Fatalf("expected ErrOrchestratorClosed, got %v", err)
		}
	})

	t.Run("unknown ID returns ErrContainerNotFound", func(t *testing.T) {
		orch := newOrch(t)
		const id = "does-not-exist"
		ops := map[string]func() error{
			"start":  func() error { return orch.Start(ctx, id) },
			"stop":   func() error { return orch.Stop(ctx, id, time.Second) },
			"remove": func() error { return orch.Remove(ctx, id, false) },
			"get": func() error {
				_, err := orch.Get(ctx, id)
				return err
			},
		}
		for name, op := range ops {
			if err := op(); !errors.Is(err, ErrContainerNotFound) {
				t.Errorf("%s: expected ErrContainerNotFound, got %v", name, err)
			}
		}
	})

	t.Run("stop of a created container returns ErrContainerStopped", func(t *testing.T) {
		orch := newOrch(t)
		container, err := orch.Create(ctx, &OrchestratorContainerSpec{Name: "never-started", Image: "alpine:latest"})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := orch.Stop(ctx, container.ID, time.Second); !errors.Is(err, ErrContainerStopped) {
			t.Fatalf("expected ErrContainerStopped, got %v", err)
		}
	})

	t.Run("removed containers are gone from get and list", func(t *testing.T) {
		orch := newOrch(t)
		var ids []string
		for _, name := range []string{"gone-1", "gone-2"} {
			container, err := orch.Create(ctx, &OrchestratorContainerSpec{Name: name, Image: "alpine:latest"})
			if err != nil {
				t.Fatalf("Create %s: %v", name, err)
			}
			ids = append(ids, container.ID)
		}
		for _, id := range ids {
			if err := orch.Remove(ctx, id, false); err != nil {
				t.Fatalf("Remove %s: %v", id, err)
			}
			if _, err := orch.Get(ctx, id); !errors.Is(err, ErrContainerNotFound) {
				t.Errorf("Get after Remove: expected ErrContainerNotFound, got %v", err)
			}
		}
		list, err := orch.List(ctx, ListOptions{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("expected empty list after removing all containers, got %d", len(list))
		}
	})
}

// TestOrchestratorDisabledFeatures checks that a wired policy evaluator or
// attestor is not consulted while its feature flag is off.
func TestOrchestratorDisabledFeatures(t *testing.T) {
	spec := func(name string) *OrchestratorContainerSpec {
		return &OrchestratorContainerSpec{Name: name, Image: "alpine:latest"}
	}

	t.Run("policy evaluator is skipped when EnablePolicy is false", func(t *testing.T) {
		policy := NewMockLifecyclePolicyEvaluator(false)
		orch, err := NewOrchestrator(OrchestratorConfig{Logger: testLogger()},
			WithPodmanBackend(NewMockPodmanBackend()),
			WithLifecyclePolicyEvaluator(policy),
		)
		if err != nil {
			t.Fatalf("NewOrchestrator: %v", err)
		}
		defer orch.Close()

		if _, err := orch.Create(context.Background(), spec("policy-off")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if policy.evalCount != 0 {
			t.Errorf("expected evalCount=0, got %d", policy.evalCount)
		}
	})

	t.Run("attestor is skipped when EnableAttestation is false", func(t *testing.T) {
		tpm := NewMockTPMProvider()
		attestor, err := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))
		if err != nil {
			t.Fatalf("NewContainerAttestor: %v", err)
		}
		orch, err := NewOrchestrator(OrchestratorConfig{Logger: testLogger()},
			WithPodmanBackend(NewMockPodmanBackend()),
			WithAttestor(attestor),
		)
		if err != nil {
			t.Fatalf("NewOrchestrator: %v", err)
		}
		defer orch.Close()

		ctx := context.Background()
		container, err := orch.Create(ctx, spec("attest-off"))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := orch.Start(ctx, container.ID); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if err := orch.Stop(ctx, container.ID, time.Second); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if err := orch.Remove(ctx, container.ID, false); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if calls := len(tpm.getExtendCalls()); calls != 0 {
			t.Errorf("expected no PCR extends, got %d", calls)
		}
	})
}
