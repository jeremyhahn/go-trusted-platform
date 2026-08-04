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

// Package container provides integration tests for the container orchestrator.
// These tests verify container lifecycle, policy evaluation, and attestation workflows
// using mocked TPM and Podman interfaces.
//
// Run tests via:
//
//	make integration-test-container
package container

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
)

// =============================================================================
// Environment Constants
// =============================================================================

const (
	// EnvIntegrationTest is the environment variable that must be set to run
	// integration tests. Set INTEGRATION_TEST=1 to enable.
	EnvIntegrationTest = "INTEGRATION_TEST"

	// DefaultTestTimeout is the default timeout for integration tests.
	DefaultTestTimeout = 2 * time.Minute
)

// =============================================================================
// Skip Helpers
// =============================================================================

// SkipIfNotIntegration skips the test if INTEGRATION_TEST is not set.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegrationTest) == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// =============================================================================
// Mock TPM Provider
// =============================================================================

// MockTPMProvider implements container.TPMProvider for testing.
type MockTPMProvider struct {
	mu          sync.RWMutex
	pcrs        map[int][]byte
	extendCalls int32
	quoteCalls  int32
	verifyCalls int32
	shouldFail  bool
	failError   error
}

// NewMockTPMProvider creates a new mock TPM provider.
func NewMockTPMProvider() *MockTPMProvider {
	provider := &MockTPMProvider{
		pcrs: make(map[int][]byte),
	}
	// Initialize PCRs with zero values (32 bytes for SHA-256)
	for i := 0; i < 24; i++ {
		provider.pcrs[i] = make([]byte, 32)
	}
	return provider
}

// ExtendPCR extends a PCR with the given hash.
func (m *MockTPMProvider) ExtendPCR(ctx context.Context, pcrIndex int, hash []byte) error {
	atomic.AddInt32(&m.extendCalls, 1)

	if m.shouldFail {
		return m.failError
	}

	if pcrIndex < 0 || pcrIndex > 23 {
		return container.ErrInvalidSpec
	}

	if len(hash) != 32 {
		return container.ErrMeasurementLogInvalid
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// PCR extend is: new_value = SHA256(old_value || hash)
	// For simplicity in tests, we just XOR the values
	current := m.pcrs[pcrIndex]
	extended := make([]byte, 32)
	for i := 0; i < 32; i++ {
		extended[i] = current[i] ^ hash[i]
	}
	m.pcrs[pcrIndex] = extended

	return nil
}

// ReadPCR reads a PCR value.
func (m *MockTPMProvider) ReadPCR(ctx context.Context, pcrIndex int) ([]byte, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	if pcrIndex < 0 || pcrIndex > 23 {
		return nil, container.ErrInvalidSpec
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]byte, 32)
	copy(result, m.pcrs[pcrIndex])
	return result, nil
}

// GenerateQuote generates a TPM quote.
func (m *MockTPMProvider) GenerateQuote(ctx context.Context, pcrIndices []int, nonce []byte) (*container.Quote, error) {
	atomic.AddInt32(&m.quoteCalls, 1)

	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	quote := &container.Quote{
		QuoteData: []byte("mock-quote-data"),
		Signature: []byte("mock-signature"),
		PCRs:      make(map[int][]byte),
		Nonce:     nonce,
		Timestamp: time.Now(),
	}

	for _, idx := range pcrIndices {
		if idx >= 0 && idx <= 23 {
			pcr := make([]byte, 32)
			copy(pcr, m.pcrs[idx])
			quote.PCRs[idx] = pcr
		}
	}

	return quote, nil
}

// VerifyQuote verifies a TPM quote.
func (m *MockTPMProvider) VerifyQuote(ctx context.Context, quote *container.Quote) error {
	atomic.AddInt32(&m.verifyCalls, 1)

	if m.shouldFail {
		return m.failError
	}

	if quote == nil {
		return container.ErrQuoteVerificationFailed
	}

	return nil
}

// SetFailure configures the mock to fail with the given error.
func (m *MockTPMProvider) SetFailure(err error) {
	m.shouldFail = true
	m.failError = err
}

// ClearFailure clears any configured failure.
func (m *MockTPMProvider) ClearFailure() {
	m.shouldFail = false
	m.failError = nil
}

// GetExtendCalls returns the number of ExtendPCR calls.
func (m *MockTPMProvider) GetExtendCalls() int32 {
	return atomic.LoadInt32(&m.extendCalls)
}

// GetQuoteCalls returns the number of GenerateQuote calls.
func (m *MockTPMProvider) GetQuoteCalls() int32 {
	return atomic.LoadInt32(&m.quoteCalls)
}

// GetVerifyCalls returns the number of VerifyQuote calls.
func (m *MockTPMProvider) GetVerifyCalls() int32 {
	return atomic.LoadInt32(&m.verifyCalls)
}

// Reset resets the mock state.
func (m *MockTPMProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := 0; i < 24; i++ {
		m.pcrs[i] = make([]byte, 32)
	}
	atomic.StoreInt32(&m.extendCalls, 0)
	atomic.StoreInt32(&m.quoteCalls, 0)
	atomic.StoreInt32(&m.verifyCalls, 0)
	m.shouldFail = false
	m.failError = nil
}

// =============================================================================
// Mock Podman Backend
// =============================================================================

// MockPodmanBackend implements container.PodmanBackend for testing.
type MockPodmanBackend struct {
	mu          sync.RWMutex
	containers  map[string]*container.PodmanContainer
	images      map[string]*container.PodmanImage
	connected   bool
	shouldFail  bool
	failError   error
	idCounter   int64
	createCalls int32
	startCalls  int32
	stopCalls   int32
	removeCalls int32
}

// NewMockPodmanBackend creates a new mock Podman backend.
func NewMockPodmanBackend() *MockPodmanBackend {
	return &MockPodmanBackend{
		containers: make(map[string]*container.PodmanContainer),
		images:     make(map[string]*container.PodmanImage),
		connected:  false,
	}
}

// Connect establishes a mock connection.
func (m *MockPodmanBackend) Connect(ctx context.Context) error {
	if m.shouldFail {
		return m.failError
	}
	m.connected = true
	return nil
}

// PullImage simulates pulling an image.
func (m *MockPodmanBackend) PullImage(ctx context.Context, imageRef string) error {
	if m.shouldFail {
		return m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.images[imageRef] = &container.PodmanImage{
		ID:      generateMockID(),
		Names:   []string{imageRef},
		Digest:  "sha256:mock-digest-" + imageRef,
		Size:    1024 * 1024,
		Created: time.Now(),
	}

	return nil
}

// ListImages returns all mock images.
func (m *MockPodmanBackend) ListImages(ctx context.Context) ([]*container.PodmanImage, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	images := make([]*container.PodmanImage, 0, len(m.images))
	for _, img := range m.images {
		images = append(images, img)
	}
	return images, nil
}

// InspectImage returns details about a mock image.
func (m *MockPodmanBackend) InspectImage(ctx context.Context, imageRef string) (*container.PodmanImage, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if img, ok := m.images[imageRef]; ok {
		return img, nil
	}

	// Return a default image for testing
	return &container.PodmanImage{
		ID:      generateMockID(),
		Names:   []string{imageRef},
		Digest:  "sha256:mock-digest",
		Size:    1024 * 1024,
		Created: time.Now(),
	}, nil
}

// CreateContainer creates a mock container.
func (m *MockPodmanBackend) CreateContainer(ctx context.Context, config *container.PodmanContainerConfig) (*container.PodmanContainer, error) {
	atomic.AddInt32(&m.createCalls, 1)

	if m.shouldFail {
		return nil, m.failError
	}

	if config == nil || config.Name == "" {
		return nil, container.ErrInvalidSpec
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if container with same name exists
	for _, c := range m.containers {
		if c.Name == config.Name {
			return nil, container.ErrContainerExists
		}
	}

	id := generateMockID()
	pc := &container.PodmanContainer{
		ID:          id,
		Name:        config.Name,
		Image:       config.Image,
		ImageDigest: "sha256:mock-image-digest",
		State:       "created",
		CreatedAt:   time.Now(),
		Labels:      config.Labels,
		Command:     config.Command,
	}

	m.containers[id] = pc
	return pc, nil
}

// StartContainer starts a mock container.
func (m *MockPodmanBackend) StartContainer(ctx context.Context, id string) error {
	atomic.AddInt32(&m.startCalls, 1)

	if m.shouldFail {
		return m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pc, ok := m.containers[id]
	if !ok {
		return container.ErrContainerNotFound
	}

	if pc.State == "running" {
		return container.ErrContainerRunning
	}

	pc.State = "running"
	now := time.Now()
	pc.StartedAt = &now
	pc.PID = 12345 // Mock PID

	return nil
}

// StopContainer stops a mock container.
func (m *MockPodmanBackend) StopContainer(ctx context.Context, id string, timeout *int) error {
	atomic.AddInt32(&m.stopCalls, 1)

	if m.shouldFail {
		return m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pc, ok := m.containers[id]
	if !ok {
		return container.ErrContainerNotFound
	}

	if pc.State != "running" {
		return container.ErrContainerStopped
	}

	pc.State = "exited"
	now := time.Now()
	pc.FinishedAt = &now
	pc.PID = 0
	pc.ExitCode = 0

	return nil
}

// RemoveContainer removes a mock container.
func (m *MockPodmanBackend) RemoveContainer(ctx context.Context, id string, force bool) error {
	atomic.AddInt32(&m.removeCalls, 1)

	if m.shouldFail {
		return m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pc, ok := m.containers[id]
	if !ok {
		return container.ErrContainerNotFound
	}

	if pc.State == "running" && !force {
		return container.ErrContainerRunning
	}

	delete(m.containers, id)
	return nil
}

// InspectContainer returns details about a mock container.
func (m *MockPodmanBackend) InspectContainer(ctx context.Context, id string) (*container.PodmanContainer, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pc, ok := m.containers[id]
	if !ok {
		return nil, container.ErrContainerNotFound
	}

	return pc, nil
}

// ListContainers returns all mock containers.
func (m *MockPodmanBackend) ListContainers(ctx context.Context, all bool) ([]*container.PodmanContainer, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	containers := make([]*container.PodmanContainer, 0, len(m.containers))
	for _, c := range m.containers {
		if all || c.State == "running" {
			containers = append(containers, c)
		}
	}
	return containers, nil
}

// WaitContainer blocks until the container exits and returns its exit code.
func (m *MockPodmanBackend) WaitContainer(ctx context.Context, id string) (int, error) {
	if m.shouldFail {
		return 0, m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.containers[id]
	if !ok {
		return 0, container.ErrContainerNotFound
	}
	c.State = "exited"
	return c.ExitCode, nil
}

// GetContainerLogs returns mock logs.
func (m *MockPodmanBackend) GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*container.PodmanContainerLogs, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.containers[id]; !ok {
		return nil, container.ErrContainerNotFound
	}

	return &container.PodmanContainerLogs{
		ContainerID: id,
		Stdout:      []byte("mock stdout logs\n"),
		Stderr:      []byte("mock stderr logs\n"),
		Since:       time.Now().Add(-time.Hour),
		Until:       time.Now(),
	}, nil
}

// Close closes the mock backend.
func (m *MockPodmanBackend) Close() error {
	m.connected = false
	return nil
}

// SetFailure configures the mock to fail.
func (m *MockPodmanBackend) SetFailure(err error) {
	m.shouldFail = true
	m.failError = err
}

// ClearFailure clears any configured failure.
func (m *MockPodmanBackend) ClearFailure() {
	m.shouldFail = false
	m.failError = nil
}

// GetCreateCalls returns the number of CreateContainer calls.
func (m *MockPodmanBackend) GetCreateCalls() int32 {
	return atomic.LoadInt32(&m.createCalls)
}

// GetStartCalls returns the number of StartContainer calls.
func (m *MockPodmanBackend) GetStartCalls() int32 {
	return atomic.LoadInt32(&m.startCalls)
}

// GetStopCalls returns the number of StopContainer calls.
func (m *MockPodmanBackend) GetStopCalls() int32 {
	return atomic.LoadInt32(&m.stopCalls)
}

// GetRemoveCalls returns the number of RemoveContainer calls.
func (m *MockPodmanBackend) GetRemoveCalls() int32 {
	return atomic.LoadInt32(&m.removeCalls)
}

// Reset resets the mock state.
func (m *MockPodmanBackend) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.containers = make(map[string]*container.PodmanContainer)
	m.images = make(map[string]*container.PodmanImage)
	atomic.StoreInt32(&m.createCalls, 0)
	atomic.StoreInt32(&m.startCalls, 0)
	atomic.StoreInt32(&m.stopCalls, 0)
	atomic.StoreInt32(&m.removeCalls, 0)
	m.shouldFail = false
	m.failError = nil
}

// AddContainer adds a container directly for test setup.
func (m *MockPodmanBackend) AddContainer(pc *container.PodmanContainer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.containers[pc.ID] = pc
}

// =============================================================================
// Mock Policy Evaluator
// =============================================================================

// MockPolicyEvaluator implements container.LifecyclePolicyEvaluator for testing.
type MockPolicyEvaluator struct {
	mu           sync.RWMutex
	defaultAllow bool
	deniedImages []string
	deniedNames  []string
	evalCalls    int32
	shouldFail   bool
	failError    error
}

// NewMockPolicyEvaluator creates a new mock policy evaluator.
func NewMockPolicyEvaluator() *MockPolicyEvaluator {
	return &MockPolicyEvaluator{
		defaultAllow: true,
		deniedImages: make([]string, 0),
		deniedNames:  make([]string, 0),
	}
}

// EvaluateContainerSpec evaluates policies for a container spec.
func (m *MockPolicyEvaluator) EvaluateContainerSpec(ctx context.Context, spec *container.OrchestratorContainerSpec) (bool, []string, error) {
	atomic.AddInt32(&m.evalCalls, 1)

	if m.shouldFail {
		return false, nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var reasons []string

	// Check denied images
	for _, img := range m.deniedImages {
		if spec.Image == img {
			reasons = append(reasons, "image not allowed: "+img)
		}
	}

	// Check denied names
	for _, name := range m.deniedNames {
		if spec.Name == name {
			reasons = append(reasons, "container name not allowed: "+name)
		}
	}

	// Check privileged
	if spec.Privileged {
		reasons = append(reasons, "privileged containers not allowed")
	}

	if len(reasons) > 0 {
		return false, reasons, nil
	}

	return m.defaultAllow, nil, nil
}

// DenyImage adds an image to the deny list.
func (m *MockPolicyEvaluator) DenyImage(image string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deniedImages = append(m.deniedImages, image)
}

// DenyName adds a container name to the deny list.
func (m *MockPolicyEvaluator) DenyName(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deniedNames = append(m.deniedNames, name)
}

// SetDefaultAllow sets the default allow behavior.
func (m *MockPolicyEvaluator) SetDefaultAllow(allow bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultAllow = allow
}

// SetFailure configures the mock to fail.
func (m *MockPolicyEvaluator) SetFailure(err error) {
	m.shouldFail = true
	m.failError = err
}

// ClearFailure clears any configured failure.
func (m *MockPolicyEvaluator) ClearFailure() {
	m.shouldFail = false
	m.failError = nil
}

// GetEvalCalls returns the number of evaluation calls.
func (m *MockPolicyEvaluator) GetEvalCalls() int32 {
	return atomic.LoadInt32(&m.evalCalls)
}

// Reset resets the mock state.
func (m *MockPolicyEvaluator) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultAllow = true
	m.deniedImages = make([]string, 0)
	m.deniedNames = make([]string, 0)
	atomic.StoreInt32(&m.evalCalls, 0)
	m.shouldFail = false
	m.failError = nil
}

// =============================================================================
// Mock Network Manager
// =============================================================================

// MockNetworkManager implements container.LifecycleNetworkManager for testing.
type MockNetworkManager struct {
	mu            sync.RWMutex
	networks      map[string]bool // containerID -> hasNetwork
	setupCalls    int32
	teardownCalls int32
	shouldFail    bool
	failError     error
}

// NewMockNetworkManager creates a new mock network manager.
func NewMockNetworkManager() *MockNetworkManager {
	return &MockNetworkManager{
		networks: make(map[string]bool),
	}
}

// SetupNetwork sets up network for a container.
func (m *MockNetworkManager) SetupNetwork(ctx context.Context, containerID string, cfg *container.ContainerNetworkConfig) error {
	atomic.AddInt32(&m.setupCalls, 1)

	if m.shouldFail {
		return m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.networks[containerID] = true
	return nil
}

// TeardownNetwork tears down network for a container.
func (m *MockNetworkManager) TeardownNetwork(ctx context.Context, containerID string) error {
	atomic.AddInt32(&m.teardownCalls, 1)

	if m.shouldFail {
		return m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.networks, containerID)
	return nil
}

// HasNetwork returns true if the container has network setup.
func (m *MockNetworkManager) HasNetwork(containerID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.networks[containerID]
}

// SetFailure configures the mock to fail.
func (m *MockNetworkManager) SetFailure(err error) {
	m.shouldFail = true
	m.failError = err
}

// ClearFailure clears any configured failure.
func (m *MockNetworkManager) ClearFailure() {
	m.shouldFail = false
	m.failError = nil
}

// GetSetupCalls returns the number of setup calls.
func (m *MockNetworkManager) GetSetupCalls() int32 {
	return atomic.LoadInt32(&m.setupCalls)
}

// GetTeardownCalls returns the number of teardown calls.
func (m *MockNetworkManager) GetTeardownCalls() int32 {
	return atomic.LoadInt32(&m.teardownCalls)
}

// Reset resets the mock state.
func (m *MockNetworkManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.networks = make(map[string]bool)
	atomic.StoreInt32(&m.setupCalls, 0)
	atomic.StoreInt32(&m.teardownCalls, 0)
	m.shouldFail = false
	m.failError = nil
}

// =============================================================================
// Test Fixtures
// =============================================================================

// TestFixtures holds all mock components for testing.
type TestFixtures struct {
	TPM     *MockTPMProvider
	Podman  *MockPodmanBackend
	Policy  *MockPolicyEvaluator
	Network *MockNetworkManager
	Logger  *slog.Logger
}

// NewTestFixtures creates a new set of test fixtures.
func NewTestFixtures() *TestFixtures {
	return &TestFixtures{
		TPM:     NewMockTPMProvider(),
		Podman:  NewMockPodmanBackend(),
		Policy:  NewMockPolicyEvaluator(),
		Network: NewMockNetworkManager(),
		Logger:  slog.Default(),
	}
}

// Reset resets all fixtures.
func (f *TestFixtures) Reset() {
	f.TPM.Reset()
	f.Podman.Reset()
	f.Policy.Reset()
	f.Network.Reset()
}

// CreateOrchestrator creates an orchestrator with the fixtures.
func (f *TestFixtures) CreateOrchestrator(enableAttestation, enablePolicy bool) (*container.Orchestrator, error) {
	config := container.OrchestratorConfig{
		Logger:             f.Logger,
		EnableAttestation:  enableAttestation,
		EnablePolicy:       enablePolicy,
		PolicyName:         "test-policy",
		DefaultStopTimeout: 10 * time.Second,
	}

	opts := []container.OrchestratorOption{
		container.WithOrchestratorLogger(f.Logger),
		container.WithPodmanBackend(f.Podman),
		container.WithLifecyclePolicyEvaluator(f.Policy),
		container.WithLifecycleNetworkManager(f.Network),
	}

	// Add attestor if enabled
	if enableAttestation {
		attestor, err := container.NewContainerAttestor(f.TPM)
		if err != nil {
			return nil, err
		}
		opts = append(opts, container.WithAttestor(attestor))
	}

	return container.NewOrchestrator(config, opts...)
}

// CreateOrchestratorWithAttestation creates an orchestrator with attestation enabled.
func (f *TestFixtures) CreateOrchestratorWithAttestation() (*container.Orchestrator, error) {
	return f.CreateOrchestrator(true, false)
}

// CreateOrchestratorWithPolicy creates an orchestrator with policy enabled.
func (f *TestFixtures) CreateOrchestratorWithPolicy() (*container.Orchestrator, error) {
	return f.CreateOrchestrator(false, true)
}

// CreateOrchestratorFull creates an orchestrator with all features enabled.
func (f *TestFixtures) CreateOrchestratorFull() (*container.Orchestrator, error) {
	return f.CreateOrchestrator(true, true)
}

// =============================================================================
// Test Helpers
// =============================================================================

// CreateTestContainerSpec creates a container spec for testing.
func CreateTestContainerSpec(name, image string) *container.OrchestratorContainerSpec {
	return &container.OrchestratorContainerSpec{
		Name:  name,
		Image: image,
		Labels: map[string]string{
			"test": "true",
		},
	}
}

// CreateTestContainerSpecWithEnv creates a container spec with environment variables.
func CreateTestContainerSpecWithEnv(name, image string, env map[string]string) *container.OrchestratorContainerSpec {
	spec := CreateTestContainerSpec(name, image)
	spec.Env = env
	return spec
}

// CreatePrivilegedContainerSpec creates a privileged container spec for testing.
func CreatePrivilegedContainerSpec(name, image string) *container.OrchestratorContainerSpec {
	spec := CreateTestContainerSpec(name, image)
	spec.Privileged = true
	return spec
}

// CreateSDNContainerSpec creates a container spec with SDN networking.
func CreateSDNContainerSpec(name, image, bridge string, vlanID uint16) *container.OrchestratorContainerSpec {
	spec := CreateTestContainerSpec(name, image)
	spec.Network = container.ContainerNetworkConfig{
		Mode: container.NetworkModeSDN,
		SDN: &container.SDNConfig{
			Bridge: bridge,
			VLANID: vlanID,
		},
	}
	return spec
}

// =============================================================================
// ID Generation
// =============================================================================

var mockIDCounter int64

// generateMockID generates a unique mock ID.
func generateMockID() string {
	id := atomic.AddInt64(&mockIDCounter, 1)
	return "mock-" + time.Now().Format("20060102150405") + "-" + string(rune('a'+id%26)) + string(rune('0'+id%10))
}
