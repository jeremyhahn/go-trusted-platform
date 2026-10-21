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

package container

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Compile-time interface check
// =============================================================================

var _ ContainerCommands = (*MockAdapter)(nil)

// =============================================================================
// Mock Adapter Implementation
// =============================================================================

// MockAdapter implements ContainerCommands using an in-memory mock orchestrator.
// This adapter enables testing container operations without requiring a real
// container runtime (Docker, Podman, etc.).
type MockAdapter struct {
	mu         sync.RWMutex
	containers map[string]*Container
	logs       map[string][]string
	idCounter  int64

	// Call tracking for test assertions
	createCalls int32
	startCalls  int32
	stopCalls   int32
	removeCalls int32
	getCalls    int32
	listCalls   int32
	logsCalls   int32
	attestCalls int32

	// Configurable failures for error testing
	failOnCreate bool
	failOnStart  bool
	failOnStop   bool
	failOnRemove bool
	failOnGet    bool
	failOnList   bool
	failOnLogs   bool
	failOnAttest bool
	failError    error

	// Latency simulation
	createLatency time.Duration
	startLatency  time.Duration
	stopLatency   time.Duration
}

// NewMockAdapter creates a new mock adapter for integration testing.
func NewMockAdapter() *MockAdapter {
	return &MockAdapter{
		containers: make(map[string]*Container),
		logs:       make(map[string][]string),
	}
}

// Name returns the protocol adapter identifier.
func (m *MockAdapter) Name() string {
	return "Mock"
}

// Setup initializes the mock adapter.
func (m *MockAdapter) Setup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.containers = make(map[string]*Container)
	m.logs = make(map[string][]string)
	atomic.StoreInt64(&m.idCounter, 0)
	m.resetCallCounters()

	return nil
}

// Teardown cleans up the mock adapter.
func (m *MockAdapter) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.containers = make(map[string]*Container)
	m.logs = make(map[string][]string)

	return nil
}

// Create creates a new mock container.
func (m *MockAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	atomic.AddInt32(&m.createCalls, 1)

	if m.failOnCreate {
		if m.failError != nil {
			return nil, m.failError
		}
		return nil, ErrCommandFailed{Command: "create", Output: "", Err: fmt.Errorf("mock create failure")}
	}

	if m.createLatency > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.createLatency):
		}
	}

	if opts.Name == "" {
		return nil, ErrCommandFailed{Command: "create", Output: "", Err: fmt.Errorf("container name is required")}
	}

	if opts.Image == "" {
		return nil, ErrCommandFailed{Command: "create", Output: "", Err: fmt.Errorf("container image is required")}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate name
	for _, c := range m.containers {
		if c.Name == opts.Name {
			return nil, ErrCommandFailed{Command: "create", Output: "", Err: fmt.Errorf("container with name %s already exists", opts.Name)}
		}
	}

	id := m.generateID()
	now := time.Now()

	container := &Container{
		ID:          id,
		Name:        opts.Name,
		Image:       opts.Image,
		ImageID:     "sha256:" + generateMockHash(opts.Image),
		State:       StateCreated,
		CreatedAt:   now,
		Labels:      opts.Labels,
		Environment: opts.Environment,
	}

	m.containers[id] = container
	m.logs[id] = []string{}

	return container, nil
}

// Start starts a mock container.
func (m *MockAdapter) Start(ctx context.Context, id string) error {
	atomic.AddInt32(&m.startCalls, 1)

	if m.failOnStart {
		if m.failError != nil {
			return m.failError
		}
		return ErrCommandFailed{Command: "start", Output: "", Err: fmt.Errorf("mock start failure")}
	}

	if m.startLatency > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.startLatency):
		}
	}

	if id == "" {
		return ErrCommandFailed{Command: "start", Output: "", Err: fmt.Errorf("container ID is required")}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	container, ok := m.containers[id]
	if !ok {
		return ErrContainerNotFound{ID: id}
	}

	if container.State == StateRunning {
		return ErrCommandFailed{Command: "start", Output: "", Err: fmt.Errorf("container is already running")}
	}

	container.State = StateRunning
	container.StartedAt = time.Now()
	container.PID = int(atomic.AddInt64(&m.idCounter, 1)) + 10000

	// Add mock log entry
	m.logs[id] = append(m.logs[id], fmt.Sprintf("[%s] Container started", time.Now().Format(time.RFC3339)))

	return nil
}

// Stop stops a mock container.
func (m *MockAdapter) Stop(ctx context.Context, id string, timeout time.Duration) error {
	atomic.AddInt32(&m.stopCalls, 1)

	if m.failOnStop {
		if m.failError != nil {
			return m.failError
		}
		return ErrCommandFailed{Command: "stop", Output: "", Err: fmt.Errorf("mock stop failure")}
	}

	if m.stopLatency > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.stopLatency):
		}
	}

	if id == "" {
		return ErrCommandFailed{Command: "stop", Output: "", Err: fmt.Errorf("container ID is required")}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	container, ok := m.containers[id]
	if !ok {
		return ErrContainerNotFound{ID: id}
	}

	if !container.State.IsRunning() {
		return ErrCommandFailed{Command: "stop", Output: "", Err: fmt.Errorf("container is not running")}
	}

	container.State = StateStopped
	container.StoppedAt = time.Now()
	container.PID = 0
	container.ExitCode = 0

	// Add mock log entry
	m.logs[id] = append(m.logs[id], fmt.Sprintf("[%s] Container stopped", time.Now().Format(time.RFC3339)))

	return nil
}

// Remove removes a mock container.
func (m *MockAdapter) Remove(ctx context.Context, id string, force bool) error {
	atomic.AddInt32(&m.removeCalls, 1)

	if m.failOnRemove {
		if m.failError != nil {
			return m.failError
		}
		return ErrCommandFailed{Command: "remove", Output: "", Err: fmt.Errorf("mock remove failure")}
	}

	if id == "" {
		return ErrCommandFailed{Command: "remove", Output: "", Err: fmt.Errorf("container ID is required")}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	container, ok := m.containers[id]
	if !ok {
		return ErrContainerNotFound{ID: id}
	}

	if container.State.IsRunning() && !force {
		return ErrCommandFailed{Command: "remove", Output: "", Err: fmt.Errorf("container is running; use force to remove")}
	}

	delete(m.containers, id)
	delete(m.logs, id)

	return nil
}

// Get retrieves a mock container by ID.
func (m *MockAdapter) Get(ctx context.Context, id string) (*Container, error) {
	atomic.AddInt32(&m.getCalls, 1)

	if m.failOnGet {
		if m.failError != nil {
			return nil, m.failError
		}
		return nil, ErrCommandFailed{Command: "get", Output: "", Err: fmt.Errorf("mock get failure")}
	}

	if id == "" {
		return nil, ErrCommandFailed{Command: "get", Output: "", Err: fmt.Errorf("container ID is required")}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	container, ok := m.containers[id]
	if !ok {
		return nil, ErrContainerNotFound{ID: id}
	}

	// Return a copy to prevent modification
	return &Container{
		ID:          container.ID,
		Name:        container.Name,
		Image:       container.Image,
		ImageID:     container.ImageID,
		State:       container.State,
		PID:         container.PID,
		ExitCode:    container.ExitCode,
		CreatedAt:   container.CreatedAt,
		StartedAt:   container.StartedAt,
		StoppedAt:   container.StoppedAt,
		Labels:      container.Labels,
		Environment: container.Environment,
	}, nil
}

// List lists mock containers.
func (m *MockAdapter) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	atomic.AddInt32(&m.listCalls, 1)

	if m.failOnList {
		if m.failError != nil {
			return nil, m.failError
		}
		return nil, ErrCommandFailed{Command: "list", Output: "", Err: fmt.Errorf("mock list failure")}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// An empty list is an empty slice, not nil.
	result := []*Container{}

	for _, c := range m.containers {
		// Apply filters
		if !opts.All && c.State.IsStopped() {
			continue
		}

		if opts.StateFilter != "" && c.State != opts.StateFilter {
			continue
		}

		if opts.NameFilter != "" {
			// Simple prefix matching
			if len(c.Name) < len(opts.NameFilter) || c.Name[:len(opts.NameFilter)] != opts.NameFilter {
				continue
			}
		}

		// Apply label filters
		if len(opts.Filters) > 0 {
			match := true
			for k, v := range opts.Filters {
				if c.Labels[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		// Return a copy
		result = append(result, &Container{
			ID:          c.ID,
			Name:        c.Name,
			Image:       c.Image,
			ImageID:     c.ImageID,
			State:       c.State,
			PID:         c.PID,
			ExitCode:    c.ExitCode,
			CreatedAt:   c.CreatedAt,
			StartedAt:   c.StartedAt,
			StoppedAt:   c.StoppedAt,
			Labels:      c.Labels,
			Environment: c.Environment,
		})

		// Apply limit
		if opts.Limit > 0 && len(result) >= opts.Limit {
			break
		}
	}

	return result, nil
}

// Logs retrieves mock container logs.
func (m *MockAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	atomic.AddInt32(&m.logsCalls, 1)

	if m.failOnLogs {
		if m.failError != nil {
			return nil, m.failError
		}
		return nil, ErrCommandFailed{Command: "logs", Output: "", Err: fmt.Errorf("mock logs failure")}
	}

	if id == "" {
		return nil, ErrCommandFailed{Command: "logs", Output: "", Err: fmt.Errorf("container ID is required")}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.containers[id]; !ok {
		return nil, ErrContainerNotFound{ID: id}
	}

	logs, ok := m.logs[id]
	if !ok {
		return []string{}, nil
	}

	// Apply tail option
	if opts.Tail > 0 && len(logs) > opts.Tail {
		logs = logs[len(logs)-opts.Tail:]
	}

	// Return a copy
	result := make([]string, len(logs))
	copy(result, logs)

	return result, nil
}

// Attest performs mock attestation.
func (m *MockAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	atomic.AddInt32(&m.attestCalls, 1)

	if m.failOnAttest {
		if m.failError != nil {
			return nil, m.failError
		}
		return nil, ErrCommandFailed{Command: "attest", Output: "", Err: fmt.Errorf("mock attest failure")}
	}

	if id == "" {
		return nil, ErrCommandFailed{Command: "attest", Output: "", Err: fmt.Errorf("container ID is required")}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	container, ok := m.containers[id]
	if !ok {
		return nil, ErrContainerNotFound{ID: id}
	}

	// Generate mock attestation report
	report := &AttestationReport{
		ContainerID:   container.ID,
		ContainerName: container.Name,
		ImageDigest:   "sha256:" + generateMockHash(container.Image),
		ConfigDigest:  "sha256:" + generateMockHash(container.Name+container.Image),
		Quote:         generateMockQuote(container),
		Signature:     generateMockSignature(container),
		PCRValues:     generateMockPCRValues(),
		Timestamp:     time.Now(),
		Verified:      true,
		Nonce:         generateMockNonce(),
		Log:           generateMockMeasurementLog(container),
	}

	return report, nil
}

// =============================================================================
// Mock Configuration Methods
// =============================================================================

// SetFailure configures the mock to fail specific operations.
func (m *MockAdapter) SetFailure(operation string, fail bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failError = err

	switch operation {
	case "create":
		m.failOnCreate = fail
	case "start":
		m.failOnStart = fail
	case "stop":
		m.failOnStop = fail
	case "remove":
		m.failOnRemove = fail
	case "get":
		m.failOnGet = fail
	case "list":
		m.failOnList = fail
	case "logs":
		m.failOnLogs = fail
	case "attest":
		m.failOnAttest = fail
	case "all":
		m.failOnCreate = fail
		m.failOnStart = fail
		m.failOnStop = fail
		m.failOnRemove = fail
		m.failOnGet = fail
		m.failOnList = fail
		m.failOnLogs = fail
		m.failOnAttest = fail
	}
}

// SetLatency configures operation latencies for testing timeouts.
func (m *MockAdapter) SetLatency(operation string, latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch operation {
	case "create":
		m.createLatency = latency
	case "start":
		m.startLatency = latency
	case "stop":
		m.stopLatency = latency
	}
}

// ClearFailures clears all configured failures.
func (m *MockAdapter) ClearFailures() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failOnCreate = false
	m.failOnStart = false
	m.failOnStop = false
	m.failOnRemove = false
	m.failOnGet = false
	m.failOnList = false
	m.failOnLogs = false
	m.failOnAttest = false
	m.failError = nil
}

// ClearLatencies clears all configured latencies.
func (m *MockAdapter) ClearLatencies() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.createLatency = 0
	m.startLatency = 0
	m.stopLatency = 0
}

// AddMockContainer directly adds a container to the mock for test setup.
func (m *MockAdapter) AddMockContainer(container *Container) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.containers[container.ID] = container
	m.logs[container.ID] = []string{}
}

// AddMockLogs adds log entries for a container.
func (m *MockAdapter) AddMockLogs(id string, logs []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.logs[id]; !ok {
		m.logs[id] = []string{}
	}
	m.logs[id] = append(m.logs[id], logs...)
}

// =============================================================================
// Call Counter Methods
// =============================================================================

// GetCreateCalls returns the number of Create calls.
func (m *MockAdapter) GetCreateCalls() int32 {
	return atomic.LoadInt32(&m.createCalls)
}

// GetStartCalls returns the number of Start calls.
func (m *MockAdapter) GetStartCalls() int32 {
	return atomic.LoadInt32(&m.startCalls)
}

// GetStopCalls returns the number of Stop calls.
func (m *MockAdapter) GetStopCalls() int32 {
	return atomic.LoadInt32(&m.stopCalls)
}

// GetRemoveCalls returns the number of Remove calls.
func (m *MockAdapter) GetRemoveCalls() int32 {
	return atomic.LoadInt32(&m.removeCalls)
}

// GetGetCalls returns the number of Get calls.
func (m *MockAdapter) GetGetCalls() int32 {
	return atomic.LoadInt32(&m.getCalls)
}

// GetListCalls returns the number of List calls.
func (m *MockAdapter) GetListCalls() int32 {
	return atomic.LoadInt32(&m.listCalls)
}

// GetLogsCalls returns the number of Logs calls.
func (m *MockAdapter) GetLogsCalls() int32 {
	return atomic.LoadInt32(&m.logsCalls)
}

// GetAttestCalls returns the number of Attest calls.
func (m *MockAdapter) GetAttestCalls() int32 {
	return atomic.LoadInt32(&m.attestCalls)
}

// ResetCallCounters resets all call counters to zero.
func (m *MockAdapter) ResetCallCounters() {
	m.resetCallCounters()
}

func (m *MockAdapter) resetCallCounters() {
	atomic.StoreInt32(&m.createCalls, 0)
	atomic.StoreInt32(&m.startCalls, 0)
	atomic.StoreInt32(&m.stopCalls, 0)
	atomic.StoreInt32(&m.removeCalls, 0)
	atomic.StoreInt32(&m.getCalls, 0)
	atomic.StoreInt32(&m.listCalls, 0)
	atomic.StoreInt32(&m.logsCalls, 0)
	atomic.StoreInt32(&m.attestCalls, 0)
}

// =============================================================================
// Internal Helpers
// =============================================================================

// generateID generates a unique container ID.
func (m *MockAdapter) generateID() string {
	id := atomic.AddInt64(&m.idCounter, 1)
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	hash := sha256.Sum256(append(randomBytes, byte(id)))
	return hex.EncodeToString(hash[:])[:64]
}

// generateMockHash generates a mock hash for test data.
func generateMockHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateMockQuote generates mock quote data for attestation.
func generateMockQuote(container *Container) []byte {
	data := fmt.Sprintf("mock-quote:%s:%s:%s", container.ID, container.Name, container.Image)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// generateMockSignature generates mock signature data for attestation.
func generateMockSignature(container *Container) []byte {
	data := fmt.Sprintf("mock-sig:%s:%d", container.ID, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// generateMockPCRValues generates mock PCR values.
func generateMockPCRValues() map[int][]byte {
	pcrs := make(map[int][]byte)
	for i := 0; i < 24; i++ {
		pcrData := make([]byte, 32)
		rand.Read(pcrData)
		pcrs[i] = pcrData
	}
	return pcrs
}

// generateMockNonce generates a mock nonce.
func generateMockNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

// generateMockMeasurementLog generates mock measurement log entries.
func generateMockMeasurementLog(container *Container) []MeasurementLogEntry {
	now := time.Now()
	return []MeasurementLogEntry{
		{
			PCRIndex:  0,
			EventType: "container_create",
			Digest:    []byte(generateMockHash("create:" + container.ID)),
			Data:      []byte(container.Name),
			Timestamp: now.Add(-10 * time.Second),
		},
		{
			PCRIndex:  1,
			EventType: "image_load",
			Digest:    []byte(generateMockHash("image:" + container.Image)),
			Data:      []byte(container.Image),
			Timestamp: now.Add(-5 * time.Second),
		},
		{
			PCRIndex:  2,
			EventType: "container_start",
			Digest:    []byte(generateMockHash("start:" + container.ID)),
			Data:      nil,
			Timestamp: now,
		},
	}
}
