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
	m.mu.RLock()
	defer m.mu.RUnlock()

	// An empty listing is an empty slice, never nil, as every served
	// transport decodes it.
	result := make([]*Container, 0, len(m.containers))

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
