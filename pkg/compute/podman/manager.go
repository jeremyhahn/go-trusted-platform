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

package podman

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// PodmanManager defines the interface for managing containers.
// This uses an embedded OCI runtime for trusted computing integrity.
type PodmanManager interface {
	// Initialize initializes the embedded runtime
	Initialize(ctx context.Context) error

	// Image operations
	PullImage(ctx context.Context, imageRef string) error
	ListImages(ctx context.Context) ([]*Image, error)
	InspectImage(ctx context.Context, imageRef string) (*Image, error)
	RemoveImage(ctx context.Context, imageRef string, force bool) error

	// Container operations
	CreateContainer(ctx context.Context, config *ContainerConfig) (*Container, error)
	StartContainer(ctx context.Context, id string) error
	StopContainer(ctx context.Context, id string, timeout *int) error
	RemoveContainer(ctx context.Context, id string, force bool) error
	InspectContainer(ctx context.Context, id string) (*Container, error)
	ListContainers(ctx context.Context, all bool) ([]*Container, error)
	WaitContainer(ctx context.Context, id string) (int, error)
	GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*ContainerLogs, error)

	// Attestation (optional - set via WithAttestor)
	SetAttestor(attestor ContainerAttestor)
	GetAttestor() ContainerAttestor

	// Lifecycle
	Close() error
	IsInitialized() bool
}

// podmanManager implements the PodmanManager interface using embedded OCI runtime.
// This provides direct container management without external daemon,
// enabling full TPM attestation and measurement of container operations.
type podmanManager struct {
	runtime        *Runtime
	config         *ManagerConfig
	logger         *slog.Logger
	attestor       ContainerAttestor
	containers     sync.Map // map[string]*Container - lock-free container cache
	containerCount atomic.Int64
	initialized    atomic.Bool
	closed         atomic.Bool
}

// ManagerConfig holds configuration for the PodmanManager
type ManagerConfig struct {
	// Runtime is the embedded runtime configuration
	Runtime *RuntimeConfig `json:"runtime" yaml:"runtime"`

	// MaxContainers is the maximum number of containers allowed
	MaxContainers int `json:"max_containers" yaml:"max_containers"`

	// DefaultStopTimeout is the default timeout in seconds for stopping containers
	DefaultStopTimeout int `json:"default_stop_timeout" yaml:"default_stop_timeout"`

	// Debug enables debug logging
	Debug bool `json:"debug" yaml:"debug"`
}

// DefaultManagerConfig returns sensible defaults for the manager
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		Runtime:            DefaultRuntimeConfig(),
		MaxContainers:      100,
		DefaultStopTimeout: DefaultStopTimeout,
		Debug:              false,
	}
}

// Validate validates the manager configuration
func (c *ManagerConfig) Validate() error {
	if c.Runtime == nil {
		return NewConfigValidationError("runtime", "runtime configuration is required")
	}

	if err := c.Runtime.Validate(); err != nil {
		return err
	}

	if c.MaxContainers <= 0 {
		return NewConfigValidationError("max_containers", "max containers must be positive")
	}

	if c.DefaultStopTimeout < 0 {
		return NewConfigValidationError("default_stop_timeout", "stop timeout cannot be negative")
	}

	return nil
}

// ManagerOption configures a podmanManager
type ManagerOption func(*podmanManager)

// WithManagerLogger sets the logger for the manager
func WithManagerLogger(logger *slog.Logger) ManagerOption {
	return func(m *podmanManager) {
		m.logger = logger
	}
}

// WithAttestor sets the container attestor for TPM measurements
func WithAttestor(attestor ContainerAttestor) ManagerOption {
	return func(m *podmanManager) {
		m.attestor = attestor
	}
}

// NewPodmanManager creates a new container manager using embedded OCI runtime.
// This is the trusted computing approach - no external daemon, full measurement capability.
func NewPodmanManager(config *ManagerConfig, opts ...ManagerOption) (PodmanManager, error) {
	if config == nil {
		config = DefaultManagerConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	manager := &podmanManager{
		config: config,
	}

	for _, opt := range opts {
		opt(manager)
	}

	if manager.logger == nil {
		manager.logger = slog.Default()
	}

	return manager, nil
}

// Initialize initializes the embedded container runtime.
// Must be called before any container operations.
func (m *podmanManager) Initialize(ctx context.Context) error {
	if m.initialized.Load() {
		return nil
	}

	m.logger.Info("initializing embedded container runtime")

	runtime, err := NewRuntime(ctx, m.config.Runtime, WithRuntimeLogger(m.logger))
	if err != nil {
		m.logger.Warn("container runtime not available, container operations disabled", "error", err)
		return err
	}

	m.runtime = runtime
	m.initialized.Store(true)

	m.logger.Info("embedded container runtime initialized")
	return nil
}

// IsInitialized returns true if the runtime is initialized
func (m *podmanManager) IsInitialized() bool {
	return m.initialized.Load()
}

// SetAttestor sets the container attestor
func (m *podmanManager) SetAttestor(attestor ContainerAttestor) {
	m.attestor = attestor
}

// GetAttestor returns the container attestor
func (m *podmanManager) GetAttestor() ContainerAttestor {
	return m.attestor
}

// PullImage pulls a container image from a registry
func (m *podmanManager) PullImage(ctx context.Context, imageRef string) error {
	if !m.initialized.Load() {
		return ErrClientNotConnected
	}

	if imageRef == "" {
		return NewImageError("", "pull", ErrImageNotFound)
	}

	return m.runtime.PullImage(ctx, imageRef)
}

// ListImages returns all images
func (m *podmanManager) ListImages(ctx context.Context) ([]*Image, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}

	// For now, return empty list - full image listing requires
	// integration with containers/storage or podman CLI
	m.logger.Debug("listing images - not fully implemented")
	return []*Image{}, nil
}

// InspectImage returns detailed information about an image
func (m *podmanManager) InspectImage(ctx context.Context, imageRef string) (*Image, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}

	if imageRef == "" {
		return nil, NewImageError("", "inspect", ErrImageNotFound)
	}

	// Return basic image info - full inspection requires containers/storage
	return &Image{
		ID:    imageRef,
		Names: []string{imageRef},
	}, nil
}

// RemoveImage removes an image
func (m *podmanManager) RemoveImage(ctx context.Context, imageRef string, force bool) error {
	if !m.initialized.Load() {
		return ErrClientNotConnected
	}

	return m.runtime.RemoveImage(ctx, imageRef, force)
}

// CreateContainer creates a new container
func (m *podmanManager) CreateContainer(ctx context.Context, config *ContainerConfig) (*Container, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}

	if config == nil {
		return nil, ErrInvalidContainerConfig
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Check container limit
	if m.containerCount.Load() >= int64(m.config.MaxContainers) {
		return nil, NewContainerError(config.Name, "create", ErrContainerAlreadyExists)
	}

	// Create container via embedded runtime
	state, err := m.runtime.CreateContainer(ctx, config)
	if err != nil {
		return nil, err
	}

	// Map to Container type
	container := mapContainerState(state)

	// Store in cache
	m.containers.Store(container.ID, container)
	m.containers.Store(container.Name, container)
	m.containerCount.Add(1)

	return container, nil
}

// StartContainer starts a container
func (m *podmanManager) StartContainer(ctx context.Context, id string) error {
	if !m.initialized.Load() {
		return ErrClientNotConnected
	}

	if id == "" {
		return NewContainerError("", "start", ErrContainerNotFound)
	}

	if err := m.runtime.StartContainer(ctx, id); err != nil {
		return err
	}

	// Update cache and trigger attestation
	if cached, ok := m.containers.Load(id); ok {
		container := cached.(*Container)
		container.State = ContainerStateRunning
		now := time.Now()
		container.StartedAt = &now

		// TPM attestation on start
		if m.attestor != nil {
			if err := m.attestor.OnContainerStart(ctx, container); err != nil {
				m.logger.Warn("container attestation failed", "container", id, "error", err)
				// Don't fail the start, just log
			}
		}
	}

	return nil
}

// StopContainer stops a running container
func (m *podmanManager) StopContainer(ctx context.Context, id string, timeout *int) error {
	if !m.initialized.Load() {
		return ErrClientNotConnected
	}

	if id == "" {
		return NewContainerError("", "stop", ErrContainerNotFound)
	}

	stopTimeout := uint(m.config.DefaultStopTimeout)
	if timeout != nil {
		stopTimeout = uint(*timeout)
	}

	if err := m.runtime.StopContainer(ctx, id, stopTimeout); err != nil {
		return err
	}

	// Update cache and trigger attestation
	if cached, ok := m.containers.Load(id); ok {
		container := cached.(*Container)
		container.State = ContainerStateStopped
		now := time.Now()
		container.FinishedAt = &now

		// TPM attestation on stop
		if m.attestor != nil {
			if err := m.attestor.OnContainerStop(ctx, container); err != nil {
				m.logger.Warn("container stop attestation failed", "container", id, "error", err)
			}
		}
	}

	return nil
}

// RemoveContainer removes a container
func (m *podmanManager) RemoveContainer(ctx context.Context, id string, force bool) error {
	if !m.initialized.Load() {
		return ErrClientNotConnected
	}

	if id == "" {
		return NewContainerError("", "remove", ErrContainerNotFound)
	}

	if err := m.runtime.RemoveContainer(ctx, id, force); err != nil {
		return err
	}

	// Remove from cache
	if cached, ok := m.containers.Load(id); ok {
		container := cached.(*Container)
		m.containers.Delete(container.ID)
		m.containers.Delete(container.Name)
		m.containerCount.Add(-1)
	}

	return nil
}

// InspectContainer returns detailed information about a container
func (m *podmanManager) InspectContainer(ctx context.Context, id string) (*Container, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}

	if id == "" {
		return nil, NewContainerError("", "inspect", ErrContainerNotFound)
	}

	state, err := m.runtime.InspectContainer(ctx, id)
	if err != nil {
		return nil, err
	}

	container := mapContainerState(state)

	// Update cache
	m.containers.Store(container.ID, container)
	m.containers.Store(container.Name, container)

	return container, nil
}

// ListContainers returns all containers
func (m *podmanManager) ListContainers(ctx context.Context, all bool) ([]*Container, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}

	states, err := m.runtime.ListContainers(ctx, all)
	if err != nil {
		return nil, err
	}

	result := make([]*Container, 0, len(states))
	for _, state := range states {
		container := mapContainerState(state)
		result = append(result, container)

		// Update cache
		m.containers.Store(container.ID, container)
		if container.Name != "" {
			m.containers.Store(container.Name, container)
		}
	}

	return result, nil
}

// WaitContainer waits for a container to exit and returns the exit code
func (m *podmanManager) WaitContainer(ctx context.Context, id string) (int, error) {
	if !m.initialized.Load() {
		return -1, ErrClientNotConnected
	}

	if id == "" {
		return -1, NewContainerError("", "wait", ErrContainerNotFound)
	}

	exitCode, err := m.runtime.WaitContainer(ctx, id)
	if err != nil {
		return -1, err
	}

	return int(exitCode), nil
}

// GetContainerLogs retrieves logs from a container
func (m *podmanManager) GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*ContainerLogs, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}

	if id == "" {
		return nil, NewContainerError("", "logs", ErrContainerNotFound)
	}

	// For now, return empty logs - full log support requires
	// integration with conmon or direct log file reading
	m.logger.Debug("getting container logs - not fully implemented", "container", id)

	logs := &ContainerLogs{
		ContainerID: id,
		Stdout:      []byte{},
		Stderr:      []byte{},
		Until:       time.Now(),
	}

	if since != nil {
		logs.Since = *since
	}

	return logs, nil
}

// Close closes the manager and releases resources
func (m *podmanManager) Close() error {
	if m.closed.Load() {
		return nil
	}

	m.closed.Store(true)

	if m.runtime != nil {
		if err := m.runtime.Close(); err != nil {
			return err
		}
	}

	// Clear container cache
	m.containers.Range(func(key, value interface{}) bool {
		m.containers.Delete(key)
		return true
	})
	m.containerCount.Store(0)

	m.initialized.Store(false)

	m.logger.Info("container manager closed")
	return nil
}

// mapContainerState converts containerState to Container
func mapContainerState(state *containerState) *Container {
	container := &Container{
		ID:        state.ID,
		Name:      state.Name,
		Image:     state.Image,
		State:     state.State,
		CreatedAt: state.CreatedAt,
		PID:       state.PID,
		ExitCode:  state.ExitCode,
	}

	if state.StartedAt != nil {
		container.StartedAt = state.StartedAt
	}

	if state.FinishedAt != nil {
		container.FinishedAt = state.FinishedAt
	}

	// Copy config fields if available
	if state.Config != nil {
		container.Labels = state.Config.Labels
		container.Mounts = state.Config.Mounts
		container.Ports = state.Config.Ports
		container.Environment = state.Config.Environment
		container.Command = state.Config.Command
		container.NetworkMode = state.Config.NetworkMode
	}

	return container
}

// Legacy compatibility - Connect is an alias for Initialize
func (m *podmanManager) Connect(ctx context.Context) error {
	return m.Initialize(ctx)
}
