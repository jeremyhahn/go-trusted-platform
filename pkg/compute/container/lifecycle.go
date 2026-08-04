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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PodmanBackend defines the interface for Podman container operations.
// This interface allows for dependency injection and mocking in tests.
type PodmanBackend interface {
	// Connect establishes connection to Podman service.
	Connect(ctx context.Context) error

	// PullImage pulls a container image from a registry.
	PullImage(ctx context.Context, imageRef string) error

	// ListImages returns all images.
	ListImages(ctx context.Context) ([]*PodmanImage, error)

	// InspectImage returns detailed information about an image.
	InspectImage(ctx context.Context, imageRef string) (*PodmanImage, error)

	// CreateContainer creates a new container.
	CreateContainer(ctx context.Context, config *PodmanContainerConfig) (*PodmanContainer, error)

	// StartContainer starts a container.
	StartContainer(ctx context.Context, id string) error

	// StopContainer stops a running container.
	StopContainer(ctx context.Context, id string, timeout *int) error

	// RemoveContainer removes a container.
	RemoveContainer(ctx context.Context, id string, force bool) error

	// InspectContainer returns detailed information about a container.
	InspectContainer(ctx context.Context, id string) (*PodmanContainer, error)

	// ListContainers returns all containers.
	ListContainers(ctx context.Context, all bool) ([]*PodmanContainer, error)

	// GetContainerLogs retrieves logs from a container.
	GetContainerLogs(ctx context.Context, id string, follow bool, since *time.Time) (*PodmanContainerLogs, error)

	// WaitContainer blocks until the container exits and returns its exit code.
	WaitContainer(ctx context.Context, id string) (int, error)

	// Close closes the Podman connection.
	Close() error
}

// PodmanImage represents a Podman container image.
type PodmanImage struct {
	ID           string
	Names        []string
	Digest       string
	Size         int64
	Created      time.Time
	Labels       map[string]string
	Architecture string
	OS           string
}

// PodmanContainer represents a Podman container.
type PodmanContainer struct {
	ID          string
	Name        string
	Image       string
	ImageDigest string
	State       string
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
	ExitCode    int
	Labels      map[string]string
	PID         int
	Command     []string
	NetworkMode string
}

// PodmanContainerConfig holds configuration for creating a container via Podman.
type PodmanContainerConfig struct {
	Name        string
	Image       string
	Command     []string
	Entrypoint  []string
	Environment map[string]string
	Labels      map[string]string
	Mounts      []PodmanMount
	Ports       []PodmanPort
	NetworkMode string
	User        string
	WorkDir     string
	Hostname    string
	Privileged  bool
	ReadOnly    bool
	AutoRemove  bool
	StopTimeout *int
	CapAdd      []string
	CapDrop     []string
	DNS         []string
	DNSSearch   []string
	TPMAccess   bool
}

// PodmanMount represents a container mount.
type PodmanMount struct {
	Source   string
	Target   string
	Type     string
	ReadOnly bool
	Options  []string
}

// PodmanPort represents a port mapping.
type PodmanPort struct {
	HostIP        string
	HostPort      uint16
	ContainerPort uint16
	Protocol      string
}

// PodmanContainerLogs holds container log data.
type PodmanContainerLogs struct {
	ContainerID string
	Stdout      []byte
	Stderr      []byte
	Since       time.Time
	Until       time.Time
}

// LifecyclePolicyEvaluator defines the interface for policy evaluation
// as used by the lifecycle orchestrator. This is a simplified interface
// that wraps the more complex PolicyEvaluator from policy.go.
type LifecyclePolicyEvaluator interface {
	// EvaluateContainerSpec evaluates policies for a container specification.
	// Returns allowed=true if the container is allowed to be created.
	EvaluateContainerSpec(ctx context.Context, spec *OrchestratorContainerSpec) (allowed bool, reasons []string, err error)
}

// LifecycleNetworkManager defines the interface for network operations
// as used by the lifecycle orchestrator. This adapts the NetworkManager
// from network.go to the simpler interface needed here.
type LifecycleNetworkManager interface {
	// SetupNetwork configures networking for a container.
	SetupNetwork(ctx context.Context, containerID string, cfg *ContainerNetworkConfig) error

	// TeardownNetwork removes networking for a container.
	TeardownNetwork(ctx context.Context, containerID string) error
}

// OrchestratorConfig holds configuration for the Orchestrator.
type OrchestratorConfig struct {
	// Logger is the logger to use.
	Logger *slog.Logger

	// SystemdDir is the directory for systemd service files.
	SystemdDir string

	// RCDir is the directory for OpenRC service files.
	RCDir string

	// EnableAttestation enables TPM attestation for containers.
	EnableAttestation bool

	// EnablePolicy enables OPA policy evaluation.
	EnablePolicy bool

	// PolicyName is the name of the policy to evaluate.
	PolicyName string

	// DefaultStopTimeout is the default timeout for stopping containers.
	DefaultStopTimeout time.Duration

	// MeasurementLogPath is the path to persist the measurement log.
	MeasurementLogPath string
}

// Validate validates the OrchestratorConfig.
func (c *OrchestratorConfig) Validate() error {
	if c.Logger == nil {
		return ErrInvalidSpec
	}
	if c.DefaultStopTimeout < 0 {
		return ErrInvalidSpec
	}
	return nil
}

// OrchestratorOption configures an Orchestrator.
type OrchestratorOption func(*Orchestrator)

// WithOrchestratorLogger sets the logger for the orchestrator.
func WithOrchestratorLogger(logger *slog.Logger) OrchestratorOption {
	return func(o *Orchestrator) {
		o.logger = logger
	}
}

// WithPodmanBackend sets the Podman backend.
func WithPodmanBackend(backend PodmanBackend) OrchestratorOption {
	return func(o *Orchestrator) {
		o.podman = backend
	}
}

// WithAttestor sets the container attestor.
func WithAttestor(attestor *ContainerAttestor) OrchestratorOption {
	return func(o *Orchestrator) {
		o.attestor = attestor
	}
}

// WithLifecyclePolicyEvaluator sets the policy evaluator.
func WithLifecyclePolicyEvaluator(evaluator LifecyclePolicyEvaluator) OrchestratorOption {
	return func(o *Orchestrator) {
		o.policy = evaluator
	}
}

// WithLifecycleNetworkManager sets the network manager.
func WithLifecycleNetworkManager(network LifecycleNetworkManager) OrchestratorOption {
	return func(o *Orchestrator) {
		o.network = network
	}
}

// WithServiceManager sets the service manager.
func WithServiceManager(service *ServiceManager) OrchestratorOption {
	return func(o *Orchestrator) {
		o.service = service
	}
}

// WithImageManager sets the image manager.
func WithImageManager(imageManager *ImageManager) OrchestratorOption {
	return func(o *Orchestrator) {
		o.imageManager = imageManager
	}
}

// Orchestrator implements the ContainerOrchestrator interface.
// It manages container lifecycle with TPM attestation, OPA policy enforcement,
// and SDN network integration.
type Orchestrator struct {
	config       OrchestratorConfig
	logger       *slog.Logger
	podman       PodmanBackend
	attestor     *ContainerAttestor
	policy       LifecyclePolicyEvaluator
	network      LifecycleNetworkManager
	service      *ServiceManager
	imageManager *ImageManager

	// containers maps container IDs to Container instances.
	containers sync.Map

	// containersByName maps container names to IDs for fast lookup.
	containersByName sync.Map

	// closed indicates if the orchestrator has been closed.
	closed atomic.Bool

	// mu protects critical sections during multi-step operations.
}

// NewOrchestrator creates a new Orchestrator with the given configuration.
func NewOrchestrator(config OrchestratorConfig, opts ...OrchestratorOption) (*Orchestrator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	o := &Orchestrator{
		config: config,
		logger: config.Logger,
	}

	for _, opt := range opts {
		opt(o)
	}

	// Set defaults if not provided
	if o.logger == nil {
		o.logger = slog.Default()
	}

	if config.DefaultStopTimeout == 0 {
		o.config.DefaultStopTimeout = 10 * time.Second
	}

	return o, nil
}

// Create creates a new container from a specification.
// It performs the following steps:
// 1. Validate the specification
// 2. Evaluate OPA policy (if enabled)
// 3. Pull image if not available locally
// 4. Create container via Podman
// 5. Record measurement in TPM (if attestation enabled)
// 6. Setup standalone service (if configured)
func (o *Orchestrator) Create(ctx context.Context, spec *OrchestratorContainerSpec) (*Container, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if spec == nil {
		return nil, ErrInvalidSpec
	}

	if err := spec.Validate(); err != nil {
		return nil, err
	}

	o.logger.Info("creating container", "name", spec.Name, "image", spec.Image)

	// Step 1: Check if container already exists
	if _, exists := o.containersByName.Load(spec.Name); exists {
		return nil, NewContainerError("", spec.Name, "create", ErrContainerExists)
	}

	// Step 2: Evaluate policy (if enabled)
	if o.config.EnablePolicy && o.policy != nil {
		allowed, reasons, err := o.policy.EvaluateContainerSpec(ctx, spec)
		if err != nil {
			return nil, NewContainerError("", spec.Name, "policy_evaluation", err)
		}
		if !allowed {
			return nil, NewPolicyError(o.config.PolicyName, reasons)
		}
	}

	// Step 3: Pull image if needed
	if o.imageManager != nil {
		if err := o.imageManager.PullImage(ctx, spec.Image, PullOptions{}); err != nil {
			o.logger.Warn("image pull failed, may already exist", "image", spec.Image, "error", err)
		}
	}

	// Step 4: Create container via Podman
	podmanConfig := convertSpecToPodmanConfig(spec)
	podmanContainer, err := o.podman.CreateContainer(ctx, podmanConfig)
	if err != nil {
		return nil, NewContainerError("", spec.Name, "podman_create", err)
	}

	// Step 5: Record measurement in TPM (if attestation enabled)
	if o.config.EnableAttestation && o.attestor != nil {
		imageDigest, err := o.attestor.ComputeImageDigest(spec.Image)
		if err != nil {
			o.logger.Error("failed to compute image digest", "error", err)
		} else {
			attestationSpec := spec.ToAttestationSpec()
			configDigest, err := o.attestor.ComputeConfigDigest(attestationSpec)
			if err != nil {
				o.logger.Error("failed to compute config digest", "error", err)
			} else {
				if err := o.attestor.RecordContainerCreate(ctx, podmanContainer.ID, spec.Name, imageDigest, configDigest); err != nil {
					o.logger.Error("failed to record container creation", "error", err)
				}
			}
		}
	}

	// Step 6: Create Container struct
	container := &Container{
		ID:        podmanContainer.ID,
		Name:      spec.Name,
		Image:     spec.Image,
		ImageID:   podmanContainer.ImageDigest,
		State:     StateCreated,
		Spec:      spec,
		CreatedAt: time.Now(),
		Labels:    spec.Labels,
	}

	// Step 7: Setup standalone service (if configured)
	if spec.Service.GetMode() == ServiceModeStandalone && o.service != nil {
		containerConfig := &ContainerConfig{
			Name:         spec.Name,
			Image:        spec.Image,
			Command:      spec.Command,
			Args:         spec.Args,
			Env:          spec.Env,
			Mounts:       spec.Mounts,
			Resources:    spec.Resources,
			Network:      spec.Network,
			Service:      spec.Service,
			Labels:       spec.Labels,
			Privileged:   spec.Privileged,
			Capabilities: spec.Capabilities,
			Ports:        spec.Ports,
		}
		if err := o.service.EnsureService(ctx, containerConfig); err != nil {
			o.logger.Error("failed to create service", "container", spec.Name, "error", err)
		}
	}

	// Store container in maps
	o.containers.Store(container.ID, container)
	o.containersByName.Store(container.Name, container.ID)

	o.logger.Info("created container", "id", container.ID, "name", container.Name)
	return container, nil
}

// Start starts a stopped container.
func (o *Orchestrator) Start(ctx context.Context, id string) error {
	if o.closed.Load() {
		return ErrOrchestratorClosed
	}

	if id == "" {
		return ErrInvalidContainerID
	}

	container, err := o.getContainer(id)
	if err != nil {
		return err
	}

	if container.State.IsRunning() {
		return NewContainerError(id, container.Name, "start", ErrContainerRunning)
	}

	o.logger.Info("starting container", "id", id, "name", container.Name)

	// Setup network (if SDN mode)
	if container.Spec != nil && container.Spec.Network.GetNetworkMode() == NetworkModeSDN && o.network != nil {
		if err := o.network.SetupNetwork(ctx, id, &container.Spec.Network); err != nil {
			return NewContainerError(id, container.Name, "network_setup", err)
		}
	}

	// Start via Podman
	if err := o.podman.StartContainer(ctx, id); err != nil {
		return NewContainerError(id, container.Name, "podman_start", err)
	}

	// Refresh runtime details (PID) from the backend. A failed inspect is
	// non-fatal: the container is running, only the PID is unknown.
	if inspected, inspectErr := o.podman.InspectContainer(ctx, id); inspectErr != nil {
		o.logger.Warn("failed to inspect container after start", "id", id, "error", inspectErr)
	} else if inspected != nil {
		container.Pid = inspected.PID
	}

	// Record attestation event
	if o.config.EnableAttestation && o.attestor != nil {
		if err := o.attestor.RecordContainerStart(ctx, id, container.Name); err != nil {
			o.logger.Error("failed to record container start", "error", err)
		}
	}

	// Update container state
	container.State = StateRunning
	now := time.Now()
	container.StartedAt = now
	o.containers.Store(id, container)

	o.logger.Info("started container", "id", id, "name", container.Name)
	return nil
}

// Stop stops a running container.
func (o *Orchestrator) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if o.closed.Load() {
		return ErrOrchestratorClosed
	}

	if id == "" {
		return ErrInvalidContainerID
	}

	container, err := o.getContainer(id)
	if err != nil {
		return err
	}

	// Only running containers can be stopped
	if !container.State.IsRunning() {
		return NewContainerError(id, container.Name, "stop", ErrContainerStopped)
	}

	o.logger.Info("stopping container", "id", id, "name", container.Name, "timeout", timeout)

	// Use default timeout if not specified
	if timeout <= 0 {
		timeout = o.config.DefaultStopTimeout
	}

	// Stop via Podman
	timeoutSec := int(timeout.Seconds())
	if err := o.podman.StopContainer(ctx, id, &timeoutSec); err != nil {
		return NewContainerError(id, container.Name, "podman_stop", err)
	}

	// Teardown network (if SDN mode)
	if container.Spec != nil && container.Spec.Network.GetNetworkMode() == NetworkModeSDN && o.network != nil {
		if err := o.network.TeardownNetwork(ctx, id); err != nil {
			o.logger.Error("failed to teardown network", "error", err)
		}
	}

	// Record attestation event
	if o.config.EnableAttestation && o.attestor != nil {
		if err := o.attestor.RecordContainerStop(ctx, id, container.Name); err != nil {
			o.logger.Error("failed to record container stop", "error", err)
		}
	}

	// Update container state
	container.State = StateStopped
	now := time.Now()
	container.FinishedAt = now
	o.containers.Store(id, container)

	o.logger.Info("stopped container", "id", id, "name", container.Name)
	return nil
}

// Remove removes a container.
func (o *Orchestrator) Remove(ctx context.Context, id string, force bool) error {
	if o.closed.Load() {
		return ErrOrchestratorClosed
	}

	if id == "" {
		return ErrInvalidContainerID
	}

	container, err := o.getContainer(id)
	if err != nil {
		return err
	}

	// If container is running and force is false, error
	if container.State.IsRunning() && !force {
		return NewContainerError(id, container.Name, "remove", ErrContainerRunning)
	}

	o.logger.Info("removing container", "id", id, "name", container.Name, "force", force)

	// Stop if running and force is true
	if container.State.IsRunning() && force {
		if err := o.Stop(ctx, id, o.config.DefaultStopTimeout); err != nil {
			o.logger.Warn("failed to stop container before removal", "error", err)
		}
	}

	// Teardown network (if SDN mode)
	if container.Spec != nil && container.Spec.Network.GetNetworkMode() == NetworkModeSDN && o.network != nil {
		if err := o.network.TeardownNetwork(ctx, id); err != nil {
			o.logger.Error("failed to teardown network", "error", err)
		}
	}

	// Remove via Podman
	if err := o.podman.RemoveContainer(ctx, id, force); err != nil {
		return NewContainerError(id, container.Name, "podman_remove", err)
	}

	// Record attestation event
	if o.config.EnableAttestation && o.attestor != nil {
		if err := o.attestor.RecordContainerRemove(ctx, id, container.Name); err != nil {
			o.logger.Error("failed to record container removal", "error", err)
		}
	}

	// Remove standalone service (if configured)
	if container.Spec != nil && container.Spec.Service.GetMode() == ServiceModeStandalone && o.service != nil {
		if err := o.service.RemoveService(ctx, container.Name); err != nil {
			o.logger.Error("failed to remove service", "error", err)
		}
	}

	// Remove from maps
	o.containers.Delete(id)
	o.containersByName.Delete(container.Name)

	o.logger.Info("removed container", "id", id, "name", container.Name)
	return nil
}

// Get retrieves a container by ID.
func (o *Orchestrator) Get(ctx context.Context, id string) (*Container, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if id == "" {
		return nil, ErrInvalidContainerID
	}

	// Try cache first
	container, err := o.getContainer(id)
	if err == nil {
		return container, nil
	}

	// Try Podman backend
	podmanContainer, err := o.podman.InspectContainer(ctx, id)
	if err != nil {
		return nil, ErrContainerNotFound
	}

	// Convert and cache
	container = convertPodmanContainerToContainer(podmanContainer)
	o.containers.Store(container.ID, container)
	if container.Name != "" {
		o.containersByName.Store(container.Name, container.ID)
	}

	return container, nil
}

// List returns containers matching the filter options.
func (o *Orchestrator) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	// Get containers from Podman
	podmanContainers, err := o.podman.ListContainers(ctx, opts.All)
	if err != nil {
		return nil, NewContainerError("", "", "list", err)
	}

	containers := make([]*Container, 0, len(podmanContainers))
	for _, pc := range podmanContainers {
		container := convertPodmanContainerToContainer(pc)

		// Apply filters
		if !matchFilters(container, opts.Filters) {
			continue
		}

		containers = append(containers, container)

		// Update cache
		o.containers.Store(container.ID, container)
		if container.Name != "" {
			o.containersByName.Store(container.Name, container.ID)
		}
	}

	// Apply limit
	if opts.Limit > 0 && len(containers) > opts.Limit {
		containers = containers[:opts.Limit]
	}

	return containers, nil
}

// Wait blocks until the container exits and returns its exit code. The
// cached container state is updated to reflect the exit.
func (o *Orchestrator) Wait(ctx context.Context, id string) (int, error) {
	if o.closed.Load() {
		return 0, ErrOrchestratorClosed
	}

	if id == "" {
		return 0, ErrInvalidContainerID
	}

	container, err := o.getContainer(id)
	if err != nil {
		return 0, err
	}

	exitCode, err := o.podman.WaitContainer(ctx, id)
	if err != nil {
		return 0, NewContainerError(id, container.Name, "podman_wait", err)
	}

	container.State = StateExited
	container.ExitCode = exitCode
	container.FinishedAt = time.Now()
	container.Pid = 0
	o.containers.Store(id, container)

	return exitCode, nil
}

// Logs returns a stream of container logs.
func (o *Orchestrator) Logs(ctx context.Context, id string, opts LogOptions) (io.ReadCloser, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if id == "" {
		return nil, ErrInvalidContainerID
	}

	container, err := o.getContainer(id)
	if err != nil {
		return nil, err
	}

	var since *time.Time
	if !opts.Since.IsZero() {
		since = &opts.Since
	}

	logs, err := o.podman.GetContainerLogs(ctx, id, opts.Follow, since)
	if err != nil {
		return nil, NewContainerError(id, container.Name, "logs", err)
	}

	// Combine stdout and stderr into a single reader
	var combined []byte
	if opts.Stdout {
		combined = append(combined, logs.Stdout...)
	}
	if opts.Stderr {
		combined = append(combined, logs.Stderr...)
	}

	return io.NopCloser(bytes.NewReader(combined)), nil
}

// Attest performs TPM attestation for a container.
func (o *Orchestrator) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if id == "" {
		return nil, ErrInvalidContainerID
	}

	if o.attestor == nil {
		return nil, ErrAttestationFailed
	}

	container, err := o.getContainer(id)
	if err != nil {
		return nil, err
	}

	// Generate quote using the attestor's configured PCR index
	quote, err := o.attestor.GenerateQuote(ctx, []int{o.attestor.GetPCRIndex()})
	if err != nil {
		return nil, NewContainerError(id, container.Name, "generate_quote", err)
	}

	// Get measurement log
	measurementLog := o.attestor.GetMeasurementLog()

	// Find container entry in log
	entry, err := measurementLog.FindEntry(id)
	if err != nil {
		return nil, NewContainerError(id, container.Name, "find_measurement", err)
	}

	report := &AttestationReport{
		ContainerID:   id,
		ContainerName: container.Name,
		Timestamp:     time.Now(),
		Quote:         quote.QuoteData,
		Signature:     quote.Signature,
		Log:           measurementLog.ToMeasurementLog(),
		ImageDigest:   entry.ImageDigest,
		ConfigDigest:  entry.ConfigDigest,
		PCRValues:     quote.PCRs,
		Verified:      false,
	}

	return report, nil
}

// VerifyAttestation verifies attestation evidence for a container.
func (o *Orchestrator) VerifyAttestation(ctx context.Context, id string, evidence []byte) error {
	if o.closed.Load() {
		return ErrOrchestratorClosed
	}

	if id == "" {
		return ErrInvalidContainerID
	}

	if o.attestor == nil {
		return ErrAttestationFailed
	}

	// This is a placeholder - in production, evidence would be parsed
	// and verified using the TPM provider
	return nil
}

// EvaluatePolicy evaluates OPA policies against a container specification.
// Returns a simple decision result for external callers.
func (o *Orchestrator) EvaluatePolicy(ctx context.Context, spec *OrchestratorContainerSpec) (bool, []string, error) {
	if o.closed.Load() {
		return false, nil, ErrOrchestratorClosed
	}

	if spec == nil {
		return false, nil, ErrInvalidSpec
	}

	if o.policy == nil {
		// If no policy evaluator, allow by default
		return true, nil, nil
	}

	return o.policy.EvaluateContainerSpec(ctx, spec)
}

// PullImage pulls a container image from a registry.
func (o *Orchestrator) PullImage(ctx context.Context, ref string, opts PullOptions) error {
	if o.closed.Load() {
		return ErrOrchestratorClosed
	}

	if ref == "" {
		return ErrInvalidImage
	}

	if o.imageManager != nil {
		return o.imageManager.PullImage(ctx, ref, opts)
	}

	if o.podman != nil {
		return o.podman.PullImage(ctx, ref)
	}

	return ErrPodmanNotAvailable
}

// VerifyImage verifies the signature of a container image.
func (o *Orchestrator) VerifyImage(ctx context.Context, ref string) (*ImageVerification, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if ref == "" {
		return nil, ErrInvalidImage
	}

	if o.imageManager != nil {
		return o.imageManager.VerifyImage(ctx, ref)
	}

	// If no image manager, return unverified
	return &ImageVerification{
		ImageRef:  ref,
		Verified:  false,
		Timestamp: time.Now(),
	}, nil
}

// Close closes the orchestrator and releases resources.
func (o *Orchestrator) Close() error {
	if o.closed.Load() {
		return nil
	}

	o.closed.Store(true)
	o.logger.Info("closing orchestrator")

	// Persist measurement log if configured
	if o.config.MeasurementLogPath != "" && o.attestor != nil {
		log := o.attestor.GetMeasurementLog()
		if err := log.Persist(o.config.MeasurementLogPath); err != nil {
			o.logger.Error("failed to persist measurement log", "error", err)
		}
	}

	// Close attestor
	if o.attestor != nil {
		if err := o.attestor.Close(); err != nil {
			o.logger.Error("failed to close attestor", "error", err)
		}
	}

	// Close Podman backend
	if o.podman != nil {
		if err := o.podman.Close(); err != nil {
			o.logger.Error("failed to close Podman backend", "error", err)
		}
	}

	// Clear container maps
	o.containers.Range(func(key, value interface{}) bool {
		o.containers.Delete(key)
		return true
	})
	o.containersByName.Range(func(key, value interface{}) bool {
		o.containersByName.Delete(key)
		return true
	})

	o.logger.Info("orchestrator closed")
	return nil
}

// getContainer retrieves a container from the cache by ID or name.
func (o *Orchestrator) getContainer(idOrName string) (*Container, error) {
	// Try by ID first
	if value, ok := o.containers.Load(idOrName); ok {
		return value.(*Container), nil
	}

	// Try by name
	if containerID, ok := o.containersByName.Load(idOrName); ok {
		if value, ok := o.containers.Load(containerID); ok {
			return value.(*Container), nil
		}
	}

	return nil, ErrContainerNotFound
}

// convertSpecToPodmanConfig converts an OrchestratorContainerSpec to PodmanContainerConfig.
func convertSpecToPodmanConfig(spec *OrchestratorContainerSpec) *PodmanContainerConfig {
	config := &PodmanContainerConfig{
		Name:        spec.Name,
		Image:       spec.Image,
		Environment: spec.Env,
		Labels:      spec.Labels,
		User:        spec.User,
		WorkDir:     spec.WorkingDir,
		Privileged:  spec.Privileged,
		CapAdd:      spec.Capabilities.Add,
		CapDrop:     spec.Capabilities.Drop,
		DNS:         spec.Network.DNSServers,
		DNSSearch:   spec.Network.DNSSearch,
		Hostname:    spec.Network.Hostname,
	}

	// Combine Command and Args into the Command slice
	// The Command slice should contain [command, arg1, arg2, ...]
	if len(spec.Command) > 0 || len(spec.Args) > 0 {
		totalLen := len(spec.Command) + len(spec.Args)
		config.Command = make([]string, 0, totalLen)
		config.Command = append(config.Command, spec.Command...)
		config.Command = append(config.Command, spec.Args...)
	}

	// Mounts
	for _, m := range spec.Mounts {
		config.Mounts = append(config.Mounts, PodmanMount{
			Source:   m.Source,
			Target:   m.Target,
			Type:     string(m.Type),
			ReadOnly: m.ReadOnly,
		})
	}

	// Ports
	for _, p := range spec.Ports {
		config.Ports = append(config.Ports, PodmanPort{
			HostIP:        p.HostIP,
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Protocol:      p.Protocol,
		})
	}

	// TPM passthrough: expose the host TPM character device inside the
	// container so workloads can perform TPM operations directly.
	if spec.TPMAccess {
		config.TPMAccess = true
		config.Mounts = append(config.Mounts, PodmanMount{
			Source: HostTPMDevicePath,
			Target: HostTPMDevicePath,
			Type:   string(MountTypeBind),
		})
	}

	// Network mode
	switch spec.Network.GetNetworkMode() {
	case NetworkModeHost:
		config.NetworkMode = "host"
	case NetworkModeNone:
		config.NetworkMode = "none"
	default:
		config.NetworkMode = "bridge"
	}

	return config
}

// convertPodmanContainerToContainer converts a PodmanContainer to Container.
func convertPodmanContainerToContainer(pc *PodmanContainer) *Container {
	state := mapPodmanState(pc.State)

	container := &Container{
		ID:       pc.ID,
		Name:     pc.Name,
		Image:    pc.Image,
		ImageID:  pc.ImageDigest,
		State:    state,
		ExitCode: pc.ExitCode,
		Pid:      pc.PID,
		Labels:   pc.Labels,
	}

	if !pc.CreatedAt.IsZero() {
		container.CreatedAt = pc.CreatedAt
	}

	if pc.StartedAt != nil && !pc.StartedAt.IsZero() {
		container.StartedAt = *pc.StartedAt
	}

	if pc.FinishedAt != nil && !pc.FinishedAt.IsZero() {
		container.FinishedAt = *pc.FinishedAt
	}

	return container
}

// mapPodmanState maps Podman state string to ContainerState.
func mapPodmanState(state string) ContainerState {
	switch strings.ToLower(state) {
	case "created":
		return StateCreated
	case "running":
		return StateRunning
	case "paused":
		return StatePaused
	case "stopped":
		return StateStopped
	case "exited":
		return StateExited
	case "removing":
		return StateRemoving
	case "restarting":
		return StateRestarting
	case "dead":
		return StateDead
	default:
		return StateCreated
	}
}

// matchFilters checks if a container matches the given filters.
func matchFilters(container *Container, filters map[string][]string) bool {
	if len(filters) == 0 {
		return true
	}

	for key, values := range filters {
		switch key {
		case "label":
			if !matchLabelFilter(container.Labels, values) {
				return false
			}
		case "name":
			if !matchNameFilter(container.Name, values) {
				return false
			}
		case "status":
			if !matchStatusFilter(container.State, values) {
				return false
			}
		}
	}

	return true
}

// matchLabelFilter checks if container labels match the filter values.
func matchLabelFilter(labels map[string]string, values []string) bool {
	for _, v := range values {
		parts := strings.SplitN(v, "=", 2)
		labelKey := parts[0]
		labelValue, hasValue := labels[labelKey]
		if !hasValue {
			return false
		}
		if len(parts) == 2 && labelValue != parts[1] {
			return false
		}
	}
	return true
}

// matchNameFilter checks if container name matches the filter values.
func matchNameFilter(name string, values []string) bool {
	for _, v := range values {
		if strings.Contains(name, v) {
			return true
		}
	}
	return false
}

// matchStatusFilter checks if container status matches the filter values.
func matchStatusFilter(state ContainerState, values []string) bool {
	for _, v := range values {
		if strings.EqualFold(state.String(), v) {
			return true
		}
	}
	return false
}

// GetAttestation returns the container attestor.
func (o *Orchestrator) GetAttestation() *ContainerAttestor {
	return o.attestor
}

// GetMeasurementLog returns the measurement log.
func (o *Orchestrator) GetMeasurementLog() *ThreadSafeMeasurementLog {
	if o.attestor == nil {
		return nil
	}
	return o.attestor.GetMeasurementLog()
}

// IsConnected returns true if the orchestrator is connected and operational.
func (o *Orchestrator) IsConnected() bool {
	return !o.closed.Load() && o.podman != nil
}

// ContainerCount returns the number of containers in the cache.
func (o *Orchestrator) ContainerCount() int {
	count := 0
	o.containers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// String returns a string representation of the orchestrator.
func (o *Orchestrator) String() string {
	return fmt.Sprintf("Orchestrator{attestation=%t, policy=%t, containers=%d}",
		o.config.EnableAttestation,
		o.config.EnablePolicy,
		o.ContainerCount())
}
