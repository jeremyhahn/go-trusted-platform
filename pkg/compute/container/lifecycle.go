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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
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

// PodmanContainerConfig is a container's effective launch configuration: the
// single derivation of everything that reaches the container, produced by
// newLaunchConfig and consumed by both the backend and the measurement
// (AttestationSpec). See launch_config.go for the invariant.
//
// It carries no TPM flag. Exposing the host TPM is a mount of
// HostTPMDevicePath and nothing else, so the grant is part of the measured
// mount list; the backend recognizes it through GrantsTPMDevice.
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

	// Resources are the declared CPU, memory and process limits. They are
	// applied by every launch path — the podman backend and the generated
	// systemd unit or rc script alike — and are deliberately not measured,
	// because a limit bounds what a workload may consume rather than what it
	// runs or what it can reach. See AttestationSpec.
	Resources ResourceConfig
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

// WithImageDigestResolver sets the resolver that turns an image reference
// into its immutable OCI content digest for measurement.
func WithImageDigestResolver(resolver ImageDigestResolver) OrchestratorOption {
	return func(o *Orchestrator) {
		o.digests = resolver
	}
}

// WithLaunchRefusal makes Create and Start refuse every launch with err. It
// is set on a host whose TPM requires measured launches but which has no
// runtime to measure them with: such a host never starts a workload
// unmeasured.
func WithLaunchRefusal(err error) OrchestratorOption {
	return func(o *Orchestrator) {
		o.launchRefusal = err
	}
}

// LaunchRefusal returns the error every launch is refused with, or nil when
// launches are allowed: see WithLaunchRefusal.
func (o *Orchestrator) LaunchRefusal() error {
	return o.launchRefusal
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
	digests      ImageDigestResolver
	policy       LifecyclePolicyEvaluator
	network      LifecycleNetworkManager
	service      *ServiceManager
	imageManager *ImageManager

	// launchRefusal, when set, is returned by every Create and Start: see
	// WithLaunchRefusal.
	launchRefusal error

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

	if o.launchRefusal != nil {
		return nil, o.launchRefusal
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

	// Step 4: Derive the container's effective launch configuration ONCE.
	// This value is what the backend applies and what step 5 measures, so
	// nothing can reach the container without passing through the
	// measurement. See launch_config.go.
	launchConfig := newLaunchConfig(spec)
	podmanContainer, err := o.podman.CreateContainer(ctx, launchConfig)
	if err != nil {
		return nil, NewContainerError("", spec.Name, "podman_create", err)
	}

	// Step 5: Measure the container. When measurement is required the
	// container is measured or it does not survive Create: a container that
	// runs while its measurement was skipped looks, to every downstream
	// verifier, exactly like one that was never approved.
	if o.measurementRequired() {
		if err := o.measureCreate(ctx, podmanContainer.ID, launchConfig); err != nil {
			o.rollbackUnmeasured(ctx, podmanContainer.ID, spec.Name)
			return nil, err
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

// ImageDigestResolver resolves an image reference to its immutable OCI
// content digest, in canonical "sha256:<64 hex>" form.
//
// It is satisfied as-is by *orchestration.ExecContainerRuntime, whose
// ResolveImageDigest reads the image's registry manifest digest and reports
// ImageDigestUnresolvedError for a locally built image that has none — rather
// than substituting a hash of the image reference, which is not the same
// value and is not portable across hosts.
type ImageDigestResolver interface {
	// ResolveImageDigest returns the content digest of image.
	ResolveImageDigest(ctx context.Context, image string) (string, error)
}

// Compile-time proof that the go-quicbaas SDK exec runtime fills the seam.
var _ ImageDigestResolver = (*orchestration.ExecContainerRuntime)(nil)

// measurementRequired reports whether containers must be measured before they
// run. It is a property of the orchestrator's configuration, never of whether
// a measurement happened to fail.
func (o *Orchestrator) measurementRequired() bool {
	return o.config.EnableAttestation && o.attestor != nil
}

// measureCreate resolves the container's image and configuration digests and
// records the creation event, extending the workload PCR.
//
// It measures the effective launch configuration — the very value handed to
// the backend — and takes no OrchestratorContainerSpec, so it cannot measure
// anything other than what the container is about to receive.
//
// Every step returns UnmeasuredLaunchError on failure. None of them logs and
// continues: the whole point of a measurement is that its absence is fatal.
func (o *Orchestrator) measureCreate(ctx context.Context, containerID string, launch *PodmanContainerConfig) error {
	if o.digests == nil {
		return &UnmeasuredLaunchError{
			ContainerID:   containerID,
			ContainerName: launch.Name,
			Stage:         "resolve_image_digest",
			Cause:         ErrImageDigestResolverUnavailable,
		}
	}

	imageDigest, err := o.digests.ResolveImageDigest(ctx, launch.Image)
	if err != nil {
		return &UnmeasuredLaunchError{
			ContainerID:   containerID,
			ContainerName: launch.Name,
			Stage:         "resolve_image_digest",
			Cause:         err,
		}
	}
	if err := orchestration.ValidateImageDigest(imageDigest); err != nil {
		return &UnmeasuredLaunchError{
			ContainerID:   containerID,
			ContainerName: launch.Name,
			Stage:         "resolve_image_digest",
			Cause:         err,
		}
	}

	attestationSpec := launch.AttestationSpec()
	attestationSpec.ImageDigest = imageDigest
	configDigest, err := orchestration.ContainerConfigDigest(attestationSpec)
	if err != nil {
		return &UnmeasuredLaunchError{
			ContainerID:   containerID,
			ContainerName: launch.Name,
			Stage:         "config_digest",
			Cause:         err,
		}
	}

	if err := o.attestor.RecordContainerCreate(ctx, containerID, launch.Name, launch.Image, imageDigest, configDigest); err != nil {
		return &UnmeasuredLaunchError{
			ContainerID:   containerID,
			ContainerName: launch.Name,
			Stage:         "record_create",
			Cause:         err,
		}
	}

	o.logger.Info("measured container",
		"id", containerID, "name", launch.Name,
		"image_digest", imageDigest, "config_digest", configDigest)
	return nil
}

// rollbackUnmeasured removes a container that was created but could not be
// measured, so nothing unmeasured is left behind for a later Start to run.
func (o *Orchestrator) rollbackUnmeasured(ctx context.Context, containerID, name string) {
	if err := o.podman.RemoveContainer(ctx, containerID, true); err != nil {
		o.logger.Error("failed to remove unmeasured container",
			"id", containerID, "name", name, "error", err)
	}
}

// Start starts a stopped container.
func (o *Orchestrator) Start(ctx context.Context, id string) error {
	if o.closed.Load() {
		return ErrOrchestratorClosed
	}

	if o.launchRefusal != nil {
		return o.launchRefusal
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

	// Measure the start event BEFORE the container runs. A measurement
	// taken afterwards is not a measured launch, it is an assertion that
	// something already running was approved.
	if o.measurementRequired() {
		if err := o.attestor.RecordContainerStart(ctx, id, container.Name); err != nil {
			return &UnmeasuredLaunchError{
				ContainerID:   id,
				ContainerName: container.Name,
				Stage:         "record_start",
				Cause:         err,
			}
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

	// Record the stop event. Unlike a launch this is a post-hoc record:
	// the container is already stopped and failing the call cannot un-stop
	// it, so the failure is logged and the log replay fails closed later.
	if o.measurementRequired() {
		if err := o.attestor.RecordContainerStop(ctx, id, container.Name); err != nil {
			o.logger.Error("failed to record container stop", "id", id, "error", err)
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

	// Record the removal event. As with stop, this is a post-hoc record of
	// something that already happened.
	if o.measurementRequired() {
		if err := o.attestor.RecordContainerRemove(ctx, id, container.Name); err != nil {
			o.logger.Error("failed to record container removal", "id", id, "error", err)
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

	// The measurement log replay produces the golden PCR value; the SDK
	// attesting runtime produces the quote and compares the two; the
	// platform's quote verifier binds that quote to this host's IAK.
	measurementLog := o.attestor.GetMeasurementLog()
	result, err := o.attestor.VerifyAttestation(ctx, id, measurementLog)
	if err != nil {
		return nil, NewContainerError(id, container.Name, "attest", err)
	}

	report := &AttestationReport{
		ContainerID:   id,
		ContainerName: container.Name,
		Timestamp:     time.Now(),
		Quote:         result.Evidence.Quoted,
		Signature:     result.Evidence.Signature,
		Log:           measurementLog.ToMeasurementLog(),
		ImageDigest:   result.ImageDigest,
		ConfigDigest:  result.ConfigDigest,
		PCRValues:     pcrValuesByIndex(result.Evidence.PCRs),
		Verified:      result.Verified,
	}

	return report, nil
}

// pcrValuesByIndex converts the SDK's PCR map to the report's index type.
func pcrValuesByIndex(pcrs map[uint32][]byte) map[int][]byte {
	out := make(map[int][]byte, len(pcrs))
	for index, value := range pcrs {
		out[int(index)] = value
	}
	return out
}

// VerifyAttestation verifies a container's attestation.
//
// The evidence argument is accepted for interface compatibility with callers
// that carry an opaque blob; verification is performed against the live host
// TPM and the orchestrator's measurement log, which is the only evidence a
// fleet verifier can trust on this side of the wire.
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

	result, err := o.attestor.VerifyAttestation(ctx, id, o.attestor.GetMeasurementLog())
	if err != nil {
		return err
	}
	if !result.Verified {
		return ErrAttestationFailed
	}
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

// VerifyImage verifies the signature of a container image and reports the
// content digest the verdict applies to.
//
// Without an ImageManager the orchestrator can establish neither the digest nor
// the endorsement, so it returns ErrImageManagerUnavailable. It does not
// synthesize an "unverified" ImageVerification: a result with an empty Digest
// names no artifact, and a caller that stores or forwards it records a verdict
// about nothing.
func (o *Orchestrator) VerifyImage(ctx context.Context, ref string) (*ImageVerification, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if ref == "" {
		return nil, ErrInvalidImage
	}

	if o.imageManager == nil {
		return nil, NewImageError(ref, "", ErrImageManagerUnavailable)
	}

	return o.imageManager.VerifyImage(ctx, ref)
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
