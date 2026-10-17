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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// containerImageModelPrefix is the profile Model prefix used by API layers
// to carry the requested container image inside a DeviceProfile.
const containerImageModelPrefix = "container:image="

// defaultContainerImage is used when neither the device profile nor the
// Podman configuration specify a container image.
const defaultContainerImage = "docker.io/library/alpine:latest"

// managedInstance tracks the compute-level view of a container managed by
// the consolidated orchestrator, including its OVS network attachment state.
type managedInstance struct {
	instance          *compute.Instance
	networkAttached   atomic.Bool
	primaryPortName   atomic.Value // string
	primaryBridgeName atomic.Value // string
}

// ComputeOrchestrator is the production container orchestrator. It presents
// the platform-wide compute.Orchestrator interface (device-profile based
// lifecycle plus OVS networking and 802.1X port authentication) on top of
// the rich container Orchestrator engine, which contributes TPM attestation,
// OPA policy enforcement, image verification, and log access.
//
// The rich capability verbs (Logs, Attest, VerifyAttestation,
// EvaluatePolicy, PullImage, VerifyImage) are exposed directly so API
// layers can reach them through capability type assertions on the
// compute.Orchestrator value.
type ComputeOrchestrator struct {
	config         *compute.OrchestratorConfig
	podmanConfig   *podman.PodmanConfig
	podmanManager  podman.PodmanManager
	logger         *logging.Logger
	engine         *Orchestrator
	tpmProvider    orchestration.HostTPM
	ovsClient      *ovs.Client
	instances      sync.Map // map[string]*managedInstance
	instanceToPort sync.Map // map[string]string
	instanceCount  atomic.Int64
	closed         atomic.Bool
}

// Compile-time proof that ComputeOrchestrator satisfies compute.Orchestrator.
var _ compute.Orchestrator = (*ComputeOrchestrator)(nil)

// ComputeOrchestratorOption configures a ComputeOrchestrator.
type ComputeOrchestratorOption func(*ComputeOrchestrator)

// WithComputePodmanConfig sets the Podman configuration.
func WithComputePodmanConfig(config *podman.PodmanConfig) ComputeOrchestratorOption {
	return func(o *ComputeOrchestrator) {
		o.podmanConfig = config
	}
}

// WithComputePodmanManager sets a custom Podman manager (useful for testing).
func WithComputePodmanManager(manager podman.PodmanManager) ComputeOrchestratorOption {
	return func(o *ComputeOrchestrator) {
		o.podmanManager = manager
	}
}

// WithComputeOVSClient sets a custom OVS client.
func WithComputeOVSClient(client *ovs.Client) ComputeOrchestratorOption {
	return func(o *ComputeOrchestrator) {
		o.ovsClient = client
	}
}

// WithComputeTPMProvider sets the go-quicbaas SDK host TPM used for
// container workload measurement and quote attestation. When set,
// attestation is enabled on the underlying engine.
func WithComputeTPMProvider(provider orchestration.HostTPM) ComputeOrchestratorOption {
	return func(o *ComputeOrchestrator) {
		o.tpmProvider = provider
	}
}

// WithComputeEngine sets a pre-constructed rich Orchestrator engine
// (useful for testing).
func WithComputeEngine(engine *Orchestrator) ComputeOrchestratorOption {
	return func(o *ComputeOrchestrator) {
		o.engine = engine
	}
}

// NewComputeOrchestrator creates the consolidated container orchestrator.
func NewComputeOrchestrator(
	config *compute.OrchestratorConfig,
	logger *logging.Logger,
	opts ...ComputeOrchestratorOption,
) (*ComputeOrchestrator, error) {
	if config == nil {
		return nil, &compute.SentinelCauseError{
			Sentinel: compute.ErrInvalidConfiguration,
			Cause:    &compute.MessageError{Msg: "config is required"},
		}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if config.Type != compute.ComputeTypeContainer {
		return nil, &compute.SentinelCauseError{
			Sentinel: compute.ErrInvalidConfiguration,
			Cause:    &compute.MessageError{Msg: "container orchestrator requires container compute type"},
		}
	}

	o := &ComputeOrchestrator{
		config: config,
		logger: logger,
	}

	for _, opt := range opts {
		opt(o)
	}

	if o.podmanConfig == nil {
		o.podmanConfig = podman.DefaultPodmanConfig()
		o.podmanConfig.MaxContainers = config.MaxInstances
		o.podmanConfig.Debug = config.Debug
	}

	if o.engine == nil {
		if err := o.buildEngine(); err != nil {
			return nil, err
		}
	}

	if o.ovsClient == nil && config.OVSSocketPath != "" {
		ovsClient, err := ovs.NewClient(config.OVSSocketPath)
		if err != nil {
			logger.Warnf("Failed to create OVS client: %v (OVS networking will be unavailable)", err)
		} else {
			o.ovsClient = ovsClient

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := o.ovsClient.Connect(ctx); err != nil {
				logger.Warnf("Failed to connect to OVS: %v (OVS networking will be unavailable)", err)
				o.ovsClient = nil
			}
		}
	}

	return o, nil
}

// buildEngine constructs the rich Orchestrator engine over the embedded
// Podman runtime and, when a TPM provider is configured, the container
// attestor.
func (o *ComputeOrchestrator) buildEngine() error {
	if o.podmanManager == nil {
		manager, err := podman.NewPodmanManager(
			o.podmanConfig.ToManagerConfig(),
			podman.WithManagerLogger(o.logger.Slog()),
		)
		if err != nil {
			return &compute.WrappedError{Msg: "failed to create Podman manager", Err: err}
		}
		o.podmanManager = manager

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := o.podmanManager.Initialize(ctx); err != nil {
			o.logger.Warnf("Failed to initialize Podman: %v (container operations will fail)", err)
		}
	}

	engineOpts := []OrchestratorOption{
		WithPodmanBackend(NewEmbeddedPodmanAdapter(o.podmanManager)),
	}

	var attestor *ContainerAttestor
	if o.tpmProvider != nil {
		// The SDK trust stack supplies image digest resolution (Tier 0)
		// and quote plus golden-PCR comparison (Tier 1). Without it the
		// platform cannot measure a launch, so attestation must not be
		// enabled: a half-configured attestor would report success on
		// containers it never measured.
		//
		// A host with no docker or podman binary gives the trust stack
		// nothing to measure launches with. The orchestrator still starts,
		// so the compute API stays served, but it refuses every launch: a
		// host with a TPM never starts a workload unmeasured. Any other
		// trust-stack failure stays fatal.
		stack, err := NewTrustStack(o.tpmProvider, o.logger.Slog())
		var noRuntime *orchestration.ContainerRuntimeNotAvailableError
		switch {
		case errors.As(err, &noRuntime):
			refusal := &MeasuredRuntimeUnavailableError{Runtimes: MeasuredRuntimes, Cause: err}
			o.logger.Warnf("Container launches refused: %v", refusal)
			engineOpts = append(engineOpts, WithLaunchRefusal(refusal))
		case err != nil:
			return &compute.WrappedError{Msg: "failed to build container trust stack", Err: err}
		default:
			attestor, err = NewContainerAttestor(o.tpmProvider, WithAttestingRuntime(stack.Attesting))
			if err != nil {
				return &compute.WrappedError{Msg: "failed to create container attestor", Err: err}
			}

			engineOpts = append(engineOpts,
				WithAttestor(attestor),
				WithImageDigestResolver(stack.Runtime),
			)
		}
	}

	engine, err := NewOrchestrator(OrchestratorConfig{
		Logger:            o.logger.Slog(),
		EnableAttestation: attestor != nil,
	}, engineOpts...)
	if err != nil {
		return &compute.WrappedError{Msg: "failed to create container orchestrator engine", Err: err}
	}
	o.engine = engine

	return nil
}

// Engine returns the underlying rich container orchestrator engine.
func (o *ComputeOrchestrator) Engine() *Orchestrator {
	return o.engine
}

// generateInstanceSuffix generates a unique container-name suffix so
// multiple instances can be created from the same device profile.
func generateInstanceSuffix() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", &compute.WrappedError{Msg: "failed to generate instance suffix", Err: err}
	}
	return hex.EncodeToString(b), nil
}

// imageFromProfile resolves the container image for a device profile. API
// layers carry the requested image in the profile Model as
// "container:image=<ref>"; otherwise the configured default image is used.
func (o *ComputeOrchestrator) imageFromProfile(profile *entities.DeviceProfile) string {
	if idx := strings.Index(profile.Model, containerImageModelPrefix); idx >= 0 {
		ref := profile.Model[idx+len(containerImageModelPrefix):]
		// The Model may carry additional comma-separated attributes.
		if comma := strings.Index(ref, ","); comma >= 0 {
			ref = ref[:comma]
		}
		if ref != "" {
			return ref
		}
	}
	if o.podmanConfig.DefaultImage != "" {
		return o.podmanConfig.DefaultImage
	}
	return defaultContainerImage
}

// buildContainerSpec builds a container specification from a device profile.
func (o *ComputeOrchestrator) buildContainerSpec(profile *entities.DeviceProfile, suffix string) *OrchestratorContainerSpec {
	spec := &OrchestratorContainerSpec{
		Name:  fmt.Sprintf("%s-%s", profile.Name, suffix),
		Image: o.imageFromProfile(profile),
		Env:   make(map[string]string),
		Labels: map[string]string{
			"trusted-platform.profile-name": profile.Name,
			"trusted-platform.profile-id":   strconv.FormatUint(profile.ID, 10),
			"trusted-platform.device-role":  profile.Role.String(),
		},
		TPMAccess: o.podmanConfig.EnableTPMAccess,
	}

	if profile.PlatformdConfig != nil {
		spec.Env["PLATFORMD_PROFILE"] = profile.Name
	}

	return spec
}

// mapEngineError translates rich engine errors onto the compute package's
// sentinel errors so callers of the compute.Orchestrator interface observe
// the documented error contract.
func mapEngineError(op string, err error) error {
	switch {
	case errors.Is(err, ErrContainerNotFound):
		return compute.ErrInstanceNotFound
	case errors.Is(err, ErrContainerExists):
		return compute.ErrInstanceAlreadyExists
	case errors.Is(err, ErrContainerRunning):
		return compute.ErrInstanceAlreadyRunning
	case errors.Is(err, ErrContainerStopped):
		return compute.ErrInstanceNotRunning
	case errors.Is(err, ErrOrchestratorClosed):
		return compute.ErrOrchestratorNotInitialized
	default:
		return &compute.WrappedError{Msg: "failed to " + op + " container", Err: err}
	}
}

// mapEngineState maps a rich engine container state to a compute instance
// state.
var engineStateToInstanceState = map[ContainerState]compute.InstanceState{
	StateCreated:    compute.StateStopped,
	StateRunning:    compute.StateRunning,
	StatePaused:     compute.StateRunning,
	StateRestarting: compute.StateStarting,
	StateStopped:    compute.StateStopped,
	StateExited:     compute.StateStopped,
	StateRemoving:   compute.StateDeleting,
	StateDead:       compute.StateError,
}

func mapEngineState(state ContainerState) compute.InstanceState {
	if mapped, ok := engineStateToInstanceState[state]; ok {
		return mapped
	}
	return compute.StateUnknown
}

// Create creates a new container instance from a device profile. The rich
// engine performs OPA policy evaluation, image pull, and TPM workload
// measurement as part of creation.
func (o *ComputeOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if o.closed.Load() {
		return nil, compute.ErrOrchestratorNotInitialized
	}

	if profile == nil {
		return nil, compute.ErrInvalidProfile
	}

	if o.instanceCount.Load() >= int64(o.config.MaxInstances) {
		return nil, compute.ErrResourceExhausted
	}

	suffix, err := generateInstanceSuffix()
	if err != nil {
		return nil, err
	}

	spec := o.buildContainerSpec(profile, suffix)

	created, err := o.engine.Create(ctx, spec)
	if err != nil {
		return nil, mapEngineError("create", err)
	}

	instance := &compute.Instance{
		ID:      created.ID,
		Name:    profile.Name,
		Type:    compute.ComputeTypeContainer,
		State:   compute.StateStopped,
		Profile: profile,
		Config: &compute.InstanceConfig{
			Memory:      o.config.DefaultMemory,
			CPUs:        o.config.DefaultCPUs,
			WorkDir:     o.podmanConfig.StorageRoot,
			NetworkMode: o.podmanConfig.DefaultNetworkMode,
			Environment: spec.Env,
		},
		NetworkAttachments: []compute.NetworkAttachment{},
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Metadata: map[string]string{
			"container_id":   created.ID,
			"container_name": spec.Name,
			"image":          spec.Image,
		},
	}

	managed := &managedInstance{instance: instance}
	managed.primaryPortName.Store("")
	managed.primaryBridgeName.Store("")

	o.instances.Store(instance.ID, managed)
	o.instanceCount.Add(1)

	o.logger.Infof("Created container instance: %s (container: %s, profile: %s)",
		instance.ID, spec.Name, profile.Name)

	return instance, nil
}

// loadManaged retrieves a managed instance by ID, validating the request.
func (o *ComputeOrchestrator) loadManaged(instanceID string) (*managedInstance, error) {
	if o.closed.Load() {
		return nil, compute.ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return nil, compute.ErrInstanceNotFound
	}
	return value.(*managedInstance), nil
}

// refreshInstance synchronizes the compute-level instance view with the
// rich engine's container state.
func (o *ComputeOrchestrator) refreshInstance(ctx context.Context, managed *managedInstance) {
	engineContainer, err := o.engine.Get(ctx, managed.instance.ID)
	if err != nil {
		return
	}
	managed.instance.State = mapEngineState(engineContainer.State)
	managed.instance.PID = engineContainer.Pid
}

// Start starts a stopped container instance.
func (o *ComputeOrchestrator) Start(ctx context.Context, instanceID string) error {
	managed, err := o.loadManaged(instanceID)
	if err != nil {
		return err
	}

	if err := o.engine.Start(ctx, instanceID); err != nil {
		return mapEngineError("start", err)
	}

	o.refreshInstance(ctx, managed)
	managed.instance.State = compute.StateRunning
	managed.instance.UpdatedAt = time.Now()

	o.logger.Infof("Started container instance: %s (PID: %d)", instanceID, managed.instance.PID)

	return nil
}

// Stop stops a running container instance.
func (o *ComputeOrchestrator) Stop(ctx context.Context, instanceID string) error {
	managed, err := o.loadManaged(instanceID)
	if err != nil {
		return err
	}

	if err := o.engine.Stop(ctx, instanceID, 0); err != nil {
		return mapEngineError("stop", err)
	}

	managed.instance.State = compute.StateStopped
	managed.instance.PID = 0
	managed.instance.UpdatedAt = time.Now()

	o.logger.Infof("Stopped container instance: %s", instanceID)

	return nil
}

// Delete deletes a container instance and cleans up its network resources.
func (o *ComputeOrchestrator) Delete(ctx context.Context, instanceID string) error {
	managed, err := o.loadManaged(instanceID)
	if err != nil {
		return err
	}

	// Remove port authentication if enabled.
	portName, _ := managed.primaryPortName.Load().(string)
	bridgeName, _ := managed.primaryBridgeName.Load().(string)
	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil && portName != "" {
		authConfig := &compute.PortAuthConfig{
			PortID:       portName,
			BridgeName:   bridgeName,
			PolicyEngine: o.config.PolicyEngine,
		}
		if err := compute.RemovePortAuth(authConfig); err != nil {
			o.logger.Warnf("Failed to remove port authentication for instance %s: %v", instanceID, err)
		}
	}

	// Force removal handles running containers (stop + remove) and records
	// the removal in the measurement log when attestation is enabled.
	if err := o.engine.Remove(ctx, instanceID, true); err != nil {
		return mapEngineError("delete", err)
	}

	o.instanceToPort.Delete(instanceID)
	o.instances.Delete(instanceID)
	o.instanceCount.Add(-1)

	o.logger.Infof("Deleted container instance: %s", instanceID)

	return nil
}

// List returns all container instances, optionally filtered.
func (o *ComputeOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	if o.closed.Load() {
		return nil, compute.ErrOrchestratorNotInitialized
	}

	result := make([]*compute.Instance, 0)

	o.instances.Range(func(key, value interface{}) bool {
		managed := value.(*managedInstance)
		o.refreshInstance(ctx, managed)

		if filter != nil && !filter.Matches(managed.instance) {
			return true
		}

		instanceCopy := *managed.instance
		result = append(result, &instanceCopy)
		return true
	})

	return result, nil
}

// Get retrieves a specific container instance by ID.
func (o *ComputeOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	managed, err := o.loadManaged(instanceID)
	if err != nil {
		return nil, err
	}

	o.refreshInstance(ctx, managed)

	instanceCopy := *managed.instance
	return &instanceCopy, nil
}

// AttachNetwork attaches a container instance to an OVS network port. When
// port authentication is enabled, the port is placed in provisioning state
// until the instance is activated.
func (o *ComputeOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if o.closed.Load() {
		return compute.ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}

	if portName == "" {
		return &compute.SentinelCauseError{
			Sentinel: compute.ErrNetworkAttachmentFailed,
			Cause:    &compute.MessageError{Msg: "port name is required"},
		}
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return compute.ErrInstanceNotFound
	}
	managed := value.(*managedInstance)

	if o.ovsClient == nil {
		return &compute.SentinelCauseError{
			Sentinel: compute.ErrNetworkAttachmentFailed,
			Cause:    &compute.MessageError{Msg: "OVS client not available"},
		}
	}

	if managed.networkAttached.Load() {
		return &compute.SentinelCauseError{
			Sentinel: compute.ErrNetworkAttachmentFailed,
			Cause:    &compute.MessageError{Msg: "network already attached"},
		}
	}

	// Container network attachment tracks the OVS port association; the
	// veth/netns plumbing is performed by the SDN layer.
	managed.networkAttached.Store(true)
	managed.primaryPortName.Store(portName)
	managed.primaryBridgeName.Store(o.config.NetworkBridge)

	attachment := compute.NetworkAttachment{
		PortName:   portName,
		BridgeName: o.config.NetworkBridge,
		AttachedAt: time.Now(),
	}
	managed.instance.NetworkAttachments = append(managed.instance.NetworkAttachments, attachment)
	managed.instance.UpdatedAt = time.Now()

	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil {
		macAddr := ""
		if managed.instance.Config != nil {
			macAddr = managed.instance.Config.MACAddress
		}

		authConfig := &compute.PortAuthConfig{
			PortID:       portName,
			BridgeName:   o.config.NetworkBridge,
			MACAddress:   macAddr,
			PolicyEngine: o.config.PolicyEngine,
		}

		if err := compute.SetProvisioningState(authConfig); err != nil {
			// Roll back the attachment on failure.
			managed.networkAttached.Store(false)
			managed.primaryPortName.Store("")
			managed.primaryBridgeName.Store("")
			managed.instance.NetworkAttachments = managed.instance.NetworkAttachments[:len(managed.instance.NetworkAttachments)-1]
			return &compute.SentinelCauseError{
				Sentinel: compute.ErrNetworkAttachmentFailed,
				Cause:    &compute.MessageError{Msg: fmt.Sprintf("failed to set provisioning state: %v", err)},
			}
		}

		o.instanceToPort.Store(instanceID, portName)

		o.logger.Infof("Attached network port %s to container instance %s with provisioning state", portName, instanceID)
	} else {
		o.logger.Infof("Attached network port %s to container instance %s", portName, instanceID)
	}

	return nil
}

// DetachNetwork detaches a container instance from an OVS network port.
func (o *ComputeOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if o.closed.Load() {
		return compute.ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}

	if portName == "" {
		return &compute.SentinelCauseError{
			Sentinel: compute.ErrNetworkDetachmentFailed,
			Cause:    &compute.MessageError{Msg: "port name is required"},
		}
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return compute.ErrInstanceNotFound
	}
	managed := value.(*managedInstance)

	if !managed.networkAttached.Load() {
		return &compute.SentinelCauseError{
			Sentinel: compute.ErrNetworkDetachmentFailed,
			Cause:    &compute.MessageError{Msg: "no network attached"},
		}
	}

	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil {
		authConfig := &compute.PortAuthConfig{
			PortID:       portName,
			BridgeName:   o.config.NetworkBridge,
			PolicyEngine: o.config.PolicyEngine,
		}
		if err := compute.RemovePortAuth(authConfig); err != nil {
			o.logger.Warnf("Failed to remove port authentication: %v", err)
		}
	}

	managed.networkAttached.Store(false)
	managed.primaryPortName.Store("")
	managed.primaryBridgeName.Store("")

	newAttachments := make([]compute.NetworkAttachment, 0)
	for _, att := range managed.instance.NetworkAttachments {
		if att.PortName != portName {
			newAttachments = append(newAttachments, att)
		}
	}
	managed.instance.NetworkAttachments = newAttachments
	managed.instance.UpdatedAt = time.Now()

	o.instanceToPort.Delete(instanceID)

	o.logger.Infof("Detached network port %s from container instance %s", portName, instanceID)

	return nil
}

// ActivateInstance transitions an instance's network port from enrolled to
// authorized, applying the full production policy with tenant-specific VLAN
// and ACLs.
func (o *ComputeOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	if o.closed.Load() {
		return compute.ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}

	if portPolicy == nil {
		return &compute.MessageError{Msg: "port policy is required"}
	}

	if !o.config.PortAuthEnabled || o.config.PolicyEngine == nil {
		return &compute.MessageError{Msg: "port authentication is not enabled"}
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return compute.ErrInstanceNotFound
	}
	managed := value.(*managedInstance)

	portNameValue, hasMappedPort := o.instanceToPort.Load(instanceID)
	if !hasMappedPort {
		return &compute.MessageError{Msg: fmt.Sprintf("no network port mapped for instance %s", instanceID)}
	}
	portName := portNameValue.(string)
	if portName == "" {
		return &compute.MessageError{Msg: fmt.Sprintf("no network port mapped for instance %s", instanceID)}
	}

	if !managed.networkAttached.Load() {
		return &compute.MessageError{Msg: fmt.Sprintf("no network attached to instance %s", instanceID)}
	}

	macAddr := ""
	if managed.instance.Config != nil {
		macAddr = managed.instance.Config.MACAddress
	}

	authConfig := &compute.PortAuthConfig{
		PortID:       portName,
		BridgeName:   o.config.NetworkBridge,
		MACAddress:   macAddr,
		PolicyEngine: o.config.PolicyEngine,
	}

	if err := compute.ActivatePort(authConfig, portPolicy); err != nil {
		return &compute.WrappedError{Msg: "failed to activate instance network port", Err: err}
	}

	managed.instance.Metadata["port_state"] = "authorized"
	managed.instance.Metadata["vlan"] = fmt.Sprintf("%d", portPolicy.VLAN)
	managed.instance.UpdatedAt = time.Now()

	o.logger.Infof("Activated container instance %s on port %s with VLAN %d", instanceID, portName, portPolicy.VLAN)

	return nil
}

// Wait blocks until a container instance exits.
func (o *ComputeOrchestrator) Wait(ctx context.Context, instanceID string) error {
	managed, err := o.loadManaged(instanceID)
	if err != nil {
		return err
	}

	exitCode, err := o.engine.Wait(ctx, instanceID)
	if err != nil {
		return mapEngineError("wait for", err)
	}

	managed.instance.State = compute.StateStopped
	managed.instance.PID = 0
	managed.instance.UpdatedAt = time.Now()
	managed.instance.Metadata["exit_code"] = strconv.Itoa(exitCode)

	o.logger.Infof("Container instance %s exited with code %d", instanceID, exitCode)

	return nil
}

// GetState returns the current state of a container instance.
func (o *ComputeOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	managed, err := o.loadManaged(instanceID)
	if err != nil {
		return compute.StateUnknown, err
	}

	engineContainer, err := o.engine.Get(ctx, instanceID)
	if err != nil {
		return managed.instance.State, nil
	}

	return mapEngineState(engineContainer.State), nil
}

// Close closes the orchestrator, stopping running containers and releasing
// the engine and OVS resources.
func (o *ComputeOrchestrator) Close() error {
	if o.closed.Swap(true) {
		return nil
	}

	o.instances.Range(func(key, value interface{}) bool {
		instanceID := key.(string)
		managed := value.(*managedInstance)

		if managed.instance.State == compute.StateRunning {
			o.logger.Infof("Stopping container instance %s during shutdown", instanceID)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := o.engine.Stop(ctx, instanceID, 0); err != nil {
				o.logger.Errorf("Failed to stop container instance %s: %v", instanceID, err)
			}
			cancel()
		}
		return true
	})

	// engine.Close persists the measurement log (when configured) and
	// closes the attestor and Podman backend.
	if o.engine != nil {
		if err := o.engine.Close(); err != nil {
			o.logger.Warnf("Failed to close container orchestrator engine: %v", err)
		}
	}

	if o.ovsClient != nil {
		if err := o.ovsClient.Close(); err != nil {
			o.logger.Warnf("Failed to close OVS client: %v", err)
		}
	}

	o.logger.Info("Container orchestrator closed")

	return nil
}

// =============================================================================
// Rich capability verbs (forwarded to the engine)
// =============================================================================

// Logs returns a stream of container logs.
func (o *ComputeOrchestrator) Logs(ctx context.Context, instanceID string, opts LogOptions) (io.ReadCloser, error) {
	if _, err := o.loadManaged(instanceID); err != nil {
		return nil, err
	}
	return o.engine.Logs(ctx, instanceID, opts)
}

// Attest performs quote-based TPM attestation for a container instance.
func (o *ComputeOrchestrator) Attest(ctx context.Context, instanceID string) (*AttestationReport, error) {
	if _, err := o.loadManaged(instanceID); err != nil {
		return nil, err
	}
	return o.engine.Attest(ctx, instanceID)
}

// VerifyAttestation verifies attestation evidence for a container instance.
func (o *ComputeOrchestrator) VerifyAttestation(ctx context.Context, instanceID string, evidence []byte) error {
	if _, err := o.loadManaged(instanceID); err != nil {
		return err
	}
	return o.engine.VerifyAttestation(ctx, instanceID, evidence)
}

// EvaluatePolicy evaluates OPA policies against a container specification
// and returns a structured policy decision.
func (o *ComputeOrchestrator) EvaluatePolicy(ctx context.Context, spec *OrchestratorContainerSpec) (*PolicyDecision, error) {
	if o.closed.Load() {
		return nil, compute.ErrOrchestratorNotInitialized
	}

	allowed, reasons, err := o.engine.EvaluatePolicy(ctx, spec)
	if err != nil {
		return nil, err
	}

	return &PolicyDecision{
		Allowed:   allowed,
		Reasons:   reasons,
		Timestamp: time.Now(),
	}, nil
}

// PullImage pulls a container image from a registry.
func (o *ComputeOrchestrator) PullImage(ctx context.Context, ref string, opts PullOptions) error {
	if o.closed.Load() {
		return compute.ErrOrchestratorNotInitialized
	}
	return o.engine.PullImage(ctx, ref, opts)
}

// VerifyImage verifies the signature of a container image.
func (o *ComputeOrchestrator) VerifyImage(ctx context.Context, ref string) (*ImageVerification, error) {
	if o.closed.Load() {
		return nil, compute.ErrOrchestratorNotInitialized
	}
	return o.engine.VerifyImage(ctx, ref)
}
