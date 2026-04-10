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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// containerInstance holds the container instance and its metadata
type containerInstance struct {
	containerID       string
	instance          *Instance
	networkAttached   atomic.Bool
	primaryPortName   atomic.Value // string
	primaryBridgeName atomic.Value // string
}

// ContainerOrchestrator implements the Orchestrator interface for Podman containers
type ContainerOrchestrator struct {
	config         *OrchestratorConfig
	podmanConfig   *podman.PodmanConfig
	logger         *logging.Logger
	lifecycle      *LifecycleManager
	podmanManager  podman.PodmanManager
	ovsClient      *ovs.Client
	instances      sync.Map // map[string]*containerInstance - lock-free container tracking
	instanceToPort sync.Map // map[string]string - Maps instance ID to primary port name
	instanceCount  atomic.Int64
	closed         atomic.Bool
}

// ContainerOrchestratorOption configures a ContainerOrchestrator
type ContainerOrchestratorOption func(*ContainerOrchestrator)

// WithContainerPodmanConfig sets the Podman configuration
func WithContainerPodmanConfig(config *podman.PodmanConfig) ContainerOrchestratorOption {
	return func(o *ContainerOrchestrator) {
		o.podmanConfig = config
	}
}

// WithContainerPodmanManager sets a custom Podman manager (useful for testing)
func WithContainerPodmanManager(manager podman.PodmanManager) ContainerOrchestratorOption {
	return func(o *ContainerOrchestrator) {
		o.podmanManager = manager
	}
}

// WithContainerOVSClient sets a custom OVS client
func WithContainerOVSClient(client *ovs.Client) ContainerOrchestratorOption {
	return func(o *ContainerOrchestrator) {
		o.ovsClient = client
	}
}

// NewContainerOrchestrator creates a new container orchestrator
func NewContainerOrchestrator(
	config *OrchestratorConfig,
	logger *logging.Logger,
	opts ...ContainerOrchestratorOption,
) (*ContainerOrchestrator, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is required", ErrInvalidConfiguration)
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if config.Type != ComputeTypeContainer {
		return nil, fmt.Errorf("%w: Container orchestrator requires container compute type", ErrInvalidConfiguration)
	}

	o := &ContainerOrchestrator{
		config:    config,
		logger:    logger,
		lifecycle: NewLifecycleManager(),
	}

	// Apply options
	for _, opt := range opts {
		opt(o)
	}

	// Create Podman config if not provided
	if o.podmanConfig == nil {
		o.podmanConfig = podman.DefaultPodmanConfig()
		o.podmanConfig.MaxContainers = config.MaxInstances
		o.podmanConfig.Debug = config.Debug
	}

	// Create Podman manager if not provided
	if o.podmanManager == nil {
		manager, err := podman.NewPodmanManager(
			o.podmanConfig.ToManagerConfig(),
			podman.WithManagerLogger(logger.Slog()),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create Podman manager: %w", err)
		}
		o.podmanManager = manager

		// Initialize the embedded runtime
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := o.podmanManager.Initialize(ctx); err != nil {
			logger.Warnf("Failed to initialize Podman: %v (container operations will fail)", err)
		}
	}

	// Create OVS client if not provided
	if o.ovsClient == nil && config.OVSSocketPath != "" {
		ovsClient, err := ovs.NewClient(config.OVSSocketPath)
		if err != nil {
			logger.Warnf("Failed to create OVS client: %v (OVS networking will be unavailable)", err)
		} else {
			o.ovsClient = ovsClient

			// Connect to OVS
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

// generateContainerInstanceID generates a unique instance ID using crypto/rand
func generateContainerInstanceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate instance ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Create creates a new container instance from a device profile
func (o *ContainerOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*Instance, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorNotInitialized
	}

	if profile == nil {
		return nil, ErrInvalidProfile
	}

	// Check instance limit
	if o.instanceCount.Load() >= int64(o.config.MaxInstances) {
		return nil, ErrResourceExhausted
	}

	// Generate unique instance ID
	instanceID, err := generateContainerInstanceID()
	if err != nil {
		return nil, err
	}

	// Check if already exists
	if _, exists := o.instances.Load(instanceID); exists {
		return nil, ErrInstanceAlreadyExists
	}

	// Set initial state
	if err := o.lifecycle.SetState(instanceID, StateCreating); err != nil {
		return nil, err
	}

	// Build container configuration from device profile
	containerConfig, err := o.buildContainerConfig(profile, instanceID)
	if err != nil {
		if sErr := o.lifecycle.SetState(instanceID, StateError); sErr != nil {
			o.logger.Warn("failed to set error state", "instanceID", instanceID, "error", sErr)
		}
		return nil, fmt.Errorf("failed to build container config: %w", err)
	}

	// Create container via Podman
	container, err := o.podmanManager.CreateContainer(ctx, containerConfig)
	if err != nil {
		if sErr := o.lifecycle.SetState(instanceID, StateError); sErr != nil {
			o.logger.Warn("failed to set error state", "instanceID", instanceID, "error", sErr)
		}
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Create instance configuration
	instanceConfig := &InstanceConfig{
		Memory:      o.config.DefaultMemory,
		CPUs:        o.config.DefaultCPUs,
		WorkDir:     o.podmanConfig.StorageRoot,
		NetworkMode: containerConfig.NetworkMode,
		Environment: containerConfig.Environment,
	}

	// Create instance metadata
	instance := &Instance{
		ID:                 instanceID,
		Name:               profile.Name,
		Type:               ComputeTypeContainer,
		State:              StateCreating,
		Profile:            profile,
		Config:             instanceConfig,
		NetworkAttachments: []NetworkAttachment{},
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Metadata:           make(map[string]string),
	}

	// Store container ID in metadata
	instance.Metadata["container_id"] = container.ID
	instance.Metadata["container_name"] = container.Name
	instance.Metadata["image"] = container.Image

	// Create container instance wrapper
	contInst := &containerInstance{
		containerID: container.ID,
		instance:    instance,
	}
	contInst.primaryPortName.Store("")
	contInst.primaryBridgeName.Store("")

	// Store instance
	o.instances.Store(instanceID, contInst)
	o.instanceCount.Add(1)

	// Update state to stopped
	if err := o.lifecycle.SetState(instanceID, StateStopped); err != nil {
		o.instances.Delete(instanceID)
		o.instanceCount.Add(-1)
		return nil, err
	}
	instance.State = StateStopped
	instance.UpdatedAt = time.Now()

	o.logger.Infof("Created container instance: %s (container: %s, profile: %s)", instanceID, container.ID[:12], profile.Name)

	return instance, nil
}

// buildContainerConfig builds a Podman container configuration from a device profile
func (o *ContainerOrchestrator) buildContainerConfig(profile *entities.DeviceProfile, instanceID string) (*podman.ContainerConfig, error) {
	// Determine container image
	image := o.podmanConfig.DefaultImage
	if image == "" {
		// Use a default trusted platform image if not configured
		image = "docker.io/library/alpine:latest"
	}

	// Build container name from profile name and instance ID suffix
	containerName := fmt.Sprintf("%s-%s", profile.Name, instanceID[:8])

	config := &podman.ContainerConfig{
		Name:        containerName,
		Image:       image,
		NetworkMode: o.podmanConfig.DefaultNetworkMode,
		Environment: make(map[string]string),
		Labels:      make(map[string]string),
	}

	// Add standard labels
	config.Labels["trusted-platform.instance-id"] = instanceID
	config.Labels["trusted-platform.profile-name"] = profile.Name
	config.Labels["trusted-platform.profile-id"] = fmt.Sprintf("%d", profile.ID)
	config.Labels["trusted-platform.device-role"] = profile.Role.String()

	// Add environment variables from profile
	if profile.PlatformdConfig != nil {
		config.Environment["PLATFORMD_PROFILE"] = profile.Name
	}

	// Enable TPM access if configured
	if o.podmanConfig.EnableTPMAccess {
		config.TPMAccess = true
		config.Mounts = append(config.Mounts, podman.Mount{
			Source:   "/dev/tpm0",
			Target:   "/dev/tpm0",
			Type:     "bind",
			ReadOnly: false,
		})
	}

	return config, nil
}

// Start starts a stopped container instance
func (o *ContainerOrchestrator) Start(ctx context.Context, instanceID string) error {
	if o.closed.Load() {
		return ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	// Check current state
	currentState, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return err
	}

	if currentState == StateRunning {
		return ErrInstanceAlreadyRunning
	}

	if currentState != StateStopped {
		return fmt.Errorf("%w: cannot start instance in state %s", ErrInvalidState, currentState)
	}

	// Update state to starting
	if err := o.lifecycle.SetState(instanceID, StateStarting); err != nil {
		return err
	}
	contInst.instance.State = StateStarting
	contInst.instance.UpdatedAt = time.Now()

	// Start container via Podman
	if err := o.podmanManager.StartContainer(ctx, contInst.containerID); err != nil {
		if sErr := o.lifecycle.SetState(instanceID, StateError); sErr != nil {
			o.logger.Warn("failed to set error state", "instanceID", instanceID, "error", sErr)
		}
		contInst.instance.State = StateError
		contInst.instance.UpdatedAt = time.Now()
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Get updated container info for PID
	container, err := o.podmanManager.InspectContainer(ctx, contInst.containerID)
	if err != nil {
		o.logger.Warnf("Failed to inspect container after start: %v", err)
	} else {
		contInst.instance.PID = container.PID
	}

	// Update state to running
	if err := o.lifecycle.SetState(instanceID, StateRunning); err != nil {
		// Container is running but state update failed - try to stop it
		o.podmanManager.StopContainer(ctx, contInst.containerID, nil)
		return err
	}
	contInst.instance.State = StateRunning
	contInst.instance.UpdatedAt = time.Now()

	o.logger.Infof("Started container instance: %s (PID: %d)", instanceID, contInst.instance.PID)

	return nil
}

// Stop stops a running container instance
func (o *ContainerOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if o.closed.Load() {
		return ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	// Check current state
	currentState, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return err
	}

	if currentState != StateRunning {
		return ErrInstanceNotRunning
	}

	// Update state to stopping
	if err := o.lifecycle.SetState(instanceID, StateStopping); err != nil {
		return err
	}
	contInst.instance.State = StateStopping
	contInst.instance.UpdatedAt = time.Now()

	// Stop container via Podman
	if err := o.podmanManager.StopContainer(ctx, contInst.containerID, nil); err != nil {
		if sErr := o.lifecycle.SetState(instanceID, StateError); sErr != nil {
			o.logger.Warn("failed to set error state", "instanceID", instanceID, "error", sErr)
		}
		contInst.instance.State = StateError
		contInst.instance.UpdatedAt = time.Now()
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// Update state to stopped
	if err := o.lifecycle.SetState(instanceID, StateStopped); err != nil {
		return err
	}
	contInst.instance.State = StateStopped
	contInst.instance.UpdatedAt = time.Now()
	contInst.instance.PID = 0

	o.logger.Infof("Stopped container instance: %s", instanceID)

	return nil
}

// Delete deletes a container instance and cleans up resources
func (o *ContainerOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if o.closed.Load() {
		return ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	// Check current state
	currentState, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return err
	}

	// Stop if running
	if currentState == StateRunning {
		if err := o.Stop(ctx, instanceID); err != nil {
			return err
		}
	}

	// Update state to deleting
	if err := o.lifecycle.SetState(instanceID, StateDeleting); err != nil {
		return err
	}
	contInst.instance.State = StateDeleting
	contInst.instance.UpdatedAt = time.Now()

	// Remove port authentication if enabled
	portName := contInst.primaryPortName.Load().(string)
	bridgeName := contInst.primaryBridgeName.Load().(string)
	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil && portName != "" {
		authConfig := &PortAuthConfig{
			PortID:       portName,
			BridgeName:   bridgeName,
			PolicyEngine: o.config.PolicyEngine,
		}
		if err := RemovePortAuth(authConfig); err != nil {
			o.logger.Warnf("Failed to remove port authentication for instance %s: %v", instanceID, err)
		}
	}

	// Remove container via Podman (force remove to handle any state)
	if err := o.podmanManager.RemoveContainer(ctx, contInst.containerID, true); err != nil {
		o.logger.Warnf("Failed to remove container %s: %v", contInst.containerID, err)
	}

	// Remove from lifecycle manager
	if err := o.lifecycle.DeleteInstance(instanceID); err != nil {
		o.logger.Warnf("Failed to remove instance from lifecycle manager: %v", err)
	}

	// Remove from instance-to-port mapping
	o.instanceToPort.Delete(instanceID)

	// Remove from instances map
	o.instances.Delete(instanceID)
	o.instanceCount.Add(-1)

	o.logger.Infof("Deleted container instance: %s", instanceID)

	return nil
}

// List returns all container instances, optionally filtered
func (o *ContainerOrchestrator) List(ctx context.Context, filter *InstanceFilter) ([]*Instance, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorNotInitialized
	}

	result := make([]*Instance, 0)

	o.instances.Range(func(key, value interface{}) bool {
		contInst := value.(*containerInstance)
		instance := contInst.instance

		// Apply filter if provided
		if filter != nil && !filter.Matches(instance) {
			return true // continue iteration
		}

		// Create a copy to avoid external modifications
		instanceCopy := *instance
		result = append(result, &instanceCopy)
		return true
	})

	return result, nil
}

// Get retrieves a specific container instance by ID
func (o *ContainerOrchestrator) Get(ctx context.Context, instanceID string) (*Instance, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return nil, ErrInvalidInstanceID
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return nil, ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	// Return a copy
	instanceCopy := *contInst.instance
	return &instanceCopy, nil
}

// AttachNetwork attaches a container instance to an OVS network port
// When port authentication is enabled, the port is set to provisioning state
func (o *ContainerOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if o.closed.Load() {
		return ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if portName == "" {
		return fmt.Errorf("%w: port name is required", ErrNetworkAttachmentFailed)
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	if o.ovsClient == nil {
		return fmt.Errorf("%w: OVS client not available", ErrNetworkAttachmentFailed)
	}

	// Check if already attached
	if contInst.networkAttached.Load() {
		return fmt.Errorf("%w: network already attached", ErrNetworkAttachmentFailed)
	}

	// For containers, network attachment typically involves:
	// 1. Creating a veth pair
	// 2. Moving one end into the container namespace
	// 3. Attaching the other end to the OVS bridge
	// This is a simplified implementation that tracks the attachment
	// Real implementation would use netns and veth manipulation

	// Update instance
	contInst.networkAttached.Store(true)
	contInst.primaryPortName.Store(portName)
	contInst.primaryBridgeName.Store(o.config.NetworkBridge)

	// Add network attachment to instance metadata
	attachment := NetworkAttachment{
		PortName:   portName,
		BridgeName: o.config.NetworkBridge,
		AttachedAt: time.Now(),
	}
	contInst.instance.NetworkAttachments = append(contInst.instance.NetworkAttachments, attachment)
	contInst.instance.UpdatedAt = time.Now()

	// If port authentication is enabled, set port to provisioning state
	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil {
		// Extract MAC address from instance config if available
		macAddr := contInst.instance.Config.MACAddress

		authConfig := &PortAuthConfig{
			PortID:       portName,
			BridgeName:   o.config.NetworkBridge,
			MACAddress:   macAddr,
			PolicyEngine: o.config.PolicyEngine,
		}

		if err := SetProvisioningState(authConfig); err != nil {
			// Cleanup on failure
			contInst.networkAttached.Store(false)
			contInst.primaryPortName.Store("")
			contInst.primaryBridgeName.Store("")
			contInst.instance.NetworkAttachments = contInst.instance.NetworkAttachments[:len(contInst.instance.NetworkAttachments)-1]
			return fmt.Errorf("%w: failed to set provisioning state: %v", ErrNetworkAttachmentFailed, err)
		}

		// Store instance-to-port mapping for activation lookup
		o.instanceToPort.Store(instanceID, portName)

		o.logger.Infof("Attached network port %s to container instance %s with provisioning state", portName, instanceID)
	} else {
		o.logger.Infof("Attached network port %s to container instance %s", portName, instanceID)
	}

	return nil
}

// DetachNetwork detaches a container instance from an OVS network port
func (o *ContainerOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if o.closed.Load() {
		return ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if portName == "" {
		return fmt.Errorf("%w: port name is required", ErrNetworkDetachmentFailed)
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	if !contInst.networkAttached.Load() {
		return fmt.Errorf("%w: no network attached", ErrNetworkDetachmentFailed)
	}

	// Remove port authentication if enabled
	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil {
		authConfig := &PortAuthConfig{
			PortID:       portName,
			BridgeName:   o.config.NetworkBridge,
			PolicyEngine: o.config.PolicyEngine,
		}
		if err := RemovePortAuth(authConfig); err != nil {
			o.logger.Warnf("Failed to remove port authentication: %v", err)
		}
	}

	// Update instance
	contInst.networkAttached.Store(false)
	contInst.primaryPortName.Store("")
	contInst.primaryBridgeName.Store("")

	// Remove network attachment from instance metadata
	newAttachments := make([]NetworkAttachment, 0)
	for _, att := range contInst.instance.NetworkAttachments {
		if att.PortName != portName {
			newAttachments = append(newAttachments, att)
		}
	}
	contInst.instance.NetworkAttachments = newAttachments
	contInst.instance.UpdatedAt = time.Now()

	// Remove from instance-to-port mapping
	o.instanceToPort.Delete(instanceID)

	o.logger.Infof("Detached network port %s from container instance %s", portName, instanceID)

	return nil
}

// ActivateInstance transitions an instance's network port from enrolled to authorized
// This applies the full production policy with tenant-specific VLAN and ACLs
func (o *ContainerOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	if o.closed.Load() {
		return ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if portPolicy == nil {
		return fmt.Errorf("port policy is required")
	}

	// Check if port authentication is enabled
	if !o.config.PortAuthEnabled || o.config.PolicyEngine == nil {
		return fmt.Errorf("port authentication is not enabled")
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	portNameValue, hasMappedPort := o.instanceToPort.Load(instanceID)
	if !hasMappedPort {
		return fmt.Errorf("no network port mapped for instance %s", instanceID)
	}
	portName := portNameValue.(string)
	if portName == "" {
		return fmt.Errorf("no network port mapped for instance %s", instanceID)
	}

	if !contInst.networkAttached.Load() {
		return fmt.Errorf("no network attached to instance %s", instanceID)
	}

	// Create port auth configuration
	authConfig := &PortAuthConfig{
		PortID:       portName,
		BridgeName:   o.config.NetworkBridge,
		MACAddress:   contInst.instance.Config.MACAddress,
		PolicyEngine: o.config.PolicyEngine,
	}

	// Activate the port with the production policy
	if err := ActivatePort(authConfig, portPolicy); err != nil {
		return fmt.Errorf("failed to activate instance network port: %w", err)
	}

	// Update instance metadata
	contInst.instance.Metadata["port_state"] = "authorized"
	contInst.instance.Metadata["vlan"] = fmt.Sprintf("%d", portPolicy.VLAN)
	contInst.instance.UpdatedAt = time.Now()

	o.logger.Infof("Activated container instance %s on port %s with VLAN %d", instanceID, portName, portPolicy.VLAN)

	return nil
}

// Wait waits for a container instance to exit
func (o *ContainerOrchestrator) Wait(ctx context.Context, instanceID string) error {
	if o.closed.Load() {
		return ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	value, exists := o.instances.Load(instanceID)
	if !exists {
		return ErrInstanceNotFound
	}
	contInst := value.(*containerInstance)

	// Wait for the container to exit
	exitCode, err := o.podmanManager.WaitContainer(ctx, contInst.containerID)
	if err != nil {
		return fmt.Errorf("failed to wait for container: %w", err)
	}

	// Update instance state
	if err := o.lifecycle.SetState(instanceID, StateStopped); err != nil {
		o.logger.Warnf("Failed to update state after container exit: %v", err)
	}
	contInst.instance.State = StateStopped
	contInst.instance.UpdatedAt = time.Now()
	contInst.instance.PID = 0
	contInst.instance.Metadata["exit_code"] = fmt.Sprintf("%d", exitCode)

	o.logger.Infof("Container instance %s exited with code %d", instanceID, exitCode)

	return nil
}

// GetState returns the current state of a container instance
func (o *ContainerOrchestrator) GetState(ctx context.Context, instanceID string) (InstanceState, error) {
	if o.closed.Load() {
		return StateUnknown, ErrOrchestratorNotInitialized
	}

	if instanceID == "" {
		return StateUnknown, ErrInvalidInstanceID
	}

	return o.lifecycle.GetState(instanceID)
}

// Close closes the orchestrator and releases resources
func (o *ContainerOrchestrator) Close() error {
	if o.closed.Swap(true) {
		// Already closed
		return nil
	}

	// Stop all running instances
	o.instances.Range(func(key, value interface{}) bool {
		instanceID := key.(string)
		contInst := value.(*containerInstance)

		// Check if running
		currentState, err := o.lifecycle.GetState(instanceID)
		if err == nil && currentState == StateRunning {
			o.logger.Infof("Stopping container instance %s during shutdown", instanceID)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := o.podmanManager.StopContainer(ctx, contInst.containerID, nil); err != nil {
				o.logger.Errorf("Failed to stop container instance %s: %v", instanceID, err)
			}
			cancel()
		}
		return true
	})

	// Close Podman manager
	if o.podmanManager != nil {
		if err := o.podmanManager.Close(); err != nil {
			o.logger.Warnf("Failed to close Podman manager: %v", err)
		}
	}

	// Close OVS client
	if o.ovsClient != nil {
		if err := o.ovsClient.Close(); err != nil {
			o.logger.Warnf("Failed to close OVS client: %v", err)
		}
	}

	o.logger.Info("Container orchestrator closed")

	return nil
}

// mapContainerStateToInstanceState maps Podman container state to compute instance state
func mapContainerStateToInstanceState(containerState podman.ContainerState) InstanceState {
	switch containerState {
	case podman.ContainerStateCreated:
		return StateStopped
	case podman.ContainerStateRunning:
		return StateRunning
	case podman.ContainerStatePaused:
		return StateRunning // Treat paused as running for orchestrator purposes
	case podman.ContainerStateStopped, podman.ContainerStateExited:
		return StateStopped
	default:
		return StateUnknown
	}
}

// mapInstanceStateToContainerState maps compute instance state to Podman container state
func mapInstanceStateToContainerState(instanceState InstanceState) podman.ContainerState {
	switch instanceState {
	case StateCreating:
		return podman.ContainerStateCreated
	case StateStopped:
		return podman.ContainerStateStopped
	case StateStarting, StateRunning:
		return podman.ContainerStateRunning
	case StateStopping:
		return podman.ContainerStateStopped
	case StateError, StateDeleting:
		return podman.ContainerStateExited
	default:
		return podman.ContainerStateUnknown
	}
}
