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
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
)

// QEMUOrchestrator implements the Orchestrator interface for QEMU virtual machines
type QEMUOrchestrator struct {
	config         *OrchestratorConfig
	logger         *logging.Logger
	lifecycle      *LifecycleManager
	ovsClient      *ovs.Client
	mu             sync.RWMutex
	instances      map[string]*qemuInstance
	instanceToPort map[string]string // Maps instance ID to primary port name for activation lookup
}

// qemuInstance holds the VM instance and its metadata
type qemuInstance struct {
	vm                *qemu.VM
	instance          *Instance
	ovsNetwork        *qemu.OVSNetwork
	swtpm             *swtpm.SWTPM
	mu                sync.Mutex
	cancelFunc        context.CancelFunc
	waitGroup         sync.WaitGroup
	networkAttached   bool
	primaryPortName   string
	primaryBridgeName string
}

// NewQEMUOrchestrator creates a new QEMU orchestrator
func NewQEMUOrchestrator(config *OrchestratorConfig, logger *logging.Logger) (*QEMUOrchestrator, error) {
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

	if config.Type != ComputeTypeVM {
		return nil, fmt.Errorf("%w: QEMU orchestrator requires VM compute type", ErrInvalidConfiguration)
	}

	// Create work directory
	if err := os.MkdirAll(config.WorkDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	// Create OVS client
	ovsClient, err := ovs.NewClient(config.OVSSocketPath)
	if err != nil {
		logger.Warnf("Failed to create OVS client: %v (OVS networking will be unavailable)", err)
	}

	o := &QEMUOrchestrator{
		config:         config,
		logger:         logger,
		lifecycle:      NewLifecycleManager(),
		ovsClient:      ovsClient,
		instances:      make(map[string]*qemuInstance),
		instanceToPort: make(map[string]string),
	}

	// Connect to OVS if available
	if o.ovsClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := o.ovsClient.Connect(ctx); err != nil {
			logger.Warnf("Failed to connect to OVS: %v (OVS networking will be unavailable)", err)
			o.ovsClient = nil
		}
	}

	return o, nil
}

// generateInstanceID generates a unique instance ID
func generateInstanceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// createSWTPM creates and initializes a software TPM instance for a VM
func (o *QEMUOrchestrator) createSWTPM(ctx context.Context, instanceID, workDir string) (*swtpm.SWTPM, error) {
	// Create TPM state directory
	tpmStateDir := filepath.Join(workDir, "tpm")
	if err := os.MkdirAll(tpmStateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create TPM state directory: %w", err)
	}

	// Configure swtpm for QEMU mode (uses --ctrl socket)
	swtpmConfig := &swtpm.Config{
		StateDir:   tpmStateDir,
		SocketPath: filepath.Join(tpmStateDir, "swtpm.sock"),
		PCRBanks:   []string{"sha256"},
		LogLevel:   20,
		Debug:      o.config.Debug,
		QEMUMode:   true, // Enable QEMU mode for TPM emulation
	}

	// Create swtpm instance
	tpm, err := swtpm.NewSWTPM(swtpmConfig, o.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create swtpm: %w", err)
	}

	// Initialize TPM state if not already initialized
	if !tpm.IsInitialized() {
		o.logger.Infof("Initializing TPM state for instance %s", instanceID)
		if err := tpm.Initialize(ctx); err != nil {
			return nil, fmt.Errorf("failed to initialize swtpm: %w", err)
		}
	} else {
		o.logger.Debugf("Using existing TPM state for instance %s", instanceID)
	}

	return tpm, nil
}

// Create creates a new VM instance from a device profile
func (o *QEMUOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*Instance, error) {
	if profile == nil {
		return nil, ErrInvalidProfile
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	// Check instance limit
	if len(o.instances) >= o.config.MaxInstances {
		return nil, ErrResourceExhausted
	}

	// Generate unique instance ID
	instanceID := generateInstanceID()

	// Check if already exists
	if _, exists := o.instances[instanceID]; exists {
		return nil, ErrInstanceAlreadyExists
	}

	// Set initial state
	if err := o.lifecycle.SetState(instanceID, StateCreating); err != nil {
		return nil, err
	}

	// Create instance configuration
	instanceConfig := &InstanceConfig{
		Memory:      o.config.DefaultMemory,
		CPUs:        o.config.DefaultCPUs,
		DiskSize:    o.config.DefaultDiskSize,
		WorkDir:     filepath.Join(o.config.WorkDir, instanceID),
		SecureBoot:  false,
		EnableKVM:   o.config.EnableKVM,
		TPMEnabled:  true,
		NetworkMode: "bridge",
		BootMode:    "boot",
	}

	// Create disk path
	instanceConfig.DiskPath = filepath.Join(instanceConfig.WorkDir, "disk.qcow2")

	// Create work directory
	if err := os.MkdirAll(instanceConfig.WorkDir, 0755); err != nil {
		o.lifecycle.SetState(instanceID, StateError)
		return nil, fmt.Errorf("failed to create instance work directory: %w", err)
	}

	// Create and initialize swtpm if TPM is enabled
	var tpm *swtpm.SWTPM
	var tpmSocket string
	if instanceConfig.TPMEnabled {
		var err error
		tpm, err = o.createSWTPM(ctx, instanceID, instanceConfig.WorkDir)
		if err != nil {
			o.lifecycle.SetState(instanceID, StateError)
			return nil, fmt.Errorf("failed to create swtpm: %w", err)
		}
		tpmSocket = tpm.SocketPath()
		o.logger.Infof("Created swtpm for instance %s (socket: %s)", instanceID, tpmSocket)
	}

	// Create QEMU configuration
	qemuConfig := &qemu.Config{
		QEMUBinary:     o.config.QEMUBinary,
		DiskPath:       instanceConfig.DiskPath,
		DiskSize:       instanceConfig.DiskSize,
		Memory:         instanceConfig.Memory,
		CPUs:           instanceConfig.CPUs,
		WorkDir:        instanceConfig.WorkDir,
		SecureBoot:     instanceConfig.SecureBoot,
		Debug:          o.config.Debug,
		OVMFCode:       o.config.OVMFCode,
		OVMFCodeSecure: o.config.OVMFCodeSecure,
		OVMFVars:       o.config.OVMFVars,
		EnableKVM:      instanceConfig.EnableKVM,
		SerialConsole:  false,
		NoGraphic:      true,
		BootOrder:      "c",
		NetworkMode:    instanceConfig.NetworkMode,
		BridgeName:     o.config.NetworkBridge,
		MACAddress:     instanceConfig.MACAddress,
		TPMSocket:      tpmSocket,
	}

	// Create VM
	vm, err := qemu.NewVM(qemuConfig, o.logger)
	if err != nil {
		o.lifecycle.SetState(instanceID, StateError)
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}

	// Create disk
	if err := vm.CreateDisk(); err != nil {
		o.lifecycle.SetState(instanceID, StateError)
		return nil, fmt.Errorf("failed to create VM disk: %w", err)
	}

	// Create instance metadata
	instance := &Instance{
		ID:                 instanceID,
		Name:               profile.Name,
		Type:               ComputeTypeVM,
		State:              StateCreating,
		Profile:            profile,
		Config:             instanceConfig,
		NetworkAttachments: []NetworkAttachment{},
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Metadata:           make(map[string]string),
	}

	// Store TPM socket path in metadata
	if tpmSocket != "" {
		instance.Metadata["tpm_socket"] = tpmSocket
	}

	// Store instance
	o.instances[instanceID] = &qemuInstance{
		vm:       vm,
		instance: instance,
		swtpm:    tpm,
	}

	// Update state to stopped
	if err := o.lifecycle.SetState(instanceID, StateStopped); err != nil {
		delete(o.instances, instanceID)
		return nil, err
	}
	instance.State = StateStopped
	instance.UpdatedAt = time.Now()

	o.logger.Infof("Created VM instance: %s (profile: %s)", instanceID, profile.Name)

	return instance, nil
}

// Start starts a stopped VM instance
func (o *QEMUOrchestrator) Start(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

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
	qemuInst.instance.State = StateStarting
	qemuInst.instance.UpdatedAt = time.Now()

	// Start swtpm if configured
	if qemuInst.swtpm != nil {
		o.logger.Infof("Starting swtpm for instance %s", instanceID)

		// Start swtpm daemon
		if err := qemuInst.swtpm.Start(ctx); err != nil {
			o.lifecycle.SetState(instanceID, StateError)
			qemuInst.instance.State = StateError
			qemuInst.instance.UpdatedAt = time.Now()
			return fmt.Errorf("failed to start swtpm: %w", err)
		}

		// Wait for socket to be ready
		if err := qemuInst.swtpm.WaitForSocket(5 * time.Second); err != nil {
			qemuInst.swtpm.Stop()
			o.lifecycle.SetState(instanceID, StateError)
			qemuInst.instance.State = StateError
			qemuInst.instance.UpdatedAt = time.Now()
			return fmt.Errorf("swtpm socket not ready: %w", err)
		}

		o.logger.Infof("swtpm started for instance %s (PID: %d)", instanceID, qemuInst.swtpm.PID())
	}

	// Determine boot mode
	bootMode := qemuInst.instance.Config.BootMode
	if bootMode == "" {
		bootMode = "boot"
	}

	// Create context for VM lifecycle
	vmCtx, cancel := context.WithCancel(context.Background())
	qemuInst.cancelFunc = cancel

	// Start VM
	if err := qemuInst.vm.Start(vmCtx, bootMode); err != nil {
		// Cleanup swtpm on failure
		if qemuInst.swtpm != nil {
			if stopErr := qemuInst.swtpm.Stop(); stopErr != nil {
				o.logger.Warnf("Failed to stop swtpm after VM start failure: %v", stopErr)
			}
		}
		o.lifecycle.SetState(instanceID, StateError)
		qemuInst.instance.State = StateError
		qemuInst.instance.UpdatedAt = time.Now()
		return fmt.Errorf("failed to start VM: %w", err)
	}

	// Update instance with PID
	qemuInst.instance.PID = qemuInst.vm.GetPID()

	// Update state to running
	if err := o.lifecycle.SetState(instanceID, StateRunning); err != nil {
		// VM is running but state update failed - try to stop it
		qemuInst.vm.Stop()
		if qemuInst.swtpm != nil {
			qemuInst.swtpm.Stop()
		}
		return err
	}
	qemuInst.instance.State = StateRunning
	qemuInst.instance.UpdatedAt = time.Now()

	// Start wait goroutine
	qemuInst.waitGroup.Add(1)
	go func() {
		defer qemuInst.waitGroup.Done()
		if err := qemuInst.vm.Wait(); err != nil {
			o.logger.Errorf("VM %s exited with error: %v", instanceID, err)
		}

		// Stop swtpm when VM exits
		qemuInst.mu.Lock()
		if qemuInst.swtpm != nil && qemuInst.swtpm.IsRunning() {
			o.logger.Infof("Stopping swtpm for instance %s", instanceID)
			if err := qemuInst.swtpm.Stop(); err != nil {
				o.logger.Errorf("Failed to stop swtpm for instance %s: %v", instanceID, err)
			}
		}
		qemuInst.mu.Unlock()

		// Update state to stopped
		o.lifecycle.SetState(instanceID, StateStopped)
		qemuInst.mu.Lock()
		qemuInst.instance.State = StateStopped
		qemuInst.instance.UpdatedAt = time.Now()
		qemuInst.instance.PID = 0
		qemuInst.mu.Unlock()
		o.logger.Infof("VM %s stopped", instanceID)
	}()

	o.logger.Infof("Started VM instance: %s (PID: %d)", instanceID, qemuInst.instance.PID)

	return nil
}

// Stop stops a running VM instance
func (o *QEMUOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

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
	qemuInst.instance.State = StateStopping
	qemuInst.instance.UpdatedAt = time.Now()

	// Stop VM
	if err := qemuInst.vm.Stop(); err != nil {
		o.lifecycle.SetState(instanceID, StateError)
		qemuInst.instance.State = StateError
		qemuInst.instance.UpdatedAt = time.Now()
		return fmt.Errorf("failed to stop VM: %w", err)
	}

	// Cancel context
	if qemuInst.cancelFunc != nil {
		qemuInst.cancelFunc()
	}

	// Wait for VM to exit (this will also stop swtpm via the wait goroutine)
	qemuInst.waitGroup.Wait()

	o.logger.Infof("Stopped VM instance: %s", instanceID)

	return nil
}

// Delete deletes a VM instance and cleans up resources
func (o *QEMUOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	qemuInst, exists := o.instances[instanceID]
	if !exists {
		return ErrInstanceNotFound
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	// Check current state
	currentState, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return err
	}

	// Stop if running
	if currentState == StateRunning {
		qemuInst.mu.Unlock()
		o.mu.Unlock()
		if err := o.Stop(ctx, instanceID); err != nil {
			o.mu.Lock()
			qemuInst.mu.Lock()
			return err
		}
		o.mu.Lock()
		qemuInst.mu.Lock()
	}

	// Update state to deleting
	if err := o.lifecycle.SetState(instanceID, StateDeleting); err != nil {
		return err
	}
	qemuInst.instance.State = StateDeleting
	qemuInst.instance.UpdatedAt = time.Now()

	// Remove port authentication if enabled
	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil && qemuInst.primaryPortName != "" {
		authConfig := &PortAuthConfig{
			PortID:       qemuInst.primaryPortName,
			BridgeName:   qemuInst.primaryBridgeName,
			PolicyEngine: o.config.PolicyEngine,
		}
		if err := RemovePortAuth(authConfig); err != nil {
			o.logger.Warnf("Failed to remove port authentication for instance %s: %v", instanceID, err)
		}
	}

	// Cleanup OVS network if attached
	if qemuInst.ovsNetwork != nil {
		if err := qemuInst.ovsNetwork.Cleanup(ctx); err != nil {
			o.logger.Warnf("Failed to cleanup OVS network for instance %s: %v", instanceID, err)
		}
	}

	// Ensure swtpm is stopped
	if qemuInst.swtpm != nil && qemuInst.swtpm.IsRunning() {
		o.logger.Infof("Stopping swtpm before deleting instance %s", instanceID)
		if err := qemuInst.swtpm.Stop(); err != nil {
			o.logger.Warnf("Failed to stop swtpm for instance %s: %v", instanceID, err)
		}
	}

	// Remove work directory (includes TPM state)
	if err := os.RemoveAll(qemuInst.instance.Config.WorkDir); err != nil {
		o.logger.Warnf("Failed to remove work directory for instance %s: %v", instanceID, err)
	}

	// Remove from lifecycle manager
	if err := o.lifecycle.DeleteInstance(instanceID); err != nil {
		o.logger.Warnf("Failed to remove instance from lifecycle manager: %v", err)
	}

	// Remove from instance-to-port mapping
	delete(o.instanceToPort, instanceID)

	// Remove from instances map
	delete(o.instances, instanceID)

	o.logger.Infof("Deleted VM instance: %s", instanceID)

	return nil
}

// List returns all VM instances, optionally filtered
func (o *QEMUOrchestrator) List(ctx context.Context, filter *InstanceFilter) ([]*Instance, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	result := make([]*Instance, 0, len(o.instances))

	for _, qemuInst := range o.instances {
		qemuInst.mu.Lock()
		instance := qemuInst.instance
		qemuInst.mu.Unlock()

		// Apply filter if provided
		if filter != nil && !filter.Matches(instance) {
			continue
		}

		// Create a copy to avoid external modifications
		instanceCopy := *instance
		result = append(result, &instanceCopy)
	}

	return result, nil
}

// Get retrieves a specific VM instance by ID
func (o *QEMUOrchestrator) Get(ctx context.Context, instanceID string) (*Instance, error) {
	if instanceID == "" {
		return nil, ErrInvalidInstanceID
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return nil, ErrInstanceNotFound
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	// Return a copy
	instanceCopy := *qemuInst.instance
	return &instanceCopy, nil
}

// AttachNetwork attaches a VM instance to an OVS network port
// When port authentication is enabled, the port is set to provisioning state
func (o *QEMUOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if portName == "" {
		return fmt.Errorf("%w: port name is required", ErrNetworkAttachmentFailed)
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	if o.ovsClient == nil {
		return fmt.Errorf("%w: OVS client not available", ErrNetworkAttachmentFailed)
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	// Check if already attached
	if qemuInst.networkAttached {
		return fmt.Errorf("%w: network already attached", ErrNetworkAttachmentFailed)
	}

	// Get or create OVS network
	vmConfig := qemuInst.vm.GetConfig()
	if vmConfig.OVS == nil {
		vmConfig.OVS = &qemu.OVSConfig{
			Enable:     true,
			BridgeName: o.config.NetworkBridge,
			SocketPath: o.config.OVSSocketPath,
			PortName:   portName,
		}
	}

	ovsNetwork, err := qemu.NewOVSNetwork(vmConfig, o.logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNetworkAttachmentFailed, err)
	}

	// Setup network (creates TAP and attaches to OVS)
	if err := ovsNetwork.Setup(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrNetworkAttachmentFailed, err)
	}

	// Update instance
	qemuInst.ovsNetwork = ovsNetwork
	qemuInst.networkAttached = true
	qemuInst.primaryPortName = portName
	qemuInst.primaryBridgeName = o.config.NetworkBridge

	// Add network attachment to instance metadata
	attachment := NetworkAttachment{
		PortName:   portName,
		BridgeName: o.config.NetworkBridge,
		AttachedAt: time.Now(),
	}
	qemuInst.instance.NetworkAttachments = append(qemuInst.instance.NetworkAttachments, attachment)
	qemuInst.instance.UpdatedAt = time.Now()

	// If port authentication is enabled, set port to provisioning state
	if o.config.PortAuthEnabled && o.config.PolicyEngine != nil {
		// Extract MAC address from instance config
		macAddr := qemuInst.instance.Config.MACAddress

		authConfig := &PortAuthConfig{
			PortID:       portName,
			BridgeName:   o.config.NetworkBridge,
			MACAddress:   macAddr,
			PolicyEngine: o.config.PolicyEngine,
		}

		if err := SetProvisioningState(authConfig); err != nil {
			// Cleanup on failure
			ovsNetwork.Cleanup(ctx)
			qemuInst.ovsNetwork = nil
			qemuInst.networkAttached = false
			qemuInst.primaryPortName = ""
			qemuInst.primaryBridgeName = ""
			return fmt.Errorf("%w: failed to set provisioning state: %v", ErrNetworkAttachmentFailed, err)
		}

		// Store instance-to-port mapping for activation lookup
		o.mu.Lock()
		o.instanceToPort[instanceID] = portName
		o.mu.Unlock()

		o.logger.Infof("Attached network port %s to instance %s with provisioning state", portName, instanceID)
	} else {
		o.logger.Infof("Attached network port %s to instance %s", portName, instanceID)
	}

	return nil
}

// DetachNetwork detaches a VM instance from an OVS network port
func (o *QEMUOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	if portName == "" {
		return fmt.Errorf("%w: port name is required", ErrNetworkDetachmentFailed)
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	if !qemuInst.networkAttached {
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

	// Cleanup OVS network
	if qemuInst.ovsNetwork != nil {
		if err := qemuInst.ovsNetwork.Cleanup(ctx); err != nil {
			return fmt.Errorf("%w: %v", ErrNetworkDetachmentFailed, err)
		}
	}

	// Update instance
	qemuInst.ovsNetwork = nil
	qemuInst.networkAttached = false
	qemuInst.primaryPortName = ""
	qemuInst.primaryBridgeName = ""

	// Remove network attachment from instance metadata
	newAttachments := make([]NetworkAttachment, 0)
	for _, att := range qemuInst.instance.NetworkAttachments {
		if att.PortName != portName {
			newAttachments = append(newAttachments, att)
		}
	}
	qemuInst.instance.NetworkAttachments = newAttachments
	qemuInst.instance.UpdatedAt = time.Now()

	// Remove from instance-to-port mapping
	o.mu.Lock()
	delete(o.instanceToPort, instanceID)
	o.mu.Unlock()

	o.logger.Infof("Detached network port %s from instance %s", portName, instanceID)

	return nil
}

// ActivateInstance transitions an instance's network port from enrolled to authorized
// This applies the full production policy with tenant-specific VLAN and ACLs
func (o *QEMUOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
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

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	portName, hasMappedPort := o.instanceToPort[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	if !hasMappedPort || portName == "" {
		return fmt.Errorf("no network port mapped for instance %s", instanceID)
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	if !qemuInst.networkAttached {
		return fmt.Errorf("no network attached to instance %s", instanceID)
	}

	// Create port auth configuration
	authConfig := &PortAuthConfig{
		PortID:       portName,
		BridgeName:   o.config.NetworkBridge,
		MACAddress:   qemuInst.instance.Config.MACAddress,
		PolicyEngine: o.config.PolicyEngine,
	}

	// Activate the port with the production policy
	if err := ActivatePort(authConfig, portPolicy); err != nil {
		return fmt.Errorf("failed to activate instance network port: %w", err)
	}

	// Update instance metadata
	qemuInst.instance.Metadata["port_state"] = "authorized"
	qemuInst.instance.Metadata["vlan"] = fmt.Sprintf("%d", portPolicy.VLAN)
	qemuInst.instance.UpdatedAt = time.Now()

	o.logger.Infof("Activated instance %s on port %s with VLAN %d", instanceID, portName, portPolicy.VLAN)

	return nil
}

// Wait waits for a VM instance to exit
func (o *QEMUOrchestrator) Wait(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	// Wait for the VM to exit
	qemuInst.waitGroup.Wait()

	return nil
}

// GetState returns the current state of a VM instance
func (o *QEMUOrchestrator) GetState(ctx context.Context, instanceID string) (InstanceState, error) {
	if instanceID == "" {
		return StateUnknown, ErrInvalidInstanceID
	}

	return o.lifecycle.GetState(instanceID)
}

// Close closes the orchestrator and releases resources
func (o *QEMUOrchestrator) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Stop all running instances
	for instanceID, qemuInst := range o.instances {
		if qemuInst.vm.IsRunning() {
			o.logger.Infof("Stopping instance %s during shutdown", instanceID)
			if err := qemuInst.vm.Stop(); err != nil {
				o.logger.Errorf("Failed to stop instance %s: %v", instanceID, err)
			}
		}
		// Stop swtpm if running
		if qemuInst.swtpm != nil && qemuInst.swtpm.IsRunning() {
			o.logger.Infof("Stopping swtpm for instance %s during shutdown", instanceID)
			if err := qemuInst.swtpm.Stop(); err != nil {
				o.logger.Errorf("Failed to stop swtpm for instance %s: %v", instanceID, err)
			}
		}
	}

	// Close OVS client
	if o.ovsClient != nil {
		if err := o.ovsClient.Close(); err != nil {
			o.logger.Warnf("Failed to close OVS client: %v", err)
		}
	}

	o.logger.Info("QEMU orchestrator closed")

	return nil
}
