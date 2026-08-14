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

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
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

	// tpmProvider caches go-xkms TPM connections to per-instance swtpm
	// sockets for VM attestation.
	tpmProvider *vtpm.TPMProvider

	// vtpmGenerator is the profile-aware vTPM facade. When set (via
	// SetVTPMGenerator at factory time) VM TPM provisioning is routed through
	// it so each VM boots against a profile-bound, CA-issued-EK bundle. Set
	// once before the orchestrator handles requests.
	vtpmGenerator vtpm.Generator

	// snapshotOpsFor produces the QMP snapshot operations for an instance.
	// Overridable seam for tests; defaults to defaultSnapshotOps.
	snapshotOpsFor func(ctx context.Context, inst *qemuInstance) (vmSnapshotOps, error)

	// vtpmDeviceFor produces the vTPM attestor device for a swtpm socket.
	// Overridable seam for tests; defaults to defaultVTPMDevice.
	vtpmDeviceFor func(socketPath string) (vm.VTPMDevice, error)
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
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "config is required"}}
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if config.Type != ComputeTypeVM {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfiguration, Cause: &MessageError{Msg: "QEMU orchestrator requires VM compute type"}}
	}

	// Create work directory
	if err := os.MkdirAll(config.WorkDir, 0755); err != nil {
		return nil, &WrappedError{Msg: "failed to create work directory", Err: err}
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
		tpmProvider:    vtpm.NewTPMProvider(logger),
	}
	o.snapshotOpsFor = o.defaultSnapshotOps
	o.vtpmDeviceFor = o.defaultVTPMDevice

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
		return nil, &WrappedError{Msg: "failed to create TPM state directory", Err: err}
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
		return nil, &WrappedError{Msg: "failed to create swtpm", Err: err}
	}

	// Initialize TPM state if not already initialized
	if !tpm.IsInitialized() {
		o.logger.Infof("Initializing TPM state for instance %s", instanceID)
		if err := tpm.Initialize(ctx); err != nil {
			return nil, &WrappedError{Msg: "failed to initialize swtpm", Err: err}
		}
	} else {
		o.logger.Debugf("Using existing TPM state for instance %s", instanceID)
	}

	return tpm, nil
}

// SetVTPMGenerator injects the profile-aware vTPM facade used to source a VM's
// swtpm from a profile-bound, CA-issued-EK bundle. It is called once by the
// compute provider factory before the orchestrator serves any request.
func (o *QEMUOrchestrator) SetVTPMGenerator(gen vtpm.Generator) {
	o.vtpmGenerator = gen
}

// provisionVTPM sources the VM's swtpm through the vTPM Generator facade,
// returning the swtpm handle, its socket path, and the bundle ID.
//
// With a generator wired it resolves an existing profile-bound bundle
// (prestaged via `platformctl vtpm create` / config-delivery EK prestaging)
// or mints one for the profile (CA-issued EK when a CA is configured, plus
// Secure Boot enrollment when requested). Without a generator it fails closed
// with ErrVTPMIdentityRequired when the profile requires a hardware-rooted
// identity, and otherwise falls back to a local identity-less swtpm with a
// loud warning — never a silent downgrade.
func (o *QEMUOrchestrator) provisionVTPM(ctx context.Context, profile *entities.DeviceProfile, cfg *InstanceConfig) (*swtpm.SWTPM, string, string, error) {
	if o.vtpmGenerator == nil {
		if vtpmIdentityRequired(profile, cfg) {
			return nil, "", "", &SentinelCauseError{
				Sentinel: ErrVTPMIdentityRequired,
				Cause:    &MessageError{Msg: fmt.Sprintf("device profile %d (%s)", profile.ID, profile.Name)},
			}
		}
		o.logger.Warnf("No vTPM generator configured; VM for profile %d (%s) will boot with an anonymous swtpm and NO CA-issued EK identity", profile.ID, profile.Name)
		tpm, err := o.createSWTPM(ctx, profile.Name, cfg.WorkDir)
		if err != nil {
			return nil, "", "", &WrappedError{Msg: "failed to create swtpm", Err: err}
		}
		socketPath := tpm.SocketPath()
		return tpm, socketPath, "", nil
	}

	inst, err := o.vtpmGenerator.GetByProfile(ctx, profile.ID)
	if err != nil {
		if _, ok := err.(vtpm.ErrProfileNotAssociated); !ok {
			return nil, "", "", &WrappedError{Msg: "failed to look up vTPM bundle for profile", Err: err}
		}
		inst, err = o.vtpmGenerator.GenerateForProfile(ctx, profile, &vtpm.GenerateOptions{
			Hostname:          profile.Name,
			SecureBootEnabled: cfg.SecureBoot,
		})
		if err != nil {
			if _, ok := err.(vtpm.ErrVTPMAlreadyExists); ok {
				inst, err = o.vtpmGenerator.GetByProfile(ctx, profile.ID)
			}
			if err != nil {
				return nil, "", "", &WrappedError{Msg: "failed to generate vTPM bundle for profile", Err: err}
			}
		}
	}

	tpm, err := o.swtpmForBundle(ctx, inst)
	if err != nil {
		return nil, "", "", err
	}
	return tpm, inst.SocketPath, inst.ID, nil
}

// swtpmForBundle opens an swtpm bound to an existing bundle's TPM state dir and
// socket. The bundle state is already initialized (EK cert injected at bundle
// creation), so re-initialization is skipped.
func (o *QEMUOrchestrator) swtpmForBundle(ctx context.Context, inst *vtpm.VTPMInstance) (*swtpm.SWTPM, error) {
	swtpmConfig := &swtpm.Config{
		StateDir:   filepath.Join(inst.StoragePath, "tpm"),
		SocketPath: inst.SocketPath,
		PCRBanks:   []string{"sha256"},
		LogLevel:   20,
		Debug:      o.config.Debug,
		QEMUMode:   true,
	}
	tpm, err := swtpm.NewSWTPM(swtpmConfig, o.logger)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open swtpm for bundle", Err: err}
	}
	if !tpm.IsInitialized() {
		o.logger.Infof("Initializing TPM state for bundle %s", inst.ID)
		if err := tpm.Initialize(ctx); err != nil {
			return nil, &WrappedError{Msg: "failed to initialize swtpm for bundle", Err: err}
		}
	}
	return tpm, nil
}

// vtpmIdentityRequired reports whether the profile requires a CA-issued,
// hardware-rooted vTPM identity: Secure Boot enabled, or a prestaged EK
// certificate / EK serial.
func vtpmIdentityRequired(profile *entities.DeviceProfile, cfg *InstanceConfig) bool {
	if cfg != nil && cfg.SecureBoot {
		return true
	}
	return profile != nil && (profile.EKCert != "" || profile.EKSerial != "")
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
		return nil, &WrappedError{Msg: "failed to create instance work directory", Err: err}
	}

	// Source the swtpm through the vTPM Generator facade so the VM boots
	// against a profile-bound, CA-issued-EK bundle rather than an anonymous
	// swtpm. Only WHERE the swtpm comes from changes here; the socket/NVRAM
	// plumbing that boots the VM below is unchanged.
	var tpm *swtpm.SWTPM
	var tpmSocket string
	var bundleID string
	if instanceConfig.TPMEnabled {
		var err error
		tpm, tpmSocket, bundleID, err = o.provisionVTPM(ctx, profile, instanceConfig)
		if err != nil {
			o.lifecycle.SetState(instanceID, StateError)
			return nil, err
		}
		o.logger.Infof("Provisioned vTPM for instance %s (socket: %s, bundle: %s)", instanceID, tpmSocket, bundleID)
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

	// Enable the serial transcript (GetVMLogs) and the interactive console
	// socket (AttachVMConsole multi-viewer broker). Paths match
	// serialLogPath()/consoleSocketPath() in the VM-ops capability code.
	qemuConfig.SerialLogFile = filepath.Join(instanceConfig.WorkDir, "serial.log")
	qemuConfig.ConsoleSocketPath = filepath.Join(instanceConfig.WorkDir, "console.sock")

	// Create VM
	vm, err := qemu.NewVM(qemuConfig, o.logger)
	if err != nil {
		o.lifecycle.SetState(instanceID, StateError)
		return nil, &WrappedError{Msg: "failed to create VM", Err: err}
	}

	// Create disk
	if err := vm.CreateDisk(); err != nil {
		o.lifecycle.SetState(instanceID, StateError)
		return nil, &WrappedError{Msg: "failed to create VM disk", Err: err}
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
	if bundleID != "" {
		instance.Metadata["vtpm_bundle_id"] = bundleID
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
		return &SentinelCauseError{Sentinel: ErrInvalidState, Cause: &MessageError{Msg: fmt.Sprintf("cannot start instance in state %s", currentState)}}
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
			return &WrappedError{Msg: "failed to start swtpm", Err: err}
		}

		// Wait for socket to be ready
		if err := qemuInst.swtpm.WaitForSocket(5 * time.Second); err != nil {
			qemuInst.swtpm.Stop()
			o.lifecycle.SetState(instanceID, StateError)
			qemuInst.instance.State = StateError
			qemuInst.instance.UpdatedAt = time.Now()
			return &WrappedError{Msg: "swtpm socket not ready", Err: err}
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
		return &WrappedError{Msg: "failed to start VM", Err: err}
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
	qemuInst.instance.StartedAt = time.Now()
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
		return &WrappedError{Msg: "failed to stop VM", Err: err}
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

	// Tear down any console broker fanning out this instance's serial socket.
	o.closeConsole(instanceID)

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
		return &SentinelCauseError{Sentinel: ErrNetworkAttachmentFailed, Cause: &MessageError{Msg: "port name is required"}}
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	if o.ovsClient == nil {
		return &SentinelCauseError{Sentinel: ErrNetworkAttachmentFailed, Cause: &MessageError{Msg: "OVS client not available"}}
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	// Check if already attached
	if qemuInst.networkAttached {
		return &SentinelCauseError{Sentinel: ErrNetworkAttachmentFailed, Cause: &MessageError{Msg: "network already attached"}}
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
		return &SentinelCauseError{Sentinel: ErrNetworkAttachmentFailed, Cause: err}
	}

	// Setup network (creates TAP and attaches to OVS)
	if err := ovsNetwork.Setup(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrNetworkAttachmentFailed, Cause: err}
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
			return &SentinelCauseError{Sentinel: ErrNetworkAttachmentFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to set provisioning state: %v", err)}}
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
		return &SentinelCauseError{Sentinel: ErrNetworkDetachmentFailed, Cause: &MessageError{Msg: "port name is required"}}
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
		return &SentinelCauseError{Sentinel: ErrNetworkDetachmentFailed, Cause: &MessageError{Msg: "no network attached"}}
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
			return &SentinelCauseError{Sentinel: ErrNetworkDetachmentFailed, Cause: err}
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
		return &MessageError{Msg: "port policy is required"}
	}

	// Check if port authentication is enabled
	if !o.config.PortAuthEnabled || o.config.PolicyEngine == nil {
		return &MessageError{Msg: "port authentication is not enabled"}
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	portName, hasMappedPort := o.instanceToPort[instanceID]
	o.mu.RUnlock()

	if !exists {
		return ErrInstanceNotFound
	}

	if !hasMappedPort || portName == "" {
		return &MessageError{Msg: fmt.Sprintf("no network port mapped for instance %s", instanceID)}
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	if !qemuInst.networkAttached {
		return &MessageError{Msg: fmt.Sprintf("no network attached to instance %s", instanceID)}
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
		return &WrappedError{Msg: "failed to activate instance network port", Err: err}
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
		o.closeConsole(instanceID)
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

	// Close cached vTPM connections
	if o.tpmProvider != nil {
		if err := o.tpmProvider.CloseAll(); err != nil {
			o.logger.Warnf("Failed to close vTPM connections: %v", err)
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
