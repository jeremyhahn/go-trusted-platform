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

package pxe

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Service defines the interface for the PXE provisioning service.
type Service interface {
	// Lifecycle methods
	Initialize(ctx context.Context, config *ServiceConfig) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsRunning() bool
	Close() error

	// Device Management
	RegisterDevice(ctx context.Context, macAddress, portID string) (*DeviceInfo, error)
	GetDevice(ctx context.Context, deviceID string) (*DeviceInfo, error)
	GetDeviceByMAC(ctx context.Context, mac string) (*DeviceInfo, error)
	ListDevices(ctx context.Context, filter *DeviceFilter) ([]*DeviceInfo, error)
	RemoveDevice(ctx context.Context, deviceID string) error

	// State Transitions
	UpdateDeviceState(ctx context.Context, deviceID string, state ProvisioningState, reason string) error

	// UpdateDeviceStateForIDevID is UpdateDeviceState for a change the
	// device reported: it compares fingerprint with the recorded IDevID
	// fingerprint under the same device lock as the transition.
	UpdateDeviceStateForIDevID(ctx context.Context, deviceID, fingerprint string, state ProvisioningState, reason string) error
	SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) error
	// RecordIDevIDFingerprint stores the device's IDevID fingerprint at
	// enrolment, before install completion (ruling 673).
	RecordIDevIDFingerprint(ctx context.Context, deviceID, fingerprint string) error
	AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) error
	QuarantineDevice(ctx context.Context, deviceID string, reason string) error
	RetryDevice(ctx context.Context, deviceID string) error

	// Events
	GetEvents(ctx context.Context, deviceID string) ([]*ProvisioningEvent, error)
	RegisterEventHandler(handler EventHandler)

	// Status
	Status() *ServiceStatus
}

// service implements the Service interface.
type service struct {
	config *ServiceConfig

	// ipxeServer is the server the next Start runs, or the one running.
	// ipxeRun is its run once it has been started: an ipxe.Server is
	// single-use (pkg/ipxe/server.go), so Start builds a fresh one when
	// ipxeServer has already run.
	ipxeServer *ipxe.Server
	ipxeRun    *ipxeRun

	stateManager *StateManager
	vlanManager  VLANIntegration
	logger       *logging.Logger

	running     atomic.Bool
	initialized atomic.Bool
	startTime   time.Time

	// lifecycle serialises Start and Stop, so two concurrent StartService
	// calls cannot both run a server.
	lifecycle sync.Mutex
	mu        sync.RWMutex

	// ops is held for reading by every device operation for its whole
	// call, and for writing by Close, so Close waits for the calls in
	// flight before it clears config.
	ops sync.RWMutex

	// devLocks holds one lock per device (keyed by the device ID, which
	// is derived from the MAC address), guarded by mu. Every lifecycle
	// method holds its device's lock for the whole state check, flow
	// change and state/VLAN commit, so two transitions of one device
	// cannot interleave and leave its port flows and recorded state
	// disagreeing.
	devLocks map[string]*deviceLock
}

// deviceLock is a device's lifecycle lock; refs counts the holders and
// waiters, so the entry is dropped when the last one releases it.
type deviceLock struct {
	mu   sync.Mutex
	refs int
}

// lockDevice takes deviceID's lifecycle lock and returns its release.
func (s *service) lockDevice(deviceID string) func() {
	s.mu.Lock()
	if s.devLocks == nil {
		s.devLocks = make(map[string]*deviceLock)
	}
	l := s.devLocks[deviceID]
	if l == nil {
		l = &deviceLock{}
		s.devLocks[deviceID] = l
	}
	l.refs++
	s.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		s.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(s.devLocks, deviceID)
		}
		s.mu.Unlock()
	}
}

// beginOp enters a device operation. It reports false when the service
// is not initialized; otherwise the caller must call s.ops.RUnlock when
// the operation returns.
func (s *service) beginOp() bool {
	s.ops.RLock()
	if !s.initialized.Load() {
		s.ops.RUnlock()
		return false
	}
	return true
}

// ipxeRun is one run of an iPXE server, from Start until it exits.
type ipxeRun struct {
	server *ipxe.Server
	cancel context.CancelFunc
	// exited closes when server.Start returns; err is what it returned
	// and is read only after exited has closed.
	exited chan struct{}
	err    error
}

// ServiceOption defines a functional option for configuring the service.
type ServiceOption func(*service)

// WithLogger sets the logger for the service.
func WithLogger(logger *logging.Logger) ServiceOption {
	return func(s *service) {
		s.logger = logger
	}
}

// WithStateManager sets the state manager for the service.
func WithStateManager(sm *StateManager) ServiceOption {
	return func(s *service) {
		s.stateManager = sm
	}
}

// WithVLANIntegration sets the VLAN integration for the service.
func WithVLANIntegration(vi VLANIntegration) ServiceOption {
	return func(s *service) {
		s.vlanManager = vi
	}
}

// WithIPXEServer sets a pre-configured iPXE server for the service.
func WithIPXEServer(server *ipxe.Server) ServiceOption {
	return func(s *service) {
		s.ipxeServer = server
	}
}

// NewService creates a new PXE provisioning service with the provided options.
func NewService(opts ...ServiceOption) Service {
	svc := &service{}

	for _, opt := range opts {
		opt(svc)
	}

	if svc.logger == nil {
		svc.logger = logging.DefaultLogger()
	}

	if svc.stateManager == nil {
		svc.stateManager = NewStateManager()
	}

	return svc
}

// Initialize validates and applies the configuration, creating the iPXE server if needed.
func (s *service) Initialize(ctx context.Context, config *ServiceConfig) error {
	if s.initialized.Load() {
		return ErrServiceAlreadyRunning{}
	}

	if config == nil {
		return ErrInvalidConfiguration{
			Field:  "config",
			Reason: "configuration is nil",
		}
	}

	if err := config.Validate(); err != nil {
		return ErrInvalidConfiguration{
			Reason: err.Error(),
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = config

	if s.ipxeServer == nil {
		server, err := ipxe.NewServer(config.IPXEConfig, s.logger)
		if err != nil {
			return ErrProvisioningFailed{
				Reason: "failed to create iPXE server",
				Cause:  err,
			}
		}
		s.ipxeServer = server
	}

	s.initialized.Store(true)
	s.logger.Info("PXE provisioning service initialized",
		"bridge", config.BridgeName,
		"quarantine_vlan", config.QuarantineVLAN,
		"provisioning_vlan", config.ProvisioningVLAN,
	)

	return nil
}

// Start starts the PXE provisioning service and returns once every iPXE
// listener has bound. The server runs until Stop or Close, not until ctx
// ends: a StartService RPC's context ends with the RPC. ctx bounds only the
// wait for the listeners.
func (s *service) Start(ctx context.Context) error {
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()

	// A Close that ran while this Start waited for lifecycle has cleared
	// the config: check again under the lock (#1896 Codex).
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}
	if s.running.Load() {
		return ErrServiceAlreadyRunning{}
	}

	// A request that has already ended starts nothing.
	if err := ctx.Err(); err != nil {
		return ErrProvisioningFailed{Reason: "start cancelled before the iPXE server was ready", Cause: err}
	}

	server, err := s.unstartedIPXEServer()
	if err != nil {
		return err
	}

	s.logger.Info("Starting PXE provisioning service")

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	run := &ipxeRun{server: server, cancel: cancel, exited: make(chan struct{})}
	s.mu.Lock()
	s.ipxeRun = run
	s.mu.Unlock()

	go func() {
		defer close(run.exited)
		run.err = server.Start(runCtx)
	}()

	select {
	case <-server.Ready():
	case <-run.exited:
		cancel()
		cause := run.err
		if cause == nil {
			cause = ErrIPXEServerExited{}
		}
		return ErrProvisioningFailed{Reason: "failed to start iPXE server", Cause: cause}
	case <-ctx.Done():
		cancel()
		<-run.exited
		return ErrProvisioningFailed{Reason: "start cancelled before the iPXE server was ready", Cause: ctx.Err()}
	}

	s.mu.Lock()
	s.startTime = time.Now()
	s.mu.Unlock()
	s.running.Store(true)

	go s.watchIPXERun(run)

	return nil
}

// unstartedIPXEServer returns the server the next Start runs: the current
// one if it has never run, otherwise a fresh one built from the config,
// because an ipxe.Server is single-use. The caller holds s.lifecycle.
func (s *service) unstartedIPXEServer() (*ipxe.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ipxeServer != nil && s.ipxeRun == nil {
		return s.ipxeServer, nil
	}

	server, err := ipxe.NewServer(s.config.IPXEConfig, s.logger)
	if err != nil {
		return nil, ErrProvisioningFailed{
			Reason: "failed to create iPXE server",
			Cause:  err,
		}
	}
	s.ipxeServer = server
	s.ipxeRun = nil
	return server, nil
}

// watchIPXERun marks the service stopped when run's server exits on its
// own, as it does when a listener fails after binding. A run that Stop
// ended, or that a later Start replaced, is left alone.
func (s *service) watchIPXERun(run *ipxeRun) {
	<-run.exited

	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()

	if s.ipxeRun != run || !s.running.Load() {
		return
	}
	s.running.Store(false)
	if run.err != nil {
		s.logger.Error(&WrappedError{Msg: "iPXE server exited", Err: run.err})
		return
	}
	s.logger.Warn("iPXE server exited; PXE provisioning service stopped")
}

// Stop stops the PXE provisioning service and waits for the iPXE server
// to exit. ctx bounds the wait.
func (s *service) Stop(ctx context.Context) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	return s.stopLocked(ctx)
}

// stopLocked stops the running iPXE server. Callers hold s.lifecycle.
func (s *service) stopLocked(ctx context.Context) error {
	if !s.running.Load() {
		return ErrServiceNotRunning{}
	}

	s.logger.Info("Stopping PXE provisioning service")

	run := s.ipxeRun
	if err := run.server.Stop(); err != nil {
		return ErrProvisioningFailed{
			Reason: "failed to stop iPXE server",
			Cause:  err,
		}
	}
	run.cancel()

	select {
	case <-run.exited:
	case <-ctx.Done():
		return ErrProvisioningFailed{Reason: "stop cancelled before the iPXE server exited", Cause: ctx.Err()}
	}

	s.running.Store(false)
	s.logger.Info("PXE provisioning service stopped")

	return nil
}

// IsRunning returns whether the service is currently running.
func (s *service) IsRunning() bool {
	return s.running.Load()
}

// Close releases all resources held by the service.
func (s *service) Close() error {
	// Wait for the device operations in flight: they read s.config.
	s.ops.Lock()
	defer s.ops.Unlock()

	// The running check, the stop and the teardown are one step under
	// lifecycle, which Start holds until its server is running: a Start
	// in flight finishes first and its run is stopped here, never cleared
	// while it listens on (#1896 Codex).
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.running.Load() {
		if err := s.stopLocked(context.Background()); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.initialized.Store(false)
	s.config = nil
	s.ipxeServer = nil
	s.ipxeRun = nil

	s.logger.Info("PXE provisioning service closed")

	return nil
}

// RegisterDevice registers a new device for provisioning.
func (s *service) RegisterDevice(ctx context.Context, macAddress, portID string) (*DeviceInfo, error) {
	if !s.beginOp() {
		return nil, ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()

	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, ErrInvalidMACAddress{
			MACAddress: macAddress,
			Reason:     err.Error(),
		}
	}

	unlock := s.lockDevice(generateDeviceID(mac))
	defer unlock()

	existing, err := s.stateManager.GetByMAC(mac)
	if err == nil && existing != nil {
		return nil, ErrDeviceAlreadyExists{
			DeviceID:   existing.ID,
			MACAddress: mac.String(),
		}
	}

	now := time.Now()
	deviceID := generateDeviceID(mac)

	device := &DeviceInfo{
		ID:             deviceID,
		MACAddress:     mac,
		PortID:         portID,
		State:          StateDiscovered,
		StateReason:    "device registered",
		CurrentVLAN:    s.config.QuarantineVLAN,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
		RetryCount:     0,
		Events:         make([]*ProvisioningEvent, 0),
	}

	event := &ProvisioningEvent{
		ID:        uuid.New().String(),
		DeviceID:  deviceID,
		Timestamp: now,
		EventType: EventDeviceDiscovered,
		FromState: StateUnknown,
		ToState:   StateDiscovered,
		Details: map[string]string{
			"mac_address": mac.String(),
			"port_id":     portID,
		},
	}
	device.Events = append(device.Events, event)

	// Fail closed: the device is registered, and advertised on the
	// quarantine VLAN, only once its port has been moved there.
	if s.vlanManager != nil {
		if vlanErr := s.vlanManager.ApplyQuarantineFlows(ctx, portID, mac); vlanErr != nil {
			return nil, ErrVLANTransitionFailed{
				DeviceID: deviceID,
				ToVLAN:   s.config.QuarantineVLAN,
				Reason:   "failed to apply quarantine VLAN; device not registered",
				Cause:    vlanErr,
			}
		}
	}

	if err := s.stateManager.Register(device); err != nil {
		return nil, ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to register device",
			Cause:    err,
		}
	}

	s.logger.Info("Device registered",
		"device_id", deviceID,
		"mac_address", mac.String(),
		"port_id", portID,
		"vlan", s.config.QuarantineVLAN,
	)

	return device, nil
}

// GetDevice retrieves a device by its ID.
func (s *service) GetDevice(ctx context.Context, deviceID string) (*DeviceInfo, error) {
	if !s.beginOp() {
		return nil, ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return nil, ErrDeviceNotFound{DeviceID: deviceID}
	}

	return device, nil
}

// GetDeviceByMAC retrieves a device by its MAC address.
func (s *service) GetDeviceByMAC(ctx context.Context, mac string) (*DeviceInfo, error) {
	if !s.beginOp() {
		return nil, ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()

	parsedMAC, err := net.ParseMAC(mac)
	if err != nil {
		return nil, ErrInvalidMACAddress{
			MACAddress: mac,
			Reason:     err.Error(),
		}
	}

	device, err := s.stateManager.GetByMAC(parsedMAC)
	if err != nil {
		return nil, ErrDeviceNotFound{MACAddress: mac}
	}

	return device, nil
}

// ListDevices returns all devices matching the provided filter.
func (s *service) ListDevices(ctx context.Context, filter *DeviceFilter) ([]*DeviceInfo, error) {
	if !s.beginOp() {
		return nil, ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()

	return s.stateManager.List(filter), nil
}

// RemoveDevice removes a device from the service.
func (s *service) RemoveDevice(ctx context.Context, deviceID string) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if err := s.stateManager.Unregister(deviceID); err != nil {
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to unregister device",
			Cause:    err,
		}
	}

	s.logger.Info("Device removed",
		"device_id", deviceID,
		"mac_address", device.MACAddress.String(),
	)

	return nil
}

// UpdateDeviceState transitions a device to a new state.
func (s *service) UpdateDeviceState(ctx context.Context, deviceID string, state ProvisioningState, reason string) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()
	return s.updateDeviceStateLocked(ctx, deviceID, state, reason)
}

// UpdateDeviceStateForIDevID applies a device-reported state change only
// when fingerprint is the IDevID fingerprint recorded for the device. The
// comparison and the transition run under one device lock, so an
// enrolment recording a new IDevID cannot land between them (#1896 Codex
// r2). A missing or different fingerprint is ErrIDevIDMismatch.
func (s *service) UpdateDeviceStateForIDevID(ctx context.Context, deviceID, fingerprint string, state ProvisioningState, reason string) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}
	if device.IDevIDFingerprint == "" || fingerprint == "" ||
		subtle.ConstantTimeCompare([]byte(device.IDevIDFingerprint), []byte(fingerprint)) != 1 {
		return ErrIDevIDMismatch{DeviceID: deviceID}
	}
	return s.updateDeviceStateLocked(ctx, deviceID, state, reason)
}

// ErrIDevIDMismatch is returned when a device-reported change is
// authenticated with an IDevID other than the one recorded for the device.
type ErrIDevIDMismatch struct {
	DeviceID string
}

// Error implements error.
func (e ErrIDevIDMismatch) Error() string {
	return "pxe: the authenticated IDevID is not the one recorded for device " + e.DeviceID
}

// updateDeviceStateLocked is UpdateDeviceState's body; the caller holds
// the operation read lock and the device lock.
func (s *service) updateDeviceStateLocked(ctx context.Context, deviceID string, state ProvisioningState, reason string) error {
	if !state.IsValid() {
		return ErrInvalidState{
			DeviceID: deviceID,
			State:    string(state),
			Reason:   "invalid state",
		}
	}

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(state) {
		return ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(state),
			Reason:    "transition not allowed",
		}
	}

	// Fail closed: a device whose VLAN move failed keeps its old state,
	// so a device sent to failed or quarantined is never reported moved
	// while it keeps its old network access.
	if err := s.applyVLANForState(ctx, device, state); err != nil {
		s.logger.Warn("VLAN enforcement failed; state transition not committed",
			"device_id", deviceID,
			"state", state,
			"error", err.Error(),
		)
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "VLAN enforcement failed; transition not committed",
			Cause:    err,
		}
	}

	// State and the VLAN the move enforced in one record write, so
	// GetDevice and a VLAN filter report the device where its port now
	// is, and a failed write leaves state and VLAN as they were.
	vlan, recordVLAN := s.vlanForState(state)
	recordVLAN = recordVLAN && s.vlanManager != nil
	if err := s.stateManager.TransitionWithUpdate(deviceID, state, reason, func(d *DeviceInfo) {
		if recordVLAN {
			d.CurrentVLAN = vlan
		}
	}); err != nil {
		// The record still says the device is where it was; put the port
		// back there unless the move only narrowed access (quarantined or
		// failed), whose restrictive flows stay in place.
		if state != StateQuarantined && state != StateFailed {
			s.restoreEnforcedFlows(ctx, device)
		}
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to transition device state",
			Cause:    err,
		}
	}

	s.logger.Info("Device state updated",
		"device_id", deviceID,
		"from_state", device.State,
		"to_state", state,
		"reason", reason,
	)

	return nil
}

// SetDeviceEnrolled marks a device as enrolled with the provided certificate serial.
func (s *service) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(StateEnrolled) {
		return ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(StateEnrolled),
			Reason:    "device must be in enrolling state",
		}
	}

	updateErr := s.stateManager.UpdateDevice(deviceID, func(d *DeviceInfo) error {
		d.CertificateSerial = certSerial
		return nil
	})
	if updateErr != nil {
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to update certificate serial",
			Cause:    updateErr,
		}
	}

	if err := s.stateManager.Transition(deviceID, StateEnrolled, "enrollment completed"); err != nil {
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to transition to enrolled state",
			Cause:    err,
		}
	}

	s.logger.Info("Device enrolled",
		"device_id", deviceID,
		"certificate_serial", certSerial,
	)

	return nil
}

// RecordIDevIDFingerprint stores the IDevID fingerprint (lower-case hex
// SHA-256 of the IDevID certificate's DER) the device presented at
// enrolment. Per ruling 70 and ruling 673, enrolment comes before install
// completion: the fingerprint is accepted while the device is discovered,
// booting or installing, and refused once the install is complete. It
// makes no state transition. Re-recording the same fingerprint is a no-op.
// A different fingerprint is a re-enrolment (for example a certificate
// delivery that failed after the finalize hook): it replaces the recorded
// one in every pre-completion state (discovered, booting, installing), and
// is refused once the install is complete; RetryDevice starts a new
// attempt and clears it.
func (s *service) RecordIDevIDFingerprint(ctx context.Context, deviceID, fingerprint string) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()
	if !isIDevIDFingerprint(fingerprint) {
		return ErrInvalidConfiguration{
			Field:  "idevid_fingerprint",
			Reason: "must be 64 lower-case hex characters (SHA-256)",
		}
	}

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	updateErr := s.stateManager.UpdateDevice(deviceID, func(d *DeviceInfo) error {
		switch d.State {
		case StateDiscovered, StateBooting, StateInstalling:
		default:
			return ErrInvalidStateTransition{
				DeviceID:  deviceID,
				FromState: string(d.State),
				ToState:   string(d.State),
				Reason:    "the IDevID fingerprint is recorded at enrolment, before install completion",
			}
		}
		// The finalize hook records before the CA commits the certificate,
		// so a storage or delivery failure there is followed by a
		// re-enrolment that issues a different IDevID. Before install
		// completion (discovered, booting or installing) the device has
		// reported no certificate in use, so the later fingerprint
		// replaces the earlier one in every one of those states; the
		// install-complete webhook then accepts only the IDevID the device
		// actually received, and past it the state check above refuses.
		d.IDevIDFingerprint = fingerprint
		return nil
	})
	if updateErr != nil {
		return updateErr
	}

	s.logger.Info("Device IDevID fingerprint recorded",
		"device_id", deviceID,
		"mac_address", device.MACAddress.String(),
		"idevid_fingerprint", fingerprint,
	)
	return nil
}

// isIDevIDFingerprint reports whether fp is a lower-case hex SHA-256 digest.
func isIDevIDFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// AuthorizeDevice authorizes a device for production network access.
func (s *service) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()

	if targetVLAN < MinVLANID || targetVLAN > MaxVLANID {
		return ErrVLANTransitionFailed{
			DeviceID: deviceID,
			ToVLAN:   targetVLAN,
			Reason:   "target VLAN out of valid range",
		}
	}

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(StateAuthorized) {
		return ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(StateAuthorized),
			Reason:    "device must be in authorizing state",
		}
	}

	oldVLAN := device.CurrentVLAN

	updateErr := s.stateManager.UpdateDevice(deviceID, func(d *DeviceInfo) error {
		d.TargetVLAN = targetVLAN
		return nil
	})
	if updateErr != nil {
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to update target VLAN",
			Cause:    updateErr,
		}
	}

	if s.vlanManager != nil {
		if vlanErr := s.vlanManager.ApplyAuthorizedFlows(ctx, device.PortID, device.MACAddress, targetVLAN); vlanErr != nil {
			return ErrVLANTransitionFailed{
				DeviceID: deviceID,
				FromVLAN: oldVLAN,
				ToVLAN:   targetVLAN,
				Reason:   "failed to apply production VLAN",
				Cause:    vlanErr,
			}
		}

	}

	// The lifecycle state and the enforced VLAN go to the store in one
	// record write; if it fails the flows just applied are undone (#2081
	// Codex), so no stored record pairs StateAuthorized with a stale VLAN.
	err = s.stateManager.TransitionWithUpdate(deviceID, StateAuthorized, "device authorized for production", func(d *DeviceInfo) {
		if s.vlanManager != nil {
			d.CurrentVLAN = targetVLAN
		}
	})
	if err != nil {
		s.undoFlows(ctx, device)
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to transition to authorized state",
			Cause:    err,
		}
	}

	s.logger.Info("Device authorized",
		"device_id", deviceID,
		"target_vlan", targetVLAN,
	)

	return nil
}

// QuarantineDevice moves a device to quarantine state.
func (s *service) QuarantineDevice(ctx context.Context, deviceID string, reason string) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(StateQuarantined) {
		return ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(StateQuarantined),
			Reason:    "cannot quarantine device from current state",
		}
	}

	oldVLAN := device.CurrentVLAN

	if s.vlanManager != nil {
		if vlanErr := s.vlanManager.ApplyQuarantineFlows(ctx, device.PortID, device.MACAddress); vlanErr != nil {
			return ErrVLANTransitionFailed{
				DeviceID: deviceID,
				FromVLAN: oldVLAN,
				ToVLAN:   s.config.QuarantineVLAN,
				Reason:   "failed to apply quarantine VLAN",
				Cause:    vlanErr,
			}
		}

	}

	// State and enforced VLAN in one record write. On failure the
	// quarantine flows stay in place: a datastore outage must never
	// restore the device's earlier (possibly production) access. The
	// stored state is unchanged and the caller retries the quarantine
	// (#2081 Codex).
	err = s.stateManager.TransitionWithUpdate(deviceID, StateQuarantined, reason, func(d *DeviceInfo) {
		if s.vlanManager != nil {
			d.CurrentVLAN = s.config.QuarantineVLAN
		}
	})
	if err != nil {
		s.logger.Warn("Quarantine state write failed; quarantine flows kept",
			"device_id", deviceID,
			"error", err.Error(),
		)
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to transition to quarantined state",
			Cause:    err,
		}
	}

	s.logger.Warn("Device quarantined",
		"device_id", deviceID,
		"reason", reason,
	)

	return nil
}

// undoFlows puts back the flows that match the device record as it was
// before a transition whose state write failed (#2081 Codex): authorized
// devices get their stored VLAN back, quarantined devices stay in
// quarantine, every other state returns to the provisioning flows.
func (s *service) undoFlows(ctx context.Context, before *DeviceInfo) {
	if s.vlanManager == nil || before == nil {
		return
	}
	var err error
	switch before.State {
	case StateAuthorized:
		err = s.vlanManager.ApplyAuthorizedFlows(ctx, before.PortID, before.MACAddress, before.CurrentVLAN)
	case StateQuarantined:
		err = s.vlanManager.ApplyQuarantineFlows(ctx, before.PortID, before.MACAddress)
	default:
		err = s.vlanManager.ApplyProvisioningFlows(ctx, before.PortID, before.MACAddress)
	}
	if err != nil {
		s.logger.Warn("Failed to undo flows after a failed state write",
			"device_id", before.ID,
			"error", err.Error(),
		)
	}
}

// restoreEnforcedFlows reinstalls the flows of the VLAN before records as
// enforced, after a state write failed. A device on the quarantine VLAN, in
// quarantined or failed state, or with no known VLAN goes back to the
// quarantine flows (fail closed).
func (s *service) restoreEnforcedFlows(ctx context.Context, before *DeviceInfo) {
	if s.vlanManager == nil || before == nil {
		return
	}
	var err error
	switch {
	case before.State == StateQuarantined || before.State == StateFailed ||
		before.CurrentVLAN == s.config.QuarantineVLAN:
		err = s.vlanManager.ApplyQuarantineFlows(ctx, before.PortID, before.MACAddress)
	case before.State == StateAuthorized && before.CurrentVLAN != 0:
		err = s.vlanManager.ApplyAuthorizedFlows(ctx, before.PortID, before.MACAddress, before.CurrentVLAN)
	case before.CurrentVLAN == s.config.ProvisioningVLAN:
		err = s.vlanManager.ApplyProvisioningFlows(ctx, before.PortID, before.MACAddress)
	default:
		err = s.vlanManager.ApplyQuarantineFlows(ctx, before.PortID, before.MACAddress)
	}
	if err != nil {
		s.logger.Warn("Failed to restore flows after a failed state write",
			"device_id", before.ID,
			"error", err.Error(),
		)
	}
}

// RetryDevice resets a device to discovered state for retry. A retry is a new
// provisioning attempt, so it clears the IDevID fingerprint the previous
// attempt recorded: the retried install enrols a new IDevID.
func (s *service) RetryDevice(ctx context.Context, deviceID string) error {
	if !s.beginOp() {
		return ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()
	defer s.lockDevice(deviceID)()

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(StateDiscovered) {
		return ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(StateDiscovered),
			Reason:    "cannot retry device from current state",
		}
	}

	if device.RetryCount >= s.config.MaxRetries {
		return ErrMaxRetriesExceeded{
			Operation:  "device provisioning",
			MaxRetries: s.config.MaxRetries,
			Reason:     "maximum retry count exceeded",
		}
	}

	// Counter, fingerprint reset and transition in one record write, so
	// a failed write never consumes a retry that did not start.
	reason := fmt.Sprintf("retry initiated (attempt %d)", device.RetryCount+1)
	if err := s.stateManager.TransitionWithUpdate(deviceID, StateDiscovered, reason, func(d *DeviceInfo) {
		d.RetryCount++
		d.IDevIDFingerprint = ""
	}); err != nil {
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to transition to discovered state",
			Cause:    err,
		}
	}

	s.logger.Info("Device retry initiated",
		"device_id", deviceID,
		"retry_count", device.RetryCount+1,
	)

	return nil
}

// GetEvents retrieves all events for a device.
func (s *service) GetEvents(ctx context.Context, deviceID string) ([]*ProvisioningEvent, error) {
	if !s.beginOp() {
		return nil, ErrServiceNotInitialized{}
	}
	defer s.ops.RUnlock()

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return nil, ErrDeviceNotFound{DeviceID: deviceID}
	}

	return device.Events, nil
}

// RegisterEventHandler adds an event handler to receive provisioning events.
func (s *service) RegisterEventHandler(handler EventHandler) {
	s.stateManager.RegisterEventHandler(handler)
}

// Status returns the current service status.
func (s *service) Status() *ServiceStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := &ServiceStatus{
		Running: s.running.Load(),
	}

	if s.config != nil {
		status.QuarantineVLAN = s.config.QuarantineVLAN
		status.ProvisioningVLAN = s.config.ProvisioningVLAN

		if s.config.IPXEConfig != nil {
			if s.ipxeServer != nil {
				status.IPXEServerAddr = s.ipxeServer.ServerIP().String()
			}
		}
	}

	if s.running.Load() {
		status.StartTime = s.startTime
	}

	if s.stateManager != nil {
		status.DeviceCount = s.stateManager.Count()
	}

	return status
}

// generateDeviceID creates a unique device ID from the MAC address.
func generateDeviceID(mac net.HardwareAddr) string {
	hash := sha256.Sum256(mac)
	return "device-" + hex.EncodeToString(hash[:8])
}

// applyVLANForState applies the appropriate VLAN for the given state.
func (s *service) applyVLANForState(ctx context.Context, device *DeviceInfo, state ProvisioningState) error {
	if s.vlanManager == nil {
		return nil
	}

	switch state {
	case StateBooting, StateInstalling, StateInstallComplete, StateEnrolling, StateEnrolled, StateAuthorizing:
		return s.vlanManager.ApplyProvisioningFlows(ctx, device.PortID, device.MACAddress)

	case StateQuarantined, StateFailed:
		return s.vlanManager.ApplyQuarantineFlows(ctx, device.PortID, device.MACAddress)

	default:
		return nil
	}
}

// vlanForState returns the VLAN applyVLANForState moves a device's port to
// for state, and false when the state moves no flows.
func (s *service) vlanForState(state ProvisioningState) (uint16, bool) {
	switch state {
	case StateBooting, StateInstalling, StateInstallComplete, StateEnrolling, StateEnrolled, StateAuthorizing:
		return s.config.ProvisioningVLAN, true

	case StateQuarantined, StateFailed:
		return s.config.QuarantineVLAN, true

	default:
		return 0, false
	}
}
