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
	SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) error
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
	config       *ServiceConfig
	ipxeServer   *ipxe.Server
	stateManager *StateManager
	vlanManager  VLANIntegration
	logger       *logging.Logger

	running     atomic.Bool
	initialized atomic.Bool
	startTime   time.Time

	mu sync.RWMutex
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

// Start starts the PXE provisioning service.
func (s *service) Start(ctx context.Context) error {
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if s.running.Load() {
		return ErrServiceAlreadyRunning{}
	}

	s.mu.Lock()
	s.startTime = time.Now()
	s.mu.Unlock()

	s.running.Store(true)

	s.logger.Info("Starting PXE provisioning service")

	if err := s.ipxeServer.Start(ctx); err != nil {
		s.running.Store(false)
		return ErrProvisioningFailed{
			Reason: "failed to start iPXE server",
			Cause:  err,
		}
	}

	return nil
}

// Stop stops the PXE provisioning service.
func (s *service) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return ErrServiceNotRunning{}
	}

	s.logger.Info("Stopping PXE provisioning service")

	if err := s.ipxeServer.Stop(); err != nil {
		return ErrProvisioningFailed{
			Reason: "failed to stop iPXE server",
			Cause:  err,
		}
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
	if s.running.Load() {
		if err := s.Stop(context.Background()); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.initialized.Store(false)
	s.config = nil
	s.ipxeServer = nil

	s.logger.Info("PXE provisioning service closed")

	return nil
}

// RegisterDevice registers a new device for provisioning.
func (s *service) RegisterDevice(ctx context.Context, macAddress, portID string) (*DeviceInfo, error) {
	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, ErrInvalidMACAddress{
			MACAddress: macAddress,
			Reason:     err.Error(),
		}
	}

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

	if err := s.stateManager.Register(device); err != nil {
		return nil, ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to register device",
			Cause:    err,
		}
	}

	if s.vlanManager != nil {
		if vlanErr := s.vlanManager.ApplyQuarantineFlows(ctx, portID, mac); vlanErr != nil {
			s.logger.Warn("Failed to apply quarantine VLAN",
				"device_id", deviceID,
				"port_id", portID,
				"error", vlanErr.Error(),
			)
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
	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	device, err := s.stateManager.Get(deviceID)
	if err != nil {
		return nil, ErrDeviceNotFound{DeviceID: deviceID}
	}

	return device, nil
}

// GetDeviceByMAC retrieves a device by its MAC address.
func (s *service) GetDeviceByMAC(ctx context.Context, mac string) (*DeviceInfo, error) {
	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

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
	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	return s.stateManager.List(filter), nil
}

// RemoveDevice removes a device from the service.
func (s *service) RemoveDevice(ctx context.Context, deviceID string) error {
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

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
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

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

	if err := s.applyVLANForState(ctx, device, state); err != nil {
		s.logger.Warn("Failed to apply VLAN for state transition",
			"device_id", deviceID,
			"state", state,
			"error", err.Error(),
		)
	}

	if err := s.stateManager.Transition(deviceID, state, reason); err != nil {
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
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

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

// AuthorizeDevice authorizes a device for production network access.
func (s *service) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) error {
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

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

		updateErr = s.stateManager.UpdateDevice(deviceID, func(d *DeviceInfo) error {
			d.CurrentVLAN = targetVLAN
			return nil
		})
		if updateErr != nil {
			s.logger.Warn("Failed to update current VLAN in state",
				"device_id", deviceID,
				"error", updateErr.Error(),
			)
		}
	}

	if err := s.stateManager.Transition(deviceID, StateAuthorized, "device authorized for production"); err != nil {
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
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

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

		updateErr := s.stateManager.UpdateDevice(deviceID, func(d *DeviceInfo) error {
			d.CurrentVLAN = s.config.QuarantineVLAN
			return nil
		})
		if updateErr != nil {
			s.logger.Warn("Failed to update current VLAN in state",
				"device_id", deviceID,
				"error", updateErr.Error(),
			)
		}
	}

	if err := s.stateManager.Transition(deviceID, StateQuarantined, reason); err != nil {
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

// RetryDevice resets a device to discovered state for retry.
func (s *service) RetryDevice(ctx context.Context, deviceID string) error {
	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

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

	updateErr := s.stateManager.UpdateDevice(deviceID, func(d *DeviceInfo) error {
		d.RetryCount++
		return nil
	})
	if updateErr != nil {
		return ErrProvisioningFailed{
			DeviceID: deviceID,
			Reason:   "failed to increment retry count",
			Cause:    updateErr,
		}
	}

	if err := s.stateManager.Transition(deviceID, StateDiscovered, fmt.Sprintf("retry initiated (attempt %d)", device.RetryCount+1)); err != nil {
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
	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

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
