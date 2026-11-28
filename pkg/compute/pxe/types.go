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
	"net"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// ProvisioningState represents the current state of a device in the provisioning workflow
type ProvisioningState string

const (
	// StateUnknown indicates the device state is unknown
	StateUnknown ProvisioningState = "unknown"

	// StateDiscovered indicates the device has been discovered on the network
	StateDiscovered ProvisioningState = "discovered"

	// StateBooting indicates the device is PXE booting
	StateBooting ProvisioningState = "booting"

	// StateInstalling indicates the device is installing the OS
	StateInstalling ProvisioningState = "installing"

	// StateInstallComplete indicates the OS installation has completed
	StateInstallComplete ProvisioningState = "install_complete"

	// StateEnrolling indicates the device is enrolling with the PKI
	StateEnrolling ProvisioningState = "enrolling"

	// StateEnrolled indicates the device has completed PKI enrollment
	StateEnrolled ProvisioningState = "enrolled"

	// StateAuthorizing indicates the device is authorizing for production network
	StateAuthorizing ProvisioningState = "authorizing"

	// StateAuthorized indicates the device is authorized for production network
	StateAuthorized ProvisioningState = "authorized"

	// StateFailed indicates the provisioning process has failed
	StateFailed ProvisioningState = "failed"

	// StateQuarantined indicates the device has been quarantined
	StateQuarantined ProvisioningState = "quarantined"
)

// String returns the string representation of ProvisioningState
func (s ProvisioningState) String() string {
	return string(s)
}

// IsValid checks if the ProvisioningState is valid
func (s ProvisioningState) IsValid() bool {
	switch s {
	case StateUnknown, StateDiscovered, StateBooting, StateInstalling,
		StateInstallComplete, StateEnrolling, StateEnrolled,
		StateAuthorizing, StateAuthorized, StateFailed, StateQuarantined:
		return true
	default:
		return false
	}
}

// IsTerminal checks if the state is a terminal state
func (s ProvisioningState) IsTerminal() bool {
	return s == StateAuthorized || s == StateFailed || s == StateQuarantined
}

// CanTransitionTo checks if a transition to the target state is valid
func (s ProvisioningState) CanTransitionTo(target ProvisioningState) bool {
	validTransitions := map[ProvisioningState][]ProvisioningState{
		StateUnknown:         {StateDiscovered, StateFailed, StateQuarantined},
		StateDiscovered:      {StateBooting, StateFailed, StateQuarantined},
		StateBooting:         {StateInstalling, StateFailed, StateQuarantined},
		StateInstalling:      {StateInstallComplete, StateFailed, StateQuarantined},
		StateInstallComplete: {StateEnrolling, StateFailed, StateQuarantined},
		StateEnrolling:       {StateEnrolled, StateFailed, StateQuarantined},
		StateEnrolled:        {StateAuthorizing, StateFailed, StateQuarantined},
		StateAuthorizing:     {StateAuthorized, StateFailed, StateQuarantined},
		StateAuthorized:      {StateQuarantined},
		StateFailed:          {StateDiscovered, StateQuarantined},
		StateQuarantined:     {StateDiscovered},
	}

	allowed, exists := validTransitions[s]
	if !exists {
		return false
	}

	for _, state := range allowed {
		if state == target {
			return true
		}
	}
	return false
}

// DeviceInfo tracks a device through the provisioning workflow
type DeviceInfo struct {
	// ID is the unique identifier for this device (typically MAC-based)
	ID string `json:"id" yaml:"id"`

	// MACAddress is the hardware address of the device
	MACAddress net.HardwareAddr `json:"mac_address" yaml:"mac_address"`

	// PortID is the OVS port identifier for this device
	PortID string `json:"port_id" yaml:"port_id"`

	// State is the current provisioning state
	State ProvisioningState `json:"state" yaml:"state"`

	// StateReason provides context for why the device is in the current state
	StateReason string `json:"state_reason,omitempty" yaml:"state_reason,omitempty"`

	// Profile is the device profile linked to this device
	Profile *entities.DeviceProfile `json:"profile,omitempty" yaml:"profile,omitempty"`

	// CertificateSerial is the serial number of the certificate after enrollment
	CertificateSerial string `json:"certificate_serial,omitempty" yaml:"certificate_serial,omitempty"`

	// CurrentVLAN is the VLAN the device is currently assigned to
	CurrentVLAN uint16 `json:"current_vlan" yaml:"current_vlan"`

	// TargetVLAN is the VLAN the device should be moved to (from profile)
	TargetVLAN uint16 `json:"target_vlan" yaml:"target_vlan"`

	// CreatedAt is when the device was first discovered
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// UpdatedAt is when the device was last updated
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`

	// StateChangedAt is when the device last changed state
	StateChangedAt time.Time `json:"state_changed_at" yaml:"state_changed_at"`

	// RetryCount tracks the number of retry attempts
	RetryCount int `json:"retry_count" yaml:"retry_count"`

	// Events is the audit trail of provisioning events
	Events []*ProvisioningEvent `json:"events,omitempty" yaml:"events,omitempty"`
}

// DeviceFilter provides filtering options for listing devices
type DeviceFilter struct {
	// State filters by provisioning state
	State ProvisioningState `json:"state,omitempty" yaml:"state,omitempty"`

	// MACAddress filters by MAC address (exact or prefix match)
	MACAddress string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`

	// VLAN filters by current VLAN assignment
	VLAN uint16 `json:"vlan,omitempty" yaml:"vlan,omitempty"`

	// Limit is the maximum number of results to return
	Limit int `json:"limit,omitempty" yaml:"limit,omitempty"`

	// Offset is the number of results to skip
	Offset int `json:"offset,omitempty" yaml:"offset,omitempty"`
}

// Matches checks if a device matches the filter criteria
func (f *DeviceFilter) Matches(device *DeviceInfo) bool {
	if device == nil {
		return false
	}

	if f.State != "" && device.State != f.State {
		return false
	}

	if f.MACAddress != "" {
		macStr := device.MACAddress.String()
		if macStr != f.MACAddress && !hasPrefix(macStr, f.MACAddress) {
			return false
		}
	}

	if f.VLAN != 0 && device.CurrentVLAN != f.VLAN {
		return false
	}

	return true
}

// hasPrefix checks if s starts with prefix
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ProvisioningEventType represents the type of provisioning event
type ProvisioningEventType string

const (
	// EventDeviceDiscovered indicates a new device was discovered
	EventDeviceDiscovered ProvisioningEventType = "device_discovered"

	// EventPXEBootStarted indicates PXE boot has started
	EventPXEBootStarted ProvisioningEventType = "pxe_boot_started"

	// EventInstallStarted indicates OS installation has started
	EventInstallStarted ProvisioningEventType = "install_started"

	// EventInstallCompleted indicates OS installation has completed
	EventInstallCompleted ProvisioningEventType = "install_completed"

	// EventEnrollmentStarted indicates PKI enrollment has started
	EventEnrollmentStarted ProvisioningEventType = "enrollment_started"

	// EventEnrollmentCompleted indicates PKI enrollment has completed
	EventEnrollmentCompleted ProvisioningEventType = "enrollment_completed"

	// EventAuthorizationStarted indicates network authorization has started
	EventAuthorizationStarted ProvisioningEventType = "authorization_started"

	// EventAuthorizationCompleted indicates network authorization has completed
	EventAuthorizationCompleted ProvisioningEventType = "authorization_completed"

	// EventQuarantined indicates the device was quarantined
	EventQuarantined ProvisioningEventType = "quarantined"

	// EventFailed indicates a failure occurred
	EventFailed ProvisioningEventType = "failed"

	// EventRetry indicates a retry attempt
	EventRetry ProvisioningEventType = "retry"
)

// String returns the string representation of ProvisioningEventType
func (t ProvisioningEventType) String() string {
	return string(t)
}

// IsValid checks if the ProvisioningEventType is valid
func (t ProvisioningEventType) IsValid() bool {
	switch t {
	case EventDeviceDiscovered, EventPXEBootStarted, EventInstallStarted,
		EventInstallCompleted, EventEnrollmentStarted, EventEnrollmentCompleted,
		EventAuthorizationStarted, EventAuthorizationCompleted,
		EventQuarantined, EventFailed, EventRetry:
		return true
	default:
		return false
	}
}

// ProvisioningEvent represents an event in the provisioning workflow
type ProvisioningEvent struct {
	// ID is the unique identifier for this event
	ID string `json:"id" yaml:"id"`

	// DeviceID is the ID of the device this event belongs to
	DeviceID string `json:"device_id" yaml:"device_id"`

	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	// EventType is the type of event
	EventType ProvisioningEventType `json:"event_type" yaml:"event_type"`

	// FromState is the state before the event
	FromState ProvisioningState `json:"from_state" yaml:"from_state"`

	// ToState is the state after the event
	ToState ProvisioningState `json:"to_state" yaml:"to_state"`

	// Details contains additional event-specific information
	Details map[string]string `json:"details,omitempty" yaml:"details,omitempty"`

	// Error contains error information if the event represents a failure
	Error string `json:"error,omitempty" yaml:"error,omitempty"`
}

// EventHandler is an interface for handling provisioning events
type EventHandler interface {
	// OnEvent is called when a provisioning event occurs
	OnEvent(ctx context.Context, event *ProvisioningEvent)
}

// WebhookPayload represents the payload sent to the webhook when OS installation completes
type WebhookPayload struct {
	// MACAddress is the MAC address of the device
	MACAddress string `json:"mac_address"`

	// Hostname is the hostname assigned to the device
	Hostname string `json:"hostname"`

	// Success indicates whether the installation was successful
	Success bool `json:"success"`

	// Message contains additional information about the installation
	Message string `json:"message"`

	// Timestamp is when the installation completed
	Timestamp time.Time `json:"timestamp"`
}

// ServiceStatus represents the current status of the PXE provisioning service
type ServiceStatus struct {
	// Running indicates whether the service is running
	Running bool `json:"running" yaml:"running"`

	// DeviceCount is the number of devices being tracked
	DeviceCount int `json:"device_count" yaml:"device_count"`

	// StartTime is when the service was started
	StartTime time.Time `json:"start_time" yaml:"start_time"`

	// IPXEServerAddr is the address of the iPXE server
	IPXEServerAddr string `json:"ipxe_server_addr" yaml:"ipxe_server_addr"`

	// QuarantineVLAN is the VLAN ID for quarantined devices
	QuarantineVLAN uint16 `json:"quarantine_vlan" yaml:"quarantine_vlan"`

	// ProvisioningVLAN is the VLAN ID for provisioning devices
	ProvisioningVLAN uint16 `json:"provisioning_vlan" yaml:"provisioning_vlan"`
}
