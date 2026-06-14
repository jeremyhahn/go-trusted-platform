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

package device

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// Typed errors for SDN integration operations.
var (
	// ErrSDNIntegrationNil indicates that the SDN integration instance is nil.
	ErrSDNIntegrationNil = errors.New("sdn integration is nil")

	// ErrInvalidNetworkEvent indicates that the network event type is invalid.
	ErrInvalidNetworkEvent = errors.New("invalid network event")

	// ErrInvalidNetworkPhase indicates that the network phase is invalid.
	ErrInvalidNetworkPhase = errors.New("invalid network phase")

	// ErrNetworkPhaseNotConfigured indicates that the requested network phase
	// is not configured in the device profile.
	ErrNetworkPhaseNotConfigured = errors.New("network phase not configured")

	// ErrProfileNil indicates that the device profile is nil.
	ErrProfileNil = errors.New("device profile is nil")

	// ErrPortIDEmpty indicates that the port ID is empty.
	ErrPortIDEmpty = errors.New("port ID is empty")

	// ErrMACEmpty indicates that the MAC address is empty.
	ErrMACEmpty = errors.New("MAC address is empty")
)

// NetworkEvent represents the type of network event that triggered the callback.
type NetworkEvent int

const (
	// NetworkEventConnect indicates a device has connected to the network.
	NetworkEventConnect NetworkEvent = iota

	// NetworkEventEnrolled indicates a device has completed enrollment.
	NetworkEventEnrolled

	// NetworkEventComplianceFail indicates a device has failed compliance checks.
	NetworkEventComplianceFail

	// NetworkEventDisconnect indicates a device has disconnected from the network.
	NetworkEventDisconnect
)

// String returns the string representation of NetworkEvent.
func (e NetworkEvent) String() string {
	switch e {
	case NetworkEventConnect:
		return "connect"
	case NetworkEventEnrolled:
		return "enrolled"
	case NetworkEventComplianceFail:
		return "compliance_fail"
	case NetworkEventDisconnect:
		return "disconnect"
	default:
		return "unknown"
	}
}

// IsValid checks if the NetworkEvent is a valid event type.
func (e NetworkEvent) IsValid() bool {
	return e >= NetworkEventConnect && e <= NetworkEventDisconnect
}

// NetworkPhase represents the network phase a device is in during its lifecycle.
type NetworkPhase string

const (
	// NetworkPhaseProvisioning indicates the device is in the provisioning network.
	NetworkPhaseProvisioning NetworkPhase = "provisioning"

	// NetworkPhaseTrusted indicates the device is in the trusted (post-enrollment) network.
	NetworkPhaseTrusted NetworkPhase = "trusted"

	// NetworkPhaseQuarantine indicates the device is in the quarantine network.
	NetworkPhaseQuarantine NetworkPhase = "quarantine"
)

// String returns the string representation of NetworkPhase.
func (p NetworkPhase) String() string {
	return string(p)
}

// IsValid checks if the NetworkPhase is a valid phase.
func (p NetworkPhase) IsValid() bool {
	switch p {
	case NetworkPhaseProvisioning, NetworkPhaseTrusted, NetworkPhaseQuarantine:
		return true
	default:
		return false
	}
}

// NetworkEventContext contains contextual information about a network event.
// This context is passed to SDN integration callbacks to provide all necessary
// information for network configuration decisions.
type NetworkEventContext struct {
	// DeviceID is the unique identifier of the device.
	DeviceID string

	// PortID is the SDN port identifier where the device is connected.
	PortID string

	// MAC is the MAC address of the device.
	MAC string

	// Serial is the serial number of the device.
	Serial string

	// Profile is the device profile containing network configuration.
	Profile *entities.DeviceProfile

	// Phase is the target network phase for the device.
	Phase NetworkPhase

	// Reason provides additional context about why the event occurred.
	Reason string

	// Metadata contains additional key-value pairs for extensibility.
	Metadata map[string]string
}

// Validate checks if the NetworkEventContext contains required fields.
func (c *NetworkEventContext) Validate() error {
	if c.PortID == "" {
		return ErrPortIDEmpty
	}
	if c.MAC == "" {
		return ErrMACEmpty
	}
	if c.Profile == nil {
		return ErrProfileNil
	}
	if !c.Phase.IsValid() {
		return ErrInvalidNetworkPhase
	}
	return nil
}

// SDNIntegration defines the interface for integrating with Software-Defined
// Networking controllers. Implementations of this interface handle network
// configuration changes in response to device lifecycle events.
type SDNIntegration interface {
	// OnDeviceConnect is called when a device connects to the network.
	// The implementation should configure the port for initial device assessment,
	// typically placing it in a provisioning or assessment VLAN.
	OnDeviceConnect(ctx context.Context, event *NetworkEventContext) error

	// OnDeviceEnrolled is called when a device successfully completes enrollment.
	// The implementation should transition the device to its trusted network
	// configuration based on the device profile.
	OnDeviceEnrolled(ctx context.Context, event *NetworkEventContext) error

	// OnComplianceFail is called when a device fails compliance checks.
	// The implementation should move the device to a quarantine network
	// to limit its access while the compliance issue is addressed.
	OnComplianceFail(ctx context.Context, event *NetworkEventContext) error

	// ApplyNetworkPhase applies the network configuration for the specified phase.
	// This method can be used to explicitly set a device's network phase
	// independent of lifecycle events.
	ApplyNetworkPhase(ctx context.Context, event *NetworkEventContext) error

	// GetPortState retrieves the current state of an SDN port.
	// Returns the current VLAN or network configuration state as a string.
	GetPortState(ctx context.Context, portID string) (string, error)
}
