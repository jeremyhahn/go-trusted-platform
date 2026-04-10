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

//go:build integration

package pxe

import (
	"context"
	"time"
)

// PXECommands defines the central command set for PXE provisioning integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix Socket) implements this interface.
// Tests are written once against this interface and run against all protocols.
type PXECommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Device Management Commands (platformctl pxe device ...)
	RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error)
	GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error)
	GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error)
	ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error)
	RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error)

	// State Management Commands (platformctl pxe state ...)
	UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error)
	SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error)
	AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error)
	QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error)
	RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error)

	// Event Commands (platformctl pxe events ...)
	GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error)

	// Service Status Commands (platformctl pxe status)
	GetStatus(ctx context.Context) (*GetStatusResult, error)
}

// =============================================================================
// Device Management Options and Results
// =============================================================================

// RegisterDeviceOptions contains options for registering a new device.
type RegisterDeviceOptions struct {
	MACAddress string
	PortID     string
}

// RegisterDeviceResult contains the result of a device registration operation.
type RegisterDeviceResult struct {
	ID          string
	MACAddress  string
	PortID      string
	State       string
	StateReason string
	CurrentVLAN uint16
	CreatedAt   time.Time
}

// GetDeviceResult contains the result of a device retrieval operation.
type GetDeviceResult struct {
	ID                string
	MACAddress        string
	PortID            string
	State             string
	StateReason       string
	CertificateSerial string
	CurrentVLAN       uint16
	TargetVLAN        uint16
	RetryCount        int
	CreatedAt         time.Time
	UpdatedAt         time.Time
	StateChangedAt    time.Time
}

// ListDevicesOptions contains options for listing devices.
type ListDevicesOptions struct {
	State      string
	MACAddress string
	VLAN       uint16
	Limit      int32
	Offset     int32
}

// ListDevicesResult contains the result of a device list operation.
type ListDevicesResult struct {
	Devices    []DeviceSummary
	TotalCount int32
	HasMore    bool
}

// DeviceSummary contains summary information about a device.
type DeviceSummary struct {
	ID          string
	MACAddress  string
	PortID      string
	State       string
	CurrentVLAN uint16
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RemoveDeviceResult contains the result of a device removal operation.
type RemoveDeviceResult struct {
	ID      string
	Removed bool
}

// =============================================================================
// State Management Options and Results
// =============================================================================

// UpdateStateOptions contains options for updating device state.
type UpdateStateOptions struct {
	DeviceID string
	State    string
	Reason   string
}

// UpdateStateResult contains the result of a state update operation.
type UpdateStateResult struct {
	ID        string
	FromState string
	ToState   string
	Reason    string
	UpdatedAt time.Time
}

// SetEnrolledResult contains the result of setting a device as enrolled.
type SetEnrolledResult struct {
	ID                string
	State             string
	CertificateSerial string
	UpdatedAt         time.Time
}

// AuthorizeResult contains the result of authorizing a device.
type AuthorizeResult struct {
	ID         string
	State      string
	TargetVLAN uint16
	UpdatedAt  time.Time
}

// QuarantineResult contains the result of quarantining a device.
type QuarantineResult struct {
	ID          string
	State       string
	Reason      string
	CurrentVLAN uint16
	UpdatedAt   time.Time
}

// RetryResult contains the result of retrying a device.
type RetryResult struct {
	ID         string
	State      string
	RetryCount int
	UpdatedAt  time.Time
}

// =============================================================================
// Event Options and Results
// =============================================================================

// GetEventsResult contains the result of getting device events.
type GetEventsResult struct {
	DeviceID string
	Events   []ProvisioningEventInfo
}

// ProvisioningEventInfo contains information about a provisioning event.
type ProvisioningEventInfo struct {
	ID        string
	DeviceID  string
	EventType string
	FromState string
	ToState   string
	Details   map[string]string
	Error     string
	Timestamp time.Time
}

// =============================================================================
// Service Status Results
// =============================================================================

// GetStatusResult contains the result of getting service status.
type GetStatusResult struct {
	Running          bool
	DeviceCount      int
	StartTime        time.Time
	IPXEServerAddr   string
	QuarantineVLAN   uint16
	ProvisioningVLAN uint16
}
