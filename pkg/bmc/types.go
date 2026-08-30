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

package bmc

import "context"

// PowerState represents the power state of a BMC-managed system.
type PowerState string

const (
	// PowerStateOn indicates the system is powered on.
	PowerStateOn PowerState = "on"

	// PowerStateOff indicates the system is powered off.
	PowerStateOff PowerState = "off"

	// PowerStateUnknown indicates the power state cannot be determined.
	PowerStateUnknown PowerState = "unknown"
)

// validPowerStates is a map-based lookup for valid power states.
var validPowerStates = map[PowerState]struct{}{
	PowerStateOn:      {},
	PowerStateOff:     {},
	PowerStateUnknown: {},
}

// IsValid returns true if the PowerState is a recognized value.
func (p PowerState) IsValid() bool {
	_, ok := validPowerStates[p]
	return ok
}

// BootDevice represents a boot device selectable via BMC.
type BootDevice string

const (
	// BootDevicePXE selects PXE network boot.
	BootDevicePXE BootDevice = "pxe"

	// BootDeviceDisk selects the local disk.
	BootDeviceDisk BootDevice = "disk"

	// BootDeviceCDROM selects the CD-ROM drive.
	BootDeviceCDROM BootDevice = "cdrom"

	// BootDeviceVirtualMedia selects virtual media.
	BootDeviceVirtualMedia BootDevice = "virtual_media"

	// BootDeviceNone selects no boot device override.
	BootDeviceNone BootDevice = "none"
)

// validBootDevices is a map-based lookup for valid boot devices.
var validBootDevices = map[BootDevice]struct{}{
	BootDevicePXE:          {},
	BootDeviceDisk:         {},
	BootDeviceCDROM:        {},
	BootDeviceVirtualMedia: {},
	BootDeviceNone:         {},
}

// IsValid returns true if the BootDevice is a recognized value.
func (b BootDevice) IsValid() bool {
	_, ok := validBootDevices[b]
	return ok
}

// Protocol represents the BMC communication protocol.
type Protocol string

const (
	// ProtocolIPMI selects the IPMI protocol.
	ProtocolIPMI Protocol = "ipmi"

	// ProtocolRedfish selects the Redfish protocol.
	ProtocolRedfish Protocol = "redfish"
)

// validProtocols is a map-based lookup for valid protocols.
var validProtocols = map[Protocol]struct{}{
	ProtocolIPMI:    {},
	ProtocolRedfish: {},
}

// IsValid returns true if the Protocol is a recognized value.
func (p Protocol) IsValid() bool {
	_, ok := validProtocols[p]
	return ok
}

// SensorReading represents a single sensor reading from the BMC.
type SensorReading struct {
	Name   string  `json:"name" yaml:"name"`
	Value  float64 `json:"value" yaml:"value"`
	Units  string  `json:"units" yaml:"units"`
	Status string  `json:"status" yaml:"status"` // "ok", "warning", "critical"
}

// SystemInfo contains system identification information from the BMC.
type SystemInfo struct {
	Manufacturer    string     `json:"manufacturer" yaml:"manufacturer"`
	Product         string     `json:"product" yaml:"product"`
	SerialNumber    string     `json:"serial_number" yaml:"serial_number"`
	FirmwareVersion string     `json:"firmware_version" yaml:"firmware_version"`
	BIOSVersion     string     `json:"bios_version" yaml:"bios_version"`
	PowerState      PowerState `json:"power_state" yaml:"power_state"`
}

// VirtualMediaInfo describes the current state of virtual media.
type VirtualMediaInfo struct {
	Mounted   bool   `json:"mounted" yaml:"mounted"`
	ImageURL  string `json:"image_url,omitempty" yaml:"image_url,omitempty"`
	MediaType string `json:"media_type,omitempty" yaml:"media_type,omitempty"` // "iso", "floppy"
}

// Client is the interface for interacting with a BMC.
type Client interface {
	// PowerOn powers on the system.
	PowerOn(ctx context.Context) error

	// PowerOff powers off the system.
	PowerOff(ctx context.Context) error

	// PowerReset performs a hard reset of the system.
	PowerReset(ctx context.Context) error

	// PowerCycle power cycles the system (off then on).
	PowerCycle(ctx context.Context) error

	// PowerStatus returns the current power state.
	PowerStatus(ctx context.Context) (PowerState, error)

	// SetBootDevice sets the next boot device.
	SetBootDevice(ctx context.Context, device BootDevice, persistent bool) error

	// GetBootDevice returns the current boot device override.
	GetBootDevice(ctx context.Context) (BootDevice, error)

	// MountISO mounts an ISO image via virtual media. It is a convenience
	// wrapper around MountVirtualMedia for the common HTTP/HTTPS ISO case.
	MountISO(ctx context.Context, isoURL string) error

	// UnmountISO unmounts the currently mounted ISO virtual media.
	UnmountISO(ctx context.Context) error

	// MountVirtualMedia mounts a virtual media image described by spec.
	// The implementation walks an internal backend chain (standard Redfish,
	// vendor OEM Redfish, vendor CGI) until one succeeds.
	MountVirtualMedia(ctx context.Context, spec *MediaSpec) error

	// UnmountVirtualMedia ejects whatever virtual media is currently inserted.
	UnmountVirtualMedia(ctx context.Context) error

	// VirtualMediaStatus returns the current virtual media state.
	VirtualMediaStatus(ctx context.Context) (*VirtualMediaInfo, error)

	// GetSensors returns sensor readings from the BMC.
	GetSensors(ctx context.Context) ([]SensorReading, error)

	// GetSystemInfo returns system identification information.
	GetSystemInfo(ctx context.Context) (*SystemInfo, error)

	// Console opens an interactive SOL (Serial Over LAN) console session.
	// The returned SOLSession implements io.ReadWriteCloser for bidirectional
	// character streaming with the BMC serial console.
	Console(ctx context.Context) (*SOLSession, error)

	// ClearUEFIBootEntries asks the BMC to clear the host's UEFI NVRAM
	// boot entries, resetting the BIOS to its factory boot order. The
	// orchestrator calls this before re-imaging a node whose existing
	// UEFI "Linux Boot Manager" entry would otherwise win over a one-shot
	// boot override (notably on Supermicro X10 hardware).
	//
	// Implementations SHOULD prefer the Redfish ComputerSystem.Reset
	// action with ResetType "BiosReset" when the BMC advertises it.
	// When the BMC does not expose any clear path, return
	// ErrUEFIBootClearUnsupported so the caller can route to a vendor
	// CGI fallback or surface the limitation to the operator.
	//
	// This call typically requires the host to be reset to take effect;
	// callers are expected to PowerReset (or PowerOff/PowerOn) afterwards.
	ClearUEFIBootEntries(ctx context.Context) error

	// GetEventLog reads the BMC's System Event Log: every record plus the
	// BMC's own overflow / free-space accounting. Implementations that
	// have no log surface return ErrUnsupportedOperation.
	GetEventLog(ctx context.Context) (*EventLog, error)

	// Close releases resources held by the client.
	Close() error
}

// ClientFactory creates BMC clients from configuration.
type ClientFactory interface {
	// NewClient creates a new BMC client from the given configuration.
	NewClient(config *Config) (Client, error)
}

// ProfileStore provides access to device profiles containing BMC configuration.
type ProfileStore interface {
	// Get retrieves a device profile by its ID.
	Get(ctx context.Context, id uint64) (*Config, error)
}
