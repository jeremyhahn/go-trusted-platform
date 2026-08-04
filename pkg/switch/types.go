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

// Package switchmgmt provides physical switch management for PXE bootstrap.
// It automates VLAN and port configuration on physical network switches
// using SSH CLI commands compatible with Cisco IOS, IOS-XE, NX-OS, Arista
// EOS, and similar platforms.
package switchmgmt

import "context"

// SwitchVendor identifies the switch vendor/platform.
type SwitchVendor string

const (
	// VendorCiscoNexus represents Cisco Nexus switches running NX-OS.
	VendorCiscoNexus SwitchVendor = "cisco-nexus"

	// VendorNoop represents a no-op configurator for testing.
	VendorNoop SwitchVendor = "noop"
)

// VLANConfig defines a VLAN to be configured on the switch.
type VLANConfig struct {
	ID          int    `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Subnet      string `yaml:"subnet" json:"subnet"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// PortConfig defines a switch port configuration.
type PortConfig struct {
	Port        string `yaml:"port" json:"port"`                                   // e.g., "Eth1/1", "Eth1/3-5"
	Mode        string `yaml:"mode" json:"mode"`                                   // "trunk" | "access"
	VLANs       []int  `yaml:"vlans,omitempty" json:"vlans,omitempty"`             // For trunk: allowed VLANs
	AccessVLAN  int    `yaml:"access_vlan,omitempty" json:"access_vlan,omitempty"` // For access: VLAN ID
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Config holds switch connection and configuration details.
type Config struct {
	Name     string       `yaml:"name" json:"name"`
	Vendor   SwitchVendor `yaml:"vendor" json:"vendor"`
	Host     string       `yaml:"host" json:"host"`
	Port     int          `yaml:"port" json:"port"`
	User     string       `yaml:"user" json:"user"`
	Password string       `yaml:"password,omitempty" json:"password,omitempty" secret:"true"`
	SSHKey   string       `yaml:"ssh_key,omitempty" json:"ssh_key,omitempty"`
	// KnownHostsPath is the directory of pinned SSH host-key envelopes used
	// to verify the switch host key during the handshake. Required for any
	// SSH-backed vendor: switch SSH is fail-closed (no trust-on-first-use).
	KnownHostsPath string       `yaml:"known_hosts_path,omitempty" json:"known_hosts_path,omitempty"`
	VLANs          []VLANConfig `yaml:"vlans" json:"vlans"`
	Ports          []PortConfig `yaml:"ports" json:"ports"`
}

// Configurator is the interface for switch configuration.
type Configurator interface {
	// ConfigureVLANs creates or updates VLANs on the switch.
	ConfigureVLANs(ctx context.Context, vlans []VLANConfig) error

	// ConfigurePorts configures switch port modes (trunk/access) and VLAN assignments.
	ConfigurePorts(ctx context.Context, ports []PortConfig) error

	// Configure runs the complete switch configuration (VLANs + ports).
	Configure(ctx context.Context, config *Config) error

	// Verify checks that the configuration was applied correctly.
	Verify(ctx context.Context, config *Config) error

	// Close releases any connections.
	Close() error
}

// ConfigureResult holds the result of a configuration operation.
type ConfigureResult struct {
	VLANsCreated    int
	PortsConfigured int
	Warnings        []string
}

// SSHExecutor abstracts SSH command execution for testability.
type SSHExecutor interface {
	// Execute runs a command on the remote switch and returns the output.
	Execute(ctx context.Context, command string) (string, error)

	// Close releases the SSH connection.
	Close() error
}

// PortMode is the switchport operating mode.
type PortMode string

const (
	// PortModeAccess represents an access-mode switchport.
	PortModeAccess PortMode = "access"

	// PortModeTrunk represents a trunk-mode switchport.
	PortModeTrunk PortMode = "trunk"
)

// PortStatus holds the observable state of a single switch port.
type PortStatus struct {
	Port        string   `json:"port"`
	Mode        PortMode `json:"mode"`
	AccessVLAN  uint16   `json:"access_vlan"`
	TrunkVLANs  []uint16 `json:"trunk_vlans,omitempty"`
	Enabled     bool     `json:"enabled"`
	LinkUp      bool     `json:"link_up"`
	Description string   `json:"description,omitempty"`
}

// Manager provides runtime per-port operations on a physical switch.
type Manager interface {
	// SetPortVLAN moves a single access-mode port to the specified VLAN.
	SetPortVLAN(ctx context.Context, port string, vlanID uint16) error

	// GetPortVLAN returns the currently active access VLAN on a port.
	GetPortVLAN(ctx context.Context, port string) (uint16, error)

	// GetPortStatus returns the full observable state of a port.
	GetPortStatus(ctx context.Context, port string) (*PortStatus, error)

	// ListPorts returns the status of all physical ports on the switch.
	ListPorts(ctx context.Context) ([]*PortStatus, error)

	// EnablePort administratively enables a port.
	EnablePort(ctx context.Context, port string) error

	// DisablePort administratively shuts down a port.
	DisablePort(ctx context.Context, port string) error

	// Close releases any underlying connections.
	Close() error
}
