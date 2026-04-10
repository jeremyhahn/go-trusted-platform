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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// ComputeType represents the type of compute instance
type ComputeType string

const (
	// ComputeTypeVM represents a virtual machine
	ComputeTypeVM ComputeType = "vm"

	// ComputeTypeContainer represents a container
	ComputeTypeContainer ComputeType = "container"
)

// String returns the string representation of ComputeType
func (ct ComputeType) String() string {
	return string(ct)
}

// IsValid checks if the ComputeType is valid
func (ct ComputeType) IsValid() bool {
	return ct == ComputeTypeVM || ct == ComputeTypeContainer
}

// NetworkAttachment represents a network attachment point
type NetworkAttachment struct {
	// PortName is the OVS port name
	PortName string `json:"port_name" yaml:"port_name"`

	// BridgeName is the OVS bridge name
	BridgeName string `json:"bridge_name" yaml:"bridge_name"`

	// VLAN is the VLAN ID (0 for untagged)
	VLAN uint16 `json:"vlan" yaml:"vlan"`

	// MACAddress is the MAC address assigned to this attachment
	MACAddress string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`

	// IPAddress is the IP address assigned to this attachment
	IPAddress string `json:"ip_address,omitempty" yaml:"ip_address,omitempty"`

	// AttachedAt is the timestamp when the attachment was created
	AttachedAt time.Time `json:"attached_at" yaml:"attached_at"`
}

// Instance represents a compute instance (VM or container)
type Instance struct {
	// ID is the unique identifier for this instance
	ID string `json:"id" yaml:"id"`

	// Name is a human-readable name for the instance
	Name string `json:"name" yaml:"name"`

	// Type is the compute type (VM or container)
	Type ComputeType `json:"type" yaml:"type"`

	// State is the current lifecycle state
	State InstanceState `json:"state" yaml:"state"`

	// Profile is the device profile used to create this instance
	Profile *entities.DeviceProfile `json:"profile,omitempty" yaml:"profile,omitempty"`

	// Config is the instance-specific configuration
	Config *InstanceConfig `json:"config,omitempty" yaml:"config,omitempty"`

	// NetworkAttachments are the network ports attached to this instance
	NetworkAttachments []NetworkAttachment `json:"network_attachments,omitempty" yaml:"network_attachments,omitempty"`

	// CreatedAt is the timestamp when the instance was created
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// UpdatedAt is the timestamp when the instance was last updated
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`

	// Metadata is a map of arbitrary key-value pairs
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// PID is the process ID of the running instance (VM or container)
	PID int `json:"pid,omitempty" yaml:"pid,omitempty"`
}

// InstanceConfig holds instance-specific configuration
type InstanceConfig struct {
	// Memory is the amount of RAM in MB
	Memory int `json:"memory" yaml:"memory"`

	// CPUs is the number of CPU cores
	CPUs int `json:"cpus" yaml:"cpus"`

	// DiskPath is the path to the instance disk
	DiskPath string `json:"disk_path" yaml:"disk_path"`

	// DiskSize is the size of the disk (e.g., "10G", "20G")
	DiskSize string `json:"disk_size,omitempty" yaml:"disk_size,omitempty"`

	// WorkDir is the working directory for instance artifacts
	WorkDir string `json:"work_dir" yaml:"work_dir"`

	// SecureBoot enables UEFI Secure Boot (VMs only)
	SecureBoot bool `json:"secure_boot" yaml:"secure_boot"`

	// EnableKVM enables KVM acceleration (VMs only)
	EnableKVM bool `json:"enable_kvm" yaml:"enable_kvm"`

	// TPMEnabled enables virtual TPM (VMs only)
	TPMEnabled bool `json:"tpm_enabled" yaml:"tpm_enabled"`

	// NetworkMode specifies the network configuration
	NetworkMode string `json:"network_mode,omitempty" yaml:"network_mode,omitempty"`

	// MACAddress is the MAC address for the primary network interface
	MACAddress string `json:"mac_address,omitempty" yaml:"mac_address,omitempty"`

	// BootMode specifies how to boot the instance (install, boot, pxe)
	BootMode string `json:"boot_mode,omitempty" yaml:"boot_mode,omitempty"`

	// ISOPath is the path to the installation ISO (for install mode)
	ISOPath string `json:"iso_path,omitempty" yaml:"iso_path,omitempty"`

	// AdditionalDisks are additional disk images to attach
	AdditionalDisks []string `json:"additional_disks,omitempty" yaml:"additional_disks,omitempty"`

	// Environment variables for the instance
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`
}

// InstanceFilter is used to filter instances in List operations
type InstanceFilter struct {
	// Type filters by compute type
	Type *ComputeType `json:"type,omitempty" yaml:"type,omitempty"`

	// State filters by instance state
	State *InstanceState `json:"state,omitempty" yaml:"state,omitempty"`

	// Name filters by instance name (substring match)
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// ProfileID filters by device profile ID
	ProfileID *uint64 `json:"profile_id,omitempty" yaml:"profile_id,omitempty"`

	// CreatedAfter filters instances created after this time
	CreatedAfter *time.Time `json:"created_after,omitempty" yaml:"created_after,omitempty"`

	// CreatedBefore filters instances created before this time
	CreatedBefore *time.Time `json:"created_before,omitempty" yaml:"created_before,omitempty"`
}

// Matches returns true if the instance matches the filter
func (f *InstanceFilter) Matches(instance *Instance) bool {
	if instance == nil {
		return false
	}

	if f.Type != nil && instance.Type != *f.Type {
		return false
	}

	if f.State != nil && instance.State != *f.State {
		return false
	}

	if f.Name != "" && instance.Name != f.Name {
		return false
	}

	if f.ProfileID != nil && (instance.Profile == nil || instance.Profile.ID != *f.ProfileID) {
		return false
	}

	if f.CreatedAfter != nil && instance.CreatedAt.Before(*f.CreatedAfter) {
		return false
	}

	if f.CreatedBefore != nil && instance.CreatedAt.After(*f.CreatedBefore) {
		return false
	}

	return true
}
