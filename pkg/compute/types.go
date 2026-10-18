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

// DiskInfo describes a single disk attached to a VM instance. The boot disk is
// tracked implicitly through InstanceConfig.DiskPath; DiskInfo records the
// additional, hot-pluggable disks so their QMP node/device identities and
// virtio bus slots can be managed over the VM's lifetime.
type DiskInfo struct {
	// ID is the caller-facing disk identifier (stable across attach/detach).
	ID string `json:"id" yaml:"id"`

	// Path is the backing image path on the host.
	Path string `json:"path" yaml:"path"`

	// Bus is the guest bus the disk is attached to (e.g. "virtio", "sata").
	Bus string `json:"bus" yaml:"bus"`

	// Index is the allocated slot on the bus (virtio slot ordinal). The boot
	// disk occupies index 0; hot-plugged disks start at 1.
	Index int `json:"index" yaml:"index"`

	// SizeGB is the virtual size of the disk in gibibytes.
	SizeGB uint64 `json:"size_gb" yaml:"size_gb"`

	// NodeName is the QMP blockdev node name backing the disk. Empty for the
	// legacy boot drive, which is addressed by device name.
	NodeName string `json:"node_name,omitempty" yaml:"node_name,omitempty"`

	// DeviceID is the QMP guest device id (device_add id). Empty for the
	// legacy boot drive.
	DeviceID string `json:"device_id,omitempty" yaml:"device_id,omitempty"`

	// Readonly reports whether the disk is attached read-only.
	Readonly bool `json:"readonly" yaml:"readonly"`

	// Bootable reports whether the disk participates in the boot order.
	Bootable bool `json:"bootable" yaml:"bootable"`

	// Hotplugged reports whether the disk was attached to a running VM via QMP
	// (true) or was present at boot (false).
	Hotplugged bool `json:"hotplugged" yaml:"hotplugged"`
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

	// Disks tracks the additional, hot-pluggable disks attached to this
	// instance beyond the boot disk (InstanceConfig.DiskPath). It is populated
	// by the VM disk manager as disks are attached and detached at runtime.
	Disks []DiskInfo `json:"disks,omitempty" yaml:"disks,omitempty"`

	// CreatedAt is the timestamp when the instance was created
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// StartedAt is the timestamp of the most recent transition to the running
	// state. It is the reference point for uptime accounting and is zero while
	// the instance has never run.
	StartedAt time.Time `json:"started_at,omitempty" yaml:"started_at,omitempty"`

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

	// Description is the caller's free-text description of the instance
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Labels are the caller's labels, which list selectors match against
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Metadata is the caller's metadata. The orchestrator's own keys live in
	// Instance.Metadata, apart from it.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
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
