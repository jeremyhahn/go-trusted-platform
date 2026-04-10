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

package tenant

import "time"

// TenantState represents the lifecycle state of a tenant as a string constant.
type TenantState string

const (
	// StateUnspecified indicates the tenant state is unknown.
	StateUnspecified TenantState = "TENANT_STATE_UNSPECIFIED"
	// StatePending indicates the tenant is awaiting activation.
	StatePending TenantState = "TENANT_STATE_PENDING"
	// StateActive indicates the tenant is active and operational.
	StateActive TenantState = "TENANT_STATE_ACTIVE"
	// StateSuspended indicates the tenant is suspended.
	StateSuspended TenantState = "TENANT_STATE_SUSPENDED"
	// StateDeleting indicates the tenant is being deleted.
	StateDeleting TenantState = "TENANT_STATE_DELETING"
	// StateDeleted indicates the tenant has been deleted.
	StateDeleted TenantState = "TENANT_STATE_DELETED"
)

// TenantInfo represents basic tenant information returned to users.
// This is a simplified view of the full Tenant entity for user-facing operations.
type TenantInfo struct {
	// ID is the unique identifier for the tenant.
	ID string `json:"id"`
	// Name is the tenant name (typically a UUID).
	Name string `json:"name"`
	// DisplayName is the human-readable display name.
	DisplayName string `json:"display_name"`
	// State is the current state of the tenant.
	State string `json:"state"`
	// CreatedAt is when the tenant was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the tenant was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// UserTenantInfo contains tenant information from the user's perspective.
type UserTenantInfo struct {
	// Tenant contains the basic tenant information.
	Tenant *TenantInfo `json:"tenant"`
	// IsOwner indicates if the current user is the tenant owner.
	IsOwner bool `json:"is_owner"`
	// Role is the user's role within the tenant.
	Role string `json:"role,omitempty"`
}

// Tenant represents the full domain model of a tenant with all fields.
type Tenant struct {
	// ID is the unique identifier for the tenant.
	ID string `json:"id" yaml:"id"`
	// Name is the unique tenant name.
	Name string `json:"name" yaml:"name"`
	// DisplayName is the human-readable display name.
	DisplayName string `json:"display_name" yaml:"display_name"`
	// State is the current lifecycle state.
	State TenantState `json:"state" yaml:"state"`
	// OVSBridge is the OVS bridge name for network isolation.
	OVSBridge string `json:"ovs_bridge" yaml:"ovs_bridge"`
	// VLANStart is the beginning of the allocated VLAN range.
	VLANStart uint32 `json:"vlan_start" yaml:"vlan_start"`
	// VLANEnd is the end of the allocated VLAN range.
	VLANEnd uint32 `json:"vlan_end" yaml:"vlan_end"`
	// Labels are key-value metadata labels.
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	// Annotations are key-value metadata annotations.
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	// CreatedAt is when the tenant was created.
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	// UpdatedAt is when the tenant was last updated.
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
	// ComputeQuota contains compute resource limits.
	ComputeQuota *ComputeQuota `json:"compute_quota,omitempty" yaml:"compute_quota,omitempty"`
	// NetworkQuota contains network resource limits.
	NetworkQuota *NetworkQuota `json:"network_quota,omitempty" yaml:"network_quota,omitempty"`
	// StorageQuota contains storage resource limits.
	StorageQuota *StorageQuota `json:"storage_quota,omitempty" yaml:"storage_quota,omitempty"`
}

// ComputeQuota defines compute resource limits for a tenant.
type ComputeQuota struct {
	// MaxVMs is the maximum number of virtual machines.
	MaxVMs int64 `json:"max_vms" yaml:"max_vms"`
	// MaxContainers is the maximum number of containers.
	MaxContainers int64 `json:"max_containers" yaml:"max_containers"`
	// MaxVCPUs is the maximum number of virtual CPUs.
	MaxVCPUs int64 `json:"max_vcpus" yaml:"max_vcpus"`
	// MaxMemoryMB is the maximum memory in megabytes.
	MaxMemoryMB int64 `json:"max_memory_mb" yaml:"max_memory_mb"`
}

// NetworkQuota defines network resource limits for a tenant.
type NetworkQuota struct {
	// MaxBridges is the maximum number of OVS bridges.
	MaxBridges int64 `json:"max_bridges" yaml:"max_bridges"`
	// MaxPorts is the maximum number of network ports.
	MaxPorts int64 `json:"max_ports" yaml:"max_ports"`
	// MaxBandwidthMbps is the maximum bandwidth in megabits per second.
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps" yaml:"max_bandwidth_mbps"`
}

// StorageQuota defines storage resource limits for a tenant.
type StorageQuota struct {
	// MaxVolumesGB is the maximum volume storage in gigabytes.
	MaxVolumesGB int64 `json:"max_volumes_gb" yaml:"max_volumes_gb"`
	// MaxSnapshots is the maximum number of snapshots.
	MaxSnapshots int64 `json:"max_snapshots" yaml:"max_snapshots"`
}

// CreateParams contains parameters for creating a new tenant.
type CreateParams struct {
	// Name is the unique tenant name.
	Name string
	// DisplayName is the human-readable display name.
	DisplayName string
	// VLANRangeStart is the beginning of the requested VLAN range (0 for auto-allocate).
	VLANRangeStart uint32
	// VLANRangeEnd is the end of the requested VLAN range (0 for auto-allocate).
	VLANRangeEnd uint32
	// ComputeQuota contains optional compute resource limits.
	ComputeQuota *ComputeQuota
	// NetworkQuota contains optional network resource limits.
	NetworkQuota *NetworkQuota
	// StorageQuota contains optional storage resource limits.
	StorageQuota *StorageQuota
}

// UpdateQuotasParams contains parameters for updating tenant quotas.
type UpdateQuotasParams struct {
	// TenantID is the ID of the tenant to update.
	TenantID string
	// ComputeQuota contains optional compute resource limits to update.
	ComputeQuota *ComputeQuota
	// NetworkQuota contains optional network resource limits to update.
	NetworkQuota *NetworkQuota
	// StorageQuota contains optional storage resource limits to update.
	StorageQuota *StorageQuota
}
