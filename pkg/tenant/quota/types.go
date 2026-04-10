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

package quota

import (
	"context"
	"time"
)

// ResourceType identifies the type of quota resource.
type ResourceType string

const (
	// ResourceVMs is the maximum number of virtual machines.
	ResourceVMs ResourceType = "vms"

	// ResourceContainers is the maximum number of containers.
	ResourceContainers ResourceType = "containers"

	// ResourceVCPUs is the maximum number of virtual CPUs.
	ResourceVCPUs ResourceType = "vcpus"

	// ResourceMemory is the maximum memory in MB.
	ResourceMemory ResourceType = "memory"

	// ResourceDisk is the maximum disk space in GB.
	ResourceDisk ResourceType = "disk"

	// ResourceBridges is the maximum number of network bridges.
	ResourceBridges ResourceType = "bridges"

	// ResourcePorts is the maximum number of network ports.
	ResourcePorts ResourceType = "ports"

	// ResourceBandwidth is the maximum network bandwidth in Mbps.
	ResourceBandwidth ResourceType = "bandwidth"

	// ResourceVolumes is the maximum number of storage volumes.
	ResourceVolumes ResourceType = "volumes"

	// ResourceSnapshots is the maximum number of snapshots.
	ResourceSnapshots ResourceType = "snapshots"
)

// String returns the string representation of ResourceType.
func (r ResourceType) String() string {
	return string(r)
}

// IsValid checks if the ResourceType is a known valid type.
func (r ResourceType) IsValid() bool {
	switch r {
	case ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceDisk, ResourceBridges, ResourcePorts, ResourceBandwidth,
		ResourceVolumes, ResourceSnapshots:
		return true
	default:
		return false
	}
}

// Category returns the category this resource belongs to.
func (r ResourceType) Category() string {
	switch r {
	case ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory:
		return "compute"
	case ResourceBridges, ResourcePorts, ResourceBandwidth:
		return "network"
	case ResourceDisk, ResourceVolumes, ResourceSnapshots:
		return "storage"
	default:
		return "unknown"
	}
}

// QuotaStore is the interface for storing quota data.
type QuotaStore interface {
	// GetQuota retrieves the quotas for a tenant.
	GetQuota(ctx context.Context, tenantID string) (*TenantQuotas, error)

	// UpdateQuota updates the quotas for a tenant.
	UpdateQuota(ctx context.Context, tenantID string, quotas *TenantQuotas) error

	// GetUsage retrieves the current usage for a tenant.
	GetUsage(ctx context.Context, tenantID string) (*TenantUsage, error)

	// UpdateUsage updates the usage for a tenant.
	UpdateUsage(ctx context.Context, tenantID string, usage *TenantUsage) error
}

// ComputeQuota defines compute resource limits.
type ComputeQuota struct {
	// MaxVMs is the maximum number of virtual machines.
	MaxVMs int64 `json:"max_vms" yaml:"max_vms"`

	// MaxContainers is the maximum number of containers.
	MaxContainers int64 `json:"max_containers" yaml:"max_containers"`

	// MaxVCPUs is the maximum number of virtual CPUs across all instances.
	MaxVCPUs int64 `json:"max_vcpus" yaml:"max_vcpus"`

	// MaxMemoryMB is the maximum memory in megabytes.
	MaxMemoryMB int64 `json:"max_memory_mb" yaml:"max_memory_mb"`
}

// NetworkQuota defines network resource limits.
type NetworkQuota struct {
	// MaxBridges is the maximum number of network bridges.
	MaxBridges int64 `json:"max_bridges" yaml:"max_bridges"`

	// MaxPorts is the maximum number of network ports.
	MaxPorts int64 `json:"max_ports" yaml:"max_ports"`

	// MaxBandwidthMbps is the maximum network bandwidth in Mbps.
	MaxBandwidthMbps int64 `json:"max_bandwidth_mbps" yaml:"max_bandwidth_mbps"`
}

// StorageQuota defines storage resource limits.
type StorageQuota struct {
	// MaxDiskGB is the maximum disk space in gigabytes.
	MaxDiskGB int64 `json:"max_disk_gb" yaml:"max_disk_gb"`

	// MaxVolumes is the maximum number of storage volumes.
	MaxVolumes int64 `json:"max_volumes" yaml:"max_volumes"`

	// MaxSnapshots is the maximum number of snapshots.
	MaxSnapshots int64 `json:"max_snapshots" yaml:"max_snapshots"`
}

// TenantQuotas holds all quota types for a tenant.
type TenantQuotas struct {
	// TenantID is the unique identifier for the tenant.
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// Compute contains compute resource quotas.
	Compute ComputeQuota `json:"compute" yaml:"compute"`

	// Network contains network resource quotas.
	Network NetworkQuota `json:"network" yaml:"network"`

	// Storage contains storage resource quotas.
	Storage StorageQuota `json:"storage" yaml:"storage"`

	// UpdatedAt is when the quotas were last updated.
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// GetLimit returns the limit for a specific resource type.
func (q *TenantQuotas) GetLimit(resource ResourceType) int64 {
	switch resource {
	case ResourceVMs:
		return q.Compute.MaxVMs
	case ResourceContainers:
		return q.Compute.MaxContainers
	case ResourceVCPUs:
		return q.Compute.MaxVCPUs
	case ResourceMemory:
		return q.Compute.MaxMemoryMB
	case ResourceBridges:
		return q.Network.MaxBridges
	case ResourcePorts:
		return q.Network.MaxPorts
	case ResourceBandwidth:
		return q.Network.MaxBandwidthMbps
	case ResourceDisk:
		return q.Storage.MaxDiskGB
	case ResourceVolumes:
		return q.Storage.MaxVolumes
	case ResourceSnapshots:
		return q.Storage.MaxSnapshots
	default:
		return 0
	}
}

// SetLimit sets the limit for a specific resource type.
func (q *TenantQuotas) SetLimit(resource ResourceType, limit int64) {
	switch resource {
	case ResourceVMs:
		q.Compute.MaxVMs = limit
	case ResourceContainers:
		q.Compute.MaxContainers = limit
	case ResourceVCPUs:
		q.Compute.MaxVCPUs = limit
	case ResourceMemory:
		q.Compute.MaxMemoryMB = limit
	case ResourceBridges:
		q.Network.MaxBridges = limit
	case ResourcePorts:
		q.Network.MaxPorts = limit
	case ResourceBandwidth:
		q.Network.MaxBandwidthMbps = limit
	case ResourceDisk:
		q.Storage.MaxDiskGB = limit
	case ResourceVolumes:
		q.Storage.MaxVolumes = limit
	case ResourceSnapshots:
		q.Storage.MaxSnapshots = limit
	}
}

// TenantUsage holds current resource usage for a tenant.
type TenantUsage struct {
	// TenantID is the unique identifier for the tenant.
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// VMs is the current number of virtual machines.
	VMs int64 `json:"vms" yaml:"vms"`

	// Containers is the current number of containers.
	Containers int64 `json:"containers" yaml:"containers"`

	// VCPUs is the current number of virtual CPUs in use.
	VCPUs int64 `json:"vcpus" yaml:"vcpus"`

	// MemoryMB is the current memory usage in megabytes.
	MemoryMB int64 `json:"memory_mb" yaml:"memory_mb"`

	// DiskGB is the current disk usage in gigabytes.
	DiskGB int64 `json:"disk_gb" yaml:"disk_gb"`

	// Bridges is the current number of network bridges.
	Bridges int64 `json:"bridges" yaml:"bridges"`

	// Ports is the current number of network ports.
	Ports int64 `json:"ports" yaml:"ports"`

	// BandwidthMbps is the current bandwidth usage in Mbps.
	BandwidthMbps int64 `json:"bandwidth_mbps" yaml:"bandwidth_mbps"`

	// Volumes is the current number of storage volumes.
	Volumes int64 `json:"volumes" yaml:"volumes"`

	// Snapshots is the current number of snapshots.
	Snapshots int64 `json:"snapshots" yaml:"snapshots"`

	// Timestamp is when the usage was last updated.
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
}

// GetUsage returns the usage for a specific resource type.
func (u *TenantUsage) GetUsage(resource ResourceType) int64 {
	switch resource {
	case ResourceVMs:
		return u.VMs
	case ResourceContainers:
		return u.Containers
	case ResourceVCPUs:
		return u.VCPUs
	case ResourceMemory:
		return u.MemoryMB
	case ResourceBridges:
		return u.Bridges
	case ResourcePorts:
		return u.Ports
	case ResourceBandwidth:
		return u.BandwidthMbps
	case ResourceDisk:
		return u.DiskGB
	case ResourceVolumes:
		return u.Volumes
	case ResourceSnapshots:
		return u.Snapshots
	default:
		return 0
	}
}

// SetUsage sets the usage for a specific resource type.
func (u *TenantUsage) SetUsage(resource ResourceType, usage int64) {
	switch resource {
	case ResourceVMs:
		u.VMs = usage
	case ResourceContainers:
		u.Containers = usage
	case ResourceVCPUs:
		u.VCPUs = usage
	case ResourceMemory:
		u.MemoryMB = usage
	case ResourceBridges:
		u.Bridges = usage
	case ResourcePorts:
		u.Ports = usage
	case ResourceBandwidth:
		u.BandwidthMbps = usage
	case ResourceDisk:
		u.DiskGB = usage
	case ResourceVolumes:
		u.Volumes = usage
	case ResourceSnapshots:
		u.Snapshots = usage
	}
}

// Reservation represents a temporary quota reservation.
type Reservation struct {
	// ID is the unique identifier for this reservation.
	ID string `json:"id" yaml:"id"`

	// TenantID is the tenant this reservation belongs to.
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// Resource is the type of resource being reserved.
	Resource ResourceType `json:"resource" yaml:"resource"`

	// Amount is the quantity being reserved.
	Amount int64 `json:"amount" yaml:"amount"`

	// CreatedAt is when the reservation was created.
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// ExpiresAt is when the reservation expires.
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`

	// Committed indicates if the reservation has been committed.
	Committed bool `json:"committed" yaml:"committed"`
}

// IsExpired returns true if the reservation has expired.
func (r *Reservation) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// DefaultReservationTTL is the default time-to-live for reservations.
const DefaultReservationTTL = 5 * time.Minute
