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

// ComputeQuota defines compute resource quotas for a tenant.
type ComputeQuota struct {
	// Limits
	MaxVMs        int64 // Maximum number of VMs
	MaxContainers int64 // Maximum number of containers
	MaxVCPUs      int64 // Maximum number of virtual CPUs
	MaxMemoryMB   int64 // Maximum memory in megabytes
	MaxDiskGB     int64 // Maximum disk space in gigabytes

	// Usage tracking
	UsedVMs        int64 // Currently used VMs
	UsedContainers int64 // Currently used containers
	UsedVCPUs      int64 // Currently used vCPUs
	UsedMemoryMB   int64 // Currently used memory in MB
	UsedDiskGB     int64 // Currently used disk in GB
}

// HasCapacity checks if the quota has capacity for the requested resources.
func (q *ComputeQuota) HasCapacity(vms, containers, vcpus, memoryMB, diskGB int64) bool {
	if vms > 0 && q.UsedVMs+vms > q.MaxVMs {
		return false
	}
	if containers > 0 && q.UsedContainers+containers > q.MaxContainers {
		return false
	}
	if vcpus > 0 && q.UsedVCPUs+vcpus > q.MaxVCPUs {
		return false
	}
	if memoryMB > 0 && q.UsedMemoryMB+memoryMB > q.MaxMemoryMB {
		return false
	}
	if diskGB > 0 && q.UsedDiskGB+diskGB > q.MaxDiskGB {
		return false
	}
	return true
}

// Reserve reserves the specified resources from the quota.
// Returns an error if insufficient capacity.
func (q *ComputeQuota) Reserve(tenantID string, vms, containers, vcpus, memoryMB, diskGB int64) error {
	if vms > 0 && q.UsedVMs+vms > q.MaxVMs {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "VMs",
			Requested: vms,
			Available: q.MaxVMs - q.UsedVMs,
		}
	}
	if containers > 0 && q.UsedContainers+containers > q.MaxContainers {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "containers",
			Requested: containers,
			Available: q.MaxContainers - q.UsedContainers,
		}
	}
	if vcpus > 0 && q.UsedVCPUs+vcpus > q.MaxVCPUs {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "vCPUs",
			Requested: vcpus,
			Available: q.MaxVCPUs - q.UsedVCPUs,
		}
	}
	if memoryMB > 0 && q.UsedMemoryMB+memoryMB > q.MaxMemoryMB {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "memory",
			Requested: memoryMB,
			Available: q.MaxMemoryMB - q.UsedMemoryMB,
		}
	}
	if diskGB > 0 && q.UsedDiskGB+diskGB > q.MaxDiskGB {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "disk",
			Requested: diskGB,
			Available: q.MaxDiskGB - q.UsedDiskGB,
		}
	}

	q.UsedVMs += vms
	q.UsedContainers += containers
	q.UsedVCPUs += vcpus
	q.UsedMemoryMB += memoryMB
	q.UsedDiskGB += diskGB

	return nil
}

// Release releases the specified resources back to the quota.
func (q *ComputeQuota) Release(vms, containers, vcpus, memoryMB, diskGB int64) {
	q.UsedVMs = max(0, q.UsedVMs-vms)
	q.UsedContainers = max(0, q.UsedContainers-containers)
	q.UsedVCPUs = max(0, q.UsedVCPUs-vcpus)
	q.UsedMemoryMB = max(0, q.UsedMemoryMB-memoryMB)
	q.UsedDiskGB = max(0, q.UsedDiskGB-diskGB)
}

// GetUtilization returns the utilization percentage for each resource type.
func (q *ComputeQuota) GetUtilization() map[string]float64 {
	utilization := make(map[string]float64)

	utilization["vms"] = safePercentage(q.UsedVMs, q.MaxVMs)
	utilization["containers"] = safePercentage(q.UsedContainers, q.MaxContainers)
	utilization["vcpus"] = safePercentage(q.UsedVCPUs, q.MaxVCPUs)
	utilization["memory"] = safePercentage(q.UsedMemoryMB, q.MaxMemoryMB)
	utilization["disk"] = safePercentage(q.UsedDiskGB, q.MaxDiskGB)

	return utilization
}

// AvailableVMs returns the number of VMs that can still be created.
func (q *ComputeQuota) AvailableVMs() int64 {
	return max(0, q.MaxVMs-q.UsedVMs)
}

// AvailableContainers returns the number of containers that can still be created.
func (q *ComputeQuota) AvailableContainers() int64 {
	return max(0, q.MaxContainers-q.UsedContainers)
}

// AvailableVCPUs returns the number of vCPUs that can still be allocated.
func (q *ComputeQuota) AvailableVCPUs() int64 {
	return max(0, q.MaxVCPUs-q.UsedVCPUs)
}

// AvailableMemoryMB returns the amount of memory (MB) that can still be allocated.
func (q *ComputeQuota) AvailableMemoryMB() int64 {
	return max(0, q.MaxMemoryMB-q.UsedMemoryMB)
}

// AvailableDiskGB returns the amount of disk (GB) that can still be allocated.
func (q *ComputeQuota) AvailableDiskGB() int64 {
	return max(0, q.MaxDiskGB-q.UsedDiskGB)
}

// NetworkQuota defines network resource quotas for a tenant.
type NetworkQuota struct {
	// Limits
	MaxBridges       int64 // Maximum number of OVS bridges
	MaxPorts         int64 // Maximum number of network ports
	MaxBandwidthMbps int64 // Maximum bandwidth in Mbps

	// Usage tracking
	UsedBridges int64 // Currently used bridges
	UsedPorts   int64 // Currently used ports
}

// HasCapacity checks if the quota has capacity for the requested resources.
func (q *NetworkQuota) HasCapacity(bridges, ports int64) bool {
	if bridges > 0 && q.UsedBridges+bridges > q.MaxBridges {
		return false
	}
	if ports > 0 && q.UsedPorts+ports > q.MaxPorts {
		return false
	}
	return true
}

// Reserve reserves the specified resources from the quota.
// Returns an error if insufficient capacity.
func (q *NetworkQuota) Reserve(tenantID string, bridges, ports int64) error {
	if bridges > 0 && q.UsedBridges+bridges > q.MaxBridges {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "bridges",
			Requested: bridges,
			Available: q.MaxBridges - q.UsedBridges,
		}
	}
	if ports > 0 && q.UsedPorts+ports > q.MaxPorts {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "ports",
			Requested: ports,
			Available: q.MaxPorts - q.UsedPorts,
		}
	}

	q.UsedBridges += bridges
	q.UsedPorts += ports

	return nil
}

// Release releases the specified resources back to the quota.
func (q *NetworkQuota) Release(bridges, ports int64) {
	q.UsedBridges = max(0, q.UsedBridges-bridges)
	q.UsedPorts = max(0, q.UsedPorts-ports)
}

// GetUtilization returns the utilization percentage for each resource type.
func (q *NetworkQuota) GetUtilization() map[string]float64 {
	utilization := make(map[string]float64)

	utilization["bridges"] = safePercentage(q.UsedBridges, q.MaxBridges)
	utilization["ports"] = safePercentage(q.UsedPorts, q.MaxPorts)

	return utilization
}

// AvailableBridges returns the number of bridges that can still be created.
func (q *NetworkQuota) AvailableBridges() int64 {
	return max(0, q.MaxBridges-q.UsedBridges)
}

// AvailablePorts returns the number of ports that can still be created.
func (q *NetworkQuota) AvailablePorts() int64 {
	return max(0, q.MaxPorts-q.UsedPorts)
}

// StorageQuota defines storage resource quotas for a tenant.
type StorageQuota struct {
	// Limits
	MaxVolumesGB int64 // Maximum total volume storage in GB
	MaxSnapshots int64 // Maximum number of snapshots

	// Usage tracking
	UsedVolumesGB int64 // Currently used volume storage in GB
	UsedSnapshots int64 // Currently used snapshots
}

// HasCapacity checks if the quota has capacity for the requested resources.
func (q *StorageQuota) HasCapacity(volumesGB, snapshots int64) bool {
	if volumesGB > 0 && q.UsedVolumesGB+volumesGB > q.MaxVolumesGB {
		return false
	}
	if snapshots > 0 && q.UsedSnapshots+snapshots > q.MaxSnapshots {
		return false
	}
	return true
}

// Reserve reserves the specified resources from the quota.
// Returns an error if insufficient capacity.
func (q *StorageQuota) Reserve(tenantID string, volumesGB, snapshots int64) error {
	if volumesGB > 0 && q.UsedVolumesGB+volumesGB > q.MaxVolumesGB {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "volume storage",
			Requested: volumesGB,
			Available: q.MaxVolumesGB - q.UsedVolumesGB,
		}
	}
	if snapshots > 0 && q.UsedSnapshots+snapshots > q.MaxSnapshots {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "snapshots",
			Requested: snapshots,
			Available: q.MaxSnapshots - q.UsedSnapshots,
		}
	}

	q.UsedVolumesGB += volumesGB
	q.UsedSnapshots += snapshots

	return nil
}

// Release releases the specified resources back to the quota.
func (q *StorageQuota) Release(volumesGB, snapshots int64) {
	q.UsedVolumesGB = max(0, q.UsedVolumesGB-volumesGB)
	q.UsedSnapshots = max(0, q.UsedSnapshots-snapshots)
}

// GetUtilization returns the utilization percentage for each resource type.
func (q *StorageQuota) GetUtilization() map[string]float64 {
	utilization := make(map[string]float64)

	utilization["volumes"] = safePercentage(q.UsedVolumesGB, q.MaxVolumesGB)
	utilization["snapshots"] = safePercentage(q.UsedSnapshots, q.MaxSnapshots)

	return utilization
}

// AvailableVolumesGB returns the amount of volume storage (GB) that can still be allocated.
func (q *StorageQuota) AvailableVolumesGB() int64 {
	return max(0, q.MaxVolumesGB-q.UsedVolumesGB)
}

// AvailableSnapshots returns the number of snapshots that can still be created.
func (q *StorageQuota) AvailableSnapshots() int64 {
	return max(0, q.MaxSnapshots-q.UsedSnapshots)
}

// safePercentage calculates percentage avoiding division by zero.
func safePercentage(used, max int64) float64 {
	if max <= 0 {
		return 0
	}
	return float64(used) / float64(max) * 100
}

// QuotaSummary provides a high-level summary of quota usage across all types.
type QuotaSummary struct {
	Compute ComputeQuotaSummary
	Network NetworkQuotaSummary
	Storage StorageQuotaSummary
}

// ComputeQuotaSummary provides summary of compute quota usage.
type ComputeQuotaSummary struct {
	VMsUsed         int64
	VMsTotal        int64
	ContainersUsed  int64
	ContainersTotal int64
	VCPUsUsed       int64
	VCPUsTotal      int64
	MemoryUsedMB    int64
	MemoryTotalMB   int64
	DiskUsedGB      int64
	DiskTotalGB     int64
}

// NetworkQuotaSummary provides summary of network quota usage.
type NetworkQuotaSummary struct {
	BridgesUsed  int64
	BridgesTotal int64
	PortsUsed    int64
	PortsTotal   int64
}

// StorageQuotaSummary provides summary of storage quota usage.
type StorageQuotaSummary struct {
	VolumesUsedGB  int64
	VolumesTotalGB int64
	SnapshotsUsed  int64
	SnapshotsTotal int64
}

// GetQuotaSummary returns a summary of all quota usage for a tenant.
func GetQuotaSummary(compute *ComputeQuota, network *NetworkQuota, storage *StorageQuota) QuotaSummary {
	summary := QuotaSummary{}

	if compute != nil {
		summary.Compute = ComputeQuotaSummary{
			VMsUsed:         compute.UsedVMs,
			VMsTotal:        compute.MaxVMs,
			ContainersUsed:  compute.UsedContainers,
			ContainersTotal: compute.MaxContainers,
			VCPUsUsed:       compute.UsedVCPUs,
			VCPUsTotal:      compute.MaxVCPUs,
			MemoryUsedMB:    compute.UsedMemoryMB,
			MemoryTotalMB:   compute.MaxMemoryMB,
			DiskUsedGB:      compute.UsedDiskGB,
			DiskTotalGB:     compute.MaxDiskGB,
		}
	}

	if network != nil {
		summary.Network = NetworkQuotaSummary{
			BridgesUsed:  network.UsedBridges,
			BridgesTotal: network.MaxBridges,
			PortsUsed:    network.UsedPorts,
			PortsTotal:   network.MaxPorts,
		}
	}

	if storage != nil {
		summary.Storage = StorageQuotaSummary{
			VolumesUsedGB:  storage.UsedVolumesGB,
			VolumesTotalGB: storage.MaxVolumesGB,
			SnapshotsUsed:  storage.UsedSnapshots,
			SnapshotsTotal: storage.MaxSnapshots,
		}
	}

	return summary
}
