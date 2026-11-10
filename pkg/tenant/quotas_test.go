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

import (
	"errors"
	"math"
	"testing"
)

// ComputeQuota Tests

func TestComputeQuota_HasCapacity(t *testing.T) {
	tests := []struct {
		name       string
		quota      ComputeQuota
		vms        int64
		containers int64
		vcpus      int64
		memoryMB   int64
		diskGB     int64
		expected   bool
	}{
		{
			name:       "has capacity for all resources",
			quota:      ComputeQuota{MaxVMs: 10, MaxContainers: 50, MaxVCPUs: 32, MaxMemoryMB: 65536, MaxDiskGB: 1024},
			vms:        5,
			containers: 25,
			vcpus:      16,
			memoryMB:   32768,
			diskGB:     512,
			expected:   true,
		},
		{
			name:     "no capacity for VMs",
			quota:    ComputeQuota{MaxVMs: 10, UsedVMs: 8},
			vms:      5,
			expected: false,
		},
		{
			name:       "no capacity for containers",
			quota:      ComputeQuota{MaxContainers: 50, UsedContainers: 48},
			containers: 5,
			expected:   false,
		},
		{
			name:     "no capacity for vCPUs",
			quota:    ComputeQuota{MaxVCPUs: 32, UsedVCPUs: 30},
			vcpus:    5,
			expected: false,
		},
		{
			name:     "no capacity for memory",
			quota:    ComputeQuota{MaxMemoryMB: 65536, UsedMemoryMB: 65000},
			memoryMB: 1000,
			expected: false,
		},
		{
			name:     "no capacity for disk",
			quota:    ComputeQuota{MaxDiskGB: 1024, UsedDiskGB: 1000},
			diskGB:   100,
			expected: false,
		},
		{
			name:     "exact capacity available",
			quota:    ComputeQuota{MaxVMs: 10, UsedVMs: 5},
			vms:      5,
			expected: true,
		},
		{
			name:     "zero request always has capacity",
			quota:    ComputeQuota{MaxVMs: 0, UsedVMs: 0},
			vms:      0,
			expected: true,
		},
		{
			name:     "negative request ignored",
			quota:    ComputeQuota{MaxVMs: 10, UsedVMs: 10},
			vms:      -1,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.quota.HasCapacity(tt.vms, tt.containers, tt.vcpus, tt.memoryMB, tt.diskGB); got != tt.expected {
				t.Errorf("HasCapacity() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestComputeQuota_Reserve_Success(t *testing.T) {
	quota := ComputeQuota{
		MaxVMs:        10,
		MaxContainers: 50,
		MaxVCPUs:      32,
		MaxMemoryMB:   65536,
		MaxDiskGB:     1024,
	}

	err := quota.Reserve("tenant-1", 2, 5, 4, 8192, 100)

	if err != nil {
		t.Errorf("Reserve() unexpected error: %v", err)
	}
	if quota.UsedVMs != 2 {
		t.Errorf("UsedVMs = %d, want 2", quota.UsedVMs)
	}
	if quota.UsedContainers != 5 {
		t.Errorf("UsedContainers = %d, want 5", quota.UsedContainers)
	}
	if quota.UsedVCPUs != 4 {
		t.Errorf("UsedVCPUs = %d, want 4", quota.UsedVCPUs)
	}
	if quota.UsedMemoryMB != 8192 {
		t.Errorf("UsedMemoryMB = %d, want 8192", quota.UsedMemoryMB)
	}
	if quota.UsedDiskGB != 100 {
		t.Errorf("UsedDiskGB = %d, want 100", quota.UsedDiskGB)
	}
}

func TestComputeQuota_Reserve_Errors(t *testing.T) {
	tests := []struct {
		name       string
		quota      ComputeQuota
		vms        int64
		containers int64
		vcpus      int64
		memoryMB   int64
		diskGB     int64
		resource   string
	}{
		{
			name:     "VMs quota exceeded",
			quota:    ComputeQuota{MaxVMs: 10, UsedVMs: 8},
			vms:      5,
			resource: "VMs",
		},
		{
			name:       "containers quota exceeded",
			quota:      ComputeQuota{MaxVMs: 10, MaxContainers: 50, UsedContainers: 48},
			containers: 5,
			resource:   "containers",
		},
		{
			name:     "vCPUs quota exceeded",
			quota:    ComputeQuota{MaxVMs: 10, MaxContainers: 50, MaxVCPUs: 32, UsedVCPUs: 30},
			vcpus:    5,
			resource: "vCPUs",
		},
		{
			name:     "memory quota exceeded",
			quota:    ComputeQuota{MaxVMs: 10, MaxContainers: 50, MaxVCPUs: 32, MaxMemoryMB: 65536, UsedMemoryMB: 65000},
			memoryMB: 1000,
			resource: "memory",
		},
		{
			name:     "disk quota exceeded",
			quota:    ComputeQuota{MaxVMs: 10, MaxContainers: 50, MaxVCPUs: 32, MaxMemoryMB: 65536, MaxDiskGB: 1024, UsedDiskGB: 1000},
			diskGB:   100,
			resource: "disk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.quota.Reserve("tenant-1", tt.vms, tt.containers, tt.vcpus, tt.memoryMB, tt.diskGB)

			if err == nil {
				t.Error("Reserve() expected error")
				return
			}

			var quotaErr ErrQuotaExceeded
			if !errors.As(err, &quotaErr) {
				t.Errorf("Reserve() error type = %T, want ErrQuotaExceeded", err)
			}
			if quotaErr.Resource != tt.resource {
				t.Errorf("ErrQuotaExceeded.Resource = %q, want %q", quotaErr.Resource, tt.resource)
			}
			if quotaErr.TenantID != "tenant-1" {
				t.Errorf("ErrQuotaExceeded.TenantID = %q, want %q", quotaErr.TenantID, "tenant-1")
			}
		})
	}
}

func TestComputeQuota_Release(t *testing.T) {
	quota := ComputeQuota{
		UsedVMs:        5,
		UsedContainers: 25,
		UsedVCPUs:      16,
		UsedMemoryMB:   32768,
		UsedDiskGB:     512,
	}

	quota.Release(2, 5, 4, 8192, 100)

	if quota.UsedVMs != 3 {
		t.Errorf("UsedVMs = %d, want 3", quota.UsedVMs)
	}
	if quota.UsedContainers != 20 {
		t.Errorf("UsedContainers = %d, want 20", quota.UsedContainers)
	}
	if quota.UsedVCPUs != 12 {
		t.Errorf("UsedVCPUs = %d, want 12", quota.UsedVCPUs)
	}
	if quota.UsedMemoryMB != 24576 {
		t.Errorf("UsedMemoryMB = %d, want 24576", quota.UsedMemoryMB)
	}
	if quota.UsedDiskGB != 412 {
		t.Errorf("UsedDiskGB = %d, want 412", quota.UsedDiskGB)
	}
}

func TestComputeQuota_Release_NoNegative(t *testing.T) {
	quota := ComputeQuota{
		UsedVMs:        2,
		UsedContainers: 2,
		UsedVCPUs:      2,
		UsedMemoryMB:   2,
		UsedDiskGB:     2,
	}

	quota.Release(10, 10, 10, 10, 10) // Release more than used

	if quota.UsedVMs < 0 {
		t.Error("UsedVMs should not be negative")
	}
	if quota.UsedContainers < 0 {
		t.Error("UsedContainers should not be negative")
	}
	if quota.UsedVCPUs < 0 {
		t.Error("UsedVCPUs should not be negative")
	}
	if quota.UsedMemoryMB < 0 {
		t.Error("UsedMemoryMB should not be negative")
	}
	if quota.UsedDiskGB < 0 {
		t.Error("UsedDiskGB should not be negative")
	}
}

func TestComputeQuota_GetUtilization(t *testing.T) {
	quota := ComputeQuota{
		MaxVMs:         10,
		MaxContainers:  50,
		MaxVCPUs:       32,
		MaxMemoryMB:    65536,
		MaxDiskGB:      1024,
		UsedVMs:        5,
		UsedContainers: 25,
		UsedVCPUs:      16,
		UsedMemoryMB:   32768,
		UsedDiskGB:     512,
	}

	util := quota.GetUtilization()

	if util["vms"] != 50.0 {
		t.Errorf("vms utilization = %f, want 50.0", util["vms"])
	}
	if util["containers"] != 50.0 {
		t.Errorf("containers utilization = %f, want 50.0", util["containers"])
	}
	if util["vcpus"] != 50.0 {
		t.Errorf("vcpus utilization = %f, want 50.0", util["vcpus"])
	}
	if util["memory"] != 50.0 {
		t.Errorf("memory utilization = %f, want 50.0", util["memory"])
	}
	if util["disk"] != 50.0 {
		t.Errorf("disk utilization = %f, want 50.0", util["disk"])
	}
}

func TestComputeQuota_GetUtilization_ZeroMax(t *testing.T) {
	quota := ComputeQuota{
		MaxVMs:  0,
		UsedVMs: 5,
	}

	util := quota.GetUtilization()

	if util["vms"] != 0 {
		t.Errorf("vms utilization with zero max = %f, want 0", util["vms"])
	}
}

func TestComputeQuota_Available(t *testing.T) {
	quota := ComputeQuota{
		MaxVMs:         10,
		MaxContainers:  50,
		MaxVCPUs:       32,
		MaxMemoryMB:    65536,
		MaxDiskGB:      1024,
		UsedVMs:        5,
		UsedContainers: 25,
		UsedVCPUs:      16,
		UsedMemoryMB:   32768,
		UsedDiskGB:     512,
	}

	if quota.AvailableVMs() != 5 {
		t.Errorf("AvailableVMs() = %d, want 5", quota.AvailableVMs())
	}
	if quota.AvailableContainers() != 25 {
		t.Errorf("AvailableContainers() = %d, want 25", quota.AvailableContainers())
	}
	if quota.AvailableVCPUs() != 16 {
		t.Errorf("AvailableVCPUs() = %d, want 16", quota.AvailableVCPUs())
	}
	if quota.AvailableMemoryMB() != 32768 {
		t.Errorf("AvailableMemoryMB() = %d, want 32768", quota.AvailableMemoryMB())
	}
	if quota.AvailableDiskGB() != 512 {
		t.Errorf("AvailableDiskGB() = %d, want 512", quota.AvailableDiskGB())
	}
}

func TestComputeQuota_Available_Overused(t *testing.T) {
	quota := ComputeQuota{
		MaxVMs:  5,
		UsedVMs: 10, // Over limit
	}

	if quota.AvailableVMs() != 0 {
		t.Errorf("AvailableVMs() when overused = %d, want 0", quota.AvailableVMs())
	}
}

// NetworkQuota Tests

func TestNetworkQuota_HasCapacity(t *testing.T) {
	tests := []struct {
		name     string
		quota    NetworkQuota
		bridges  int64
		ports    int64
		expected bool
	}{
		{
			name:     "has capacity",
			quota:    NetworkQuota{MaxBridges: 5, MaxPorts: 100},
			bridges:  2,
			ports:    50,
			expected: true,
		},
		{
			name:     "no capacity for bridges",
			quota:    NetworkQuota{MaxBridges: 5, UsedBridges: 4},
			bridges:  2,
			expected: false,
		},
		{
			name:     "no capacity for ports",
			quota:    NetworkQuota{MaxBridges: 5, MaxPorts: 100, UsedPorts: 90},
			ports:    20,
			expected: false,
		},
		{
			name:     "exact capacity",
			quota:    NetworkQuota{MaxBridges: 5, UsedBridges: 3, MaxPorts: 100, UsedPorts: 80},
			bridges:  2,
			ports:    20,
			expected: true,
		},
		{
			name:     "zero request",
			quota:    NetworkQuota{MaxBridges: 0, MaxPorts: 0},
			bridges:  0,
			ports:    0,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.quota.HasCapacity(tt.bridges, tt.ports); got != tt.expected {
				t.Errorf("HasCapacity() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNetworkQuota_Reserve_Success(t *testing.T) {
	quota := NetworkQuota{
		MaxBridges: 5,
		MaxPorts:   100,
	}

	err := quota.Reserve("tenant-1", 2, 50)

	if err != nil {
		t.Errorf("Reserve() unexpected error: %v", err)
	}
	if quota.UsedBridges != 2 {
		t.Errorf("UsedBridges = %d, want 2", quota.UsedBridges)
	}
	if quota.UsedPorts != 50 {
		t.Errorf("UsedPorts = %d, want 50", quota.UsedPorts)
	}
}

func TestNetworkQuota_Reserve_Errors(t *testing.T) {
	tests := []struct {
		name     string
		quota    NetworkQuota
		bridges  int64
		ports    int64
		resource string
	}{
		{
			name:     "bridges quota exceeded",
			quota:    NetworkQuota{MaxBridges: 5, UsedBridges: 4},
			bridges:  2,
			resource: "bridges",
		},
		{
			name:     "ports quota exceeded",
			quota:    NetworkQuota{MaxBridges: 5, MaxPorts: 100, UsedPorts: 90},
			ports:    20,
			resource: "ports",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.quota.Reserve("tenant-1", tt.bridges, tt.ports)

			if err == nil {
				t.Error("Reserve() expected error")
				return
			}

			var quotaErr ErrQuotaExceeded
			if !errors.As(err, &quotaErr) {
				t.Errorf("Reserve() error type = %T, want ErrQuotaExceeded", err)
			}
			if quotaErr.Resource != tt.resource {
				t.Errorf("ErrQuotaExceeded.Resource = %q, want %q", quotaErr.Resource, tt.resource)
			}
		})
	}
}

func TestNetworkQuota_Release(t *testing.T) {
	quota := NetworkQuota{
		UsedBridges: 3,
		UsedPorts:   50,
	}

	quota.Release(1, 20)

	if quota.UsedBridges != 2 {
		t.Errorf("UsedBridges = %d, want 2", quota.UsedBridges)
	}
	if quota.UsedPorts != 30 {
		t.Errorf("UsedPorts = %d, want 30", quota.UsedPorts)
	}
}

func TestNetworkQuota_Release_NoNegative(t *testing.T) {
	quota := NetworkQuota{
		UsedBridges: 2,
		UsedPorts:   10,
	}

	quota.Release(10, 100)

	if quota.UsedBridges < 0 {
		t.Error("UsedBridges should not be negative")
	}
	if quota.UsedPorts < 0 {
		t.Error("UsedPorts should not be negative")
	}
}

func TestNetworkQuota_GetUtilization(t *testing.T) {
	quota := NetworkQuota{
		MaxBridges:  5,
		MaxPorts:    100,
		UsedBridges: 2,
		UsedPorts:   50,
	}

	util := quota.GetUtilization()

	if util["bridges"] != 40.0 {
		t.Errorf("bridges utilization = %f, want 40.0", util["bridges"])
	}
	if util["ports"] != 50.0 {
		t.Errorf("ports utilization = %f, want 50.0", util["ports"])
	}
}

func TestNetworkQuota_Available(t *testing.T) {
	quota := NetworkQuota{
		MaxBridges:  5,
		MaxPorts:    100,
		UsedBridges: 2,
		UsedPorts:   60,
	}

	if quota.AvailableBridges() != 3 {
		t.Errorf("AvailableBridges() = %d, want 3", quota.AvailableBridges())
	}
	if quota.AvailablePorts() != 40 {
		t.Errorf("AvailablePorts() = %d, want 40", quota.AvailablePorts())
	}
}

// StorageQuota Tests

func TestStorageQuota_HasCapacity(t *testing.T) {
	tests := []struct {
		name      string
		quota     StorageQuota
		volumesGB int64
		snapshots int64
		expected  bool
	}{
		{
			name:      "has capacity",
			quota:     StorageQuota{MaxVolumesGB: 2048, MaxSnapshots: 100},
			volumesGB: 500,
			snapshots: 50,
			expected:  true,
		},
		{
			name:      "no capacity for volumes",
			quota:     StorageQuota{MaxVolumesGB: 2048, UsedVolumesGB: 2000},
			volumesGB: 100,
			expected:  false,
		},
		{
			name:      "no capacity for snapshots",
			quota:     StorageQuota{MaxVolumesGB: 2048, MaxSnapshots: 100, UsedSnapshots: 90},
			snapshots: 20,
			expected:  false,
		},
		{
			name:      "exact capacity",
			quota:     StorageQuota{MaxVolumesGB: 2048, UsedVolumesGB: 1548, MaxSnapshots: 100, UsedSnapshots: 50},
			volumesGB: 500,
			snapshots: 50,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.quota.HasCapacity(tt.volumesGB, tt.snapshots); got != tt.expected {
				t.Errorf("HasCapacity() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStorageQuota_Reserve_Success(t *testing.T) {
	quota := StorageQuota{
		MaxVolumesGB: 2048,
		MaxSnapshots: 100,
	}

	err := quota.Reserve("tenant-1", 500, 25)

	if err != nil {
		t.Errorf("Reserve() unexpected error: %v", err)
	}
	if quota.UsedVolumesGB != 500 {
		t.Errorf("UsedVolumesGB = %d, want 500", quota.UsedVolumesGB)
	}
	if quota.UsedSnapshots != 25 {
		t.Errorf("UsedSnapshots = %d, want 25", quota.UsedSnapshots)
	}
}

func TestStorageQuota_Reserve_Errors(t *testing.T) {
	tests := []struct {
		name      string
		quota     StorageQuota
		volumesGB int64
		snapshots int64
		resource  string
	}{
		{
			name:      "volumes quota exceeded",
			quota:     StorageQuota{MaxVolumesGB: 2048, UsedVolumesGB: 2000},
			volumesGB: 100,
			resource:  "volume storage",
		},
		{
			name:      "snapshots quota exceeded",
			quota:     StorageQuota{MaxVolumesGB: 2048, MaxSnapshots: 100, UsedSnapshots: 90},
			snapshots: 20,
			resource:  "snapshots",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.quota.Reserve("tenant-1", tt.volumesGB, tt.snapshots)

			if err == nil {
				t.Error("Reserve() expected error")
				return
			}

			var quotaErr ErrQuotaExceeded
			if !errors.As(err, &quotaErr) {
				t.Errorf("Reserve() error type = %T, want ErrQuotaExceeded", err)
			}
			if quotaErr.Resource != tt.resource {
				t.Errorf("ErrQuotaExceeded.Resource = %q, want %q", quotaErr.Resource, tt.resource)
			}
		})
	}
}

func TestStorageQuota_Release(t *testing.T) {
	quota := StorageQuota{
		UsedVolumesGB: 500,
		UsedSnapshots: 25,
	}

	quota.Release(200, 10)

	if quota.UsedVolumesGB != 300 {
		t.Errorf("UsedVolumesGB = %d, want 300", quota.UsedVolumesGB)
	}
	if quota.UsedSnapshots != 15 {
		t.Errorf("UsedSnapshots = %d, want 15", quota.UsedSnapshots)
	}
}

func TestStorageQuota_Release_NoNegative(t *testing.T) {
	quota := StorageQuota{
		UsedVolumesGB: 100,
		UsedSnapshots: 10,
	}

	quota.Release(200, 20)

	if quota.UsedVolumesGB < 0 {
		t.Error("UsedVolumesGB should not be negative")
	}
	if quota.UsedSnapshots < 0 {
		t.Error("UsedSnapshots should not be negative")
	}
}

func TestStorageQuota_GetUtilization(t *testing.T) {
	quota := StorageQuota{
		MaxVolumesGB:  2048,
		MaxSnapshots:  100,
		UsedVolumesGB: 1024,
		UsedSnapshots: 50,
	}

	util := quota.GetUtilization()

	if util["volumes"] != 50.0 {
		t.Errorf("volumes utilization = %f, want 50.0", util["volumes"])
	}
	if util["snapshots"] != 50.0 {
		t.Errorf("snapshots utilization = %f, want 50.0", util["snapshots"])
	}
}

func TestStorageQuota_Available(t *testing.T) {
	quota := StorageQuota{
		MaxVolumesGB:  2048,
		MaxSnapshots:  100,
		UsedVolumesGB: 1024,
		UsedSnapshots: 60,
	}

	if quota.AvailableVolumesGB() != 1024 {
		t.Errorf("AvailableVolumesGB() = %d, want 1024", quota.AvailableVolumesGB())
	}
	if quota.AvailableSnapshots() != 40 {
		t.Errorf("AvailableSnapshots() = %d, want 40", quota.AvailableSnapshots())
	}
}

// safePercentage Tests

func TestSafePercentage(t *testing.T) {
	tests := []struct {
		name     string
		used     int64
		max      int64
		expected float64
	}{
		{"50% utilization", 50, 100, 50.0},
		{"100% utilization", 100, 100, 100.0},
		{"0% utilization", 0, 100, 0.0},
		{"zero max returns 0", 50, 0, 0.0},
		{"negative max returns 0", 50, -1, 0.0},
		{"fractional utilization", 1, 3, 100.0 / 3.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safePercentage(tt.used, tt.max)
			if math.Abs(got-tt.expected) > 0.0001 {
				t.Errorf("safePercentage(%d, %d) = %f, want %f", tt.used, tt.max, got, tt.expected)
			}
		})
	}
}

// GetQuotaSummary Tests

func TestGetQuotaSummary_AllQuotas(t *testing.T) {
	compute := &ComputeQuota{
		MaxVMs:         10,
		MaxContainers:  50,
		MaxVCPUs:       32,
		MaxMemoryMB:    65536,
		MaxDiskGB:      1024,
		UsedVMs:        5,
		UsedContainers: 25,
		UsedVCPUs:      16,
		UsedMemoryMB:   32768,
		UsedDiskGB:     512,
	}
	network := &NetworkQuota{
		MaxBridges:  5,
		MaxPorts:    100,
		UsedBridges: 2,
		UsedPorts:   50,
	}
	storage := &StorageQuota{
		MaxVolumesGB:  2048,
		MaxSnapshots:  100,
		UsedVolumesGB: 1024,
		UsedSnapshots: 50,
	}

	summary := GetQuotaSummary(compute, network, storage)

	// Verify compute summary
	if summary.Compute.VMsUsed != 5 {
		t.Errorf("Compute.VMsUsed = %d, want 5", summary.Compute.VMsUsed)
	}
	if summary.Compute.VMsTotal != 10 {
		t.Errorf("Compute.VMsTotal = %d, want 10", summary.Compute.VMsTotal)
	}
	if summary.Compute.ContainersUsed != 25 {
		t.Errorf("Compute.ContainersUsed = %d, want 25", summary.Compute.ContainersUsed)
	}
	if summary.Compute.ContainersTotal != 50 {
		t.Errorf("Compute.ContainersTotal = %d, want 50", summary.Compute.ContainersTotal)
	}

	// Verify network summary
	if summary.Network.BridgesUsed != 2 {
		t.Errorf("Network.BridgesUsed = %d, want 2", summary.Network.BridgesUsed)
	}
	if summary.Network.BridgesTotal != 5 {
		t.Errorf("Network.BridgesTotal = %d, want 5", summary.Network.BridgesTotal)
	}
	if summary.Network.PortsUsed != 50 {
		t.Errorf("Network.PortsUsed = %d, want 50", summary.Network.PortsUsed)
	}
	if summary.Network.PortsTotal != 100 {
		t.Errorf("Network.PortsTotal = %d, want 100", summary.Network.PortsTotal)
	}

	// Verify storage summary
	if summary.Storage.VolumesUsedGB != 1024 {
		t.Errorf("Storage.VolumesUsedGB = %d, want 1024", summary.Storage.VolumesUsedGB)
	}
	if summary.Storage.VolumesTotalGB != 2048 {
		t.Errorf("Storage.VolumesTotalGB = %d, want 2048", summary.Storage.VolumesTotalGB)
	}
	if summary.Storage.SnapshotsUsed != 50 {
		t.Errorf("Storage.SnapshotsUsed = %d, want 50", summary.Storage.SnapshotsUsed)
	}
	if summary.Storage.SnapshotsTotal != 100 {
		t.Errorf("Storage.SnapshotsTotal = %d, want 100", summary.Storage.SnapshotsTotal)
	}
}

func TestGetQuotaSummary_NilQuotas(t *testing.T) {
	summary := GetQuotaSummary(nil, nil, nil)

	// All values should be zero
	if summary.Compute.VMsUsed != 0 || summary.Compute.VMsTotal != 0 {
		t.Error("Compute summary should be zero when nil")
	}
	if summary.Network.BridgesUsed != 0 || summary.Network.BridgesTotal != 0 {
		t.Error("Network summary should be zero when nil")
	}
	if summary.Storage.VolumesUsedGB != 0 || summary.Storage.VolumesTotalGB != 0 {
		t.Error("Storage summary should be zero when nil")
	}
}

func TestGetQuotaSummary_PartialQuotas(t *testing.T) {
	compute := &ComputeQuota{
		MaxVMs:  10,
		UsedVMs: 5,
	}

	summary := GetQuotaSummary(compute, nil, nil)

	if summary.Compute.VMsUsed != 5 {
		t.Errorf("Compute.VMsUsed = %d, want 5", summary.Compute.VMsUsed)
	}
	if summary.Network.BridgesUsed != 0 {
		t.Error("Network should be zero when nil")
	}
	if summary.Storage.VolumesUsedGB != 0 {
		t.Error("Storage should be zero when nil")
	}
}

// Edge Cases and Boundary Tests

func TestComputeQuota_LargeValues(t *testing.T) {
	// Test with large but realistic values to avoid overflow
	quota := ComputeQuota{
		MaxVMs:  1000000,
		UsedVMs: 999999,
	}

	if !quota.HasCapacity(1, 0, 0, 0, 0) {
		t.Error("Should have capacity for 1 VM")
	}
	if quota.HasCapacity(2, 0, 0, 0, 0) {
		t.Error("Should not have capacity for 2 VMs")
	}
}

func TestNetworkQuota_LargeValues(t *testing.T) {
	// Test with large but realistic values
	quota := NetworkQuota{
		MaxBridges:  1000000,
		UsedBridges: 999999,
	}

	if !quota.HasCapacity(1, 0) {
		t.Error("Should have capacity for 1 bridge")
	}
	if quota.HasCapacity(2, 0) {
		t.Error("Should not have capacity for 2 bridges")
	}
}

func TestStorageQuota_LargeValues(t *testing.T) {
	// Test with large but realistic values (petabyte scale)
	quota := StorageQuota{
		MaxVolumesGB:  1000000000, // 1 PB
		UsedVolumesGB: 999999999,
	}

	if !quota.HasCapacity(1, 0) {
		t.Error("Should have capacity for 1 GB")
	}
	if quota.HasCapacity(2, 0) {
		t.Error("Should not have capacity for 2 GB")
	}
}
