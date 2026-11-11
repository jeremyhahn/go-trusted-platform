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
	"testing"
	"time"
)

func TestResourceType_String(t *testing.T) {
	tests := []struct {
		name     string
		resource ResourceType
		expected string
	}{
		{name: "vms", resource: ResourceVMs, expected: "vms"},
		{name: "containers", resource: ResourceContainers, expected: "containers"},
		{name: "vcpus", resource: ResourceVCPUs, expected: "vcpus"},
		{name: "memory", resource: ResourceMemory, expected: "memory"},
		{name: "disk", resource: ResourceDisk, expected: "disk"},
		{name: "bridges", resource: ResourceBridges, expected: "bridges"},
		{name: "ports", resource: ResourcePorts, expected: "ports"},
		{name: "bandwidth", resource: ResourceBandwidth, expected: "bandwidth"},
		{name: "volumes", resource: ResourceVolumes, expected: "volumes"},
		{name: "snapshots", resource: ResourceSnapshots, expected: "snapshots"},
		{name: "custom", resource: ResourceType("custom"), expected: "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resource.String()
			if result != tt.expected {
				t.Errorf("String() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestResourceType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		resource ResourceType
		expected bool
	}{
		{name: "vms_valid", resource: ResourceVMs, expected: true},
		{name: "containers_valid", resource: ResourceContainers, expected: true},
		{name: "vcpus_valid", resource: ResourceVCPUs, expected: true},
		{name: "memory_valid", resource: ResourceMemory, expected: true},
		{name: "disk_valid", resource: ResourceDisk, expected: true},
		{name: "bridges_valid", resource: ResourceBridges, expected: true},
		{name: "ports_valid", resource: ResourcePorts, expected: true},
		{name: "bandwidth_valid", resource: ResourceBandwidth, expected: true},
		{name: "volumes_valid", resource: ResourceVolumes, expected: true},
		{name: "snapshots_valid", resource: ResourceSnapshots, expected: true},
		{name: "empty_invalid", resource: ResourceType(""), expected: false},
		{name: "unknown_invalid", resource: ResourceType("unknown"), expected: false},
		{name: "custom_invalid", resource: ResourceType("custom"), expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resource.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestResourceType_Category(t *testing.T) {
	tests := []struct {
		name     string
		resource ResourceType
		expected string
	}{
		// Compute category
		{name: "vms_compute", resource: ResourceVMs, expected: "compute"},
		{name: "containers_compute", resource: ResourceContainers, expected: "compute"},
		{name: "vcpus_compute", resource: ResourceVCPUs, expected: "compute"},
		{name: "memory_compute", resource: ResourceMemory, expected: "compute"},
		// Network category
		{name: "bridges_network", resource: ResourceBridges, expected: "network"},
		{name: "ports_network", resource: ResourcePorts, expected: "network"},
		{name: "bandwidth_network", resource: ResourceBandwidth, expected: "network"},
		// Storage category
		{name: "disk_storage", resource: ResourceDisk, expected: "storage"},
		{name: "volumes_storage", resource: ResourceVolumes, expected: "storage"},
		{name: "snapshots_storage", resource: ResourceSnapshots, expected: "storage"},
		// Unknown category
		{name: "unknown_category", resource: ResourceType("unknown"), expected: "unknown"},
		{name: "empty_category", resource: ResourceType(""), expected: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.resource.Category()
			if result != tt.expected {
				t.Errorf("Category() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestTenantQuotas_GetLimit(t *testing.T) {
	quotas := &TenantQuotas{
		TenantID: "tenant-123",
		Compute: ComputeQuota{
			MaxVMs:        10,
			MaxContainers: 20,
			MaxVCPUs:      32,
			MaxMemoryMB:   65536,
		},
		Network: NetworkQuota{
			MaxBridges:       5,
			MaxPorts:         100,
			MaxBandwidthMbps: 1000,
		},
		Storage: StorageQuota{
			MaxDiskGB:    1000,
			MaxVolumes:   50,
			MaxSnapshots: 100,
		},
	}

	tests := []struct {
		name     string
		resource ResourceType
		expected int64
	}{
		{name: "vms", resource: ResourceVMs, expected: 10},
		{name: "containers", resource: ResourceContainers, expected: 20},
		{name: "vcpus", resource: ResourceVCPUs, expected: 32},
		{name: "memory", resource: ResourceMemory, expected: 65536},
		{name: "bridges", resource: ResourceBridges, expected: 5},
		{name: "ports", resource: ResourcePorts, expected: 100},
		{name: "bandwidth", resource: ResourceBandwidth, expected: 1000},
		{name: "disk", resource: ResourceDisk, expected: 1000},
		{name: "volumes", resource: ResourceVolumes, expected: 50},
		{name: "snapshots", resource: ResourceSnapshots, expected: 100},
		{name: "unknown_returns_zero", resource: ResourceType("unknown"), expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := quotas.GetLimit(tt.resource)
			if result != tt.expected {
				t.Errorf("GetLimit(%s) = %d, expected %d", tt.resource, result, tt.expected)
			}
		})
	}
}

func TestTenantQuotas_SetLimit(t *testing.T) {
	tests := []struct {
		name     string
		resource ResourceType
		limit    int64
		verify   func(*TenantQuotas) int64
	}{
		{
			name:     "set_vms",
			resource: ResourceVMs,
			limit:    15,
			verify:   func(q *TenantQuotas) int64 { return q.Compute.MaxVMs },
		},
		{
			name:     "set_containers",
			resource: ResourceContainers,
			limit:    25,
			verify:   func(q *TenantQuotas) int64 { return q.Compute.MaxContainers },
		},
		{
			name:     "set_vcpus",
			resource: ResourceVCPUs,
			limit:    64,
			verify:   func(q *TenantQuotas) int64 { return q.Compute.MaxVCPUs },
		},
		{
			name:     "set_memory",
			resource: ResourceMemory,
			limit:    131072,
			verify:   func(q *TenantQuotas) int64 { return q.Compute.MaxMemoryMB },
		},
		{
			name:     "set_bridges",
			resource: ResourceBridges,
			limit:    10,
			verify:   func(q *TenantQuotas) int64 { return q.Network.MaxBridges },
		},
		{
			name:     "set_ports",
			resource: ResourcePorts,
			limit:    200,
			verify:   func(q *TenantQuotas) int64 { return q.Network.MaxPorts },
		},
		{
			name:     "set_bandwidth",
			resource: ResourceBandwidth,
			limit:    2000,
			verify:   func(q *TenantQuotas) int64 { return q.Network.MaxBandwidthMbps },
		},
		{
			name:     "set_disk",
			resource: ResourceDisk,
			limit:    2000,
			verify:   func(q *TenantQuotas) int64 { return q.Storage.MaxDiskGB },
		},
		{
			name:     "set_volumes",
			resource: ResourceVolumes,
			limit:    75,
			verify:   func(q *TenantQuotas) int64 { return q.Storage.MaxVolumes },
		},
		{
			name:     "set_snapshots",
			resource: ResourceSnapshots,
			limit:    150,
			verify:   func(q *TenantQuotas) int64 { return q.Storage.MaxSnapshots },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quotas := &TenantQuotas{TenantID: "test-tenant"}
			quotas.SetLimit(tt.resource, tt.limit)
			result := tt.verify(quotas)
			if result != tt.limit {
				t.Errorf("SetLimit(%s, %d) resulted in %d, expected %d", tt.resource, tt.limit, result, tt.limit)
			}
		})
	}
}

func TestTenantQuotas_SetLimit_Unknown(t *testing.T) {
	quotas := &TenantQuotas{TenantID: "test-tenant"}
	original := *quotas
	quotas.SetLimit(ResourceType("unknown"), 100)
	// Verify nothing changed
	if quotas.Compute != original.Compute || quotas.Network != original.Network || quotas.Storage != original.Storage {
		t.Error("SetLimit with unknown resource should not modify quotas")
	}
}

func TestTenantQuotas_GetSetRoundTrip(t *testing.T) {
	quotas := &TenantQuotas{TenantID: "test-tenant"}
	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceBridges, ResourcePorts, ResourceBandwidth,
		ResourceDisk, ResourceVolumes, ResourceSnapshots,
	}

	for i, resource := range resources {
		limit := int64((i + 1) * 100)
		quotas.SetLimit(resource, limit)
		if got := quotas.GetLimit(resource); got != limit {
			t.Errorf("GetLimit(%s) after SetLimit = %d, expected %d", resource, got, limit)
		}
	}
}

func TestTenantUsage_GetUsage(t *testing.T) {
	usage := &TenantUsage{
		TenantID:      "tenant-123",
		VMs:           5,
		Containers:    10,
		VCPUs:         16,
		MemoryMB:      32768,
		DiskGB:        500,
		Bridges:       2,
		Ports:         50,
		BandwidthMbps: 500,
		Volumes:       25,
		Snapshots:     50,
	}

	tests := []struct {
		name     string
		resource ResourceType
		expected int64
	}{
		{name: "vms", resource: ResourceVMs, expected: 5},
		{name: "containers", resource: ResourceContainers, expected: 10},
		{name: "vcpus", resource: ResourceVCPUs, expected: 16},
		{name: "memory", resource: ResourceMemory, expected: 32768},
		{name: "disk", resource: ResourceDisk, expected: 500},
		{name: "bridges", resource: ResourceBridges, expected: 2},
		{name: "ports", resource: ResourcePorts, expected: 50},
		{name: "bandwidth", resource: ResourceBandwidth, expected: 500},
		{name: "volumes", resource: ResourceVolumes, expected: 25},
		{name: "snapshots", resource: ResourceSnapshots, expected: 50},
		{name: "unknown_returns_zero", resource: ResourceType("unknown"), expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := usage.GetUsage(tt.resource)
			if result != tt.expected {
				t.Errorf("GetUsage(%s) = %d, expected %d", tt.resource, result, tt.expected)
			}
		})
	}
}

func TestTenantUsage_SetUsage(t *testing.T) {
	tests := []struct {
		name     string
		resource ResourceType
		value    int64
		verify   func(*TenantUsage) int64
	}{
		{
			name:     "set_vms",
			resource: ResourceVMs,
			value:    7,
			verify:   func(u *TenantUsage) int64 { return u.VMs },
		},
		{
			name:     "set_containers",
			resource: ResourceContainers,
			value:    15,
			verify:   func(u *TenantUsage) int64 { return u.Containers },
		},
		{
			name:     "set_vcpus",
			resource: ResourceVCPUs,
			value:    24,
			verify:   func(u *TenantUsage) int64 { return u.VCPUs },
		},
		{
			name:     "set_memory",
			resource: ResourceMemory,
			value:    49152,
			verify:   func(u *TenantUsage) int64 { return u.MemoryMB },
		},
		{
			name:     "set_bridges",
			resource: ResourceBridges,
			value:    3,
			verify:   func(u *TenantUsage) int64 { return u.Bridges },
		},
		{
			name:     "set_ports",
			resource: ResourcePorts,
			value:    75,
			verify:   func(u *TenantUsage) int64 { return u.Ports },
		},
		{
			name:     "set_bandwidth",
			resource: ResourceBandwidth,
			value:    750,
			verify:   func(u *TenantUsage) int64 { return u.BandwidthMbps },
		},
		{
			name:     "set_disk",
			resource: ResourceDisk,
			value:    750,
			verify:   func(u *TenantUsage) int64 { return u.DiskGB },
		},
		{
			name:     "set_volumes",
			resource: ResourceVolumes,
			value:    35,
			verify:   func(u *TenantUsage) int64 { return u.Volumes },
		},
		{
			name:     "set_snapshots",
			resource: ResourceSnapshots,
			value:    75,
			verify:   func(u *TenantUsage) int64 { return u.Snapshots },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usage := &TenantUsage{TenantID: "test-tenant"}
			usage.SetUsage(tt.resource, tt.value)
			result := tt.verify(usage)
			if result != tt.value {
				t.Errorf("SetUsage(%s, %d) resulted in %d, expected %d", tt.resource, tt.value, result, tt.value)
			}
		})
	}
}

func TestTenantUsage_SetUsage_Unknown(t *testing.T) {
	usage := &TenantUsage{TenantID: "test-tenant"}
	original := *usage
	usage.SetUsage(ResourceType("unknown"), 100)
	// Verify nothing changed
	if usage.VMs != original.VMs || usage.Containers != original.Containers ||
		usage.VCPUs != original.VCPUs || usage.MemoryMB != original.MemoryMB {
		t.Error("SetUsage with unknown resource should not modify usage")
	}
}

func TestTenantUsage_GetSetRoundTrip(t *testing.T) {
	usage := &TenantUsage{TenantID: "test-tenant"}
	resources := []ResourceType{
		ResourceVMs, ResourceContainers, ResourceVCPUs, ResourceMemory,
		ResourceBridges, ResourcePorts, ResourceBandwidth,
		ResourceDisk, ResourceVolumes, ResourceSnapshots,
	}

	for i, resource := range resources {
		value := int64((i + 1) * 10)
		usage.SetUsage(resource, value)
		if got := usage.GetUsage(resource); got != value {
			t.Errorf("GetUsage(%s) after SetUsage = %d, expected %d", resource, got, value)
		}
	}
}

func TestReservation_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not_expired_future",
			expiresAt: time.Now().Add(5 * time.Minute),
			expected:  false,
		},
		{
			name:      "expired_past",
			expiresAt: time.Now().Add(-5 * time.Minute),
			expected:  true,
		},
		{
			name:      "expired_just_past",
			expiresAt: time.Now().Add(-1 * time.Millisecond),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reservation := &Reservation{
				ID:        "res-123",
				TenantID:  "tenant-123",
				Resource:  ResourceVMs,
				Amount:    1,
				CreatedAt: time.Now().Add(-1 * time.Minute),
				ExpiresAt: tt.expiresAt,
				Committed: false,
			}
			result := reservation.IsExpired()
			if result != tt.expected {
				t.Errorf("IsExpired() = %v, expected %v (expiresAt: %v, now: %v)",
					result, tt.expected, tt.expiresAt, time.Now())
			}
		})
	}
}

func TestDefaultReservationTTL(t *testing.T) {
	expected := 5 * time.Minute
	if DefaultReservationTTL != expected {
		t.Errorf("DefaultReservationTTL = %v, expected %v", DefaultReservationTTL, expected)
	}
}

func TestTenantQuotas_UpdatedAt(t *testing.T) {
	now := time.Now()
	quotas := &TenantQuotas{
		TenantID:  "tenant-123",
		UpdatedAt: now,
	}

	if !quotas.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, expected %v", quotas.UpdatedAt, now)
	}
}

func TestTenantUsage_Timestamp(t *testing.T) {
	now := time.Now()
	usage := &TenantUsage{
		TenantID:  "tenant-123",
		Timestamp: now,
	}

	if !usage.Timestamp.Equal(now) {
		t.Errorf("Timestamp = %v, expected %v", usage.Timestamp, now)
	}
}
